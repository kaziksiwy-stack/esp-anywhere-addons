/**
 * ESP Anywhere - Experimental Cloudflare Worker Relay (WebSocket PoC with Durable Objects)
 *
 * NOTE: This is an EXPERIMENTAL alternative transport layer. The primary and default
 * transport for ESP Anywhere remains the MQTT Broker.
 *
 * This file implements the WebSocket routing using Cloudflare Durable Objects.
 * Durable Objects ensure that the Home Assistant connection and its corresponding ESP devices
 * connect to the EXACT SAME JavaScript state instance, fixing the routing issue present in
 * standard stateless Cloudflare Workers across different Edge locations.
 */

// Wzajemne uwierzytelnienie i konfiguracja
const HEARTBEAT_INTERVAL_MS = 30000;
const MAX_DEVICES_PER_TENANT = 100;
const MAX_MESSAGES_PER_SECOND = 10;

// Klasa Durable Object - działa jako singleton dla konkretnego Tenanta (Home Assistant)
export class TenantRelayDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;

    // Używamy in-memory state TYLKO dla tymczasowych kodów i rate limits.
    // Gniazda WebSockets w przypadku ewikcji DO z pamięci pobierane będą natywnie przez API: this.state.getWebSockets()
    this.pairingCodes = new Map(); // pinCode -> { expires, deviceId }
    this.rateLimits = new Map(); // deviceId -> { count, lastReset }
  }

  async fetch(request) {
    const url = new URL(request.url);
    const upgradeHeader = request.headers.get('Upgrade');

    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('Expected Upgrade: websocket', { status: 426 });
    }

    const path = url.pathname;

    // 1. Home Assistant (HA) podłącza się do tego Tenanta
    if (path.startsWith('/connect/ha')) {
      // Proste uwierzytelnienie (w PoC symulowane stałym tokenem)
      const token = url.searchParams.get('token');
      if (token !== this.env.SHARED_HA_TOKEN) {
        return new Response('Unauthorized HA', { status: 401 });
      }

      const [client, server] = Object.values(new WebSocketPair());

      // Zamykamy ewentualne stare gniazda HA (reconnect) by zapewnić jedno połączenie HA
      for (const ws of this.state.getWebSockets("ha")) {
         ws.close(1008, "New HA connection established");
      }

      // DO WebSocket Hibernation - akceptujemy z tagiem
      this.state.acceptWebSocket(server, ["ha"]);

      return new Response(null, { status: 101, webSocket: client });
    }

    // 2. Generowanie kodu parowania przez HA (HTTPS POST)
    if (path.startsWith('/pair/generate')) {
      const token = request.headers.get('Authorization');
      if (token !== `Bearer ${this.env.SHARED_HA_TOKEN}`) {
         return new Response('Unauthorized', { status: 401 });
      }
      const pin = Math.floor(100000 + Math.random() * 900000).toString(); // 6 cyfr
      // Ważne 10 minut
      this.pairingCodes.set(pin, { expires: Date.now() + 600000 });
      return new Response(JSON.stringify({ pin }), { status: 200 });
    }

    // 3. Połączenie urządzenia ESP z użyciem PINu
    if (path.startsWith('/connect/esp')) {
      const pin = url.searchParams.get('pin');
      const deviceId = url.searchParams.get('device_id');

      if (!pin || !deviceId) {
         return new Response('Missing pin or device_id', { status: 400 });
      }

      const pairing = this.pairingCodes.get(pin);
      if (!pairing || pairing.expires < Date.now()) {
         return new Response('Invalid or expired pairing code', { status: 401 });
      }

      // Liczymy wszystkie zhibernowane gniazda z tagiem "esp"
      const espSockets = this.state.getWebSockets("esp");
      if (espSockets.length >= MAX_DEVICES_PER_TENANT) {
          return new Response('Tenant device limit reached', { status: 429 });
      }

      // Jednorazowy kod - kasujemy
      this.pairingCodes.delete(pin);

      const [client, server] = Object.values(new WebSocketPair());

      // Zamykamy ewentualne stare gniazdo tego samego urządzenia
      for (const ws of this.state.getWebSockets(deviceId)) {
          ws.close(1008, "Reconnect");
      }

      // Tagujemy jako "esp" ORAZ pod konkretne ID urządzenia
      this.state.acceptWebSocket(server, ["esp", deviceId]);

      this.rateLimits.set(deviceId, { count: 0, lastReset: Date.now() });

      return new Response(null, { status: 101, webSocket: client });
    }

    return new Response('Not found in DO', { status: 404 });
  }

  // Obsługa wiadomości z zhibernowanych WebSocketów
  async webSocketMessage(ws, message) {
    const tags = this.state.getTags(ws);

    try {
      // Obsługa heartbeatu (ping/pong) omijająca logowanie sekretów
      if (message === 'PING') {
        ws.send('PONG');
        return;
      }

      if (tags.includes("ha")) {
        // Routing wiadomości od HA do konkretnego ESP
        const payload = JSON.parse(message);
        const targetDevice = payload.device_id;

        // Pobieramy gniazdo ESP po tagu
        const targetSockets = this.state.getWebSockets(targetDevice);
        if (targetSockets.length > 0) {
          targetSockets[0].send(message);
        }
      } else if (tags.includes("esp")) {
        const deviceId = tags.find(t => t !== "esp");

        // Rate limiting
        let rl = this.rateLimits.get(deviceId);
        if (rl) {
          const now = Date.now();
          if (now - rl.lastReset > 1000) {
            rl.count = 0;
            rl.lastReset = now;
          }
          if (rl.count >= MAX_MESSAGES_PER_SECOND) {
            // Drop message
            return;
          }
          rl.count++;
        } else {
            // Restore lost rate limit state after eviction
            this.rateLimits.set(deviceId, { count: 1, lastReset: Date.now() });
        }

        // Routing wiadomości od ESP wprost do instancji HA
        const haSockets = this.state.getWebSockets("ha");
        if (haSockets.length > 0) {
          haSockets[0].send(message);
        }
      }
    } catch (err) {
      // Nigdy nie loguj treści wiadomości (brak przechowywania sekretów w logach)
      console.error("Message routing failed", err.name);
    }
  }

  async webSocketClose(ws, code, reason, wasClean) {
     const tags = this.state.getTags(ws);
     if (tags.includes("esp")) {
        const deviceId = tags.find(t => t !== "esp");
        this.rateLimits.delete(deviceId);
     }
  }
}

// Główny entrypoint Workera - przekierowujący żądania do odpowiedniego TenantRelayDO
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const tenantId = url.searchParams.get('tenant_id');

    if (!tenantId) {
      return new Response('Missing tenant_id', { status: 400 });
    }

    // Izolacja tenantów poprzez generowanie unikalnego ID dla Durable Object (ID tenanta)
    const id = env.TENANT_RELAY.idFromName(tenantId);
    const obj = env.TENANT_RELAY.get(id);

    // Przekazanie requestu do konkretnego singletonu DO
    return await obj.fetch(request);
  }
};
