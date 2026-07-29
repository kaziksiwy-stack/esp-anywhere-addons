/**
 * ESP Anywhere - Cloudflare Worker Relay (Serverless WebSocket POC)
 *
 * Ten kod jest punktem wyjścia dla infrastruktury "Pasożyta na gigantach".
 * Worker działa jako router wiadomości (Message Broker) oparty na WebSockets.
 *
 * W pełnej implementacji użyjemy Cloudflare Durable Objects, by utrzymać stały stan
 * (listę otwartych połączeń WebSockets dla danego Tenanta/Home Assistanta) i
 * precyzyjnie kierować wiadomości od ESP do konkretnej instancji HA.
 *
 * Tutaj prezentujemy zarys logiki uwierzytelniania i nawiązywania gniazda.
 */

export default {
  async fetch(request, env, ctx) {
    const upgradeHeader = request.headers.get('Upgrade');

    // Obsługa tylko połączeń WebSocket
    if (!upgradeHeader || upgradeHeader !== 'websocket') {
      return new Response('ESP Anywhere Relay. Proszę użyć WebSockets.', { status: 426 });
    }

    const url = new URL(request.url);
    const path = url.pathname; // np. /connect/ha lub /connect/esp

    // 1. Logika dla Home Assistant (Tenant)
    if (path.startsWith('/connect/ha')) {
      const tenantToken = url.searchParams.get('token');
      if (!tenantToken) return new Response('Brak tokenu', { status: 401 });

      // Tworzymy parę WebSocketów: jeden dla klienta (HA), drugi zostaje u nas na serwerze
      const [client, server] = Object.values(new WebSocketPair());

      server.accept();

      server.addEventListener('message', event => {
        // HA może wysyłać komendy do konkretnych urządzeń:
        // np. {"action": "send_command", "device_id": "esp-123", "command": "turn_on"}
        console.log("Otrzymano od HA:", event.data);

        // Docelowo: Odszukaj połączenie WebSocket dla "esp-123" w strukturach
        // Durable Object i przekaż wiadomość.
      });

      server.addEventListener('close', () => {
        console.log("HA rozłączony");
      });

      return new Response(null, {
        status: 101,
        webSocket: client,
      });
    }

    // 2. Logika dla Urządzenia ESP
    else if (path.startsWith('/connect/esp')) {
      const pinCode = url.searchParams.get('pin');

      // Docelowo: Weryfikacja PINu w Cloudflare KV.
      // Z KV pobieramy przypisany tenant_id.
      if (!pinCode) return new Response('Brak kodu PIN', { status: 401 });

      const [client, server] = Object.values(new WebSocketPair());
      server.accept();

      server.addEventListener('message', event => {
        // ESP zgłasza swój stan:
        // np. {"state": {"temperature": 22.5}}
        console.log("Otrzymano od ESP:", event.data);

        // Docelowo: Odszukaj połączenie HA przypisane do tego urządzenia
        // (na podstawie walidacji w Cloudflare KV) i przekaż mu stan.
      });

      return new Response(null, {
        status: 101,
        webSocket: client,
      });
    }

    return new Response('Nieznany endpoint', { status: 404 });
  }
};
