// Prosty test dwóch klientów WebSocket (Funkcjonalny Node.js)
// Wymaga uruchomienia Workera lokalnie (wrangler dev) oraz pakietu 'ws' (npm install ws)

const WebSocket = require('ws');
const http = require('http');

const WORKER_URL = "http://localhost:8787";
const WS_URL = "ws://localhost:8787";
const TENANT_ID = "tenant-123";
const HA_TOKEN = "secret-token"; // Zgodny ze zmienną środowiskową SHARED_HA_TOKEN

async function runTest() {
    console.log("=== Start PoC Test ===");

    // 1. Połączenie HA
    console.log("1. Podłączanie Home Assistant...");
    const haWs = new WebSocket(`${WS_URL}/connect/ha?tenant_id=${TENANT_ID}&token=${HA_TOKEN}`);

    haWs.on('open', async () => {
        console.log("HA Połączony.");

        // 2. Generowanie PIN-u przez HTTPS jako HA (wymaga zmockowanego fetch lub wbudowanego http)
        console.log("2. Generowanie kodu parowania przez HTTP POST...");
        fetch(`${WORKER_URL}/pair/generate?tenant_id=${TENANT_ID}`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${HA_TOKEN}` }
        })
        .then(res => res.json())
        .then(data => {
            const pin = data.pin;
            console.log(`Wygenerowano PIN: ${pin}`);

            // 3. Połączenie ESP
            console.log("3. Podłączanie ESP z użyciem PINu...");
            const espWs = new WebSocket(`${WS_URL}/connect/esp?tenant_id=${TENANT_ID}&pin=${pin}&device_id=esp-001`);

            espWs.on('open', () => {
                console.log("ESP Połączone.");

                // 4. Test heartbeatu
                console.log("4. Wysyłanie PING z ESP...");
                espWs.send("PING");

                // 5. Wysyłanie stanu z ESP do HA
                setTimeout(() => {
                    console.log("5. Wysyłanie stanu temperatury z ESP do HA...");
                    espWs.send(JSON.stringify({ state: { temp: 22.5 } }));
                }, 500);
            });

            espWs.on('message', (msg) => {
                const message = msg.toString();
                if (message === "PONG") {
                    console.log("ESP odebrało PONG");
                } else {
                    console.log(`ESP odebrało komendę: ${message}`);
                    setTimeout(() => {
                        console.log("=== Zamykanie ===");
                        haWs.close();
                        espWs.close();
                    }, 500);
                }
            });

            espWs.on('error', err => console.error("Błąd ESP:", err.message));
        })
        .catch(err => console.error("Błąd parowania:", err));
    });

    haWs.on('message', (msg) => {
        const message = msg.toString();
        console.log(`HA odebrał stan: ${message}`);

        // 6. HA odsyła komendę do ESP
        console.log("6. HA wysyła komendę 'turn_on' do ESP...");
        haWs.send(JSON.stringify({ device_id: "esp-001", action: "turn_on" }));
    });

    haWs.on('error', err => console.error("Błąd HA:", err.message));
}

runTest();
