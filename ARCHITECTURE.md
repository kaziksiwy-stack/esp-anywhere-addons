# ESP Anywhere - Architektura Systemu

## Wizja
Rozwiązanie umożliwiające podłączanie urządzeń ESPHome do zdalnego Home Assistanta przez internet bez VPN, przekierowywania portów i ręcznej konfiguracji MQTT.
Głównym celem jest zapewnienie konfiguracji tak prostej, jak w przypadku komercyjnych urządzeń (np. Tuya), z zachowaniem wysokiego poziomu bezpieczeństwa i prywatności, przy **zerowych kosztach infrastruktury centralnej** (Serverless).

## Przepływ Użytkownika (User Flow)
1. **Instalacja:** Użytkownik instaluje integrację ESP Anywhere w swoim Home Assistant (HACS).
2. **Generowanie Kodu:** Integracja łączy się do chmury (Cloudflare Workers) przez WebSocket i generuje 6-cyfrowy jednorazowy PIN.
3. **Konfiguracja ESP:** Użytkownik podłącza zdalne ESP do prądu, łączy się z jego siecią (Captive Portal), wybiera Wi-Fi działki i wpisuje wygenerowany kod PIN.
4. **Magia Pod Spodem:** ESP łączy się z Cloudflare Workerem (HTTPS/WSS), wymienia PIN na docelowy, krótkotrwały token sesyjny. Worker "skleja" gniazda (WebSockets) ESP i Home Assistanta w czasie rzeczywistym.
5. **Wykrycie:** Urządzenie natychmiast pojawia się w instancji Home Assistant użytkownika wraz z encjami.

## Architektura i Komponenty - Podejście "Pasożyt na Gigantach" (Serverless)
Zamiast tradycyjnego brokera MQTT (np. Mosquitto) i maszyny VPS (np. Hetzner), architektura opiera się na usługach "Edge Computing".
*   **Urządzenie ESP:** Pracujące pod kontrolą ESPHome z lekkim, niestandardowym komponentem komunikacyjnym C++ opartym na WebSockets (Zamiast MQTT).
*   **Publiczny Relay (Cloudflare Workers + Durable Objects):** Bezserwerowy węzeł komunikacyjny. Przerzuca wiadomości przez w otwarte tunele WebSockets z niemal zerowymi opóźnieniami.
*   **Baza Danych (Cloudflare KV):** Ekstremalnie szybka pamięć podręczna klucz-wartość do przechowywania 6-cyfrowych kodów aktywacyjnych i przypisań urządzeń.
*   **Integracja Home Assistant:** Działa jako klient WebSocket nawiązujący jedno stałe połączenie (tunel) na zewnątrz z infrastrukturą Cloudflare (przebijając w ten sposób NAT bez UPnP i Port Forwarding).

## Założenia Bezpieczeństwa
*   **Izolacja (Tenant Namespace):** Routing wiadomości w Cloudflare Durable Objects gwarantuje, że zdarzenia trafiają tylko do gniazda WebSocket konkretnego Home Assistanta.
*   **Brak stałych haseł:** Brak danych logowania wpisanych w kod ESP. Uwierzytelnianie następuje dynamicznie w oparciu o jednorazowy PIN.
*   **Zero widocznych portów (NAT Traversal):** Zabezpieczenie wynikające z zasady, że wszystkie połączenia wychodzą *na zewnątrz* do Cloudflare (Zarówno z domu, jak i z działki). Żadne porty nie muszą być otwarte.
*   **Odporność na przejęcie urządzenia:** Skradzione urządzenie z działki używa ograniczonych czasowo kluczy / przypisanych UUID. Po usunięciu go z HA, Worker odrzuca połączenia WebSockets.

## Zmiana w stosunku do pierwotnych założeń (Pożegnanie z MQTT)
Decyzja architektoniczna zdejmuje konieczność płacenia z własnej kieszeni za flotę serwerów MQTT (jak Mosquitto/VerneMQ) czy wiązania użytkowników z zewnętrznymi rejestracjami (jak HiveMQ). WebSockets na mikrokontrolerach są niesamowicie lekkie, a środowiska darmowe typu Cloudflare rozwiązują problem opóźnień i masowej skali.
