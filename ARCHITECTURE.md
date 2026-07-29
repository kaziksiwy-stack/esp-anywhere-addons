# ESP Anywhere - Architektura Systemu

## Wizja
Rozwiązanie umożliwiające podłączanie urządzeń ESPHome do zdalnego Home Assistanta przez internet bez VPN, przekierowywania portów i ręcznej konfiguracji MQTT.
Głównym celem jest zapewnienie konfiguracji tak prostej, jak w przypadku komercyjnych urządzeń (np. Tuya), z zachowaniem wysokiego poziomu bezpieczeństwa i prywatności.

## Przepływ Użytkownika (User Flow)
1. **Instalacja:** Użytkownik instaluje integrację lub dodatek ESP Anywhere w swoim Home Assistant (poprzez HACS lub oficjalny sklep z dodatkami).
2. **Kod aktywacyjny:** System generuje jednorazowy kod aktywacyjny.
3. **Konfiguracja urządzenia:** Użytkownik wpisuje otrzymany kod podczas wstępnej konfiguracji urządzenia ESP (np. poprzez portal Captive Portal / Access Point ESP).
4. **Automatyczne wykrycie:** Urządzenie po podłączeniu automatycznie pojawia się w instancji Home Assistant użytkownika wraz ze wszystkimi swoimi encjami.

## Architektura i Komponenty
*   **Urządzenie ESP:** Pracujące pod kontrolą ESPHome.
*   **Publiczny Relay/API:** Serwer pośredniczący w procesie onboardingu i przekazujący ruch.
*   **Broker MQTT:** Centralny punkt komunikacji pomiędzy ESP a HA. Zapewnia transport wiadomości z wykorzystaniem szyfrowania.
*   **Integracja/Dodatek Home Assistant:** Zarządza cyklem życia urządzeń z poziomu HA.

## Założenia Bezpieczeństwa
*   **Izolacja:** Ścisła izolacja użytkowników i urządzeń za pomocą przestrzeni nazw (tenant/device namespace). Urządzenie nie ma dostępu do danych innych użytkowników ani innych urządzeń.
*   **Uwierzytelnianie:** Wykorzystanie krótkotrwałych tokenów dostępowych oraz rotowanych tokenów odświeżających (access/refresh tokens).
*   **Indywidualne uprawnienia (MQTT):** Indywidualne poświadczenia MQTT i ścisłe listy kontroli dostępu (ACL) dla każdego pojedynczego urządzenia.
*   **Brak stałych haseł:** Brak wspólnych, stałych haseł (hardcoded) zaszytych w firmware urządzeń.
*   **Odporność:** Zabezpieczenie przed przejęciem jednorazowego kodu aktywacyjnego, tokenów i samego urządzenia.
*   **Zarządzanie dostępem:** Możliwość natychmiastowego unieważnienia dostępu (revoke) dla pojedynczego urządzenia ze strony serwera lub instancji HA.

## Funkcje Dodatkowe
*   **Zdalne OTA (Over-The-Air):** Bezpieczna aktualizacja oprogramowania urządzeń z wykorzystaniem protokołu HTTPS (firmware signed by Ed25519 jak zaimplementowano w Builderze).
*   **Przenośność / Self-hosting:** Architektura musi zakładać możliwość pełnego self-hostingu całej infrastruktury chmurowej (Relay/API, MQTT) oraz późniejszego, bezproblemowego przejścia z publicznego (udostępnianego) brokera na własne rozwiązanie.
*   **Kompatybilność:** Pełna kompatybilność ze standardem ESPHome oraz Home Assistant.
