# Eksperymentalny Transport ESP Anywhere: Cloudflare Workers + WebSockets (PoC)

## Kontekst
Poniższy dokument opisuje alternatywny transport oparty na WebSockets przy użyciu architektury Cloudflare Workers (z Durable Objects), stworzony jako dowód koncepcji (PoC). Główną, docelową architekturą ESP Anywhere wciąż pozostaje **Broker MQTT**. Ten transport jest eksperymentem mającym na celu weryfikację możliwości obejścia restrykcji sieciowych i firewalli przy pomocy bezserwerowych rozwiązań brzegowych (Edge Computing).

## Dlaczego początkowy kod (globalna pamięć) był niewystarczający?
Pierwsza wersja skryptu `worker.js` (używająca tylko `WebSocketPair()`) nie zapewniała poprawnego routingu z powodu rozproszonej natury Cloudflare Workers.
Gdy klient (HA lub ESP) łączy się z Workerem, żądanie jest kierowane do serwera (węzła) znajdującego się najbliżej niego geograficznie (np. HA łączy się w Warszawie, a ESP w innym mieście lub państwie może trafić na węzeł w Berlinie). W efekcie, instancja Workera w Warszawie i instancja Workera w Berlinie posiadają odizolowane środowiska operacyjne – nie dzielą zmiennych globalnych ani otwartych gniazd. ESP nie miało fizycznej możliwości wysłania wiadomości do połączenia HA, ponieważ gniazdo HA istniało w innym procesie na innym serwerze (izolacja "V8 isolates").

Rozwiązaniem tego problemu w architekturze Cloudflare są **Durable Objects (DO)**.

## Architektura Durable Objects (DO)
Durable Object gwarantuje jeden, unikalny punkt w sieci (singleton), do którego kierowane są wszystkie żądania dla danego identyfikatora, niezależnie od tego, skąd na świecie przychodzą klienci.

**Kluczowe założenia PoC z użyciem DO:**
1. **Jeden Tenant = Jeden Durable Object:** Dla każdej instalacji Home Assistant tworzony jest unikalny Durable Object na podstawie ID Tenanta. Gwarantuje to absolutną izolację tenantów (klienci jednego HA nigdy nie wejdą w kontakt z pamięcią/DO innego HA).
2. **WebSocket Hibernation:** DO hibernuje WebSockets, kiedy nie przesyłają danych, drastycznie zmniejszając użycie pamięci (i koszty).
3. **Uwierzytelnienie i Jednorazowe Piny:** Urządzenia uwiarytelniają się przez DO, korzystając z parowania kodami jednorazowymi, zanim zostaną dopuszczone do tunelu.
4. **Reconnect i Heartbeat:** Implementacja obsługuje ponowne łączenie bez utraty autoryzacji oraz okresowe wysyłanie heartbeatów (ping/pong), by utrzymać otwarte tunele i zapobiec timeoutom ze strony CDN.

## Realistyczna Analiza Limitów i Kosztów
Architektura Serverless (Workers + DO) **nie jest darmowa na zawsze** ani w nieskończoność. O ile darmowy plan Cloudflare pozwala na wdrożenie standardowych Workerów, **Durable Objects są funkcją wyłącznie płatną (wymagają planu Workers Paid)**, kosztującego od $5/miesiąc.

*   **Pamięć i czas CPU:** Każda wiadomość przepływająca przez zhibernowane WebSocket "budzi" DO, zużywając ułamek limitu CPU. Choć WebSocket hibernacja redukuje koszty połączeń bezczynnych, *wysoki ruch* (np. co sekundowe raportowanie czujnika energii) szybko spali darmowe limity zapytań (Requests).
*   **Żądania (Requests):** Nawet otwarte gniazda WebSocket kosztują. Koszt naliczany jest nie tylko przy nawiązywaniu (handshake), ale Cloudflare nalicza użycie za wbudzone zdarzenia. Przy tysiącach urządzeń ruch wzrośnie drastycznie.
*   **Limity urządzeń/wiadomości:** By zapobiec bankructwu, konieczne jest nałożenie twardych limitów na urządzeniu ESP (np. wysyłanie stanów tylko co minutę lub przy zmianie, wymuszanie minimalnego cyklu telemetrycznego).

Dlatego w ostatecznym rozrachunku model oparty na własnym / publicznym brokerze MQTT i serwerze Relay wydaje się bardziej przewidywalny cenowo w dłuższej perspektywie. Ten transport pozostanie polem badawczym dla poszukiwania P2P.
