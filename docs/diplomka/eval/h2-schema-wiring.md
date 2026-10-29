# H2 krok 2: Community ID zapojeno do schématu (Deliverable 26)

**Status: hotovo (29. 10. 2026) — schema wiring, ne ještě fúzní vrstva.** Navazuje na Deliverable 25 (join-key primitivum, ověřené proti reálnému Zeek i Suricata). Tohle zapojuje `community_id_v1` do skutečně používaného datového modelu, ne jen do izolovaných testů.

## Co bylo postaveno

1. **`ConnectionObservation.src_port: Option<u16>`** — dřív chybělo úplně (audit finding). Zeek `conn.log`'s `id.orig_p` se nikdy neparsovalo, CTU-13 binetflow's `Sport` sloupec se nikdy nečetl, i když obě data mají.
2. **`ConnectionObservation::community_id(&self) -> Option<String>`** — POČÍTANÁ metoda, ne uložené pole. Záměrně: uložené pole by riskovalo zastaralost (kdyby se `src_ip`/`dst_port` změnily nezávisle na dřív spočítané hodnotě). Vrací `None`, pokud chybí `src_ip`/`src_port`, nebo protokol není tcp/udp/sctp.
3. **Opraveny 3 konstrukční místa** (`src/passive/zeek.rs`, `src/eval/sources/ctu13.rs`, `src/eval/sources/iot23.rs`) — všechna teď parsují a nesou `src_port`.

## Ověřeno

- **Žádná regrese na reálných datech**: CTU-13 cross-dataset test (885 known klíčů) vrací identická čísla jako před touto změnou (precision 0.767, F1 0.306) — čistě přídavná změna schématu, ne změna detekční logiky.
- **H1 literal Zeek test** (Deliverable 21) dál funguje end-to-end s novým polem (19 connections zachyceno, 3 pasivní findings, 5 kombinovaných).
- **3 nové testy** pro `ConnectionObservation::community_id()` — včetně té samé referenční hodnoty z reálného Zeeku jako v Deliverable 25, teď ověřené přes celý tok (ne jen přes holou funkci).

## Co ještě H2 potřebuje

Dependency-aware fúzní vrstva (`src/fusion.rs`, neexistuje) — vlastní H2 claim (korekce závislosti evidence při srovnávacím skórování, ne jen join podle community_id). To je oddělený, netriviální analytický krok (1-2 týdny), ne tahle změna schématu. Detailní fázování: `docs/diplomka/produkcni-plan.md`.
