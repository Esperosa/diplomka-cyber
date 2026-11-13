# H2 krok 1: Community ID join-key, ověřeno proti reálnému Zeek i Suricata (Deliverable 25)

**Status: hotovo (29. 10. 2026) — join-key, ne celá H2.** První krok produkčního plánu (`docs/diplomka/produkcni-plan.md`) pro H2: žádná cross-senzorová fúze nemůže existovat bez sdíleného identifikátoru toku, protože `src/passive/zeek.rs` (Zeek `uid`) a `src/passive/suricata.rs` (Suricata `flow_id`) používají senzor-lokální ID, která nejsou mezi senzory porovnatelná — přesně to, co nezávislý audit potvrdil čtením kódu (`grep` na `community_id|flow_id|suricata` v `correlation_v2.rs` = 0 výsledků).

## Co bylo postaveno

- **`src/passive/community_id.rs`** — `community_id_v1(src_ip, src_port, dst_ip, dst_port, proto) -> Option<String>`: implementace Community ID v1 algoritmu (normalizace směru podle bajtů adresy/portu, SHA-1 přes seřazenou 5-tuple, base64 s prefixem `"1:"`). Omezeno na TCP/UDP/SCTP (ICMP vyžaduje jinou type/code logiku, zatím neimplementováno).

## Jak byl algoritmus ověřen — ne jen podle specifikace odhadnut

1. **Reálný TCP handshake zachycen** (`tcpdump` sidecar sdílející network namespace s cílovým kontejnerem, stejný postup jako Deliverable 21).
2. **Zeek 9.0.1** s `policy/protocols/conn/community-id-logging` spuštěný offline nad stejným pcapem vrátil `community_id = 1:nTs1CSdTGlG13eI4k9WSGFAbjAw=` pro tok `172.17.0.1:49818 → 172.17.0.2:80 tcp`.
3. **Suricata 8.0.7** (`jasonish/suricata`), offline nad druhým zachyceným pcapem s `community-id=yes`, vrátila `1:ylOa6zhQXyUgu30rGBQ82VAhhk4=` pro tok `172.17.0.1:35682 → 172.17.0.2:80 tcp`.
4. **Rust implementace vrátila bajtově identické hodnoty pro oba toky** — ověřeno jako testy (`matches_real_zeek_reference_value_for_captured_tcp_flow`, `matches_real_suricata_reference_value_for_captured_tcp_flow`), ne jen manuálně jednou spočítáno.
5. **Směrová nezávislost ověřena přímo**: stejný tok zadaný v obráceném směru (server→klient místo klient→server) dá identický výsledek — to je celá hodnota Community ID jako join-key (bez toho by stejný tok viděný "z druhé strany" dostal jiné ID).

## Interpretace

Tohle je přesně ten "modest effort, dny ne týdny" kus, který všechny tři nezávislé revize v produkčním auditu identifikovali jako kritickou cestu k H2 — a je hotový, cross-senzorově ověřený proti dvěma nezávislým reálným implementacím (ne proti jedné, a ne proti psané specifikaci, která by mohla mít nejasnosti v interpretaci).

## Co ještě H2 potřebuje — honestně, ne zamlčeno

1. **Zapojení do schématu.** `ConnectionObservation`/`NormalizedEvent` ještě nemají pole `community_id`/`src_port` — `zeek.rs` dnes `id.orig_p` (zdrojový port) vůbec neparsuje. `community_id_v1` je zatím `#[allow(dead_code)]`, nevolaná z produkčního kódu.
2. **Dependency-aware fúzní vrstva** (`src/fusion.rs`, neexistuje) — vlastní H2 claim (korekce závislosti evidence, ne jen deduplikace podle join-key) je nový analytický design, 1-2 týdny práce, ne tahle funkce.
3. **Žádný nový dataset potřeba pro strukturální test** — multiservice lab (Deliverable 15/16/21) může dostat Suricata sidecar vedle existujícího Zeek capture, stejný postup jako u tohohle ověření.

Detailní fázování: `docs/diplomka/produkcni-plan.md`.
