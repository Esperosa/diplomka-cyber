# H2 krok 3: dependency-aware evidence fusion (Deliverable 27)

**Status: hotovo (29. 10. 2026) — fúzní logika, ne ještě zapojená do produkčního rozhodování.** Navazuje na Deliverable 25 (join-key, ověřeno proti reálnému Zeek/Suricata) a 26 (schema wiring). Tohle je první kód v celé diplomce, který literalně implementuje H2 claim (návrh sekce 5.1): *"stejný tok pozorovaný Suricatou, Zeekem a firewallem nejsou tři nezávislé důkazy."*

## Co bylo postaveno (`src/fusion.rs`)

- **`naive_independent_sum()`** — kontrolní protiklad: sečte skóre všech položek evidence, jako by byly nezávislé. Tohle je přesně "prostý scoring eventů", proti kterému H2 tvrdí zlepšení.
- **`dependency_corrected_fusion()`** — evidence se **stejným** `community_id` (stejný fyzický tok, Deliverable 25/26) se sloučí do jedné položky s **MAX** skóre mezi senzory, ne SOUČTEM — další senzor potvrzující už zachycený tok nepřináší nezávislou informaci. Evidence **bez** společného `community_id` (různé toky, nebo chybějící join-key) zůstává samostatná a její skóre se **sčítají** — přesně tam, kde nezávislost evidence skutečně existuje.

## Ověřeno

4 testy, včetně dvou, které přímo demonstrují tu vlastnost, kterou H2 tvrdí:
- `same_flow_from_two_sensors_is_not_double_counted`: Zeek (0.6) + Suricata (0.8) na stejném toku → naivní součet 1.4, korigované skóre 0.8 (MAX), **korigované < naivní** — přesně ten rozdíl, který H2 claim tvrdí.
- `different_flows_remain_independent_and_scores_sum`: 2 různé toky (jiné `community_id`) → korigované a naivní skóre se **shodují** — korekce nesnižuje skóre tam, kde závislost skutečně neexistuje (důležité: fúze nesmí být jen "vždycky sniž skóre", musí rozlišovat).
- `evidence_without_community_id_never_merges_with_other_unlabeled_evidence`: evidence bez join-key se nikdy tiše neslučuje s jinou evidencí bez join-key, jako by šlo o stejný tok — to by byla NOVÁ, horší chyba.
- `three_sensors_on_same_flow_still_cap_at_max_not_sum`: 3 senzory na stejném toku stále MAX, ne součet — vlastnost se nerozpadá při více než 2 senzorech.

## Co ještě H2 potřebuje — honestně

1. **Zapojení do `correlation_v2.rs`/`decision.rs`** — fúzní logika zatím nerozhoduje nic v produkčním kódu, je samostatná, testovaná jednotka (`#![allow(dead_code)]`).
2. **Re-validace ablací B/C/E na reálných dual-sensor datech** — potřeba Suricata sidecar vedle existujícího Zeek capture v multiservice labu (Deliverable 21 vzor), aby šlo změřit `naive_independent_sum` vs. `dependency_corrected_fusion` na REÁLNÉM provozu, ne jen na syntetických `EvidenceItem` v testech. To je Fáze 2 produkčního plánu — větší investice, samostatný krok.

Detailní fázování: `docs/diplomka/produkcni-plan.md`.
