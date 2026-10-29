# Cross-dataset generalizace: IoT-23 → CTU-13 (Deliverable 9, vlna 1)

**Status: naměřeno (29. 10. 2026).** Nejdůležitější zjištění z celé diplomky dosud: heuristiky, které na IoT-23 vypadaly rozumně, **výrazně hůř generalizují** na odlišný dataset. Tohle je přímo to, co design doc sekce 7.2 požaduje ("vyhodnocení na neviděném datasetu je nutné; náhodné rozdělení flow často vytváří nerealisticky dobré výsledky") a přímo zdůvodňuje, proč je typovaná nejistota (Deliverable 4) a VOI planner (Deliverable 5), ne jen heuristické prahy, skutečným cílem diplomky.

## Metodika

**Stejný, nezměněný kód** (`passive::anomaly`, `correlation.rs`, `correlation_v2.rs`) jako na IoT-23 — žádné ladění prahů pro CTU-13. Nový vstup je jen `src/eval/sources/ctu13.rs` (parser pro CTU-13 `binetflow` CSV formát — jiná modalita než IoT-23's Zeek conn.log, žádné sdílení parsovací logiky). Reprodukce: `cargo test --lib ctu13_cross_dataset -- --ignored --nocapture` (vyžaduje stažený výřez, viz `docs/diplomka/dataset-registry.md`).

**Dataset:** CTU-Malware-Capture-Botnet-54 (RBot), prvních 30 MB (reprezentativní výřez přes HTTP Range, ne celý 251MB soubor) — 229 653 flows, 6 185 malicious (2,7 %, mnohem nižší podíl malicious než IoT-23's 11 %).

## Naměřeno

| | IoT-23 (44-1) | CTU-13 (Botnet-54 výřez) |
|---|---|---|
| Flows | 237 | 229 653 |
| Malicious podíl | 11 % | 2,7 % |
| **Ablace A precision** | 0.250 | **0.083** |
| **Ablace A recall** | 0.667 | **0.192** |
| **Ablace A F1** | 0.364 | **0.115** |
| Ablace B precision/recall/F1 | 0.250/0.667/0.364 (beze změny) | **0.049/0.069/0.057 (HORŠÍ než A)** |

## Interpretace

1. **Přesnost dramaticky klesla přechodem na jiný dataset** — to je přesně ten "overfitting na jeden korpus" problém, který design doc (sekce 7.2, 12 bod 11) explicitně varuje nezaměňovat s obecnou kvalitou detekce. Číslo 0.250/0.667 z IoT-23 nikdy nebylo tvrzeno jako obecná vlastnost enginu — teď je přímo změřeno, že neplatí jinde.
2. **Temporal windowing (ablace B) na CTU-13 věc ZHORŠIL, ne zlepšil** — opak toho, co by se dalo intuitivně čekat od "sofistikovanější" korelace. Pravděpodobné vysvětlení (nepotvrzeno dalším měřením, zapsáno jako hypotéza k ověření): CTU-13 capture trvá podstatně déle než IoT-23's těsný burst, a udržované nízko-objemové C2 beaconing vzory, které se agregací přes celý capture (ablace A) dostanou přes práh (`count>=3` apod.), se 300s tumbling oknem rozpadnou na kousky, které práh jednotlivě nepřekročí — TP kleslo z 158 na 57. Okénkování bez korekce na typ/periodicitu signálu může ztratit přesně ten typ signálu, který má zachytit.
3. **`State` pole (NetFlow "FPA_FPA"/"CON" vs. Zeek "S0"/"REJ") je jiný vokabulář** — `is_timeout_like` heuristika laděná na Zeek `conn_state` hodnoty pravděpodobně na CTU-13 vůbec nefunguje jak má (nikdy nenajde shodu s "S0"/"REJ"/"RSTOS0"/"RSTRH"/"SH"), což částečně vysvětluje nižší recall i precision — modelový předpoklad implicitně svázaný s jedním zdrojem dat, teď explicitně zdokumentovaný jako limitace, ne skrytý.

## Co to znamená pro další postup

Tohle číslo **je** ten baseline, proti kterému se musí měřit skutečná typovaná-nejistota/VOI vrstva, až bude napojená na rozhodování — ne jen IoT-23. Pokud budoucí vrstva (kalibrace, Case Memory) zlepší CTU-13 výsledek bez zhoršení IoT-23, je to measurable evidence generalizace, přesně co diplomka potřebuje prokázat. Bez tohoto měření by každé budoucí tvrzení o zlepšení bylo nepodložené na jediném malém korpusu.
