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
2. **Temporal windowing (ablace B) na CTU-13 věc ZHORŠIL, ne zlepšil** — opak toho, co by se dalo intuitivně čekat od "sofistikovanější" korelace. **Hypotéza potvrzena sweepem `time_window_s` ∈ {60, 300, 900, 1800, 3600, 7200}s** (test `ctu13_time_window_sweep_tests_fragmentation_hypothesis`): F1 roste monotónně s velikostí okna (0.029 → 0.057 → 0.081 → 0.093 → 0.102 → 0.115) a **při 7200s přesně konverguje k ablaci A** (TP=158, precision=0.083, recall=0.192, F1=0.115 — identické). Výřez trvá přesně 1h 16min 50s (17:13:40–18:30:30), takže 7200s okno pokryje celý capture jedním oknem — matematicky to je přesně ten samý případ jako ablace A (jedno "okno" = celý capture). **Potvrzeno, ne jen domněnka**: udržovaný nízko-objemový C2 beaconing, který se agregací přes celý capture dostane přes práh (`count>=3` atd.), se při kratším tumbling okně rozpadne na kousky, které práh jednotlivě nepřekročí. Okénkování bez korekce na typ/periodicitu signálu ztrácí přesně ten typ signálu, který má zachytit.
3. **`State` pole (NetFlow "FPA_FPA"/"CON" vs. Zeek "S0"/"REJ") je jiný vokabulář** — `is_timeout_like` heuristika laděná na Zeek `conn_state` hodnoty pravděpodobně na CTU-13 vůbec nefunguje jak má (nikdy nenajde shodu s "S0"/"REJ"/"RSTOS0"/"RSTRH"/"SH"), což částečně vysvětluje nižší recall i precision — modelový předpoklad implicitně svázaný s jedním zdrojem dat, teď explicitně zdokumentovaný jako limitace, ne skrytý.

## Důsledek: fixní tumbling okno je špatný nástroj pro udržovaný nízko-objemový signál

Sweep ukazuje jasný trade-off, ne "větší okno = lepší": malé okno dobře odděluje krátké, intenzivní bursty (proč ablace B nebyla o nic horší na IoT-23, kde celý útok trvá ~178s), ale ztrácí sustained low-rate C2 patterns, které potřebují agregaci přes celou dobu, aby překročily práh. **Fixní `time_window_s` zvolené podle jednoho datasetu (300s, odhadnuto z IoT-23 burstu) se nepřenáší na jiný typ provozu.** To je přímá, měřená motivace pro to, co návrh v sekci 5.2 nazývá "adaptivní" korelaci — okno/agregace by se měly volit podle charakteru signálu (burst vs. sustained beaconing), ne jako jedna globální konstanta. To je konkrétní, změřený (ne teoretický) argument pro navazující práci na typované nejistotě/Verification Planneru místo ladění jednoho čísla.

## Co to znamená pro další postup

Tohle číslo **je** ten baseline, proti kterému se musí měřit skutečná typovaná-nejistota/VOI vrstva, až bude napojená na rozhodování — ne jen IoT-23. Pokud budoucí vrstva (kalibrace, Case Memory) zlepší CTU-13 výsledek bez zhoršení IoT-23, je to measurable evidence generalizace, přesně co diplomka potřebuje prokázat. Bez tohoto měření by každé budoucí tvrzení o zlepšení bylo nepodložené na jediném malém korpusu.
