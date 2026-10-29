# H4 — první skutečné měření: izotonická kalibrace přes leave-one-scenario-out (Deliverable 19)

**Status: naměřeno (29. 10. 2026).** Dosavadní H4 sekce (`souhrn-vysledku-a-hypotez.md`) byla jen "neověřitelné bez Case Memory" + změřený baseline, proti kterému by budoucí kalibrace musela prokázat zlepšení. Tohle je ten krok: minimální kalibrace (izotonická regrese, ne plný Case Memory s verzováním/poisoning guardem — to návrh sekce 5.6 sám řadí jako větší investici), vyhodnocená leave-one-scenario-out přes 3 CTU-13 scénáře (Deliverable 18).

## Co bylo postaveno

- **`passive::anomaly::score_connection_keys`** — nová funkce vystavující kontinuální anomaly skóre (stejný `max(robust_zscore(count), robust_zscore(pps), timeout_component)` vzorec, který `inductive_outlier_events` už počítal interně), pro VŠECHNY klíče s `count>=3`, ne jen pro ty, co překročily binární práh 3.2/2.4. Beze změny existujícího chování `detect_connection_anomalies`/ablace A — čistě nová, paralelní cesta ke čtení stejných dat.
- **`src/eval/calibration.rs`** — `IsotonicCalibrator` (PAVA, pool adjacent violators — ~40 řádků), `scored_points()` (spáruje skóre s ground truth, vyřadí Unknown-only klíče stejně jako `dataset_replay::run_ablation`), `brier_score()`.
- **Test `h4_isotonic_calibration_loso_brier_score_across_ctu13_scenarios`** — 3-fold leave-one-scenario-out: kalibrátor se natrénuje na 2 scénářích, vyhodnotí na tom třetím, nikdy se žádný scénář neobjeví současně v treningu i testu.

## Metodika srovnání

**"Nekalibrované" skóre** = přesně ten binární práh (`score >= 3.2 → 1.0 jinak 0.0`), který produkční kód už dnes používá k rozhodnutí, jestli se má vygenerovat event. To je nejhonestnější dostupný baseline — ne vymyšlená sláma, ale literálně to, co systém dnes dělá, přeformulované jako (chybná) "pravděpodobnost" pro účely Brier skóre.

## Naměřeno

```
LOSO held-out=Botnet-54: raw_brier=0.8398 calibrated_brier=0.7002
LOSO held-out=Botnet-51: raw_brier=0.7015 calibrated_brier=0.3376
LOSO held-out=Botnet-42: raw_brier=0.5086 calibrated_brier=0.2629
LOSO prumer pres 3 scenare: raw_brier=0.6833 calibrated_brier=0.4336
```

| Held-out scénář | Raw Brier (binární práh) | Kalibrovaný Brier (izotonická regrese) |
|---|---|---|
| Botnet-54 (Virut) | 0.840 | 0.700 |
| Botnet-51 (Rbot) | 0.702 | 0.338 |
| Botnet-42 (Neris) | 0.509 | 0.263 |
| **Průměr** | **0.683** | **0.434** |

## Interpretace

1. **Kalibrace zlepšila Brier skóre na VŠECH 3 held-out foldech** (ne jen v průměru) — konzistentní, ne artefakt jednoho scénáře. To je první skutečně naměřená, pozitivní podpora H4 v tomhle projektu, ne jen zdokumentovaná limitace.
2. **Důvod zlepšení je částečně mechanický, a je potřeba to říct nahlas**: binární 0/1 "pravděpodobnost" má ze své podstaty vysoký Brier skóre na nejistých bodech (každý false positive/negative u binárního prahu stojí plnou penaltu 1.0², zatímco kalibrovaná pravděpodobnost blízko empirické frekvenci stojí mnohem méně). Zlepšení tedy ukazuje hodnotu **měkkého, kalibrovaného skóre nad tvrdým prahem**, který produkce dnes používá — to je přesně to, co H4 a obecně typovaná nejistota (Deliverable 4) navrhují, ne nafouknuté tvrzení, že "model teď umí predikovat budoucnost".
3. **N=3 scénáře/2 rodiny** (Botnet-51=Rbot, Botnet-42=Neris, Botnet-54=Virut) — málo na formální statistiku, ale dost na to, aby zlepšení nebylo jen šťastná náhoda na jednom foldu (3/3 shoda směru).

## Honestní omezení

- **Tohle NENÍ Case Memory.** Case Memory (návrh sekce 5.6) vyžaduje verzování modelu, poisoning guard (jen verifikované label sources), a historii případů — nic z toho tu nevzniklo. Tohle je jednorázová kalibrace na existujících 3 datasetových scénářích, ne průběžně se učící systém.
- **Izotonická regrese je monotónní step-funkce** — snadno overfituje na malém N (max. počet "poolů" = počet trénovacích bodů). Na větším N (víc scénářů) by bylo potřeba regularizaci/vyhlazení, které tu není.
- **Srovnání je vůči binárnímu prahu, ne vůči jinému kalibračnímu přístupu** (Platt scaling, beta kalibrace) — izotonická regrese byla zvolena pro jednoduchost implementace (PAVA, ~40 řádků), ne proto, že by byla prokázaně nejlepší metoda.
- **`score_connection_keys` reflektuje jen `inductive_outlier_events`** (jeden ze 3 detektorů v `detect_connection_anomalies`) — `unexpected_traffic_events`/`aggregate_pattern_events` do kalibrovaného skóre nevstupují. Kalibrace je tedy kalibrací JEDNÉ heuristiky, ne celého ensemble, který ablace A ve skutečnosti používá pro binární rozhodnutí.
