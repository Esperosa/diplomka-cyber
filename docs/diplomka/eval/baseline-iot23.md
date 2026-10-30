# Baseline (ablace A) — IoT-23, nezměněný současný engine

**Commit:** `e0f4a43b09c3044cffab1e39ca57c3e429b27d8d` (29. 10. 2026) — výsledek je reprodukovatelný vůči tomuto konkrétnímu stavu kódu. Dataset: viz `docs/diplomka/dataset-registry.md`, vlna 0 (IoT-23).

**Reprodukce:** `cargo test --lib eval::dataset_replay -- --nocapture` (testy v `src/eval/dataset_replay.rs`, modul `tests`).

## Metodika

Ablace A = pasivní pravidla bez aktivního inventáře hostů (sekce 9.1 návrhu). Spouští se **nezměněný** současný engine: `passive::detect_connection_anomalies` → `correlation::correlate_events(&[], ...)` (prázdný `hosts`, protože IoT-23 je čistě pasivní capture bez Nmap inventáře) → `findings::generate_findings` → `decision::build_decision_bundle`. Žádná logika v `correlation.rs`/`decision.rs`/`report.rs`/`model.rs` nebyla pro toto měření upravena — pouze visibility bumpy (`pub` → `pub(crate)` na několika typech/funkcích), aby na ně `src/eval/` mohl sáhnout.

**Metrika a její granularita:** `detect_connection_anomalies` rozhoduje na úrovni `(dst_ip, proto, dst_port)` agregátu, ne per-flow — proto je i ground truth agregovaná na stejnou trojici (klíč je "malicious", pokud mezi flows patřícími pod tento klíč byl alespoň jeden s `label=Malicious`). To je vědomé metodologické rozhodnutí: měříme na granularitě, na které engine skutečně rozhoduje, ne na granularitě jednotlivého flow, kde by srovnání bylo zavádějící.

**Label-leakage záruka:** ground truth (`GroundTruthLabel`) se čte poprvé až po doběhnutí `correlate_events`/`generate_findings`/`build_decision_bundle` — nikdy není parametrem těchto funkcí. Zaručeno strukturně (`LabeledDataset.observations`/`.labels` jsou paralelní `Vec`, ne spojené přes klíč) — viz `src/eval/ground_truth.rs`.

## Naměřené výsledky

### Scénář CTU-IoT-Malware-Capture-44-1 (237 flows: 26 malicious / 211 benign)

| Metrika | Hodnota |
|---|---|
| Distinct `(dst_ip,proto,port)` klíčů | 10 |
| TP / FP / FN / TN | 2 / 6 / 1 / 1 |
| Precision | **0.250** |
| Recall | **0.667** |
| F1 | **0.364** |
| Vygenerováno `Finding` | 27 |
| Vygenerováno triage akcí | 3 |
| Zastoupené typy útoku (`detailed-label`) | C&C, C&C-FileDownload, DDoS |

### Scénář CTU-Honeypot-Capture-7-1 / Somfy-01 (130 flows, 100 % benign)

| Metrika | Hodnota |
|---|---|
| Distinct `(dst_ip,proto,port)` klíčů | 13 |
| FP / TN | 7 / 6 |
| Vygenerováno `Finding` | 17 |
| Vygenerováno triage akcí | 3 |

## Interpretace (bez přeceňování)

- **Recall 0.667 na 44-1** znamená, že současná heuristika anomálií zachytí 2 ze 3 skutečně napadených `(dst_ip,proto,port)` klíčů čistě z objemových/timeout vzorců — bez jakékoli signatury, CVE kontextu nebo aktivního ověření. To je rozumný základ, ne důkaz kvality.
- **Precision 0.250 na 44-1 a 7 FP ze 13 klíčů na čistě benigním Somfy-01** potvrzuje přesně to, co backendová analýza předpokládala: heuristika generuje citelný počet falešných poplachů i na klidném provozu. To je přímo měřitelný důvod, proč je temporal/graph korelace a typovaná nejistota (sekce 5 návrhu) potřebná, ne kosmetické zlepšení.
- **Žádné z těchto čísel není kalibrovaná pravděpodobnost** — jde o popis chování jedné konkrétní (velmi malé, 237+130 flows) sady scénářů. Zobecnění na jiný provoz/vlnu datasetů vyžaduje vlnu 1 (CTU-13, CICIDS...) a je to příští krok, ne tento.
- Tato dvě čísla (precision/recall ablace A) jsou referenční baseline pro budoucí ablace B/C/D/E — jakékoli tvrzení o zlepšení musí být citováno proti těmto hodnotám na stejném datasetu a stejné metodice, ne proti pocitu.

## Co tento baseline NEdokazuje

Shoduje se s omezeními v sekci 9.3 návrhu: nic o reálné propustnosti, chování na větší/jiné síti, dlouhodobém driftu, ani o aktivním ověřování (zde nebylo spuštěno žádné aktivní skenování — `hosts: &[]`). Vzorek 2 malých scénářů (367 flows celkem) je dostatečný pro ověření, že pipeline funguje a je reprodukovatelná, ne pro statisticky silné závěry o kvalitě detekce — to je úkol pro vlnu 1 s větším objemem a více zdroji.

## Dodatek (30. 10. 2026) — rozšíření ze 2 na 9 scénářů, 4 rodiny/techniky

Reakce na stejný požadavek, který vedl k rozšíření CTU-13 ze 3 na 13 scénářů (viz `ctu13-three-scenarios-dataset-sufficiency.md`): N=2 (1 malware scénář + 1 benigní) nestačí na statisticky průkazné tvrzení o kvalitě detekce. Doplněno 7 dalších malých committed scénářů (`dataset-registry.md`, sekce "Rozšíření 30.10.2026") — 5 malware (Malware-8-1/20-1/21-1/34-1/42-1, rodiny C&C/C&C-Torii/DDoS/FileDownload/PartOfAHorizontalPortScan) + 2 další benigní honeypoty (Honeypot-4-1/5-1). Reprodukce: `cargo test --lib eval::dataset_replay::tests::iot23_nine_scenarios_four_families_dataset_sufficiency_check -- --nocapture`.

**Reálný bug nalezený při rozšíření**: `extract_label` (`src/eval/sources/iot23.rs`) neuměl IoT-23 scénáře s novějším formátem labelu (3 řádně oddělené tab-pole místo jednoho smáčknutého) — `CTU-IoT-Malware-Capture-34-1` by bez opravy tiše změřil 0 known klíčů. Opraveno, ověřeno rozbij→spadne→vrať→projde. Detaily v commit message `de82d69`.

| Scénář | Rodina/technika | known_keys | TP/FP/FN/TN | Precision | Recall | F1 | Triviální baseline F1 |
|---|---|---|---|---|---|---|---|
| 44-1 | C&C, C&C-FileDownload, DDoS | 10 | 2/6/1/1 | 0.250 | 0.667 | **0.364** | 0.462 |
| Malware-8-1 | C&C | 9 | 2/6/0/1 | 0.250 | 1.000 | **0.400** | 0.364 |
| Malware-20-1 | C&C-Torii | 41 | 1/30/0/10 | 0.032 | 1.000 | **0.062** | 0.048 |
| Malware-21-1 | C&C-Torii | 51 | 1/35/0/15 | 0.028 | 1.000 | **0.054** | 0.038 |
| Malware-34-1 | C&C, DDoS, PartOfAHorizontalPortScan | 52 | 4/31/2/15 | 0.114 | 0.667 | **0.195** | 0.207 |
| Malware-42-1 | C&C-FileDownload, FileDownload | 48 | 2/36/0/10 | 0.053 | 1.000 | **0.100** | 0.080 |

**Agregát přes 6 malware scénářů**: F1 min=0.054, median=0.148, max=0.400. Ablace A poráží triviální baseline ("vše=malicious") jen na **4 ze 6** scénářů (44-1, Malware-8-1, Malware-20-1, Malware-21-1) — na Malware-34-1 a Malware-42-1 prohrává. To je slabší a honestnější tvrzení, než by dovolil N=2 (kde se ablace A na jediném malware scénáři jevila jako jasně nad baseline) — stejná třída poučení jako u CTU-13 rozšíření.

**3 benigní honeypot scénáře** (Somfy-01, Honeypot-4-1, Honeypot-5-1): false positive rate 0.444–0.688 — konzistentně vysoká, potvrzuje napříč 3 nezávislými čistě benigními vzorky (ne jen 1), že současná objemová heuristika generuje citelný šum i na klidném provozu.

**Co toto rozšíření stále nedokazuje**: N=6 malware scénářů umožňuje smysluplný medián/rozsah, ale je přesně na hraně, kde formální statistický test (Wilcoxon, n≥6) má jakoukoliv sílu. `CTU-IoT-Malware-Capture-3-1` (24 MB, rodiny Attack/C&C/PartOfAHorizontalPortScan) je zaznamenán v registru, ale vědomě gitignored a nezapojen do tohoto testu — další krok, ne provedený.

## Dodatek (31.10.2026): formální test na N=6 — NEprůkazné, zapsáno honestně

`src/eval/stats.rs::wilcoxon_signed_rank_test` aplikován na `f1(ablace A) - f1(triviální baseline)` přes 6 malware scénářů: **n_effective=6, W=7.0, p=0.5625**.

**Rozdíl NENÍ statisticky významný.** Na rozdíl od CTU-13 (N=13, p=0.001 — viz `ctu13-three-scenarios-dataset-sufficiency.md`), kde je ztráta ablace A proti triviálnímu baseline jasně průkazná, u IoT-23 na N=6 raw počet "4 ze 6 scénářů prohrává" nedosahuje statistické síly na to, aby šlo tvrdit obecný závěr — se stejnými daty by i opačný výsledek (3/6, 2/6) mohl snadno nastat jen náhodou na tak malém vzorku. To je přesně ten typ zjištění, které menší dataset (N=2 z Deliverable 1) nemohl vůbec odhalit — tam formální test nebyl ani proveditelný. Honestní závěr: IoT-23 F1 vs. triviální baseline zůstává **neprůkazné** při současné velikosti vzorku, ne "potvrzené v menší míře než CTU-13". Reprodukce: `cargo test --lib eval::dataset_replay::tests::iot23_nine_scenarios_four_families_dataset_sufficiency_check -- --nocapture`.
