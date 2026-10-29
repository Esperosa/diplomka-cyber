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
