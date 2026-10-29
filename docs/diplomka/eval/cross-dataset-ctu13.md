# Cross-dataset generalizace: IoT-23 → CTU-13 (Deliverable 9, vlna 1)

**OPRAVA 29.10.2026 — původní verze tohoto dokumentu měla chybná čísla.** Nezávislá kontrola (Opus Plan agent, v rámci master-plánovacího kola) na reálných datech ukázala, že parser `src/eval/sources/ctu13.rs` mapoval CTU-13 kategorii `Background` (neověřený provoz) na `Benign` (potvrzeně benigní) — z 26 212 distinct `(dst_ip,proto,port)` klíčů ve výřezu je **25 317 (96,6 %) "Background-only"**. Tahle chyba sama způsobila původně hlášenou precision 0.083. Opraveno: `GroundTruthLabel` má teď tři hodnoty (Malicious/Benign/**Unknown**), `dataset_replay.rs` klíče s pouze Unknown flows **vyřazuje** z confusion matrix (ani FP, ani TN), ne tiše počítá jako benigní. Reprodukce opravy: `cargo test --lib eval::sources::ctu13::tests` a `cargo test --lib ctu13_cross_dataset -- --ignored --nocapture`.

**Status po opravě: naměřeno, s podstatně jiným a zajímavějším závěrem než původně.**

## Metodika

**Stejný, nezměněný kód** (`passive::anomaly`, `correlation.rs`, `correlation_v2.rs`) jako na IoT-23 — žádné ladění prahů pro CTU-13. Reprodukce: `cargo test --lib ctu13_cross_dataset -- --ignored --nocapture` (vyžaduje stažený výřez, viz `docs/diplomka/dataset-registry.md`).

**Dataset:** CTU-Malware-Capture-Botnet-54 (RBot), prvních 30 MB — 229 653 flows, 885 "known" (dst_ip,proto,port) klíčů po vyřazení Background-only (825 malicious, 60 confirmed benign — silně nevyvážené, ne reprezentativní vzorek reálného provozu).

## Naměřeno (opravená čísla)

| | IoT-23 (44-1) | CTU-13 (Botnet-54 výřez, po opravě) |
|---|---|---|
| Known klíčů | 10 | 885 (24 433 vyřazeno jako Unknown/Background) |
| **Ablace A precision** | 0.250 | **0.767** |
| **Ablace A recall** | 0.667 | **0.192** |
| **Ablace A F1** | 0.364 | **0.306** |
| **Triviální baseline "vše=malicious" F1** | **0.462** | **0.965** |

**Klíčové a humbling zjištění (nové, díky doplněnému triviálnímu baseline — návrh N2 z auditu):** na **obou** datasetech triviální klasifikátor "označ vše jako malicious" **poráží ablaci A na F1** (0.462 > 0.364 na IoT-23; 0.965 > 0.306 na CTU-13). Bez tohoto srovnání vypadala čísla ablace A jako "rozumná detekce" — ve skutečnosti aktuální heuristika na obou datasetech **nepřekonává nejhloupější možný klasifikátor**. Tohle je přesně ten "missing baseline" pitfall, který metodologická literatura k ML v bezpečnosti (Arp et al., USENIX Security 2022) jmenuje jako nejčastější chybu.

## Interpretace (opravená)

1. **Precision na CTU-13 je po opravě VYŠŠÍ než na IoT-23** (0.767 vs 0.250), ne nižší — přesný opak původního (chybného) tvrzení "precision dramaticky klesla". Recall zůstává nižší (0.192 vs 0.667). Důvod vysoké precision na CTU-13: po vyřazení Unknown je zbylá "known" populace silně nevyvážená (825 malicious vs 60 benign) — vysoká precision je z velké části artefaktem prevalence, ne důkazem kvality detekce (viz triviální baseline výše).
2. **Skutečný závěr není "heuristika hůř generalizuje"** — je to **"heuristika nepřekonává triviální baseline na žádném z obou datasetů"**. To je silnější a užitečnější zjištění pro odůvodnění diplomky: ukazuje, že problém není jen "přenositelnost mezi datasety", ale že současná heuristika jako taková ještě nepřináší měřitelnou hodnotu nad nejhloupější možné rozhodnutí.
3. **Temporal windowing (ablace B/C) na CTU-13 ablaci A dál zhoršuje** (F1 0.306→0.124 při 300s okně) — tohle zjištění **přežívá opravu** beze změny směru, jen s jinými absolutními čísly. Sweep `time_window_s` ∈ {60,...,7200}s (test `ctu13_time_window_sweep_tests_fragmentation_hypothesis`) dál ukazuje monotónní růst F1 s velikostí okna (0.059→0.306), konvergující při 7200s k ablaci A (matematicky stejný případ, okno = celý capture, trvající 1h16m50s).
4. **`State` pole (NetFlow vs. Zeek vokabulář) zůstává jako nepotvrzená, ale plausibilní dílčí příčina** nižšího recallu — nezměněno oproti předchozí verzi.

## Co to znamená pro další postup

Oprava nezneplatňuje fragmentační hypotézu o oknech (bod 3) — ta zůstává platná a podepřená sweepem. Mění ale celkový rámec: místo "naše heuristika generalizuje hůř na nový dataset" je přesnější "naše heuristika je na obou datasetech blízko nebo pod úrovní triviálního klasifikátoru, a teprve typovaná nejistota/kalibrace (H4) má šanci to změřitelně zlepšit". Každá budoucí tabulka v tomhle projektu musí obsahovat triviální baseline vedle ablací — bez něj je číslo bez kontextu.

**Omezení generalizačního tvrzení samotného (N1 auditu):** CTU-13 strana stojí na **jediném** scénáři (Botnet-54/RBot) z 13 dostupných. "Cross-dataset" zde fakticky znamená "druhý capture soubor", ne prokázanou šíři generalizace — rozšíření na víc CTU-13 scénářů (a ideálně i jiné botnet rodiny) je nutné, než se tomuto zjištění může říkat "generalizace" bez výhrady.
