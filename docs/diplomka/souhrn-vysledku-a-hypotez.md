# Souhrn výsledků (Deliverables 1–13) a vztah k výzkumným hypotézám H1–H5

**Status: konsolidace k 29. 10. 2026, OPRAVENO po nezávislém master-plan auditu (3 agenti, Opus + pragmatik + skeptik).** Návrhový dokument (sekce 11) definuje 5 výzkumných hypotéz pro diplomku. Tento dokument mapuje, co z dosavadních deliverables tyto hypotézy skutečně testuje — **honestně**, včetně částečně negativních výsledků, ne jako seznam úspěchů.

**Oprava 29.10.2026 (Deliverable 14):** nezávislý audit (Opus Plan agent) odhalil a ověřil přímo v datech/kódu konkrétní chyby v předchozí verzi tohoto dokumentu a navazujících eval reportů:
1. **CTU-13 "Background" se chybně počítal jako "Benign"** — opraveno na tříhodnotový label (Malicious/Benign/**Unknown**), `Unknown`-only klíče se teď vyřazují z confusion matrix. Přesná oprava: `docs/diplomka/eval/cross-dataset-ctu13.md`.
2. **Chyběl triviální baseline** ("klasifikuj vše jako malicious") — doplněno (`ConfusionMatrix::trivial_always_positive_baseline()`). Výsledek je humbling: tenhle triviální klasifikátor **poráží ablaci A na F1 na obou datasetech** (IoT-23 0.462 vs 0.364, CTU-13 0.965 vs 0.306 po opravě bodu 1).
3. **Ablace B/C/D v kódu neodpovídají ablacím B/C/D/E z návrhu** (sekce 9.1) — kódové B/C/D jsou všechny podvarianty návrhové ablace C (temporal/graph), návrhové B (aktivní signály) a E (kalibrace) nikdy neběžely v tomhle harnessu. H2 status níže je proto opraven na konzervativnější "netestováno", ne "částečně vyvráceno".
4. **Hashe v `dataset-registry.md` byly useknuté o 1 znak** — opraveno, doplněn automatický test (`eval::tests::committed_iot23_files_match_hashes_recorded_in_dataset_registry`).

## Co bylo postaveno (Deliverables 1–10, chronologicky)

| # | Co | Klíčový soubor | Status |
|---|---|---|---|
| 1 | Label-leakage-safe eval framework, baseline (ablace A) | `src/eval/` | Hotovo, IoT-23 |
| 2 | Identity vrstva (MAC-aware cross-run resolver) | `src/identity.rs` | Hotovo, syntetické scénáře |
| 3 | Temporal/graph korelace (ablace B/C), honestní nulový výsledek + NTP FP nález | `src/correlation_v2.rs` | Hotovo, IoT-23 |
| 4 | Typovaná nejistota (6 typů), žádná fabrikace chybějících | `src/hypothesis.rs` | Hotovo |
| 5 | VOI Verification Planner (jen selekce, bez exekuce) | `src/verification_planner.rs` | Hotovo |
| 6 | 3 odložené P0 bezpečnostní bugy opraveny | `server.rs`/`platform.rs`/`broker.rs` | Hotovo |
| 7 | První reálná aktivní verifikace (Docker lab, nmap+httpx+nuclei) | `src/lab.rs` | Hotovo |
| 8 | Zavření smyčky Observation→Finding→Hypothesis→Planner na reálném nálezu | `src/lab.rs` | Hotovo |
| 9 | Vlna 1 — CTU-13, cross-dataset generalizace + potvrzená fragmentační hypotéza | `src/eval/sources/ctu13.rs` | Hotovo |
| 10 | Ablace D (multi-scale), honest "safety net", ne tvrzené zlepšení | `src/correlation_v2.rs` | Hotovo |
| 11 | Skutečné vykonání vybrané verifikace (ne jen výběr) | `src/lab.rs` | Hotovo |
| 12 | H1 poprvé reálně změřeno (pasivní vs. pasivní+aktivní) | `src/lab.rs` | Hotovo |
| 13 | H3 měření zablokováno potvrzeným strukturním důvodem (ne domněnkou) | `docs/diplomka/eval/h3-measurement-difficulty.md` | Hotovo |
| 14 | Oprava CTU-13 label bugu + triviální baseline + hash fix (nezávislý audit) | `src/eval/ground_truth.rs`, `src/eval/dataset_replay.rs` | Hotovo |

## Vztah k H1–H5

### H1: spojení pasivní a aktivní telemetrie zvýší kvalitu rozhodnutí proti samotné pasivní vrstvě za definovaných nákladů.

**Status: POPRVÉ ZMĚŘENO (Deliverable 12), na jednom lab cíli.** `docs/diplomka/eval/h1-passive-vs-active.md`: na stejných datech ze stejného běhu má "pasivní+aktivní" varianta víc findings (2 vs 1) a víc decision akcí (4 vs 3) než čistě pasivní, s malým, změřeným dodatečným nákladem (1 nuclei sken + 1 GET). Klíčové: nález exponovaného `/metrics` (a jeho 7 konkrétních citlivých metrik, Deliverable 11) **vůbec nevznikne** bez aktivní kontroly — to je strukturní, ne jen statistický rozdíl. **Omezení**: jeden lab cíl, jeden typ zranitelnosti — nedokazuje H1 obecně, dokazuje ji na jednom reprodukovatelném případu. Zobecnění vyžaduje víc lab scénářů.

### H2: temporal/graph evidence fusion s korekcí závislosti zdrojů sníží falešné incidenty oproti prostému scoringu eventů.

**Status: NETESTOVÁNO (opraveno z "částečně vyvráceno" po auditu).** Ablace B/C/D (Deliverable 3, 9, 10) testují jen **okénkování** jedné pasivní heuristiky (`passive::anomaly`), ne temporal/graph fúzi s korekcí závislosti zdrojů, kterou H2 explicitně žádá (návrh sekce 5.1: "stejný tok pozorovaný Suricatou, Zeekem a firewallem nejsou tři nezávislé důkazy"). Dataset má navíc jediný zdroj evidence (jen Zeek/NetFlow), takže "závislost zdrojů" v něm ani nemůže nastat — žádná verze ablace B/C/D proto H2 testovat nemůže, dokud nebude multi-senzorová fúze (Community ID deduplikace mezi Zeek/Suricata) skutečně postavena. Měřeno bylo: naivní temporal windowing na jediném zdroji dat (bez fúze) nesnižuje falešné incidenty (po opravě label bugu: F1 0.306→0.124 na CTU-13 při 300s okně) — to je validní, hodnotný dílčí nález o oknech samotných, ale **neodpovídá H2** ve znění, jaké má. Graph-linking (ablace C) byl implementován jen jako naivní multi-target heuristika bez baseline-awareness a prokazatelně generuje FP na legitimním provozu (NTP fan-out, Deliverable 3).

### H3: typovaná nejistota a VOI-based planner dosáhne stejné či vyšší přesnosti s menším počtem aktivních kontrol oproti pravidelnému plošnému skenu.

**Status: STRUKTURA HOTOVA (Deliverable 4/5/8/11), MĘŘENÍ HYPOTÉZY ZABLOKOVÁNO POTVRZENÝM STRUKTURNÍM DŮVODEM (Deliverable 13).** `docs/diplomka/eval/h3-measurement-difficulty.md`: ověřeno přímo v kódu, že `correlate_events()` v celém eval harnessu (ablace A-D) běží vždy s `hosts: &[]` — proto má `observation` nejistota v tomhle harnessu nulovou variancí (vždy `Confidence::Low`), žádný signál k postavení escalate/ne-escalate rozhodnutí. Juice Shop lab naopak reálný inventář má, ale jen 1 finding — žádná variace k porovnání. **Potvrzený, konkrétní požadavek na další krok**: dataset/lab s párovaným aktivním inventářem A více nálezy současně — žádný dosavadní zdroj tuhle kombinaci nemá.

### H4: verzované učení a kalibrace z ověřených případů zlepší přenositelnost na neviděná data oproti statickým heuristikám.

**Status: NEOVĚŘITELNÉ BEZ CASE MEMORY, které ještě neexistuje.** `hypothesis.rs` vědomě nepočítá `probability`/kalibraci (dokumentováno jako limitace). Deliverable 9 ALE už změřila přesně tu "přenositelnost na neviděná data" část H4 nepřímo — po opravě N1 je obraz jemnější než se původně tvrdilo: **statické heuristiky (ablace A) neztrácejí drtivou většinu F1 při přechodu na jiný dataset** (F1 0.364 na IoT-23 → 0.306 na CTU-13, pokles ~16 %, ne přes 2/3 jak se chybně uvádělo v původní verzi), ale **na obou datasetech zůstávají pod triviálním baseline "vše=malicious"** (0.462 na IoT-23, 0.965 na CTU-13 — viz `docs/diplomka/eval/cross-dataset-ctu13.md`). To je přesnější a náročnější baseline, proti kterému by budoucí kalibrace/Case Memory musela prokázat zlepšení, aby H4 potvrdila: nejde jen o "neztratit F1 při přechodu na jiný dataset", ale především o "překonat nejhloupější možný klasifikátor na obou datasetech".

### H5: rozdělení workerů a stavu umožní s přidáním hardwaru zvýšit propustnost bez disproporčního růstu latence.

**Status: ZCELA NEOVĚŘENO.** Žádný z deliverables 1–10 se netýkal distribuovaného zpracování/škálování workerů — to vyžaduje infrastrukturu (vícero uzlů/workerů), která ještě nebyla postavena. Broker oprava (Deliverable 6) je nutná předpodmínka (bez spolehlivého crash recovery by škálování na víc workerů jen zvýšilo počet ztracených jobů), ale sama o sobě H5 neměří.

## Co z tohoto plyne pro další postup

**H1, H2 a H4 mají teď reálná, měřená čísla** (H1 na jednom lab cíli, H2/H4 na cross-dataset ablacích) — včetně honest negativních/částečných výsledků, ne jen implementovanou strukturu. **H3 je strukturně zablokovaná potvrzeným důvodem** (žádný dosavadní zdroj nemá současně aktivní inventář i více nálezů) — další krok musí buď přidat druhý/třetí lab cíl s odlišnými nálezy, nebo najít/postavit dataset s párovaným active+passive snímkem, než bude mít smysl cokoliv měřit. **H5 je zatím zcela netknutá** a vyžaduje distribuovanou infrastrukturu, kterou projekt ještě nemá.
