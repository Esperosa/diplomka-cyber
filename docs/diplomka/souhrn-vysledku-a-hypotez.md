# Souhrn výsledků (Deliverables 1–10) a vztah k výzkumným hypotézám H1–H5

**Status: konsolidace k 29. 10. 2026.** Návrhový dokument (sekce 11) definuje 5 výzkumných hypotéz pro diplomku. Tento dokument mapuje, co z deseti dosavadních deliverables tyto hypotézy skutečně testuje, co potvrzuje, co vyvrací, a co ještě čeká na ověření — **honestně**, včetně částečně negativních výsledků, ne jako seznam úspěchů.

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

## Vztah k H1–H5

### H1: spojení pasivní a aktivní telemetrie zvýší kvalitu rozhodnutí proti samotné pasivní vrstvě za definovaných nákladů.

**Status: POPRVÉ ZMĚŘENO (Deliverable 12), na jednom lab cíli.** `docs/diplomka/eval/h1-passive-vs-active.md`: na stejných datech ze stejného běhu má "pasivní+aktivní" varianta víc findings (2 vs 1) a víc decision akcí (4 vs 3) než čistě pasivní, s malým, změřeným dodatečným nákladem (1 nuclei sken + 1 GET). Klíčové: nález exponovaného `/metrics` (a jeho 7 konkrétních citlivých metrik, Deliverable 11) **vůbec nevznikne** bez aktivní kontroly — to je strukturní, ne jen statistický rozdíl. **Omezení**: jeden lab cíl, jeden typ zranitelnosti — nedokazuje H1 obecně, dokazuje ji na jednom reprodukovatelném případu. Zobecnění vyžaduje víc lab scénářů.

### H2: temporal/graph evidence fusion s korekcí závislosti zdrojů sníží falešné incidenty oproti prostému scoringu eventů.

**Status: ČÁSTEČNĚ VYVRÁCENO naivní implementací, a to je důležitý výsledek.** Ablace B/C/D (Deliverable 3, 9, 10) jsou přímý test téhle hypotézy — a naivní temporal windowing (bez korekce závislosti zdrojů, bez adaptace na typ signálu) **nesnížilo** falešné incidenty, na CTU-13 je dokonce zhoršilo (F1 0.115→0.057 při 300s okně). Teprve multi-scale union (D) vrátil výkon na úroveň A, ne nad ní. **To neznamená, že H2 je vyvrácená obecně** — znamená to, že "temporal fusion" bez korekce závislosti zdrojů (přesně to, co H2 explicitně požaduje a co ještě nebylo implementováno — `graph` část H2, propojení přes assety/služby/uživatele, ne jen okénkování jedné metriky) je nedostatečné. Graph-linking (ablace C) byl implementován jen jako naivní multi-target heuristika bez baseline-awareness a prokazatelně generuje FP na legitimním provozu (NTP fan-out, Deliverable 3). **Korektní test H2 vyžaduje dokončit "korekci závislosti zdrojů"**, která v návrhu (sekce 5.1: "stejný tok pozorovaný Suricatou, Zeekem a firewallem nejsou tři nezávislé důkazy") ještě nebyla postavena.

### H3: typovaná nejistota a VOI-based planner dosáhne stejné či vyšší přesnosti s menším počtem aktivních kontrol oproti pravidelnému plošnému skenu.

**Status: STRUKTURA HOTOVA (Deliverable 4/5/8/11), MĘŘENÍ HYPOTÉZY ZABLOKOVÁNO POTVRZENÝM STRUKTURNÍM DŮVODEM (Deliverable 13).** `docs/diplomka/eval/h3-measurement-difficulty.md`: ověřeno přímo v kódu, že `correlate_events()` v celém eval harnessu (ablace A-D) běží vždy s `hosts: &[]` — proto má `observation` nejistota v tomhle harnessu nulovou variancí (vždy `Confidence::Low`), žádný signál k postavení escalate/ne-escalate rozhodnutí. Juice Shop lab naopak reálný inventář má, ale jen 1 finding — žádná variace k porovnání. **Potvrzený, konkrétní požadavek na další krok**: dataset/lab s párovaným aktivním inventářem A více nálezy současně — žádný dosavadní zdroj tuhle kombinaci nemá.

### H4: verzované učení a kalibrace z ověřených případů zlepší přenositelnost na neviděná data oproti statickým heuristikám.

**Status: NEOVĚŘITELNÉ BEZ CASE MEMORY, které ještě neexistuje.** `hypothesis.rs` vědomě nepočítá `probability`/kalibraci (dokumentováno jako limitace). Deliverable 9 ALE už změřila přesně tu "přenositelnost na neviděná data" část H4 nepřímo — **statické heuristiky (ablace A) ztratily přes 2/3 F1 skóre při přechodu na jiný dataset** (0.364→0.115). To je přesný baseline, proti kterému by budoucí kalibrace/Case Memory musela prokázat zlepšení, aby H4 potvrdila.

### H5: rozdělení workerů a stavu umožní s přidáním hardwaru zvýšit propustnost bez disproporčního růstu latence.

**Status: ZCELA NEOVĚŘENO.** Žádný z deliverables 1–10 se netýkal distribuovaného zpracování/škálování workerů — to vyžaduje infrastrukturu (vícero uzlů/workerů), která ještě nebyla postavena. Broker oprava (Deliverable 6) je nutná předpodmínka (bez spolehlivého crash recovery by škálování na víc workerů jen zvýšilo počet ztracených jobů), ale sama o sobě H5 neměří.

## Co z tohoto plyne pro další postup

**H1, H2 a H4 mají teď reálná, měřená čísla** (H1 na jednom lab cíli, H2/H4 na cross-dataset ablacích) — včetně honest negativních/částečných výsledků, ne jen implementovanou strukturu. **H3 je strukturně zablokovaná potvrzeným důvodem** (žádný dosavadní zdroj nemá současně aktivní inventář i více nálezů) — další krok musí buď přidat druhý/třetí lab cíl s odlišnými nálezy, nebo najít/postavit dataset s párovaným active+passive snímkem, než bude mít smysl cokoliv měřit. **H5 je zatím zcela netknutá** a vyžaduje distribuovanou infrastrukturu, kterou projekt ještě nemá.
