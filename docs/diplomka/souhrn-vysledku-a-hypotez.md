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

## Vztah k H1–H5

### H1: spojení pasivní a aktivní telemetrie zvýší kvalitu rozhodnutí proti samotné pasivní vrstvě za definovaných nákladů.

**Status: NEOVĚŘENO.** Deliverable 7/8 ukázaly, že aktivní verifikace (nmap+httpx+nuclei) funguje end-to-end a najde reálné věci (prometheus-metrics-exposed na Juice Shopu), ale **nebylo změřeno srovnání** "jen pasivní rozhodnutí" vs. "pasivní+aktivní rozhodnutí" na stejném cíli s definovanou cenou. To je přesně další krok: vzít hypotézu z pasivního nálezu, spočítat VOI pro aktivní kontrolu (Deliverable 5 to umí), skutečně ji provést (Deliverable 7/8 to umí), a změřit rozdíl v kvalitě rozhodnutí před/po. Infrastruktura na to existuje, měření H1 samo ještě ne.

### H2: temporal/graph evidence fusion s korekcí závislosti zdrojů sníží falešné incidenty oproti prostému scoringu eventů.

**Status: ČÁSTEČNĚ VYVRÁCENO naivní implementací, a to je důležitý výsledek.** Ablace B/C/D (Deliverable 3, 9, 10) jsou přímý test téhle hypotézy — a naivní temporal windowing (bez korekce závislosti zdrojů, bez adaptace na typ signálu) **nesnížilo** falešné incidenty, na CTU-13 je dokonce zhoršilo (F1 0.115→0.057 při 300s okně). Teprve multi-scale union (D) vrátil výkon na úroveň A, ne nad ní. **To neznamená, že H2 je vyvrácená obecně** — znamená to, že "temporal fusion" bez korekce závislosti zdrojů (přesně to, co H2 explicitně požaduje a co ještě nebylo implementováno — `graph` část H2, propojení přes assety/služby/uživatele, ne jen okénkování jedné metriky) je nedostatečné. Graph-linking (ablace C) byl implementován jen jako naivní multi-target heuristika bez baseline-awareness a prokazatelně generuje FP na legitimním provozu (NTP fan-out, Deliverable 3). **Korektní test H2 vyžaduje dokončit "korekci závislosti zdrojů"**, která v návrhu (sekce 5.1: "stejný tok pozorovaný Suricatou, Zeekem a firewallem nejsou tři nezávislé důkazy") ještě nebyla postavena.

### H3: typovaná nejistota a VOI-based planner dosáhne stejné či vyšší přesnosti s menším počtem aktivních kontrol oproti pravidelnému plošnému skenu.

**Status: STRUKTURA HOTOVA (Deliverable 4/5/8), MĘŘENÍ HYPOTÉZY NEPROVEDENO.** `plan_verification()` korektně vybírá nejlevnější/nejinformativnější kandidáta na reálném nálezu (Deliverable 8) — ale žádné srovnání "VOI-řízený výběr" vs. "plošný sken všeho" ještě neproběhlo. Tohle je přímo následující krok: vzít CTU-13/IoT-23 nálezy, definovat sadu možných aktivních kontrol pro každý, srovnat VOI-planner výběr vs. "sken všeho" podle počtu provedených kontrol a výsledné přesnosti.

### H4: verzované učení a kalibrace z ověřených případů zlepší přenositelnost na neviděná data oproti statickým heuristikám.

**Status: NEOVĚŘITELNÉ BEZ CASE MEMORY, které ještě neexistuje.** `hypothesis.rs` vědomě nepočítá `probability`/kalibraci (dokumentováno jako limitace). Deliverable 9 ALE už změřila přesně tu "přenositelnost na neviděná data" část H4 nepřímo — **statické heuristiky (ablace A) ztratily přes 2/3 F1 skóre při přechodu na jiný dataset** (0.364→0.115). To je přesný baseline, proti kterému by budoucí kalibrace/Case Memory musela prokázat zlepšení, aby H4 potvrdila.

### H5: rozdělení workerů a stavu umožní s přidáním hardwaru zvýšit propustnost bez disproporčního růstu latence.

**Status: ZCELA NEOVĚŘENO.** Žádný z deliverables 1–10 se netýkal distribuovaného zpracování/škálování workerů — to vyžaduje infrastrukturu (vícero uzlů/workerů), která ještě nebyla postavena. Broker oprava (Deliverable 6) je nutná předpodmínka (bez spolehlivého crash recovery by škálování na víc workerů jen zvýšilo počet ztracených jobů), ale sama o sobě H5 neměří.

## Co z tohoto plyne pro další postup

**Nejsilněji podložená, nejcennější část dosavadní práce je k H2 a H4** — oba mají reálná, měřená, explicitně honest čísla (včetně negativních/částečných výsledků), ne jen implementovanou strukturu. **H1 a H3 mají hotovou infrastrukturu, ale chybí jim samotné srovnávací měření** — to je nejbližší smysluplný další krok, protože nevyžaduje novou infrastrukturu, jen propojení už existujících kusů (lab + planner + baseline srovnání). **H5 je zatím zcela netknutá** a vyžaduje distribuovanou infrastrukturu, kterou projekt ještě nemá.
