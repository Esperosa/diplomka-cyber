# Produkční plán (ne jen diplomka) — syntéza 3-agentního kola (29. 10. 2026)

**Důvod vzniku tohoto dokumentu:** uživatel explicitně odmítl rámec "jen diplomka" pro rozhodnutí o H5/H2/firewall/DNS/IPS — "produkční program by to měl umět", H5 "nesmí být vyřazeno", H2 "netestováno... je také velký problém". Tohle není routinní inženýrské rozhodnutí (kde rozhoduju autonomně) — je to skutečná změna rámce pro celý projekt, proto prošlo stejnou 3-agentní metodikou (Opus comprehensive + pragmatik + skeptik) jako předchozí master plán, teď s explicitním zadáním "neber to jako diplomku, ber to jako produkční program".

## Co se všichni 3 agenti shodli (vysoká důvěra)

**H2 a H5 jsou jiná kategorie než firewall/DNS/IPS** — jsou to vlastnosti JÁDRA, které už existuje (správnost fúze evidence, správnost škálování workerů), ne nové, nabalené subsystémy. Design dokument sám (sekce 10) řadí "source-aware evidence fusion" a distribuovaný broker do P0/P1, ne P2/P3 — firewall/DNS/IPS jsou tam explicitně P2. Skeptik nezávisle došel ke stejnému závěru jako pragmatik a Opus: **re-scoping H2 a H5 zpět do rozsahu je obhajitelný na vlastních termínech návrhového dokumentu, ne jen na emoční reakci.**

### H2 — ověřeno přímo v kódu, ne jen odhadnuto

- `src/passive/zeek.rs` a `src/passive/suricata.rs` už extrahují 5-tuple/timestamp data, co Community ID hash potřebuje — **join-key funkce je otázka dní, ne týdnů**.
- `src/correlation_v2.rs` dnes vůbec neví o Suricatě (grep na `community_id|flow_id|suricata` = 0 výsledků) — žádná cross-senzorová fúze neexistuje v žádné formě.
- Skutečná H2 claim (korekce závislosti, ne jen deduplikace) vyžaduje novou fúzní vrstvu s váhováním částečně závislé evidence — **to je nový analytický design, 1-2 týdny, ne parser patch**.
- **IoT-23/CTU-13 jsou single-sensor, takže plně statisticky H2 nemůžou testovat** — ale strukturální test ANO, pomocí existujícího multiservice labu (Deliverable 15/16/21): přidat Suricata sidecar vedle už fungujícího tcpdump+Zeek capture (Deliverable 21), žádný nový dataset potřeba.

### H5 — "docela dost blízko" je optimistické, ale ne bezdůvodné

- `src/broker.rs` (XREADGROUP/XAUTOCLAIM/XACK) je skutečně solidní, testovaná distribuovaná korektnost — **to je ten "blízko" kus, co uživatel vnímá správně**.
- ALE: `src/platform.rs` state store je SQLite na jednom souboru — **žádný druhý uzel nemůže bezpečně sdílet stav přes síť**. To je skutečný blokátor, ne ceremonie.
- Žádný test ani kód nezaručuje unikátní `consumer` jméno mezi víc procesy; atomicita claim-query v `platform.rs` není ověřená pod konkurencí; žádný skutečný test se 2 reálnými worker procesy neexistuje.
- `mark_job_succeeded`/`mark_job_failed` nemají `WHERE claimed_by = ?` fencing — stale worker může přepsat výsledek. Lease reclaim hardcoded na 30s, ne navázaný na `job_lease_s`. Žádný DLQ.

## Kde se agenti NESHODLI — potřebuje rozhodnutí uživatele, ne mé

**Firewall/DNS/IPS/multi-tenant/HA-DR**: Opus a pragmatik navrhli konkrétní MVP sekvence (SOAR→firewall TTL-sets→DNS RPZ→IPS), protože "produkce to teď chce". Skeptik nezávisle nesouhlasí: design dokument sám tohle řadí do P2/P3, nulová produkční instalace/zákazník existuje, a "re-opening těchto rozhodnutí dny po jejich uzavření bez nového faktického zjištění je žlutá vlajka pro emoční/completionistické přehodnocení, ne nový fakt". Skeptik to řadí jako "nejvyšší riziko scope creepu ze všech osmi položek... nejpravděpodobněji tlačené z completionistických důvodů ('porazit Fortinet'), ne z potřeby korelační platformy".

**Multi-tenant/HA-DR**: všichni 3 souhlasí, že spouštěcí podmínka je konkrétní (2. placený zákazník / enforcement vrstva live v produkci), ne kalendářní — tohle zůstává odloženo bez kontroverze.

**Supply-chain**: levné, bez rizika scope creepu, všichni doporučují udělat brzy (SBOM, pinned deps, signed artifacts) bez ohledu na zbytek debaty.

## Rozhodnutí

1. **H2 se vrací do rozsahu** — stavím Community ID join-key + dependency-aware fúzi, bounded (dny až 2 týdny), reuse existujícího multiservice labu.
2. **H5 se vrací do rozsahu, ale right-sized** — nejdřív uzavřu reálné korektnostní mezery (claimed_by fencing, lease navázaný na config, DLQ, connection pooling) a postavím test se 2 REÁLNÝMI worker procesy proti jednomu Redis+DB (levné, honestní, dny) — PŘED skokem na Postgres migraci a multi-host test (to je skutečný příští blokátor, větší investice, další fáze).
3. **Firewall/DNS/IPS/SOAR zůstávají odloženy (rozhodnutí uživatele, 29.10.2026, po předložení obou stran argumentace).** Skeptikova pozice potvrzena: zůstává P2/P3 jako v návrhu, dokud nebude reálné nasazení/zákazník. Žádná implementace tady nezačíná — jen H2/H5.
4. **Multi-tenant/HA-DR** — odloženo, trigger-based (2. zákazník / enforcement live), bez kontroverze mezi agenty.
5. **Supply-chain** — levné, bez kontroverze, zařazeno do plánu jako nízko-prioritní ale snadný krok, ne aktuálně prováděno.

## Fázovaný plán (syntéza, Fáze 0 = jádro, hotovo)

- **Fáze 1 (týdny, začíná hned)**: H5 korektnostní opravy + 2-proces test (`src/platform.rs`, `src/broker.rs`); H2 Community ID + fúzní vrstva (`src/passive/community_id.rs`, nový `src/fusion.rs`) + Suricata sidecar v multiservice labu.
- **Fáze 2 (po Fázi 1, větší investice)**: Postgres migrace pro skutečný multi-host H5; re-validace ablací B/C/E s H2 fúzí na dual-sensor datech.
- **Fáze 3 (odloženo, rozhodnuto 29.10.2026)**: firewall/DNS/IPS/SOAR zůstává P2/P3 podle skeptika a návrhu samotného — uživatel potvrdil tuhle volbu po předložení obou stran. MVP sekvence od Opus/pragmatika (SOAR→firewall TTL-sety→DNS RPZ→IPS) zůstává zapsaná výše pro budoucí referenci, až bude reálné nasazení/zákazník.
- **Fáze 4 (trigger-based, ne kalendářní)**: multi-tenant (2. zákazník), HA/DR (enforcement live v produkci), supply-chain hardening (první procurement security review).

## Dodatek (29.10.2026): zapojení ověřeného jádra do produkční cesty + "framework style"

**Impuls**: uživatel se zeptal, jestli je "core hotový a framework style, snadno rozšiřitelný". Ověřeno přímo v kódu (ne odhadem): produkční pipeline (`run_pipeline` v `main.rs`) stále běží na pre-diplomkové logice. `correlation_v2.rs`/`fusion.rs`/`hypothesis.rs`/`verification_planner.rs`/`identity.rs` jsou vědecky ověřené, ale volané jen z `eval/`/`lab.rs`, ne z produkční cesty. Architektonicky existuje jediný skutečný runtime extension point v celém crate (`vuln::VulnerabilityProvider`) — nový typ detekce dnes zasahuje až 10 souborů, nový senzor až 8.

**3-agentní kolo (Opus comprehensive + pragmatik + skeptik)** nezávisle ověřilo kód a došlo k těmto závěrům:

1. **`correlation_v2` NENÍ náhrada `correlate_events`** — je to alternativa k `passive::anomaly::detect_connection_anomalies` (jiný vstup/výstup). Přepnutí produkční cesty na B/C/D jako VÝCHOZÍ chování by bylo podle vlastních naměřených čísel diplomky **zhoršení** (ablace B: F1 0,306→0,124; C dává FP na NTP fan-outu; D jen "safety net" bez zlepšení přesnosti) a rozbilo by `tests/mas_deep.rs` (v2 vynechává z-score detektor, test ho vyžaduje).
2. **Skeptik**: dnešní (tehdy) schválený plán výše o workspace splitu/pluginové architektuře vůbec nemluví — je to nová škála práce. Bezpečné a bez rizika regrese je zapojit **stínově/aditivně** (nová pole v `RunReport`, žádná změna výchozího rozhodování), ne nahradit výchozí cestu.
3. **Pragmatik**: nejlevnější skutečný plug-point pro detektory je `passive::load_and_normalize` (ne main.rs), přes malý trait `EventDetector` ve stylu už existujícího `eval::source::ScenarioSource`. `hypothesis`/hodnoty jdou nejlevněji jako nové pole na `RunReport` (konstruuje se na 1 místě), ne na `Finding` (25+ konstrukčních míst).

**Rozhodnutí**: pokračovat podle Opusova fázovaného plánu, začít Fází 0 (bezpečnostní síť), další fáze jen aditivně/za přepínači, výchozí produkční chování se mění JEN tam, kde je to změřeně lepší (dnes nikde kromě zdroj-centrického skóre z Deliverable 28, které ještě nemá funkční rozhodovací mechanismus — Deliverable 29/30).

### Fáze 0 (bezpečnostní síť pro refaktor): HOTOVO (29. 10. 2026)

`tests/golden_snapshot.rs` — golden-snapshot regresní test nad `full_visibility_stack_populates_lanes_and_findings` fixturami (plně deterministický vstup, `data/*.json` + `simulace generuj --seed 7`). Normalizuje volatilní pole (run_id i jako substring, ISO8601 časová razítka, unixová razítka v `event_id`, a — honestně odhalený zdroj nedeterminismu — skutečně naměřené `mas_*`/`runtime_ms`/`parallelism_ratio` hodnoty z reálného `thread::scope` běhu) a porovná zbytek proti committed `tests/golden/full_visibility_stack.json`. Ověřeno: stabilní přes 3 opakované běhy beze změny; negativní kontrola (dočasná změna `--nazev`) test spolehlivě shodí. Test NENÍ `#[ignore]` (potřebuje jen binárku + commitnuté fixtury, žádný Docker/nmap/httpx/nuclei) — běží normálně v CI. Aktualizace po vědomé změně: `BAKULA_UPDATE_GOLDEN=1 cargo test --test golden_snapshot`.

Další fáze (1–6, dle Opusova plánu: pipeline do lib beze změny chování → `ConnectionDetector`/`FindingKindSpec` traity se stejným chováním → stínové aditivní zapojení hypotéz/identity/plannneru/community_id → přepínače s výchozím "staré chování" → změna výchozího chování jen na základě měření → volitelný workspace split) jsou navazující, samostatné kroky.

**Dodatek (29.10.2026): nezávislá kontrola Fáze 0 (2 levné modely).** Poslány 2 nezávislé review (haiku + fable) na `tests/golden_snapshot.rs` předtím, než se na něm začalo stavět dál. Oba nezávisle našly stejné 3 reálné problémy (shoda zvyšuje důvěru v nález, ne jen jednoho modelu domněnka): (1) `core.autocrlf=true` bez `.gitattributes` — čerstvý Windows checkout by commitnutý LF golden soubor převedl na CRLF a test by spadl i beze skutečné změny chování; (2) panic zprávy pořád radily `-- --ignored` po dřívější opravě `#[ignore]` atributu — ten příkaz by spustil 0 testů a tiše by neaktualizoval golden soubor; (3) `summary.mas_queue_wait_ms_avg`/`mas_agent_sla_ratio` jsou stejná třída skutečně naměřeného cas-steny-hodiny jako `mas_parallelism_ratio`, ale chyběly v seznamu volatilních polí. Všechny 3 opraveny a ověřeny (simulace reálné CRLF konverze, opakovaná stabilita, negativní kontrola stále funguje). Bezpečnostní síť je teď prokazatelně solidnější, ne jen "funguje na mém stroji".

### Fáze 1 (pipeline do lib beze změny chování): HOTOVO (29. 10. 2026)

- `Workspace::save_run` (21 pozičních parametrů → `RunArtifacts` struct, `src/storage.rs`), `report::build_source_metadata` (21 pozičních parametrů → `SourceInputs` struct, `src/report.rs`) — mechanické, beze změny chování.
- `run_pipeline` + `BehArgs` + celý privátní pomocný cluster (validace, latency-hint odhady, MAS plánování, ~1420 řádků) přesunuty z `main.rs` do nového `src/pipeline/mod.rs` v knihovně. `main.rs` kleslo z 3195 na 1782 řádků. Veřejné (nutně `pub`, ne `pub(crate)` — `main.rs` je samostatný bin crate) je jen těch 6 symbolů, které `main.rs` volá zvenčí (`BehArgs`, `run_pipeline`, `promote_monitor_args`, `promote_autopilot_args`, `validate_monitor_args`, `resolve_simulation_profile`); zbytek zůstal privátní modulu. Vnitřní volání beze změny (stejná nekvalifikovaná jména, teď řešená přes upravený `use` import), takže samotná logika se needitovala ručně — nižší riziko transkripční chyby.
- Odchýleno od původního Opusova návrhu `impl From<BehArgs> for PipelineConfig` — `BehArgs`ovy `clap` atributy jsou jen kompilační, nebrání použití jako běžný struct odjinud; duplikovat ~55 polí do paralelní struktury jen kvůli odstínění od clapu nestálo za extra riziko transkripce. Zapsáno jako vědomá odchylka, ne přehlédnutí.
- Sjednocen trojí doslovně opsaný přepočet `monitoring_lanes_total`/`live_lanes_total`/`audit_lanes_total` (po MAS scheduler lane, po validation bundle, po automation insights) do jedné `resort_and_recompute_lane_summary` funkce, volané na stejných 3 místech.
- **Vědomě NEdotčeno**: druhé duplicitní zapisování (`mas_parallelism_ratio`/`mas_queue_wait_ms_avg`/`mas_agent_sla_ratio` se nastaví z lokálních MAS metrik, pak o pár set řádků dál přepíše hodnotami z `automation_insights`) — tohle jsou dva RŮZNÉ vzorce, ne doslovně stejný kód, takže sloučení je skutečná otázka chování, ne čistý dedup, a potřebuje vlastní ověřovací krok.
- Ověřeno: byte-identický golden snapshot po každém kroku, plná `lib`/`e2e`/`mas_deep` sada zelená (stejná dávno potvrzená nesouvisející selhání jako vždy), clippy čisté na dotčených souborech.

### Fáze 2 (traity se stejným chováním): PROBÍHÁ (29. 10. 2026)

- **Hotovo — `ConnectionDetector` trait** (`src/passive/detector.rs`): sjednocuje ablace A/B/C/D (`passive::anomaly::detect_connection_anomalies`, `correlation_v2::detect_windowed_anomalies[_linked]`, `correlation_v2::detect_multiscale_windowed_anomalies`) za jeden trait — `LegacyAnomalyDetector`/`WindowedDetector`/`LinkedDetector`/`MultiscaleDetector`. **Zavřelo konkrétní mezeru, co Opusova analýza našla**: `passive::load_and_normalize` (produkce) a `eval::dataset_replay::run_ablation` (eval) dřív volaly tytéž 4 funkce DVĚMA nezávislými cestami — eval tedy nikdy přímo neměřil to, co by produkce spustila s jinak zvolenou ablací. Teď obě cesty jdou přes stejné trait objekty. `load_and_normalize` bere `&dyn ConnectionDetector` parametr; jediné produkční volací místo (`pipeline::run_pipeline`) posílá explicitně `&LegacyAnomalyDetector` — výchozí produkční chování (ablace A) se nemění. Ověřeno: nový test potvrzuje bajtovou shodu `LegacyAnomalyDetector` s přímým voláním, golden snapshot beze změny, všech 8 reálných CTU-13 eval regresních testů reprodukuje přesně stejná čísla jako dřív zapsaná v `souhrn-vysledku-a-hypotez.md`.
- **Hotovo — sdílené prahy** (`src/passive/thresholds.rs`): `2500 pps`/`35 Mbps` byly nezávisle opsané jako magické konstanty v `anomaly.rs`, `correlation_v2.rs` a `lanes.rs` — teď na jednom místě, hodnoty beze změny.
- **Zbývá**: `FindingKindSpec` s kategorií + registr (dnes nový `event_type` zasahuje až 10 souborů — `decision.rs`, `triage.rs`, `validation.rs`, `automation.rs`, `intel.rs`), rozdělení `generate_findings` (630 řádků) na `FindingRule` postupně, volitelně `ObservationSource` pro vendory v `context.rs`/`lanes.rs` (dnes nový senzor zasahuje až 8 souborů).
