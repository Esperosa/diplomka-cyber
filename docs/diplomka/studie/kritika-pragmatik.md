# Kritika pragmatika: 00-zaver-jak-vylepsit-core.md (v1.0)

Úhel: realizovatelnost a praktická užitečnost pro správce malé až střední sítě, omezené zdroje (jeden vývojář, jeden stroj, na kterém běží `bakula-soak-*`). Čtu studii celou a audit 01 jen tam, kam studie odkazuje. Závažnost 0 až 4 (4 = zablokuje nebo zcela znehodnotí plán). Nic jsem nespouštěl ani neměnil.

## 0. Ověření odkazů v kódu (osm klíčových plus dva doplňkové)

| odkaz ve studii | výsledek |
|---|---|
| `passive/anomaly.rs:249` práh `max_pps >= 2_800 \|\| max_bps >= 40_000_000` | sedí, maximum přes toky v agregátu |
| `passive/zeek.rs:173-175` filtr `in_scope(scope, &dst_ip)` | sedí, jen cíl |
| `passive/suricata.rs:69-70` totéž | sedí |
| `passive/suricata.rs:111-124` `classify_signature` | sedí (klíčová slova, větev `dst_port == Some(80)` na `insecure_auth_possible`, jinak `suricata_alert`) |
| `findings.rs:28` `SERVICE_RULES` bez pravidla pro `suricata_alert` | sedí, v `findings.rs` ani `finding_kinds.rs` se `suricata_alert` nevyskytuje |
| `verification_planner.rs:53-62` `utility` | sedí, `info_gain * impact - náklady`, bez aktuální pravděpodobnosti |
| `verification_exec.rs:38-46`, `:79` | sedí (10 kontrol na běh, 2 na cíl; `passive_extended_observation` vrací jen text) |
| `findings.rs:815-826` `build_finding_id` | sedí. ID je bez času, tedy stabilní. Problém není ID, ale to, že za ním není perzistentní stav (viz nález P4) |
| `hypothesis.rs:156` `contradicting_evidence: Vec::new()` | sedí |
| `eval/dataset_replay.rs:137` `known_services = HashSet::new()` | sedí |
| `passive/anomaly.rs:482-496` `is_timeout_like` počítá `r`/`t` v `history` | sedí |

Odchylka: studie píše, že `score_source_hosts` je „dnes jen v `src/eval`“. Funkce je definovaná v `passive/anomaly.rs:110` jako `pub(crate)` a používá ji jen `eval/`. Zprovoznění jako produkční detektor je tedy levnější, než studie naznačuje (hodiny až 1 den na zapojení, ne „L“ na převod). Samotný detektor i jeho prahy ale levné nejsou.

Neověřeno (mimo rozpočet): řádky v `soak/*` (episode.rs 700-760, traffic.rs 1194-1216), `case_memory.rs:209-232` (struktura `estimate` vypadá jako popisovaná), `correlation_v2.rs:269`. Kód v `src/` je jinak v souladu s tím, co studie tvrdí; to je silná stránka dokumentu.

## 1. Pořadí 12 doporučení: efekt vs. náročnost vs. závislosti

Hlavní zjištění: pořadí je seřazené podle **metodické čistoty** (P1 až P4), ne podle poměru efekt/cena. Pro cíl „méně šumu“ je to obráceně: 97 % šumu v [v1] tvoří `inductive_volume_anomaly` (75 %) a `packet_rate_spike` (22 %), a oba zdroje jsou opravitelné v řádu dnů v enginu. Kdo začne R1 (harness, M až L), zaplatí první dva týdny za měření a engine zůstane stejně hlučný.

| # | nález | místo | závažnost | návrh |
|---|---|---|---|---|
| P1 | R1 je příliš velký a blokuje vše. Brána G0 má 11 bodů (§7.1), včetně změn generátoru (S1, S2, S3), clusterového bootstrapu, kontrafaktuálu `mask_truth`, kotvy s inventářem a opravy úniku haldy. Odhad „M“ je podhodnocený, realisticky 1,5 až 3 týdny. Každá další R má závislost „R1“. | §5.g, §5.x, §7.1 | 4 | Rozdělit G0 na **G0-min** (dny: absolutní FP/síť-den, `S_quiet`, hash/dirty ve status, `noop_share`, sdílené seedy A/B) a **G0-plné** (S1 až S3, placebo, kontrafaktuál, bootstrap), které se dělá paralelně s enginovými změnami a platí až pro potvrzovací E5. Snížení šumu se dá měřit na surových počtech nálezů za síť-den bez opravené atribuce, protože atribuce ovlivňuje „detekováno“, ne počet nálezů. |
| P2 | R5 (robustní packet rate, S) je v pořadí až pátá a závisí na „R1“. Přitom je to nejlevnější změna s největším doloženým zdrojem šumu (22 % v [v1], 10,6 % v [v2b]) a mechanismus je v kódu ověřený (maximum přes toky, práh 2 800 pps, `anomaly.rs:249`). | §5.a R5 | 3 | Dát na první místo, závislost na R1 škrtnout (stačí G0-min). |
| P3 | `inductive_volume_anomaly` je největší zdroj (75 % v [v1], 37,7 % v [v2b]) a řeší ho R7 (L, závislost na R4 a R8). Studie to sama dokládá sklonem ≈ 1,0. Plný `baseline.rs` s tvarem role a peer group je na dva týdny nereálný. | R7, D2 | 4 | Vytáhnout „R7-lite“: minimální počet toků a pozorování na klíč, robustní medián/MAD přes historii klíče místo průřezového z-skóre bez paměti (`anomaly.rs:334-398`), gating při otevřeném nálezu. Sezónní tvar role, shrinkage a peer group odložit. 3 až 5 dnů. |
| P4 | R4 je „M“, ale ve skutečnosti zahrnuje perzistentní stav (nový `finding_state.rs`), migraci uložených nálezů a Case Memory, změnu `Finding`, agregaci `unmapped`, změnu UI a nový model „incident“. To je spíš 1,5 až 2 týdny. Navíc `build_finding_id` je už stabilní, takže jádro „opakovaně vydávané stejné nálezy“ je v pipeline (znovuvydání každý cyklus), ne v ID. | §5.a R4, `findings.rs:815-826` | 3 | Dvě etapy: (a) **R4-lite**: `first_seen/last_seen/occurrences` a znovuvydání jen při změně stadia nebo Δp ≥ 0,1 nebo po klidu, bez „incidentů“; (b) agregace do incidentů až později. První výskyt vždy zobrazit (studie to správně chce). |
| P5 | R2 (scope `src ∈ S ∨ dst ∈ S`) je „S“ v kódu (tři místa, ověřeno), ale není to snížení šumu, nýbrž nárůst: studie sama říká, že přibudou FP z `retry_storm` a `software_update`, a bez S1 v generátoru je zisk artefakt. | §5.d R2 | 3 | Nezařazovat do 14denního jádra. Je to rozšíření detekce, patří za R5/R4-lite/R3. Při zavedení omezit kardinalitu (viz bezpečnostní nález B2). |
| P6 | R3 (Suricata mapování, S) je správně malé a správně v P1. Přínos je ale kvalitativní (typ nálezu pro správce), ne snížení počtu nálezů; navíc „strop 40,7 %“ je daný IDS viditelností. | §5.d R3 | 2 | Nechat, přidat do jádra jako „srozumitelnost“: správce dnes vidí `suricata_alert` jako nepojmenovaný `unmapped`. Dělat spolu s R4-lite (agregace unmapped). |
| P7 | R9 (RBA řazení a rozpočet alertů): důkaz nízký, očekávaný efekt AUROC 0,75 vs 0,72 (malý), jedno preprintové zdroj, studie sama píše rozpor kontrolora a revizora v Tab. 4. | §5.e R9 | 2 | Škrtnout z core plánu. Nahradit dvěma řádky kódu: řazení podle (závažnost, počet výskytů, počet distinktních typů na hostu) a pevný denní limit „zobrazených nových“ s počítadlem potlačených. To je zároveň RBA-light bez nutnosti předregistrovat H17/H18. |
| P8 | R8 (identita, M až L): reálný problém (32,8 % falešných rozdělení v [v2b]), ale 190 sítí z generátoru, kde identita je syntetická, nic neříká o MAC randomizaci a DHCP. Efekt bez podkladu. | §5.d R8 | 2 | Do 14 dnů ne. Přesunout na „po R7-lite“, a nejdřív změřit, kolik z `inductive`/`unexpected_traffic` FP vzniká kvůli identitě (jedna diagnostická tabulka). |
| P9 | R6 kontextová brána: nejužitečnější pro správce (údržbová okna, restart sensoru), ale velká (nový modul, kalendář s TTL a schvalováním, UI pro kalendář) a spojuje pět různých věcí s různou jistotou. | §5.a R6 | 2 | Rozdělit: **R6a** (S, 2 dny) `service_unavailable` místo `connection_timeout_burst` (A07) a zdraví sensoru jako snížení váhy; **R6b** kalendář a schvalování (M, odložit). Vždy `Discount` se zobrazitelným důvodem, nikdy mazání. |
| P10 | R10 je L a smíšený: obsahuje levnou opravu (no-op `passive_extended_observation`, 88,5 % plánů mimo rozpočet) i výzkumnou část (EVOI, SPRT, fondy, pivot, randomizace). Pivot a EVOI bez podkladu se nesmí zavádět jako jedno. | §5.b R10, D5 | 3 | Vytáhnout **R10-lite** (S až M): neplánovat kontroly, které `LocalRunner` stejně neprovede (no-op), idempotence na (cíl, metoda) s TTL napříč běhy, deduplikace plánů. To srazí 88,5 % „mimo rozpočet“ bez matematiky. EVOI, SPRT, pivot: škrtnout z core, nechat jako kapitolu „budoucí práce“. |
| P11 | R11 (pokrytí): 5 L-položek, z toho reverse shell a pivot nemají žádný podklad a studie je sama označuje jako P4. Beacon na tocích: soak má artefakt periodicity (RQ5), takže zisk nelze změřit. | §5.c R11 | 3 | Z core škrtnout. Ponechat jen „zapojit `score_source_hosts` jako signál, vypnuto ve výchozím stavu, měřit na kotvě CTU-13“ (≤ 1 den, viz ověření odkazu). Pivot/reverse shell: nepsat do diplomky jako cíl. |
| P12 | R12: dvě různé věci. Přesun `IsotonicCalibrator` z `eval` do knihovny a kalibrace zvlášť pro behaviorální typy je levné a užitečné (82,2 % predikcí v koši [0,9; 1,0) jsou statické expozice). Auto-uzavírání alertů a LR tabulky jsou riziko pro bezpečnost. | §5.e R12 | 2 | Rozdělit. Kalibrace: S až M, po R4-lite. Auto-uzavírání: škrtnout (viz bezpečnostní nález B4). |
| P13 | Přeskupení celkově. Doporučené pořadí: G0-min → R5 + R7-lite → R4-lite → R3 (+ agregace unmapped) → R10-lite → R6a → G0-plné (S1 až S3) → R2 → R12-kalibrace → R6b → R8 → (R9-light). Škrtnout: R9 jako samostatný modul, EVOI/SPRT/pivot z R10, R11 mimo zapojení `score_source_hosts`, FDR, auto-uzavírání, LLM. | §5.x | 3 | Přepsat §5.x podle tohoto pořadí a přidat sloupec „dny“. |

## 2. Proveditelnost změn (odkazy a odhady)

| # | nález | místo | závažnost | návrh |
|---|---|---|---|---|
| Q1 | Odkazy na kód jsou věrohodné (viz §0, 10 ze 10 ověřených sedí). Dokument se na kód opírá poctivě a rozlišuje „ověřeno“. Největší vada: odhad S pro R2 podceňuje, že `in_scope` se volá na třech místech a pravidla závislá na inventáři (`unexpected_traffic`) musí dostat příznak směru, jinak každé odchozí spojení na internet vyrobí „neznámý provoz“. | §5.d R2 | 2 | Před R2 napsat test: synthetic odchozí tok na veřejnou IP nesmí vyrobit `unexpected_traffic`. |
| Q2 | Odhady S/M/L pocházejí z auditu 01 (odhad autora auditu), nikdo je neověřil. Moje korekce na jednoho vývojáře s testy, migrací a dokumentací: R5 2 dny (S), R3 2 dny, R7-lite 4 dny, R4-lite 6 až 8 dní, R10-lite 3 dny, R6a 2 dny, G0-min 3 dny, G0-plné 8 až 12 dní, R2 3 dny, R12-kalibrace 4 dny, R8 8 až 12 dní, R7-plné 10 až 15 dní, R10-plné a R11 měsíc a víc. Součet „celého top 12“ je spíš 3 až 4 měsíce, ne 12 položek po týdnu. | §5.x | 3 | Doplnit sloupec „dny jednoho vývojáře včetně testů a migrace“. |
| Q3 | Prahy typu „pokles ≥ 50 %“ jsou „volba autora“ bez opory; pro R5 je zvolená polovina dolní meze analytického odhadu. Dobré jako předregistrace, ale slabé jako důkaz úspěchu pro obhajobu. | §5.a R5 | 1 | Ponechat, ale hlásit i absolutní číslo FP/síť-den, protože to správce cítí. |

## 3. Nejmenší sada změn s největším efektem (2 týdny) a její měření

Sada (v pořadí):

1. **G0-min** (3 dny): FP/síť-den absolutně per typ, `S_quiet` (`attack_rate = 0`), `noop_share`, hash a dirty příznak ve status, deterministické párování (seed, síť) pro A/B.
2. **R5 + R7-lite** (6 dní): robustní `packet_rate_spike` (agregát služby, p95, minimální počet toků a doba) a historie klíče pro `inductive_volume_anomaly`. Cíl: dva typy tvoří ≈ 97 % FP v [v1].
3. **R4-lite** (6 až 8 dní): perzistentní `first_seen/last_seen/occurrences`, znovuvydání jen při změně, první výskyt vždy viditelný, agregace `unmapped` podle (cíl, port, typ, den). Zároveň **R3** (2 dny) jako názvy pro správce.
4. **R10-lite** (3 dny) jen pokud zbude čas.

Měření (jedna sada, rozumná cena):
- Rameno A = současný engine, rameno B = nový. Stejné seedy z ladicí sady L, stratifikace velikostí: například 5 seedů × 40 sítí, S/M/L plus pár XL. Při 0,05 sítě/s je to ≈ 200 sítí ≈ 1,1 h na rameno. Důležité: soak už běží, takže si zjisti, kolik jader zbývá, jinak se čísla zkreslí (mimo `bakula-soak-*` se nezasahuje).
- Primární metrika: **zobrazené nálezy/síť-den** (po deduplikaci) a **FP/síť-den absolutně**, medián a p90 přes sítě, párový rozdíl s bootstrapem přes sítě (jednoduchý, stačí dopočet bez nové infrastruktury).
- Ochranná metrika: počet „detekovaných“ útoků po rodinách A vs. B na stejných seedech, ztráta nesmí být větší než 2 p. b. u rodin s ≥ 100 pozorováními. Přiznat, že atribuce oknem není opravená, ale protože je stejná v obou ramenech, párový rozdíl je interpretovatelný.
- Kotva CTU-13 jako kontrola vedlejších účinků (122 s na průchod): FP na benigních tocích nesmí vzrůst.
- Realistické očekávání: pokles FP položek ≥ 70 % (hypotéza, ne slib). Pokud bude pokles pod 50 %, hypotézu zveřejnit jako neúspěšnou.

## 4. Co by správce skutečně ocenil

| # | nález | místo | závažnost | návrh |
|---|---|---|---|---|
| U1 | Správce počítá nálezy za den, ne FP/síť-den ve smyslu simulace. [v2b] má 932 FP/síť-den; i po −90 % to je ≈ 90/den na síť, pořád nepoužitelné. Studie nikde nestanoví cílovou hodnotu „zobrazených nových nálezů za den na 100 zařízení“. | §8.3 bod 1, §5 | 4 | Stanovit provozní cíl, např. ≤ 10 nových položek/den na 100 zařízení, a měřit proti němu. Je to rozhodnutí o zadání (studie to sama uvádí), ale bez čísla je 12 doporučení bez cíle. |
| U2 | Vysvětlitelnost: studie mluví o `Discount`, `Explain`, benigních vysvětleních, ale nezmiňuje, co uvidí správce v UI. | §5.a R6 | 3 | Každý potlačený nebo zlevněný nález musí mít „proč“ (pravidlo, kalendář, zdraví sensoru) a být dohledatelný v seznamu „potlačeno“ s počítadlem. Bez toho správce nedůvěřuje nižšímu počtu. |
| U3 | Bezpečnost zásahů: správce ocení, že se nic neprovádí aktivně bez schválení. Studie to má (passive-first, schvalování), ale R10 zavádí „L1/L2 kontroly (connect/banner, ARP)“. | §5.b R10 | 3 | Výchozí vypnuto, jen na hosty v `scope_policy`, per-cíl rate limit, zákaz u OT/IoT bez schválení. |
| U4 | Pořadí a seskupení „nový/opakující se/vyřešený“ je pro správce největší zisk za nejmenší cenu (R4-lite). | R4 | 2 | Zobrazit „poprvé viděno, počet výskytů, naposledy“ v UI. |

## 5. Rizika regresí a bezpečnostní rizika

| # | nález | místo | závažnost | návrh |
|---|---|---|---|---|
| B1 | Deduplikace a potlačení maskují nový útok na „otevřené“ službě (studie to uvádí v rizicích, ale bez technického zábradlí). | R4 | 3 | Znovuvydání při změně stadia, Δp, nové zdrojové IP nebo nového typu na stejném klíči; test „útok na hostu s už otevřeným nálezem“ v soaku. |
| B2 | R2 otevírá ingest pro toky se zdrojem mimo scope: útočník zvenku (nebo skener) generuje neomezený počet unikátních klíčů a nafoukne stav nálezů a Case Memory (DoS na paměť a na pozornost správce). Stejné platí pro stavovou tabulku v R4. | R2, R4 | 3 | Strop kardinality na stav (např. top N podle skóre, zbytek do agregátu „externí šum“), TTL, metrika velikosti tabulky. |
| B3 | Aktivní ověřování a pivot: L1/L2 sondy mohou překročit scope pivotem, narušit služby, nebo být zneužity vyvoláním (útočník vyrobí „podezřelý“ tok, aby engine sondoval třetí stranu). | R10 | 3 | Pivot škrtnout. Sondy jen interní cíle, pevný seznam metod, strop sond na hodinu, žádné sondy podle polí řízených z internetu bez schválení. |
| B4 | Auto-uzavírání alertů (R12, V3-H20) při FNR vzorkem 2 %: pro správce, který nemá SOC, je tichá ztráta nálezu horší než šum. | R12 | 3 | Škrtnout z core. Případně jen „sbalit“, nikdy „uzavřít“. |
| B5 | Studie správně zakazuje LLM ve verdiktní cestě. Pragmaticky: přidat do plánu nulu práce (nic nedělat). V3-H34 zbytečná. | §5.f, V3-H34 | 1 | Škrtnout H34, v diplomce jedna věta. |
| B6 | Změna prahů (R5) přeladěná na lognormální generátor (A34) může na reálné síti nic nedělat nebo zhoršit. | R5 | 3 | Prahy vyvodit ze statistiky vlastní kotvy (CTU-13) a z pozorovaných p95 reálné sítě správce (nasadit v shadow režimu), ne z parametrů generátoru. |
| B7 | Kalendář údržby (R6b) a allowlist jsou cesta, jak se útočník schová. | R6 | 2 | TTL, schválení člověkem, audit záznam, zobrazit v UI aktivní výjimky. |

## 6. Experimentální plán soak v3

| # | nález | místo | závažnost | návrh |
|---|---|---|---|---|
| E1 | 37 předregistrovaných hypotéz (V3-H01 až H37) s Holm-Bonferroni je pro jednoho vývojáře nepoužitelné. Mnoho z nich jsou zrcadlení hypotéz z literatury bez opory (H15, H28, H33, H34 průzkumné). Více hypotéz zvyšuje riziko, že nic nebude dokončeno a předregistrace ztratí váhu. | §7.4, §9 | 3 | Zredukovat na ≈ 8 primárních: pokles FP/síť-den celkem, recall ochrana po rodinách, packet_rate, inductive, dedup (zobrazené nálezy), typ exploit po R3, plán mimo rozpočet po R10-lite, kalibrace. Zbytek jako explorativní tabulka. |
| E2 | Rozpočet ≈ 180 h je odhad autora a předpokládá exkluzivní stroj. Soak v2b zároveň ukazuje únik haldy +78 MiB/h, takže dlouhé běhy jsou rizikové. | §7.5 | 3 | Omezit běhy na ≤ 2 h nebo opravit únik. Počítat reálně 3 až 4 týdny wall-clock při sdílení CPU. |
| E3 | Zkrácení: (a) nezačínat 10 seedy × 200 sítí, ladit na 3 seedech × 40 sítí; (b) **generovat telemetrii jednou na seed a opakovaně přes ni pouštět varianty enginu**, pokud `--engine` a harness oddělí generování od zpracování. U pasivních změn (R5, R7-lite, R4-lite, R3, R6a, R2) se telemetrie nemění, takže generátor netřeba pouštět znovu. U R10 (ověřování zpětně ovlivňuje scénář) to neplatí. | §7.3 | 3 | Uložit surovou telemetrii seedu na disk (dev vzorek) a udělat „replay-only“ A/B. Tím se E1 sníží z ≈ 53 h na hodiny. |
| E4 | Paralelizace: A a B ramena lze pouštět nezávisle. Bottleneck je CPU, ne vlákna; u 20 vláken je dnes 0,05 sítě/s. Neparalelizovat nad počet jader, nespouštět vedle běžícího `bakula-soak-*`, pokud se tím zpomalí jeho měření (konflikt prostředků). | §7.5 | 2 | Sjednotit s vlastníkem stroje časové okno, kdy je stroj volný. |
| E5 | Držené seedy a držené rodiny jsou dobrá disciplína a levná. Seed 20261101 je správně přesunut do ladicích. | §7.2 | 0 | Ponechat. Držené použít jen jednou, na konci. |
| E6 | Hybridní režim CTU-13 + injekce a nezávislý scénář `slow_scan_camouflage` jsou drahé a vázané na R10-plné, které doporučuji odložit. | §7.2 | 1 | Vyřadit z v3, nechat pro budoucnost. |

## 7. Chybějící praktické věci

| # | nález | místo | závažnost | návrh |
|---|---|---|---|---|
| M1 | **Migrace dat**: nový perzistentní stav nálezů a změna `Finding` (`first_seen`, `occurrences`, `incident_id`) zasáhne uložené nálezy a Case Memory (`record.finding_type`, váhy). Studie migraci nezmiňuje vůbec. | R4, R12 | 3 | `#[serde(default)]` na nová pole, verze schématu, jednorázový převod, test načtení starých souborů. |
| M2 | **Zpětná kompatibilita výstupů**: ID, API a export (`server.rs`, `report.rs`) mohou používat `finding_id`. Změna sémantiky (znovuvydání jen při změně) změní, co klient vidí. | R4 | 2 | Přepínač v konfiguraci (stará/nová emise) a shadow režim: engine počítá obě varianty a loguje rozdíl, zobrazuje starou, dokud se nepotvrdí. To je zároveň pojistka pro rollback. |
| M3 | **UI**: studie mluví o incidentech, kalendáři, potlačených nálezech, ale nezmiňuje žádnou práci v UI. Pro správce je to to, co vidí. | R4, R6 | 3 | Do plánu přidat 2 až 3 dny UI (sloupce first/last/count, filtr „nové dnes“, seznam potlačených s důvodem). |
| M4 | **Testy**: chybí regresní zlatá sada. Změny prahů a deduplikace potřebují deterministické testy (stejný seed → stejné nálezy) a testy bezpečnostního zábradlí (útok na otevřený nález). | všechny | 3 | Ke každé R jednotkový test + jeden zlatý scénář. `soak verify` (30/30 deterministické) je výborný základ, využít. |
| M5 | **Dokumentace**: chybí změnový záznam, popis nových prahů a jejich verzí (studie navrhuje `passive/thresholds.rs` s verzí, dobře). | R5 | 1 | Krátký doc po každé R, jinak se diplomka nedá obhájit. |
| M6 | **Monitorování enginu**: žádná provozní metrika (počet nálezů/den, velikost stavové tabulky, `noop_share`, latence cyklu, úniky paměti). Únik +78 MiB/h by v produkci zabil proces. | G0, R4 | 3 | Přidat do `ops.rs`/status: nálezy za cyklus podle typu, velikost stavu, RSS. Musí být před nasazením R4. |
| M7 | **Nasazení v shadow režimu na reálné síti**: celý plán se opírá o simulátor (A34). Žádný krok neověřuje na skutečném provozu správce. | celé | 3 | Po 14 dnech pustit nový engine paralelně na pasivních datech jedné reálné sítě a porovnat počty nálezů (bez odesílání osobních dat kamkoli). |

## 8. Verdikt

Studie je poctivá, dobře dohledatelná a kód, na který se odvolává, existuje (10 ze 10 odkazů sedí). Problém není pravdivost, ale **plánovací váha**: je to rozsáhlý výzkumný program (12 R, 37 H, ≈ 180 h výpočtu, 3 až 4 měsíce práce) postavený za bránu G0, která sama zabere víc než dva týdny a odsouvá opravu největších zdrojů šumu. Pro cíl „prokazatelně nižší šum“ je pořadí neoptimální: nejlevnější a nejefektivnější jsou R5, R7-lite, R4-lite a R3, kterým studie přiřazuje pozdější místa nebo závislosti, které nepotřebují. R9, EVOI/SPRT/pivot, R11 (mimo zapojení existující funkce), FDR, auto-uzavírání a LLM bych z core vyškrtl a nechal jako budoucí práci nebo negativní výsledky. Doporučuji verzi 1.1: stejné závěry z literatury, ale přepsané §5.x (pořadí a dny), §7.4 (≈ 8 primárních hypotéz) a doplněné o §M1 až M7 a provozní cíl U1.

Celkové hodnocení: realizovatelnost jako celek 2/4 (v dané podobě), realizovatelnost zmenšeného jádra 4/4; praktická užitečnost jádra vysoká, zbytek spekulativní.

## 9. Plán na 14 dní

Předpoklad: jeden vývojář, žádný zásah do `bakula-soak-*`, commit po kusech, push až po dokončené sekci.

| den | práce | výstup / kontrola |
|---|---|---|
| 1 | G0-min: FP/síť-den absolutně per typ, `S_quiet`, hash a dirty ve status, `noop_share`. Zmrazit základní běh A (současný engine, seedy L, 40 sítí × 5 seedů). | základní čísla A uložená |
| 2 | Shadow režim a přepínač emise (stará/nová) v konfiguraci, metrika velikosti stavu a počtu nálezů v `ops.rs`. Zjistit volná jádra pro A/B. | přepínač funguje, test načtení starých dat |
| 3 | R5: agregát služby a p95 přes toky s ≥ 10 pakety a ≥ 1 s, prahy do `passive/thresholds.rs` s verzí. Jednotkové testy. | commit |
| 4 | R5: kalibrace prahů na L a CTU-13 (ne podle parametrů generátoru), test `ddos_volume`. A/B běh 1. | tabulka packet_rate FP před/po, ddos recall |
| 5 | R7-lite: historie klíče, medián/MAD, minimální počet toků a pozorování místo průřezového z-skóre. | commit + testy |
| 6 | R7-lite: gating při otevřeném nálezu, A/B běh 2, kontrola recallu po rodinách. | tabulka inductive FP před/po |
| 7 | Rezerva/oprava, zápis do `kritika`-deníku (co selhalo). Pokud pokles FP < 50 %, zastavit a zjistit proč, než se jde dál. | rozhodnutí go/no-go |
| 8 | R4-lite: pole `first_seen/last_seen/occurrences` v `Finding` (`serde(default)`), migrace uložených nálezů, test. | commit |
| 9 | R4-lite: stavový modul, znovuvydání při změně stadia, Δp, nové zdrojové IP nebo nového typu, po klidu. Strop kardinality a TTL. | testy zábradlí (útok na otevřený nález) |
| 10 | R4-lite: agregace `unmapped` podle (cíl, port, typ, den); R3 `classify_signature` podle kategorie a prefixu, zrušit větev portu 80, pravidlo `ids_alert` v `SERVICE_RULES`. | commit |
| 11 | UI: sloupce first/last/count, filtr „nové dnes“, seznam potlačených s důvodem. | ruční kontrola v UI |
| 12 | A/B běh 3 (celé jádro B vs. A) na L, kotva CTU-13, výpočet párového rozdílu s bootstrapem přes sítě. | hlavní tabulka |
| 13 | Volitelně R10-lite (zrušit no-op plány, idempotence s TTL) nebo opravy z běhu 3. Potvrzení na malé sadě H seedů (3 seedy), jednou. | tabulka plánů mimo rozpočet |
| 14 | Shadow běh na pasivních datech jedné reálné sítě (lokálně), dokumentace změn a prahů, aktualizace studie na v1.1 (pořadí, dny, hypotézy), zápis neúspěchů. | zpráva o poklesu zobrazených nálezů/den a ztrátě recallu |

Kritérium úspěchu na konci dne 14: zobrazené nálezy/síť-den klesly o ≥ 70 % (minimálně 50 %), recall žádné rodiny s ≥ 100 pozorováními o více než 2 p. b., kotva bez nárůstu FP, žádná paměťová regrese. Jinak publikovat jako negativní výsledek a vrátit přepínač.
