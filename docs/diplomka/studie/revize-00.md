# Revize závěrečné studie 00 (v1.0 → v1.1)

Datum: 2026-11-01. Revidovaný soubor: `00-zaver-jak-vylepsit-core.md`. Vstupy: `kritika-skeptik.md` (K1 až K23, verdikt PŘIJATELNÉ S OPRAVAMI) a `kritika-pragmatik.md` (P, Q, U, B, E, M; plán na 14 dní).

Postup:
- Úpravy jsou cílené, co bylo v pořádku, zůstalo.
- Jistoty jsem nezvyšoval a nová čísla z literatury jsem nepřidával.
- Čísla z v2b jsou dál ze snímku **2026-11-01 00:03 SEČ** (1,00 h) a jsou tak označena. Novější snímky (1,25 h u skeptika, 9,50 h při revizi) jsem do studie nepřebíral.
- Zdrojový kód jsem neměnil, necommitoval jsem a procesů `bakula-soak-*` jsem se nedotkl.
- Ověřil jsem v kódu dvě nová tvrzení: `score_source_hosts` je `pub(crate)` v `passive/anomaly.rs:110` s `#[allow(dead_code)]`, a `known_services` v `passive/mod.rs:58-66` obsahuje jen otevřené služby.
- Ze zdrojů jsem znovu přečetl řádky RQ4-039, RQ6-002 a RQ6-006.

## Skeptik

| zjištění | změna ve v1.1 | místo |
|---|---|---|
| K1 BotProbe a „bez stropu 15 až 80 %“ | Opraveno. 15,4 % je podíl nerozhodnutých se stropem 3 kol; TRW > 80 % kvůli málo pokusům. Strop omezuje náklady, nerozhodnutost neřeší, proto eskalace a trojstav. Kritérium (dříve V3-H23, nyní X23) přeformulováno na „nerozhodnutých po eskalaci > 15 %“ | §1 bod 2, M12, R10 očekávaný efekt a měření, X23 |
| K2 LLM formulace | Zjemněno. Výsledky pocházejí z jednoho preprintu a jednoho modelu (Alert-Bench, GPT-4.1). Doplněn protichůdný údaj AIDA FNR 3,1 % (RQ6-006). Doporučení opřeno o riziko injection (střední pro existenci) a chybějící replikaci, „selhání LLM není prokázané“ | §1 bod 5, M41, §5.f, §6 |
| K3 ATLANTIDES neřeší inventář | Opraveno. M9 rozlišuje aktivní ověření zranitelnosti (Kruegel), ověření podle odpovědi služby (ATLANTIDES) a degradaci podle inventáře (bez přímého podkladu). V R6 je očekávaný efekt degradace „bez přímého podkladu“. Hypotéza X12 přesunuta do priority 3 | §1 bod 2, M9, R6, X12, příloha |
| K4 Holt-Winters a pozdější útok | Opraveno: druhá polovina tvrzení označena jako inference | M23 |
| K5 IoT-23 lift | Opraveno. Lift je 0,00× v 6 ze 7 scénářů se škodlivým provozem, 10,75× u Capture-3-1, u 3 honeypotů nedefinován. Byla to moje chyba čtení tabulky. „Záhada“ v §4.3 zrušena, otevřená otázka §8.3 bod 4 upravena | D14, §4.3, §8.3 |
| K6 rogue_device XL 0 % | Částečně. V mém snímku (1,00 h) bylo XL opravdu 0 % (n = 31), záměna sloupců to nebyla. Novější snímek má 4 % (n = 55). Doplněna n u všech buněk, tvrzení o trendu staženo na „S proti L + XL + XXL, malá n“ | D9, §4.3 |
| K7 jistota RQ4 Z9 v §6 | Sjednoceno na střední podle R-1. U řádku AUC uvedeny obě jistoty (RQ4 Z1 nízká, RQ5 Z-7 střední pro obecný jev) | §6 |
| K8 M5 „o řády horší“ | Doplněno: AUC téměř beze změny (Argus 99,83 → 98,44, RQ4-039), propad AP a AUC na přísně štítkovaných LM událostech | M5 |
| K9 D5 jako strukturální chyba | Opraveno. D5 je smíšený jev (rozpočet jádra a plánování harnessu A32), podíl obou určí E0 | §1 bod 6, D5, §4.4 |
| K10 malý vzorek kontroly souhrnu | Přiznáno: odhadovaná chybovost interpretace kolem 15 % a doporučení znovu projít tvrzení se střední a vyšší jistotou. Plnou novou kontrolu jsem **neprovedl**, ani 5 ověření přes URL. Podle zadání šetřit to zůstává otevřené | §2.1, §8.1 |
| K11 sklon FP vs velikost | Opraveno. Sklon byl jen ze dvou bodů, XXL je nižší než XL a velikost je zmatená s archetypem (Cloud). Mechanismus „maximum přes toky“ omezen na `packet_rate_spike`. Regrese s efektem archetypu po typech FP přidána do E0. Doplněna nestacionarita snímků | §1 bod 6, D2, §4.2, §5.g, §7.3, §8.1 |
| K12 `unexpected_traffic` bez doporučení | Přidáno R13 (diagnostika příčin v E0, rozdělení SF a S0/REJ, perzistentní inventář s `inventory_cold`, agregace) a primární hypotéza P4 | §5.a R13, §5.x, §5A, §7.4a |
| K13 „strop 40,7 %“ u R3 | Přeformulováno na „referenční mez při dnešním generátoru a výhradně IDS cestě“ | R3 |
| K14 jednotka a zkreslení D1 a D3 | Doplněna jednotka nález × cyklus a oba protichůdné zdroje zkreslení. Precision nepoužívat, dokud ji E0 nepřepočítá | §4.1 úvod, D1, D3 |
| K15 v1 a v2b vedle sebe | Doplněna poznámka o nesrovnatelnosti | §4.1 úvod |
| K16 odhady efektů | R2: ≈ 37 % označeno jako horní reference diagnostického skóre, ne efekt. R6: −30 % označeno jako práh bez opory. Prahy „volba autora“ jsou zamražené v §7.4a | R2, R6, §7.4a |
| K17 statistická síla | Přidán výpočet P0. Při n = 100 je i při nulové diskordanci horní mez ≈ 3 p. b. (pravidlo tří), takže 2 p. b. per rodina je nesplnitelné. Nové ochranné kritérium G: agregát ≤ 2 p. b., per rodina s n ≥ 100 ≤ 5 p. b. s Holmem, n < 100 popisně. Po E0 se přepočítá z naměřené diskordance a design effectu | §5 úvod, §7.4a |
| K18 mnohonásobné testování | 8 primárních H, každá s jednou metrikou, odhadem a prahem vztaženým k mezi CI. Holm už při rozhodování na V (E1, E2), BH q = 0,10 pro průzkumné. Všechna „viz RQ“ rozepsána přímo do tabulek | §7.4a, §7.4b |
| K19 opakované použití H a kotvy | Sady L, V, H1, H2. H1 i H2 se použijí každá jen jednou. Kotva rozdělena předem na vývojovou (Botnet-42 až 48) a testovací (Botnet-49 až 54 a IoT-23), testovací se k ladění nepoužije. Přiznáno, že držené seedy nechrání před spoluadaptací generátoru a enginu; doplněn požadavek pcap replaye. Slabost držených rodin uvedena | §3 R-7, §7.2, R11 |
| K20 kumulativní design a párování | Finální E3 s ablací po jednom (leave-one-out). Bootstrap stratifikovaný podle seedu a archetypu. Párování přes uloženou telemetrii, jinak s vypnutou zpětnou vazbou zásahů; u změn se zpětnou vazbou se hlásí divergence ramen | §5 úvod, §7.3 |
| K21 rozpočet výpočtu | Přepočteno jako rozsah a spodní mez, s replayem. Přepočet po E0 | §7.5 |
| K22 alternativní vysvětlení | D11 doplněno o flash_crowd, backup_burst a authorized_scanner (R6a je neřeší). Práh TTD v P3. Rekalibrace jen s rozdělením typů (R12a) | D11, R6, R12, §7.4a P3 |
| K23 novost | Zúženo. Výběr ověřovací kontroly nad toky, se zmínkou o sousedních liniích (nákladově citlivá odezva). Reference z kritiky jsou označené jako mnou neověřené. Benigní vysvětlení zúženo na toky a provozní události | §8.4 |

## Pragmatik

| zjištění | změna ve v1.1 | místo |
|---|---|---|
| P1 R1 blokuje vše | G0 rozdělena na G0-min (≈ 3 dny, podmínka jádra) a G0-plné (souběžně, podmínka E2 a finále) | R1, §7.1 |
| P2 R5 až pátá | R5 přeřazena na 2. místo, závisí jen na G0-min | R5, §5.x, §5A |
| P3 inductive a R7 | Přidána R7-lite (historie klíče, medián/MAD, N_min, gating), plná R7 odložena | R7, §5.x |
| P4 R4 větší, ID není problém | R4-lite (stav, znovuvydání, strop a TTL) a plná R4 později. Upřesněno, že `build_finding_id` je stabilní | R4 |
| P5 R2 není snížení šumu | Přesunuto za G0-plné, mimo jádro. Kardinalita a test směru přidány | R2, §5.x |
| P6 R3 kvalitativní přínos | Ponecháno v jádru jako srozumitelnost | R3 |
| P7 R9 RBA | Odloženo, v jádru RBA-light řazení bez H | R9, §5.x |
| P8 R8 identita | Odloženo, nejdřív diagnostická tabulka v E0 | R8 |
| P9 R6 příliš velké | Rozděleno na R6a (2 dny) a R6b (kalendář, odloženo). Důvod potlačení zobrazit v UI | R6 |
| P10 R10 smíšené | R10-lite (no-op, deduplikace plánů, idempotence, trojstav) jako primární P5. EVOI, SPRT a fondy odloženy, pivot škrtnut | R10, §5.x |
| P11 R11 | Ponecháno jen zapojení `score_source_hosts` (vypnuto ve výchozím stavu, měřeno na kotvě), zbytek odložen | R11, §5.x |
| P12 R12 | Rozděleno: R12a kalibrace (primární P8), R12b odloženo, auto-uzavírání škrtnuto | R12 |
| P13 nové pořadí | Převzato do §5.x se sloupcem dnů. R13 jsem vložil do jádra navíc kvůli K12 | §5.x |
| Q1 R2 a `unexpected_traffic` | Test „odchozí tok na veřejnou IP nevytvoří `unexpected_traffic`“ v R2 a v regresních testech | R2, §5A.3 |
| Q2 dny | Sloupec dnů v §5.x (odhad pragmatika, označeno) | §5.x |
| Q3 absolutní FP | Absolutní FP/síť-den je součást G0-min a primárních metrik | §7.1, §7.4a |
| U1 provozní cíl | Doplněn jako rozhodnutí o zadání (návrh ≤ 10/den/100 zařízení). Číslo jsem nestanovil, protože je to volba autora práce | §5A.3, §8.3 |
| U2 až U4 UI a vysvětlitelnost | Doplněno (důvod potlačení, seznam potlačených, první/poslední/počet, aktivní sondy ve výchozím stavu vypnuté) | R6, R10, §5A.3 |
| B1 dedup maskuje útok | Znovuvydání při novém zdroji nebo typu, regresní test | R4, §5A.3, P3 |
| B2 kardinalita | Strop a TTL stavu, metrika velikosti | R2, R4, §5A.3 |
| B3 pivot a sondy | Pivot škrtnut, sondy jen interní a ve výchozím stavu vypnuté | R10, §6 |
| B4 auto-uzavírání | Škrtnuto, nanejvýš „sbalit“ | R12, §5.x, §6 |
| B5 LLM a H34 | Z plánu škrtnuto, X34 jen podmíněně | §5.f, §5.x |
| B6 prahy z generátoru | Prahy R5 z vývojové kotvy a z shadow režimu | R5, §5A |
| B7 kalendář jako úkryt | TTL, schválení, audit, zobrazení výjimek | R6, §5A.3 |
| E1 37 hypotéz | 8 primárních, ostatní průzkumné | §7.4a, §7.4b, příloha |
| E2 rozpočet a únik haldy | Rozpočet přepočten, únik uveden jako riziko a jako metrika enginu | §7.5, §5A.3 |
| E3 3 × 40 a replay | Převzato | §7.2, §7.3 |
| E4 sdílení CPU | Uvedeno v předpokladech 14denního plánu | §5A |
| E5 seedy | Ponecháno a zpřísněno (H1 a H2 jednou) | §7.2 |
| E6 hybrid a camouflage | Odloženo z v3 | §5.x, §7.2 |
| M1 až M7 praktické věci | Nový oddíl §5A.3 (migrace, shadow, UI, regresní testy, metriky enginu, strop a TTL, riziko dedup, provozní cíl, dokumentace, reálná síť) | §5A.3 |
| 14denní plán | Nový oddíl §5A podle pragmatika. Přidal jsem diagnostiku R13 (den 1) a rozhodnutí R13 (den 11). Potvrzení na H1 jednou (den 13) | §5A.1 |
| Laťka 70 % / 50 % | Převzata jako volba zadavatele. Doplněno poctivé upozornění: na mixu v2b tvoří packet_rate a inductive jen 48,3 % FP, takže samy laťku splnit nemohou; potřeba R4-lite a R13 | §5A.2, §7.4a P7 |

## Co jsem nezměnil a proč

- **Závěry z literatury (§3) a jejich jistoty:** kritiky je nezpochybnily kromě K3, K4, K7 a K8, které jsou opravené. Žádnou jistotu jsem nezvýšil.
- **Plná nová kontrola souhrnu a 5 ověření zdroje přes URL (K10):** neprovedeno. Šetřím rozpočet a nová rešerše nebyla zadaná. Zůstává jako otevřený úkol v §8.1.
- **Čísla z novějších snímků v2b:** nepřebral jsem je, aby studie měla jeden konzistentní snímek. Skeptikova čísla z 1,25 h zmiňuji jen tam, kde mění výklad (K6, K11).
- **Pragmatikův odhad dnů:** převzal jsem ho bez ověření a je označený jako odhad pragmatika.
- **Provozní cíl:** konkrétní hodnotu jsem nestanovil, je to rozhodnutí o zadání.
