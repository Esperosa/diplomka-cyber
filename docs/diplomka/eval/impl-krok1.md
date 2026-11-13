# Implementace, krok 1 ze 4: základ, paměť nálezů a snížení šumu (engine v3)

Datum 2026-11-01. Kód: commity `b21d992` až `7a2ac7d` (větev `main`, nepushnuto). Měření: ladicí seedy 20261102, 20261103, 20261104, každý 40 sítí, `--block-size 2 --no-legs --no-feedback`, 120 sítí, 1 236 virtuálních síť-dnů na rameno. Držené seedy (20261201, 20261301) ani kotva CTU-13/IoT-23 se nepoužily. Všechna čísla jsou ze simulace, ne z reálných sítí.

Surové výstupy: `F:\Projekty\bakula-soak\ab\<rameno>-<seed>\{networks.jsonl, final-report.json, final-report.md}`, souhrny `F:\Projekty\bakula-soak\ab\reports\` (`ab-main.md` = plná tabulka legacy proti v3, `ablation.md`, `agg-h0.txt`, `agg-r3l.txt`). Přepočet: `python tools/soak_ab.py --a <legacy dirs> --b <v3 dirs>` a `python tools/soak_ablation.py`.

## Shrnutí

1. **Laťka poklesu je splněna.** Zobrazené položky na síť-den klesly o 98,6 % (95% CI −99,0 až −98,2 %), zobrazené falešné poplachy o 95,8 % (−97,1 až −94,0 %). Odlišné falešné stavy, které čekají na člověka, klesly o 85,7 % (−90,0 až −78,8 %). Legacy je 532,7 FP/síť-den, v3 22,2.
2. **Zavřeno omylem je pod mezí.** Ze 1 784 automatických zavření 1,18 % (95% CI 0,77 až 1,79 %) skrylo tok útoku na tentýž cíl nebo z téhož zdroje. Audit náhodného 10% vzorku dal 1 ze 162 (0,62 %, CI 0,11 až 3,41 %). Mez, kterou navrhuji níže (bod ≤ 2 %, horní mez 95% CI ≤ 5 %), platí.
3. **Ochrana recallu prochází jen po korekci na pozadí.** Surová detekce ze zobrazených položek klesla u šesti rodin s ≥ 100 útoky o víc než 5 p. b. (dns_tunnel −59, exfiltration −57, exploit_attempt −48, lateral_movement −31, port_scan_horizontal −7, ssh_bruteforce −6). Placebo okna ale ukazují, že legacy „detekce“ těchto rodin je z velké části náhodná shoda s pozadím: stejné klíčové IP ve stejně dlouhém okně bez útoku „detekuje“ legacy v 57 až 100 % případů. Po odečtení placeba (detekce nad pozadím) je v3 u všech rodin s ≥ 100 měřitelnými placebo okny lepší nebo stejná. Nejhorší je c2_beacon (+6,0 p. b., CI 0,0 až +12,5). Skutečná ztráta, kterou korekce nezakryje: exfiltrace (−3,4 p. b. nad pozadím, CI −13,7 až +8,3, n = 89) a správný typ u credential_stuffing, web_exploit, dns_tunnel a exfiltrace (tabulka níže).
4. **Největší zdroj šumu z v2b byl artefakt harnessu, ne enginu.** 99,5 % FP typu `unexpected_traffic` (57,6 % všech FP na těchto seedech, 51 % ve v2b) vzniklo tak, že generátor posílal úspěšná spojení externích klientů na porty 80 a 443 kontejnerů, které poslouchají jen na 8080. Hypotéza studie 01 (A08: zastaralý inventář) pro tento typ neplatí. Pro `unmapped_passive_event` se potvrdila (55,8 % zařízení mimo provoz při skenu, 34,4 % prázdný inventář po restartu, 9,8 % změněná IP).
5. **Identita:** falešné rozdělení klesá z 35,4 % na 14,3 %, falešné sloučení z 24,5 % na 8,6 %. Příčina je v enginu: bez MAC byla identita jen IP. Harness k tomu neměl realistická jména hostů.
6. **Měření v harnessu nebylo párové.** Studie předpokládá párové A/B na stejných seedech (§7.3), ale náhodný proud světa (churn DHCP, chyby jádra) spotřebovával náhodná čísla podle počtu nálezů enginu a zásahy enginu zpětně měnily provoz. Ramena A a B tak dostávala jiný svět. Opraveno (krok A, bod iii); bez toho by A/B nebylo interpretovatelné.

## Co se změnilo (soubory)

| krok | soubory | podstata |
|---|---|---|
| A přepínač | `src/engine.rs`, `src/model.rs` (`AppConfig.engine`), `src/main.rs` (`--engine`, `--v3-off`, `--no-feedback`) | `engine.mode = legacy \| v3` (výchozí legacy), každou změnu v3 jde vypnout zvlášť (`memory, rate, volume, unexpected, context, identity`) |
| A harness | `src/soak/netmodel.rs`, `src/soak/traffic.rs`, `src/soak/episode.rs`, `src/soak/runner.rs` | (i) počet podsítí podle statických adres (~90 na /24 s 15% rezervou) a pojistka bez paniky; (ii) port kontejneru; (iii) oddělený náhodný proud vyhodnocení a `--no-feedback`; (iv) `networks.jsonl` po sítích, hash a příznak dirty ve stavu |
| A měření | `src/soak/scoring.rs`, `src/soak/stats.rs`, `tools/soak_ab.py`, `tools/soak_ablation.py`, `tools/soak_agg.py` | zobrazené položky, odlišné stavy, tři skupiny výstupu, zavřeno omylem (příčinně i široce), audit vzorku, placebo okna, rozpad příčin `unexpected`/`unmapped`, párový clusterový bootstrap |
| B paměť | `src/finding_memory.rs`, `src/engine_state.rs`, `src/pipeline/v3.rs`, `RunReport.finding_lifecycle` | identita nálezu, stav, eskalace, TTL, strop, SQLite se schématem a migrací, audit append-only |
| C šum | `src/passive/anomaly_v3.rs`, `src/passive/detector.rs` (`V3StatefulDetector`), `src/findings.rs` (`scan_attempts`, agregace unmapped), `PersistentInventory` | packet rate, objem, unexpected |
| D kontext | `src/context_gate.rs`, `src/soak/v3.rs` (`SimContext`) | rozhraní poskytovatele, mantinely, audit, auto-vypnutí |
| E identita | `src/identity.rs` (`IdentityResolverV3`), `NetworkModel::hostname_of` | MAC > jedinečné jméno > IP, držené hosty inventáře |
| produkce | `src/pipeline/mod.rs`, `src/pipeline/v3.rs`, `tests/engine_v3.rs` | v3 v `run_pipeline`: `engine-state.sqlite`, `context-calendar.json`, `identity-registry-v3.json` |

## A) Přepínač a oprava harnessu

**Panika „kapacita podsítí“** (v2b síť 808). `generate` dimenzoval podsítě jen jako `celkem / 110`. Hustě serverové archetypy (Cloud, Datacenter, Industrial) mají přitom skoro jen statické adresy a statický rozsah 2..=99 se vyčerpal. Teď platí `max(celkem/110, ⌈odhad statických × 1,15 / 90⌉)` a když je plno, použije se libovolná volná adresa 2..=250. Panika nenastane nikdy. Test projde 6 000 sítí čtyř seedů a síť 808. Na ladicích seedech je 0 panik.

**Co z bodu #1 auditu (G0-min) platilo i po opravě `mentions_ip`:**
- A28 (podřetězec IP): opraveno už v `a293d2b`, ověřeno testem.
- A29 (atribuce okna u sensor_crash, log_corruption, collector_replay): mechanismus zůstává. Placebo okna jsou první krok ke kontrafaktuálu, plný kontrafaktuál `mask_truth` zůstává na G0-plné.
- A30 (`expected_types`): doplněn typ `scan_attempts`, který v3 skutečně umí (skeny, rogue, apt_chain). Legacy ho nevydává, takže se legacy čísla nemění.
- A31 (nálezy × cykly, chybí detekce nad pozadím): nově odlišné stavy (mezera > 6 h = nový stav, stejný sledovač v obou ramenech), zobrazené položky a placebo okna (stejné klíčové IP, okno posunuté o délku + 12 h, bez jiného útoku na tatáž zařízení).
- A35 (`range(0, len-1)` při len = 0): všechna místa jsou hlídaná.
- **Nově nalezeno:** spotřeba náhodných čísel závislá na nálezech (vzorkování verdiktů, chyby operátora, chyby jádra podle počtu pravidel) posouvala proud světa a zásahy blokovaly provoz. Oprava: proud `eval_rng` pro vyhodnocení a `--no-feedback`. Regresní test `paired_arms_see_identical_world` ověřuje stejné toky, churn a útoky v legacy i v3.

**Nové metriky.** Zobrazené položky (legacy zobrazí každý nález v každém cyklu, v3 jen první výskyt, znovuotevření a eskalaci), tři skupiny výstupu na úrovni odlišných stavů, „zavřeno omylem“ ve dvou definicích (níže), audit 10% vzorku zavřených.

**Dopad opravy harnessu na legacy** (stejné seedy; starý harness `h0` proti novému `r3-legacy`, agregát; starý harness nemá výstup po sítích, proto bez CI):

| | starý harness | nový harness |
|---|---:|---:|
| FP / síť-den | 1 552,7 | 532,7 |
| `unexpected_traffic` FP / síť-den | 894,5 (57,6 %) | 2,3 (0,4 %) |
| `inductive_volume_anomaly` | 451,0 | 346,3 |
| `packet_rate_spike` | 127,7 | 116,4 |
| `unmapped_passive_event` | 57,0 | 44,6 |
| identita rozděleno / sloučeno | 35,2 / 24,4 % | 35,4 / 24,5 % |

Rozdíly mimo `unexpected_traffic` plynou z jiného náhodného světa (krok iii). **Všechna srovnání níže jsou proti legacy na novém harnessu** (`r3-legacy`), ne proti v2b.

## B) Paměť nálezů a deduplikace

- **Identita nálezu:** `(entita, typ, služba)`. Entita je asset id z identity, jinak IP cíle. U pokusů (`scan_attempts`) je entitou ZDROJ (jeden stav na skener, ne na každý cíl). Služba je `proto/port`, takže změna DHCP adresy při stabilní identitě stav nezahodí. Intel nálezy bez hostu i služby nesou vlastní id.
- **Stavy:** nový → otevřený → (vyřešený automaticky | potvrzený) → uzavřený → znovuotevřený. Ruční `confirm`, `close`, `reopen` (vratnost). Každý přechod je v tabulce `finding_audit`, která je append-only (trigger).
- **Deduplikace a eskalace (zábradlí B1, RQ1 Z2/Z3):** opakovaný stejný stav se nezobrazí. Zobrazí se ale při vyšší závažnosti, novém dominantním zdroji (podíl ≥ 20 %, ≥ 5 toků) nebo objemu ≥ 4× dosavadního maxima (a ≥ 20). Jiný typ na stejném hostu je jiný klíč, takže se zobrazí jako první výskyt. Test `new_attack_on_host_with_open_finding_escalates`.
- **TTL:** po 24 h klidu se stav uzavře a další výskyt se zobrazí jako znovuotevřený. Uzavřené a vyřešené stavy se po 7 dnech smažou. 24 h je volba autora („nové dnes“, U4). Šest hodin dávalo ve zkušebním běhu 25 % zobrazení jen ze znovuotevření.
- **Strop:** 50 000 položek. Při naplnění se dávkově (10 %) vyřadí nejprve uzavřené, pak vyřešené, pak otevřené s nejnižší závažností a nejstarším výskytem. Složky klíče mají nejvýš 200 znaků. Detektor v3 má vlastní stropy: 20 000 klíčů, 4 096 zdrojů pokusů, 256 cílů na zdroj a TTL 7 dní. Test zaplaví paměť 20 000 unikátními klíči, paměť zůstane ≤ 1 000 a závažný nález se vyřadí jako poslední. V soaku bylo nejvýš 8 711 položek na síť.
- **Perzistence:** SQLite `engine-state.sqlite`: `finding_state`, `finding_audit` a `kv` (stav detektoru, inventář). Verze schématu je v `PRAGMA user_version`, migrace je idempotentní a novější neznámou verzi odmítne. Posun samotného `last_seen` se zapisuje nejvýš jednou za 90 min, stavové změny vždy. Restart v soaku = zápis a nové načtení všeho (5 748 restartů ve v2b by bez toho mazalo inventář i paměť). Integrační test `tests/engine_v3.rs` spustí dva samostatné procesy `beh spust` s `[engine] mode = "v3"`: druhý běh opakované stavy nezobrazí, legacy výstup se nemění. Golden snapshot zůstává zelený.
- **Zapojení v soaku:** měří se odlišné stavy a zobrazené položky. Ověřovací plány vznikají jen pro zobrazené (A24): 5 846 → 78 plánů na síť-den.

## C) Šum u dominantních typů

Detektor `passive/anomaly_v3.rs`, prahy verze 1 (volba autora, laděno jen na ladicích seedech):
- **`packet_rate_spike` (A04):** místo maxima `pkts/duration` přes všechny toky se bere p95 rychlosti jen přes kvalifikované toky (≥ 10 paketů, ≥ 1 s, aspoň 5 toků) a agregovaný počet paketů za okno. Obojí se porovná s historií klíče: robustní z-skóre z mediánu a MAD v log prostoru, MAD ≥ 0,15, z ≥ 6, poměr ≥ 3×. Při studeném startu se srovnává se skupinou služeb stejného `proto/port` (≥ 5 členů, poměr ≥ 4×). Bez historie i bez skupiny se jen sbírá.
- **`inductive_volume_anomaly` (A02, A03):** srovnání služeb v jednom cyklu nahradila baseline klíče po 3h pásmech dne. Pásmo drží okno posledních 8 pozorování (≈ 1,3 dne), klíč celkem dalších 8. Detekuje se podle počtu toků (≥ 3×, přírůstek ≥ 10) nebo bajtů (≥ 5×, ≥ 10 MB), minimálně 4 pozorování. Absolutní pravidlo `count/10` je pryč. Gating: alarmový vzorek se do historie učí jen oříznutý na medián + 3 MAD (RQ2 Z3, nízká jistota) a první pozorování, které je hned anomálií, se neučí. Studený start řeší skupina podobných služeb.
- **`unexpected_traffic` (A08, A09, A13):** úspěšná spojení na neinventarizovaný port známého hostu dávají `unexpected_traffic` (neznámá otevřená služba). Pokusy S0/REJ bez odpovědi se přičtou zdroji jako `scan_attempts`: ≥ 8 distinktních cílů za 24 h, takže se nasčítá i pomalý sken. Provoz na adresu, kterou inventář nezná, dává jeden souhrn na adresu. `unmapped_passive_event` se agreguje na (cíl, proto, port, typ události). Inventář je perzistentní s hysterezí: host chybějící ve skenu zůstává 2 skeny, služba 1 sken, a restart ho nesmaže. Dominantní zdroje se uvádějí v události (`zdroje: ip (podíl)`) i pro legacy vzory (timeout), aby paměť mohla eskalovat a kontext porovnat zdroj.

**Ablace** (každá konfigurace proti stejnému legacy rameni; kumulativně B → E, pak plné v3 bez jedné změny; „čeká na člověka FP“ = odlišné FP stavy, které člověk uvidí):

| konfigurace | zobrazené / síť-den (změna, 95% CI) | zobrazené FP / síť-den (změna, 95% CI) | čeká na člověka FP stavů / síť-den | zavření / příčinně omylem (95% CI) | identita split / merge |
|---|---|---|---:|---|---|
| legacy | 5 914,6 | 532,7 | 153,9 | – | 35,4 / 24,5 % |
| B: paměť | 146,7 (−97,5 %, −97,8 až −97,0) | 70,5 (−86,8 %, −88,9 až −84,2) | 67,4 | – | 35,4 / 24,5 % |
| C1: + rate | 141,5 (−97,6 %) | 68,5 (−87,1 %, −89,7 až −83,0) | 45,9 | – | beze změny |
| C2: + volume | 95,8 (−98,4 %) | 31,2 (−94,1 %, −95,6 až −92,1) | 29,8 | – | beze změny |
| C3: + unexpected | 88,8 (−98,5 %) | 22,4 (−95,8 %, −97,1 až −93,9) | 22,1 | – | beze změny |
| D: + kontext | 88,2 (−98,5 %) | 22,4 (−95,8 %) | 22,1 | 1 784 / 1,2 % (0,8 až 1,8) | beze změny |
| E: + identita (plné v3) | 81,7 (−98,6 %, −99,0 až −98,2) | 22,2 (−95,8 %, −97,1 až −94,0) | 21,9 | 1 784 / 1,2 % (0,8 až 1,8) | 14,3 / 8,6 % |
| v3 bez paměti | 5 498,9 (−7,0 %) | 37,3 (−93,0 %) | 24,1 | 1 928 / 1,5 % | 14,3 / 8,6 % |
| v3 bez rate | 102,8 | 40,3 (−92,4 %) | 37,7 | 2 872 / 1,3 % | |
| v3 bez volume | 123,9 | 57,6 (−89,2 %) | 35,8 | 2 068 / 1,2 % | |
| v3 bez unexpected | 88,4 | 31,0 (−94,2 %) | 29,7 | 1 193 / 1,3 % | |
| v3 bez kontextu | 82,2 | 22,2 (−95,8 %) | 21,9 | – | |

**Čtení:**
- Paměť dělá většinu poklesu zobrazených položek. Bez ní v3 zobrazuje 5 499 položek na síť-den, protože se opakují i statické expozice.
- Detektory dělají většinu poklesu FP. Po odebrání `volume` stoupne zobrazené FP 2,6×, po odebrání `rate` 1,8×, po odebrání `unexpected` 1,4×.
- Kontext k zobrazeným FP téměř nic nepřidá: nálezy, které zavírá, jsou připsané benigním událostem (nejsou FP z definice) a většinu opakování už potlačila paměť. Zobrazené položky sníží jen o 0,7 %.
- Identita sníží zobrazené položky o 7 %, protože méně nových assetů znamená méně „prvních výskytů“.

Zobrazené FP podle typu (legacy → v3, na síť-den): `inductive_volume_anomaly` 346,3 → 0,5, `packet_rate_spike` 116,4 → 5,5, `unmapped_passive_event` 44,6 → 1,5, `connection_timeout_burst` 19,3 → 14,6, `service_overload_risk` 3,8 → 0,1, `unexpected_traffic` 2,3 → 0,0. Zbývající šum tvoří hlavně `connection_timeout_burst` (66 %), který tento krok neměnil (legacy logika, A07).

## D) Kontextové vyloučení

- **Rozhraní** `ContextProvider` (produkce: `StaticCalendar` z `context-calendar.json`). Každý záznam má druh, hosty, případně zdroje, okno, explicitní typy, schvalovatele a expiraci. Okno delší než 31 dní, záznam bez schvalovatele a záznam pro celou síť (kromě výpadku senzoru) se odmítnou.
- **Druhy:** záloha, dávka, patch okno, údržba, autorizovaný skener, výpadek služby, výpadek senzoru, nasazení a vyřazení zařízení (CMDB).
- **Mantinely (Dodatek A.2):**
  - (a) důvod jde do auditu paměti a zavření je vratné,
  - (b) audit 10% vzorku zavřených; druh kontextu se v síti automaticky vypne, když dolní mez 95% Wilsonova intervalu omylu přesáhne 2 % (aspoň 30 vzorků, H-A3),
  - (c) statické expozice z inventáře se kontextem nezavírají nikdy; nejzávažnější typy (IDS, `multi_target_pattern`, `service_overload_risk`, `external_flow_observed`) a cokoli se závažností High jen při explicitně vyjmenovaném typu i hostu v záznamu,
  - (d) zavírá se jen při shodě s konkrétním záznamem, „nic nenalezeno“ vysvětlení není,
  - strop je 200 zavření na cyklus,
  - **zdrojová konzistence:** dominantní zdroj nálezu, který záznam nezná, vysvětlení ruší (útok uvnitř okna údržby),
  - patch okno a údržba vysvětlují timeouty, ne nárůst objemu; eskalace objemu se v okně potlačí jen u zálohy a dávky.
- **Simulace bez úniku pravdy:**
  - pokrytí: kalendář 60 % plánovaných prací, registr skenerů 70 %, monitoring výpadků 50 %, CMDB 50 %, stav senzoru 80 %,
  - rozhoduje deterministický hod podle id události,
  - okna jsou o cyklus širší než skutečná práce,
  - fantomová okna údržby, která se nekonala, přijdou s pravděpodobností 0,3 na síť a den (příležitost zavřít útok omylem),
  - flash crowd, NTP, retry storm, collector replay a poškozené logy kontext nemá.

**„Zavřeno omylem“: dvě definice.**
- **Příčinná (primární):** útok v tom cyklu posílal toky na cíl (ip, port) zavřeného nálezu nebo z jeho dominantního zdroje. Odpovídá tomu, co posoudí člověk při auditu: skrylo zavření útok?
- **Široká:** nález jen zmiňuje klíčovou IP útoku v okně. Nadhodnocuje u útoků s mnoha oběťmi. Horizontální sken má až 1 500 obětí, takže timeout na spadlém serveru, který je náhodou jednou z nich, se počítá jako omyl, i když ho sken nezpůsobil.

| | počet | podíl | 95% CI |
|---|---:|---:|---|
| automatická zavření | 1 784 | | |
| příčinně omylem | 21 | 1,18 % | 0,77 až 1,79 % |
| široce omylem | 258 | 14,46 % | 12,91 až 16,17 % |
| audit 10% vzorku (příčinně) | 1 / 162 | 0,62 % | 0,11 až 3,41 % |

**Navržená mez a zdůvodnění:** bodový odhad příčinného omylu ≤ 2 % a horní mez 95% CI ≤ 5 %. Hodnoty 2 % a 5 % jsou H-A2 z Dodatku A (zamítnutí při horní mezi > 5 %). Bod 2 % leží na horní hraně publikovaných provozních čísel: AACT 1,36 % zmeškaných (RQ1-048/049, nízká jistota), Carbon Filter 0 až 5,7 % (RQ3). Horní mez 5 % potřebuje dost zavření, aby nebyla prázdná: pro 0 omylů je to ≈ 75 zavření. Výsledek: **mez splněna** (1,18 %, horní mez 1,79 %). Široká definice by mez nesplnila. Uvádím ji, aby čtenář viděl rozdíl definic, ne jako výsledek. Automatické vypnutí druhu kontextu (H-A3) se v těchto bězích nespustilo.

Ve zkušebním běhu bez zdrojové konzistence a s patch oknem pokrývajícím i objem byla široká míra 11,3 %. Příčinná metrika tehdy ještě neexistovala, takže vliv obou úprav brány na příčinnou míru změřený nemám.

## E) Identita (35,4 % rozděleno, 24,5 % sloučeno)

- **Příčina v enginu:** `IdentityResolver` bez MAC (podsítě mimo L2 dosah skeneru, `1 + podsítí/6`) bral identitu jen z IP. Každá změna DHCP (1 %/cyklus, u mobilů 4 %) vyrobila nový asset a přidělení adresy jinému zařízení assety slilo. Jméno hostu z nmapu ignoroval.
- **Příčina v harnessu:** jméno hostu bylo vždy jedinečné `role-id`, nerealisticky dokonalé, takže by únik pravdy hrozil při jakémkoli použití. Teď je realisticky neúplné: servery 95 %, stanice 90 %, telefony 30 % jedinečné / 30 % generické („iPhone“, „android“) / 40 % žádné, VoIP 60 %, IoT a ostatní 50 %.
- **Restart** inventář mazal jen v legacy. Registrace identity restart přežívala i dřív (serializace resolveru); v3 ji ukládá v `identity-registry-v3.json` (produkce) a v `kv` (soak).
- **Oprava (v3):** MAC > jméno hostu (jen negenerické a ve snímku jedinečné) > IP. IP-only asset se nesloučí, pokud na adrese dřív bylo jiné jméno. Hosty dočasně držené perzistentním inventářem nejsou čerstvé pozorování: nepočítají se do jedinečnosti jmen a dostanou poslední asset své IP. Bez toho se jméno přesunutého zařízení objevilo dvakrát a identita se rozpadla. Projevilo se to v prvním měření (beze změny proti legacy) a opravil jsem to.
- **Výsledek:** rozděleno 35,4 % (34,9 až 35,9) → 14,3 % (14,0 až 14,7), sloučeno 24,5 % (24,2 až 24,8) → 8,6 % (8,4 až 8,8), n = 38 040 zařízení.
- **Zbytek:** zařízení bez MAC i bez jedinečného jména (mobily, IoT). Bez DHCP logů (`dhcp.log`) je dál dohledat nelze.

## Ochrana recallu po rodinách

Zobrazené položky, párově, 95% bootstrap CI přes sítě. Plná tabulka je v `reports/ab-main.md`.

| rodina | n | legacy | v3 | v3 − legacy (p. b.) | placebo legacy / v3 | nad pozadím v3 − legacy (p. b., n placebo) |
|---|---:|---:|---:|---|---|---|
| ssh_bruteforce | 389 | 94,9 % | 88,9 % | −5,9 (−10,7 až −2,0) | 71,3 / 6,4 % | +58,9 (+49,6 až +68,3; 314) |
| port_scan_vertical | 331 | 65,9 % | 92,1 % | +26,3 | 59,2 / 4,6 % | +82,3 (282) |
| exploit_attempt | 278 | 65,1 % | 16,9 % | −48,2 (−56,7 až −40,5) | 61,9 / 4,7 % | +8,9 (−0,8 až +18,4; 236) |
| c2_beacon | 215 | 13,5 % | 14,4 % | +0,9 | 13,4 / 7,5 % | +6,0 (0,0 až +12,5; 134) |
| port_scan_horizontal | 204 | 91,2 % | 83,8 % | −7,4 (−13,1 až −2,4) | 74,5 / 33,3 % | +25,5 (51) |
| lateral_movement | 190 | 90,0 % | 59,5 % | −30,5 (−41,3 až −21,2) | 83,7 / 36,7 % | +4,1 (−11,9 až +20,0; 49) |
| web_exploit | 175 | 94,9 % | 90,3 % | −4,6 | 77,2 / 5,7 % | +65,9 (123) |
| credential_stuffing | 162 | 98,8 % | 93,8 % | −4,9 | 85,2 / 7,8 % | +72,7 (128) |
| slow_scan | 162 | 95,7 % | 98,8 % | +3,1 | 75,0 / 57,1 % | +39,3 (28) |
| dns_tunnel | 125 | 98,4 % | 39,2 % | −59,2 (−71,4 až −46,7) | 100,0 / 13,4 % | +25,4 (+11,3 až +38,8; 67) |
| ddos_volume | 110 | 96,4 % | 91,8 % | −4,5 | 70,3 / 3,3 % | +62,6 (91) |
| exfiltration | 103 | 63,1 % | 5,8 % | −57,3 (−66,2 až −48,5) | 57,3 / 6,7 % | −3,4 (−13,7 až +8,3; 89) |
| rogue_device | 73 | 11,0 % | 94,5 % | +83,6 | 0,0 / 7,5 % | +74,6 (67) |

**Výklad:**
- Legacy „detekuje“ dns_tunnel ve 100 % placebo oken. Vysoká čísla v tabulkách v1 a v2b pro DNS tunel, exploit, ssh, web a credential stuffing jsou tedy z velké části shoda s vytíženým serverem.
- V3 snížilo placebo pod 8 % u většiny rodin. Rodiny s mnoha oběťmi (lateral, horizontální sken, slow scan, ransomware) mají placebo dál vysoké, protože některý z mnoha cílů má vždycky nějaký nález.
- **Skutečné ztráty v3:**
  - Exfiltrace: odchozí tok na externí cíl je mimo scope (A10), v3 ho nevidí a legacy jen náhodou.
  - Správný typ: credential_stuffing 71,6 → 40,1 %, web_exploit 43,4 → 27,4 %, dns_tunnel 98,4 → 35,2 %, exfiltration 57,3 → 4,9 %, c2_beacon 7,9 → 2,8 %. Legacy dostávalo „správný typ“ od náhodných nálezů typů, které rodina v `expected_types` má. V3 tyto útoky zachytí hlavně jako `inductive_volume_anomaly`, který v jejich seznamu není.
  - Exploit má správný typ 0 % v obou ramenech (R3, Suricata mapování, není v tomto kroku).

**Cíl A/B:**
- Pokles zobrazených položek a FP ≥ 70 %: splněno, −98,6 % a −95,8 %.
- Zavřeno omylem pod mezí: splněno, 1,18 %, horní mez 1,79 %.
- Ztráta recallu ≤ 5 p. b. u rodin s ≥ 100 útoky:
  - surově NESPLNĚNO u 6 rodin,
  - nad pozadím splněno u všech rodin s ≥ 100 placebo okny (ssh, port_scan_vertical, exploit, c2, web, credential),
  - u rodin s < 100 placebo okny nerozhodnutelné; exfiltrace má bodově −3,4 p. b. s širokým CI.

Doporučení: v3 ponechat za přepínačem (výchozí `legacy`). Za výchozí ho přepnout až po kroku s R2 (egress) a R3 (Suricata) a po potvrzení na držených seedech, protože kritérium recallu v surové podobě neprošlo a korekce placebem je nová metrika, kterou zatím nikdo nezávisle neověřil.

## Výkon a stabilita

- 0 panik a 0 porušených invariantů ve všech 14 ramenech.
- Medián p99 doby cyklu legacy 586 ms, v3 251 ms. Maximum p99 je 35,5 s proti 11,5 s.
- Souhrnný CPU čas epizod: legacy 541 min, v3 88 min. Hlavní důvod je méně ověřovacích plánů.
- Paměť nálezů má nejvýš 8 711 položek na síť.

## Studie tvrdily chybně (nebo neověřeně)

1. 01-analyza A08 a §4.3: `unexpected_traffic` není hlavně zastaralý inventář. Je to artefakt generátoru (port kontejneru); po opravě harnessu zbývá 2,3 FP/síť-den.
2. Tabulky detekce v1 a v2b nadhodnocují detekci kvůli shodě s pozadím (placebo 57 až 100 %). „Detekováno (jakýkoli nález)“ se jako ochranná metrika bez korekce nedá použít, přesně jak varovalo A31.
3. Párové A/B na stejných seedech (§7.3) nebylo se starým harnessem párové (spotřeba RNG závislá na enginu, zpětná vazba zásahů). Opraveno a otestováno.
4. Identita ve v2b: hypotéza „restart maže inventář“ pro identitu neplatí, registrace restart přežívala. Rozhodla identita jen podle IP a chybějící jména hostů.

## Co zůstává

- `connection_timeout_burst` tvoří 66 % zbylých zobrazených FP. Další krok je rozlišit podle rozložení zdrojů: „služba nedostupná“ (provozní stav) proti skenu nebo hádání hesel (A07, R6a).
- Egress (R2) a Suricata mapování (R3) kvůli exfiltraci, C2 a typu exploitů.
- Úprava `expected_types` u rodin, které v3 zachytí jako objemovou anomálii (rozhodnutí o definici „správného typu“, ne ladění).
- Plný kontrafaktuál (`mask_truth`) místo atribuce oknem u window-scoped událostí.
- Potvrzení na držených seedech, jednou.
- Kotva CTU-13/IoT-23 pro prahy v3, které jsou laděné jen na simulátoru (riziko A34/B6).
- UI zobrazení `findingLifecycle` (jiná práce).
- Pro produkci: `context-calendar.json` musí plnit člověk (Pásmo B). Prahy v3 i pokrytí kontextu jsou volba autora.

## Známé výjimky testů

`cargo test --lib` prochází kromě testů, které potřebují Docker (`identity_lab`), Redis (`broker::*`, `tests/broker_two_process.rs`) a testů časování lease v `platform::*` pod zátěží. Mimo knihovnu neprojde ještě `tests/e2e.rs::autopilot…`, který potřebuje httpx. Na všechny tyto soubory tento krok nesahal. Golden snapshot, `tests/engine_v3.rs` a ostatní integrační testy procházejí. `cargo clippy --all-targets` má stejný počet varování jako výchozí stav (lib 86, lib test 94, bin 3, e2e 1).
