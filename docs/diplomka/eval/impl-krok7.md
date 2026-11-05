# Implementace, krok 7: zadržení, invarianty a detekce bez neřízených slepých míst

Datum 2026-11-05. Výchozí stav: krok 6 hotov (`impl-krok6.md` včetně review kol 1 až 3). `legacy` je výchozí, v3 volitelné s presetem kroku 6 (`v3k6` = preset kroku 5 + `sensor_strict` + `novelty`). Council (Claude Opus 5.5, GPT-6.1 Sol, DeepSeek) hodnotil krok 6 na 7, 6 a 6,5 z 10: návrh 8 až 8,5, důkazy 4 až 5,5. Doporučil krok 7 v pořadí zadržení a invarianty (A), detekce (B), evaluace (C).

Čísla, ze kterých se vychází, jsou z kroku 6 (držené seedy 20261701 a 20261801, rameno `v3k6` proti `legacy`, `k6/held-*.md`), ne z kroku 5:

| metrika | `legacy` | `v3k6` |
|---|---:|---:|
| detekce (cf, fronta podezření) | 59,5 % | 78,4 % (74,8 až 81,8) |
| zobrazené FP na síť-den | 900,8 | 13,1 |
| zavřeno omylem (G3) | – | 33 / 1 320 = 2,5 % (1,8 až 3,5) |
| K3 (fronta podezření) | – | 84,0 % proti 69,3 % |
| LOFO (náhrada vynecháním typů) | – | 2 ze 6 |
| exploit_attempt | 21,9 % | 39,5 % (n = 233) |
| lateral_movement | 69,5 % | 67,0 % (n = 197) |

**Cílové tvrzení.** Uvnitř deklarovaného rozsahu (19 simulovaných rodin × parametrické osy z kroků 5 a 7, 18 provozních poruch a lookalike, zvolené veřejné datasety) je každá buňka s n ≥ 20 v jedné ze tří kategorií:

- **(a) zachycena:** detekce ≥ 70 % a dolní mez Wilsonova 95% intervalu ≥ 60 %;
- **(b) vedená:** naměřená míra je uvedená a mitigaci vynucuje kódová invarianta s property testem (nikdy automaticky nezavřít, nikdy habituovat, nikdy neodklonit z fronty podezření, vždy zobrazit);
- **(c) netestovaná:** n < 20.

Mimo rozsah jsou výslovně taktiky jen na hostu (Execution, Persistence, Privilege Escalation), exploit bez IDS signatury a šifrované payloady. Invarianta (b) nezachrání nález, který nikdy nevznikl. Pomůže jen detekce, proto se (b) uvádí vždy s naměřenou mírou detekce.

Omezení (beze změny proti kroku 6): žádné nové útočné techniky, jen parametrické variace existujících rodin, veřejná data a obecné detektory. `engine.mode` zůstává `legacy` až do G4 (XXXL p99 cyklu < 3 s na klidném stroji). G4 se měří až po skončení obou 72h běhů (PID 45080 a 50240, přibližně 2026-11-07 večer). Zátěž: priorita Idle, nejvýš 6 vláken, nejvýš 2 ramena současně. Nic se neodesílá ven.

## A) Zadržení a invarianty (návrh před implementací)

### A1. Chráněné nálezy

Nález je **chráněný**, když platí aspoň jedno:

| # | třída | podmínka |
|---|---|---|
| P1 | novost | typ `novel_persistent_peer`, `novel_fanout`, `novel_burst_peer` |
| P2 | graf | typ `pivot_chain` |
| P3 | signatura (exploit) | typ `suricata_alert`, `egress_ids_alert`, `ids_alert` |
| P4 | degradované pozorování | v čase nálezu nebo v předchozím cyklu platí kontext výpadku senzoru (mezera v telemetrii), nebo jde o behaviorální nález (vrstva kroku 3) vnitřního aktéra, jehož profil je mladší než 48 h |
| P5 | nejednoznačný kontext | identita hostu je nejednoznačná (`IdentityMatch::Ambiguous`), nebo záznam kontextu odpovídá hostu a typu, ale byl odmítnut kvůli zdroji mimo záznam nebo kvůli P6 |

**P6 (kontextové zavření nálezu vysoké závažnosti nebo bez identifikovaného zdroje):** kontext ho zavře jen tehdy, když ve stejném čase platí aspoň dva různé druhy kontextu (`ContextKind`), každý by nález sám vysvětlil a žádný není výpadek senzoru. Jinak kontext odmítne a nález je P5.

Chráněný nález:

1. kontext ho nezavře (`explain` vrací `None`) ani nedá žebříku podpůrný důkaz;
2. paměť nálezů ho nikdy nepřevede do `AutoResolved` ani `Refuted`. Uložená položka chráněného typu v těchto stavech se po načtení převede na `Closed` (další výskyt ji znovu otevře a zobrazí) a převod se zapíše do auditu;
3. žebřík ho nevyvrátí: rozhodnutí `Refuted` se změní na `Escalated` (člověk) a zapíše se důvod. Uložený případ chráněného typu s neškodným důkazem se po načtení resetuje stejně jako novost v kroku 6;
4. zobrazí se hned při vzniku stavu (jako vysoký dopad), ne až po ověření;
5. třída provoz ho z fronty podezření nikdy neodkloní (platí pro všechny nálezy, viz B1).

Přepínač `protect` (v3), mimo preset až do rozhodnutí v sekci E. Produkční invarianty A3 a A4 přepínač nemají.

**Property testy** (vlastní deterministický generátor, bez nové závislosti): náhodné posloupnosti pozorování, vysvětlení kontextu, rozhodnutí žebříku, zápisů a načtení stavu (restart) a ručních zásahů. Po každém kroku platí: chráněný klíč není `AutoResolved` ani `Refuted`, dispozice chráněného pozorování není `AutoResolved` a rozhodnutí žebříku o chráněném případu není `Refuted`. Druhý test přehraje uložené uzavřené případy (paměť v SQLite a žebřík v JSON se zakázanými stavy) všemi dalšími cestami: načtení, pozorování, krok žebříku, obnovení.

### A2. Tiché potlačení

Metrika v soaku (rameno s pamětí nálezů), po útocích:

- **viditelnost:** podíl cyklů útoku od jeho prvního zobrazení ve frontě podezření do konce, ve kterých je některý jeho připsaný klíč otevřený a byl zobrazen (stav `new`, `open`, `reopened` nebo `confirmed`);
- **ztráta viditelnosti:** útok, který po prvním zobrazení měl aspoň jeden cyklus bez viditelného klíče. Příčina podle stavu klíčů: `ladder` (vyvráceno), `context` (automaticky vyřešeno), `quiet` (24 h bez výskytu, tedy i zvyk profilu), `evicted` (strop paměti), `ops` (fronta provoz);
- **habituace:** útok, jehož dvojice (aktér, protistrana z klíčových IP útoku) se během útoku stala zavedeným zvykem profilu.

Spočítá se na konfiguraci kroku 6 (`v3k6`) na seedech 20261701 a 20261801. Stávající výstupy kroku 6 stav po cyklech neobsahují, proto se běh zopakuje s binárkou, která metriku zapisuje. Ostatní pole musí zůstat bajtově stejná. Totéž se pak spočítá pro `v3k7`.

**Invarianta profilu:** dvojice s poplachem typu novost nebo graf je poznamenaná. Poznamenaná dvojice se nesmí stát zvykem a poznámka se nesmí ztratit dřív než za `forget_s` (14 dní) a ani kvůli stropu zvyků hostu. Ze stropu se vyřazují nejdřív nepoznamenané kandidáty. Kryje to property test přes učení, zametání a serializaci. Patří pod přepínač `protect`, takže rameno `v3k6` zůstává beze změny.

### A3. Provozní audit uzavření

Produkční cesta (`pipeline/v3.rs`), dnes bez auditu (`record_audit` volají jen soak a testy):

- každé automatické zavření (kontext podle druhu, žebřík jako druh `ladder`) se s pravděpodobností 10 % (deterministicky podle tajného klíče instalace a klíče nálezu) zařadí do vzorku pro člověka s termínem 72 h;
- API `GET /api/closure-audit` (stav, čekající vzorky, vypnuté druhy) a `POST /api/closure-audit/{id}/review` (`{"wrong": bool, "note": ...}`), autentizace a CSRF stávajícím mechanismem (`findings.write`);
- druh se trvale vypne, když dolní mez Wilsonova 95% intervalu omylu > 2 % při aspoň 30 recenzích. Vypnutí přežije restart (SQLite), vrátí ho jen člověk přes API a zapíše se do auditu. Dolní mez nad 2 % je doklad, že omyl cíl překračuje. Není to certifikace, že omyl je pod horní mezí: druh, který vypnutý není, nemá prokázanou chybovost ≤ 2 %;
- fail-safe: když existuje vzorek po termínu nebo je čekajících víc než 50, automatické zavírání se pro všechny druhy zastaví (kontext nezavírá, vyvrácení žebříkem jde člověku), dokud backlog nezmizí. Bez recenzí se tedy po 72 h nezavírá nic;
- auditní stopa: vzorek, recenze, vypnutí, obnovení i zastavení se zapíše do `finding_audit` (append-only).

Test: jedno produkční zavření kontextem projde vzorkováním, recenzí přes API, vypnutím po překročení meze a restartem (vypnutí platí dál), a samostatně běží fail-safe po termínu.

### A4. Viditelnost degradace pokrytí

`RunReport.coverage_status` (API a data UI, bez zásahu do vzhledu UI): `degraded`, seznam důvodů a příznak `deployment_blocking`. Důvody:

- `no_ids`: chybí IDS (žádné alerty ani zdroj IDS), takže exploit bez signatury je mimo rozsah;
- `immature_profiles`: podíl vnitřních hostů s profilem mladším než 48 h;
- `telemetry_gap`: platí výpadek senzoru, nebo okno toků je prázdné či kratší než polovina cyklu;
- `low_ics_data`: v inventáři je průmyslové zařízení, ale toků průmyslových protokolů je málo.

Blokující příznak: `no_ids` nebo `telemetry_gap`. `exploit_attempt` (IDS typy, P3) se vždy ukáže člověku a nikdy se automaticky nezavře.

## B) Předregistrace (zamčeno commitem před prvním měřicím během)

Sekce B se po prvním měřicím běhu nemění. Oprava chyby harnessu nebo kandidáta se zapíše jako odchylka do sekce D. Prahy, seedy ani definice se po pohledu na držená data nemění.

### B1. Rotace seedů a světů

| účel | seedy | svět | sítí |
|---|---|---|---:|
| ladění kandidátů a výběr sestavy | 20261701, 20261801 | `--coverage full --families all` | 2 × 40 |
| kontrola sestavy před drženým během | 20261401, 20261501 | totéž | 2 × 40 |
| **držené, jeden běh** | **20261901, 20262001** | `--coverage k7 --families all` | 2 × 40 |
| ICS, držené | 20262101 (a 20262102, jen pokud ics_attack n < 50) | `--coverage k7 --size industrial` | 40 (+ 40) |

Držené položky kroků 5 a 6 jsou teď ladicí: držené rodiny, držené úrovně os, poruchy cert_expired, segment_power_loss, vpn_reconnect_storm, cloud_migration, lookalike `saas_adoption` a seedy 20261401, 20261501, 20261701, 20261801. Svět `full` zůstává bajtově stejný.

**Nové držené parametrické varianty** (jen `--coverage k7`, vlastní větev výběru, ladicí svět je nevidí):

| osa nebo položka | `full` | `k7` přidává |
|---|---|---|
| tempo | 0,25× až 8× | 0,125×, 16× |
| rozptyl | 0,15; 0,3; 0,5 | 0,7 |
| zdroje | 3; 10 | 30 |
| doba | 0,5×; 2×; 4× | 0,25×, 8× |
| objem | 0,25×; 0,5×; 2× | 0,125×, 4× |
| intenzita | 0,05 až 1,0 | 0,02 až 1,0 |
| `saas_adoption` | 1 klient | 2 až 5 klientů téže služby (`saas_group`, polovina výskytů) |
| `cert_expired` | port 443 | port 8443 (polovina výskytů) |
| intenzita poruch kroku 5 | 0,4 až 1,0 | 0,05 až 1,0 |

Index S zůstává definovaný jako v kroku 5, hranice pásem `--edges 0.1718,0.2363,0.3053,0.3917`. Nové úrovně dávají S nejvýš 1 na složku (strop).

**ICS (`--size industrial`):** každá síť má vynucený archetyp Industrial, ostatní generování je beze změny. Cíl je n ≥ 50 pro ics_attack. Pravidlo zastavení: když je po 40 sítích seedu 20262101 n < 50, přidá se 40 sítí seedu 20262102 a víc už ne.

### B2. Ramena

Jedna binárka (release, `CARGO_TARGET_DIR=F:/claude-tmp/target-soak`, commit zapsaný v sekci D). Společné volby: `--block-size 2 --no-legs --no-feedback --counterfactual --max-networks 40`, šum 1×, bez kalibrace. Zátěž: 2 ramena současně, 3 vlákna každé, priorita Idle, kontrola zatížení před spuštěním.

| rameno | konfigurace |
|---|---|
| `legacy` | `--engine legacy` |
| `v3k6` | `--engine v3` (preset kroku 6, beze změny až do rozhodnutí v sekci E) |
| `v3k7A` | `--engine v3 --v3-on protect` (preset kroku 6 + invarianty A1; A3 je jen produkční cesta, soak má vlastní simulovaný audit) |
| `v3k7A+X` | `v3k7A` + kandidát X z B3 (jen ladicí seedy) |
| `v3k7` | `v3k7A` + kandidáti, kteří prošli B4 |
| `lofo-X` | `v3k7` s maskou typů D(X) a signatur (C3), jen držené seedy |

### B3. Kandidáti detekce (každý za přepínačem, parametry dané v kódu před prvním během)

| # | přepínač | co dělá | kill kritérium (ladicí seedy, párově) |
|---|---|---|---|
| B1 | `ops_annotate` | Třída provoz je jen ANOTACE: zobrazený nález s důkazem provozní příčiny zůstává ve frontě podezření a dostane jen značku `ops_reason`. Oprava klíče služby pro E1: `unmapped_passive_event` a `service_unreachable` bez portu se porovnají s důkazem hostu cíle, ne s klíčem nálezu. | útoky zobrazené jen ve frontě provoz > 0 (invarianta, test); útoky s provozní značkou na připsaném nálezu > 3 % útoků; přesnost značky (poruchy / (poruchy + útoky) mezi označenými výskyty) < 80 % |
| B2 | `graph` + `graph_incident` | Graf `pivot_chain` (chráněný typ P2: nevyvratitelný slabým kontextem ani profilem, nikdy automaticky nezavřít) a deduplikace incidentu: všechny hopy jednoho pivotu a kořene jsou jeden klíč paměti | zobrazené FP > 1,15 × `v3k6`, nebo zavřeno omylem (počet) > `v3k6` |
| B3a | `novel_burst` | `novel_burst_peer`: zralý host, 3 úspěšná okna během 6 h, vzácný vnější cíl (flotila ≤ 2), závažnost Low, jistota Low, chráněný typ P1 | FP ve frontě podezření u `saas_adoption` > +5 p. b., nebo zobrazené FP celkem > +5 % |
| B3b | `fanout2` | `novel_fanout` (8 nových vnitřních vazeb za 6 h) jen s druhým signálem: host má zároveň novou vazbu ven (stav novosti), nebo ho v posledních 6 h nově kontaktoval jiný vnitřní host (pivot) | zisk lateral_movement < 5 p. b., nebo zobrazené FP > 1,15 × |
| B4 | `cross_source` | Agregace přes zdroje: na jednu vnitřní službu aspoň 10 zdrojů jen se selháním nebo novou vazbou, z toho aspoň 70 % nejsou dosavadní klienti služby (opak E1) → nález `distributed_sources` (jen podezření, chráněný proti zavření jako P5) | zobrazené FP > +5 %, nebo roste záměna provoz a útok (poruchy s nálezem `distributed_sources` > 5 % výskytů poruch) |
| B5 | `saas_group` | Opakovaná upozornění na jednu novou vazbu ven se seskupí do jednoho incidentu (klíč host a vnější /24), incident zůstane nevyřešený a nezavírá se. Úzký expirující souhlas člověka (host, cíl, protokol a port, nejvýš 30 dní) přes API. Souhlas jen potlačí nový poplach téže dvojice, profil se dvojici z trvání nenaučí (poznamenání zůstává). | počet zobrazených položek na výskyt `saas_adoption` neklesne aspoň o 30 %, nebo detekce c2_beacon či dns_tunnel klesne o víc než 1 p. b. |

Společné kill kritérium všech kandidátů: rodina s n ≥ 100 klesne o víc než 3 p. b., nebo se automaticky zavře chráněný nález (soakové počítadlo musí být 0). Každý kandidát smí projít nejvýš jednou úpravou parametrů na ladicích seedech a ta se zapíše s čísly před a po.

### B4. Výběr sestavy `v3k7`

`v3k7` = `v3k7A` + kandidáti, kteří na ladicích seedech 20261701 a 20261801 nesplnili žádné kill kritérium. Sestava se před drženým během jednou ověří na kontrolních seedech 20261401 a 20261501 proti `v3k6`: detekce ≥ 0 p. b. (bod), zobrazené FP ≤ 1,15 ×, zavřeno omylem počtem ≤ `v3k6`. Když sestava neprojde, vypouští se kandidát s nejhorším poměrem FP / přínos, dokud neprojde.

### B5. Metriky (C2)

- **Detekce útoku:** kontrafaktuální zobrazená detekce ve frontě podezření (definice kroku 6).
- **Zavřeno omylem počtem:** kontrafaktuálně omylem zavřené nálezy (kontext + žebřík), celkem a na útok: počet útoků s aspoň jedním takovým nálezem a rozdělení počtu na útok. Podíl G3 se hlásí dál.
- **Intervaly:** Wilson pro podíly v buňkách, bootstrap clusterovaný po sítích a stratifikovaný po seedech (B = 2000) pro souhrny, poměry a párové rozdíly.
- **Makro-průměr** detekce přes rodiny (každá rodina váhou 1) vedle mikro-průměru.
- **Latence první detekce:** cykly od začátku útoku do prvního zobrazení ve frontě podezření (medián a 90. percentil, jen detekované útoky).
- **Zátěž analytika:** zobrazené položky na síť-den (všechny, nejen FP).
- **Vícenásobná srovnání:** kategorie (a) se počítá dvakrát. Bez korekce: bod ≥ 70 % a Wilsonova dolní mez ≥ 60 %. S Holmovou korekcí: jednostranný přesný binomický test H0: p ≤ 0,60 na hladině 0,05 pro rodinu všech buněk s n ≥ 20 a bod ≥ 70 %. Tvrzení práce používá variantu s korekcí.
- **Párová srovnání** `v3k7` − `v3k6`, `v3k7` − `legacy` a `v3k6` − `legacy` na stejných sítích.
- **Tiché potlačení** (A2), **ops-only útoky** (B1) a **chráněná automatická zavření** (počítadlo, musí být 0).

### B6. Prahy (držené seedy 20261901 a 20262001, rameno `v3k7`, jeden běh; rozhoduje bodový odhad, kde není uvedeno jinak)

| práh | definice | splněno, když |
|---|---|---|
| K6 | zavřeno omylem (G3) | horní mez Wilsona ≤ 5 % (cíl ≤ 2 %) |
| K6n | útoky s aspoň jedním omylem zavřeným nálezem, počet, `v3k7` proti `v3k6` | `v3k7` ≤ `v3k6` |
| S0 | chráněná automatická zavření a ops-only útoky | 0 a 0 |
| S1 | útoky se ztrátou viditelnosti příčinou `ladder` nebo `context` | `v3k7` ≤ `v3k6` |
| D1 | `v3k7` − `v3k6` po rodinách s n ≥ 100 | žádný pokles o víc než 3 p. b. |
| D2 | `v3k7` − `v3k6` souhrnně | ≥ 0 p. b. |
| D3 | `v3k7` − `legacy` souhrnně a makro | obojí ≥ 0 p. b. |
| F1 | zobrazené FP na síť-den `v3k7` / `v3k6` | ≤ 1,15 |
| L1 | zátěž analytika (zobrazené položky na síť-den) `v3k7` / `v3k6` | ≤ 1,15 |
| L2 | medián latence první detekce `v3k7` − `v3k6` | ≤ +1 cyklus |
| K3 | fronta podezření: nové držené varianty poruch `k7` (saas_group, cert_expired 8443, poruchy s intenzitou < 0,4) proti stejným druhům ve variantách `full` (stejný běh) | držené ≤ ladicí + 10 p. b. |
| K3p | párová změna po poruchách `v3k7` − `v3k6` a záměna provoz a útok (B1) | hlásí se |
| K5 | LOFO skutečnou ablací (maska typů D(X) a signatur v enginu), první útok rodiny bez signatury | zobecňuje (bod ≥ 50 %, Wilsonova dolní mez ≥ 30 %) aspoň 3 ze 4 rodin c2_beacon, ssh_bruteforce, lateral_movement, dns_tunnel; exfiltration a port_scan_vertical jsou definiční (kryje je vlastní detektor, důkazem jsou křivky skrytosti) a hlásí se zvlášť |
| ICS | ics_attack na ICS seedu | n ≥ 50 a kategorie podle cílového tvrzení |
| C | buňky s n ≥ 20 (rodina, rodina × úroveň osy, pásmo S, porucha) | každá je v (a) s korekcí, (b) nebo (c); žádná nezůstane bez kategorie |
| R | determinismus: `soak verify` na drženém výstupu, golden snapshot (legacy) zelený, svět `full` bajtově beze změny | shoda |
| K8 | panika a porušené invarianty ve všech ramenech | 0 a 0 |
| K1, K2, K4, K7 | definice kroku 5 | hlásí se |
| G4 | XXXL p99 cyklu < 3 s na klidném stroji (seedy 20261901 a 20262001, 3 sítě každý, 1 vlákno) | měří se jen po skončení obou 72h běhů. Jinak se nevyhodnotí a `legacy` zůstává výchozí. |

Výchozí režim se přepne na `v3` jen tehdy, když `v3k7` splní G1 až G5 kroku 4 (G1 a G2 proti `legacy` ve stejném běhu, G3 = K6, G4 změřený na klidném stroji, G5 = K8). Prahy K, S, D, F a L o výchozím režimu nerozhodují, rozhodují o tom, co smí práce tvrdit.

### B7. C3: K5 jako skutečná ablace

Maska `--v3-mask <typy>` odstraní nálezy vyjmenovaných typů z výstupu detekce, ještě než vstoupí do paměti, kontextu, žebříku, indexu podezření pro pivot a zmrazení učení profilu. Detektor tedy pro zbytek enginu neexistuje. LOFO rameno rodiny X maskuje D(X) z kroku 5 (A5) a signatury (`suricata_alert`, `egress_ids_alert`). Detekce se počítá jako v kroku 5 (první útok rodiny v síti, bez IDS viditelnosti) ze všech zobrazených nálezů. Kontrola: maskovaný typ se ve výstupu ramene nesmí objevit.

### B8. C5: dlouhý chronologický replay veřejných dat

Licence a dostupnost dlouhých záznamů (UGR'16, IoT-23) se ověří na oficiálních stránkách. Adaptér přehraje toky veřejného datasetu chronologicky po 30min oknech celou produkční cestou v3 (paměť, kontext, žebřík, profil, novost) v dočasném workspace. Studený start (prvních 48 h) a zralé období se hlásí zvlášť. Aktivní kontroly, které na záznamu nejdou provést, zůstanou „neznámé“ a nikdy nejsou důkazem. V tomto kroku vznikne adaptér a malý ověřovací běh. Plný běh se pustí jen tehdy, když to dovolí zátěž po skončení 72h běhů.

## C) Implementace

(doplní se)

## D) Měření

(doplní se)

## E) Registr slepých míst a tvrzení

(doplní se)

## Review

(doplní hlavní konverzace)
