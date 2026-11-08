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

Všechno nové v3 je za přepínači (`--v3-on`, `[engine.v3]`), `V3Features::recommended()` se do sekce E nemění. Výjimkou jsou A3 a A4: ty platí v produkční cestě v3 vždy (předregistrace A3 a A4 přepínač nemají), legacy se jich netýká.

| blok | soubory | co |
|---|---|---|
| A1 | `src/protection.rs` (nový), `context_gate.rs`, `finding_memory.rs`, `verify_ladder.rs`, `pipeline/v3.rs`, `soak/episode.rs`, `soak/ladder_env.rs` | Třídy ochrany P1 až P5 (`type_protection`, `Signals`, `immature_actor`). Brána: `explain_decision` vrací i nejednoznačnost; chráněný vstup kontext nezavře ani nepodpoří; P6 (vysoká závažnost nebo bez zdroje) zavře jen při dvou různých druzích kontextu, výpadek senzoru se nepočítá; `sensor_gap` (P4). Paměť: `MemoryConfig::protect`, `Observation::protected`; chráněný klíč nikdy `AutoResolved` ani `Refuted`, zakázaný uložený stav se při načtení i při pozorování převede na `Closed` s auditem `protect_reset`, `refute` chráněný typ odmítne (`protect_refuse`). Žebřík: `LadderPolicy::protect`, `CaseInput::protected`; vyvrácení chráněného případu se změní na eskalaci člověku (`protect_escalated`), kontext ani zvyk profilu nejsou u chráněného případu důkaz, uložené chráněné případy s neškodným důkazem se resetují. Soak: chráněný nález se zobrazí hned (ne až po ověření), počítadla `protected_displayed` a `protected_auto_closed`. Lifecycle v API nese `protection`. |
| A1 testy | `protection.rs` | `property_memory_never_auto_closes_protected` (60 náhodných posloupností po 300 krocích: pozorování, vysvětlení, vyvrácení, ruční zavření, zápis a načtení z SQLite, zametání), `property_ladder_never_refutes_protected` (40 posloupností, samé neškodné důkazy včetně kontextu a zvyku profilu, serializace žebříku; kontrola, že nechráněné se vyvracet dál smí), `replayed_closed_protected_cases_never_auto_close` (stav paměti a žebříku vzniklý bez ochrany přehraný načtením, pozorováním, krokem žebříku a obnovením). Ověřeno vrácením ochrany: všechny tři selžou. Brána: `protected_findings_are_never_explained_nor_supported`, `sourceless_or_high_needs_two_independent_kinds`. |
| A2 | `behavior/profile.rs`, `soak/episode.rs`, `soak/coverage.rs` | `ProfilePolicy::keep_tainted` (pod `protect`): poznamenaná dvojice se drží `forget_s` a poznámka se s opakovaným poplachem obnovuje, ze stropu zvyků se vyřazuje až po nepoznamenaných. Property test `property_tainted_pairs_never_become_habits` (selže bez opravy). Metrika po útocích `AttackK7`: viditelnost po prvním zobrazení, ztráta viditelnosti a její příčina, habituace (povýšení zvyku s dvojicí z klíčových IP útoku během útoku), počet omylem zavřených nálezů, latence. |
| A3 | `src/closure_audit.rs` (nový), `pipeline/v3.rs`, `server.rs` | Vzorkování 10 % s tajným klíčem instalace, termín 72 h, append-only `closure_reviews` (server vkládá, pipeline započte), trvalé vypnutí druhu (dolní mez Wilsona > 2 % při ≥ 30 recenzích, `closure-audit.json` jen v bezpečných mezích), fail-safe po termínu nebo nad 50 čekajícími (kontext nezavírá, vyvrácení žebříkem jde člověku), auditní stopa `audit_sample`, `audit_review`, `audit_disable`, `audit_enable`. API: `GET /api/closure-audit`, `POST /api/closure-audit/{id}/review`, `POST /api/closure-audit/kinds/{kind}/enable` (stávající autentizace, `findings.write` a CSRF). Report `closureAudit`. Integrační test `v3_closure_audit_samples_review_disables_kind_and_survives_restart` (tři procesy: zavření, vzorek, verdikt „omyl“, vypnutí, restart, druh už nezavírá). |
| A4 | `src/coverage_status.rs` (nový), `pipeline/v3.rs`, `model.rs` | `coverageStatus`: `no_ids`, `immature_profiles`, `telemetry_gap`, `low_ics_data`, `deployment_blocking` (chybí IDS nebo mezera v telemetrii), `exploit_always_shown`. |
| B1 | `ops_evidence.rs`, `soak/episode.rs`, `pipeline/v3.rs` | `ops_annotate`: značka provozní příčiny jen jako anotace (`ops_note` v API), fronta podezření beze změny; diagnostika `diagnose` (typ, tvar klíče, počet zdrojů, shoda s důkazem). Chráněný nález neodkloní ani `ops_class`. Test `k7_world_mask_and_ops_annotation_invariants`: s anotací `ops_class_displayed` = 0 a žádný útok ve frontě provoz. |
| B2 | `behavior/graph.rs` | `graph_incident`: všechny hopy pivotu jsou jeden klíč `chain/incident/tcp/0`; `pivot_chain` je chráněný typ (A1). |
| B3 | `behavior/novelty.rs` | `novel_burst` (`novel_burst_peer`, 3 okna za 6 h, Low/Low, do vyhlášení trvalé vazby), `fanout2` (`novel_fanout` s prahem 8 jen s druhým signálem). |
| B4 | `ops_evidence.rs` | `cross_source`: `distributed_sources` (≥ 10 zdrojů jen se selháním nebo novou vazbou, ≥ 70 % mimo klientelu služby), chráněný typ. |
| B5 | `behavior/novelty.rs`, `src/novelty_consent.rs` (nový), `server.rs` | `saas_group`: nová vazba ven jako incident na vnější /24 a službu; souhlas `POST /api/novelty/consent` (přesná dvojice, nejvýš 30 dní, append-only), souhlasená dvojice zůstává pro profil zmrazená. |
| C1, C3, C4 | `soak/coverage.rs`, `soak/traffic.rs`, `soak/netmodel.rs`, `main.rs` | `--coverage k7` (nové úrovně os a varianty poruch podle B1, vlastní větev výběru), `--size industrial`, `--v3-mask` (skutečná ablace: maskované typy se odstraní z výstupu detekce před pamětí, kontextem, žebříkem, indexem pivotu a zmrazením učení). |
| C2 | `tools/soak_k7.py` (nový) | Metriky B5 a kategorie buněk s Holmovou korekcí. |
| C5 | `tools/replay_public.py` (nový), `pipeline/mod.rs` | Přehrání `conn.log.labeled` po 30min oknech skutečnými běhy `beh spust` ve v3; čas běhu z `BAKULA_REPLAY_NOW` (jen evaluace, bez proměnné beze změny). |

**Zpětná kompatibilita a determinismus.** Binárka `749047d` dává na 4 sítích seedu 20261701 bajtově stejný `networks.jsonl` jako výstupy kroku 6 (`legacy` 4 ze 4 sítí, `v3k6` 2 ze 2 hotových sítí; po odečtení časových polí a nových polí `k7`). Nová pole se zapisují jen ve v3 s pamětí nálezů. Starý stav (`ladder`, `behavior`, paměť nálezů, `clientele`) se načte: nová pole mají serde výchozí hodnoty.

**Odchylka D1 (harness, před drženým během).** Počet „omylem zavřených nálezů na útok“ v binárce `749047d` počítal pozorování v zavřeném stavu (každý cyklus vyvráceného klíče znovu), ne různé nálezy. Opraveno v `997d81f` (počítají se různé `finding_id`). Týká se jen této metriky, ladicí rozhodnutí z ní nevychází a držený běh jede s opravenou binárkou.

## D) Měření

### D1. Ladicí seedy 20261701 a 20261801 (A2 na konfiguraci kroku 6, kandidáti B)

Binárka `749047d`, svět `--coverage full --families all`, 2 × 40 sítí, 2 224 útoků, 2 ramena současně po 3 vláknech s prioritou Idle vedle dvou 72h běhů (zatížení stroje 34 až 49 %). Párově proti `v3k6`, bootstrap po sítích stratifikovaný po seedech. Plný výstup je v `k7/tuning.md`.

| rameno | detekce | párově (p. b.) | FP/síť-den (poměr) | zobrazeno/síť-den (poměr) | zavřeno omylem (G3) | útoků se ztrátou viditelnosti (ladder / context / quiet) |
|---|---:|---:|---:|---:|---:|---|
| `v3k6` | 78,4 % | – | 13,1 | 116,6 | 33 / 1 320 = 2,5 % (1,8 až 3,5) | 9 / 0 / 36 (+1 evicted) |
| `v3k7A` (protect) | 78,5 % | +0,1 (−0,1 až +0,3) | 13,4 (1,022) | 118,2 (1,014) | 21 / 807 = 2,6 % (1,7 až 3,9) | 6 / 0 / 31 |
| B1 `ops_annotate` | 78,5 % | +0,1 | 13,4 (1,022) | 118,2 (1,014) | 21 / 807 | 6 / 0 / 31 |
| B2 `graph,graph_incident` | 80,6 % | **+2,2 (+1,6 až +2,9)** | 14,1 (1,073; 1,036 až 1,125) | 127,7 (1,095) | **14 / 1 031 = 1,4 %** | 4 / 0 / 28 |
| B3a `novel_burst` | 78,9 % | +0,5 (+0,2 až +0,9) | 14,2 (**1,084**) | 120,5 (1,034) | 31 / 773 = 4,0 % | 4 / 0 / 31 |
| B3b `fanout2` | 79,8 % | +1,4 (+0,8 až +2,0) | 13,7 (1,041) | 137,0 (1,175) | 33 / 806 = 4,1 % | 4 / 0 / 28 |
| B4 `cross_source` | 79,8 % | +1,4 (+0,7 až +2,3) | 432,5 (**35,7**) | 743,8 (7,27) | 26 / 332 = 7,8 % | 1 / 0 / 6 |
| B5 `saas_group` | 78,5 % | +0,1 | 13,4 (1,019) | 118,1 (1,013) | 21 / 820 | 8 / 0 / 30 |

Všechna ramena kromě `v3k6` mají `protect`. Chráněná automatická zavření: 0 ve všech ramenech. Ops-only útoky: 0 ve všech ramenech. Panika ani porušený invariant nenastaly.

**A2: tiché potlačení na konfiguraci kroku 6** (`v3k6`, výstupy kroku 6 zopakované binárkou s metrikou; ostatní pole jsou bajtově stejná). Po prvním zobrazení je útok viditelný v 92,1 % svých cyklů. Ztrátu viditelnosti měl 46 útoků z 2 224 (2,1 %): u 9 nález vyvrátil žebřík, u 36 se klíč 24 h neobjevil a zavřel se (`quiet`), 1 vypadl ze stropu paměti. Ztrátu kontextem nemá žádný útok, protože kontextem zavřený nález se k útoku v soaku nepřipisuje jako zobrazený. U 109 útoků se během útoku stala dvojice z jejich klíčových IP zavedeným zvykem profilu. S `protect` (`v3k7A`) je viditelnost 93,7 %, ztrátu vyvrácením žebříkem mají 6 útoků místo 9 a habituace se nemění (109). Habituace tedy nevzniká na poznamenaných dvojicích (ty se podle property testu zvykem nestanou), ale na dvojicích útoku, které nikdy neměly poplach. To je slepé místo detekce, ne zadržení (registr, bod 12).

**Rozhodnutí podle kill kritérií (B3):**

| kandidát | kritérium | hodnota | výsledek |
|---|---|---|---|
| B1 | útoky s provozní značkou ≤ 3 %; přesnost značky ≥ 80 % | 133 / 2 224 = 6,0 %; 221 / (221 + 133) = 62 % | **zamítnut** |
| B2 | FP ≤ 1,15 × `v3k6`; zavřeno omylem (počet) ≤ `v3k6` | 1,073; 14 ≤ 33 | **přijat** |
| B3a | FP u `saas_adoption` ≤ +5 p. b.; FP celkem ≤ +5 % | +1,1 p. b.; **+8,4 %** | **zamítnut** |
| B3b | zisk lateral ≥ 5 p. b.; FP ≤ 1,15 × | +9,6 p. b. (67,0 → 76,6 %); 1,041 | **přijat** |
| B4 | FP ≤ +5 %; záměna provoz a útok neroste | FP × 35,7 | **zamítnut** |
| B5 | položky na výskyt `saas_adoption` −30 %; c2 a dns_tunnel bez poklesu > 1 p. b. | 3,41 → 3,41 (0 %) | **zamítnut** |
| společné | rodina n ≥ 100 bez poklesu > 3 p. b.; chráněná zavření 0 | nejhorší −1,4 p. b. (B4, ssh); 0 | splněno všemi |

Žádný kandidát nevyužil povolenou úpravu parametrů. U zamítnutých kandidátů by úprava nemohla rozhodnout bez ladění na konkrétní poruchu (B1, B5) nebo by vyžadovala jiný návrh (B4).

**B1: proč E1 nezabírá** (diagnostika `diagnose`, zobrazené položky poruch, seed 20261701). Otevřený bod kroku 6 („klíč nálezu proti cíli selhání“) se potvrdil jen zčásti:

- `dns_outage`: nálezy mají přesný klíč služby DNS (`ip/udp/53`), takže klíč sedí. E1 přesto pro službu nevzniká: z 79 položek má shodu E1 jen 3, 17 má shodu E3 a 59 žádnou. Pravděpodobná příčina je práh `max_median_attempts` = 6. Klienti posílají DNS dotazy průběžně a při výpadku selhávají všechny, takže medián pokusů na zdroj práh přesáhne. „Málo pokusů na zdroj“ odlišuje poruchu od hádání hesel u TCP služeb, ale u upovídaných protokolů neplatí. Přímo jsem to neověřil. Nepřímo to podporuje to, že E3 (nárůst nesou dosavadní klienti) u téže služby vzniká, takže klientela i zdroje jsou v pořádku.
- `cert_expired`: polovina položek jsou objemové typy (`inductive_volume_anomaly`) s přesnou shodou E1 (anotace 19 z 38 výskytů). Zbytek je `unexpected_traffic` a objem s klíčem jen na úrovni hostu, kde E1 hosta chybí. Tady klíč nesedí.
- Anotace se ale lepí i na útoky: 6 % útoků (rozložené hádání hesel, DDoS, sken na službu s klientelou). Jako značka pro člověka je proto nespolehlivá (přesnost 62 %) a zůstává jen za přepínačem.

**B4** (`distributed_sources`) zachytí rozložené útoky (exploit_attempt 39,5 → 51,1 %, credential_stuffing +4,4 p. b.), ale veřejné služby s mnoha novými vnějšími klienty ho spouštějí trvale: zobrazené FP × 35,7. Je to přesně riziko, které předregistrace jmenovala (podmínka „jen selhání nebo nová vazba“ nerozliší nového klienta webu od útočníka). **B5** seskupení na vnější /24 u `saas_adoption` nic nemění, protože jeden klient a jedna adresa už jsou jeden klíč. Opakované položky na výskyt (3,4) dělají jiné typy nálezů téhož hostu. Souhlas člověka (API) zůstává jako produkční funkce, v soaku ho nikdo neudělí.

**Odchylka D2.** Druhý seed ramene B4 (20261801) jsem zastavil po 38 ze 40 sítí, aby souběžně neběžela tři ramena (limit 2 ramena a 6 vláken). Kill kritérium (FP × 35,7) bylo splněné už na 78 sítích, rozhodnutí to nemění.

**Vybraná sestava `v3k7` = `--v3-on protect,graph,graph_incident,fanout2`** (preset kroku 6 + A1 + B2 + B3b).

### D2. Kontrola sestavy (seedy 20261401 a 20261501, binárka `997d81f`)

Plný výstup je v `k7/check.md`. `v3k7` proti `v3k6`: detekce 78,8 → 81,0 %, párově +2,1 p. b. (+1,5 až +2,8). Zobrazené FP 14,7 → 16,3 na síť-den, poměr 1,106 (1,063 až 1,187). Zavřeno omylem 29 / 2 083 → 12 / 962 (1,4 → 1,2 %). Útoků s omylem zavřeným nálezem je 16 místo 27. Kritéria B4 (detekce ≥ 0, FP ≤ 1,15, omyly počtem ≤ `v3k6`) jsou splněná, sestava jde do drženého běhu beze změny. Varování před drženým během: všech zobrazených položek je o 25,8 % víc (1,175 až 1,327), protože chráněné nálezy se zobrazují hned a graf přidává incidenty. Předregistrovaný práh L1 (≤ 1,15) proto pravděpodobně nesplní. Sestava se kvůli tomu neupravuje, B4 o zátěži analytika nerozhoduje.

### D3. Držený běh (seedy 20261901 a 20262001, svět `k7`, jednou)

Binárka `997d81f`, 2026-11-05 23:34 až 2026-11-06 02:44. Ve frontě 20 úloh po 2 ramenech, každé se 3 vlákny, priorita Idle, zatížení stroje 37 až 51 %, oba 72h běhy běžely dál. Každé rameno má 2 × 40 sítí a 2 934 útoků. Plné výstupy: `k7/held.md` (párově proti `v3k6` a LOFO), `k7/held-vs-legacy.md`, `k7/ics.md`.

| rameno | detekce mikro | makro | FP/síť-den | zobrazeno/síť-den | zavřeno omylem (G3) | útoky s omylem zavřeným nálezem | latence medián / p90 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `legacy` | 62,6 % (59,5 až 65,5) | 65,5 % | 919,0 | 8 993 | – | – | – |
| `v3k6` | 77,9 % (74,7 až 81,2) | 80,3 % | 28,4 | 153,8 | 30 / 2 153 = 1,4 % (1,0 až 2,0) | 31 | 0 / 8 |
| `v3k7` | **80,3 % (77,2 až 83,2)** | **82,9 %** | 29,9 | 183,7 | 17 / 1 232 = 1,4 % (0,9 až 2,2) | 27 | 0 / 6 |

Párově `v3k7` − `v3k6`: detekce +2,4 p. b. (+1,7 až +3,1), FP poměr 1,051 (1,021 až 1,134), zobrazené položky 1,195 (1,145 až 1,249). Párově `v3k7` − `legacy`: detekce +17,7 p. b. (+15,5 až +20,2), FP poměr 0,033, zobrazené 0,020. `v3k6` − `legacy`: +15,3 p. b. (+13,1 až +17,9). Největší zisk `v3k7` proti `v3k6` má lateral_movement (72,7 → 86,8 %), dál fleet_beacon (+6,5), c2_beacon (+3,5), dns_tunnel (+3,4) a cryptomining (+2,5). Nejhorší rodina s n ≥ 100 je exfiltration (−0,5 p. b.).

**Prahy B6:**

| práh | hodnota | výsledek |
|---|---|---|
| K6 | G3 1,4 %, horní mez 2,2 % | **splněno** (≤ 5 %, i cíl ≤ 2 % bodově) |
| K6n | 27 útoků proti 31 | **splněno** |
| S0 | chráněná automatická zavření 0 (27 947 chráněných zobrazení), ops-only útoky 0 | **splněno** |
| S1 | ztráta viditelnosti `ladder` + `context`: 14 proti 16 (15 + 1) | **splněno** |
| D1 | nejhorší rodina n ≥ 100: exfiltration −0,5 p. b. | **splněno** |
| D2 | +2,4 p. b. | **splněno** |
| D3 | +17,7 p. b. mikro, +17,4 p. b. makro | **splněno** |
| F1 | 1,051 | **splněno** |
| L1 | 1,195 (1,145 až 1,249) | **nesplněno** (> 1,15) |
| L2 | medián 0 proti 0 cyklů | **splněno** |
| K3 | držené varianty proti ladicím ve stejném běhu (`v3k7`): `cert_expired` 8443 100 % (52/52) proti 93,5 % (29/31), tedy +6,5 p. b.; poruchy kroku 5 s intenzitou < 0,4 77,4 % (260/336) proti 75,0 % (408/544), +2,4 p. b.; `saas_group` 85,7 % (48/56) proti 78,7 % (37/47), +7,0 p. b. | **splněno** (vše ≤ +10 p. b.) |
| K3p | `v3k7` − `v3k6` ve frontě podezření: `saas_group` +10,7 p. b. (75,0 → 85,7 %), `saas_adoption` s 1 klientem +4,2, poruchy s nízkou intenzitou +2,7, ostatní poruchy kroku 5 +1,7, `cert_expired` 0. Záměna provoz a útok (B1) se nehodnotí, anotace není v sestavě. | hlásí se |
| K5 | LOFO skutečnou ablací, první útok rodiny bez IDS: ssh_bruteforce 88,9 % (74,7 až 95,6; n = 36), lateral_movement 69,2 % (53,6 až 81,4; n = 39), dns_tunnel 61,5 % (45,9 až 75,1; n = 39), **c2_beacon 30,8 % (19,9 až 44,3; n = 52)**. Definiční: exfiltration 12,8 % (n = 47), port_scan_vertical 5,9 % (n = 51). | **splněno** (3 ze 4), c2_beacon nezobecňuje |
| ICS | seed 20262101, 40 sítí Industrial: ics_attack n = 78 (seed 20262102 nebyl potřeba), `v3k7` 69,2 % (58,3 až 78,4), `v3k6` 65,4 % (54,3 až 75,0) | n splněno; kategorie (b) |
| C | 598 buněk: bez korekce (a) 261, (b) 76, (c) 261; s Holmovou korekcí (a) 141, (b) 196, (c) 261. Každá buňka má kategorii. | **splněno** |
| K8 | paniky 0, porušené invarianty 0 ve všech 20 úlohách | **splněno** |
| R | viz D5 | viz D5 |
| G4 | XXXL p99 cyklu 1 083,6 ms (seed 20261901) a 428,8 ms (seed 20262001), prah 3 s; 3 sítě na seed, 1 vlákno, klidný stroj po skončení obou 72h běhů, engine v3, binárka bakula-k7-0a59fb2, výstupy F:akula-soak\g4 | splněno |

**Výchozí režim zůstává `legacy`.** G4 nelze změřit, dokud běží 72h běhy (B6). `V3Features::recommended()` se mění na sestavu kroku 7, protože ta splnila všechny prahy kromě L1 (viz E). L1 je jediný nesplněný práh: zobrazených položek je o 19,5 % víc než u `v3k6`, ale pořád 50× méně než u `legacy`. Zvýšení jde ze zásady A1 (chráněný nález se zobrazí hned, nečeká na ověření, a nezavře se) a z incidentů grafu. Práce proto nesmí tvrdit, že krok 7 zátěž analytika drží.

**A2 na drženém světě.** Po prvním zobrazení je útok viditelný 97,0 % cyklů (`v3k6` 94,4 %). Ztrátu viditelnosti mělo 53 útoků (`ladder` 14, `quiet` 39), u `v3k6` 79 (`ladder` 15, `context` 1, `quiet` 63). Habituace: 160 útoků (`v3k6` 168).

### D4. C5: přehrání veřejných dat celou produkční cestou

**Licence a dostupnost.** UGR'16 (`nesg.ugr.es`): obě oficiální stránky vracejí HTTP 403 a ve výsledcích vyhledávání podmínky použití nejsou, licenci jsem tedy neověřil. Dataset se proto nepoužije. IoT-23 (Stratosphere Lab): licence je podle registru datasetů CC BY-NC-SA 4.0 (ověřeno 31. 10. 2026). Současná stránka datasetu text licence neuvádí, jen žádá citaci. Nejdelší záznamy jsou rotované po 24 h a v repozitáři jsou jen labelované výřezy do 24 MB.

**Běh** (`tools/replay_public.py`, protect zapnutý, debug binárka `f28029a`, okna 30 min, prázdný nmap, bez IDS, bez aktivních kontrol):

| záznam | toků | oken | škodliví hosté | zobrazeno (na škodlivém hostu / jinde) | auto zavřeno | žebřík (potvrzeno/vyvráceno/eskalováno) | degradace pokrytí |
|---|---:|---:|---:|---|---:|---|---|
| CTU-IoT-Malware-Capture-44-1 (ověření) | 237 | 4 | 1 | 2 (2 / 0) | 0 | 0/0/1 | `no_ids`, `immature_profiles` ve všech oknech |
| CTU-IoT-Malware-Capture-34-1 | 23 145 | 48 | 1 | 4 (2 / 2) | 0 | 0/0/4 | totéž |
| CTU-IoT-Malware-Capture-3-1 | 156 103 | 73 | 2 | 3 (3 / 0) | 0 | 0/0/3 | totéž |

Všechna okna spadají do studeného startu (< 48 h). Zralé období v žádném dostupném záznamu nevzniká, takže C5 dokládá jen to, že celá produkční cesta na reálných tocích běží, nic automaticky nezavře, nevyvrátí nic bez aktivní kontroly a degradaci pokrytí ohlásí. O detekci po zrání profilu nic neříká. Plný dlouhý běh (B8) chybí, protože chybí dlouhý záznam s ověřenou licencí. Zůstává otevřený (registr, bod 15).

### D5. Determinismus a zpětná kompatibilita (R)

- `soak verify --samples 6` nad drženým výstupem `v3k7-20261901`: 6 ze 6 bloků bit po bitu shodných.
- Golden snapshot (legacy) je zelený (`cargo test --test golden_snapshot`).
- Svět `full` bez nových přepínačů: kód kroku 7 (`749047d`) dává na 40 sítích seedu 20261701 bajtově stejný `networks.jsonl` jako výstup kroku 6 (`8828834`). Na seedu 20261801 se liší 2 sítě ze 40 (8 a 25), a to jen ve výsledcích žebříku. Abych zjistil příčinu, sestavil jsem stav těsně před krokem 7 (`24be082`) a pustil 26 sítí seedu 20261801: proti kroku 7 se neliší žádná síť, proti `8828834` tytéž 2 sítě. Rozdíl tedy způsobily opravy z review kol 2 a 3 kroku 6 (`fceb31e`, reset uložených případů novosti v žebříku) až po drženém běhu kroku 6, ne krok 7. Zpětná kompatibilita kroku 7 je doložená. Výstupy kroku 6 nejsou bajtově reprodukovatelné aktuálním kódem kroku 6: změna leží jen v počtu rozhodnutí žebříku na 2 sítích ze 80 a čísla kroku 6 nemění.
- Dotčené testy po změně presetu prošly (`engine::`, `eval::`, `soak::`, `behavior::`, 138 testů). Celá knihovna před změnou presetu: 513 prošlo, 0 selhalo (`--skip broker::`). Integrační `engine_v3`: 3 ze 3.

**R: splněno.**

## E) Registr slepých míst a tvrzení

**Preset v3** (`V3Features::recommended()`) = sestava kroku 7: preset kroku 6 + `protect` + `graph` + `graph_incident` + `fanout2`. Pro párové srovnání jsou `V3Features::step6()` a `step5()`. `ops_annotate`, `novel_burst`, `cross_source` a `saas_group` jsou zamítnuté a zůstávají volitelné za přepínačem. Provozní audit uzavření (A3) a stav pokrytí (A4) platí v produkční cestě v3 vždy.

**Výchozí režim zůstává `legacy`.** G1 až G3 a G5 jsou splněné ve stejném drženém běhu (D3), G4 změřený není, protože pořád běží oba 72h běhy. Až skončí, stačí pustit jen G4 (`--size xxxl --max-networks 3 --threads 1 --block-size 1`, seedy 20261901 a 20262001, nic dalšího současně). Pokud projde, výchozí režim se přepne na `v3` s presetem kroku 7. **Migrace:** nové klíče stavu `closure_audit` a tabulky `closure_reviews` a `novelty_consents` v `engine-state.sqlite` vznikají samy. Uložené chráněné nálezy ve stavu `AutoResolved` nebo `Refuted` se při prvním načtení převedou na `Closed` (audit `protect_reset`) a další výskyt je znovu otevře. Uložené chráněné případy žebříku s neškodným důkazem se resetují. Volitelný `closure-audit.json` mění parametry auditu jen v bezpečných mezích.

### Co smí práce tvrdit (držený běh, rameno `v3k7`)

1. Chráněné nálezy (novost, graf, signatura IDS, degradace, nejednoznačný kontext nebo identita) se nikdy automaticky nezavřou, nevyvrátí ani neodkloní do fronty provoz. Doložené to je property testy, přehráním uloženého stavu a v soaku: 0 automatických zavření z 27 947 chráněných zobrazení a 0 ops-only útoků.
2. Detekce útoků 80,3 % (77,2 až 83,2), makro 82,9 %, o +2,4 p. b. lepší než krok 6 a o +17,7 p. b. lepší než `legacy` na stejných sítích. Zobrazené FP jsou 1,05× proti kroku 6 a 0,03× proti `legacy`.
3. Zavřeno omylem 1,4 % (0,9 až 2,2). Útoků s omylem zavřeným nálezem je 27 ze 2 934 (krok 6: 31). Automatická zavření má v produkci provozní audit s trvalým vypnutím druhu a fail-safe.
4. Bez signatur zobecňují na neznámou variantu rodiny ssh_bruteforce, lateral_movement a dns_tunnel, při skutečném vypnutí vlastních detektorů v enginu.

### Co práce tvrdit nesmí

- Že krok 7 drží zátěž analytika: zobrazených položek je 1,195× víc než v kroku 6 (L1 nesplněn).
- Že nevypnutý druh kontextu má chybovost pod 2 %: audit dokládá jen překročení (dolní mez Wilsona nad cílem).
- Cokoliv o detekci na reálných datech po zrání profilu (D4: jen studený start).

### Registr slepých míst po kroku 7

| # | slepé místo | stav | měření (držený `v3k7`) | mitigace |
|---|---|---|---|---|
| 1 | Kontext zavírá útoky | **zadrženo** | zavřeno omylem 17 / 1 232 = 1,4 %; ztráta viditelnosti kontextem 0 útoků | chráněné typy kontext nezavře; bez zdroje nebo u vysoké závažnosti jsou potřeba dva druhy kontextu; produkční audit 10 %, 72 h, trvalé vypnutí, fail-safe |
| 2 | Vyvrácení žebříkem skryje útok | **částečně** | 14 útoků ztratilo viditelnost vyvrácením (krok 6: 15) | chráněné případy se nevyvracejí; vyvrácení je ve vzorku auditu jako druh `ladder` |
| 3 | Tiché zapomenutí (24 h bez výskytu) | zůstává | 39 útoků (`quiet`), krok 6: 63 | další výskyt nález znovu otevře; je to vlastnost paměti, ne zavření |
| 4 | c2_beacon bez detektoru majáku | **nezobecňuje** | LOFO 30,8 % (19,9 až 44,3) | detektor majáku je pro tuto rodinu nutný; novost a graf ho nenahradí |
| 5 | exploit_attempt | zůstává (b) | 35,5 % (30,1 až 41,3; n = 276), nejslabší i ve všech úrovních os | mimo tokový detektor; signatura IDS je chráněná (P3) a vždy se zobrazí; bez IDS `coverageStatus` hlásí `no_ids` a `deployment_blocking` |
| 6 | Krátký útok (doba 0,25× až 0,5×) | zůstává (b) | c2 0,25× 54,5 %, port_scan_horizontal 0,5× 48,1 % | vlastnost útoku |
| 7 | Rozložený útok (10 a 30 zdrojů) | **částečně** | osa zdrojů v (a); exploit_attempt × 3 zdroje 24,5 %, dns_tunnel × 10 58,1 % | agregace přes zdroje (B4) zachytí, ale FP × 35,7, zamítnuto |
| 8 | Provozní poruchy jako podezření | zůstává | K3p: držené varianty 77 až 100 % výskytů s FP ve frontě podezření | anotace (B1) má přesnost 62 % a zamítnuta; E1 nezabírá u upovídaných protokolů (DNS) a u nálezů s klíčem hostu |
| 9 | Nová cloudová služba více klientů (`saas_group`) | **vědomá cena** | 85,7 % výskytů s FP (krok 6: 75,0 %) | souhlas člověka přes API (přesná dvojice, nejvýš 30 dní), profil se dvojici z trvání nenaučí |
| 10 | Zátěž analytika | **nové** | 183,7 zobrazených na síť-den (krok 6: 153,8) | cena A1 a grafu; incident grafu slučuje hopy pivotu |
| 11 | Habituace dvojic útoku bez poplachu | zůstává | 160 útoků | poznamenané dvojice se zvykem nestanou (property test); dvojice, která nikdy neměla poplach, se naučí |
| 12 | ics_attack | (b) | 69,2 % (58,3 až 78,4), n = 78 | `coverageStatus` hlásí `low_ics_data`; průmyslové protokoly potřebují vlastní parser |
| 13 | Výpadek senzoru a nezralý profil | **viditelné** | `coverageStatus`: `telemetry_gap`, `immature_profiles`; nálezy v okně jsou chráněné (P4) | – |
| 14 | Reálná data po zrání profilu | otevřené | D4: IoT-23 jen studený start | dlouhý záznam s ověřenou licencí (UGR'16 nedostupný), laboratoř UHK |
| 15 | Výkon XXXL (G4) | p99 cyklu 1,08 s a 0,43 s | < 3 s | splněno |

### Odchylky od předregistrace (souhrn)

1. **D1:** počet omylem zavřených nálezů na útok v binárce `749047d` počítal pozorování, ne nálezy. Opraveno v `997d81f` před drženým během. Ladicí rozhodnutí na tom nestojí.
2. **D2:** druhý seed ramene B4 jsem zastavil po 38 ze 40 sítí. Kill kritérium bylo splněné už předtím.
3. Kandidáti B1, B3a, B4 a B5 jsou zamítnutí, ale jejich kód zůstává za přepínači. Výchozí cestu nemění (D5).
4. C5 proběhl jen jako ověření na třech záznamech IoT-23 (B8 to připouští). Plný dlouhý běh chybí (registr, bod 14).

### Co zůstává otevřené

- G4 na nezatíženém stroji po skončení 72h běhů a podle výsledku přepnutí výchozího režimu.
- Zátěž analytika (L1): seskupení chráněných nálezů do incidentů bez ztráty viditelnosti.
- E1 pro upovídané protokoly (práh pokusů na zdroj podle protokolu) a pro nálezy s klíčem hostu.
- Dlouhý replay reálných dat a laboratoř.

## Review

(doplní hlavní konverzace)
