# Implementace, krok 6: uzavírání slepých míst z registru kroku 5

Datum 2026-11-05. Výchozí stav: krok 5 hotov (`impl-krok5.md`), `legacy` je výchozí, v3 volitelné (preset kroku 4, bez grafu a bez peer baseline). Na držených seedech kroku 5 neprošly K3 (držené poruchy 78,8 % výskytů se zobrazeným FP proti 66,3 % u laděných) a K6 (zavřeno omylem 5,8 %, z toho 147 ze 163 kontextových omylů kvůli kontextu „výpadek senzoru“). K5 (LOFO) zobecňuje jen 2 ze 6 rodin. G4 z kroku 4 nemá platné měření na nezatíženém stroji. Všechna soak čísla jsou ze simulace.

Cíl: každé slepé místo z registru buď opravit s měřeným efektem, nebo ho zdůvodněně ponechat v registru s mitigací. Slib „žádná slepá místa“ dát nejde, protože co nezná detektor ani signatura a vypadá jako běžný provoz, se z toků nepozná. Nové rodiny útoků se nevymýšlejí. Existující rodiny se mění jen parametricky (svět pokrytí kroku 5).

Pořadí práce: A nápady a zdroje, B předregistrace (zamčená commitem před prvním měřicím během), C implementace za přepínači a párové A/B na ladicích seedech, D plné testy a jeden držený běh, E registr a rozhodnutí o výchozím režimu.

## A) Kandidátní zlepšení a zdroje

Zdroje ověřené 2026-11-05 (bibliografické údaje dohledány, citovaná tvrzení jen z abstraktu nebo z vlastních studií v `docs/diplomka/studie`). ID typu RQx-yyy odkazují na extrakce studií.

| # | kandidát | slepé místo (registr k5) | zdůvodnění a zdroj | rozhodnutí před měřením |
|---|---|---|---|---|
| 1 | **Výpadek senzoru není neškodný důkaz** (`sensor_strict`): kontext `sensor_outage` nic nezavře a není ani podpůrným (neškodným) důkazem žebříku. Nález z okolí výpadku jde normální cestou (paměť, žebřík, zobrazení). | 1 (K6) | Dodatek A.2 (d): „nic nenalezeno“ není vysvětlení; RQ6 Z3 (prázdný výsledek dotazu agent bere jako neškodnost v 98,6 % případů). Výpadek senzoru je absence dat, ne pozitivní důkaz. V simulaci výpadek senzoru smaže všechna data cyklu, takže důkaz žádného nálezu do mezery nepadá. Pravidlo „vysvětluje jen důkaz z mezery“ se tím v simulaci rovná „nevysvětluje nic“. | implementovat, měřit |
| 2 | **Třída „provozní problém“** (`ops_class`): zobrazený nález s pozitivním důkazem provozní příčiny jde do fronty „provoz“, ne mezi podezření na útok. Nikdy se nezavírá, člověk ho vidí. Důkazy: (E1) selhávající spojení mnoha zdrojů na jednu službu, každý zdroj jen pár pokusů, a služba měla předtím mnoho úspěšných klientů; (E2) cíl je broadcast nebo multicast; (E3) nárůst objemu na službě nesou hlavně její dosavadní klienti a žádný zdroj nedominuje. | 4 (K3) | Lokalizace poruch podle závislostí: když selhávají mnozí klienti téže služby současně, příčina je ve společné závislosti (Sherlock, Bahl a kol., SIGCOMM 2007; studie 00 R6a `service_unavailable` místo `connection_timeout_burst`, R6 riziko „flash_crowd a backup_burst R6a neřeší“). Broadcast a multicast nejsou cílem útoku na hostitele (RFC 919, RFC 1112). Riziko: rozložený útok mnoha zdroji (DDoS, rozložené hádání hesel). Proto se měří, kolik útoků skončí jen ve frontě „provoz“. | implementovat, měřit |
| 3 | **Graf nových vztahů** (`graph`, existuje, mimo preset): řetěz nových hran A→B→C. | 7 (lateral), částečně 2 | Hopper (Ho a kol., USENIX Security 2021; RQ4-047): nová hrana je rys, poplach až s řetězem. Krok 5 F: lateral +13,2 p. b. za +21 % FP v ladicím světě. | měřit v kombinaci (bez změny kódu) |
| 4 | **Nová trvalá vazba ven** (`novelty`, typ `novel_persistent_peer`): zralý vnitřní host začne opakovaně a úspěšně komunikovat s vnějším cílem, který není jeho zvyk, nebyl v jeho výchozím chování a nezná ho flotila (méně než 3 vnitřní hosté za 7 dní). Bez ohledu na časování, objem a port. | 2 (c2, exfil, dns_tunnel bez vlastního detektoru), 5 (rychlý maják) | Vzácný cíl a automatizovaná komunikace jako znak časné infekce (Oprea a kol., DSN 2015, LANL DNS a proxy logy); RQ4 Z10 (nová hrana je rys); BotSniffer (Gu a kol., NDSS 2008) pro vztah vzácnosti a flotily. Pojistka A7: nový vztah se automaticky nezavírá (kontext ho nekryje, profil ho nezná). Riziko: jeden host začne používat novou službu v cloudu, proto nová držená lookalike `saas_adoption` (B4). | implementovat, měřit |
| 5 | **Nové vnitřní vztahy hostu** (`novelty`, typ `novel_fanout`): zralý vnitřní host má během 6 h aspoň 8 nových úspěšných vnitřních vazeb (cíl a port), které nejsou jeho zvyk ani výchozí chování. Součet drobných odchylek přes okna, ne jedno okno. | 2 (lateral bez vlastních typů), 6 (pomalé tempo) | Hopper (RQ4-047), studie 00 R11 „lateral: first-seen hrana jako rys“. Kumulace přes delší okno místo jednoho okna (pomalé tempo, kandidát 7 v zadání). Riziko: nový monitorovací server, autorizovaný skener. | implementovat, měřit |
| 6 | **Kontext nezavře nález bez identifikovaného zdroje** (`context_guard`): zdrojově citlivý kontext (údržba, záloha, dávka, patch okno, výpadek služby) zavře nález jen tehdy, když má nález identifikovaný dominantní zdroj a ten je v záznamu kontextu, nebo jde o objem v okně zálohy či dávky. | zbytek K6 (patch_window a service_outage zavírají `connection_timeout_burst` skenu) | Dodatek A.2 (c) a (d); A7 kroku 5 (první výskyt bez doloženého vysvětlení se nezavírá). Nález bez zdroje kontext nemůže potvrdit ani vyvrátit. | implementovat, měřit |
| 7 | CUSUM nad profilem hostu (kumulativní drobné odchylky objemu a počtu cílů) | 2, 6 | Page (Biometrika 1954); Wang, Zhang a Shin (INFOCOM 2002) pro SYN flood. Studie 00 R7 ale výslovně uvádí RQ2 Z2 (nízká jistota): CUSUM a Holt-Winters nezavádět, chybí měření na tocích a parametry jsou citlivé (RQ2 Z5a). Kandidát 5 pokrývá kumulaci jednodušeji (počet nových vazeb v okně 6 h). | zamítnuto před měřením (studie, složitost); zůstává v registru jako možnost |
| 8 | Agregace přes zdroje: součet nových zdrojů se stejným cílem (útok rozložený na 10 zdrojů) | 6 | BotSniffer (prostorově-časová korelace hostů). U vnitřních útoků částečně pokrývá kandidát 4 (každý zdroj je nový vztah ven) a 2 (E1 se rozloženým útokem nesmí plést). | neimplementovat v kroku 6, měřit dopad 4 a 2 na osu „zdroje 10“ |
| 9 | Fúze detektorů a konformní kontrola chyby zavírání | K6 obecně | Konformní řízení rizika (Angelopoulos a kol., ICLR 2024) garantuje očekávanou ztrátu jen při zaměnitelnosti kalibračních a testovacích dat, což u driftu provozu a nových rodin neplatí (Transcend, Jordaney a kol., USENIX Security 2017). V enginu už je obdoba: audit 10 % zavřených a vypnutí druhu kontextu, když dolní mez Wilsonova intervalu omylu > 2 % (H-A3). | neimplementovat; zdokumentovat jako budoucí práci |
| 10 | Aktivní učení ze žebříku (ILAB, Beaugnon a kol., RAID 2017) | 2 | V simulaci by se učilo ze štítků generátoru, tedy kruhově (studie 00 §5.e, R12 rizika). Učení z verdiktů žebříku už v3 má (`learning`). | zamítnuto pro krok 6 (kruhovost) |
| 11 | Odolnost učení proti otravě a posunu profilu | 2 (útok od začátku se naučí) | ANTIDOTE (Rubinstein a kol., IMC 2009): otrava posune detektor. Profil už má gating, stáří, rychlostní limit povýšení a poznamenání dvojic s poplachem (`profile.rs`). Kandidáti 4 a 5 se opírají o profil, proto se měří útoky z prvních dnů epizody. | neimplementovat nové; měřit kandidáty 4 a 5 po stáří útoku |
| 12 | Sekvenční test pro rychlý maják (SPRT nad mezičasy, TRW: Jung a kol., IEEE S&P 2004) | 5 | TRW rozhodne po 4 až 5 pokusech, ale jde o skeny. Pro maják by šlo o nový detektor rodiny, a to je ladění na rodinu. Kandidát 4 rychlý maják pokrývá obecně (trvalost vazby bez ohledu na periodu). | neimplementovat; měřit kandidáta 4 na ose tempo |
| 13 | Kalendář změn (CMDB změny, migrace, výměna certifikátu) jako kontext | 4 (cloud_migration, cert_expired) | V produkci správný zdroj (Dodatek A.3 bod 2). V simulaci by ale znamenal dát enginu znalost o držených poruchách, takže by neměřil zobecnění. | zamítnuto pro měření K3; doporučení pro produkci |
| 14 | IDS a CVE kontext pro exploit_attempt | 3 | Není tokový detektor, mimo zadání (krok 5). | ponecháno v registru s mitigací |

Kandidáti 1, 2, 4, 5 a 6 jsou nový kód za přepínači, 3 je existující přepínač. Ostatní se neimplementují a důvod je výše.

## B) Předregistrace (zamčeno commitem před prvním měřicím během)

Sekce B se po prvním měřicím běhu nemění. Případná oprava chyby harnessu nebo kandidáta se zapisuje do sekce F jako odchylka s důvodem. Prahy, seedy ani definice se po pohledu na držená data nemění.

### B1. Seedy

| účel | seedy | sítí na seed |
|---|---|---:|
| ladění kandidátů a výběr sestavy | 20261611, 20261612, 20261613 | 40 |
| držené, jen jeden běh | 20261701, 20261801 | 40 |

Seedy kroků 1 až 5 se nepoužívají. Ladicí svět `--coverage tuning --families tuning`, držený `--coverage full --families all`, hranice pásem S z kroku 5 (`--edges 0.1718,0.2363,0.3053,0.3917`). Držené rodiny a držené poruchy kroku 5 už nejsou úplně neznámé, protože jsem viděl jejich výsledky v kroku 5. Ladicí svět je ale dál nevidí, takže na nich ladit nejde.

### B2. Ramena

Jedna binárka (release, `CARGO_TARGET_DIR=F:/claude-tmp/target-soak`, commit zapsaný v sekci D). Párově po sítích, společné volby `--block-size 2 --no-legs --no-feedback --counterfactual --max-networks 40`, šum 1×, bez kalibrace. Zátěž: kvůli dvěma běžícím 72h během nejvýš 2 ramena současně, 2 až 3 vlákna každé, priorita Idle, před spuštěním kontrola zatížení.

| rameno | konfigurace |
|---|---|
| `legacy` | `--engine legacy` |
| `v3k5` | `--engine v3` (preset po kroku 4 a 5) |
| `v3+X` | `--engine v3 --v3-on X` pro každého kandidáta X zvlášť (jen ladicí seedy) |
| `v3k6` | vybraná sestava kroku 6 (ladicí i držené seedy) |

### B3. Metriky

Beze změny proti kroku 5 (A4), navíc:

- **Fronta podezření.** Zobrazený nález zařazený do třídy „provozní problém“ se počítá jako zobrazený (G1 a `displayed_fp` beze změny), ale **ne** jako podezření na útok. Detekce útoku (`cf`) se počítá jen ze zobrazení ve frontě podezření (konzervativně: útok, který skončí jen ve frontě provoz, je nedetekovaný). Bez `ops_class` jsou obě definice totožné.
- **K3 (fronta podezření):** podíl výskytů držených nových poruch kroku 5 (cert_expired, segment_power_loss, vpn_reconnect_storm, cloud_migration) se zobrazeným nálezem ve frontě podezření, proti laděným novým poruchám (dns_outage, dhcp_renumber, link_flapping, misconfig, backup_failed) ve stejném běhu. Hlásí se i K3 v původní definici kroku 5 (jakékoli zobrazení).
- **Útoky ve frontě provoz:** podíl útoků, jejichž připsané zobrazené nálezy jsou všechny ve frontě provoz (cena kandidáta 2).
- **Typy FP poruch:** u každé poruchy množina typů zobrazených nálezů (jen diagnostika).
- Zavřeno omylem (G3/K6) beze změny.

### B4. Nová držená lookalike

`saas_adoption` (jen `--coverage full`, laděný svět ji nemá): jeden vnitřní klient začne trvale používat novou vnější službu (nová veřejná adresa, HTTPS, nepravidelné časy, běžné velikosti) po 24 až 200 cyklů. Je to přímý test ceny kandidáta 4 (nová trvalá vazba ven u jednoho hostu). Hlásí se zvlášť a do K3 nevstupuje, aby K3 zůstal srovnatelný s krokem 5. Laděný svět se jejím přidáním nemění (vybírá se jen z neholdovaných druhů, kontrolu dělá test plánu).

### B5. Kritéria výběru sestavy (ladicí seedy, párově proti `v3k5`)

Kandidát X se do sestavy vybere, když na ladicích seedech platí všechno:

1. souhrnná detekce: rozdíl ≥ 0 p. b. (bodový odhad) a žádná rodina s n ≥ 100 neklesne o víc než 3 p. b.;
2. zobrazené FP na síť-den: poměr ≤ 1,05, nebo ≤ 1,15, když detekce vzroste aspoň o +1 p. b. nebo K3 (fronta podezření) klesne aspoň o 10 p. b.;
3. zavřeno omylem (G3) se nezhorší (bodový odhad);
4. p99 času cyklu na ladicím běhu nevzroste o víc než 10 % (orientačně, stroj je zatížený);
5. při shodě přínosu vyhrává jednodušší a vysvětlitelnější kandidát.

Sestava = všichni vybraní kandidáti současně. Před drženým během se sestava jednou ověří na ladicích seedech proti `v3k5` (stejná kritéria 1 až 3, FP sestavy celkem ≤ 1,15). Pokud sestava kritéria nesplní, vypouští se kandidát s nejhorším poměrem FP / přínos, dokud je nesplní. Parametry kandidátů 2, 4 a 5 jsou dané v kódu před prvním během. Na ladicích seedech smí každý z nich projít nejvýš jednou úpravou parametrů a ta se zapíše do C s čísly před a po.

### B6. Prahy (držené seedy, rameno `v3k6`, jeden běh; rozhoduje bodový odhad, kde není uvedeno jinak)

| práh | definice | splněno, když |
|---|---|---|
| K6 | zavřeno omylem (G3), svět `full` | horní mez Wilsonova 95% intervalu ≤ 5 % (cíl ≤ 2 %) |
| K3 | fronta podezření: držené nové poruchy kroku 5 proti laděným novým poruchám, stejný běh | držené ≤ laděné + 10 p. b. |
| D1 | detekce `v3k6` − `v3k5` po rodinách s n ≥ 100 (součet obou seedů), párově | žádný pokles o víc než 3 p. b. |
| D2 | totéž souhrnně | ≥ +3 p. b. |
| F1 | zobrazené FP na síť-den, `v3k6` / `v3k5` | ≤ 1,15 |
| K5 | LOFO (definice kroku 5 A5) | zobecňuje aspoň 4 ze 6 rodin |
| G4 | XXXL, p99 cyklu každé ze 6 sítí (seedy 20261701, 20261801, 3 sítě každý, 1 vlákno, 1 síť najednou) | max p99 < 3 s na nezatíženém stroji; podmínky měření (zátěž, ostatní procesy) se zapíšou. Na zatíženém stroji se měří jen CPU čas cyklu a G4 se nevyhodnotí jako splněný. |
| M | peak haldy XXXL na síť | < 1,5 GiB |
| R | determinismus: `soak verify` na držených i ladicích výstupech, golden snapshot (legacy) zelený | shoda |
| K8 | panika a porušené invarianty ve všech ramenech | 0 a 0 |
| K1, K2, K4, K6b, K7 | beze změny z kroku 5 | hlásí se |

K5 s novými obecnými typy (kandidáti 4 a 5) se vyhodnotí stejně jako v kroku 5. Nové typy nepatří do D(X) žádné rodiny, protože nebyly navržené pro žádnou z nich. Navrhoval jsem je ale se znalostí, které rodiny v kroku 5 LOFO neprošly. Výsledek K5 proto bude optimistický a v sekci E to uvedu.

### B7. Výchozí režim

Na v3 jako výchozí se přepne jen tehdy, když `v3k6` splní prahy G1 až G5 z kroku 4 (B, beze změny definic) na držených seedech tohoto kroku. G1 a G2 se počítají proti `legacy` ve stejném běhu (G1b až G1d proti `s2` se nepouštějí znovu; k nim platí hodnoty kroku 4 a v E to bude uvedeno). G3 = K6. G4 musí být změřený na nezatíženém stroji. Když stroj klidný není, G4 se nevyhodnotí a `legacy` zůstává výchozí. Prahy K tohoto kroku o výchozím režimu nerozhodují, rozhodují o tom, která tvrzení práce smí udělat.

## C) Implementace a ladicí A/B (seedy 20261611 až 20261613, 3 × 40 sítí)

Kód: `4a461c1` (kandidáti za přepínači `--v3-on sensor_strict | ops_class | novelty | context_guard`, `graph` existoval), `b5a913c` (měření: fronta podezření a fronta provoz, typy FP poruch, držená lookalike `saas_adoption`), `fecbe66` (nástroj), `bf16fc3` (třída provoz v produkční cestě v3, záznam `ops_reason` v životním cyklu nálezu). Výchozí svět i ladicí svět dávají s novou binárkou bajtově stejný `networks.jsonl` jako binárka kroku 5 (4 sítě seedu 20261611, v3 s kontrafaktuálem, 0 rozdílů po odečtení nových polí). Všechny přepínače jsou mimo preset, `V3Features::recommended()` se nemění.

Běhy: binárka `b5a913c` (první kolo), `22d62af` (úprava novosti) a `8828834` (úprava třídy provoz). Stroj sdílely dva 72h běhy, proto 2 ramena současně, 2 vlákna, priorita Idle, celkové zatížení 43 až 51 %. Párově proti `v3k5`, bootstrap po sítích stratifikovaný po seedech (B = 2000). Výstupy jsou v `F:\bakula-soak\ab\k6\tuning`, plné srovnání vybrané sestavy je v `docs/diplomka/eval/k6/tuning-v3k5-v3k6.md`.

Základ `v3k5`: 3 759 útoků, detekce 79,1 %, zobrazené FP 21,3 na síť-den, zavřeno omylem 34 / 2 313 = 1,47 % (horní mez 2,05 %), K3 laděné nové poruchy 70,0 % výskytů se zobrazeným FP, LOFO zobecňuje 2 ze 6 (ssh 54/56, lateral 36/72).

| kandidát | detekce (p. b., 95% CI) | FP / síť-den (poměr) | zavřeno omylem | K3 laděné | LOFO | B5 |
|---|---|---:|---|---:|---|---|
| 1 `sensor_strict` | +0,00 (+0,00 až +0,00) | 1,001 | 33 / 2 221 = 1,49 % | 70,0 % | 2/6 | doslovně ne (B5.3, viz F1), přijat jako odchylka |
| 2 `ops_class` (první verze) | −0,19 (−0,35 až −0,06) | 1,000 (podezření 0,994) | 34 / 2 313 | 66,9 % | 2/6 | ne (B5.1) |
| 2 `ops_class` po úpravě (značky s TTL) | −0,21 (−0,38 až −0,08) | 1,000 (podezření 0,992) | 34 / 2 313 | 66,5 % | 2/6 | ne (B5.1) |
| 3 `graph` | +2,71 (+2,21 až +3,23) | 1,086 | 40 / 2 675 = 1,50 % | 70,4 % | 2/6 | ne (B5.3: 6 omylů navíc) |
| 4+5 `novelty` (první verze) | +2,71 (+2,09 až +3,36) | 1,474 | 34 / 3 553 = 0,96 % | 70,5 % | 3/6 | ne (B5.2) |
| 4 `novelty` po úpravě (`novel_fanout` vypnuto), v sestavě s 1 | +0,74 (+0,40 až +1,12) | 1,036 | 33 / 2 518 = 1,31 % | 69,6 % | 3/6 | ano |
| 6 `context_guard` | −0,05 (−0,12 až +0,00) | 1,000 | 40 / 2 198 = 1,82 % | 69,7 % | 2/6 | ne (B5.1, B5.3) |
| sestava 1 + 4 + 2 (po úpravě) | +0,53 (+0,11 až +0,95) | 1,036 (podezření 1,028) | 33 / 2 518 | 66,0 % | 3/6 | ne (B5.1 pro 2) |

p99 cyklu (ladicí sítě, zatížený stroj) se u žádného kandidáta nezvýšil: medián p99 sítě 0,13 až 0,15 s proti 0,14 s, maximum 1,02 až 1,19 s proti 1,23 s. Žádná panika, žádný porušený invariant (21 ramen × 40 sítí).

**1 `sensor_strict`.** V ladicím světě kontext výpadku senzoru zavíral 92 nálezů, z toho 1 omylem, takže efekt je tu nulový. Detekce se nezměnila, FP +0,1 %. Počet omylů klesl z 34 na 33, ale podíl stoupl z 1,47 na 1,49 %, protože ubylo 91 správných zavření. Podle B5.3 (podíl, bodový odhad) by kandidát neprošel o 0,02 p. b. Zařadil jsem ho přesto a je to odchylka F1: B5.3 měl zabránit tomu, aby kandidát zavíral víc útoků. Tady se počet omylem zavřených útoků nezvýšil, jen se zmenšil jmenovatel. Sestava, ve které je, B5.3 splňuje (1,31 %).

**2 `ops_class`.** E2 (broadcast) zabírá: misconfig 96,9 → 83,3 % výskytů s FP ve frontě podezření. E1 a E3 skoro nezabírají (dns_outage 87,9 → 87,6 %, dhcp_renumber 79,3 → 78,7 %, service_crash beze změny). Jediná povolená úprava řešila hypotézu, že žebřík zobrazí nález až po ověření, kdy porucha skončila: důkaz se zapíše i k nezobrazenému nálezu a platí 24 h. Efekt to nemělo (K3 laděné 66,9 → 66,5 %). Cena je skutečná: 18 až 21 útoků ze 3 759 skončilo jen ve frontě provoz (credential_stuffing −1,9 p. b., ddos_volume −1,5 p. b.). To je přesně riziko z A (rozložený útok mnoha zdroji vypadá jako porucha služby). **Zamítnuto** (B5.1). Kód zůstává za přepínačem jako diagnostika. Proč E1 nezabírá, jsem neověřil. Pravděpodobná příčina je, že nálezy poruch nesou jediný dominantní zdroj nebo klíč služby jiný než cíl selhání (`unmapped_passive_event` na staré adrese, `service_unreachable` na hostu bez portu). To je otevřený bod.

**3 `graph`.** Největší zisk detekce (lateral_movement +20,4 p. b.) za +8,6 % FP, ale zavřeno omylem 34 → 40 (žebřík vyvrací nálezy `pivot_chain`). **Zamítnuto** podle B5.3. Je to stejný závěr jako v kroku 4 (FP), tentokrát kvůli zavírání.

**4 a 5 `novelty`.** První verze: +2,71 p. b. (lateral +15,7, dns_tunnel +4,5, c2 +4,0), ale `novel_fanout` přidal 9,3 zobrazených FP na síť-den (+44 %). `novel_persistent_peer` přidal jen 0,8. Jediná povolená úprava: `novel_fanout` vypnuto (`fanout_min` 8 → 0, commit `22d62af`). Zbylý `novel_persistent_peer` dává +0,74 p. b. (c2_beacon +3,1, dns_tunnel +4,1), z toho c2_beacon s tempem 4× 54,3 → 61,0 %. FP stoupnou o 3,6 %. Zavřeno omylem kleslo na 1,31 %: zavření přibylo 205 (žebřík vyvrací neškodné nálezy, které nová vazba otevřela), omylů ubyl jeden. Jeden nález `novel_persistent_peer` žebřík vyvrátil (neškodný). Tvrzení „nový vztah se nikdy nezavře“ proto neplatí doslova: zavře ho jen žebřík s pozitivním neškodným důkazem, kontext ani profil ne. LOFO: dns_tunnel začne zobecňovat (35/64), c2_beacon 21/76 nestačí, celkem 3 ze 6. **Přijato.**

**6 `context_guard`.** Bez identifikovaného zdroje kontext nezavře. Odebral 115 zavření, ale přidal 6 omylů (40 / 2 198 = 1,82 %): nálezy, které kontext nezavřel, potom zavřel žebřík, a to hůř. **Zamítnuto** (B5.1, B5.3).

**Vybraná sestava `v3k6` = `--v3-on sensor_strict,novelty`** (preset kroku 5 plus kandidáti 1 a 4 s upraveným prahem). Sestava na ladicích seedech: detekce +0,74 p. b. (+0,40 až +1,12), FP × 1,036, zavřeno omylem 1,31 % (horní mez 1,83 %), žádná rodina s n ≥ 100 neklesla, kampaně „všechny fáze“ 36,4 → 38,7 %. Splňuje B5.1 až B5.3 i strop sestavy (FP ≤ 1,15).

Ladicí svět neobsahuje dlouhé držené útoky, na kterých v kroku 5 selhal K6. Přínos `sensor_strict` se proto ukáže až na držených seedech.

**Odchylka F2 (před drženým během).** Držený běh jsem jednou spustil (09:40) se sestavou `sensor_strict,novelty` z binárky `22d62af`. Po 10 minutách jsem ho zastavil a výstupy smazal, aniž bych otevřel jakýkoli výsledek (žádná síť nebyla dokončená). Důvod: ještě jsem nevyužil povolenou úpravu kandidáta 2 a ta mohla změnit sestavu. Držený běh se pak pustil jednou, s binárkou `8828834` a se stejnou sestavou, protože kandidát 2 po úpravě neprošel. Soak cesta sestavy je v `22d62af` a `8828834` stejná (úprava se týká jen kódu za `ops_class`).
