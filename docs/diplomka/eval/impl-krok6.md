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

## D) Držený běh a plné testy

**Držený běh** (seedy 20261701 a 20261801, jednou, binárka `8828834`, 2026-11-05 10:47 až 11:45, priorita Idle, 2 ramena po 2 vláknech, celkové zatížení stroje 39 až 46 %). Svět `--coverage full --families all`, 2 × 40 sítí, 2 224 útoků. Ramena `legacy`, `v3k5` (preset kroku 5) a `v3k6` (`--v3-on sensor_strict,novelty`). Plné výstupy: `docs/diplomka/eval/k6/held-v3k5-v3k6.md` a `held-legacy-v3k6.md` (`tools/soak_coverage.py`, hranice S z kroku 5). Po pohledu na výsledek se nic neladilo a běh se neopakoval.

| práh | definice | hodnota | splněno |
|---|---|---|---|
| K6 | zavřeno omylem (G3), horní mez Wilson ≤ 5 % (cíl ≤ 2 %) | `v3k6` 33 / 1 320 = 2,50 % (1,79 až 3,49 %); `v3k5` 88 / 1 318 = 6,68 % (5,45 až 8,15 %) | **ano** (cíl 2 % ne) |
| K3 | fronta podezření: držené nové poruchy ≤ laděné + 10 p. b. | 84,0 % (79,6 až 87,6) proti 69,3 % (65,0 až 73,3), +14,7 p. b. | **ne** |
| D1 | `v3k6` − `v3k5` po rodinách s n ≥ 100, nepokles o víc než 3 p. b. | nejhorší 0,0 p. b.; c2_beacon +3,3, dns_tunnel +3,3 | ano |
| D2 | `v3k6` − `v3k5` souhrnně ≥ +3 p. b. | +0,49 p. b. (+0,16 až +0,78) | **ne** |
| F1 | zobrazené FP / síť-den `v3k6` / `v3k5` ≤ 1,15 | 13,1 / 12,4 = 1,059 (1,040 až 1,090) | ano |
| K5 | LOFO zobecňuje ≥ 4 ze 6 | 2 ze 6 (ssh 29/32, lateral 24/39; dns_tunnel 13/28 = 46 %, c2 8/35, exfil 0/37, vertikální sken 2/39) | **ne** |
| G4 | XXXL p99 cyklu < 3 s na nezatíženém stroji | stroj zatížený (dva 72h běhy, ~45 %): p99 v reálném čase 0,73 až 1,65 s, CPU čas cyklu p99 281 až 422 ms (6 sítí, 8 147 až 9 543 zařízení, 1 vlákno) | **nevyhodnoceno** (podmínka klidného stroje nesplněna) |
| M | peak haldy XXXL < 1,5 GiB | 382 a 368 MiB | ano |
| R | determinismus | `soak verify` 2/2 bloky shodné (ladicí `k6set-20261611` i držený `v3k6-20261701`); golden snapshot zelený; výchozí a ladicí svět bajtově beze změny | ano |
| K8 | panika, porušené invarianty | 0 / 0 (6 držených, 27 ladicích a 2 XXXL běhy) | ano |
| K1 | Q5 / Q1 | 0,93 | ano |
| K2 | `v3k6` − `v3k5` vše a Q4 + Q5 | +0,5 a +0,2 p. b. | ano |
| K4 | souběh s nesenzorovou poruchou | +1,9 p. b. | ano |
| K6b | útoky s automatickým zavřením: držené rodiny proti laděným | 3,5 % proti 0,9 % | ano |
| K7 | kampaně zachycené aspoň v jedné fázi | 95,8 % (91,6 až 97,9) | ano |

**Co se opravilo.** Slepé místo 1 z kroku 5 (výpadek senzoru zavírá útoky) je pryč: kontext `sensor_outage` měl v `v3k5` 40 zavření nálezů připsaných útoku, v `v3k6` žádné; kontrafaktuální kontextové omyly klesly ze 47 na 9. Omylem vyvrácené případy žebříku klesly z 41 na 24, protože výpadek senzoru už nebyl ani podpůrným důkazem. Zbylých 9 kontextových omylů dělají patch_window, service_outage, backup, batch_job a authorized_scanner. Platí se za to vyšším FP u samotného výpadku senzoru (sensor_crash 13,5 → 19,1 % výskytů se zobrazeným FP): nálezy kolem výpadku se teď ukážou člověku. Druhý přínos: c2_beacon +3,3 a dns_tunnel +3,3 p. b. z `novel_persistent_peer`.

**Co neprošlo.**

- **D2:** zisk +0,49 p. b. je skutečný (interval vylučuje nulu), ale malý. Velké zisky (graf +2,7 p. b., `novel_fanout` +2,7 p. b.) neprošly ladicími kritérii kvůli zavírání omylem nebo FP.
- **K3:** třída provoz (kandidát 2) neprošla ani po úpravě. Držené poruchy cert_expired (90,4 %), cloud_migration (97,4 %) a vpn_reconnect_storm (88,6 %) dál vypadají jako útok.
- **K5:** dns_tunnel na ladicích seedech zobecňoval (35/64), na držených 13/28 = 46 % už ne. Neznámý maják bez vlastního detektoru se zachytí v 23 % případů (8/35).
- **Cena novosti:** držená lookalike `saas_adoption` (jeden klient a nová cloudová služba) má FP ve frontě podezření v 69,0 % výskytů proti 36,8 % bez novosti. Je to přesně ten případ, který tok od majáku neodliší. Nález se nezavírá a člověk ho vidí.

**Proti `legacy` (G z kroku 4, držený běh tohoto kroku):**

| práh | hodnota | splněno |
|---|---|---|
| G1a | FP / síť-den 900,8 → 13,1, −98,5 % (poměr 0,015, 0,012 až 0,020) | ano |
| G1b až G1d | znovu nepuštěno, platí krok 4 (1,010 / 1,031 / 1,083) | (krok 4) |
| G2a | nejhorší rodina s n ≥ 100: lateral_movement −2,5 p. b. (−7,1 až +1,3) | ano (≥ −5) |
| G2b | souhrnně +18,9 p. b. (+16,8 až +21,6) | ano |
| G3 | = K6, horní mez 3,49 % | ano |
| G4 | nevyhodnoceno (stroj zatížený), viz výše | ne |
| G5 | 0 panik, 0 invariantů | ano |

**Plné testy** (binárka a kód `eb0fb1f`, kde se mění jen preset):

- `cargo test --lib`: 486 prošlo, 5 selhalo, všechny `broker::tests` (známá výjimka, chybí Redis);
- integrační testy: golden snapshot, engine_v3, case_memory_learning, incremental_ingest, mas_deep a verification_execution zelené; `e2e` autopilot selhal (známá výjimka, httpx); broker_two_process vyžaduje Redis;
- `cargo clippy --all-targets`: lib 89, lib test 97, bin 3, e2e 1, tedy stejně jako HEAD před krokem 6;
- kotvy (preset se změnil, takže jednou dev a jednou zamčené části, 2026-11-05 kolem 12:10, výstup `F:\claude-tmp\k6\anchor.out`): výsledky jsou totožné s kroky 4 a 5. Zamčená CTU-13 a IoT-23: 2 ze 30 škodlivých a 1 ze 112 neškodných hostů. CIC-IDS2017 a UNSW-NB15: 0 nálezů. Novost potřebuje zralý profil (48 h), krátké výřezy ji nespustí.

## E) Rozhodnutí, registr slepých míst a co zůstává

**Preset v3** (`V3Features::recommended()`, commit `eb0fb1f`) = vybraná sestava kroku 6: preset kroku 5 + `sensor_strict` + `novelty` (jen `novel_persistent_peer`). Pro párové srovnání zůstává `V3Features::step5()`. Třída provoz, `context_guard` a graf jsou dál volitelné přes `--v3-on`.

**Výchozí režim zůstává `legacy`.** G1a, G2, G3 a G5 jsou na nových držených seedech splněné. G4 ale podle B7 vyžaduje měření na nezatíženém stroji a ten celý krok sdílely dva 72h běhy (asi 45 % CPU). Orientační čísla jsou daleko pod prahem: p99 v reálném čase nejvýš 1,65 s, CPU čas cyklu nejvýš 422 ms. Formálně ale G4 změřený není, a podle předregistrace se proto výchozí režim nemění. Až 72h běhy skončí (přibližně 2026-11-07), stačí pustit jen G4 (`--size xxxl --max-networks 3 --threads 1 --block-size 1` na seedech 20261701 a 20261801, nic dalšího současně). Pokud projde, výchozí režim se přepne na `v3`. Poznámka k migraci pro tu chvíli: `engine.mode = "v3"` v konfiguraci a nové klíče stavu `clientele` a `ops_marks` v `engine-state.sqlite` vznikají jen s `ops_class`. Behaviorální stav dostane pole `novelty` (serde default, starý stav se načte). Kontext `sensor_outage` v `context-calendar.json` přestane zavírat nálezy, záznamy zůstávají platné.

### Registr slepých míst po kroku 6 (držený běh `v3k6`, pokud není uvedeno jinak)

| # | slepé místo | stav po kroku 6 | měření | mitigace |
|---|---|---|---|---|
| 1 | Kontext „výpadek senzoru“ zavírá útoky | **opraveno** | zavření útoků kontextem sensor_outage 40 → 0, K6 6,7 → 2,5 % | výpadek senzoru je jen informace pro člověka, nikdy důkaz neškodnosti |
| 1b | Zbylé kontextové omyly (patch_window, service_outage, backup, batch_job, scanner) | zůstává | 9 kontrafaktuálních omylů z 367 kontextových zavření (2,5 %), K6 cíl 2 % nesplněn | audit 10 % zavřených a automatické vypnutí druhu kontextu (H-A3); `context_guard` vyzkoušen a zamítnut (víc omylů přes žebřík) |
| 2 | Neznámá rodina podobná majáku, exfiltraci, vertikálnímu skenu nebo pohybu v síti | **částečně** | LOFO 2/6: c2 23 %, exfil 0 %, vertikální sken 5 %, dns_tunnel 46 %; obecná novost přidala c2 +3,3 a dns_tunnel +3,3 p. b. | nový vztah se nezavírá kontextem ani profilem a jde člověku; zbytek je vlastnost tokových dat (vertikální sken na otevřené porty nevytvoří úspěšnou novou vazbu ven) |
| 3 | exploit_attempt | zůstává | 39,5 % (n = 233) | mimo tokový detektor (IDS a CVE kontext), vždy zobrazit IDS alerty |
| 4 | Provozní problémy jako podezření na útok | zůstává | K3 84,0 % vs 69,3 %; třída provoz zachytí jen broadcast (misconfig −13,6 p. b. v ladění) a stojí detekci (credential_stuffing −1,9, ddos −1,5 p. b.) | neautomatizovat; kalendář změn (CMDB) jako zdroj kontextu v produkci, v simulaci by zkreslil měření (A, kandidát 13) |
| 4b | Nová cloudová služba jednoho hostu (`saas_adoption`, nová držená lookalike) | **nové a vědomé** | FP 69,0 % výskytů (bez novosti 36,8 %) | cena obecné novosti; nález má nízkou závažnost, nezavírá se a doporučuje ověřit službu; po 3 dnech zvyku profil cíl naučí |
| 5 | Rychlý maják (tempo 2× až 8×) | **částečně** | v ladění c2 tempo 4× 54,3 → 61,0 % | obecná trvalost vazby; zbytek je krátké trvání (méně než 6 oken za 24 h) |
| 6 | Útok rozložený na 10 zdrojů | zůstává | viz `held-v3k5-v3k6.md`, osa zdroje | agregace přes zdroje neimplementována (kandidát 8) |
| 7 | lateral_movement | zůstává | 67,0 % (n = 197), legacy 69,5 % | graf (+20 p. b. v ladění) a `novel_fanout` (+16 p. b.) neprošly kvůli omylům a FP; další krok je graf, jehož případy žebřík nezavírá |
| 8 | Krátké útoky | zůstává | vlastnost útoku | – |
| 9 | Reálná data | zůstává | kotvy beze změny (2/30 škodlivých) | laboratoř a pasivní sběr (`lab-plan.md`) |
| 10 | ics_attack | nedostatečná data | n = 8 | cílený běh průmyslových sítí |
| 11 | Výpadek senzoru zvyšuje FP | **nové, vědomé** | sensor_crash 13,5 → 19,1 % výskytů se zobrazeným FP | cena opravy 1; okno výpadku je v UI vidět |

Na otázku, zda už nejsou žádná slepá místa: nejsou opravená. Dvě jsem opravil (1 a část 2 a 5). Dvě nová vznikla vědomě (4b a 11) jako cena za to, že engine nezavírá neznámé věci. Ostatní zůstávají s mitigací. Žádné slepé místo engine neschová tichým zavřením: kromě kontextů s auditem a žebříku s pozitivním důkazem se nic automaticky nezavírá.

### Odchylky od předregistrace (souhrn)

1. **F1:** `sensor_strict` doslovně nesplnil B5.3 (podíl omylů na ladění 1,47 → 1,49 %, počet omylů 34 → 33, jmenovatel menší o 91 správných zavření). Do sestavy jsem ho zařadil s tímto zdůvodněním. Sestava B5.3 splňuje.
2. **F2:** první spuštění drženého běhu (09:40) jsem po 10 minutách zastavil, aniž bych viděl jakýkoli výsledek, a držený běh se pustil jednou znovu.
3. Kandidát 2 je zamítnutý, ale jeho kód v enginu zůstává za přepínačem (`ops_class`), včetně produkční cesty. Je vypnutý a výchozí cestu nemění.
4. Sestava proti B5 na ladicích seedech proběhla s binárkou `22d62af`, držený běh s `8828834`. Rozdíl je jen v kódu za `ops_class`, `soak verify` s `8828834` nad ladicím výstupem `22d62af` dal 2/2 shodné bloky.

### Co zůstává otevřené

- G4 na nezatíženém stroji (po skončení 72h běhů) a podle výsledku přepnutí výchozího režimu.
- Proč důkaz E1 třídy provoz nezabírá (klíč nálezu proti cíli selhání). Bez opravy zůstává K3 nesplněný.
- Graf a `novel_fanout` s pravidlem, že jejich případy žebřík nezavírá, s novou předregistrací.
- Zbylé kontextové omyly (1b) pod cíl 2 %.
- Laboratoř, pasivní sběr a UHK (nic neodesláno).

## Commity kroku 6

`3054301` předregistrace, `4a461c1` kandidáti v enginu, `b5a913c` měření v soaku, `fecbe66` nástroj, `bf16fc3` třída provoz v produkční cestě, `22d62af` úprava novosti, `8828834` úprava třídy provoz, `f6afbe1` ladicí výsledky, `eb0fb1f` preset, a commit této sekce.

## Review kola 1 (sol-loop)

Nezávislé review kódu kroku 6 (GPT-6.1 Sol, kolo 1, jen čtení) našlo 3 blokery a 3 menší nálezy. Všechny jsou opravené nejmenší změnou. Ke každému je regresní test, který bez opravy selže. Ověřil jsem to tak, že jsem opravy dočasně vrátil: 6 z 6 testů selhalo a po obnovení prošly. Výchozí režim zůstává `legacy` a předregistrace (B) ani výběr sestavy se nemění.

| # | závažnost | nález | oprava | regresní test | změřený dopad (ladicí seedy, párově) |
|---|---|---|---|---|---|
| S1 | blocker | Značka třídy provoz (TTL 24 h) obešla pojistky: nový jednozdrojový útok se stejným `finding_id` dostal starý důvod provozu. | Značka nese otisk důkazu (klíč služby, seřazené dominantní zdroje). Bez čerstvého důkazu ji zneplatní jediný dominantní zdroj, zdroj mimo otisk, jiná služba nebo eskalace v paměti nálezu. Starý stav `ops_marks` se načte, značky bez otisku se zahodí (fail closed). | `ops_evidence::mark_is_invalidated_by_contradicting_evidence`, `legacy_ops_marks_state_loads_and_fails_closed` | jen rameno s `ops_class`: zobrazené ve frontě provoz 3 702 → 3 595 (−2,9 %), zobrazené FP ve frontě podezření 29 061 → 29 107 (+0,16 %), útoky zobrazené jen ve frontě provoz 20 → 19, K3 laděné 66,0 → 66,1 % |
| S2 | blocker | Brána kontextu nevylučovala typy novosti: záznam, který je výslovně pokrývá, by je zavřel nebo dodal žebříku neškodný důkaz. | `explain()` i `supporting_context()` odmítnou `novel_persistent_peer` a `novel_fanout` (společný seznam `behavior::novelty::NOVELTY_TYPES`). | `context_gate::novelty_types_are_never_explained_nor_supported_even_if_covered` | 0 (simulovaný kalendář novost nepokrývá, výchozí `covers` druhů ji neobsahuje). Jde o produkční pojistku. |
| S3 | blocker | Kontrola Profile vyvracela novost zvykem flotily (zvyk 14 dní proti novosti 7 dní, LR 0,35 a s peers 0,25 prior asi 0,015). | Pro oba typy novosti dává zvyk hostu i flotily výsledek „nezjištěno“ (žádný neškodný LR). Plán kontrol se nemění. | `verify_ladder::profile_habit_is_not_benign_evidence_for_novelty` (kontrola: `beacon_periodic` neškodný důkaz dál dostane) | 4 výsledky `profile:benign` → `undetermined` (všechny u neškodné pravdy), 2 sítě ze 120. Rozhodnutí žebříku, zobrazení ani zavření se nezměnila. |
| S4 | should | Každá IPv4 končící .255 se brala jako broadcast. | Směrovaný broadcast se počítá podle skutečného prefixu podsítě z rozsahu (nejdelší shoda, jen prefix ≤ 30). Bez známé podsítě se neuznává. Omezený broadcast a multicast platí vždy. | `ops_evidence::directed_broadcast_follows_real_subnet_prefix` | v soaku 0 (rozsah sítí je /24, takže .255 je skutečný broadcast). V produkci s /16 rozsahem 10.0.3.255 už do fronty provoz nejde. |
| S5 | should | Se zapnutým `novel_fanout` neměl vektor nových vazeb na hostitele strop. | `fanout_cap` (výchozí 256, nejméně `fanout_min`): další vazby v okně se nepřidají, pořadí je deterministické (BTreeSet), poplach při překročení prahu zůstává. | `behavior::novelty::fanout_relations_per_host_are_capped_deterministically` | 0 (`novel_fanout` je ve výchozích prazích vypnuté) |
| S6 | nit | Důvod na úrovni hostu bral první shodnou službu z náhodně uspořádané HashMap. | Služby se procházejí seřazeně, vyhrává nejmenší klíč. | `ops_evidence::host_level_reason_is_deterministic` | v rameni s `ops_class` je zahrnuté v S1 (samostatně neměřeno) |

**Měření dopadu.** Binárka před opravou `8828834` (ladicí výstupy z C) a po opravě `29dfabb`. Ladicí seedy 20261611 až 20261613, 3 × 40 sítí, stejné volby jako v C. Ramena: `v3k6` (`--v3-on sensor_strict,novelty`) a `v3k6 + ops_class`. Běželo se 2 ramena současně po 3 vláknech, s prioritou Idle, vedle dvou 72h běhů (zatížení stroje 38 až 51 %). Párová srovnání jsou v `k6/r1-tuning-k6set.md` a `k6/r1-tuning-k6set-ops.md`.

| rameno | detekce (cf, fronta podezření) | zobrazené FP / síť-den | zavřeno omylem (G3) | sítí se změnou |
|---|---|---|---|---|
| `v3k6` před → po | 79,9 % → 79,9 %, párově +0,0 p. b. (+0,0 až +0,0), 0 z 3 759 útoků jinak | 22,1 → 22,1 (29 279 = 29 279) | 33 / 2 518 → 33 / 2 518 (1,3 %, 0,9 až 1,8 %) | 2 ze 120 (jen výsledky kontroly Profile) |
| `v3k6 + ops_class` před → po | 79,7 % → 79,7 %, párově +0,0 p. b., 0 z 3 759 útoků jinak | 22,1 → 22,1; ve frontě podezření 21,93 → 21,97 | 33 / 2 518 → 33 / 2 518 | 25 ze 120 |

Opravy uzavírají cesty, které by v produkci mohly zavřít nebo odklonit útok. V simulaci se po nich detekce, FP i zavřeno omylem nezměnily. Výsledky kroku 6 (C, D a E) proto platí beze změny. Kandidát 2 (`ops_class`) zůstává zamítnutý. Po S1 klasifikuje do fronty provoz o 2,9 % méně položek, takže je ještě o něco slabší.

**Ostatní kontroly.** Výchozí i ladicí svět (`legacy`, seed 20261611, 4 sítě) dávají s binárkou po opravách stejný `networks.jsonl` jako binárka `8828834` (bajtově, po odečtení `wall_s` a `cycle_p99_s`). `soak verify` s konečnou binárkou `0ab8c55` nad výstupy po opravě (`v3k6` i `+ops_class`, seed 20261611) dal 2 ze 2 bloků bit po bitu shodné. Diagnostika paměti proto výsledky nemění. Golden snapshot, engine_v3, case_memory_learning, incremental_ingest a verification_execution jsou zelené. `cargo test --lib`: 494 testů prošlo, 5 selhalo, všechny `broker::tests` (známá výjimka, chybí Redis). `cargo clippy --all-targets`: lib 89, lib test 97, bin 3, e2e 1, tedy stejně jako HEAD `51a4f7b`. `cargo fmt --check` je čisté. Zpětná kompatibilita: starý stav `ops_marks` (`[čas, důvod]`), behaviorální stav bez `novelty` a prahy novosti bez `fanout_cap` se načtou (testy výše a `behavior::novelty::old_behavior_state_and_thresholds_load`). Formát paměti nálezů ani `engine-state` se jinak nemění.

### Paměť: stropy stavu novosti a třídy provoz a příčina 4+ GiB haldy

Stropy v kódu: `NoveltyState.pairs` ≤ 200 000 (nečinnost 3 dny), `fanout` ≤ 50 000 hostitelů a nově ≤ 256 vazeb na hostitele (S5), `Clientele` ≤ 100 000 služeb × 64 klientů (okno 7 dní), `OpsMarks` ≤ 200 000 (TTL 24 h). Všechny struktury mají strop i stáří.

Měření: diagnostika `BAKULA_SOAK_STATE_TRACE=1` (commit `0ab8c55`) vypisuje každých 48 cyklů velikost složek stavu v3 jako bajty serializovaného JSON. Je to přibližná míra, ne přesná halda. Jedna síť XXXL (9 350 zařízení, seed 20261611), 96 h, šum 10×, `--engine v3 --v3-on sensor_strict,novelty,ops_class`, 1 vlákno:

| cyklus | živá halda procesu | SQLite stav | profil hostů | detektor | beacon | inventář | egress | klientela | novost | ops_marks |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 47 | 813 MiB | 0,9 MB | 11,3 MB | 6,8 MB | 5,9 MB | 6,2 MB | 0,9 MB | 1,7 MB | 0 | 0 |
| 95 | 876 MiB | 1,2 MB | 16,3 MB | 9,7 MB | 8,8 MB | 6,3 MB | 1,3 MB | 2,1 MB | 0 | 0 |
| 143 | 921 MiB | 77,7 MB | 20,5 MB | 10,8 MB | 11,6 MB | 6,3 MB | 1,6 MB | 2,4 MB | 0,43 MB | 0 |
| 191 | 924 MiB | 77,9 MB | 23,1 MB | 11,5 MB | 10,3 MB | 6,2 MB | 1,7 MB | 2,5 MB | 0,61 MB | 0 |

Peak haldy této sítě je 1 054 MiB, stejná síť v `legacy` má 475 MiB. Po skončení sítě klesne živá halda na 0,2 MiB, takže mezi sítěmi nic nezůstává. Stav novosti a třídy provoz je malý (dohromady pod 3,2 MB JSON po 4 dnech na největší síti). Největší složky stavu v3 jsou SQLite (historie toků L0 po prvním zápisu, dál skoro neroste), profil hostů, detektor a beacon. Profil roste s dny pozorování a má vlastní strop a stáří (`profile.rs`). Zbytek haldy, zhruba 0,5 GiB i v `legacy`, tvoří simulace sítě a toky cyklu. Je úměrný velikosti sítě a šumu, ne délce běhu.

Příčina 4+ GiB u druhého 72h běhu (`run-v3-72h-b`, PID 45080): ten běh používá binárku kroku 4 (`b3a6dd0`), která novost ani třídu provoz vůbec neobsahuje. Běží s 12 vlákny, tedy až 12 sítí současně, se směsí šumu až 50× a s 1,5 % sítí XXXL. Peak 4 692 MiB je součet souběžných sítí. Živá halda kolísá mezi 1,1 a 4,1 GiB a regrese v `status.md` trend neukazuje (−64 MiB/h, R² 0,24, u druhého běhu +26 MiB/h, R² 0,06). Únik to není a nové stropy nejsou potřeba. Pro běh s pevnou pamětí stačí snížit `--threads` nebo podíl XXXL a šumu 50×.

### Co zůstává otevřené po kole 1

- Další kolo review (kolo 2) je na hlavní konverzaci.
- S2 a S4 jsou produkční pojistky, které simulace neprověří. Kalendář soaku novost nepokrývá a rozsah je vždy /24. Ověřují je jen jednotkové testy.
- Diagnostika paměti měří JSON, ne skutečnou haldu po složkách. Přesný rozpad (dhat) by vyžadoval novou závislost, a tu jsem nepřidával.

Commity kola 1: `65b2e0c` (S2), `3cf2ecd` (S3), `a571a15` (fmt), `1744631` (S5), `c563b9b` (S1, S4, S6), `29dfabb` (test zpětné kompatibility), `6bcfd8a` (clippy v testu), `0ab8c55` (diagnostika paměti) a commit této sekce.
