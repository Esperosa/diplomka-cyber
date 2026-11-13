# Revize metodiky a rizik: `00-zaver-jak-vylepsit-core.md` v1.0

Datum 2026-11-01. Zaměření: metodika, statistika a rizika závěrů. Studii ani jiné soubory jsem neměnil, nic jsem nespouštěl (kromě čtení CSV skriptem) a procesů `bakula-soak-*` jsem se nedotkl.

Závažnost: 0 = kosmetika, 1 = drobnost, 2 = zkresluje dílčí závěr, 3 = ohrožuje doporučení nebo plán, 4 = zneplatňuje studii.

## 0. Co jsem ověřoval a co ne

- **Řádky extrakce proti textu tvrzení (24 řádků):** RQ1-001, -017, -018, -019, -024, -038, -039, -040, -048; RQ2-019, -043; RQ3-001, -015, -020, -021, -025; RQ4-002, -012, -014, -023, -024, -039, -040, -047; RQ5-030; RQ6-001, -002, -003, -009, -031, -046. Nesoulad textu s řádkem jsem našel u 4 z nich (RQ3-025, RQ6-002, RQ1-024, RQ2-019), viz K1 až K4.
- **Zdroje přes veřejnou URL: neověřoval jsem.** Kvůli rozsahu (bez další široké rešerše) jsem tento bod vynechal. Plánovaných pět ověření zdrojů tedy chybí. Kandidáti na doplnění: RQ6-002 (arXiv 2610.10608), RQ3-025 (Stoll ACSAC09 PDF), RQ1-024 (USENIX LISA07 PDF), RQ4-039 (arXiv 2607.29390), RQ1-038 (arXiv 2609.02465).
- **Čísla z měření:** všech 14 čísel z [v1] sedí se `soak-findings.md` (210,7; 75 %; 22 %; 68 % z 74,1 M; 68,8/0,0 %; 2 301 z 5 061; 0,0 → 42,1 %; 4,7/0,3 %; 0,2 %; 12,5 %; Brier 0,0107; 8,7/1,7 %; 6 z 20; halda bez trendu). **`F:\Projekty\bakula-soak\run-v2b\status.md` se mezitím přepsal**: teď je to snímek po 1,25 h, 234 sítí a 1 955 síť-dnů, studie čerpala ze snímku po 1,00 h (190 sítí, 1 586 síť-dnů). Proto jsem u 18 čísel z [v2b] kontroloval konzistenci, ne přesnou shodu. 16 z nich je konzistentních (podíly FP typů 45,7/36,5/10,3/5,0 %, mimo rozpočet 89,7 %, exploit 67,5/0,0 % a IDS 185/461, exfil 0,0 → 35,1 %, c2 11,7 %, lateral 54,2 %, lookalike 98,2/94,5/89,4/75,8/74,3/0/0/0 %, Brier 0,0213, koš [0,9; 1) 83,0 %, identita 32,2/21,0 %, 6 z 20, halda +61 MiB/h). Dvě čísla konzistentní nejsou, viz K5 a K6.

---

## 1. Zjištění

### A. Citace, které tvrzení nepodporují nebo ho přetahují

**K1 (záv. 2): „bez stropu 15 až 80 % nerozhodnutých“ (§5 R10, Očekávaný efekt; také M12).**
Důkaz proti: RQ3-025 (BotProbe) má strop výslovně, „limit 3 kola kvůli rušení uživatelů“. Číslo 15,4 % je podíl nerozhodnutých *po* stropu 3 kol, ne bez něj. U TRW (RQ3-021) nezůstává > 80 % hostů nerozhodnuto kvůli chybějícímu stropu, ale proto, že vzdálení hosté udělají příliš málo pokusů. Strop na tom nic nezmění. Obě čísla tedy argumentují opakem: nerozhodnutost trvá i se stropem a eskalace je potřeba proto, že strop sám nestačí.
Oprava: přepsat na „i se stropem zůstává 15,4 % nerozhodnuto (BotProbe, 3 kola) a u TRW > 80 % hostů s málo pozorováními. Strop omezuje náklady, nerozhodnutost neřeší, proto je nutná eskalace nebo trojstav.“ Kritérium V3-H23 (nerozhodnutých > 15 %) přeformulovat stejně.

**K2 (záv. 2): §1 bod 5 a §6 „LLM jako ověřovatel: FNR 40,4 až 70,2 % na realistickém benchmarku“.**
Důkaz proti: RQ6-001, -002 a -003 pocházejí z téže práce (Tsegai et al., arXiv 2610.10608, jeden model GPT-4.1). Výraz „realistické benchmarky“ v množném čísle (§1) přesazuje. Táž citace v RQ6-002 pokračuje „…while AIDA reduces this rate to 3.1%“. Cílený vyšetřovací agent tedy v témže zdroji dosáhl FNR 3,1 %, a tento protichůdný údaj studie zamlčuje. Jistota M40 a M41 je „nízká“, přesto §1 formuluje kategoricky „LLM nepatří do verdiktní cesty“.
Oprava: uvést jeden preprint, jeden model a údaj AIDA 3,1 %. Doporučení zdůvodnit hlavně rizikem prompt injection (M44, střední) a chybějící nezávislou replikací, ne formulací, jako by bylo selhání LLM prokázané.

**K3 (záv. 2): M9 a R6 „ověření proti stavu cíle / kontextová degradace na službu, která v inventáři neexistuje nebo není zranitelná: 50 až 100 % (RQ1-024)“.**
Důkaz proti: ATLANTIDES (RQ1-024, LISA 2007) neověřuje inventář ani zranitelnost. Analyzuje anomálie v *odpovědích* serveru (výstupní provoz) po protokolech HTTP/FTP/SMTP/Telnet. Mechanismus, který R6 navrhuje (inventář a zranitelnost), je jiný a číslo 50 až 100 % se na něj nepřenáší. Navíc jde o protokoly s výstupem v otevřeném textu, který Salticus z toků nemá.
Oprava: v M9 a R6 uvést „ověření podle odpovědi služby (výstupní provoz)“ a u degradace podle inventáře napsat „bez přímého podkladu, mechanismus se liší“. V3-H12 posunout do P3.

**K4 (záv. 1): M23 „Holt-Winters se adaptuje na dlouhou anomálii a pozdější útok mine“.**
Důkaz: RQ2-019 dokládá adaptaci („will adapt itself to the anomaly data“) a 64 z 67 detekovaných. Řádek ale neříká, že by mineným útokem byl ten pozdější. Druhá polovina tvrzení je inference.
Oprava: „…se adaptuje na anomálii (64/67 detekováno, FPR neuvedeno). Že tím mine pozdější útok, je inference.“

**K5 (záv. 3): §4.3 „IoT-23: zdrojový lift 0,00× ve všech 10 scénářích“ (také D14).**
Důkaz proti: v [v2b] má `iot23/CTU-IoT-Malware-Capture-3-1` lift **10,75×**. Kotva je deterministická („nedeterministických průchodů: 0“) a při každém průchodu se přehrává totéž, takže hodnota nemohla mezi snímkem 1,00 h a 1,25 h vzniknout. Jde téměř jistě o chybně přečtenou tabulku. Na tomto čísle stojí „záhada“ v §4.3 i otevřená otázka 4 v §8.3. Tři honeypot scénáře navíc nemají žádný škodlivý provoz, takže u nich je lift 0,00× nedefinovaný, ne nulový.
Oprava: „lift 0,00× v 6 ze 7 scénářů IoT-23 se škodlivým provozem, 10,75× u Capture-3-1. U 3 honeypotů bez škodlivého provozu metrika není definovaná.“ Formulaci záhady upravit.

**K6 (záv. 1 až 2): D9 „rogue_device S 42 %, XL 0 %“.**
Důkaz: v aktuálním snímku je XL 4 % (n = 55) a 0 % je u XXL (n = 2). Mohlo jít o záměnu sloupců XL a XXL, tvrdit to ale nemohu, protože snímek 1,00 h už neexistuje. Ať tak či onak, n = 19 a n = 2 nedovolují tvrdit, že rogue „klesá s velikostí“.
Oprava: uvádět n u každé buňky a trend vyjádřit nanejvýš jako S 42 % (n = 19) proti L+XL+XXL ≈ 4 % (n = 81).

### B. Jistoty a vnitřní rozpory

**K7 (záv. 2): §6 řádek „Přebírat čísla z literatury jako cíl … RQ4 Z9 (vysoká)“.**
Rozpor s R-1 v §3, kde je RQ4 Z9 sjednocená na **střední** podle vlastního pravidla 2.2. Totéž se opakuje v §6 „Hodnotit jen AUC“, kde je M32 vedena jako střední, přestože RQ4 Z1 má nízkou (pravidlo nižší jistoty se tu nepoužilo, i když jde o poněkud jinou veličinu).
Oprava: sjednotit na střední, případně u každého řádku §6 uvést jistotu podle pravidla 2.2.

**K8 (záv. 1): M5 „o řády horší“.**
Důkaz: RQ4-039 ukazuje, že o řády klesá AP (32,27 → 0,09 %), kdežto AUC Argusu se skoro nezměnila (99,83 → 98,44). Čtenář si může vyložit, že selhalo všechno. Selhání je ve skutečnosti v provozním bodě a v přísném štítkování (RQ4-040, AUC kolem 50 %).
Oprava: přidat „AUC téměř beze změny, propad AP a AUC na přísně štítkovaných LM událostech“.

**K9 (záv. 2): §1 bod 6 „Tři z těchto čtyř bodů jsou strukturální chyby kódu“, kam patří i D5 (88,5 % plánů mimo rozpočet).**
Rozpor s §7.1, bod 8: „A32: soak plánuje stejnou funkcí jako produkce“ je mezi opravami harnessu. Soak tedy dnes neplánuje jako produkce, a D5 je proto aspoň zčásti artefakt harnessu. Jako strukturální chybu jádra jej lze tvrdit jen pro rozpočet 10/2 v produkčním `verification_exec.rs`.
Oprava: D5 označit jako smíšený jev (rozpočet jádra a plánovač soaku, A32) a podíl obou nechat rozhodnout E0.

**K10 (záv. 1): §2.1 „kontrola 23 id: vše nalezeno“ a „5 hodnot sedí“.**
Studie cituje řádově stovky id. Vzorek 23 existenčních a 5 hodnotových kontrol je pod laťkou, kterou protokol §9 klade na samotné RQ (≥ 30 %). Moje kontrola 24 řádků našla 4 nesoulady textu s řádkem (≈ 17 %, nad hranicí 5 % z protokolu §9), i když jde o nesoulad interpretace, ne opsaných hodnot.
Oprava: v §8.1 uvést, že souhrn má odhadovanou chybovost interpretace kolem 15 %, a před použitím v práci znovu projít všechna tvrzení s jistotou střední a vyšší.

### C. Logické mezery mezi diagnózou a doporučením

**K11 (záv. 3): D2 a §4.2 „FP rostou zhruba lineárně s velikostí sítě, sklon log-log ≈ 1,0 … maximum přes toky to vysvětluje“.**
Důkaz proti:
1. Sklon vznikl ze dvou koncových bodů (S a XL). XXL (2 701 zařízení) má **2 201** FP/síť-den, tedy méně než XL (4 302). Při n = 5 to sice nic nedokazuje, monotonní linearitu ale vyvrací.
2. Velikost je zmatená s archetypem: Cloud má 10 147 FP/síť-den při 463 zařízeních, Enterprise 1 467 při 914 (studie to sama uvádí v §4.3).
3. Sklon 1,0 je triviální očekávání, pokud je FP na zařízení konstantní. Na jeho vysvětlení není potřeba žádný mechanismus.
4. `packet_rate_spike`, na který se mechanismus „maximum přes toky“ vztahuje, tvoří jen ≈ 10 % FP, a sklon celku tedy vysvětlit nemůže. Dominantní `unexpected_traffic` (43 až 46 %) s mechanismem nesouvisí.
5. Snímková čísla jsou nestabilní: FP/síť-den vzrostl za 15 minut z 932 na 1 043 a vrstva 720 h ze 198,7 na 620,5 (n = 16 sítí). Snímek neměří stacionární veličinu.

Oprava: sklon odhadnout regresí přes sítě (log FP proti log zařízení s fixním efektem archetypu, clusterový CI) a zvlášť pro každý typ FP. Kauzální výklad „maximum přes toky“ omezit na `packet_rate_spike`.

**K12 (záv. 3): Největší zdroj FP nemá vlastní doporučení.**
`unexpected_traffic` tvoří 43,3 % [v2b] (teď 45,7 %), a je to tedy největší typ. Studie k němu má jen poznámku v R2 („pouštět jen na interní cíle“) a neověřenou hypotézu zastaralého inventáře (§8.2). R5 (packet rate, ≈ 10 %) a R7 (inductive, ≈ 37 %) mají vlastní H, `unexpected_traffic` nemá žádnou, ani očekávaný efekt, ani zamítací kritérium. Pro cíl „nižší šum“ je to největší mezera mezi diagnózou a doporučením.
Oprava: doplnit diagnostiku do E0 (rozpad `unexpected_traffic` podle příčiny: churn kontejnerů, onboarding, restart enginu se ztrátou inventáře, 501 restartů v [v2b]) a podle výsledku samostatné R s hypotézou V3-H38.

**K13 (záv. 2): R3 „strop správného typu ≈ 40,7 % … Výš to bez jiného zdroje nepůjde“.**
„IDS vidělo“ znamená, že k útoku dorazil aspoň jeden alert. Správný typ mohou dát i ne-IDS signály (např. behaviorální nebo bannerové kontroly). Oprava S2 a S6 navíc změní i viditelnost. Výrok o stropu je proto silnější, než data unesou.
Oprava: „při dnešním generátoru a výhradně IDS cestě je referenční mez ≈ 40 %“, bez slova strop.

**K14 (záv. 2): D3 precision ≈ 17 % a D1 FP/síť-den.**
Obojí je v jednotce nález × cyklus s opakovaným vydáváním (A14) a s benevolentní atribucí oknem ±2 cykly (S5). Atribuce posouvá nálezy z FP do „připsaných“, takže precision je nadsazená a FP podhodnocené, kdežto opakované vydávání obojí nafukuje. Směr výsledného zkreslení není znám. Studie to říká jen u základní četnosti.
Oprava: v D1 a D3 výslovně uvést jednotku a oba protichůdné zdroje zkreslení. Precision v §1 nepoužívat, dokud ji E0 nepřepočítá na incidenty.

**K15 (záv. 1): D1 sloupce v1 a v2b vedle sebe.**
v1 (11 rodin, 5 archetypů, bez provozních událostí) a v2b (19 rodin, 10 archetypů, lookalike) jsou jiné generátory. Řádek 210,7 proti 932,1 svádí k dojmu zhoršení.
Oprava: poznámka „nesrovnatelné: jiný generátor a jiný mix velikostí“.

### D. Odhady efektů

**K16 (záv. 1): převážně dobře označeno.** Studie u efektů zpravidla poctivě píše „bez podkladu“ nebo „odhad autora“. Výjimky:
- R2 „≈ 37 %“ pochází z diagnostického skóre `score_source_hosts` nad všemi toky, ne z produkčního detektoru po R2. Je to horní reference stejné metriky, ne očekávaný efekt změny.
- R6 „pracovní spodní hranice −30 %“ je odhad autora RQ6, který se v tabulce H mění v zamítací práh. Práh tím dostává zdání opory.
- Zamítací prahy označené „volba autora“ (H05, H09, H16, R3) jsou v pořádku, jen musí být zamražené před během (viz K19).

### E. Rizika experimentálního plánu

**K17 (záv. 3): statistická síla ochranného kritéria.**
Kritérium „horní mez 95% CI poklesu typované detekce ≤ 2 p. b. u každé rodiny s ≥ 100 útoky na rameno“ je test non-inferiority s mezí 2 p. b. U párového rozdílu při n = 100 a p ≈ 0,5 je SE nepárového rozdílu ≈ 7 p. b. Aby horní mez spadla pod 2 p. b. při skutečném efektu 0, musela by korelace ramen překročit zhruba 0,99. Clusterový bootstrap interval dál rozšíří (RQ5 H-7 očekává ≥ 1,5×). Prakticky každá H tak buď kritérium nesplní, nebo se bude vykládat volně. Navíc se kritérium uplatní na 19 rodin × až 37 H, tedy na stovky srovnání, a mnohá „selžou“ jen náhodou. Studie žádnou výpočetní analýzu síly nemá.
Oprava: předem spočítat sílu z dat [v2b] (párová korelace ramen, design effect přes sítě). Mez non-inferiority nastavit podle dosažitelného n (např. 5 p. b. pro rodiny s n < 500) nebo kritérium hodnotit na agregátu rodin s Holmovou korekcí, ne per rodina. Velikost vzorku na rameno určit z požadované šířky CI, ne z rozpočtu výpočtu.

**K18 (záv. 3): mnohonásobné testování a FDR.**
Holm-Bonferroni se plánuje jen „přes primární metriky potvrzujících H ve fázi E5“. Fáze E5 ale testuje hlavně finální konfiguraci proti v1 a H35 až H37, zatímco rozhodnutí o ponechání změn padá v E1 až E4 bez korekce. Každá H má navíc několik metrik a podmínek spojených „nebo“ (např. H10: pokles < 30 % u ≥ 3 ze 4 událostí nebo −5 p. b.), takže skutečný počet testů výrazně přesahuje 37. Některé H mají místo prahu jen „viz RQ…“ (H21, H23, H25, H27, H29 až H32), takže v tomto dokumentu předregistrované nejsou. Statistika je navíc nejednotná: R9 používá Wilcoxonův test s p > 0,05, jinde se rozhoduje bootstrapem a u řady prahů není řečeno, zda se vztahují k bodovému odhadu, nebo k mezi CI.
Oprava:
- Rozdělit H na konfirmační (≤ 10, s jednou primární metrikou) a průzkumné.
- Konfirmační hodnotit hierarchickým gatekeepingem (pevné pořadí E1 → E4) nebo BH na q = 0,05 přes všechny konfirmační testy.
- U každé H uvést jednu primární metriku, odhadovanou veličinu, test a to, zda se práh vztahuje k bodu, nebo k mezi CI.
- Všechny „viz RQ…“ rozepsat přímo do tabulky.

**K19 (záv. 3): opakované použití držených seedů a ladění proti testu.**
- E1 má „potvrzení na H“ a E5 testuje znovu na H. Držená sada se tak použije adaptivně nejméně dvakrát a rozhodnutí z E1 ovlivní konfiguraci v E5. Tím přestává být držená.
- Kotva CTU-13/IoT-23 slouží jako vývojová (R5 „na kotvě nárůst FP“, R7 „ověřuje na kotvě“, R11 „beacon se hlásí na CTU-13 jako primární“) a zároveň jako „primární pro tvrzení o detekční schopnosti“ v E5. Je tedy kontaminovaná laděním.
- Držené seedy pocházejí z téhož generátoru, který píše tentýž autor jako engine, a G0 generátor ještě mění. Držené seedy proto nechrání před spoluadaptací generátoru a enginu (cirkularita), chrání jen před přeladěním na konkrétní náhodu.
- Držené rodiny jsou slabé. fleet_beacon je příbuzná c2_beacon, na které se ladí. ics_attack má 11 útoků a vzniká jen v Industrial (L).

Oprava:
- Seedy H použít jen jednou, v E5. Pro E1 zavést třetí sadu V (validační).
- Kotvu rozdělit na vývojové a testovací scénáře, např. CTU-13 42 až 48 vývojové, 49 až 54 a IoT-23 testovací. Rozdělení zapsat před E0.
- Jako držený zdroj s jiným autorem doplnit aspoň jeden pcap replay (RQ5 S7).

**K20 (záv. 2): kumulativní design E2 a nezávislost jednotek.**
E2 skládá R6, R8 a R7 kumulativně na E1. Efekty se pak nedají oddělit, protože závisí na pořadí a interagují (identita resetuje baseline, jak studie sama píše). Bootstrap přes sítě je správně, musí ale být stratifikovaný podle seedu a archetypu, protože mix archetypů a délek je mezi sítěmi silně nevyvážený (Metro = XXL, n = 5). Párování (seed, network_id) předpokládá, že změna enginu nezmění generovaný provoz. U aktivních kontrol a zásahů to neplatí, protože blok mění provoz útočníka (zadrženo až 80 %), a ramena se tak rozejdou.
Oprava: v E5 dělat ablaci po jednom (leave-one-out) z finální konfigurace, bootstrap stratifikovat a u R10 hlásit i divergenci ramen.

**K21 (záv. 1): rozpočet výpočtu.**
Propustnost 0,05 sítě/s pochází ze snímku, ve kterém propustnost klesá (−4,1 cyklu/s za hodinu) a halda roste. Dlouhé sítě (720 h a 1 440 h) se navíc v časném snímku započítávají podle stavu, nejspíš neúplně. Odhad ≈ 180 h je proto spíš spodní mez.
Oprava: uvést rozsah a přepočítat ho po E0.

### F. Co chybí

**K22 (záv. 2): alternativní vysvětlení a negativní důkazy.**
- U D11 se vynechává flash_crowd 66,6 %, backup_burst 64,1 % a authorized_scanner 42 % s FP. To jsou lookalike události, které nejde vysvětlit kalendářem ani zdravím senzoru, na něž míří R6.
- Pro R4 chybí negativní důkaz, že agregace v korelačních enginech zvyšuje latenci detekce. Metrika TTD je v R4 uvedena, zamítací práh pro ni chybí.
- Jako alternativní vysvětlení D12 (podkonfidence p ≥ 0,6) chybí možnost, že Case Memory kalibruje na mix statických a behaviorálních typů. Studie to zmiňuje (A33), ale nevyvozuje, že rekalibrace bez rozdělení typů je zbytečná.

Oprava: doplnit do D11 a R6 a přidat práh TTD do V3-H08.

### G. Novost

**K23 (záv. 2): §8.4 „VOI/EVOI pro výběr ověřovací kontroly: nenalezeno“ a „Benigní vysvětlení jako konkurenční hypotézy ve velkém měřítku: nenalezeno“.**
Prior art (09) stojí na abstraktech. Sousední, dlouho známá linie je nákladově citlivá detekce a odezva (např. Lee et al., „Toward Cost-Sensitive Modeling for Intrusion Detection and Response“, J. Computer Security 2002) a rozhodovací a herně teoretické enginy odezvy (např. RRE, DSN 2009). Konkrétně u výběru *ověřovací* kontroly může být mezera skutečná, formulace ale musí zmínit, proč se tyto práce nepočítají. Benigní kontext jako konkurenční vysvětlení studie sama cituje u NoDoze (R-2 a R-3: kauzální kontext, −84 %), takže „nenalezeno“ v té podobě neplatí. Nový je nanejvýš tokový kontext s provozními událostmi.
Oprava: „Pro výběr ověřovací kontroly nad tokovými alerty se ground truth jsme měření nenašli. Sousední práce o nákladově citlivé odezvě existují a liší se tím, že…“ Benigní vysvětlení zúžit na „pro toky a provozní události“.

---

## 2. Verdikt

**PŘIJATELNÉ S OPRAVAMI.**

Studie poctivě odděluje naměřené od interpretace a spekulace, efekty převážně označuje jako „bez podkladu“, vyřazuje v2 a seed 20261101 a přiznává vlastní nezávislost i nedostatek kontroly. Žádné zjištění nemá závažnost 4. Slabá místa jsou ve dvou vrstvách:
- **Diagnóza dat:** chybně přečtená čísla (K5), korelační výklad sklonu (K11), největší typ FP bez doporučení (K12).
- **Experimentální plán:** neprověřená statistická síla (K17), mnohonásobné testování mimo E5 (K18), opakované použití držených seedů a kontaminovaná kotva (K19).

Předregistrace soaku v3 se v současné podobě nesmí zamrazit.

## 3. Deset nejdůležitějších oprav

1. **K19:** seedy H použít jen jednou (E5), pro E1 zavést validační sadu V. Kotvu rozdělit na vývojovou a testovací část předem.
2. **K17:** spočítat sílu ochranného kritéria z dat [v2b] (párová korelace ramen, design effect) a mez non-inferiority a n na rameno nastavit podle ní, ne naopak.
3. **K18:** rozdělit H na ≤ 10 konfirmačních a průzkumné, použít gatekeeping nebo BH přes všechny konfirmační testy, u každé H uvést jednu primární metriku a vztah prahu k bodu nebo mezi CI a rozepsat všechna „viz RQ…“.
4. **K12:** doplnit diagnostiku a samostatné doporučení s H pro `unexpected_traffic` (43 až 46 % FP).
5. **K11:** sklon FP vůči velikosti přepočítat regresí s efektem archetypu a po typech FP. Mechanismus „maximum přes toky“ omezit na `packet_rate_spike` a zmínit výjimku XXL.
6. **K5:** opravit „IoT-23 lift 0,00× ve všech scénářích“ (Capture-3-1 má 10,75×, honeypoty nemají definovaný lift) a podle toho upravit §4.3 a §8.3.
7. **K1:** opravit výklad nerozhodnutosti (BotProbe 15,4 % je se stropem 3 kol) a z toho odvozené kritérium V3-H23.
8. **K2:** u LLM uvést jeden preprint a jeden model, doplnit protichůdný údaj AIDA 3,1 % FNR a doporučení opřít o injection riziko a chybějící replikaci.
9. **K3 a K9:** ATLANTIDES neopravňuje efekt degradace podle inventáře (H12 přesunout do P3). D5 přeřadit ze „strukturální chyby jádra“ na smíšený jev s A32.
10. **K7 a K10:** sjednotit jistoty v §6 podle pravidla 2.2 (RQ4 Z9 je střední) a v §8.1 přiznat odhadovanou chybovost interpretace kolem 15 %. Před použitím v diplomce projít všechna tvrzení s jistotou střední a vyšší a ověřit 5 zdrojů přes URL, což tato revize nestihla.
