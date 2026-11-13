# RQ2: Statistické postupy a jejich doložený vliv na FPR/TPR u síťových anomálií

Datum: 2026-10-31. Protokol: `docs/diplomka/studie/00-protokol.md` v1.0. Data: `extrakce.csv` (53 řádků, id `RQ2-001` až `RQ2-053`), `hledani.csv` (28 dotazů), `neovereno.md`. Zdrojové texty (PDF a jejich textové výtahy) jsou mimo repozitář v `<pracovní adresář>/rq2\` (revizní stažení v `<pracovní adresář>/rq2rev\`). Všechny doslovné citace v `extrakce.csv` byly strojově ověřeny proti textu staženého PDF (53/53 nalezeno). Proběhla nezávislá kontrola (`kontrola-RQ2.md`, verdikt PŘIJATO S OPRAVAMI) a revize (`revize-RQ2.md`); stav po revizi popisuje tento text, původní hodnoty chyb jsou jen v revizním logu.

## 1. Abstrakt a hlavní závěry

Otázka: které statistické postupy (adaptivní a sezónní baseline, detekce změn, FDR, kalibrace, konformní metody) mají doložený vliv na FPR a TPR u síťových anomálií.

Hlavní zjištění (podrobně v §5, každé s id důkazů):

1. **Přímé „před/po“ měření FPR při dané TPR je u těchto postupů vzácné.** Čitelná měření na síťových datech existují jen pro per-entity detekci (Lévy-Leduc & Roueff, Hopper, Powell) a pro jednoduchý baseline proti složitému modelu (Arp et al.). Pro BH/FDR, konformní metody a kalibraci jsem nenašel žádné recenzované měření na entitách nebo tocích reálné sítě; existují jen výsledky na tabulkových či časových řadách a nerecenzované preprinty.
2. **Benchmarky časových řad jsou často řešitelné jednoduchým pravidlem a mezi detektory často není jasný vítěz** (Yahoo: 86,1 % řad řešitelných jedním řádkem; Schmidl: žádný jasný vítěz; ADBench: žádný z 14 nesupervizovaných detektorů statisticky lepší; střední jistota, nesíťová data). Že by jednoduchý robustní práh byl při nízkém FPR srovnatelný nebo lepší než složitý detektor, doložilo jediné síťové měření (Mirai v laboratoři: TPR 0,996 vs 0,882 při FPR 0,001; autoři sami uvádějí, že nedokazuje detekci v reálu), proto jen nízká jistota. Do harnessu přesto patří triviální baseline jako kontrola.
3. **Per-entity testování a denní rozpočet alertů jsou v literatuře spojeny s nízkým počtem FP při vysoké detekci, ale přímé srovnání jsou jen dvě a nejsou čistá:** 3/1/9/0 vs 69/65/62/22 falešných alarmů (RQ2-018; 4 útoky, jedna stopa, prahy post hoc, jiný detektor); 3 560 vs 27 927 FP při 94,5 % detekce (RQ2-024; Hopper vs jiný detektor SAL, ne per-entity vs globální). Násobné snížení FP nelze přičíst samotnému per-entity testování (nízká jistota).
4. **Hyperparametry mění FPR násobně** (PCA topk faktor >= 3; PELT/BOCPD F1 0,66-0,67 výchozí vs 0,86-0,89 oracle).
5. **BH nad konformními p-hodnotami drží průměrný FDR** u iid dat (nominál 0,2: 0,19 u KDDCup99), ale 90. percentil kalibrací nominál překračuje (0,23) a při malé kalibrační množině klesá síla k nule.
6. **Porušení výměnnosti (drift, adverzní posun) rozbíjí záruky:** pokrytí konformní predikce při cíli 0,95 kleslo na 0,08 až 0,85; ECE vzrostlo z <= 0,007 na 0,170-0,209. Časový posun snižuje výkon supervizovaných IDS: UGR'16 červenec -> srpen F1 0,96 -> 0,687 (jeden měsíc, motivační měření autorů) a MAWI 2011 -> 2021 AUC 0,90 -> 0,61 (RF, 10 let). Pokles F1 0,99 -> 0,61 mezi CIC-IDS-2017 a 2018 je přenos mezi dvěma různě sestavenými kolekcemi, ne drift téhož provozu, a jako důkaz časové škály se nepoužívá.
7. **Hlášené výkonnosti jsou citlivé na protokol:** AP na LANL klesla při jednotném preprocessingu z 5,23 na 0,02 (Euler) a z 32,27 na 0,09 (Argus); „o řády“ platí jen pro LANL a OpTC v jediném preprintu (Larroche), střední jistota.

Silné stránky studie: doslovně ověřené citace, uvedené negativní výsledky. Slabiny: většina zdrojů je E3 (jedna síť nebo benchmark), část jsou preprinty, o peer-group baselinech pro zařízení a o FDR při tisících entit v IDS jsem nenašel žádné měření (§9).

## 2. Metodika a PRISMA

Hledání: webové vyhledávání (28 dotazů, viz `hledani.csv`; 7 dotazů typu „proti“: kritika, selhání, drift, base-rate, chybějící srovnání), plné texty přes PDF stažené a převedené `pdftotext` (přímé načtení PDF vracelo nečitelný binární obsah). Období 2015-2026, starší práce označeny `seminal=ano` (Ringberg 2007, Soule 2005, Münz & Carle 2008, Brauckhoff 2010, Lévy-Leduc & Roueff 2009). Hodnoty a citace v `extrakce.csv` pocházejí z textu PDF; citace (<= 25 slov) byly strojově porovnány s textem. Citační řetězení bylo omezené (viz §8); do plného textu se nedostaly Sommer & Paxson 2010, INSOMNIA 2021 ani Brauckhoff INFOCOM 2009 (servery odmítly spojení nebo vrátily 403).

| Krok PRISMA | Počet | Poznámka |
|---|---:|---|
| Identifikováno (zobrazené odkazy) | ~280 | 28 dotazů x 10 výsledků; přesný počet unikátních děl nebyl logován |
| Po deduplikaci a odstranění vendor stránek, patentů, blogů | ~120 | odhad autora, nelogováno |
| Vybráno po titulu/abstraktu k otevření | ~58 pokusů | |
| Plný text získán | 42 děl | ~25 pokusů o stažení selhalo, část šlo nahradit jinou URL (viz `neovereno.md`) |
| Vyřazeno po zhodnocení plného textu | 11 | PAC-Wrap (bez sítě, bez použitelné hodnoty), Bashari/Sesia e-hodnoty (jen simulace), Komolafe (grafové sítě, ne provoz), Skaperas (syntetika), Kitsune (hodnoty jen v grafech), Camarda (KDD99), Costa (generátor driftu bez FPR), Yumlembam (konformní botnet, bez čísel v textu), Araz (fyzika částic), Wilmet (bez FPR), Spark scan (stažen, nepřečten, vyřazen po titulu) |
| Zahrnuto do extrakce | 31 děl, 53 řádků | |
| z toho V3 / V2 | 30 děl (50 řádků) / 1 dílo (3 řádky) | V2: abstrakt disertace Brauckhoff (tělo 300 tis. znaků nečteno) |
| Řádky s číselnou hodnotou | 42 | cíl 40 splněn těsně |
| Nezávislá kontrola (protokol §9) | 37 z 53 řádků (70 %) | 2026-10-31, nezávislý kontrolor; vzorek A = 29 řádků, na nichž stály závěry se střední/vysokou jistotou, vzorek B = 8 řádků ručně napříč zdroji (bez seedu); věcná chybovost 0/37 (0 %), drobné chyby 6/37 (16 %), neověřitelné 0; verdikt **PŘIJATO S OPRAVAMI** (`kontrola-RQ2.md`) |
| Revize po kontrole | 16 dosud nekontrolovaných řádků znovu ověřeno u zdroje; upraveno 12 řádků extrakce | viz `revize-RQ2.md`: opraveny drobné chyby (001, 018, 031, 038, 039, 046, 050; URL u 014, 015, 051), při vlastním ověření nalezena další nepřesnost (047) a doplněn dataset u 052, sníženo nebo rozděleno 6 závěrů (Z1, Z4, Z5, Z6, Z8, Z9); neověřitelné řádky žádné, takže `neovereno.md` se nerozrostlo |

Cíle protokolu: >= 30 přečtených zdrojů (splněno: 31 zahrnutých + 11 vyřazených), >= 20 s V3/V2 (31), >= 40 číselných řádků (42), nezávislá kontrola >= 30 % a >= 20 řádků (splněno: 70 %, 37). Po revizi je znovu zdrojem ověřeno všech 53 řádků (37 kontrolorem, 16 autorem revize; řádky 007 až 009 jen na úrovni abstraktu, V2). Strojová kontrola citací nenahrazuje kontrolu čtení tabulek; ta proběhla nezávisle jen u vzorku. Z původních hodnot chyb nic nezůstalo v hlavním textu, původní znění je v revizním logu.

Poznámky ke zdrojům: DOI Schmidl (`10.14778/3538598.3538602`) a Lévy-Leduc & Roueff (`10.1214/08-AOAS232`) se nepodařilo otevřít jako PDF; hodnoty jsou ověřeny na vldb.org PDF resp. na preprintu arXiv 0908.2310 (stejná práce, ne finální časopisecká sazba). URL USENIX u Soule et al. v době revize vrací HTML stránku, ne PDF; hodnoty jsem ověřil na dříve staženém PDF téže práce.

## 3. Výsledky podle podtémat

Zkratky: E = úroveň důkazu, B = riziko zkreslení, FDR = míra falešných objevů, BH = Benjamini-Hochberg, CP = konformní predikce, AP = average precision, ECE = expected calibration error.

### 3a. Detekce anomálií objemu a toků: EWMA/CUSUM, sezónní baseline, Holt-Winters, jednoduché vs složité modely

| id | Zdroj, data | Metoda | Výsledek | E / B |
|---|---|---|---|---|
| RQ2-001 | Münz & Carle, ISP backbone toky | Shewhart/CUSUM/EWMA na rezidua | 11 / 15 / 11 alarmů na řadě bytů (bez ground truth) | E3 / vysoké |
| RQ2-002 | tamtéž | Holt-Winters vs exp. vyhlazování | rezidua „quite similar“, HW nepřináší zjevné zlepšení | E3 / vysoké |
| RQ2-003 | tamtéž | kontrolní grafy | „many anomalies are provoked by legitimate traffic“ | E3 / vysoké |
| RQ2-006, 053 | Soule et al., Abilene, 27 anomálií | Kalman filtr + test reziduí | TPR 100 % při FPR 7 % (základní test), další metoda ~85 %; zpoždění 0 u 95 % (basic) vs 90 % (GLR) | E3 / vysoké |
| RQ2-004, 005 | Ringberg et al., Abilene + Géant | PCA | FPR se mění faktorem >= 3 v malém rozsahu topk; heuristika 3 sigma dává 3x vyšší FPR než ideál | E3 / střední |
| RQ2-007 až 009 | Brauckhoff 2010 | PCA s časovou korelací; histogramy + asociační pravidla | přesnost až +20 %; čas řešení alarmu z ~1 h na minuty (V2, abstrakt) | E3 / střední |
| RQ2-019 | Nguyen et al., testbed | Holt-Winters nad toky | 64 z 67 vložených útoků; HW se adaptuje na opakované anomálie a poslední útok mine; FPR neuvedeno | E3 / vysoké |
| RQ2-020 | Beach & Modaff (studentská zpráva) | Holt-Winters | krátká data -> „higher amount of false positives“; bez metrik | E4 / vysoké |
| RQ2-010, 011 | NAB (58 souborů, nesíťové) | HTM, Twitter ADVec (sezónní ESD), Skyline, random | NAB skóre (Standard): 64,7 / 47,1 / 35,7 / 16,8; v profilu „Reward low FP“ 56,5 / 33,6 / 27,1 / 5,8 | E3 / střední (autoři jsou tvůrci HTM) |
| RQ2-012, 013 | Wu & Keogh | one-liner pravidla | 316 z 367 řad Yahoo (86,1 %) řešitelných jednořádkem | E3 / střední |
| RQ2-014, 015, 051 | Schmidl et al., 976 datasetů, 71 algoritmů | široký benchmark | žádný jasný vítěz; deep learning nekonkurenceschopný; AUC-ROC 0,54 (RobustPCA) až 0,83 (DWT-MLEAD) | E2 / nízké |
| RQ2-046 | ADBench, 57 datasetů, 30 algoritmů (14 nesupervizovaných) | nesupervizované AD | žádný z 14 nesupervizovaných algoritmů není statisticky lepší (nic o jednoduchých prazích) | E2 / nízké |
| RQ2-021 | Arp et al., Mirai | Kitsune vs boxplot na počet paketů | AUC 0,968 vs 0,998; TPR při FPR 0,001: 0,882 vs 0,996 | E3 / střední |
| RQ2-047, 048 | Adaptive NAD, CIC-Darknet2020, Edge-IIoTset | online adaptivní dvouprahový VAE | FAR/MDR (%): 1,33/12,21 vs HST 2,72/35,24 a OCSVM 0,29/96,95; Edge-IIoTset 0,08/18,52 vs SOM 8,57/12,98 | E3 / střední |
| RQ2-044 | MAWIFlow (MAWILab 2011/2016/2021) | RF vs CNN-BiLSTM | AUC RF 0,90 -> 0,61 při tréninku 2011 a testu 2021; CNN-BiLSTM 0,89 -> 0,79 | E3 / střední |

Interpretace: u rezidui po sezónním odstranění nenašel žádný přečtený zdroj, že CUSUM nebo Holt-Winters výrazně zlepšuje FPR proti jednoduchému prahu na reziduích. Münz & Carle nemají ground truth, takže nelze říci nic o TPR. Pro robustní z-skóre (MAD) jsem **nenašel žádné měření na síťových datech** (dotaz #19 vrátil jen obecné statistické zdroje). Mimo-sezónní NAB/Yahoo ukazují, že benchmarky se dají „vyhrát“ jednoduchými pravidly, proto jsou nevhodnou kotvou. Na MAWI/CIC jsem nenašel statistický baseline (EWMA, STL) vs model; MAWIFlow porovnává jen modely mezi roky.

### 3b. Peer-group a per-entity baseline, cold-start

| id | Zdroj | Výsledek | E / B |
|---|---|---|---|
| RQ2-018 | Lévy-Leduc & Roueff, ISP trace | per-cílový change-point (TopRank) vs CUSUM na agregátu: falešné alarmy 3/1/9/0 vs 69/65/62/22 pro SYN flood 1000/500/200/50 SYN/s; prahy (p-hodnota, h) u každého útoku post hoc na nejmenší detekující hodnotu; falešný alarm jen vůči 4 vloženým útokům | E3 / vysoké |
| RQ2-026 | Powell, 78 privilegovaných účtů, 4 týdny historie | per-uživatelská baseline: FPR 1,6 % a 2,2 %, TPR 98 % a 96 % (simulované útoky) | E3 / střední |
| RQ2-023 až 025 | Hopper, 15 měsíců, 780 mil. loginů | spec. + anomálie s denním rozpočtem alertů z 30 dní historie: 94,5 % detekce, < 9 alertů/den; SAL při stejném TPR 27 927 FP vs 3 560; rozpočet 5/den -> 95 % „unclear“ útoků | E3 / střední |
| RQ2-031 | Hennhöfer & Preisach | malá kalibrační množina (n_train 106-5 461): deterministická EDF a deterministická vážená EDF -> FDR 0 a síla 0 (nulové objevy); randomizovaná vážená EDF síla 0,100; KDE 0,417 (WBC) | E3 / střední |
| RQ2-047 | Adaptive NAD | počáteční prahy z 5. a 95. percentilu na 1 % dat; přeladění po 500 anomáliích | E3 / střední |

**Peer-group baseline pro zařízení (podobná zařízení jako prior pro nové zařízení) jsem nenašel jako měřený postup.** Nalezené „peer analysis“ jsou patenty (V1) a seskupování uživatelů. Cold-start doložen jen nepřímo: malá kalibrace -> nulová síla (RQ2-031), per-uživatelská baseline potřebovala 4 týdny (RQ2-026). Tvrzení výrobce (Dynatrace) o 14 dnech je v §10 a do závěrů nejde.

### 3c. Detekce změn (PELT, BOCPD)

| id | Zdroj | Výsledek | E / B |
|---|---|---|---|
| RQ2-016, 017 | van den Burg & Williams, 37 řad (nesíťové) | F1 (univariate), výchozí parametry: PELT 0,674, BOCPD 0,662, Binseg 0,698, „zero“ 0,645; oracle: PELT 0,864, BOCPD 0,886 | E2 / nízké |
| RQ2-018 | Lévy-Leduc & Roueff | viz 3b (změnový test per-cíl) | E3 / střední |
| RQ2-034 až 037 | Youssef (CALIBURN, BOCPD IDS) | autor sám v pozdější verzi uvádí, že popis skóre nesedí na kód a proudy jsou sestavené konstrukce | E3-E5 / vysoké |

PELT i BOCPD jsou bez ladění jen o 0,02-0,05 F1 nad metodou „nehlásit žádnou změnu“; po oracle ladění o 0,2. Síťový benchmark porovnávající PELT a BOCPD s ground truth jsem **nenašel**. Výsledky CALIBURN/BOCPD IDS se nesmí použít jako důkaz (viz Hrozby).

### 3d. Multiple testing a FDR

| id | Zdroj | Výsledek | E / B |
|---|---|---|---|
| RQ2-028 | Bates et al. (Ann. Statist. 2023), nominál 0,2 | BH nad konformními p-hodnotami: KDDCup99 průměrný FDR 0,194 (90. percentil 0,23), síla 0,754; podmíněná kalibrace FDR 0,131 (0,168), síla 0,684 | E2 / nízké |
| RQ2-029 | tamtéž | cena podmíněné záruky: síla Digits 0,417 -> 0,096, Mammography 0,176 -> 0,059 | E2 / nízké |
| RQ2-030 | tamtéž | důkaz: p-hodnoty jsou pozitivně závislé, BH dává přesný marginální FDR | E2 / nízké |
| RQ2-032 | Rebjock et al. (Amazon) | online FDR (LORD, SAFFRON): síla klesá k nule při nízkém podílu anomálií; verze s decay pamětí to řeší, ale cílové FDR na SMD drží nepřesně | E3 / střední |
| RQ2-033 | nonconform (CPAL 2026) | IForest + split CP + BH, alfa 0,2: FDR 0,18, síla 0,99 (Shuttle, jedno spuštění) | E3 / střední |
| RQ2-026 | Powell | autoři upozorňují, že při denním testu desítek účtů budou FP významné | E3 / střední |

**Nenašel jsem recenzované měření BH/FDR při tisících entit v IDS nebo síťových alertech** (dotazy #5 a #28). Všechna FDR měření jsou na tabulkových datech (ODDS/UCI) nebo časových řadách bez síťové struktury, tedy nepřímá.

### 3e. Kalibrace skóre a konformní predikce

| id | Zdroj | Výsledek | E / B |
|---|---|---|---|
| RQ2-034 | CALIBURN v1 (nezávislý autor) | isotonická kalibrace snižuje Brier o 30 % (LITNET-2020), 32 % (CICIDS2017), 63 % (UNSW-NB15) proti surovému posterioru BOCPD | E3 / vysoké |
| RQ2-035 | tamtéž | při prevalenci 64 % všechny streamingové metody blízko prevalenčního dna; CRC kolabuje při malém alfa | E3 / vysoké |
| RQ2-041 | Li (preprint 2026), LLaMA3-8B, alfa 0,05 | pokrytí standardní CP po perturbaci: HIKARI 0,849 / 0,837; RT-IoT 0,09 / 0,08; CIC-IDS-2018 0,39 / 0,36; traffic-aware CP vrací ~0,95, ale za cenu sad o velikosti ~4,2 štítku | E3 / střední |
| RQ2-042, 043 | Alalawi (IJACSA 2026), NSL-KDD, UNSW-NB15 | ECE <= 0,007 in-distribution; pod posunem 0,170-0,209 (NSL-KDD), 0,025-0,068 (UNSW); rekalibrace na tréninkových datech se nepřenese, ~100 štítků z cílové distribuce dá většinu zlepšení | E3 / střední |
| RQ2-045 | Martinez Gil et al. (ICLR 2026), nesíťové KPI řady | průměrná FPR (oracle práh): Gaussian 0,123 -> konformní 0,111 -> adaptivní vážená 0,077; CalErr 0,075 / 0,038 / 0,025 | E3 / střední |

Platt vs isotonic vs temperature scaling: **porovnání na síťových datech jsem nenašel** (dotaz #26). Isotonické zlepšení Brier (RQ2-034) pochází od autora, který později opravil popis kódu a přiznal sestavené proudy, proto má velmi nízkou jistotu. Konformní záruky při porušení výměnnosti: měřený rozpad v RQ2-041 (adverzní perturbace, ne přirozený drift) a vážená adaptace v RQ2-045 (mimo síť).

### 3f. Concept drift a sezónnost v IDS

| id | Zdroj | Výsledek | E / B |
|---|---|---|---|
| RQ2-038 | Gupta et al. (KDD'25), motivační měření autorů metody | CIC-IDS: trénink 2017, test 2018 (dvě různě sestavené kolekce, ne drift téhož provozu): F1 0,99 -> 0,61 (0,61 odpovídá Tab. 3, 60,62); UGR'16 červenec -> srpen (skutečný časový posun, 1 měsíc) 0,96 -> 0,687 (úvod; Tab. 5 bez adaptace: MLP 68,77, XGBoost 74,33) | E3 / střední až vysoké |
| RQ2-039 | tamtéž | adaptace s 1 % štítků při přenosu CIC-IDS-2017 -> 2018: F1 0,60 -> 0,86 (Tab. 3: 60,62 -> 86,00); vzácné útoky 0,001 -> 0,30, 0,04 -> 0,50, 0,00 -> 0,71 (RQ2-052, tamtéž 2017 -> 2018) | E3 / střední až vysoké |
| RQ2-040 | Drago et al. (ITASEC 2026) | drift detektor bez štítků: F1 0,928 při 5,4 % štítků vs 0,978 při 100 % (NSL-KDD) | E3 / vysoké |
| RQ2-044 | MAWIFlow | viz 3a | E3 / střední |
| RQ2-042 | Alalawi | viz 3e | E3 / střední |

Časová škála skutečného časového posunu v měřeních: jeden měsíc (UGR'16, jedno měření) a roky (MAWI 2011 -> 2021, jedno měření). Hodnota „rok“ z CIC-IDS-2017 -> 2018 není časová škála driftu, jde o přenos mezi dvěma kolekcemi. Sezónnost (den/týden) jako příčina FP u IDS jsem v recenzované literatuře neměřenou nenašel; zdroje o sezónních baselinech jsou vendor dokumentace (§10).

### 3g. Validita hodnocení (protínající závěr)

| id | Zdroj | Výsledek | E / B |
|---|---|---|---|
| RQ2-027, 050 | Larroche | AP při jednotném preprocessingu: LANL Euler 0,02 (hlášeno 5,23), Argus 0,09 (32,27); OpTC Argus 3,36 (80,74) | E2 / nízké |
| RQ2-036 | Youssef v3 | CICIDS2017: testovací vzorky sdílejí jen 32,5 % záznamů; prevalence 68,235 % vs 25,2396 % podle sestavení proudu | E3 / střední |
| RQ2-022 | Arp et al., 30 článků | sampling bias 90 %, data snooping 73 %, každý článek >= 3 pitfally | E1 / střední |
| RQ2-049 | Erbacher | base-rate fallacy; FP si zaslouží stejnou analýzu jako TP | E5 / střední |

## 4. Syntéza (rozsahy bez sdružování)

Protokol §8 povoluje kvantitativní souhrn jen při >= 3 studiích se stejnou metrikou a srovnatelnými podmínkami. **Takové sdružení tu není možné:** metriky (FPR, FDR, AP, F1, ECE, pokrytí, počet alarmů) i datasety se liší. Uvádím rozsahy v rámci metriky:

| Metrika | Studií / datasetů | Rozsah (min až max) | Heterogenita |
|---|---|---|---|
| Snížení FP při přechodu na per-entity / budget | 2 přímá srovnání (Powell má jen absolutní FPR 1,6-2,2 %, bez srovnání) | ~8x (Hopper 27 927 -> 3 560 při stejném TPR, jiný detektor); 7x až 65x v poměru alarmů (Lévy-Leduc 62/9 až 65/1; u 22/0 nedefinováno; prahy post hoc) | vysoká: odlišné útoky, jednotky, srovnávané metody se liší víc než jen entitou |
| Empirický FDR při nominálu 0,2 (BH + konformní p-hodnoty) | 2 zdroje, 7 + 1 dataset | 0,001 až 0,202 průměr; 90. percentil až 0,266 (Digits) | střední; vždy iid tabulková data |
| Pokles F1/AUC při časovém posunu | 2 zdroje (UGR'16, MAWI) | F1 0,96 -> 0,687 (měsíc); AUC 0,90 -> 0,61 (RF, 10 let) | střední: jiné modely a metriky, každé jedno měření. Přenos CIC-IDS-2017 -> 2018 (F1 0,99 -> 0,61) sem nepatří, jsou to dvě různé kolekce |
| Pokrytí konformní predikce po posunu (cíl 0,95) | 1 zdroj, 3 datasety | 0,08 až 0,85 | jediný autor, adverzní posun |
| Rozdíl výchozí vs oracle F1 u change-point metod | 1 zdroj, 37 řad | PELT +0,19, BOCPD +0,22 | n/a |

Rozpory: (i) Soule uvádí 100 % TPR při 7 % FPR na Abilene, což je u tisíců entit nepoužitelné; Hopper dosahuje 0,12 % FPR, ale s jinou úlohou. Neřeší se jedna metrika, ale kvalita úlohy (agregace, per-entity, doménová specifikace). (ii) CNN-BiLSTM drží výkon při driftu lépe než RF (RQ2-044), ale Arp et al. ukazují, že jednoduchý baseline porazí složitý model; nejde o spor, jde o rozdílné protokoly. (iii) Adaptivní baseline se může otrávit (RQ2-019), kdežto adaptivní kalibrace zlepšuje FPR (RQ2-045); rozdíl: adaptace baseline vs adaptace prahu.

## 5. Závěry

| Z-id | Tvrzení | Důkazy | Jistota | Důvody snížení jistoty | Použitelnost pro Salticus | Doporučená akce |
|---|---|---|---|---|---|---|
| Z1a | Benchmarky časových řad (Yahoo, NAB) jsou často řešitelné jednoduchým pravidlem a mezi detektory často není jasný vítěz; deep learning zatím není konkurenceschopný. | RQ2-012, 013, 014, 015, 046, 051 | střední | nesíťová data; RQ2-046 se týká jen 14 nesupervizovaných algoritmů a o jednoduchých prazích nic netvrdí; RQ2-051 jen ukazuje rozptyl mezi rodinami | ano | do harnessu zařadit triviální baseline a nepovažovat Yahoo/NAB za důkaz sofistikovanosti |
| Z1b | Jednoduchý robustní práh bývá při nízkém FPR srovnatelný nebo lepší než složitý detektor (u síťových dat). | RQ2-021 | **nízká** (dříve střední) | jediné síťové měření (Mirai, laboratoř, velmi nápadný provoz); autoři sami říkají, že nedokazuje detekci v reálu; ostatní řádky o prazích nic netvrdí | s úpravou | porovnávat TPR při pevné FPR proti triviální baseline, ale nespoléhat na tvrzení jako na doložené |
| Z2 | Přidání složité sezónní/CUSUM struktury nad rezidua nemá doložený přínos; dostačují rezidua + jednoduchý práh. | RQ2-001, 002, 053 | nízká | bez ground truth (Münz), Abilene 27 anomálií, nerecenzováno, žádné FPR | ano | začít s EWMA/robustním prahem nad denním profilem, CUSUM/HW zavést až po A/B |
| Z3 | Adaptivní baseline (Holt-Winters) se adaptuje na dlouhotrvající anomálii a pozdější útoky mine. | RQ2-019 | nízká | testbed, 1 zdroj, 3/67 minuto, FPR neuvedeno | ano | zmrazit baseline entity při aktivním alarmu, ověřit H4 |
| Z4 | Per-entity testování a rozpočet alertů jsou spojeny s nízkým počtem FP při vysoké detekci; násobné snížení FP je doloženo jen ve dvou nečistých srovnáních (jiný detektor, post hoc prahy). | RQ2-018, 024 (přímá srovnání); RQ2-023, 025 (rozpočet, bez srovnání s globálním prahem); RQ2-026 jen jako absolutní údaj FPR 1,6-2,2 %, ne důkaz snížení | **nízká** (dříve střední) | RQ2-018: 4 útoky, jedna stopa, prahy post hoc; RQ2-024: Hopper vs SAL je jiný detektor, ne per-entity vs globální; efekt „specifikace“ nelze oddělit od „rozpočtu“; simulované útoky | s úpravou | testovat per-entity vs globální práh a denní rozpočet odděleně (H1, H2) |
| Z5a | Parametry detektorů (topk u PCA, penalizace PELT, hazard BOCPD) mění FPR/F1 řádově desítky procent až násobně. | RQ2-004, 005, 016, 017 | střední | PCA je podle studie mimo rozsah (E3, ruční ground truth); change-point měření jsou nesíťová | ano | prahy a penalizace ladit na držených seedech, uvádět variabilitu |
| Z5b | Ladění parametrů na štítcích je nutné. | (extrapolace z RQ2-017) | **nepodloženo měřením** | normativní závěr; oracle v RQ2-017 je horní mez nedosažitelná bez štítků a neříká, zda existuje lepší postup bez štítků | s úpravou | brát jako pracovní předpoklad, ne jako doložené |
| Z6a | BH nad konformními p-hodnotami drží průměrný FDR u iid dat, ale ne v každé kalibraci (90. percentil nad nominálem) a stojí sílu. | RQ2-028, 029, 030, 033 | střední (iid tabulková data), **velmi nízká** pro síťové entity | žádné měření na síťových entitách, nepřímost | s úpravou | prototyp BH/BY nad per-entity p-hodnotami, měřit FDR vs nominál (H3) |
| Z6b | Při malé kalibrační množině může konformní AD s deterministickým odhadem nic neobjevit (RQ2-031, WBC); u online FDR (LORD, SAFFRON) klesá síla k nule při vzácných anomáliích (RQ2-032, syntetická data; netýká se BH nad konformními p-hodnotami). | RQ2-031, 032 | **nízká** (nové rozdělení Z6) | malé tabulkové datasety, preprinty, syntetika u 032 | s úpravou | hlídat velikost kalibrační množiny; online FDR s decay pamětí jen jako hypotéza |
| Z7 | Při porušení výměnnosti (posun, drift) konformní pokrytí a kalibrace pravděpodobností klesají; rekalibrace vyžaduje štítky z nové distribuce. | RQ2-041, 042, 043, 045 | nízká | preprint(y), adverzní posun místo přirozeného driftu, staré datasety, nesíťová data (045) | ano | monitorovat ECE/FPR na držených rodinách, rekalibrovat po ~100 verdiktech (H5, H6) |
| Z8a | Supervizované IDS ztrácí výkon při časovém posunu (UGR'16 jeden měsíc, MAWI roky). | RQ2-038 (jen část UGR'16), RQ2-044 | střední pro směr; **nízká** pro časovou škálu „měsíce“ (jedno měření) | jedno měření na škálu, motivační měření autorů, různé metriky; CIC-IDS-2017 -> 2018 (RQ2-038, 039) je přenos mezi dvěma kolekcemi a z důkazů o driftu je vyřazen | s úpravou | plánovat sledování driftu a přetrénování (H7) |
| Z8b | Adaptace s malým rozpočtem štítků část výkonu vrací. | RQ2-039 (přenos 2017 -> 2018, 1 % štítků), RQ2-040 (NSL-KDD, simulovaný drift) | **nízká** | vlastní měření autorů metody, přenos mezi kolekcemi, zastaralý NSL-KDD | s úpravou | hypotéza H7, ne doložený postup |
| Z9 | Hlášené výkony IDS/lateral-movement jsou citlivé na preprocessing, sestavení proudu a prevalenci; AP na LANL a OpTC klesla při jednotném preprocessingu o řády (jediný preprint). | RQ2-027, 050 (jeden preprint jednoho autora), 036 (preprint nezávislého výzkumníka), 022 (obecný přehled, neměří citlivost AP) | **střední** (dříve vysoká) | směr efektu konzistentní a čísla ověřená, ale nejsou dvě nezávislé replikace; 027 a 050 jsou táž práce, 036 pochází od autora, který opravil své dřívější práce; „o řády“ drží jen pro Larroche; patří i do RQ5 | ano | reportovat prevalenci, time-aware split, absolutní počty FP |
| Z10 | Velká část alarmů z objemových řad pochází z legitimního provozu; relevance závisí na metrice a části provozu. | RQ2-003 | nízká | 1 síť, kvalitativní | ano | kontextové metadata a udržovací okna jako vstup; souvisí s RQ1 |
| Z11 | Isotonická kalibrace snižuje Brier proti surovému skóre BOCPD (velikost nespolehlivá). | RQ2-034 | velmi nízká | autor opravil popis kódu a sestavené proudy | s úpravou | pouze jako hypotéza H5, ne důkaz |

## 6. Překlad do praxe (Salticus)

Označení: [D] doloženo uvedenými id, [E] extrapolace (a proč).

1. **Robustní per-entity skóre.** Pro `inductive_volume_anomaly` a `packet_rate_spike` použít residual = pozorování - medián profilu (hodina týdne, per entita) děleno 1,4826 x MAD a práh přes cílový FPR. [E]: robustní z-skóre ani STL na síťových datech jsem neviděl změřené; opírá se o RQ2-021 (boxplot práh; Z1b nízká jistota), RQ2-001 (rezidua po vyhlazení, malý rozdíl HW vs exp. vyhlazování) a RQ2-018 (per-entity; Z4 nízká jistota, post hoc prahy).
2. **Nezavádět CUSUM/HW bez důkazu.** [D] RQ2-001, 002.
3. **Zmrazení baseline při alarmu** a „quarantine“ pro entitu s aktivním nálezem. [D] RQ2-019; [E] přenos na naši architekturu.
4. **Minimální historie.** Pro per-entity baseline požadovat >= 4 týdny nebo fallback na prior archetypu ([D] RQ2-026: 4 týdny historie; [E] peer-group prior, protože měření pro zařízení nenalezeno). HW potřebuje 2 sezóny (RQ2-020, slabý zdroj).
5. **Denní rozpočet alertů** s prahem z percentilu historických alertů za 30 dní ([D] RQ2-023 až 025). Rozpočet řídit plánovačem kontrol (souvislost s 68 % plánů mimo rozpočet v soak v1).
6. **FDR vrstva.** BH (nebo BY při závislosti) nad per-entity konformními p-hodnotami, alfa 0,1-0,2, Storey odhad podílu nulových; hlídat 90. percentil FDR přes seedy ([D] RQ2-028, 029). Pro streamy online variant s decay pamětí ([D] RQ2-032). Pozor: malá kalibrační množina -> nulová síla (RQ2-031).
7. **Kalibrace.** Isotonická regrese na verdiktech plánovače; sledovat ECE po týdnech; rekalibrovat po ~100 verdiktech z nové distribuce ([D] RQ2-043; [E] pro naše case memory).
8. **Drift.** Měřit FPR a TPR na držených rodinách po čase a při změně archetypu; plánovat přetrénování měsíční až čtvrtletní kadencí jako výchozí hypotézu ([E]: kadence z RQ2-038 UGR'16 jeden měsíc a RQ2-044 roky; přenos CIC-IDS-2017 -> 2018 se nepoužívá).
9. **Reportování.** Vždy FP absolutně / síť-den, prevalenci, TPR při pevné FPR; nespoléhat na AUC ([D] RQ2-027, 036, 049).

## 7. Hypotézy k ověření v soak harnessu

Kontext (čteno z `docs/diplomka/eval/soak-findings.md` a `F:\Projekty\bakula-soak\run-v2-72h\status.md`, jen čtení): soak v1: 210,7 FP nálezů/síť-den, 75 % `inductive_volume_anomaly`, 22 % `packet_rate_spike`; v2 (zatím): 1 255,9 FP nálezů/síť-den, z nich `unexpected_traffic` 3,22 mil., `inductive_volume_anomaly` 2,26 mil., `packet_rate_spike` 0,64 mil. z 6,54 mil.; benigní lookalike s falešným nálezem: patch_window 99,1 %, collector_replay 97,4 %, sensor_crash 92,6 %, service_crash 91,0 %, batch_job 86,8 %, flash_crowd 80,0 %, backup_burst 75,2 %; kalibrace case memory v v2: predikce 0,531 -> skutečnost 0,439, 0,638 -> 0,516 (nadkonfident), 0,863 -> 0,991 (podkonfident), Brier 0,0290, isotonická kalibrace nezapojena. Co v literatuře odpovídá: velký podíl legitimních alarmů (RQ2-003), degradace kalibrace pod posunem (RQ2-042), nutnost rozpočtu alertů (RQ2-023). Žádný zdroj nepotvrzuje naše absolutní čísla; jednotky (nálezy vs alerty) nejsou srovnatelné.

| H | Změna | Očekávaný efekt (z důkazů) | Metrika | Scénář / seedy | Kritérium zamítnutí |
|---|---|---|---|---|---|
| H1 | per-entity robustní baseline (medián/MAD, profil hodina týdne) místo globálního prahu pro `inductive_volume_anomaly` a `packet_rate_spike` | pokles FP/síť-den; rozsah 3-8x je [odhad autora z RQ2-018 a RQ2-024, extrapolace; Z4 nízká jistota, efekt per-entity nelze oddělit od jiného detektoru] | FP nálezů/síť-den při stejné TPR (19 rodin), TPR s Wilsonovým intervalem | A/B na stejných seedech, držené rodiny, kotva CTU-13/IoT-23 | pokles FP < 2x, nebo pokles TPR kterékoli rodiny > 5 b.p. mimo Wilson interval |
| H2 | denní rozpočet alertů na entitu a síť (práh = percentil historických alertů z 30 dní) | detekce zůstane blízko původní při malém rozpočtu (Hopper: 95 % při 5/den) | alerty/síť-den vs detekce rodin | rozpočty 5, 11, 25/den | detekce libovolné rodiny s pozorovatelnými útoky klesne > 10 b.p. při rozpočtu odpovídajícímu <= 10 alertům/den |
| H3 | BH/BY nad per-entity konformními p-hodnotami (alfa 0,1) pro nálezy bez příčiny | empirický FDR <= alfa + 0,03 u průměru; 90. percentil přes seedy do 1,5 alfa (RQ2-028: 0,194 vs 0,2; 0,23) | podíl nálezů bez příčiny mezi odesílanými (FDR), síla | sítě 200+ zařízení, 3 seedy x kalibrační množina 100/1000 | průměrný FDR > 1,5 alfa, nebo síla na kalibraci < 100 nulová u > 25 % entit (RQ2-031) |
| H4 | zmrazení baseline při aktivním alarmu | zlepšení TPR perzistentních rodin (slow_scan, exfiltration, cryptomining, c2_beacon), jejichž baseline se jinak adaptuje (RQ2-019: 3 z 67 minuto) | TPR rodin, latence | A/B, dlouhé epizody (>= 4 dny) | zlepšení TPR perzistentních rodin < 2 b.p. |
| H5 | zapojení isotonické kalibrace do case memory | ECE klesne v pásmu 0,4-0,7 (nadkonfidence 0,09-0,12) a v pásmu >= 0,8 (podkonfidence); rekalibrace po ~100 verdiktech (RQ2-043) | ECE, Brier, kalibrační křivka | rolling rekalibrace na verdiktech; držené archetypy | ECE nepoklesne o >= 30 % [odhad autora], nebo Brier se zhorší |
| H6 | split-konformní práh vs adaptivní vážený práh na skóre „bez příčiny“ po posunu (nový archetyp, svátky) | split-CP pokrytí klesne pod nominál (RQ2-041: 0,08-0,85); vážený práh FPR bližší nominálu (RQ2-045: 0,123 -> 0,077) | empirická FPR / nominální alfa | trénink na 5 archetypech, test na 5 nových | split-CP FPR <= 1,2 x alfa i po posunu (posun není problém) |
| H7 | sledování driftu (FPR a TPR po týdnech) s přetrénováním při poklesu | ztráta výkonu měsíc až roky (RQ2-038 jen UGR'16, RQ2-044; Z8a); přetrénování část vrací (RQ2-039, jen přenos CIC-IDS-2017 -> 2018, Z8b nízká) | F1/TPR@FPR v čase | simulace s driftem archetypů, kotva IoT-23 | žádný pokles výkonu po 8 virtuálních týdnech |
| H8 (průzkumná) | peer-group prior (archetyp + role) pro zařízení s < 14 dny historie | bez literárního důkazu; očekávám nižší FP v prvních dnech než per-entity bez priorů | FP/TPR v dnech 0-14 po `device_onboarding` | scénáře onboardingu | prior nesníží FP o >= 20 % [odhad autora] |

Neúspěšné hypotézy se zveřejní.

## 8. Hrozby validity

- **Datasety nejsou síťový provoz:** NAB, Yahoo, KPI řady (RQ2-010 až 013, 045), TCPD (RQ2-016, 017), ODDS/UCI (RQ2-028 až 031, 033). Přenositelnost na toky a Zeek logy je extrapolace.
- **Jediný autor, preprint, opravené dílo:** Youssef (RQ2-034 až 037), Li (RQ2-041), Hennhöfer & Preisach (RQ2-031). Youssefovy výsledky jsou nepoužitelné jako důkaz a drží se pouze pro úplnost.
- **Staré a kritizované datasety:** NSL-KDD, KDD99 (RQ2-040, 028 řádek KDDCup99, 042). Autoři to přiznávají.
- **Ground truth:** Münz (žádný), Ringberg (ruční), MAWILab (heuristické), Hopper a Powell (simulované útoky), Lévy-Leduc (neoznačené útoky v trace).
- **Střet zájmů:** autoři NAB jsou tvůrci HTM.
- **Vendor/nerecenzované zdroje v extrakci:** Beach & Modaff (studentská zpráva, RQ2-020) a řada preprintů; recenzované jsou Ringberg, Soule, Lévy-Leduc, Bates, Arp, Schmidl, ADBench, NAB (ICMLA), nonconform (CPAL), Alalawi (IJACSA), TSFM (ICLR).
- **Nezávislá kontrola proběhla (2026-10-31, 37/53 řádků, věcná chybovost 0 %, 6 drobných chyb opraveno)**, zbylých 16 řádků ověřil autor revize u zdroje. Zbývá riziko chyby při čtení tabulek u zdrojů s rozbitým sloupcovým textem; Larroche Tab. 6 a NAB Tab. I byly při revizi znovu přečteny a sedí. Hodnoty u Schmidl a Lévy-Leduc jsou z PDF vldb.org resp. preprintu arXiv, ne z finální časopisecké sazby.
- **Přenos mezi datasety není drift:** CIC-IDS-2017 -> 2018 (RQ2-038, 039, 052) jsou dvě různě sestavené kolekce; interpretovat jako domain shift, ne časový posun téhož provozu.
- **Citační řetězení omezené:** projit zpětně jen několik řetězců (Ringberg -> Brauckhoff, Lévy-Leduc -> Siris & Papagalou, Bates -> nonconform, Hopper -> SAL), dopředné řetězení neprovedeno.
- **Jazykový výběr a publikační zkreslení:** pouze angličtina; negativní výsledky jsou ve vzorku vzácné.
- **Nesrovnatelné jednotky:** FAR/MDR (%), počet alarmů, F1, AP; nebyly sčítány. U RQ2-027 a RQ2-050 nejsou v tabulce uvedeny jednotky AP.

## 9. Co NEBYLO nalezeno

1. Měření robustního z-skóre (MAD) nebo STL na síťových tocích proti prahu.
2. Peer-group baseline pro **zařízení** (jen patent a seskupování uživatelů) a kvantifikace cold-start pro nové zařízení.
3. Síťový benchmark PELT vs BOCPD s ground truth změn.
4. Aplikace BH/BY nebo online FDR v IDS při tisících entit (jediné FDR zdroje jsou tabulkové a časové řady).
5. Porovnání Platt vs isotonic vs temperature scaling na síťových datech; recenzované měření konformní predikce pro anomálie na CIC/Zeek tocích s empirickou FPR.
6. Měření sezónního baseline (den/týden) vs statický práh na toku nebo IDS s FPR (existuje jen vendor dokumentace).
7. Statistický baseline (EWMA/STL) proti modelu na MAWI/CIC.
8. Plné texty: Sommer & Paxson 2010, INSOMNIA AISec 2021, Brauckhoff INFOCOM 2009, Callegari et al., Sun et al. ICML 2024, O-RAN konformní ICML 2026, MAWILab CoNEXT 2010 (viz `neovereno.md`).
9. Negativní výsledky konformních metod v IDS za přirozeného driftu (publikované); nalezen byl jen adverzní posun.
10. Nezávislá replikace měření citlivosti AP na preprocessingu (jen jeden preprint, RQ2-027 a 050).

## 10. Tvrzení výrobců (nepoužito v závěrech)

| Výrobce | Tvrzení | Stav |
|---|---|---|
| Dynatrace (dokumentace „Seasonal baseline“) | model trénuje na posledních 14 dnech per-minutových hodnot, trénink denně, při selhání validace se použije jednoduchý model s pevným pásmem z robustního rozdělení | stránka otevřena, marketingová/produktová dokumentace, bez měření |
| Dynatrace (dle shrnutí vyhledávače) | statický práh vytváří FP na denních špičkách | V1, nečteno |
| Vectra, Praetorian, n-able a podobné | „46 %“ a „50-80 %“ průměrná FP míra bezpečnostních nástrojů | V1, nečteno |
