# Nezávislá kontrola extrakce RQ2 (protokol §9)

Datum kontroly: 2026-10-31. Kontrolor: nezávislý kontrolor, bez znalosti závěrů studie před výběrem vzorku. `extrakce.csv` ani `studie.md` nebyly měněny.

## 1. Vzorek a postup

- Celkem řádků: 53 (RQ2-001 až RQ2-053), prakticky všechny V3 (RQ2-007 až 009 jsou V2 a do vzorku nepatří).
- Vzorek A (povinný): všechny řádky, o které se opírají závěry se jistotou „vysoká“ nebo „střední“ v tabulce Závěry (Z1, Z4, Z5, Z6, Z8, Z9), tedy 29 řádků:
  - Z1: 012, 014, 015, 021, 046, 051
  - Z4: 018, 023, 024, 025, 026
  - Z5: 004, 005, 016, 017
  - Z6: 028, 029, 030, 031, 032, 033
  - Z8: 038, 039, 040, 044
  - Z9: 022, 027, 036, 050
- Vzorek B (doplňkový, ruční výběr z ostatních řádků, bez seedu): 001, 002, 003, 013, 019, 041, 042, 052. Výběr nebyl náhodný, ale zvolen napříč zdroji, které ve vzorku A chyběly (Münz, Nguyen, Li, Alalawi, další řádky Wu a NetGuard).
- Celkem ověřeno 37 z 53 řádků (70 %). Požadavek (aspoň 30 % a aspoň 20 řádků) splněn.
- Způsob ověření: zdroj stažen čerstvě přes curl z uvedené URL (arXiv PDF, princeton.edu, ceur-ws.org, thesai.org, tum.de), převeden `pdftotext -layout`, hodnoty a citace dohledány v textu. U tabulky v RQ2-044 (MAWIFlow) byl text z PDF rozházený, proto jsem stránku vykreslil jako obrázek a tabulku přečetl vizuálně. Použité PDF jsem nečerpal z `<pracovní adresář>/rq*pdf\`.
- Obchází se: DOI `10.14778/3538598.3538602` (Schmidl) přes curl nevrátil PDF, ověřeno na PDF z vldb.org (`pvldb/vol15/p1779-wenig.pdf`). DOI `10.1214/08-AOAS232` (Lévy-Leduc) je za ochranou Project Euclid (Incapsula), ověřeno na arXiv verzi 0908.2310 (stejná práce; „Table 1“ a strana 14 odpovídají citaci v řádku). Hodnoty u těchto dvou řádků jsou z preprintové verze, ne z finálního časopisu.

## 2. Tabulka kontrolovaných řádků

| id | výsledek | poznámka (opravená hodnota, umístění) |
|---|---|---|
| RQ2-001 | OK | Münz, Sekce 4, za Obr. 4: „We obtained 11, 15, and 11 alarms for Shewhart, CUSUM, and EWMA, respectively.“ Hodnoty a citace doslovně shodné. (V řádku je „za Obr. 3“, v textu je to Obr. 4; zanedbatelné.) |
| RQ2-002 | OK | Citace „additional complexity of Holt-Winters forecasting does not seem to ensure better results than simple exponential smoothing“ nalezena doslovně. |
| RQ2-003 | OK | „many anomalies are provoked by legitimate traffic“ v Závěru; text na jiném místě navíc říká, že většina alarmů pochází z legitimního provozu. |
| RQ2-004 | OK | Ringberg, abstrakt: „the false-positive rate can vary by a factor of three or more within a small range of topk values“. SIGMETRICS 2007, Abilene + Géant, 1 týden. |
| RQ2-005 | OK | „lead to a false positive rate that is three times as high as ideal“, týká se heuristiky 3σ na Géant ingress routerech (Obr. 5a, 4a). |
| RQ2-012 | OK | Wu a Keogh, Sekce 2.2: „316 out of 367 (86.1%) can be easily solved with a one-liner“ (Yahoo). Brute-force výběr k, c, b na každou řadu potvrzen. |
| RQ2-013 | OK | Abstrakt: „suffer from one or more of four flaws“. |
| RQ2-014 | OK | Schmidl, Sekce 4.2.1 (RI 5): „every anomaly detection family can be effective and there is no clear winner“, „no single algorithm achieved perfect scores“. 976 datasetů, 71 algoritmů, tabulka 61 algoritmů. |
| RQ2-015 | OK | Sekce 5: „deep learning approaches are not (yet) competitive despite their higher processing effort“. |
| RQ2-016 | OK | van den Burg, Tab. Default, univariate F1: PELT 0,674, BOCPD 0,662, Binseg 0,698, zero 0,645. Sedí. Text: „the zero method outperforms many of the other methods“. |
| RQ2-017 | OK | Univariate F1 Default → Oracle: PELT 0,674 → 0,864, BOCPD 0,662 → 0,886. Sedí. Citát o „large number of false positives“ je z textu pod tabulkou („suggests that many methods return …“), ne z tabulky. |
| RQ2-018 | DROBNÁ | Čísla sedí (TopRank 3/1/9/0, CUSUM 69/65/62/22; Tab. 1, s. 14). Chybí podmínka: prahy v obou metodách jsou u každého útoku nastaveny na nejmenší hodnotu, která útok ještě detekuje (p-hodnota resp. h), tedy post hoc a zvlášť pro každý útok. „False alarm“ je definováno jen vůči 4 vloženým útokům a autoři přiznávají, že stopa může obsahovat další. Doplnit do `podminky`. |
| RQ2-019 | OK | Nguyen, Tab. II: 28/26, 11/10, 13/13, 15/15, tedy 64 z 67. Citace o adaptaci Holt-Wintersu doslovně. |
| RQ2-021 | OK | Arp, Tab. 5, Sekce 4.4: Kitsune AUC 0,968, TPR 0,882 (FPR 0,001); boxplot AUC 0,998, TPR 0,996. Autoři výslovně uvádějí, že pokus nedokazuje detekci Mirai v reálu. |
| RQ2-022 | OK | Sekce 3: sampling bias (P1) 90 %, data snooping (P3) 73 %, „Each paper suffers from at least three of the pitfalls“. |
| RQ2-023 | OK | Hopper: 94,5 % (309/327), „< 9 alerts per day“; denní rozpočet 5 alertů, práh z historických alertů za měsíc. |
| RQ2-024 | OK | Tabulka v Sekci 7.3: SAL equal FP 156/327 (47,7 %), 3 556 FP; SAL equal TP 309/327, 27 927 FP (0,94 %); Hopper 3 560 FP (0,12 %). |
| RQ2-025 | OK | Budget Sensitivity: rozpočet 5 → 171 z 180 (95 %); rozpočet 11 → všech 180, FPR 0,00076. |
| RQ2-026 | OK | Powell, Závěr: FPR 1,6 % a 2,2 %, TPR 98 % a 96 %. FPR je vztaženo k novým systémům daného dne, ne ke všem. 78 účtů, 4 týdny sedí. |
| RQ2-027 | OK | Larroche, Tab. 5: Euler AP 0,02 vs 5,23; Argus 0,09 vs 32,27; Pikachu AUC 78,28 vs 94. Citace „all detectors perform worse in our evaluation setting“ doslovně. |
| RQ2-028 | OK | Bates, Tab. 2, KDDCup99: FDR marg. 0,194 / podm. 0,131; 90. percentil 0,23 / 0,168; síla 0,754 / 0,684. Sedí. „Both calibration methods control the marginal FDR“ je v textu pod tabulkou. |
| RQ2-029 | OK | Digits síla 0,417 → 0,096; Mammography 0,176 → 0,059 (marginální → podmíněná). |
| RQ2-030 | OK | Abstrakt: „positively dependent and enable exact false discovery rate control“. |
| RQ2-031 | DROBNÁ | Hennhöfer, Tab. 1, WBC: nulové objevy (FDR 0,000, síla 0,000) jen u deterministického EDF a deterministické vážené EDF; randomizovaná vážená EDF má sílu 0,100 ± 0,244, KDE 0,417 / 0,078 sedí. V řádku zpřesnit „deterministická“. Citace „baselines yield zero discoveries“ je z abstraktu, ne z Tab. 1 (v řádku „Tab. 1, Sekce 8“). |
| RQ2-032 | OK | Rebjock, popisek Obr. 1: „The power decreases to zero when the proportion of alternative hypotheses π1 is low for all FDR controllers“ (syntetická N(0,1)/N(3,1)). SMD 4,16 % anomálních. Pozor: Obr. 1 je syntetický a týká se online FDR (LORD/SAFFRON), ne BH nad konformními p-hodnotami. |
| RQ2-033 | OK | Nonconform, Sekce 4: FDR 0,18, síla 0,99, IForest, Split(1000), alpha 0,2, seed 42. PMLR 329 (COPA 2026). |
| RQ2-036 | OK | Youssef v3, abstrakt: 32,5 % sdílených záznamů, prevalence 68,235 % vs 25,2396 %, obrácení pořadí skórerů. |
| RQ2-038 | DROBNÁ | Hodnoty sedí (F1 0,99 → 0,61; UGR'16 červenec → srpen 0,96 → 0,687, úvod). Dataset v řádku „CIC-IDS 2018“ je nepřesný: podle Tab. 3 jde o trénink CIC-IDS-2017, test CIC-IDS-2018, tedy dvě různě sestavené kolekce, ne přirozené „rok N → rok N+1“ jednoho provozu. Má dopad na interpretaci Z8 (viz sekce 5). |
| RQ2-039 | DROBNÁ | Abstrakt: F1 0,60 → 0,86 sedí (Tab. 3: 60,62 → 86,00 při 1 % štítků). Dataset má být „trénink CIC-IDS-2017, test CIC-IDS-2018“, ne „CIC-IDS 2018“. |
| RQ2-040 | OK | Drago, Tab. 2: AXGBOOST 100 % štítků F1 0,978; s UME_CDD 5,4 % F1 0,928; ARF 0,989 vs 0,965. NSL-KDD. |
| RQ2-041 | OK | Li, Tab. 1: standardní CP HIKARI 0,849 / 0,837, RT-IoT 0,09 / 0,08, CIC-IDS-2018 0,39 / 0,36; ta-CP 0,947 až 0,967. Citace „Standard CP loses coverage on all three benchmarks“ doslovně. |
| RQ2-042 | OK | Alalawi, abstrakt: „from at most 0.007 in distribution to between 0.170 and 0.209“. |
| RQ2-044 | OK | MAWIFlow, Obr. 3d (čteno z vykreslené stránky): RF trénink 2011 → AUC 0,61, in-domain 2021 → 0,90; CNN-BiLSTM 0,79 vs 0,89. Doslovně „RF drops from 0.90 AUC by 0.29 to 0.61 when trained on 2011“. Poznámka: v řádku „baseline: trénink 2021“ znamená in-domain trénink na 2021 (test vždy 2021). |
| RQ2-046 | DROBNÁ | Citace „none of the benchmarked unsupervised algorithms is statistically better than others“ je z úvodu (Key takeaways) a z Sekce 4 u Obr. 4a, ne z abstraktu. Pole „metoda 30 AD algoritmů“ je zavádějící: tvrzení platí jen pro 14 nesupervizovaných. Zmínka o KDDCup99 mezi 57 datasety jsem v hlavním textu nepotvrdil (seznam datasetů není v extrahovaném textu). |
| RQ2-050 | DROBNÁ | Hodnoty sedí (Tab. 6, AP all: Argus 3,36 vs 80,74; Euler 0,51 vs 8,8). Uvedená „citace“ „Argus [30] 43.23“ je ale hodnota AUC (LM only), nikoli doložená AP. Nahradit řádkem „Argus [30] 43.23±3.05 79.75±2.19 99.7 0.01±0.00 3.36±1.10 80.74“. OpTC 9 dní potvrzeno. |
| RQ2-051 | OK | Schmidl, Sekce 4.2.2: DWT-MLEAD 0,83, RobustPCA 0,54, oba s reliability 100 %. |
| RQ2-052 | OK | Abstrakt NetGuard: 0,001 / 0,04 / 0,00 → 0,30 / 0,50 / 0,71. V Tab. 4 je Web Attack před adaptací 0,0 (rozpor uvnitř zdroje, ne chyba extrakce). |
| RQ2-002/003 | OK | viz výše. |

Nezpracované řádky (nekontrolováno): 006, 007, 008, 009, 010, 011, 020, 034, 035, 037, 043, 045, 047, 048, 049, 053 (16 řádků).

## 3. Chybovost

- Ověřeno: 37 řádků, NEOVĚŘITELNÝCH: 0 (0 %).
- OK: 31. DROBNÁ CHYBA: 6 (018, 031, 038, 039, 046, 050). VĚCNÁ CHYBA: 0.
- Věcná chybovost: 0 / 37 = 0 % (limit 5 %). Podíl NEOVĚŘITELNÝCH: 0 %.
- U žádného řádku se závěrem s jistotou „vysoká“ (Z9: 022, 027, 036, 050) není věcná chyba.
- Nenalezena žádná vymyšlená citace ani vymyšlená hodnota. Všechny zdroje existují, URL fungují (arXiv, princeton.edu, ceur-ws.org, thesai.org, tum.de). DOI Schmidl a Lévy-Leduc se v mém prostředí neotevřely jako PDF (viz sekce 1), ale práce existují a hodnoty odpovídají.

## 4. Nutné opravy v extrakci/studii

1. RQ2-038, RQ2-039 (pole `dataset`, `podminky`): doplnit „trénink CIC-IDS-2017, test CIC-IDS-2018 (dvě kolekce)“. V 039 je hodnota 0,60 → 0,86 platná právě pro tuto dvojici.
2. RQ2-018 (pole `podminky`): doplnit, že prahy (p-hodnota u TopRank, h u CUSUM) jsou u každého útoku nastaveny post hoc na nejmenší detekující hodnotu a „false alarm“ je počítán jen vůči 4 vloženým útokům.
3. RQ2-031 (pole `hodnota`): „nulové objevy jen u deterministických EDF a vážených EDF; randomizovaná vážená EDF síla 0,100“. Citaci „baselines yield zero discoveries“ přesunout na „Abstrakt“.
4. RQ2-046 (pole `umisteni_a_citace`, `metoda`): umístění „Úvod (Key takeaways) a Sekce 4, Obr. 4a“, ne abstrakt; „14 nesupervizovaných z 30 algoritmů“; tvrzení o KDDCup99 buď ověřit v příloze, nebo smazat.
5. RQ2-050 (pole `umisteni_a_citace`): citovat řádek s AP (viz tabulka) místo AUC hodnoty 43.23.
6. RQ2-001 (drobnost): Obr. 4 místo Obr. 3.
7. V RQ2-014 a RQ2-018 doplnit do `url_nebo_doi` také funkční odkaz na plný text (vldb.org PDF resp. arXiv 0908.2310), protože DOI nevede přímo na PDF.

## 5. Přesazené závěry (jistota vyšší než důkaz)

Zkontrolováno všech 6 závěrů se střední/vysokou jistotou plus Z2 a Z10 (celkem 8; požadováno 5).

| Z | Problém | Navrhovaná úprava |
|---|---|---|
| Z9 (vysoká) | Čtyři řádky: 027 a 050 jsou jeden jediný preprint jednoho autora (ANSSI, nerecenzováno), 036 je preprint nezávislého výzkumníka, jehož dřívější práce (034, 037 ve stejné tabulce) sám opravil kvůli nesouladu s kódem; 022 je obecný přehled (recenzovaný, USENIX Security 2022), nikoli měření citlivosti AP na preprocessing. Formulace „AP může být nafouknuté o řády“ je podložena jen Larroche. Nejsou tu dvě nezávislé replikace. | Snížit na střední (směr efektu je konzistentní a čísla ověřená; „o řády“ drží jen pro LANL a OpTC u Larroche). |
| Z1 (střední) | První část („jednoduchý robustní práh bývá při nízkém FPR srovnatelný nebo lepší než složitý detektor“) stojí na jediném síťovém měření (021, Mirai, lab-only, autoři sami říkají, že nedokazuje detekci v reálu). Řádky 046 a 051 o jednoduchých prazích nic netvrdí (046: žádný nesupervizovaný není statisticky lepší, 051: rozptyl mezi rodinami), 015 a 014 hovoří o „no clear winner“ a o nekompetitivním deep learningu. Druhá část (benchmarky jsou řešitelné jednoduchým pravidlem, 012, 014) je podložena. | Rozdělit: „benchmarky jsou triviální/vadné“ = střední; „jednoduchý práh je srovnatelný“ = nízká. |
| Z4 (střední) | „Per-entity testování a rozpočet alertů snižují FP násobně“: násobné snížení FP je doložené v 024 (Hopper vs SAL, ale jde o jiný detektor, ne o per-entity vs globální) a v 018 (4 útoky, jedna stopa, prahy post hoc). 026 neobsahuje srovnání s globálním prahem, jen absolutní FPR 1,6 až 2,2 %. 023 a 025 měří rozpočet, nikoli per-entity vs globální. Studie sama přiznává, že efekt specifikace nelze oddělit od rozpočtu. | Snížit na nízkou pro „násobně“; vyloučit 026 z důkazů o „snížení“ (zůstává jako absolutní údaj). |
| Z5 (střední) | Citlivost na parametry (004, 005, 016, 017) je doložena, ale dvojice 016/017 je nesíťová, 004/005 jsou o PCA, které je podle studie mimo rozsah. Věta „ladění na štítcích je nutné“ je normativní závěr, který z měření citlivosti neplyne (oracle v 017 je horní mez nedosažitelná bez štítků). | Rozlišit „citlivost doložena“ (střední) a „nutnost ladění na štítcích“ (extrapolace). |
| Z8 (střední) | Řádky 038 a 039 porovnávají dvě různé kolekce (CIC-IDS-2017 vs 2018), nikoli drift téhož provozu, a jde o vlastní motivační měření autorů metody. 040 je NSL-KDD se simulovaným driftem. Jen 044 (MAWI 2011 → 2021) a UGR'16 v 038 ukazují skutečný časový posun. Formulace „během měsíců až let“ je z UGR (1 měsíc) a MAWI (10 let); „měsíce“ je z jednoho měření. | Ponechat střední jen se zpřesněním důkazu, nebo snížit na nízkou pro „během měsíců“. |
| Z6 | OK. Střední pro iid tabulková data a velmi nízká pro síť jsou odpovídající. Poznámka: „vzácné anomálie → síla k nule“ pochází z online FDR (032, syntetika), ne z BH nad konformními p-hodnotami; ve větě by to mělo být odděleno. | Rozdělit větu. |
| Z2 (nízká), Z10 (nízká) | Odpovídají řádkům (001, 002, 053 resp. 003) a nehodnotí víc, než řádky říkají. | Bez změny. |

## 6. Verdikt

**PŘIJATO S OPRAVAMI.**

Věcná chybovost 0 % (≤ 5 %), žádná chyba u závěru s vysokou jistotou, žádná vymyšlená hodnota ani citace. Podmínkou přijetí je provedení opravy v sekci 4 (šest drobností v extrakci) a snížení/zpřesnění jistoty u závěrů Z9, Z1, Z4 a doplnění vymezení u Z5, Z8 (sekce 5). Doporučuji také, aby nezpracovaných 16 řádků (zejména 034, 035, 037, 045, 047, 048) prošlo samostatnou kontrolou, pokud se na ně v dalších verzích opřou závěry.
