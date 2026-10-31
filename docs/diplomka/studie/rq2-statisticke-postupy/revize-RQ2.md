# Revize RQ2 po nezávislé kontrole (audit trail)

Datum revize: 2026-10-31. Vstup: `kontrola-RQ2.md` (verdikt PŘIJATO S OPRAVAMI). Změněné soubory: `extrakce.csv` (12 řádků), `studie.md`, tento soubor. `neovereno.md` beze změny (žádný řádek se nepodařilo neověřit, viz §4). Zdroje jsem znovu stáhl do `F:\claude-tmp\rq2rev\` (curl, `pdftotext -layout`) a hodnoty hledal v textu sám; kontrolora jsem nepřebíral slepě. Ve všech opravovaných bodech se kontrolor nemýlil. Původní verze pro srovnání: `F:\claude-tmp\rq2rev\extrakce.pre-revize.csv`, `studie.pre-revize.md`.

## 1. Opravy v extrakci (původní hodnota zde, ne v hlavním textu)

| Řádek | Co bylo špatně (původně) | Nová hodnota | Jak ověřeno u zdroje |
|---|---|---|---|
| RQ2-001 | umístění „za Obr. 3“ | „za Obr. 4“ | Münz, text: „Figure 4 shows … three control charts“, věta „We obtained 11, 15, and 11 alarms“ následuje po Obr. 4 (Obr. 3 je autokorelace) |
| RQ2-014 (+015, 051 shodně) | `url_nebo_doi` jen DOI, které nevede na PDF | doplněn `https://vldb.org/pvldb/vol15/p1779-wenig.pdf` | PDF stažen z vldb.org; „there is no clear winner“, „not (yet) competitive“, DWT-MLEAD 0,83 a RobustPCA 0,54 nalezeny |
| RQ2-018 | `podminky` bez informace o post hoc prazích; `riziko_zkreseni` „střední“; použitelnost „snižuje FP o řád“; URL jen DOI | podmínky: prahy (p-hodnota u TopRank, h u CUSUM) nastaveny u každého útoku post hoc na nejmenší detekující hodnotu, „false alarm“ jen vůči 4 vloženým útokům; riziko „vysoké“; použitelnost „orientačně“, Z4 nízká; doplněn arXiv 0908.2310 | arXiv 0908.2310, Table 1 popisek: „the smallest ones that ensure the detection of the attack“, „h row gives the smallest threshold values“; Sekce 4.2.1: „it is possible that the underlying ADSL and P2P traffic contains some other attacks“. Čísla 3/1/9/0 a 69/65/62/22 sedí. Poznámka: jednotka falešných alarmů u CUSUM na agregátu není v textu vymezena stejně přímo jako u TopRank, v řádku to uvedeno |
| RQ2-031 | „diskrétní vážená EDF: FDR 0,000, síla 0,000“ bez rozlišení; citace u „Tab. 1, Sekce 8“ | nulové objevy jen u deterministické EDF a deterministické vážené EDF; randomizovaná vážená EDF síla 0,100 ± 0,244 (FDR 0,075 ± 0,245), randomizovaná EDF síla 0,200 ± 0,332; KDE 0,417 sedí; citace „baselines yield zero discoveries“ uvedena jako z Abstraktu | arXiv 2603.23205, Tab. 1 (WBC): `EDF 0.000/0.000 | 0.062/0.200`, `Weighted EDF 0.000/0.000 | 0.075/0.100`, `Weighted KDE 0.078/0.417`; citace je v abstraktu a v závěru, ne v tabulce |
| RQ2-038 | dataset „CIC-IDS 2018“, metoda „trénink rok N, test rok N+1“, pouzitelnost „drift během týdnů až měsíců“ | CIC-IDS: trénink CIC-IDS-2017, test CIC-IDS-2018 (dvě různě sestavené kolekce); UGR'16 červenec -> srpen je skutečný časový posun (1 měsíc); pouzitelnost: jen UGR'16 je časový posun; riziko „střední až vysoké“ | arXiv 2503.03022: Tab. 3 „Train: 2017 Test: 2018“, MLP None 0 %: F1 60,62 (odpovídá 0,61); poznámka pod čarou: CIC 2017 a 2018 se liší sítí a útoky. **Dodatečně zjištěno:** hodnota 0,99 (a 0,96 u UGR'16) je jen v úvodu, v žádné tabulce jsem ji nenašel; „dataset [51]“ je citace článku Sharafaldin et al., úvod nejmenuje dvojici datasetů, shodu s 2017 -> 2018 odvozuji z hodnoty 60,62 (inference). Tab. 5 (UGR'16, bez adaptace): MLP 68,77, XGBoost 74,33, úvod uvádí 0,687 |
| RQ2-039 | dataset „CIC-IDS 2018“ | trénink CIC-IDS-2017, test CIC-IDS-2018; hodnota doplněna o Tab. 3 (60,62 -> 86,00, 1 % štítků); použitelnost snížena | Abstrakt „0.60 … to 0.86“, Tab. 3 `NetGuard 1% 86.00` |
| RQ2-052 | dataset „CIC-IDS 2018“ | doplněno „trénink 2017, test 2018“ (nad rámec kontroly, stejný zdroj) | Tab. 4 „Class-wise E2E results (Train:2017 -> Test:2018)“; rozpor Web Attack 0,0 vs abstrakt 0,04 ponechán v poznámce |
| RQ2-046 | umístění „Abstrakt“; metoda „30 AD algoritmů“; v datasetu zmínka o KDDCup99 | umístění Úvod (Key takeaways) + Sekce 4.2, Obr. 4a; 14 nesupervizovaných z 30; zmínka o KDDCup99 odstraněna | ADBench: řádek 45 „including 14 unsupervised“, řádek 50 „Key takeaways … none of the benchmarked unsupervised algorithms is statistically better“; KDDCup99 jsem v textu ADBench nenašel (grep „kdd“ dává jen citace jiných prací), proto smazáno |
| RQ2-050 | citace „Argus [30] 43.23“ (je to AUC LM only) | celý řádek Tab. 6 `Argus [30] 43.23±3.05 79.75±2.19 99.7 0.01±0.00 3.36±1.10 80.74`, vysvětleny sloupce | Larroche Tab. 6: záhlaví AUC (LM only), AUC (all), AUC (rep.), AP (LM only), AP (all), AP (rep.); Argus AP all 3,36, AP rep. 80,74; Euler AP all 0,51, AP rep. 8,8 |
| RQ2-047 | metoda: „prahy z 5. a 95. percentilu ztráty na 1 % předtrénování“; umístění „Tab. 1 a Tab. 4“ | předtrénování 5 % normálních dat (610 vzorků) u CIC-Darknet2020, 1 % u NSL-KDD a Edge-IIoTset; citace je z Sekce 4.1.4 (Implementation Details) | **Chyba nalezena při vlastním ověření, kontrola ji nezachytila (řádek byl mezi nekontrolovanými).** arXiv 2410.22967: „we allocate 5% of normal data (610 samples) for CIC-Darknet2020, 1% (673 samples) for NSL-KDD, and 1% (32,310 samples) for Edge-IIoTset“. FAR/MDR hodnoty sedí |

## 2. Samostatné ověření 16 dosud nekontrolovaných řádků

| Řádek | Výsledek | Kde a co |
|---|---|---|
| 006 | OK | Soule, Sekce 5: „For a false positive rate of 7%, it misses no anomalies (100% true positives), while the next best method catches about 85%“; 27 anomálií Abilene |
| 007, 008, 009 | OK (V2) | Brauckhoff, abstrakt: „improvement in accuracy of up to 20 percent“, „from typically one hour to a few minutes“, „false alarm problem is broadly ignored by the scientific community“. Jen abstrakt, tělo nečteno; řádky nenesou žádný závěr tabulky Z |
| 010, 011 | OK | NAB Tab. I: Standard 64,7 / 47,1 / 35,7 / 16,8 / 0,0; Reward low FP 56,5 / 33,6 / 27,1 / 5,8; 58 souborů, 365 551 instancí; text uvádí pořadí Etsy před Twitter, tabulka opačně (v řádku poznamenáno) |
| 020 | OK | Beach & Modaff, Sekce 2: „a higher amount of false positives … due to the lack of time duration“; „data within the first two seasons will not be able to take advantage“ |
| 034, 035 | OK | CALIBURN v1: Brier -30 % / -32 % / -63 % (LITNET/CICIDS2017/UNSW), UNSW-NB15 prevalence 64 %, „2B/(n0+1)“, doporučení prevalence pod cca 25 % (řádky 164, 1765). Sníženou spolehlivost zdroje nic nemění |
| 037 | OK | arXiv 2510.09619 v2, Correction note: skóre a práh neodpovídají kódu, „evaluation streams are assembled constructions“; „This manuscript reports no quantitative result tables“ |
| 043 | OK | Alalawi, abstrakt: „Most of the aggregate top-label ECE reduction is obtained with about one hundred labeled target samples“; „Recalibrating on training-distribution data does not reliably transfer“. Rekalibrace potřebuje štítky z cílové distribuce (autoři sami) |
| 045 | OK | Martinez Gil et al., Tab. 1 Chronos: FPR Gaussian 0,123 / Conformal 0,111 / W1-ACAS 0,077; CalErr 0,075 / 0,038 / 0,025; SD u W1-ACAS FPR 0,114; oracle práh potvrzen |
| 047, 048 | 047 opraveno (viz §1); 048 OK | 048: Edge-IIoTset Tab. 3: AdaptiveNAD FAR 0,08 / MDR 18,52, SOM 8,57 / 12,98, HST FAR 41,48; Tab. 1 HST 2,72 / 35,24, OCSVM 0,29 / 96,95; 10 běhů |
| 049 | OK | Erbacher (arXiv 2203.08801, U.S. Army Research Laboratory), abstrakt: „the paper argues for deeper analysis of false positives, akin to the analysis that true positives are treated“; jde o koncept bez dat, E5 |
| 053 | OK | Soule, Sekce 5, Obr. 5(a): „the GLR method detected 90% of the anomalies with no lag, while the basic method detected 95%“; wavelet „over half an hour“ u některých anomálií |

## 3. Závěry: změny jistoty a úpravy navazujících částí

| Z-id | Stará | Nová | Důvod |
|---|---|---|---|
| Z9 | vysoká | střední | 027 a 050 jsou jeden preprint jednoho autora; 036 preprint autora, který sám opravil související práce; 022 je obecný přehled, neměří citlivost AP. Nejsou dvě nezávislé replikace. Formulace „o řády“ omezena na LANL a OpTC u Larroche |
| Z1 | střední | rozděleno: Z1a (benchmarky řešitelné jednoduchým pravidlem, žádný jasný vítěz) střední; Z1b (jednoduchý práh srovnatelný/lepší při nízkém FPR) nízká | druhou část nese jediné síťové měření (021, Mirai, laboratoř; autoři: nedokazuje reálnou detekci); 046 a 051 o prazích nic netvrdí, přesunuty pod Z1a jako kontext „žádný jasný vítěz“ |
| Z4 | střední | nízká | násobné snížení FP stojí na 018 (4 útoky, post hoc prahy, jiný detektor) a 024 (jiný detektor, ne per-entity vs globální); 023, 025 měří rozpočet bez srovnání; 026 odebráno z důkazů o snížení (zůstává jako absolutní údaj) |
| Z5 | střední | rozděleno: Z5a (citlivost na parametry) střední; Z5b („ladění na štítcích je nutné“) nepodloženo měřením, extrapolace | oracle v 017 je horní mez nedosažitelná bez štítků |
| Z6 | střední (iid), velmi nízká (síť) | Z6a beze změny; nový Z6b (malá kalibrace -> nulové objevy u deterministických odhadů, 031; síla k nule u online FDR na syntetice, 032) nízká | kontrolor: věta míchala BH nad konformními p-hodnotami s online FDR (LORD/SAFFRON) na syntetických datech. Úroveň Z6b „nízká“ jsem určil já (preprinty, malé tabulkové datasety, syntetika) |
| Z8 | střední | rozděleno: Z8a (pokles při časovém posunu) střední pro směr, nízká pro časovou škálu „měsíce“; Z8b (adaptace s malým rozpočtem štítků) nízká | 038 a 039 jsou přenos CIC-IDS-2017 -> 2018, ne drift; jen UGR'16 (1 měsíc) a MAWI (10 let) jsou časový posun, každé jedno měření; 039 je vlastní měření autorů metody; 040 je NSL-KDD se simulací |
| Z2, Z3, Z7, Z10, Z11 | nízká / velmi nízká | beze změny | řádky 001, 002, 053, 003, 019, 041–043, 045, 034 jsem ověřil nebo je ověřil kontrolor; nehodnotí víc, než řádky říkají |

Navazující úpravy `studie.md`: §1 abstrakt (body 2, 3, 6, 7), §2 PRISMA + metodika (řádky nezávislé kontroly a revize, poznámky ke zdrojům), §3a (046 14 nesupervizovaných), §3b (018 post hoc), §3d (031), §3f (038, 039 a časová škála), §4 (tři řádky rozsahů přepsány: snížení FP, pokles při časovém posunu bez CIC 2017 -> 2018), §5 (Z-tabulka), §6 (položky 1 a 8), §7 (H1, H7), §8 (nezávislá kontrola, přenos mezi datasety), §9 (nová položka 10). Kvantitativní rozsahy neměnily hodnoty, jen se odstranil řádek CIC 0,99 -> 0,61 z „driftu“ a upřesnil se počet studií u snížení FP (2 přímá srovnání místo 3).

## 4. Co zůstává nevyřešené nebo neověřeno

1. Řádky ze vzorku kontrolora, které jsem při revizi znovu neotevíral (např. 044, MAWIFlow Obr. 3d, čteno kontrolorem z vykreslené stránky), přebírám z kontroly. Jedno čtení tabulky z obrázku nemám nezávisle potvrzené.
2. RQ2-038: hodnoty 0,99 (CIC) a 0,96 (UGR'16) jsou jen v textu úvodu, ne v tabulce; identifikace dvojice 2017 -> 2018 je inference z hodnoty 60,62; 0,687 v úvodu vs 68,77 v Tab. 5.
3. Lévy-Leduc & Roueff: hodnoty z preprintu arXiv 0908.2310, ne z finální sazby Annals of Applied Statistics (Project Euclid za ochranou). Schmidl: PDF z vldb.org, DOI neotevřeno. Soule: uvedená URL USENIX dnes vrací HTML, ne PDF; hodnoty jsem ověřil na dříve staženém PDF téže práce (`F:\claude-tmp\rq2\pdf\soule2.pdf`).
4. 018: jednotka „falešný alarm“ u CUSUM na agregátu není vymezena tak přímo jako u TopRank; srovnání zůstává nečisté.
5. Žádný řádek se nepřesouval do `neovereno.md`: u všech 53 řádků byla hodnota nalezena ve zdroji. Řádky 007–009 zůstávají V2 (abstrakt); netvoří opěru žádného Z.
6. Z5b a Z1b jsou ponechány v tabulce jako označené nepodložené / nízké, ne smazány.
7. Hypotézy H1 a H7 jsou upraveny jen poznámkou o nižší jistotě; jejich očekávané efekty (3–8x, pokles po týdnech) jsou stále odhad autora, ne doložená hodnota.
8. Jazyková korektura a anonymizace nebyly součástí revize.

## 5. Souhrn

Provedeno 15 oprav: 7 bodů z §4 kontroly (řádky extrakce 001, 014, 018, 031, 038, 039, 046, 050), 6 změn závěrů (Z1, Z4, Z5, Z6, Z8, Z9) a 2 vlastní nálezy (047 pětiprocentní předtrénování, 052 dataset); k tomu 2 kosmetické URL úpravy (015, 051 shodně s 014). Verdikt kontroly, věcná chybovost 0 %, zůstává; po revizi je podmínka přijetí splněna.
