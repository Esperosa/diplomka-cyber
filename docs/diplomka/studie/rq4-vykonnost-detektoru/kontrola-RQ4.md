# Nezávislá kontrola extrakce RQ4 (protokol §9)

Datum: 2026-10-31. Kontrolor: druhý kontrolor, bez znalosti závěrů před načtením `extrakce.csv`. `extrakce.csv` ani `studie.md` jsem neměnil.

## 1. Vzorek a postup

- Řádků V3/V2 celkem: 56 (55 × V3, 1 × V2). Požadovaný minimální vzorek: 30 % (17 řádků), nejméně 20.
- Závěry Z1-Z15 s jistotou „vysoká“ nebo „střední“ se opírají o 46 ze 56 řádků (Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, Z12, Z14, Z15). Zbylých 10 řádků (001-003 u Z1/Z2 s jistotou nízká, 005, 007, 014, 015, 021, 022, 031, 032, 041, 042, 051, 056 podle mapování) jsem prošel také. Vzorek je proto **všech 56 řádků (100 %)**, bez losování.
- Zdroje jsem stáhl znovu a čerstvě (curl + pdftotext do nového adresáře `<pracovní adresář>/kontrola4\`, kam jsem nic z dřívějších RQ adresářů nekopíroval): 22 PDF z arXiv (stažení z `https://arxiv.org/pdf/<id>`), PDF Barradas (uwaterloo.ca), Bowman (gwu.edu), Clausen (github.io), Javed (icir.org), Jung (mit.edu), King/Euler (ndss-symposium.org), Hynek (Springer, open access PDF). Hodnoty jsem hledal v textu PDF; u rozbitých tabulek (Anderson Tab. V, Drichel/Anderson Tab. 3, Trizna Tab. II) jsem použil `pdftotext -raw`. Přímé načtení stránky jsem nepoužil, protože curl dá stejný obsah a umožňuje plný text.
- Plný text se nepodařilo získat u: Lee a Lee (Springer, Unpaywall `oa_status: closed`; stránka dává jen abstrakt), Maiolini 2009 (Springer, jen abstrakt), Hu et al. Baywatch (pure.psu.edu, jen abstrakt; `doi.org/10.1109/DSN.2016.50` vrací prázdnou odpověď HTTP 202).

## 2. Kontrolované řádky

Legenda: OK / DROBNÁ / VĚCNÁ / NEOVĚŘITELNÉ.

| id | výsledek | poznámka (opravená hodnota, umístění) |
|---|---|---|
| RQ4-001 | OK | AUC 0,97 / 0,85 / 0,85 / 0,64 ověřeno; poměr 5 %, 10 000 / 6 000 zařízení ověřeno. Správné umístění je §4.4 (ne §4.2), s. 10. |
| RQ4-002 | OK | TPR 77 %, ostatní bez detekce, min. FPR Baywatch 14,4 %, WARP 3 % ověřeno (§4.4 s. 10-11). |
| RQ4-003 | DROBNÁ | 77 zařízení / 62 %; 365 CP / 19 %; 42 CP ověřeno. U WARP je text sám nekonzistentní: „lowest false positive rate (0 %)“ i „only 2 % false positives“. Řádek uvádí jen 0 %; doplnit „0 % resp. 2 % (rozpor v textu)“. |
| RQ4-004 | OK | „mean F1 scores between 0.78 and 1 … 95 %“ je v §1 (s. 2) a v abstraktu; „ten times less training flows“ ověřeno (§6.2). |
| RQ4-005 | DROBNÁ | jQuery F1 0,99 a „downgraded performances“ ověřeno (§6.4). Nepřesnost: čtyři trasy MTA jsou HTTPS a jQuery HTTP je pátá; výkon je podle autorů většinou srovnatelný s Ramos et al. („equals or outdo“). Poznámka „selhání při neznámém profilu“ je silnější než zdroj (viz Z3). |
| RQ4-006 | OK | 99 % přesnost, 111k vyvážených vzorků, prvních 20 TLS záznamů ověřeno. |
| RQ4-007 | OK | Framework-side 90 %, payload-side 50 %, až 3× více TLS bajtů ověřeno (abstrakt). |
| RQ4-008 | OK | C-Cert 99,48 / 99,91, TPR 100; C-Behav 99,42 / 99,78, TPR 93,87 ověřeno (úvod, Tab. 4). |
| RQ4-009 | DROBNÁ | 99,13 % / 96,35 % benigní ověřeno (úvod s. 2). Chybný odhad autora studie: 99,13 % a 96,35 % se vztahuje na **TLS 1.3 toky** (z ~10 M toků „more than half“ jsou TLS 1.3), takže 0,87 % = přibližně 45-50 tis. toků, ne ~87 tis.; 3,65 % = ~180-190 tis., ne ~365 tis. Závěr o „0,87-3,65 % toků“ v Z4 je třeba doplnit slovy „TLS 1.3 toků“. Závěr článku navíc uvádí 99,15 % (rozpor ve zdroji). |
| RQ4-010 | OK | 0,878 / 0,859 / 0,711 / SD 0,131 / foldy 0,946-0,893 ověřeno (§V-A, Tab. I). |
| RQ4-011 | OK | +0,28 F1 (View B, TLS pohled) a 0,022 ověřeno. |
| RQ4-012 | OK | 13,2 % / 0 % při FPR 1 % ověřeno; umístění je §V-F „Operational Threshold Behavior“, ne „Diskuse“. |
| RQ4-013 | OK | 20 z 62 captur (32 %), „every model performs worse“ než F1 0,711 ověřeno. |
| RQ4-014 | OK | RITA 0,0 u všech 11 profilů, <12 spojení za 60 s u P2/P3 ověřeno. |
| RQ4-015 | OK | Pouze abstrakt na pure.psu.edu: 8 kroků, >30 mld. událostí, 5 měsíců, >130 000 zařízení. Řádek správně uvádí V2. |
| RQ4-016 | OK | 99,6 % a 92,6 % u 0,01 % FDR (Meta+SPLT+BD+TLS+SS) potvrzeno přes `-raw`; „No SChannel“ 87,4 % (rozdíl ~5 %). Rozbitý layout nebyl problém. |
| RQ4-017 | DROBNÁ | 1 352 / 1 500 005 (0,09 %) a 947 / 133 744 ověřeno. Zdroj uvádí 0,7 % výslovně, není to „dopočet autora studie“ (0,71 %). |
| RQ4-018 | DROBNÁ | F1 >0,99 platí pro **rodinu procesů** (0,9941, ±0,0004), pro proces 0,9650 (±0,0013); baseline 0,8953 je Top Process pro rodinu (pro proces 0,8860). Abstrakt zdroje říká „process identification“, ale řádek směšuje hodnoty ze dvou sloupců Tab. 3. Doplnit „rodina / proces“. |
| RQ4-019 | OK | precision 99,9 %, recall 88,7 % ověřeno (abstrakt). |
| RQ4-020 | OK | precision >99 %, CDN 85 až >99 %, SSLBL a Feodo ověřeno. |
| RQ4-021 | OK | PR-AUC 0,542, ROC-AUC 0,968, T=0,217, P 0,498, R 0,601 (laděno na testu) ověřeno. |
| RQ4-022 | OK | F1 0,54 / 0,28 (Netflow v5), 0,74 / 0,37 (v9) ověřeno, §4.4. Formulace „v9 horší než burst/velikosti“ je volná, ale ne chybná. |
| RQ4-023 | OK | α=2·10^-5, Ts=0,653, Akamai ≥100 tis. uživatelů, 35 mil. dotazů/h ověřeno. |
| RQ4-024 | OK | 12/18 bezpečnostní služby, ≤1 nová FP doména/den po dvou dnech ověřeno (§V-D, Tab. VI). Pozor na význam, viz Z7 níže. |
| RQ4-025 | DROBNÁ | TPR 0,9237, FPR 0,0052, precision 0,9939; Normal FPR 0,0762 ověřeno (Tab. 5). Chybí důležitý kontext z Tab. 3: z 8 000 tunelových domén je pouze 23 dnscat2, 78 DNSExfiltrator, 346 iodine a 7 553 „Not specified“ (v tom i neúspěšné pokusy). „dnscat2 100 %“ platí pro 23 domén. |
| RQ4-026 | OK | TPR 96,6 / 96,5 / 100 %, FPR 5,8 % (2 966 / 51 459 spojení) ověřeno (Tab. 3-4); práh pro FPR ~0,5 % zmíněn. |
| RQ4-027 | OK | B-ResNet TPR 0,99978, FPR 0,00147; FANCI 0,99744 / 0,00216 ověřeno (Tab. 2). |
| RQ4-028 | OK | 49 435 FP, FPR 0,00182, ~69 FP/h ověřeno (§7; ne §6.4). Jmenovatel je 27 mil. unikátních NXD. |
| RQ4-029 | OK | „FNR increases by more than a factor of 10“ ověřeno (§6.3.2). Důvod (4 DGA rodiny nebyly v tréninku) řádek správně uvádí. Viz přesazení Z8. |
| RQ4-030 | OK | ~89 % při FPR 0,008; 67-78 % při FPR 0,001-0,002; 0,00362-0,35998 % ověřeno (§6). |
| RQ4-031 | DROBNÁ | GB/RF ≈99,99 %; LR 37,0 %; DoHxP 2,1 % detekce a 27,2 % FP ověřeno (Tab. 9-10). „FP ≥ 1 %“ nesedí přesně: GB 1,1 %, RF 0,9 %, LR 0,7 %. Správně „≈1 %“. |
| RQ4-032 | OK | 94,9 % / 1,71 %; UNSW 98,04 / 98,65 / 63,58 / 1,98 % ověřeno. |
| RQ4-033 | NEOVĚŘITELNÉ | Springer: closed access, získal jsem jen abstrakt (Seoul, >10 000 zaměstnanců, náhrada DARPA99, DR 99,9 % v tréninku). Hodnoty 70,52 % / 5,18 % / 23 serverů / 1 153 řádků nelze ověřit. Řádek tvrdí V3 s odkazem na Tab. 9; zdroj plného textu v `hledani.csv` ani `neovereno.md` není zaznamenán. |
| RQ4-034 | NEOVĚŘITELNÉ | Totéž (Tab. 10: recall 100 %, precision 19,7 %, FPR 1,1 %). Opírá se o ni Z15 (vysoká) a §6 bod 1. |
| RQ4-035 | OK | GL-GV 635 TP, 107 960 FP, 85 %, 0,9 %; GL-LV 503 / 146 285 / 67 % / 1,2 % ověřeno (Tab. 3); „over 100,000“ ověřeno. Odvozené: precision 0,58 %, 6 000 FP/den (označeno jako odhad). |
| RQ4-036 | OK | UA 542 / 530 082 / 72 % / 4,4 %; FL 4 % / 1,0 %; LOF 12 % / 9,6 %; IF 9 % / 16,9 % ověřeno. |
| RQ4-037 | OK | UA TPR 100 %, FPR 1,5 %; GL-LV i GL-GV FPR 0 % ověřeno (Tab. 2). |
| RQ4-038 | OK | AUC 0,9912, AP 0,0523, TPR 86,10, FPR 0,5698, P 0,0054; LSTM 89,65 / 0,5723 ověřeno v PDF NDSS (ne v ACM TOPS); „FPRs are still too high“ ověřeno. |
| RQ4-039 | OK | Tab. 5: Argus 98,44±0,78 / 99,83 / 0,09±0,04 / 32,27; Euler 97,97 / 99,12 / 0,02 / 5,23; Pikachu 78,28 / 94 ověřeno. Tab. 4: 369 569 626 událostí, 702 maliciózních, 16 159 uzlů ověřeno. |
| RQ4-040 | OK | Tab. 6 ověřeno (Pikachu 50,74; Euler 52,90; Argus 43,23; „all“ 86,02 / 84,31 / 79,75; původně 99 / 88,8 / 99,7). 1 354 / 244 LM ověřeno. |
| RQ4-041 | OK | Tab. 3 „no duplicates“: UltraLMD++ .9868 / .0088 / .1788; Argus .9821 / .0056 / .1126 ověřeno. |
| RQ4-042 | OK | Tab. 2 OpTC: UltraLMD++ .9909 / .1510 / .0623; Argus .9300 / .0240 / .0273 ověřeno. |
| RQ4-043 | OK | XGBoost 86,51 % / 0,0013 %, FCDN 92,13 % / 0,0029 %; 263 716 042 a 66 530 377 (89 malicious) ověřeno. |
| RQ4-044 | OK | 89 : 66 530 377 ověřeno (1 : 747 500). |
| RQ4-045 | OK | 309 / 327 (94,5 %), 784 459 506 loginů, 15 měsíců, 9 FP/den, 9 z 18 FN kvůli atributům ověřeno. |
| RQ4-046 | OK | 3 560 FP za 396 dní, FPR 0,0012, 2,94 M loginů ověřeno (§7.3). |
| RQ4-047 | OK | >24 000 alertů (>1 600 měsíčně) ověřeno (§1/§4); SAL 82 % při 0,3 % a >500 FP/den je uvedeno v souvisejících pracích jako výsledek SAL na datech jeho autorů (řádek to správně označuje „na jejich datech“). |
| RQ4-048 | DROBNÁ | AUC (Tab. 3), ~80 % TPR při FPR <0,1 %, nafouknutý SSH podíl 0,2 % ověřeno. Pozadí: Tab. 1 dává CAIDA 60 000 + SSH 20 000 + multimédia 20 000 = **100 000** spojení, ne 120 000. |
| RQ4-049 | OK | Tab. 4 (D=1000 ms, FP 0,4 %) přesně ověřeno. |
| RQ4-050 | VĚCNÁ | Hodnota „všechny metody selhávají, jakmile chaff tvoří většinu provozu“ zdroj nepodporuje. Autoři píšou „all methods struggle“ a v abstraktu „no method … reliably“. Tab. 5 (chaff 300 %) dává AUC: PContext 0,639, DeepCorr 0,886, WuNeur 0,615, RWalk 0,641, C-Over 0,589, Ano1 0,782, Ano2 0,738, WM 0,839. Tedy 4 z 8 metod blízko náhodě, ostatní mají AUC 0,74-0,89. Opravit na „4 z 8 metod AUC 0,59-0,64 při chaff 300 %, ostatní 0,74-0,89“. Řádek tuto Tab. 5 nikde neuvádí. |
| RQ4-051 | DROBNÁ | 99,5 % a 99,88 % ověřeno **jen z abstraktu** (Springer, plný text nedostupný). Řádek má V3, ale cituje „Abstrakt“; správně V2. Popis „lab/emulace, k-means na prvních paketech“ z abstraktu plyne jen částečně. |
| RQ4-052 | OK | 99,47 % (AdaBoost), AUC 0,998 ověřeno (§5, otevřený PDF). |
| RQ4-053 | OK | 86 000 toků / 564 klientů, ML 444 vs NEMEA 318, FP 2 vs 3 ověřeno; správně Tab. 7 (ne Tab. 5-6). |
| RQ4-054 | OK | 99 epoch, 9 falešných, 9 306 hostů, ~2 pokusy na stroj/hodinu ověřeno (§5, §6). |
| RQ4-055 | OK | LBL TRW 0,963 / 0,960, Bro 1,000 / 0,150, Snort 0,615 / 0,126; ICSI TRW 1,000 / 0,992, Bro 1,000 / 0,029 ověřeno (Tab. 8). |
| RQ4-056 | OK | GBDT 99,94 %, bez augmentace 7,12 %, vyvážená 7,75 % při FPR 10^-5 ověřeno (Tab. II, přes `-raw`). |

Souhrn: 56 řádků, z nich 54 s ověřitelnou hodnotou.

| Výsledek | Počet |
|---|---:|
| OK | 44 |
| DROBNÁ CHYBA | 9 (003, 005, 009, 017, 018, 025, 031, 048, 051) |
| VĚCNÁ CHYBA | 1 (050) |
| NEOVĚŘITELNÉ | 2 (033, 034) |

## 3. Chybovost

- Věcná chybovost: 1 / 54 = **1,9 %** (limit 5 %).
- Drobné chyby: 9 / 54 = 16,7 %.
- Podíl NEOVĚŘITELNÝCH: 2 / 56 = **3,6 %** (oba z jednoho uzavřeného zdroje, Lee a Lee 2021).
- Žádná vymyšlená nebo neexistující citace nebyla nalezena. Všech 54 ověřitelných zdrojů existuje, venue, rok a recenzovanost sedí.
- Žádná z věcných chyb není u řádku, který by nesl závěr s vysokou jistotou. Vysoká jistota (Z6, Z9, Z15) se přitom zčásti opírá o neověřený řádek 034.

## 4. Nutné opravy v extrakci a studii

Extrakce (`extrakce.csv`):

1. RQ4-050: nahradit „všechny metody selhávají“ hodnotami z Tab. 5 (viz tabulka), přidat umístění Tab. 5.
2. RQ4-033, RQ4-034: buď doložit plný text (jak byly Tab. 9 a 10 získány), nebo snížit na V1/V2 a vyřadit z závěrů. Do té doby nemají podporovat Z15 ani §6 bod 1.
3. RQ4-051: V3 změnit na V2 (jen abstrakt).
4. RQ4-009: opravit odhad na ~45-50 tis. (C-Cert) a ~180-190 tis. (C-Behav) toků TLS 1.3, nebo výpočet vypustit; doplnit „z TLS 1.3 toků“.
5. RQ4-018: oddělit „rodina procesů F1 0,9941 (baseline 0,8953)“ a „proces F1 0,9650 (baseline 0,8860)“; SD ±0,0004 resp. ±0,0013.
6. RQ4-025: doplnit složení tunelů (23 dnscat2 / 78 DNSExfiltrator / 346 iodine / 7 553 Not specified); „dnscat2 100 %“ je z 23 domén.
7. RQ4-003 (WARP 0 % vs 2 %), RQ4-005 (čtyři trasy HTTPS, jQuery je pátá; výkon srovnatelný s Ramos et al.), RQ4-017 (0,7 % uvádí zdroj), RQ4-031 (FP ≈1 %: 1,1 / 0,9 / 0,7 %), RQ4-048 (pozadí 100 000), RQ4-001/002 (sekce §4.4), RQ4-012 (§V-F), RQ4-028 (§7), RQ4-053 (Tab. 7).

Studie (`studie.md`):

1. Z7: věta „po whitelistu klesají na ≤1 novou FP doménu/den“ je chybná. V Nadler et al. je ≤1 nová FP doména/den naměřena **bez** whitelistu (Fig. 5), jde o počet nových distinktních FP domén za den (opakované alerty na již viděnou doménu se nepočítají). Whitelist autoři jen navrhují („one can assemble a whitelist“). Totéž se týká §6 bod 4 (označení [D] pro whitelist) a H4-3, kde očekávaný efekt „FP klesne k ≤1/den“ nepochází z whitelistu.
2. §1 bod 6 a Z12 a H4-6, §6 bod 6: „při chaff přes 100 % selhávají všechny“ opravit (viz RQ4-050).
3. Z4: „0,87-3,65 % toků označeno C2“ doplnit „TLS 1.3 toků kampusu“.
4. Z15 a §6 bod 1 (RQ4-034): odstranit nebo označit jako neověřené; zbytek Z15 (poměr 1 : 747 000, 1 : 526 000, 1 : 1) je podložen ověřenými řádky.
5. Abstrakt bod 7 a Z8: příčina nárůstu FNR >10× po 17 měsících je podle zdroje chybějících 4 DGA rodin v trénovacích datech, ne obecná nestacionarita sítě; sjednotit formulaci.

## 5. Kontrola tvrzení v tabulce Závěry a přesazené závěry

Zkontroloval jsem Z1, Z3, Z6, Z7, Z8, Z10, Z12 a Z14 (z toho 5 vylosovaných ze seznamu: Z3, Z6, Z7, Z10, Z12, ostatní doplněny, protože sdílejí vadné řádky).

| Z-id | Uvedená jistota | Nález |
|---|---|---|
| Z1 | nízká | V souladu s řádky 001 a 002, jistota je přiměřená. |
| Z3 | střední | **Přesazení.** Věta spojuje laboratorní výsledky 004 a 006 (nikdy nezměřené při FPR 1 %) s propadem na 13,2 % z 012, který platí jen pro jednu práci (preprint, 62 captur, RF fúze; pozdní průměrování 0 %). „+0,28 F1“ vzniklo chybným předzpracováním (globální frekvenční kódování) v autorově vlastní kontrolní variantě, není to obecný efekt úniku. Správně: „v jedné preprintové studii na reálných capturech …“, jistota nízká až střední. |
| Z6 | **vysoká** | **Přesazení.** Věta slučuje dva různé úkoly (DNS tunel: 025, 026; DGA: 027-030) a mísí rozsahy TPR 92-99,98 % z různých datasetů, přičemž 025 je z 94 % „Not specified“ lab doménové vzorky a 026 má benigní data z jedné firmy a maliciózní z veřejných PCAP. Jedna vysoká jistota se opírá o jedinou síť (Siemens) pro 028/029 a o preprint-like metodiku 030. Doporučuji „střední“. |
| Z7 | střední | **Chybný závěr** (whitelist, viz výše). Zbytek (12/18 jsou bezpečnostní služby) sedí. |
| Z8 | střední | Příčina jiná než „nestacionarita“ (chybějící DGA rodiny), viz opravy; jistota může zůstat, formulace ne. |
| Z10 | střední | **Přesazení.** „TPR 85-92 % … s FP v řádu 10^5“ cituje 043, ale Kushwaha má FPR 0,0013-0,0029 %, tedy ~10^2 FP a precision ~8 % (per-user XGBoost, ne grafová metoda), a u 038 absolutní počet FP není v řádku. FP 10^5 platí jen pro 035 a 036. |
| Z12 | střední | **Přesazení** u chaff („všechny“), viz 050. Část o zpoždění (4 z 8 metod AUC 0,56-0,64) sedí. |
| Z14 | střední | Mírné přesazení: monitorovací SSH klienti byly v Hynek et al. FP detektoru NEMEA (3), kdežto 2 potvrzené FP nového ML detektoru byly nejednoznačné klienty; formulace „FP pochází z legitimního periodického SSH“ platí pro NEMEA, ne pro ML. |
| Z9, Z11, Z2, Z4 (mimo odhad), Z5, Z13, Z15 (kromě 034) | | Odpovídají řádkům. |

Přesazené závěry: Z3, Z6, Z7 (chyba), Z10, Z12, částečně Z8, Z14 a Z15 (podpora 034 neověřena).

## 6. Verdikt

**PŘIJATO S OPRAVAMI.**

Věcná chybovost 1,9 % (limit 5 %), žádná vymyšlená citace, hodnoty z tabulek a textu zdrojů se v 44 z 54 ověřených řádků shodují přesně, v dalších 9 jsou drobné nepřesnosti. Plná akceptace (PŘIJATO) není možná kvůli: (a) jedné věcné chybě (RQ4-050), (b) dvěma neověřitelným řádkům, na nichž stojí část závěru s vysokou jistotou (Z15), (c) chybě v závěru Z7 a přesazeným závěrům Z3, Z6, Z10, Z12. Opravy výše jsou rozsahem malé a nevyžadují novou rešerši, kromě doložení plného textu Lee a Lee (nebo vyřazení řádků 033, 034).
