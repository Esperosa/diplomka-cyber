# RQ4: Publikovaná výkonnost detekce beaconingu/C2, DNS tunelů, exfiltrace, lateral movementu, pivotingu a reverse shellů z tokových a Zeek dat

Verze 1.1 (po nezávislé kontrole a revizi), 2026-10-31. Postup podle `00-protokol.md` (V3/V2 do závěrů, E1-E5, extrakční schéma). Data: `extrakce.csv` (54 řádků, 31 zdrojů; po revizi), `revize-RQ4.md` (audit trail oprav), `hledani.csv` (28 dotazů + 3 pokusy o fetch), `neovereno.md`.

## 1. Abstrakt

Otázka: jaká je publikovaná výkonnost (TPR, FPR, latence, dataset) detekce šesti tříd chování z tokových a Zeek dat. Prošel jsem 28 dotazů (8 „proti“), z nich jsem otevřel plné texty 35 prací (po nezávislé kontrole zpřesněno, viz §2: u dvou prací plný text ve skutečnosti nebyl dostupný). Do extrakce po revizi vstoupilo 31 zdrojů: 29 jako V3 a 2 jako V2 (Baywatch a Maiolini, jen abstrakt), celkem 54 řádků s číselnou hodnotou (52 V3, 2 V2).

Hlavní závěry (podrobně v §6):

1. Tři oblasti jsou dobře zmapované a měřené na reálném provozu: skeny (TRW), SSH brute-force (Javed-Paxson, Hynek) a lateral movement z autentizačních logů (LANL, Hopper). Ostatní jsou zmapované hlavně v laboratoři nebo se simulovaným útokem.
2. Pro reverse shell a interaktivní relace ze síťových toků jsem nenašel žádnou recenzovanou práci s TPR/FPR. Jediný kvantifikovaný výsledek (QuasarNix) je z endpointu (auditd), ne ze sítě.
3. Zveřejněná čísla jsou silně závislá na poměru útok:benign a na předzpracování. Při stejných datech (LANL) nová nezávislá re-evaluace snížila AP u Argus z 32,27 % na 0,09 % a AUC u Pikachu z 94 na 78 (RQ4-039).
4. Vysoké AUC neříká nic o provozním bodu: v DNS beaconingu při FPR 1 % nezachytily dvě ze tří metod nic, třetí 77 % (RQ4-001, 002). U šifrovaného C2 laboratorní F1 0,86-0,88 odpovídá v jedné preprintové studii (62 reálných captur, jedna kombinace metod) při FPR 1 % záchytu 13,2 % (RQ4-012); jde o jednu práci, ne o obecné pravidlo.
5. Detekce lateral movementu: samotná „nová hrana“ dává FPR 4,4 % (530 082 FP na 542 TP, RQ4-036), nejlepší grafová metoda 85 % TPR při 107 960 FP (precision ~0,6 %, RQ4-035). Jediný systém s provozně přijatelným objemem (Hopper: 9 FP/den, 94,5 % z převážně simulovaných útoků) využívá kauzální cesty a přepnutí přihlašovacích údajů, tj. data, která Zeek bez Kerberos/NTLM logů nemá (RQ4-045 až 047).
6. Stepping-stone/pivoting: bez evase AUC 0,85-0,9998, při zpoždění 1 s u čtyř z osmi metod AUC 0,56-0,64, při chaffu 300 % u čtyř z osmi metod AUC 0,59-0,64, ostatní 0,74-0,89 (RQ4-048 až 050; simulace útoku na reálném pozadí). Autoři v textu tvrdí, že detekce není při vhodném chaffu spolehlivá u žádné metody; tabulka AUC tvrzení „selhávají všechny“ nedokládá.
7. FP v DNS exfiltraci vznikají převážně z legitimních bezpečnostních služeb (12 z 18 FP domén, měřeno bez whitelistu, RQ4-024). U DGA klasifikátoru vzrostlo po 17 měsících FNR více než desetinásobně, podle autorů proto, že 4 DGA rodiny v testu nebyly v tréninku (RQ4-029), ne prokazatelně kvůli obecné nestacionaritě sítě.

Neodpovídá se: výkon RITA na reálném provozu (jediná nezávislá zkouška má velmi nízkou kvalitu, RQ4-014), JA4, Kerberos/NTLM pravidla v Zeek (žádná měřená FPR), exfiltrace z toků (jen slabé zdroje).

## 2. Metodika a PRISMA

Zdroje: WebSearch (kombinace indexů, USA), stažení PDF přes curl a `pdftotext` (všechny hodnoty čteny z textu, ne ze shrnutí), WebFetch pro abstrakty. Datum 2026-10-31. Období 2015-2026, starší jen označené `seminal=ano` (Jung 2004, Javed 2013, Maiolini 2009). Dotazy jsou v `hledani.csv`; 28 dotazů, z toho „proti“: 8 (beacon evasion, DNS FP z CDN/AV, port scan FP, DGA limitace, DoH limitace, JA3 limitace, cross-dataset CTU-13, DNS low-and-slow). Citační řetězení: u Hopper (SAL, Latte, rare-edge), Euler (Argus, Pikachu, GL-GV), Nadler (DoH diplomka), Clausen (osm SSD metod) jsem prošel reference, ale jen u Euler/Bowman/Larroche jsem referencovaný článek skutečně otevřel. Požadavek protokolu „aspoň 5 klíčových prací se zpětným i dopředným řetězením“ proto splněn pouze zpětně a částečně (přiznáno).

PRISMA (počty jsou moje evidence; „identifikováno“ jsou řádky výsledků hledání, ne unikátní práce):

| Krok | Počet |
|---|---:|
| Identifikováno (řádky výsledků, 28 dotazů × max. 10) | ~275 |
| Po deduplikaci a odstranění nevědeckých typů (patenty ~25, blogy/dokumentace výrobců ~35, „skill“ stránky 7, duplicity) | ~85 kandidátních prací (odhad autora) |
| Po screeningu názvů/abstraktů | 45 |
| Plný text zhodnocen (PDF staženo a čteno) | 35 původně; po kontrole 33 (u Lee a Lee a Maiolini 2009 byl dostupný jen abstrakt; předpokládám, že obě práce byly v původních 35 započteny) |
| Vyloučeno po plném textu | 4: Maiolini 2010 (soudní workspace, bez relevance), Bian CNSM 2019 (tabulky nečitelné, jiná jednotka: cílové hosty), CERT r4.2 2602.11019 (uživatelské logy, ne síť), DGA 2003.05703 (nedočteno do hloubky) |
| Zahrnuto | 31 zdrojů (původně 32; Lee a Lee přesunut do `neovereno.md`) |
| z toho V3 / V2 | 29 / 2 (V2: Baywatch, Maiolini 2009) |
| V1/V0 (jen abstrakt/shrnutí/blog), viz `neovereno.md` | 33 položek (celkem 37 položek v souboru vč. vyloučených a V2) |

Důvody vyloučení na úrovni screeningu: bez metriky (blogy, tutoriály), patenty, dokumentace výrobců, nedostupný plný text (MDPI 403, paywall Elsevier/IEEE), duplicita.

### Nezávislá kontrola a revize

Nezávislá kontrola proběhla 2026-10-31 (`kontrola-RQ4.md`, druhý agent bez znalosti závěrů): vzorek všech 56 řádků V3/V2 (100 %), plné texty staženy znovu. Výsledek: 44 OK, 9 drobných chyb, 1 věcná chyba (RQ4-050), 2 neověřitelné řádky (RQ4-033, 034, Lee a Lee, uzavřený přístup); věcná chybovost 1/54 = 1,9 % (limit 5 %), drobná 9/54 = 16,7 %, neověřitelných 2/56 = 3,6 %; žádná vymyšlená citace. Verdikt: PŘIJATO S OPRAVAMI. Po kontrole se změnilo: 54 řádků (033 a 034 přesunuty do `neovereno.md`), RQ4-051 přeznačen na V2, opraveny hodnoty nebo umístění v 17 řádcích, závěry Z3, Z6, Z7, Z8, Z10, Z12, Z14, Z15 sníženy nebo přeformulovány, upraveny abstrakt, §6 a hypotézy H4-3, H4-6, H4-7, H4-8. Původní chybné hodnoty a postup oprav jsou jen v `revize-RQ4.md` (audit trail). U dotčených hodnot jsem zdroje znovu otevřel (viz `revize-RQ4.md`).

Hodnocení kvality: `E` a `riziko_zkreseni` podle §6 protokolu. Žádný zdroj není E1 (systematický přehled s kvantitativní syntézou); Larroche 2026 (RQ4-039/040) a Clausen (RQ4-048 až 050) jsou nejblíže E2 (re-evaluace/nezávislé srovnání).

## 3. Výsledky podle podtémat

Sloupec „typ dat“: R = reálný provoz, L = lab/emulace, S = simulace nebo injektovaný útok do reálného pozadí. „Poměr“ = útok:benign v testu, je-li uveden. „FP/den“ = zda zdroj uvádí falešné poplachy v absolutním počtu za čas.

### (a) Beaconing / C2

| Metoda | Dataset | Typ | TPR | FPR / precision | Poměr, podmínky | FP/den? | ID |
|---|---|---|---|---|---|---|---|
| WARP / MORTON / Baywatch (DNS periodicita) | Akamai DNS, 16 000 zařízení | R benigní + S injektovaný | AUC 0,97 / 0,85 / 0,85 (B-100), 0,64 (B-10) | při FPR 1 %: MORTON TPR 77 %, ostatní 0; min. FPR Baywatch 14,4 %, WARP 3 % | 5 % zařízení infikovaných | ne | 001, 002 |
| totéž, reálný provoz bez labelů | 2 firmy, 20 000 uživatelů, týden | R (proxy ground truth VT) | n/a | MORTON 62 % ze 77 ověřeno, Baywatch-100 19 % z 365, WARP 42 párů (FP 0 % resp. 2 %, text zdroje nekonzistentní) | bez labelů | ne (počet za týden) | 003 |
| Baywatch (FFT+ACF + 8 filtrů) | web proxy, >30 mld. událostí, 5 měsíců, 130 000 zařízení | R | v abstraktu neuvedeno (V2) | neuvedeno | – | ne | 015 |
| ML nad NetFlow v5/v9 (Cobalt Strike profily) | virtualizace + 4 reálné HTTPS stopy MTA a jQuery (HTTP) | L, R | střední F1 0,78-1 (L), jQuery profil F1 0,99, při neodpovídajícím profilu „downgraded“ (většinou srovnatelné s Ramos et al.) | n/a | per-profil modely | ne | 004, 005 |
| ML nad velikostmi TLS záznamů (Metasploit) | vlastní zachycení 111 tis. vzorků | L | přesnost 99 % | n/a | 1:1 | ne | 006 |
| Evase téhož (aware detector) | tentýž | L | evase 90 % (framework-side), 50 % (payload-side) | – | – | ne | 007 |
| C-Cert / C-Behav pro TLS 1.3 | Tranco, DoHBrw, in-house + MS C2 | L C2 + R benigní | TPR 100 % / 93,87 % | TNR 99,48-99,91 % / 99,42-99,78 % | – | ne | 008 |
| totéž na kampusu | ~10 M neoznačených TLS toků | R | n/a | 0,87 % (C-Cert) resp. 3,65 % (C-Behav) TLS 1.3 toků označeno C2 | bez labelů | ne | 009 |
| fúze flow+TLS (JA3) Random Forest | 17 577 toků z 62 reálných CS captur | R | F1 0,859-0,878, trivialita 0,711 | při FPR 1 %: TPR 13,2 % (RF), 0 % (late) | 55 % pozitivních, po seskupení 4,2 % | „tisíce za den“ (kvalitativně) | 010, 012 |
| záměrně chybné globální kódování (kontrolní varianta autorů) | tentýž | R | F1 +0,28 oproti správnému kódování; není to obecný efekt úniku | – | – | – | 011 |
| fúze pod evasí obou sad příznaků | tentýž | R | každý model pod triviálním 0,711 | – | – | – | 013 |
| TLS fingerprint + cíl, naivní Bayes | 2 lokality, 50+ mil. relací/den + sandbox | R + sandbox | F1 0,9941 rodina / 0,9650 proces (baseline 0,8953 / 0,8860), malware: recall 88,7 % | precision 99,9 % | trénink květen, test červen 2020 | ne | 018, 019 |
| TLS metadata malware vs podnik, 10-fold | 225 000 podnikových toků vs sandbox | R + sandbox | 99,6 % přesnost, 92,6 % při 0,01 % FDR | – | sandbox bias | ne | 016 |
| RF/DT/LR per-flow | CTU-13, 10,6 M toků | R(lab botnet) | R≈0,60 | P≈0,50, PR-AUC 0,542 | 2,48 % botnet, práh ladi na testu | ne | 021 |
| RITA na MCP/syntetickém C2 | Docker testbed | S | skóre 0,0 u 11 profilů | – | okna 60 s, <12 spojení | ne | 014 |
| aktivní otisk TLS serveru | 28 mil. serverů, C2 blocklisty | R | – | precision >99 % (nové C2) | – | ne | 020 |

Pozorování: (i) žádná práce nereportuje FPR na síťový alert za den ani latenci detekce beaconu; MORTON a Hopper-stylem se přibližuje jen počet detekcí za týden. (ii) Výsledky na vyvážených nebo silně nafouknutých datech (55 % pozitivních, 1:1) jsou zavádějící, což explicitně ukazují RQ4-010 až 012. (iii) JA3 jako takové nemá v nalezené literatuře izolované FPR; nejblíže je RQ4-018 („hundreds of processes can map to the same fingerprint string“).

### (b) DNS tunely, DGA

| Metoda | Dataset | Typ | TPR | FPR | Poměr, podmínky | FP/den? | ID |
|---|---|---|---|---|---|---|---|
| jednotřídní anomálie nad doménou (okno 6 h) | Akamai rekurzivní DNS týden, >=100 tis. uživatelů | R benigní + S injekce (dns2tcp, iodine, 2 malware) | všechny subjekty detekovány | α=2·10^-5, bez whitelistu: konverguje na <=1 nová distinktní FP doména/den po 2 dnech, 18 FP domén celkem | několik subjektů | ano (za den) | 023, 024 |
| 1D-CNN nad řetězcem domény | 8 000 tunelů (VM lab; 23 dnscat2, 78 DNSExfiltrator, 346 iodine, 7 553 neurčeno) + 8 000 Alexa/Bambenek/cz | L | 0,9237 | 0,0052 (tabulka) vs „0,8 %“ (abstrakt) | 1:1 | ne | 025 |
| NN + one-class SVM nad prvními bajty | reálná firma 2 dny (benigní) + veřejné PCAP | R benigní + L maliciózní | 96,5-100 % | 5,8 % (2 966 FP z 51 459 spojení) | – | ne | 026 |
| DGA binární klasifikátory (FANCI, ResNet) | NX-domény RWTH/Siemens + DGArchive | R benigní + DGArchive | B-ResNet 0,99978, FANCI 0,99744 | 0,00147 / 0,00216 | 1:1 | ne | 027 |
| tentýž B-ResNet v provozu | Siemens, 1 měsíc | R | – | 0,00182 = 49 435 FP/měsíc ≈ 69 FP/hod | – | ano (za hodinu) | 028 |
| tentýž po 17 měsících | Siemens | R | FNR >10× vyšší | SD FPR roste | – | – | 029 |
| bias-reduced klasifikátor | 311 mil. benigních e2LD + 46 DGA | R | 89 % při FPR 0,008; 67-78 % při FPR 0,001-0,002 | – | maliciózní 0,0036-0,36 % | ne | 030 |
| GB/RF nad DoH toky (CIRA-CIC-DoHBrw) | 3 nástroje, 100-1100 b/s | L | ≈99,99 % | ≈1 % (GB 1,1, RF 0,9, LR 0,7 %) | – | ne | 031 |

Zdroje FP: legitimní bezpečnostní služby (Sophos, McAfee, Nessus: 12 z 18, RQ4-024; měřeno bez whitelistu), obecné služby 4 z 18. CDN: kvantitativní měření FP z CDN jsem nenašel (jen blog Elastic, V1). Selhání: DGA rodiny přítomné v testu a chybějící v tréninku po 17 měsících, FNR >10× (RQ4-029), skutečný výkon kontextově-prostých klasifikátorů se po odstranění zkreslení snižuje (RQ4-030), vyvážený benchmark vs provoz (RQ4-027 vs 028).

### (c) Exfiltrace

| Metoda | Dataset | Typ | TPR | FPR | Poměr | ID |
|---|---|---|---|---|---|---|
| DNS exfiltrace (viz b) | Akamai týden | R + S | všechny subjekty | <=1 nová FP doména/den (bez whitelistu) | – | 023, 024 |
| NN/OC-SVM, light/heavy file exfil. přes DNS | viz b | R + L | 96,6 % / 96,5 % | 5,8 % | – | 026 |
| DoH exfiltrace GB/RF | DoHBrw | L | ≈99,99 % | ≈1 % | – | 031 |
| bi-clustering + OC-SVM nad NetFlow (insider) | UNSW-NB15, NSL-KDD | S/legacy | 94,9 % (průměr) | 1,71 % (UNSW: precision 63,58 %) | ~3,5 % útoků | 032 |

Pro exfiltraci z objemu/asymetrie v tokových datech jsem nenašel recenzovanou práci s přijatelným designem a FPR. Dostupné jsou jen DNS/DoH a obecná anomálie na legacy datech (nízká váha, `pouzitelnost=ne` u RQ4-032). Vlastní soak: exfiltrace v produkčním filtru nulová (0,0 % zdrojové pořadí), 42,1 % se zahrnutím odchozích toků (soak v1); ve v2 30,7 %.

### (d) Lateral movement a pivoting z grafu

| Metoda | Dataset | Typ | TPR | FPR (nebo AP) | Poměr / podmínky | FP/den? | ID |
|---|---|---|---|---|---|---|---|
| node2vec + LR link predikce (GL-GV) | LANL, trénink 40 d / test 18 d | R + red team | 85 % | 0,9 %, TP 635, FP 107 960 | precision ~0,6 % | FP/den ~6 000 (odhad autora: 107 960/18) | 035 |
| nová hrana (UA) | LANL | R | 72 % | 4,4 %, FP 530 082 | – | ano (počty) | 036 |
| nová hrana (UA) | PicoDomain | S | 100 % | 1,5 % | malá simulace | – | 037 |
| EULER GCN-GRU/LSTM | LANL | R | 86,1-89,65 % | 0,57 %, P 0,0054, AP 0,0523 | „FPR too high alone“ | – | 038 |
| Argus/Euler/Pikachu re-evaluace | LANL (702 mal. z 369,6 mil.) | R | – | AP 0,09 / 0,02 / 0,00 % (původně 32,27 / 5,23 / –), AUC 98,44 / 97,97 / 78,28 | 1:526 000 | – | 039 |
| totéž | OpTC | S | – | AUC pro pouze LM: 43-53 | 244 LM z 36 mil. | – | 040 |
| UltraLMD++ (GFM) | LANL / OpTC | R / S | Rec@10 0,179 / 0,062 | AP 0,0088 / 0,151 | – | – | 041, 042 |
| per-user XGBoost/FCDN | LANL (89 mal. z 66,5 mil.) | R | 86,5-92,1 % | 0,0013-0,0029 % | 1:747 000 | odhad ~865 FP | 043, 044 |
| Hopper (kauzální cesty) | Dropbox 15 měsíců, 784 mil. loginů | R + 326 S + 1 red team | 94,5 % | 9 FP/den, FPR 0,0012 | 396 dní | ano | 045, 046 |
| rare-edge a SAL | tentýž | R | SAL 82 % | SAL 0,3 % (>500 FP/den), rare-edge >1 600 alertů/měsíc | – | ano | 047 |

Kerberos/NTLM: nenalezena měřená FPR (viz §9). Zeek-specifické pivot detekce (first-seen hosts/services) taktéž ne. Všechny LANL výsledky jsou z autentizačních logů, ne z toků; použití na Zeek conn.log bez identity je extrapolace.

### (e) Reverse shell, interaktivní relace, SSH tunely, stepping stones

| Metoda | Dataset | Typ | TPR | FPR | Poměr, podmínky | ID |
|---|---|---|---|---|---|---|
| 8 SSD metod, bez evase | vlastní generovaný stepping-stone + 100 000 benigních spojení | S útok + R pozadí | ~80 % při FPR <0,1 % (PContext, DeepCorr), AUC 0,85-0,9998 | – | spojení >1 500 paketů, SSH nad realitou | 048 |
| totéž, zpoždění 1 s | tentýž | S | AUC 0,56-0,64 u 4 metod (PContext, WuNeur, RWalk, WM), DeepCorr 0,995, Ano 0,997/0,996 | práh FP 0,4 % | – | 049 |
| totéž, chaff 300 % | tentýž | S | AUC: 4 z 8 metod 0,59-0,64 (PContext 0,639, WuNeur 0,615, RWalk 0,641, C-Over 0,589), ostatní 0,74-0,89 (DeepCorr 0,886, WM 0,839, Ano1 0,782, Ano2 0,738) | práh FP 0,4 % | autoři: „no method reliably“ | 050 |
| k-means nad prvními pakety (SSH), V2 (jen abstrakt) | lab SSH | L | 99,5 % SSH, 99,88 % aplikace | – | – | 051 |
| tunel detekce RF z NetFlow v5 | UNIBS/UPC | L tunely | F1 0,54 / 0,28 při přenosu | – | – | 022 |
| endpoint: GBDT nad příkazovou řádkou | 50 000 Linux hostů, syntetika | S (endpoint) | 99,94 % při FPR 1e-5 (bez augmentace 7,12 %) | 1e-5 | NE síť | 056 |

SSH přes proxy (Lee a Lee 2021): hodnoty nelze ověřit (jen abstrakt), přesunuto do `neovereno.md`. Reverse shell/interaktivní relace ze sítě: žádná nalezená recenzovaná kvantifikace (patent Salesforce o velikosti paketu na stisk klávesy, dokumentace Juniper: bez metrik). SSH keystroke: klasika (Song-Wagner-Tian 2001) je útok na soukromí, ne detektor; zde V1.

### (f) Skeny a brute-force (referenční úlohy)

| Metoda | Dataset | Typ | TPR / effectiveness | FPR / efficiency | Podmínky | ID |
|---|---|---|---|---|---|---|
| TRW (Jung 2004) | Bro logy LBL, ICSI, 24 h | R, ground truth heuristický | LBL 0,960; ICSI 0,992 | efficiency 0,963 / 1,000 | Bro recall 0,150 / 0,029, Snort 0,126 | 055 |
| CUSUM + beta-binomická (SSH distribuovaný BF) | 8 let SSH logů | R | 90 epoch, FN neznámé | 9 z 99 epoch falešných | – | 054 |
| ML nad rozšířenými IP toky (SSH BF) | dataset2: 86 000 toků, 564 klientů, CESNET2-GÉANT | R | ML 444 vs NEMEA 318 (+40 %) | potvrzené FP ML 2, NEMEA 3 | ground truth AbuseIPDB | 052, 053 |

Skeny a brute-force jsou nejlépe zmapované, ale i tady je FP z legitimního periodického chování (u NEMEA SSH monitoring, u ML nejednoznační klienti, RQ4-053) a ground truth heuristický (RQ4-055). Starší práce jsou 2004-2013, po roce 2020 jsem nenalezl nový reálný vyhodnocený TRW/BF benchmark.

## 4. Syntéza

Dle §8 protokolu agreguji jen při >=3 studiích se stejnou metrikou a srovnatelnými podmínkami. Takové podmínky nesplňuje žádná skupina, proto uvádím jen rozsahy bez sdružování.

| Skupina | N studií / datasetů | Rozsah (min / medián / max) | Heterogenita |
|---|---|---|---|
| LANL lateral movement, FPR (%) | 3 / 1 (jiná předzpracování) | 0,0013 / 0,5698 / 0,9 (Kushwaha, Euler, Bowman) | extrémní (3 řády); různé jednotky (uživatel/hrana/událost), Larroche ukazuje vliv předzpracování |
| LANL TPR (%) | 3 | 85 / 86,1-89,65 / 92,1 | střední |
| DNS lexikální TPR (informativně: 2 úlohy tunel + 1 DGA, nesrovnatelné podmínky, medián jen z 3 hodnot) | 3 (Palau, Sobrero, Drichel) | 0,924 / 0,966 / 0,9998 | různé úlohy a zdroje dat; neslučovat |
| DNS lexikální FPR (informativně, viz výše) | 3 | 0,0015 / 0,0052 / 0,058 | 40× rozptyl; nesrovnatelné |
| C2 laboratorní přesnost/F1 | 3 (Cobalt, Metasploit, Nguyen-Huu) | 0,78 až 1 (Cobalt), 0,99 (Metasploit), 0,859-0,878 (reálné captury) | nelze sdružit |
| Stepping-stone AUC bez evase | 1 studie, 6 metod | 0,853 / 0,981 (medián ze 6 hodnot) / 0,9998 | jeden dataset |

Rozpory vysvětlené:

- LANL AP: Argus uvedl AP 32,27 %, nezávislá re-evaluace 0,09 % (RQ4-039). Důvod: původní předzpracování vyřadilo benigní události (Larroche: „excessively optimistic“), ne změna metody.
- DNS tunel Palau: abstrakt FPR „close to 0,8 %“, tabulka 0,52 % (třída Tunneling) a 7,62 % (třída Normal). Uvádím obě; jde o definici „pozitivní třídy“.
- MORTON: nejnižší AUC ze tří (0,85), ale jediný použitelný při FPR 1 % (77 %). AUC a provozní bod se rozcházejí.
- DeepCorr: odolný vůči zpoždění (AUC 0,995), při chaffu 300 % AUC 0,886 (nejvyšší z 8 metod, ale pokles). PContext: zpoždění 0,638, chaff 0,639 (RQ4-049 vs 050).

Porovnání s naším soakem (simulace, vlastní model, RQ5 varuje před cirkularitou; nejde o srovnání stejných metrik):

| Rodina | Soak v1 (3 h) detekováno / správný typ | Soak v2 (3,5 h, částečný) | Nejbližší literatura |
|---|---|---|---|
| c2_beacon | 4,7 % / 0,3 %, median 60 min | 12,9 % / 6,9 %, median 420 min | MORTON při FPR 1 %: ostatní metody 0 %, MORTON 77 % (RQ4-002); fúze 13,2 % při FPR 1 % (RQ4-012). Nízká detekce při nízkém FPR odpovídá literatuře. |
| fleet_beacon | – | 76,5 % / 32,5 % | bez literatury |
| dns_tunnel | 99,8 % / 99,8 % | 99,8 % / 99,6 % | lab: 92-100 % (RQ4-025, 026); reálně FP 69/h (028); náš simulátor nezahrnuje AV/CDN lookalike (`software_update` 0 nálezů), tj. optimistické |
| exfiltration | 66,6 % / 65,9 %, zdroj 0 % (filtr) | 69,9 % / 67,0 %, zdroj 0 % → 30,7 % s egress | v literatuře chybí srovnání |
| lateral_movement | 90,2 % / 12,5 % | 96,9 % / 65,8 % | LANL: TPR 85-92 % při FPR 0,0013-0,9 % (035, 038, 043); náš „detekováno“ nezahrnuje precision |
| ssh_bruteforce | 99,8 % / 78,9 % | 96,4 % / 75,8 % | Hynek: FP 2 potvrzeno z 444 (RQ4-053) |
| port_scan horiz./vert. | 89,5 / 72,7 % | 95,3 / 74,1 % | TRW 0,96-0,99 (RQ4-055) |
| FP | 210,7 / sít-den | 1 282 / sít-den | Hopper 9/den (jedna enterprise síť, jen lateral); nelze srovnat (různá jednotka) |

Odpovídá literatuře: nízká detekce beaconu při omezeném FPR, rozdíl „detekováno vs. správný typ“ u lateral movementu (literatura: FP a nízká precision), slabá viditelnost exfiltrace ve filtrovaných datech. Neodpovídá/nelze porovnat: 99,8 % u dns_tunnel je vyšší než reálné provozní hodnoty, které mají FP stovky za den; 1 282 FP na sít-den je řádově jiná veličina než Hopper (9/den na jedné síti, jen lateral).

## 5. Závěry

| Z-id | Tvrzení | Důkazy | Jistota | Důvody snížení | Pro Skákavku | Doporučená akce |
|---|---|---|---|---|---|---|
| Z1 | Vysoké AUC periodických detektorů beaconingu (0,85-0,97) neimplikuje použitelnost: při FPR 1 % dvě ze tří testovaných metod nenajdou nic, MORTON 77 %. | RQ4-001, 002 | nízká | jeden dataset, injektovaný útok, bez CI, DNS místo toků | ano | hodnotit TPR při pevném FPR (1e-3, 1e-4), ne AUC |
| Z2 | Na reálném provozu bez labelů je podíl ověřitelně maliciózních detekcí z periodicity 19 % (Baywatch-100) až 62 % (MORTON); detekcí jsou desítky až stovky za týden na ~20 tis. uživatelů. | RQ4-003 | nízká | proxy ground truth (VT), jeden běh | ano | počítat precision proti nezávislému ground truth, počítat alerty/týden |
| Z3 | Laboratorní studie šifrovaného C2 uvádějí přesnost 99 % a F1 0,78-1 (RQ4-004, 006), ale provozní bod FPR 1 % v nich nebyl měřen. V jedné preprintové studii na 62 reálných capturech (RQ4-010 až 013) odpovídá F1 0,86-0,88 záchytu 13,2 % (RF fúze; pozdní průměrování 0 %) při FPR 1 % a po podvržení příznaků jsou modely pod triviální baseline; chybné předzpracování tam zvýšilo F1 o 0,28 (v autorově záměrně chybné kontrolní variantě, ne obecný efekt). | RQ4-004, 006, 010-013 | nízká | jediná preprintová studie pro provozní bod a evasi, lab data u zbytku, nepřímost | ano | split po cíli/zachycení, ne po toku; evaluace s evasí a při pevném FPR |
| Z4 | Kryptografické metadata (JA3-like, velikosti záznamů) rozlišují malware od podniku, ale otisk sám nestačí (stovky procesů na jeden otisk) a v TLS 1.3 se musí příznaky odvodit; na neoznačeném kampusu je 0,87-3,65 % TLS 1.3 toků označeno C2 (skutečné TNR nelze určit). | RQ4-008, 009, 016-019 | střední | sandbox bias, TNR bez ground truth | s úpravou | otisk brát jako rys s kontextem cíle, ne alert |
| Z5 | Aktivní otisk TLS serveru dosáhl precision >99 % na nových C2 serverech z blocklistů (30 týdnů, 28 mil. serverů). | RQ4-020 | střední | blocklist jako ground truth, FP u sdílených serverů | ano | kandidát pro ověřovací krok Skákavky |
| Z6a | DNS tunel: lexikální detektor (RQ4-025) dosáhl na vyváženém lab vzorku (94 % tunelových domén bez určeného nástroje) TPR 92 % při FPR 0,52 %; detektor nad prvními bajty (RQ4-026) TPR 96,5-100 % při FPR 5,8 % na reálném benigním provozu jedné firmy a veřejných PCAP tunelů. | RQ4-025, 026 | nízká | vyvážené lab vzorky, benigní a maliciózní data z různých zdrojů, jedna firma, bez CI | s úpravou | kontextová agregace, ne rozhodnutí po doméně |
| Z6b | DGA: na vyvážených datech TPR 99,7-99,98 % při FPR 0,15-0,22 % (RQ4-027); v jedné síti (Siemens) v provozu 69 FP/hod, FPR 0,18 % (RQ4-028); po odstranění zkreslení 67-78 % TPR při FPR 0,1-0,2 % (RQ4-030). | RQ4-027 až 030 | střední | jedna reálná síť pro provozní bod, různé zdroje benigních a maliciózních dat | ano | kontextová agregace, ne rozhodnutí po doméně |
| Z7 | Většina FP u DNS exfiltrace/tunelů jsou legitimní bezpečnostní služby (12 z 18 FP domén); počet nových distinktních FP domén za den klesl u modelu bez whitelistu na nejvýše 1 po dvou dnech (Fig. 5). Whitelist autoři jen navrhují, zdroj jeho efekt neměřil. | RQ4-023, 024 | střední | jedna sada, reálná, málo útoků, whitelist neměřen | ano | whitelist AV/bezp. služeb a CDN vzorů ověřit jako hypotézu (H4-3), ne jako doložený postup |
| Z8 | Po 17 měsících od tréninku FNR DGA klasifikátoru vzrostlo >10×; podle autorů proto, že 4 DGA rodiny (Ccleaner, Nymaim2, Tinynuke, Wd) byly v testu a ne v tréninku. Po 1 měsíci autoři přeučení nepovažují za nutné. Vliv obecného driftu sítě se od vlivu nových rodin nedá oddělit. | RQ4-029 | střední | jedna síť, záměna příčin (nové rodiny vs drift) | ano | sledovat nové rodiny/typy; interval přeučení je extrapolace |
| Z9 | Publikované výsledky lateral movementu na LANL/OpTC jsou nadsazené (AP z 32,27 % na 0,09 %; AUC Pikachu 94 → 78; OpTC LM-only AUC 0,43-0,53). | RQ4-039, 040 | vysoká | jedna skupina autorů, ale deterministická re-evaluace a 10 běhů | ano | nepřebírat čísla z originálních prací |
| Z10 | Grafové metody dosahují na LANL TPR 85-89,65 % (RQ4-035, 038); CyberGraph s 107 960 FP (precision ~0,6 %, odhad autora studie), u Euler FPR 0,57 % a precision 0,0054 (absolutní počet FP není v řádku). Per-user XGBoost/FCDN (RQ4-043, není grafová metoda) má TPR 86,5-92,1 % při FPR 0,0013-0,0029 %, tj. odhadem ~10^2 FP a precision ~8 % (odhad autora studie). Samotná nová hrana má FPR 4,4 % (530 082 FP). | RQ4-035, 036, 038, 043 | střední | různé předzpracování a jednotky, 1 red-team scénář | ano | first-seen = rys, ne alert |
| Z11 | Systém s kauzálními cestami a přepnutím přihlašovacích údajů (Hopper) dosáhl 94,5 % TPR při 9 FP/den; samotný rare-edge by dal >1 600 alertů/měsíc, SAL 8× více FP. | RQ4-045 až 047 | střední | 326 ze 327 útoků simulováno, autentizační logy, ne toky | s úpravou | potřeba identit (Kerberos/NTLM) |
| Z12a | Stepping-stone detekce selhává proti zpoždění: při 1 s u 4 z 8 metod AUC 0,56-0,64; bez evase AUC 0,85-0,9998. | RQ4-048, 049 | střední | simulace útoku, spojení >1 500 paketů | s úpravou | testovat zpoždění 0/0,5/1 s |
| Z12b | Při chaffu 300 % mají 4 z 8 metod AUC 0,59-0,64 (blízko náhodě), ostatní 0,74-0,89 (DeepCorr 0,886); autoři v textu tvrdí, že detekce není při vhodném chaffu spolehlivá u žádné metody, což tabulka AUC přímo nedokládá. | RQ4-050 | nízká | simulace, TPR při FP 0,4 % jen v grafu (nepřečteno), jedna skupina autorů | s úpravou | pivoting s chaffem nepočítat jako spolehlivě detekovatelný |
| Z13 | Pro reverse shell/interaktivní relace ze síťových toků nebyla nalezena recenzovaná práce s TPR/FPR; jediný kvantifikovaný výsledek je z endpointu. | RQ4-056 (mimo síť), neg. nález | velmi nízká | absence důkazů | ne | nastavit vlastní cíle, nepřebírat z literatury |
| Z14 | Skeny a SSH brute-force jsou nejlépe zmapované; 3 potvrzené FP detektoru NEMEA byly legitimní monitorovací SSH klienti, 2 potvrzené FP nového ML detektoru byly nejednoznační klienti (ne monitoring); ground truth u skenů je heuristický. | RQ4-052 až 055 | střední | stáří (2004, 2013), AbuseIPDB jako ground truth | ano | reference pro srovnání |
| Z15 | Čísla různých studií nejsou srovnatelná: poměr útok:benign sahá od 1:1 (RQ4-025, 027) po 1:526 000 (RQ4-039) a 1:747 500 (RQ4-043, 044); při malém podílu pozitivních vychází nízká precision i při malém FPR (CyberGraph: 635 TP a 107 960 FP, precision ~0,6 %, odhad autora studie z RQ4-035). | RQ4-025, 027, 035, 039, 043, 044 | vysoká | – | ano | vždy uvádět poměr a precision |

## 6. Překlad do praxe pro Skákavku

Označení: [D] přímo z důkazu, [E] extrapolace.

1. Metriky: u každé rodiny reportovat TPR při FPR 1e-3 a 1e-4, počet FP na sít-den a precision při deklarovaném poměru. [D] RQ4-002, 030, 035 (precision z TP/FP je odhad autora studie).
2. Beaconing: nepočítat s periodicitou z krátkých oken; RITA-styl skóre je prázdné pod ~12 spojení na dvojici (RQ4-014, [D]); pro jitter ±50 % a více volit hodinové/denní agregace a relativní toleranci [E, podle V1 zdrojů, neověřeno]. Filtr legitimního beaconingu (aktualizace, monitoring) je nutná součást (RQ4-015, V2, [D]).
3. TLS: JA3/JA4 samotný jako alert ne; kombinovat s cílem (adresa, SNI) [D] RQ4-018. Pro TLS 1.3 používat velikosti a typy záznamů [D] RQ4-008.
4. DNS: whitelist AV/bezp. služeb a CDN vzorů před alertováním [E: RQ4-024 měřilo FP složení bez whitelistu, 12 z 18 FP domén jsou bezpečnostní služby; whitelist autoři jen navrhují, efekt neměřen]; α=2e-5 na doménu jako konzervativní start [D] RQ4-023; agregace po hostu (doporučení autorů, neměřeno) [D/E] RQ4-028; po 1 měsíci autoři přeučení nepovažují za nutné, po 17 měsících FNR >10× kvůli novým rodinám (RQ4-029); interval přeučení je extrapolace [E].
5. Lateral movement: first-seen hrany používat jako rys; alert až s kauzální cestou nebo přepnutím identity; denní rozpočet alertů (Hopper: 5 pro anomálii) [D] RQ4-046, 047. U Zeek bez Kerberos/NTLM identity je to extrapolace [E].
6. Stepping-stone/pivoting: korelace časování interaktivních spojení funguje jen na spojeních >1 500 paketů, zpoždění 1 s srazí 4 z 8 metod na AUC 0,56-0,64 a chaff 300 % také 4 z 8 metod na AUC 0,59-0,64 (ostatní 0,74-0,89) [D] RQ4-048 až 050. Náš pivoting agent by se měl testovat s chaff 0/50/100/200 % a zpožděním 0/0,5/1 s.
7. Exfiltrace: v produkci zahrnout odchozí toky (soak: 0 % → 30,7 %) [D soak]; literatura kvantitativní cíle nedává.
8. Evaluace: split po cíli/zachycení (RQ4-010; velikost efektu úniku neznámá, RQ4-011 byl záměrně chybný kontrolní případ), deduplikace opakovaných LM hran (RQ4-041), jednotné předzpracování (RQ4-039). Přidat do harnessu benigní lookalike: AV/DNS lookupy, CDN subdomény, periodický SSH monitoring, update checkery, beacon jitter 0/10/25/50/100 %.

## 7. Hypotézy k empirickému ověření

Formát: změna → očekávaný efekt (rozsah z důkazů) → metrika → scénář/seedy → kritérium zamítnutí.

- **H4-1** Hodnocení beaconingu při pevném FPR místo AUC. Změna: přidat do harnessu TPR@FPR 1e-3. Očekávaný efekt: pořadí metod se může změnit (MORTON 77 % vs 0 % při 1 %, RQ4-002). Metrika: TPR@FPR 1e-3 pro c2_beacon a fleet_beacon na stejných seedech. Scénář: soak v2, seedy 20261031+0..9. Zamítnutí: pořadí metod shodné s AUC pořadím na všech seedech.
- **H4-2** Dlouhé okno a minimum spojení. Změna: periodicita nad okny >= 24 h a >= 12 spojení na dvojici. Očekávaný efekt: zvýšení detekce c2_beacon nad 12,9 % (extrapolace, bez kvantifikace z literatury; MORTON 77 % při FPR 1 % je horní reference na DNS datech). Metrika: detekce c2_beacon a FP/sít-den. Zamítnutí: přírůstek detekce <5 p.b. nebo růst FP/sít-den >10 %.
- **H4-3** Whitelist bezpečnostních služeb a CDN pro DNS. Změna: porovnat A (bez whitelistu) s B (s whitelistem). Očekávaný efekt: bez whitelistu konverguje počet nových distinktních FP domén na <=1/den po ~2 dnech (RQ4-024, měřeno bez whitelistu); efekt whitelistu zdroj nekvantifikuje (extrapolace, očekává se snížení oproti A). Metrika: nové FP domény za den na benigních lookalike (přidat AV/CDN do simulátoru). Zamítnutí: >3 nové FP domény/den po 2 dnech při zachování dns_tunnel >=99 %, nebo B nesníží počet FP oproti A (upraveno po kontrole).
- **H4-4** First-seen jako rys vs. alert. Změna: lateral alert jen při first-seen + přepnutí identity/cesta o >=2 hopech. Očekávaný efekt: FP sníženy řádově (Hopper vs rare-edge: >1 600 alertů/měsíc → 9/den; SAL 8×, RQ4-047) při TPR >=90 %. Metrika: FP/sít-den lateral, TPR, správný typ (v2: 65,8 %). Zamítnutí: pokles FP <50 % nebo TPR <85 %.
- **H4-5** Zahrnutí odchozích toků pro exfiltraci. Očekávaný efekt: zdrojové pořadí 0 % → ~30-42 % (vlastní měření soak; literatura nic nedává). Metrika: top-3 zdroj exfiltrace. Zamítnutí: <20 % ve v2 po opravě filtru.
- **H4-6** Pivoting pod chaffem. Změna: korelace časování interaktivních řetězců (PContext/DeepCorr-like). Očekávaný efekt: ~80 % TPR při FPR <0,1 % bez evase (RQ4-048), pokles při zpoždění 1 s (4 z 8 metod AUC 0,56-0,64, RQ4-049) a při chaffu 300 % (4 z 8 metod AUC 0,59-0,64, ostatní 0,74-0,89, RQ4-050); úplné selhání všech metod zdroj v číslech nedokládá. Metrika: TPR při FPR 0,4 % vs chaff {0, 50, 100, 200 %}. Zamítnutí: TPR při chaff 0 <60 % nebo žádný pokles při chaff 200 %.
- **H4-7** Evaluační únik. Změna: split podle cíle místo podle toku v kotvě CTU-13/IoT-23. Očekávaný efekt: pokles F1 / PR-AUC; velikost efektu literatura neposkytuje (RQ4-011 popisuje +0,28 F1 jen u záměrně chybné kontrolní varianty, není to očekávaný efekt; RQ4-021: PR-AUC 0,54 i při náhodném splitu). Metrika: PR-AUC rozdíl. Zamítnutí: rozdíl <0,02.
- **H4-8** Drift. Změna: přeučení/kalibrace po 1 měsíci vs po 17 měsících simulovaného driftu. Očekávaný efekt: FNR >10× při výskytu nových DGA rodin v testu a ne v tréninku (RQ4-029); po 1 měsíci čistého driftu zůstává FNR stejného řádu. Změna rozdělit na (a) nové rodiny, (b) čistý drift. Metrika: FNR po driftu. Zamítnutí: (a) nárůst <2×.

## 8. Hrozby validity

- Silné zkreslení výběrem: WebSearch vrací shrnutí, ne systematický index; nepoužil jsem ACM DL/IEEE Xplore přímo. Paywallované práce (Stergiopoulos, ETDetector, Song 2001) jsou V1.
- 33 položek V1/V0 se nepromítlo do závěrů, ale mohou obsahovat protichůdné výsledky (např. UC Davis: osminásobný nárůst FPR TRW při vzorkování 1/10).
- Nezávislá kontrola proběhla (`kontrola-RQ4.md`, 100 % řádků; věcná chybovost 1,9 %); revizi provedl autor-revizor a opravené hodnoty druhý agent znovu nekontroloval.
- Několik zahrnutých zdrojů jsou preprinty 2026 (Larroche 2026, Nguyen-Huu, Sohail, Gurappa) nebo MSc práce (Elaoumari) a nebyly recenzovány.
- Čísla z tabulek PDF mají některá riziko chyby extrakce (RQ4-016 Tab. V rozbitá, RQ4-038 sloupce P); označeno v řádcích.
- Autor studie provedl několik odvozených výpočtů (precision z TP/FP, FP/den z FP/18 dní, 865 FP, počty toků z procent u RQ4-009), označeno „odhad autora studie“.
- Soak je simulace s vlastním ground truth (cirkularita, RQ5).
- Většina důkazů je E3; žádný E1.

## 9. Co NEBYLO nalezeno

- Nezávislé vyhodnocení RITA na reálném provozu s TPR/FPR (jen Sohail 2026 s nízkou kvalitou, RQ4-014).
- Baywatch: číselné TPR/FPR (plný text nedostupný).
- Lee a Lee 2021 (SSH přes proxy): plný text uzavřený, hodnoty nelze ověřit (`neovereno.md`).
- JA3/JA4: kontrolovaná studie FPR/evase s čísly (jen blogy výrobců, V1).
- Kerberos/NTLM/pass-the-hash pravidla v Zeek: žádná měřená FPR.
- Exfiltrace z objemu/asymetrie toků s baseline: recenzovaná studie s přijatelnou evaluací; jediné nalezené práce jsou DNS/DoH a legacy datasety.
- Reverse shell/bind shell a interaktivní relace z toků: jakýkoli recenzovaný TPR/FPR.
- Cross-dataset studie pro C2 z NetFlow (mimo Mazel pro tunely).
- Aktuální (po 2020) reálný benchmark skenů a SSH brute-force s FPR za den.
- FP z CDN: kvantitativní měření (jen Elastic blog).
- Výkon na Zeek logech specificky (conn/dns/ssl): většina prací používá PCAP, NetFlow nebo proxy logy.
- Negativní/replikační výsledky: nejbližší jsou Larroche 2026, Clausen 2020, Nguyen-Huu 2026, Drichel 2023.

## 10. Tvrzení výrobců (nepoužito v závěrech)

| Zdroj | Tvrzení | Stav |
|---|---|---|
| Infoblox blog | CNN autoencoder + RF 99,7 % F1 pro DNS tunely | V1, vendor, bez dat |
| DNSSense | detekce ultra-pomalého DNS tunelování (2 MB za 2 roky) | V1, vendor |
| Elastic Network beaconing framework (dokumentace) | snížení minimální autokovariance zvyšuje recall a snižuje precision | V1, dokumentace |
| Vectra blog | JA3 randomizace snižuje hodnotu JA3 | V1, vendor |
| Juniper ATP Cloud, Salesforce patent | detekce reverse shellu z počtů/velikostí paketů | V1, bez metrik |
