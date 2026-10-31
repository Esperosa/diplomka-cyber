# Revizní log RQ4 (audit trail po kontrole)

Datum: 2026-10-31. Autor-revizor. Vstup: `kontrola-RQ4.md` (verdikt PŘIJATO S OPRAVAMI). Měnil jsem jen `extrakce.csv`, `studie.md`, `neovereno.md` a tento soubor. Původní (chybné) hodnoty jsou jen zde, v hlavním textu ne.

Ověření: zdroje jsem znovu stáhl do `F:\claude-tmp\revize4\` (curl, `pdftotext -layout`): Daihes (arXiv 2008.02003), Barradas (uwaterloo.ca), Parssegny (2506.08922), Nguyen-Huu (2609.27311), Anderson 2016 (1607.01639) a 2020 (2009.01939), Palau (2006.06122), Nadler (1709.08395), Drichel (2006.11103), Elaoumari (2512.20423), Kushwaha (2208.13524), Clausen (NSS20.pdf), Hynek (Springer OA). Sloupec „ověřil jsem sám“ říká, že jsem hodnotu našel v textu PDF.

## 1. Opravy v extrakci

| Řádek | Co bylo špatně (původně) | Nová hodnota | Ověřil jsem sám |
|---|---|---|---|
| RQ4-001 | umístění „§4.2 s.10“ | §4.4 s.10 | ano, Daihes: nadpis „4.4 Evaluation results“ |
| RQ4-002 | „§4.2 s.10-11“ | §4.4 s.10-11 | ano, „minimal FPR of 14.4%“ v části 4.4 |
| RQ4-003 | WARP „0 % FP (dle textu)“ | „FP 0 % resp. 2 %“, text nekonzistentní | ano: „WARP achieves the lowest false positive rate (0%)“ a o odstavec níže „MORTON with only 2% false positives“. Poznámka: druhá věta je gramaticky nejasná, komu 2 % patří; zapsal jsem oba údaje jako rozpor zdroje |
| RQ4-005 | „selhání při neznámém profilu“; „4 reálné trasy“ | čtyři trasy MTA jsou HTTPS, jQuery (HTTP) je pátá; pokles výkonu při neodpovídajícím profilu, podle autorů většinou srovnatelné s Ramos et al. | ano: Tab. datasetů (MTA 4× HTTPS, jQuery HTTP), věta „equals or outdo the performances reached by Ramos et al.“. Pozor: tato věta se v textu týká hlavně NetFlow v9 modelů; formulace „většinou srovnatelné“ je proto opatrná |
| RQ4-009 | „0,87 % resp. 3,65 % toků“, odhad ~87 tis. / ~365 tis. toků | doplněno „TLS 1.3 toků“; odhad řádově 45-50 tis. / 180-190 tis. (hrubý odhad autora studie); zdroj jinde uvádí 99,15 % | ano: „99.13% (resp. 96.35%) of all TLS 1.3 flows as benign“, „roughly 10 million unlabeled TLS flows, more than half being TLS 1.3“, jinde „99.15% and 96.35%“. Přesný počet TLS 1.3 toků zdroj nedává, odhad je proto jen řádový |
| RQ4-012 | umístění „§Diskuse“ | §V-F „Operational Threshold Behavior“ | ano |
| RQ4-017 | „dopočet ~0,71 %“ | 0,7 % uvádí zdroj výslovně | ano: „947 out of the 133,744 TLS sessions, or 0.7%“ |
| RQ4-018 | směšovalo rodinu a proces; „F1 >0,99 (celkem), baseline 0,8953“ | rodina F1 0,9941 (±0,0004), baseline 0,8953; proces F1 0,9650 (±0,0013), baseline 0,8860 | ano, Tab. 3 (řádky „fp, sni, ip, port 0.9941 / 0.9650“, „fp 0.8953 / 0.8860“). Který sloupec je rodina a který proces jsem převzal z popisu kontroly a z textu „0.9941 for process family identification“ |
| RQ4-024 | metoda „α=2·10^-5, whitelist bezpečnostních služeb“; podmínky „FP lze snížit whitelistem“ | metoda bez whitelistu; počet nových distinktních FP domén měřen bez whitelistu; whitelist autoři jen navrhují | ano: „converges to at most a single domain per day only after only two days“ (Fig. 5), „In a real-world implementation, one can assemble a whitelist of these domains“. Kontrola měla pravdu |
| RQ4-025 | chybělo složení tunelů | 23 dnscat2, 78 DNSExfiltrator, 346 iodine, 7 553 „Not specified“; „dnscat2 100 %“ z 23 domén | ano, Tab. 3 |
| RQ4-028 | umístění „§6.4“ | §7 s.12 | ano (sekce 7 REAL WORLD, 49,435 FP) |
| RQ4-029 | poznámka „čas/drift“ | doplněna příčina (4 DGA rodiny v testu, ne v tréninku) a že po 1 měsíci autoři přeučení nepovažují za nutné | ano: „The reason for this is that the 4 DGAs: Ccleaner, Nymaim2, Tinynuke, and Wd are not included in the training sets but in the testing sets“; „it seems unnecessary to retrain the classifier after one month“ |
| RQ4-031 | „FP ≥ 1 %“ | FP ≈ 1 % (GB 1,1 %, RF 0,9 %, LR 0,7 %) | ano, Tab. 9 (hodnoty 1.1 %, 0.9 %, 0.7 %); přiřazení řádků ke klasifikátorům je z rozložení tabulky v `pdftotext`, přesné spárování jsem z textu jisté nepotvrdil, proto je v řádku uvedeno jako rozsah 0,7-1,1 % |
| RQ4-048 | pozadí 120 000 spojení | 100 000 (CAIDA 60 000 + SSH 20 000 + multimédia 20 000) | ano, Tab. 1 |
| RQ4-050 | „všechny metody selhávají, jakmile chaff tvoří většinu provozu“ | Tab. 5 (chaff 300 %), AUC: PContext 0,639, DeepCorr 0,886, WuNeur 0,615, RWalk 0,641, C-Over 0,589, Ano1 0,782, Ano2 0,738, WM 0,839; 4 z 8 metod 0,59-0,64, ostatní 0,74-0,89; umístění s citací doplněno | ano. Zdroj má vlastní silnější formulace: §5.3 „all methods struggle“ a §5.4 „render detection impossible for all methods examined“. Kontrola tedy má pravdu, že AUC tabulka „selhání všech“ nedokládá, ale je přesnější říci, že autoři sami v souhrnu tvrdí „impossible“; obojí je v řádku. TPR při FP 0,4 % je jen v grafu Fig. 6, nepřečetl jsem ho |
| RQ4-051 | V3 s citací abstraktu | V2 | souhlasím, zdroj je jen abstrakt (kontrola; plný text jsem nehledal znovu) |
| RQ4-053 | umístění Tab. 5-6 | Tab. 7; poznámka: 3 potvrzené FP NEMEA byli monitorovací klienti, 2 potvrzené FP ML nejednoznační | ano: Table 7 (NEMEA 3 / ML 2) a Table 6 rozpis (ML only: 4 neuvedeno na AbuseIPDB, 2 potvrzeno FP; NEMEA only: 3, 3) |
| RQ4-033, RQ4-034 | V3 s Tab. 9 a 10 (Lee a Lee), plný text nedostupný | odebráno z `extrakce.csv`, přesunuto do `neovereno.md` jako položka 37 (V2 z abstraktu) | nepodařilo se ověřit; Springer stránka plný text nedává (kontrola: closed access). Neplatí žádný závěr z těchto řádků. ID 033 a 034 v extrakci chybí záměrně (neprecislováno, aby odkazy zůstaly stabilní) |

Další (nenamítnuté kontrolou) zjištění při revizi:
- Studie §6 bod 4 tvrdila „přeučení minimálně měsíčně [D] RQ4-029“. Drichel et al. píší opak: po 1 měsíci „unnecessary to retrain“. Opraveno na extrapolaci [E].
- Syntéza: „DeepCorr ... ne vůči chaff“ přepsáno podle Tab. 5 (DeepCorr 0,886 je nejvyšší z 8).
- Syntéza: tabulky „DNS lexikální TPR/FPR“ míchaly dva úkoly (tunel a DGA); označeno jako informativní, nesrovnatelné.
- RQ4-011: „+0,28 F1“ je podle kontroly efekt záměrně chybné kontrolní varianty; abstrakt zdroje říká „an incorrect preprocessing step increases the F1 score by 0.28“. Samotný fakt „kontrolní varianta autorů“ jsem z textu PDF znovu neověřoval, přebírám z kontroly; v hlavním textu je proto formulace opatrná („není obecný efekt úniku“).

Počet provedených oprav v extrakci: 17 řádků změněno (001, 002, 003, 005, 009, 012, 017, 018, 024, 025, 028, 029, 031, 048, 050, 051, 053) plus 2 řádky přesunuty (033, 034) = 19 položek; k nim 4 opravy v textu mimo extrakci uvedené výše.

Nevyřešené z kontroly: Lee a Lee (plný text nedostupný), RQ4-005 a RQ4-018 v detailu přiřazení sloupců (viz poznámky), RQ4-051 plný text.

## 2. Opravy ve studii a změny jistoty

| Z-id | Stará formulace/jistota | Nová | Důvod |
|---|---|---|---|
| Z3 | střední | **nízká** | Spojení lab výsledků (004, 006, bez FPR 1 %) s propadem na 13,2 % z jedné preprintové studie (012); „+0,28 F1“ z záměrně chybné kontrolní varianty, ne obecný efekt |
| Z4 | střední | střední, doplněno „TLS 1.3 toků“ a „TNR nelze určit“ | RQ4-009 |
| Z6 | vysoká, jeden závěr pro tunel i DGA | rozděleno: **Z6a** (DNS tunel, 025, 026) **nízká**; **Z6b** (DGA, 027-030) **střední** | dva různé úkoly, nesrovnatelné datasety, jedna reálná síť (Siemens) |
| Z7 | střední; „po whitelistu klesají na ≤1 FP doménu/den“ | střední, ale tvrzení přepsáno: ≤1 nová distinktní FP doména/den **bez whitelistu**, whitelist jen navržen | RQ4-024 |
| Z8 | střední; příčina „nestacionarita“ | střední, příčina: 4 DGA rodiny nezahrnuté v tréninku; po 1 měsíci přeučení nepovažováno za nutné | RQ4-029 |
| Z10 | střední; „TPR 85-92 % ... s FP v řádu 10^5“ | střední, rozděleno podle metod: CyberGraph 107 960 FP; Euler FPR 0,57 %, P 0,0054 (absolutní FP nemám); per-user XGBoost/FCDN (není grafová metoda) FPR 0,0013-0,0029 %, odhadem ~10^2 FP, precision ~8 %; rozsah TPR „85-89,65 %“ pro grafové metody | FP 10^5 platí jen pro 035 a 036 |
| Z12 | střední; „chaff: selhávají všechny“ | rozděleno: **Z12a** zpoždění **střední**; **Z12b** chaff **nízká** (4 z 8 metod AUC 0,59-0,64, ostatní 0,74-0,89; autorské „impossible“ AUC tabulka nepodporuje) | RQ4-050 |
| Z14 | střední; „FP z legitimního periodického SSH“ | střední; NEMEA FP = monitoring, ML FP = nejednoznační klienti | RQ4-053 |
| Z15 | vysoká, 033 a 034 | vysoká, bez 033/034; ilustrace precision přes RQ4-035 (635 TP / 107 960 FP, odhad autora studie); poměry 1:1, 1:526 000, 1:747 500 | 033, 034 neověřeny |
| Z9, Z1, Z2, Z5, Z11, Z13 | – | beze změny | v souladu s řádky |

Souhrn: Z3 střední → nízká; Z6 vysoká → Z6a nízká / Z6b střední; Z12 střední → Z12a střední / Z12b nízká; Z7, Z8, Z10, Z14 jistota zůstává, formulace upravena; Z15 vysoká zůstává (jiné důkazy).

Přepočítané souhrnné rozsahy: LANL FPR (0,0013 / 0,5698 / 0,9 %) a TPR (85 / 86,1-89,65 / 92,1 %) se opírají o řádky 035, 038, 043, které se nezměnily; beze změny. Medián DNS lexikálních TPR/FPR (0,966; 0,0052) se opírá o 025, 026, 027, nezměnilo se číslo, ale označeno jako informativní a nesrovnatelné.

Další upravené sekce: Abstrakt body 1, 4, 6, 7 a počty; Metodika/PRISMA (počty a nová podsekce „Nezávislá kontrola a revize“); §3 tabulky (a), (b), (c), (e), (f); §4 rozpory; §6 body 1, 4, 6, 8; hypotézy H4-3 (A/B, whitelist není měřený efekt), H4-6 (chaff 300 % v číslech), H4-7 (+0,28 není očekávaný efekt), H4-8 (nové rodiny vs čistý drift); §8 hrozby; §9 co nebylo nalezeno (Lee a Lee).

## 3. Aktualizovaná PRISMA

Identifikováno ~275; po deduplikaci ~85; po screeningu 45; plný text 35 původně, po kontrole 33 (Lee a Lee a Maiolini 2009 jen abstrakt; že byly obě v původních 35, je můj předpoklad, původní evidence to nerozlišuje); zahrnuto 31 zdrojů, z toho 29 V3 a 2 V2 (54 řádků: 52 V3, 2 V2).

## 4. Co zůstává nevyřešené

- Lee a Lee 2021 (RQ4-033, 034): plný text nedostupný; získat přes knihovnu nebo je ponechat mimo.
- RQ4-051 a RQ4-015: jen abstrakt (V2).
- Fig. 6 v Clausen (TPR při FP 0,4 % v závislosti na chaffu) není v textu v číslech; tvrzení „detekce nemožná u všech metod“ lze ověřit jen z grafu.
- Přesné přiřazení hodnot 0,7/0,9/1,1 % ke klasifikátorům u RQ4-031 a sloupců rodina/proces u RQ4-018 závisí na čtení rozbitého layoutu tabulek; hodnoty jsou správně, přiřazení u 031 jsem proto ponechal jako rozsah.
- Kontrolu opravených hodnot neprovedl druhý agent.
