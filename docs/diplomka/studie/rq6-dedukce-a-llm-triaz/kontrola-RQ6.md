# Nezávislá kontrola extrakce RQ6 (protokol §9)

Datum kontroly: 2026-10-31. Kontrolováno: `extrakce.csv` (51 řádků, všechny V3 kromě RQ6-050 = V2) a tabulka Závěry v `studie.md`. Soubory extrakce.csv ani studie.md jsem nezměnil.

## 1. Vzorek a postup

Požadavek: aspoň 30 % řádků V3/V2 (tj. aspoň 16 z 51) a aspoň 20 řádků. Zkontrolováno **26 řádků (51 %)**.

Výběr:
- (a) Všechny řádky, o které se opírají závěry se jistotou „vysoká" nebo „střední". V tabulce Závěry není žádný závěr s jistotou „vysoká"; „střední" mají Z1 (RQ6-009, 021, 022), Z3 (RQ6-003), Z6 (RQ6-023, 024, 025; střední pro existenci rizika) a Z9 (RQ6-033, 035, 040, 041, 042, 043, 045). To je 14 řádků.
- (b) Systematický výběr: každý čtvrtý řádek od RQ6-002 (002, 006, 010, 014, 018, 022, 026, 030, 034, 038, 042, 046, 050). Po odečtení překryvu (022, 042) přibylo 11 řádků.
- (c) Ručně přidán RQ6-001 (hlavní řádek Alert-Bench, základ Z2 a Z3).

Zdroje: všechny hodnoty jsem ověřoval na čerstvě stažených plných textech z primárních URL z pole `url_nebo_doi` (arXiv PDF, USENIX, NDSS, SciTePress) převedených `pdftotext`. Přímé načtení PDF nefunguje, proto jsem PDF stáhl `curl` do nového adresáře `%TEMP%\kontrola6` a text přečetl lokálně. Staré kopie z `<pracovní adresář>/rq*pdf\` jsem nepoužil. RQ6-050 jsem ověřil přímo na README repozitáře GitHub.

Co jsem nekontroloval: čísla stránek a oddílů v poli `umisteni_a_citace` jsem ověřoval jen tak, že doslovná citace nebo číslo v uvedené tabulce skutečně existuje, ne číslování stránek. Poznámky `pouzitelnost` a `poznamka` jsou úsudek autora, ty jsem hodnotil jen tam, kde z nich plyne tvrzení o datech.

## 2. Kontrolované řádky

| id | výsledek | poznámka |
|---|---|---|
| RQ6-001 | DROBNÁ CHYBA | Všechna čísla sedí (F1 0,744, recall 0,596, ostatní 0,371–0,625, McNemar 1,1e-3 proti Self-Consistency, 6235 vyšetřování, 225/1022, 1247, 4 dny; doslovná citace v oddílu „RQ1. Triage effectiveness"). Tvrzení „zkrácená verze NeurIPS 2026 WS Agents in the Wild, WS verze ano" v PDF není: zdroj je jen arXiv:2610.10608v1 (7. 10. 2026), bez uvedení venue. Venue nelze potvrdit. |
| RQ6-002 | OK | „every approach missed at least 40.4 %" i „40.4–70.2 %, AIDA 3.1 %" sedí (abstrakt, úvod). |
| RQ6-003 | OK | 98,6 % vs 30,3 % (ReAct), korelace 0,383 p<1e-40, 1125 útočných vyšetřování, 211 z 602 FN, benigní rozdíl max 2,8 p.b. Vše sedí doslova. Poznámka: jde o asociaci (autoři píšou „associated"), viz Z3. |
| RQ6-006 | OK | AIDA F1 0,958, recall 0,969, FNR 3,1 %, eskalace 18,4 % vs 8,5–14,0 %. Tabulka výsledků potvrzuje. |
| RQ6-009 | DROBNÁ CHYBA | „the baseline achieved 0% accuracy on the malicious subset" je v textu oddílu IV.A, Tab. II. Hodnota správná. Venue „workshop" v PDF nenalezeno (jen arXiv). Věcná nuance: baseline vstup nebyl „jen text alertu", ale alert plus přehledový dotaz (overview query) nad logy. V Tab. II je navíc u Claude 3 Haiku 99 %, u Qwen3 100 % a u GPT-5-mini většina verdiktů „uncertain", jen Gemma dala 100 % benigní. 0 % přesnosti tedy zčásti znamená „nejisté", ne „benigní". |
| RQ6-010 | OK | Tři ze čtyř modelů >90 %, Gemma 81 %, průměr 93 %, max FNR 4 %, <1 % škodlivých verdiktů na benigní podmnožině, GPT-5-mini označuje benigní jako „uncertain" (text i Tab. III). Sedí. |
| RQ6-014 | OK | CIC-IDS2017 (5 TP, 30 FP): GPT-5 97,1 %, Claude-4.5 88,57 %, GPT-4o-mini 51,4 % (FP 14/30); TII-SRC-23 GPT-4o-mini 75 % (FP 32/50). Tab. 10, doslovná citace sedí. |
| RQ6-018 | OK | Nejlepší 0,606 (Claude-Opus-4.5), GPT-4o 0,293, GPT-4.1 0,338 v posledním sloupci Tab. 2 (průměr). 57 tabulek. Venue: v6 PDF uvádí „Proceedings of the 43rd International Conference on Machine Learning", takže ICML 2026 je věrohodné. |
| RQ6-021 | DROBNÁ CHYBA | Tab. 1: Llama3-8B 48,56/40,56 %, GPT-4 50,85/53,47 %, citace „worse than random selection" sedí. Hodnota „RF vážené F1 92,17 %" ale není měření autorů: jde o převzatou hodnotu z cizí práce [21], kterou autoři jen citují. V extrakci to není uvedeno, a Z1/abstrakt ji používají jako srovnání. |
| RQ6-022 | DROBNÁ CHYBA | Abstrakt: „7B ... with flags reaches macro-F1 near 0.78" na 200 tocích sedí. Ale „3B s few-shot ~0,68" je z N = 1000 toků (F1(+) 0,68, accuracy 0,70), ne z 200; pole `podminky` („200 toků") to slučuje. Navíc u N = 2000 bez kalibrace klesá F1(+) na 0,43. |
| RQ6-023 | OK | 68 % potlačení (persona hijack, naivní klasifikátor), 96 % (S3 sumarizace bez obrany, 38 % s omezeným výstupem), průměr 26,6 % → 11,8 %, 48 kombinací, gpt-4o-mini. Doslovně v abstraktu. |
| RQ6-024 | OK | 12 847 záznamů, 2 569 adversarních, až 88,2 % (průměr 83,4 %; Llama-3-70B 88,2), vrstvená obrana −90,4 %, zbytek 8,4 %. Abstrakt a tabulka sedí. |
| RQ6-025 | OK | 1100 záznamů, otrávené modely 100 % misklasifikace, čistý Llama 20 %, čistý Qwen 71 %, validační přesnost 82,7 %. Citace sedí. Nuance: čistý Qwen už má 71 %, takže pro Qwen je přírůstek jen 71 → 100 %. |
| RQ6-026 | OK | 167 analytiků, 25 e-mailů, F1 +77 % (korpus), +48 % (kontrafaktuál 0,8), až 6,5× TP/min, +53 % času na škodlivé, precision i recall agenta 100 % na korpusu. Citace „driving an 77% in F1" sedí. |
| RQ6-030 | OK | ~3,1 mil. alertů, 61 % uzavřeno, FNR 1,36 % za 6 měsíců, offline 34 % při FNR 1,5 %. Sedí. |
| RQ6-033 | OK | HOLMES: interval [338,25; 608,26] je rozsah mezi maximem skóre benigních a minimem skóre útočných podgrafů testovaných datasetů, „accuracy and recall equal to 1" (oddíl VI-E). Sedí včetně data snoopingu. |
| RQ6-034 | DROBNÁ CHYBA | 330 270 alertů → 93 attack grafů, CPTC-2018, citace z abstraktu sedí. Venue „KDD WS / VizSec" není v PDF uvedeno (jen arXiv v2); nelze potvrdit. |
| RQ6-035 | OK | KAIROS Tab. 4: precision 0,438 (E5-CADETS) až 1,000, OpTC 0,579; Tab. 5 po úpravě E5-CADETS 1,000, OpTC 0,842; „manually identify these fake FPs". Sedí. |
| RQ6-038 | OK | ORTHRUS 48 uzlů (25 TP, 23 FP), precision 52 %; Flash 2 394 uzlů (13 TP, 2 381 FP), <1 %; 68 relevantních uzlů. Citace sedí. |
| RQ6-040 | OK | „eight of nine DARPA datasets", ADP Kairos 0,01, Nodlink 0,96, Orthrus 1,00 (příklad), 9 nedostatků SC1–SC9. Sedí. |
| RQ6-041 | OK | SC5: „ORTHRUS on E3-THEIA yields ADP values ranging from 1.00 in the best case to below 0.1", 5 iterací. Sedí. |
| RQ6-042 | OK | SC3: „applying such thresholding to ORTHRUS significantly lowers precision, even reaching 0% on E3-CLEARSCOPE". Pozor: jde o práh z validační množiny (metoda SIGL/NODLINK) aplikovaný na ORTHRUS, to extrakce uvádí správně. |
| RQ6-043 | OK | Orthrus <1 %, Kairos <12 %, ostatní PIDS >23 %; z 5 systémů jsou „ostatní" tři. Sedí. |
| RQ6-045 | OK | „attacker can consistently evade detection (100% success rate)"; pět systémů StreamSpot, Unicorn, ProvDetector, Pagoda, FGA. Sedí. |
| RQ6-046 | OK | Tab. 2: false alarm 1,58 → 0,74 % (29 → 13/den), predikce 76,92 → 73,88 %. Sedí. |
| RQ6-050 | OK | README: 8 322 alertů (2 496 / 5 826), 241 typů, 3 podniky, 16 LLM, průměrná TPR 79,71 %, F1 70,92 %, FPR 44,13 %. Autoři sami neuvádějí způsob průměrování. Článek bez venue, V2 správně. |

## 3. Chybovost

| ukazatel | hodnota |
|---|---|
| ověřeno řádků | 26 |
| OK | 21 |
| DROBNÁ CHYBA | 5 (RQ6-001, 009, 021, 022, 034) |
| VĚCNÁ CHYBA | 0 |
| NEOVĚŘITELNÉ | 0 (podíl 0 %) |
| **věcná chybovost** | **0 / 26 = 0 %** (prahový limit protokolu 5 %) |
| drobná chybovost | 5 / 26 = 19 % (venue a upřesnění kontextu) |

Žádná hodnota ve vzorku nebyla vymyšlená ani zkreslená, žádná citace neexistující. Všech 26 URL funguje a tvrzení „V3" (plný text) platí.

## 4. Nutné opravy v extrakci

1. RQ6-001, RQ6-009, RQ6-034: pole `venue` / `recenzovano` upravit na „arXiv preprint". Zmínka o NeurIPS WS (001), workshopu (009) a KDD WS / VizSec (034) v PDF chybí, ověřit nebo smazat.
2. RQ6-009, pole `metoda` / `podminky`: baseline nedostával „jen text alertu", ale alert plus přehledový dotaz nad logy; 0 % přesnosti je u 3 ze 4 modelů převážně verdikt „uncertain", ne „benign". Přidat do poznámky.
3. RQ6-021: u hodnoty RF F1 92,17 % doplnit „převzato z [21], neměřeno autory".
4. RQ6-022: oddělit podmínky: 7B s flags 0,78 makro-F1 při N = 200; 3B few-shot s kalibrací F1(+) 0,68 při N = 1000; nekalibrovaný běh N = 2000 F1(+) 0,43.

## 5. Přesazené závěry (tabulka Závěry a text studie)

Zkontrolováno 7 závěrů: Z1, Z3, Z5, Z6, Z8, Z9, Z10 (a mimo to Z2, Z4, Z7 pouze podle řádků).

1. **Z9 (střední): „konzistentní napříč 4 nezávislými týmy".** Nezávislé jsou jen tři týmy (Bilot et al. RQ6-040/041/042 jsou jeden tým, dále Xiao RQ6-043 a Goyal RQ6-045). RQ6-033 (HOLMES) a RQ6-035 (KAIROS) jsou práce původních autorů, jejichž vlastní dodatečný práh či přeštítkování prezentují jako metodu, takže to není „nezávislé hodnocení". Doporučení: „3 nezávislé týmy + 2 samoohlášená omezení původních autorů" a jistotu ponechat jen, pokud se tvrzení omezí na to, co 040–043, 045 říkají (bez 033, 035 jako nezávislých důkazů). Navíc „precision až 0 %" platí jen pro jeden systém na jednom datasetu.
2. **Z1 (střední): „LLM, které dostane jen alert bez kontextu z logů ... a na tocích je na úrovni náhody".** (a) RQ6-009 baseline měl přehled logů, viz oprava 2. (b) RQ6-022 tvrzení částečně vyvrací: 7B model s příznaky dosahuje makro-F1 ~0,78; „na úrovni náhody" platí jen pro nenaváděný zero-shot (RQ6-021: Llama3-8B a GPT-4, jeden dataset). (c) Základ je jeden scénář a jeden dataset z malých modelů. Jistota „střední" je příliš vysoká, správně „nízká" a tvrzení rozdělit na dvě.
3. **Z8 (nízká): „Kontextové řazení podle kauzálního grafu snižuje FP o 60–98 % při plném TPR".** RQ6-044 (Louvain shlukování procesů, FPR 25 → 10 %) není kauzální graf a TPR 100 % u něj nikdo neuvádí; 60 % tedy není srovnatelná veličina s RQ6-031 (snížení objemu falešných alarmů při 100 % TPR) a RQ6-032 (odstranění falešných TPG). Rozsah 60–98 % míchá tři různé metriky (protokol §8 zakazuje). Hypotéza H-1 a H-4 z tohoto rozsahu vychází.
4. **Z5 (nízká): „FNR na 3–4 %" s důkazem RQ6-011.** Řádek RQ6-011 (CORTEX) uvádí FPR a actionable F1, ne FNR; tvrzení o FNR z něj neplyne. RQ6-007 je ablace na podmnožině a měří F1, ne FNR.
5. **Z3 (střední): „Prázdný výsledek vyhledávání vede agenty k zamítnutí útoku".** Zdroj píše „strongly associated" (korelační pozorování, jeden scénář, jeden model GPT-4.1, preprint), ne kauzální vliv. Slovo „vede" je kauzální, doporučuji „souvisí s". Jistota „střední" pro jedinou studii je hraniční, „nízká" odpovídá důkazu.
6. **Syntéza (věcná chyba textu, ne extrakce): „FNR ... medián přibližně 40 %".** Pět přístupů má FNR 40,4 / 51,1 / 51,6 / 54,2 / 70,2 %, medián je 51,6 %, 40,4 % je minimum. Opravit.
7. **Z6: „úspěšnost bez obrany 26,6–96 %".** Rozsah míchá průměr přes všechny útoky a obrany (26,6 %) s nejhorším případem sumarizace (96 %). U RQ6-025 čistý Qwen už „selhává" na 71 %, takže „100 %" nepopisuje plný efekt otrávení. Přesnost lze zlepšit formulací, jistota může zůstat.
8. **Z4 (nízká):** tvrzení o „reasoning modelech" stojí na RQ6-017 (CyberSOCEval, test s výběrem odpovědí, ne triáž), který není v mém vzorku; neověřeno.

## 6. Verdikt

**PŘIJATO S OPRAVAMI.**

Zdůvodnění: věcná chybovost extrakce je 0 % (0/26), neověřitelných řádků 0 %, tedy podmínka „≤ 5 %" je splněna a extrakci RQ6 není nutné procházet znovu. Žádný závěr nemá jistotu „vysoká", takže pravidlo o chybě u závěru s vysokou jistotou se neuplatní. Verdikt není prosté „PŘIJATO", protože bod 5 výše ukazuje přesazení u závěrů se střední jistotou (Z1, Z9, Z3), míchání nesrovnatelných metrik v Z8 a chybu v syntéze (medián FNR). Doporučuji opravit extrakci (bod 4) a text studie (bod 5) před použitím hypotéz H-1 až H-4.
