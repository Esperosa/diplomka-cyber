# Revize RQ6 po nezávislé kontrole (audit trail)

Datum revize: 2026-10-31. Vstup: `kontrola-RQ6.md` (verdikt PŘIJATO S OPRAVAMI, věcná chyba 0/26, drobné chyby 5/26). Upraveno: `extrakce.csv`, `studie.md`, `neovereno.md` (doplněn oddíl o venue). Nic mimo adresář RQ6 se neměnilo, nic nebylo commitováno. Původní hodnoty jsou uvedeny zde, v hlavním textu zůstaly jen nové.

Ověření: znovu jsem stáhl plné texty z arXiv (`curl`, `pdftotext`): 2604.25846 (RQ6-009), 2408.04342 (RQ6-021), 2510.17883 (RQ6-022), 2610.10608 (RQ6-001, FNR), 2107.02783 (RQ6-034), 2605.24421 (RQ6-023), 2511.02600 (RQ6-025), 2509.20166 (RQ6-017). Tab. II u RQ6-009 jsem otevřel jako obrázek stránky 8, protože text z PDF je pomíchaný.

## 1. Opravy extrakce

| id | co bylo špatně (původně) | nová hodnota | jak ověřeno |
|---|---|---|---|
| RQ6-001 | venue „arXiv (zkracena verze NeurIPS 2026 WS Agents in the Wild)“, recenzováno „WS verze ano“ | „arXiv preprint (venue v PDF neuvedeno)“, recenzováno „ne (preprint)“. Tvrzení přesunuto do `neovereno.md` | `grep -i "workshop\|neurips"` v textu 2610.10608: jediný nález je odkaz v literatuře (security experimentation and test workshop 2024). Kontrola potvrzena. |
| RQ6-009 venue | „arXiv (workshop)“ | „arXiv preprint (venue v PDF neuvedeno)“ | v textu 2604.25846 zmínka o workshopu chybí. Potvrzeno. |
| RQ6-009 metoda | baseline = „verdikt LLM jen z textu alertu a souhrnu logu“ | baseline = text alertu plus přehledový dotaz (overview query) nad logy, bez cíleného šetření | Oddíl IV.A: „The baseline configuration presents the Verdict LLM with the same initial information as the workflow (overview query + alert text).“ Potvrzeno. |
| RQ6-009 hodnota, poznámka | „0 % u všech 4 modelů“ bez rozdělení, poznámka „Gemma vše označila benigní“ | 0 % doplněno rozdělením verdiktů z Tab. II (škodlivá podmnožina): Claude 3 Haiku 1 % benigní / 99 % nejisté, Gemma 3:27B 100 % benigní, GPT-5-mini 100 % nejisté, Qwen3:30B 35 % benigní / 65 % nejisté | Tab. II přečtena z obrázku. **Kontrolor se zde částečně mýlil:** tvrdí „u Qwen3 100 %“, tabulka ale uvádí 35 % benigní a 65 % nejisté (100 % nejisté má GPT-5-mini). Jeho podstatné zjištění (většina verdiktů „nejisté“ u 3 ze 4 modelů) platí. Navíc text oddílu IV.A doslova říká „all models incorrectly classifying malicious runs as benign“, což odporuje vlastní Tab. II. Do extrakce zapsáno, že platí tabulka. |
| RQ6-021 | „RF vážené F1 92,17 %“ vedeno jako součást srovnání | doplněno „PŘEVZATO z cizí práce [21] Layeghy a Portmann, NEMĚŘENO autory, není součástí vlastního srovnání“ | Úvod: „a Random Forest and an LSTM ... achieve a weighted F1-score of 92.17% and 92.82% [21]“, [21] = S. Layeghy and M. Portmann, Explainable Cross-domain Evaluation. Potvrzeno. |
| RQ6-022 | „7B s příznaky ~0,78, 3B s few-shot ~0,68“, podmínky „200 toků“ | tři oddělené podmínky: 7B makro-F1 ~0,78 při N = 200 (acc ~0,79, F1(+) ~0,80), 3B few-shot s kalibrací F1(+) ~0,68 při N = 1000 (acc ~0,70), nekalibrovaný běh N = 2000 acc 0,50 a F1(+) 0,43 (po kalibraci F1(+) 0,69, recall 1,00, precision 0,53) | Shrnutí závěrů a abstrakt v 2510.17883 (N = 200: 7B; N = 1000: 3B; N = 2000: 0,43). Potvrzeno. |
| RQ6-034 | venue „KDD WS / VizSec“, recenzováno „ano (workshop)“ | „arXiv preprint (venue v PDF neuvedeno)“, recenzováno „ne (preprint)“. Tvrzení v `neovereno.md` | v 2107.02783 VizSec jen v seznamu literatury a v návrzích pro komunitu VizSec, KDD není. Potvrzeno. |
| RQ6-003 poznámka | bez upozornění na asociaci | doplněno „asociace, ne prokázaný kauzální vliv, jeden scénář a jeden model“ | kontrola i autoři („associated“) |
| RQ6-023 poznámka | rozsah 26,6 % až 96 % bez upřesnění | doplněno: 26,6 % je průměr přes strategie při naivním promptu (přímé přepisy S1 0 %), 96 % je nejhorší případ (S3 sumarizace bez obrany) | Abstrakt 2605.24421: „average injection success falls from 26.6% under naive prompting to 11.8% under our strongest defense“; „context manipulation reaches 96% injection success without defenses and 38% even with constrained output“; „all S1 classification attacks achieve 0% suppression“. **Pozn.:** extrakce říkala „průměr 26,6 % (naivní) → 11,8 % (omezené)“, abstrakt říká „nejsilnější obrana“, ne omezený výstup. V textu studie jsem formulaci opravil na „nejsilnější obrana“. |
| RQ6-025 poznámka | bez nuance | doplněno: čistý Qwen už 71 %, přírůstek jen 71 → 100 % | text 2511.02600: „cleanly fine-tuned Qwen model already had a 71% misclassification rate“ |
| RQ6-042 poznámka | bez upřesnění | doplněno: práh z validace (metoda SIGL/NODLINK) aplikovaný na ORTHRUS, jeden systém a jeden dataset, Bilot je podle řádku RQ6-038 spoluautor ORTHRUS | první část z kontroly. Spoluautorství Bilota jsem převzal z pole `citace` řádku RQ6-038 (Jiang, Bilot et al.), PDF ORTHRUS jsem znovu neotevíral. |
| RQ6-044 pouzitelnost | bez upozornění | doplněno: není kauzální graf, TPR neuveden | kontrola, text studie |
| RQ6-050 poznamka | „jen prumery“ | doplněno: průměrování pres 16 LLM neuvedeno, článek nedohledán | README (podle kontroly, WebFetch jsem neopakoval) |

Počet oprav v extrakci: 13 položek v 11 řádcích (RQ6-001, 003, 009 ×3 pole, 021, 022, 023, 025, 034, 042, 044, 050). Z toho 4 povinné opravy z bodu 4 kontroly + 3 venue + 6 doplňujících nuancí.

Neověřitelné řádky: kontrola nenašla žádné (0/26). Všechny řádky zůstávají v extrakci. Z `extrakce.csv` jsem do `neovereno.md` přesunul jen tvrzení o venue (RQ6-001, 009, 034). RQ6-050 (V2) zůstává, nese jen Z2 s jistotou nízká, v Z2 je to poznamenáno. Žádný závěr s vysokou jistotou není postaven na řádku V2.

## 2. Opravy textu studie a změny jistoty

| část | původní znění | nové znění | ověření |
|---|---|---|---|
| Syntéza, medián FNR | „medián přibližně 40 %“ | medián 51,6 % (40,4 / 51,1 / 51,6 / 54,2 / 70,2 %) | Tabulka v 2610.10608 obsahuje 40,4 (Direct), 51,6 (ReAct), 54,2, 51,1, 70,2. Seřazeno: 40,4; 51,1; 51,6; 54,2; 70,2, medián 51,6. Kontrola potvrzena. U „max 100 %“ doplněno, že „nejisté“ se počítá jako nezachycení. |
| Z1 | střední: „LLM, které dostane jen alert bez kontextu z logů, nerozpozná útoky (0 %) a na tocích je na úrovni náhody“ | rozděleno: **Z1a** (RQ6-009): střední → **nízká**, formulace „alert plus přehledový dotaz, 0 % verdiktu malicious, převážně nejisté“. **Z1b** (RQ6-021, 022): střední → **nízká**, nenaváděný zero-shot kolem náhody, ale 7B s příznaky makro-F1 ~0,78 | RQ6-009 baseline měl přehled logů (viz výše). RQ6-022 tvrzení „na úrovni náhody“ pro naváděný model vyvrací. |
| Z3 | střední: „vede agenty k zamítnutí útoku“ | **nízká**: „souvisí se zamítnutím útoku“, doplněno „asociace, ne kauzální vliv“ | autoři píšou „strongly associated“; jedna studie, jeden scénář a model |
| Z4 | nízká: „Sebe-revize ... a víc výpočtu (vzorkování, reasoning modely) kvalitu nezlepší“ | nízká (beze změny), reformulováno: sebe-revize zhoršila, vzorkování nezlepšilo, reasoning modely jen nepřímý údaj z CyberSOCEval (ne triáž) | Kontrolor RQ6-017 neověřil. Já jsem v 2509.20166 ověřil větu: „Surprisingly, we did not observe a large performance boost from reasoning models“ a čísla 23–34 % a 0,63 % náhoda. Tvrzení sedí, ale není o triáži. |
| Z5 | nízká: „snižuje FNR na 3–4 %“, důkazy 006, 007, 010, 011 | nízká (beze změny), FNR jen z RQ6-006 (3,1 %) a RQ6-010 (max 4 %). RQ6-007 (F1) a RQ6-011 (FPR, actionable F1) označeny jako podpůrné jiné metriky | z extrakce: 011 uvádí FPR a F1, 007 F1; FNR neuvádí. Potvrzeno. |
| Z6 | střední/nízká: „úspěšnost bez obrany 26,6–96 %, se zbytkem 8,4–11,8 %“ | jistota beze změny (střední pro existenci rizika, nízká pro velikost). Rozsah rozdělen: průměr přes strategie 26,6 % → 11,8 % (RQ6-023), nejhorší případ 96 % / 38 % (RQ6-023), LogInject až 88,2 % → 8,4 % (RQ6-024), RQ6-025 s poznámkou o 71 % u čistého Qwen | abstrakty 2605.24421 a 2511.02600 |
| Z8 | nízká: „snižuje FP o 60–98 % při plném TPR“ | rozděleno: **Z8a** (RQ6-031, 032; kauzální graf, −84 % objemu falešných alarmů a −97,8 % falešných TPG, 100 % TPR podle autorů) nízká. **Z8b** (RQ6-044; Louvain, FPR 25 → 10 %, TPR neuveden) nízká. Rozsah 60–98 % zrušen | Kontrola: RQ6-044 není kauzální graf, 60 % je relativní pokles FPR, ne snížení objemu při 100 % TPR (§8 protokolu zakazuje míchání). |
| Z9 | střední: „konzistentní napříč 4 nezávislými týmy“, důkazy 040, 041, 042, 043, 045, 033, 035 | **střední** (zachováno), ale jen 3 nezávislé týmy: Bilot et al. (040, 041, 042), Xiao (043), Goyal (045). RQ6-033 a RQ6-035 přesunuty do nového **Z9b** („samoohlášená omezení původních autorů“, střední jen pro existenci tohoto popisu), nepočítají se jako nezávislé hodnocení. Doplněno, že precision 0 % je jeden systém na jednom datasetu a že Bilot je spoluautor ORTHRUS | kontrola, řádky 040–045 |
| Abstrakt | bod 1 „LLM bez kontextu ... 0 %“, bod 3 „nejsilněji doložený mechanismus“, bod 5 „26,6 % / 83,4 % / 96 %“, bod 6 „nezávislá hodnocení“ | přepsáno podle Z1a, Z1b, Z3, Z6 a Z9 (3 týmy, mimikry jako samostatné tvrzení) | viz výše |
| Překlad do praxe | „neprovedené nebo prázdné ověření se snadno změní na zamítnutí útoku (Z3)“; odkazy Z1 | „souvisí se zamítnutím útoku (asociace, Z3)“, odkazy Z1a, Z1b, Z8b | |
| H-1 | „pokles o 60–98 % (rozsah ze Z8)“ | rozsah odstraněn, odhad označen jako pracovní (aspoň 30 %, bez horního odhadu, literatura benigní vysvětlení neměří). Kritérium zamítnutí beze změny | rozsah vycházel z Z8, které bylo opraveno |
| H-3 | „Očekávaný efekt podle Z3“ | „vychází z asociace ve Z3, bez prokázané kauzality“ | Z3 sníženo |
| H-4 | „−30 až −84 % FP“ | zachováno, ale upřesněno: 30 % je pracovní hranice autora, 84 % je NoDoze (Z8a, snížení objemu, dodatečný práh). 60 % z Louvain se v H-4 nepoužívá | Z8 rozděleno |
| H-5 | „část efektů zmizí (ADP 1,0 → < 0,1, práh shodil precision na 0 %)“ | „může zmizet“, s upřesněním, že 0 % je jeden systém a jeden dataset | Z9 zúženo |
| H-6 | „26,6–96 % bez obrany a 8,4–11,8 % s obranou“ | rozsahy rozepsány podle studií a podmínek | Z6 |
| Metodika | „Nezávislá kontrola zatím neproběhla“ | doplněn odstavec o kontrole (datum, 26/51, 0 % věcná, 19 % drobná, verdikt, změny) a upraven odstavec Hrozby validity | |

Změny jistoty: Z1 (střední) → Z1a nízká, Z1b nízká. Z3 střední → nízká. Z8 nízká → Z8a nízká, Z8b nízká (bez změny úrovně, změna obsahu). Z9 střední → střední (zúženo na 3 týmy), nové Z9b střední (jen existence popisu). Z4, Z5, Z6 beze změny úrovně, upraven obsah.

Počet oprav textu studie: 22 položek (medián FNR 1, Z-řádky 8 včetně rozdělení, abstrakt 3 body, praxe 3, hypotézy 5, metodika a hrozby 2).

## 3. Co zůstává nevyřešené

- 25 z 51 řádků nikdo nezávislý nezkontroloval (jen autor extrakce).
- Venue u RQ6-001, 009, 034 nelze potvrdit (publikační stav může být jiný, než ukazuje PDF).
- RQ6-050 (SecAlertBench) je V2 (jen README, článek nedohledán), způsob průměrování přes 16 LLM neznámý. Nové čtení jsem neprováděl a spoléhám na kontrolu.
- Spoluautorství Bilota u ORTHRUS je převzato z řádku RQ6-038, ne z PDF.
- U RQ6-009 text oddílu IV.A a Tab. II si odporují, rozhodl jsem podle tabulky (u autorů nelze rozhodnout).
- Hypotézy H-2, H-5 a zbytek H-1, H-4 stojí na extrapolaci z hostových logů na toky (to studie uvádí). H-1 nemá žádný literární odhad velikosti efektu.
- Z9: Xiao (RQ6-043) je preprint z jednoho hostu, FPR > 23 % nemá druhé potvrzení.
