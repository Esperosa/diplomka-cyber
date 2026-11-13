# Nezávislá kontrola extrakce RQ3 (protokol §9)

Datum: 2026-10-31. Kontrolor neznal závěry studie předem; extrakce.csv ani studie.md nebyly měněny.

## 1. Vzorek a postup

- Celkem 57 řádků (56 × V3, 1 × V2). Ověřeno **48 řádků (84 %)**, požadavek byl ≥ 30 % a ≥ 20 řádků.
- (a) Povinná část: všechny řádky, o které se opírají závěry s jistotou „střední“ (v tabulce Závěry není žádná „vysoká“): 001, 002, 011, 015 (Z1); 006, 018–020, 022 (Z2); 009, 017, 021, 025 (Z3); 029–031, 036, 037, 039 (Z5); 040–042, 044, 052 (Z7); 027, 053 (Z10); 054 (Z13). Tedy i všechny řádky doporučené autorem studie.
- (b) Doplněk: protože zdroje Jung 2004, Schechter 2004, Jung 2008, Alsaleh, BotSniffer a BotProbe byly stejně staženy celé, ověřil jsem **všechny jejich řádky 001–027** (bez výběru). Z ostatních zdrojů, určených systematicky (každý druhý nezahrnutý řádek podle pořadí): 034, 035, 038, 043, 045, 046, 049, 056.
- Neověřeno (9 řádků): 028, 032, 033, 047, 048, 050, 051, 055, 057.
- Postup: všechny zdroje stažené znovu a čerstvě z `url_nebo_doi` (curl + `pdftotext -layout` do nového adresáře, žádné starší soubory z <pracovní adresář> nepoužity). Hodnota hledána v uvedeném umístění a porovnána včetně sloupce tabulky, jednotek, datasetu a metriky. Všechny URL fungovaly a vrátily plný text (tvrzení „V3“ platí pro všechny ověřené řádky). U 010 a 054 jsem navíc zkontroloval metadata (venue, recenzovanost).
- Omezení kontroly: ověřoval jsem hodnoty, umístění, kontext a metadata. Pole `limity_autoru` a `riziko_zkresleni` jsem kontroloval jen okrajově. Venue a rok NoDoze, Kim a Dán a Sudyana jsem proti zdroji neověřoval nad rámec titulní strany.

## 2. Tabulka kontrolovaných řádků

| id | výsledek | poznámka (opravená hodnota, umístění) |
|---|---|---|
| RQ3-001 | OK | Jung 2004 Tab.8: LBL 4,08 / 21,40 / 14,06 (TRW/Bro/Snort), sloupec N, přiřazení potvrzeno textem „4.1 … about 3 times lower than Snort, 5 times lower than Bro“. |
| RQ3-002 | OK | Tab.8 ICSI: 4,06 / 36,91 / 6,00. Pozor: u ICSI je TRW jen 1,5× rychlejší než Snort (viz přesazení Z1). |
| RQ3-003 | OK | Tab.8 LBL: efficiency 0,963/1,000/0,615, effectiveness 0,960/0,150/0,126. |
| RQ3-004 | OK | Tab.8 ICSI: 1,000/1,000/1,000 a 0,992/0,029/0,029. V extrakci stojí „TRW 1,000 / 0,992; Bro 1,000 / 0,029“, souhlasí. |
| RQ3-005 | OK | „for LBL, 38.5% of the alarms by Snort were due to false positives“, text pod Tab.8 (v extrakci „Sec.5.2“, správně). |
| RQ3-006 | DROBNÁ | 33 FP potvrzeno, 29 crawlerů/proxy potvrzeno. Zbývající 4: 3 hosty s IDENT odpověďmi na odchozí spojení a 1 SMTP klient. Extrakce uvádí jen „1 SMTP klient“ a vynechává 3 IDENT hosty. |
| RQ3-007 | OK | „nearly 14,000 scanners … vastly more than the 122 detected by Bro“ (Sec.6 How to Respond). |
| RQ3-008 | OK | Doslovně ověřeno („For TRW, this is not so difficult.“, „camouflage connections … drive the random walk away“). |
| RQ3-009 | OK | Sec.5.1, oscilace nahoru/dolů nikdy nedosáhne prahu. |
| RQ3-010 | DROBNÁ | Hodnoty 34 / 11 / 0,324 / 0,917 a 10 / 5 / 0,500 / 0,417 sedí. Umístění špatně: jde o **Tab.5** (tělo tabulky předchází popisku „Table 5. Comparison of rate limiting by CBCRL vs. virus throttle“), ne o Tab.4 (Tab.4 je „Composite results“ s 7 HTTP + 5 e-mailovými červy). |
| RQ3-011 | OK | „10 first-contact … as many as 526“, Sec.5. |
| RQ3-012 | OK | „more than 10% of the hosts in both traces were rate limited by Twycross and Williamson's algorithm“. |
| RQ3-013 | OK | Sec.6 Limitations, „not likely to detect a topological worm“. |
| RQ3-014 | OK (poznámka) | „0.07 … 0.57 per hour“ doslovně (Sec.6.3 Post-detection response). Hodnota je přenesena správně. Vnitřně však nesedí s Tab.3 (3 FP / 137 h = 0,02; 3 FP / 10 h = 0,3). Zdroj to nevysvětluje, nutno uvést jako varování. |
| RQ3-015 | OK | Tab.3: Lab-II TRW 3 FN, 21 FP, N 18,5; RBS+TRW 0 FN, 3 FP, 6,9. ISP TRW 0 FN, 7 FP, 10,0; RBS+TRW 1 FN, 3 FP, 5,0. Sloupce správné. |
| RQ3-016 | OK | „Had we run RBS and TRW in parallel … 33 false alarms altogether“, Sec.6.3. |
| RQ3-017 | OK | Abstrakt a Sec.1/4.4: „number of observations is not bounded by a deterministic …“, p0 = 0,1, p1 = 0,15, α = β = 0,1; „much smaller number of connection attempts“. |
| RQ3-018 | OK | Tab.5.3: 9 734 / 5 071 / 2 383 / 47 %. Pozn.: „FP“ je vůči aproximované ground truth (T RW aGT FP), ne vůči úplné pravdě. Zdroj sám říká, že zachytí jen podmnožinu FP. |
| RQ3-019 | DROBNÁ | 19–50 % sedí (Tab.5.3, 10 konfigurací + závěr 5.5). Ale Tab.5.3 je jen datová sada „Class C“; v „Class B“ (Sec.5.4.2) je FD rate TRW vůči stejnému kritériu mnohem nižší (text: „less than 1 %“ a nejvýše 24 % v exp. 8). Rozsah 19–50 % tedy neplatí pro „dva datasety“, jak extrakce říká. |
| RQ3-020 | DROBNÁ | „29 % a 77 %“ doslova v 5.5 i v abstraktu kapitoly. Dvojice 77 % a 29 % se v textu nepřiřazuje jednoznačně k datasetům (Sec.5.4.1 říká 77 % pro STRW2 u Class C), 94 % u Class B je v rozporu s 29 %. STRW1 měl průměrné FD jen 34 %. Navíc STRW hlásí o 43 % méně skenerů než TRW (Sec.5.4.1), takže „bez ztráty detekce“ je tvrzení autora, ne měření. |
| RQ3-021 | DROBNÁ | Hodnota doslovně sedí. Umístění je Sec.5.4.1 (Class C), ne 5.3. Platí pro první dataset, ne pro „dva datasety“. |
| RQ3-022 | DROBNÁ | „on average 94% of TRW false positives in all experiments are eliminated“ je v Sec.5.4.2 (Class B), ne 5.4. Hodnota správná. |
| RQ3-023 | OK | Sec.4.2.1: FPR 0,0016 (11 z 6 848), α = 0,005, β = 0,01. |
| RQ3-024 | OK (poznámka) | „100 % detekce“ doslovně (4.2.2). Zdroj je vnitřně rozporný: v Tab.2 je B-HTTP-II „Yes“, v Tab.4 „No“. Extrakce zachytila selhání B-HTTP-II. |
| RQ3-025 | OK | Tab.II: 75,3 % po 2 kolech, 9,3 % po 3, 15,4 % nerozhodnuto, 97 uživatelů (84 meebo + 13 IRC), 0 FP. Záhlaví tabulky je v převodu zlomené, ale hodnoty potvrzuje text. |
| RQ3-026 | OK | Tab.I: 2 až 4 kola; „100% detection rate in recognizing IRC-based botnet C&Cs“. |
| RQ3-027 | OK | „might be deemed controversial because they alter network flows to human users“, „more formal study of cost-benefit analysis and risk assessment is needed“. |
| RQ3-029 | DROBNÁ | Hodnoty 0,868 (k=200) a 0,737 (k=1000) sedí (Tab.2 řádek 12). Chybí podmínka: jde o **hodnoty ze 12. a poslední týdne**; zdroj to uvádí jen v poznámce pod čarou 1. Hodnoty se mezi týdny výrazně liší (k=200: 1. týden obě metody 0,133; 8. týden nesupervizovaná 0,333 vs AI² 0,815), takže jde o nejlepší, ne typický týden. |
| RQ3-030 | OK | Abstrakt: „average of 3.41×“ a „fivefold“ false positives. |
| RQ3-031 | OK | Sec.8.2: 42 vs 143 vs 211 z 318, k = 100. |
| RQ3-034 | OK | Ziai: „F1 goes from 0.90 to 0.98 with just 10 queries“. |
| RQ3-035 | OK | Ziai Sec.4.2: Nmap < 0,01 %, „failure of uncertainty sampling has been documented“. |
| RQ3-036 | OK | Chen, popisek Tab.3: 8× nižší cena štítků, 50 vs 400 vzorků/měsíc, F1 > 89 % (jen APIGraph). |
| RQ3-037 | OK | Abstrakt: FNR 14 → 9 %, FPR 0,86 → 0,48 %. |
| RQ3-038 | OK | 38 % FNR za 7 let (popisek Obr.1 a úvod), F1 0,99 → 0,76 po 6 měsících. |
| RQ3-039 | DROBNÁ | „up to 76% less labelled data“ není v abstraktu (ten říká „requires as little of 24 % of the training data“), ale v přehledu příspěvků v úvodu. Hodnota je odvozená a konzistentní. |
| RQ3-040 | DROBNÁ | 82,5 % / 0 % / 108 sedí (Tab.5, Sec.4.4). Chybí: 108 je počet **po bias-korekci** (Tab.4); původně 32 škodlivých alertů v testu. „0 ztraceno“ z 32 nese horní hranici 95 % CI zhruba 9–11 %. Extrakce tvrdí „108 z 108“ jako počet případů. |
| RQ3-041 | DROBNÁ | 84 % / 5,7 % / 58 z 1 003 sedí (Tab.5). 1 003 je po korekci; původně 88 škodlivých. |
| RQ3-042 | DROBNÁ | 5 024,2 s a 1 780,02 s (Tab.6), 317 z 491 sedí. Chybí: použitá varianta je **clustering only** (viz Obr.3 a Sec.4.5; autoři píšou, že na ATLASv2 nelze aplikovat scoring model), tedy jiná komponenta než v řádcích 040 a 041. |
| RQ3-043 | DROBNÁ | AUC 0,94 / 0,90 / 0,60 sedí, ale 0,94 je „Carbon Filter (Clustering Only)“ (popisek Obr.3), ne celý systém. |
| RQ3-044 | OK | Abstrakt: 61 % za šest měsíců, FNR 1,36 %. |
| RQ3-045 | OK | Sec.V: 34 % při FNR 1,5 %, 728 834 uzavřených, ~74 %. |
| RQ3-046 | OK | Abstrakt DeepCASE: 86,72 %, 90,53 %, < 0,001 %. |
| RQ3-049 | OK | Kruegel Tab.1: 6 659 alertů, 24 relevantních, 99,64 % → 0 %. |
| RQ3-052 | OK | Abstrakt: až 24× (≈ 1,38 řádu), 95 % / 100 % u neviděných útoků. |
| RQ3-053 | OK | Samanis 5.5.2: PLC po Nmap s určitými příznaky, „full power cycle“; 5.5.3: druhé zařízení při technice více nástrojů. |
| RQ3-054 | VĚCNÁ (metadata) | Hodnoty sedí (119 záznamů, 87 jádrových, 65 Tier 2 + 13 Tier 3 = 78). **Recenzovanost špatně**: titulní strana říká „author's preprint of a manuscript **submitted** to ACM Computing Surveys (May 2026). The version of record will appear … once published“. Pole `recenzovano` = „ano (nepotvrzeno)“ má být „ne (preprint odeslaný do časopisu)“, venue „ACM Comput. Surv.“ je jen cíl, ne publikace. |
| RQ3-056 | OK | Abstrakt: MSE až o 50 %, výpočet o 85 %. |

## 3. Chybovost

- Ověřeno: 48 řádků. OK: 35 (z toho 3 s poznámkou). Drobná chyba: 12. **Věcná chyba: 1** (054, jen metadata, žádná číselná hodnota). Neověřitelné: 0.
- **Věcná chybovost = 1 / 48 = 2,1 %.** Podíl neověřitelných = 0 %.
- Žádná vymyšlená ani neexistující citace; všech 15 stažených zdrojů existuje a hodnoty z nich byly (až na drobnosti níže) přenesené věrně. Číselná přesnost extrakce je vysoká.
- Slabina nejsou přepisy čísel, ale **chybějící podmínky u čísel** (12 drobných chyb): bias-korekce, varianta systému, týden měření, dataset, na který rozsah platí.

## 4. Nutné opravy extrakce a studie

1. **054**: `recenzovano` = „ne (preprint odeslaný do ACM CSUR, květen 2026)“; v studie.md (§8, tabulka) nepsat „ACM Comput. Surv.“ jako venue.
2. **040, 041**: do `podminky`/`poznamka` doplnit: čísla 108 a 1 003 jsou po bias-korekci (Tab.4), původní testovací počty škodlivých alertů jsou 32 (TAU) a 88 (MDR). „0 % ztraceno“ je z 32 případů (95 % CI horní hranice kolem 10 %). Přepsat „108 z 108“.
3. **042, 043**: doplnit, že jde o variantu „clustering only“ (potlačení 317 z 491 alertů, AUC 0,94), ne o scoring model z 040/041. V ATLASv2 je jen 50 škodlivých alertů z 491.
4. **029**: doplnit „hodnoty z 12. (posledního) týdne, nikoli průměr za období“ (Tab.2, poznámka pod čarou 1). Totéž v abstraktu studie (bod 4) a v Z5.
5. **019, 021**: omezit na dataset Class C (Tab.5.3 a Sec.5.4.1), ne „dva datasety“. U 019 doplnit, že v Class B je FD rate TRW vůči stejnému kritériu nižší (< 1 %, max. 24 % v exp. 8).
6. **020, 022**: opravit umístění (022: Sec.5.4.2; 021: Sec.5.4.1). U 020 přiřadit 77 % k Class C (STRW2) a poznamenat, že STRW hlásí o 43 % méně skenerů a 29 % vs 94 % u Class B není vysvětleno.
7. **010**: umístění Tab.5, ne Tab.4.
8. **039**: citace z přehledu příspěvků v úvodu, ne z abstraktu (abstrakt: „as little of 24 %“).
9. **006**: doplnit 3 hosty s IDENT odpověďmi.
10. **014**: poznamenat, že 0,07 a 0,57 FP/h nelze odvodit z Tab.3 (3 FP / 137 h ≈ 0,02; 3 FP / 10 h = 0,3); jde o údaj autorů bez vysvětlení.

## 5. Kontrola 5 závěrů (Z1, Z4, Z7, Z9, Z12)

- **Z1 (střední): přesazení.** „Rozhoduje po ~4 až 10 pozorováních“ vychází z hodnoty N|H1 pro TRW ze dvou vzorků z roku 2003. Stejné TRW měl Jung 2008 (řádek 015) na 18,5 (Lab-II) a 10,0 (ISP) prvních spojení, což do rozsahu „4–10“ nezapadá. Rozsah smíchává rozdílné jednotky (distinct IP, první spojení). „Výrazně dříve než Snort“: u ICSI 4,06 vs 6,00. Přesnější formulace: TRW 4 až 18,5, rychlejší než Bro (21–37), vůči Snortu 1,5× až 3×.
- **Z4 (nízká): drobné přesazení.** „Cíl α a β se plnil“: u BotSniffer ano (FPR 0,0016 < 0,005), ale u 014 (0,07–0,57 FP/h) žádné α srovnávané není. Alsaleh (018, 019) naopak naměřil 19–50 % FD u TRW; Z4 tento protipříklad neuvádí.
- **Z7 (střední pro směr): přesazení.** Mísí dvě různé komponenty Carbon Filter (úspora času −65 % je z clustering-only varianty v ATLASv2, 491 alertů; recall 0–5,7 % je ze scoring modelu na TAU/MDR). Formulace „−65 % ve dvou datasetových číslech“ je zavádějící: jde o jeden dataset (ATLASv2), dvě časová čísla. Spodní hranice ztráty recallu 0 % pochází z 32 případů. Ztrátu recallu clusteringu v ATLASv2 autoři nepublikují. „Střední“ pro směr je únosné, velikost má být „nízká“ a spojení obou čísel zakázat.
- **Z9 (nízká): v pořádku.** 049 podporuje 99,64 % → 0 % v jedné testbed, jistota nízká odpovídá. Odkaz na 020 je nepřímý (STRW s mapou služeb na reálném provozu), ne ověření expozice aktivním skenem.
- **Z12 (nízká): přesazení u důkazu.** Z důkazů 056, 057 podporuje jen 056 (Kim a Dán: MSE až −50 %, pozor „up to“). 057 (Hammar a Stadler, prahové strategie optimálního zastavování, čísla jen v grafech) o entropii belief ani MSE nic nemá. Z12 má mít jediný řádek důkazu (056).

Dále z tabulky Závěry: Z2 (střední) se opírá o „bez ztráty detekce“, což je tvrzení autora disertace, ne měření (viz 020), a o rozsah 19–50 %, který platí jen pro jeden dataset (viz 019). Doporučuji snížit jistotu Z2 na „nízká až střední“ nebo formulaci upravit.

## 6. Seznam přesazených závěrů

1. Z7: spojení dvou různých komponent a odvozené „−65 %“ z jednoho datasetu; velikost úspory a ztráty recallu zůstat „nízká“.
2. Z1: rozsah „4–10“ ignoruje Jung 2008 (TRW samotné 10–18,5).
3. Z12: důkaz 057 nepodporuje tvrzení.
4. Z2: „bez ztráty detekce“ a „dva datasety“ pro 19–50 %.
5. Z5 / abstrakt bod 4: 0,868 vs 0,737 jsou hodnoty jednoho týdne (12.), nikoli průměr.

## 7. Verdikt

**PŘIJATO S OPRAVAMI.** Věcná chybovost 2,1 % (1 / 48, jen metadata) je pod prahem 5 % a žádný závěr s vysokou jistotou neexistuje. Zdroje existují, čísla jsou věrně přenesena. Opravy 1 až 10 výše a přeformulování Z1, Z2, Z7, Z12 jsou však nutné, protože několik čísel je vytrženo z podmínek, které mění jejich váha (bias-korekce, varianta systému, jeden týden, jeden dataset).
