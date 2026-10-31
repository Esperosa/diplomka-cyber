# Revize RQ5 po druhé nezávislé kontrole (v1.1 → v1.2)

Datum: 2026-11-01. Podklad: `kontrola-RQ5-v2.md` (verdikt PŘIJATO S OPRAVAMI, věcná chybovost 5 / 59 = 8,5 %, 16 drobných chyb). Revidovány byly `extrakce.csv` a `studie.md`. `neovereno.md` se neměnil: kontrola nenašla žádný neověřitelný řádek (0 / 59) a řádky 048, 062 a 063 zůstávají V2 s již snížením závěrů z první revize. Nic nebylo commitnuto ani pushnuto, soaky nebyly zasaženy.

**Tato revize není nezávislá.** Píše ji stejná linie autor-revizor, která extrakci a první revizi psala. Ověření je moje vlastní čtení zdrojů, ne vnější kontrola. Opravené řádky tedy nikdo jiný znovu neprověřil.

## 1. Postup

- Zdroje jsem 2026-11-01 stáhl znovu (curl, jen veřejné URL, žádné osobní údaje) do nového adresáře `F:\claude-tmp\rq5v2rev\` a převedl přes `pdftotext -layout`. Tabulky, kde text přeházel sloupce (NetDiffusion Tab. 4, Majorczyk slajd 21), jsem ověřil obrazově (`pdftoppm` a prohlédnutí PNG). Venue a DOI jsem ověřil přes Crossref API.
- Hodnotu z kontroly jsem nepřebíral, každou jsem našel ve zdroji. Kde jsem zdroj neotevřel nebo jsem ověřil jen část, je to uvedeno ve sloupci „ověření“.
- Mimo adresář RQ5 jsem nic nezměnil. Kód soaku jsem nečetl znovu; stav commitu `a293d2b` jsem ověřil jen čtením `git log` (čas 2026-10-31 23:40:07 +0100).

## 2. Opravy v extrakci (původní hodnota → nová hodnota → ověření)

V = věcná chyba podle kontroly, D = drobná.

| id | typ | původní hodnota | nová hodnota | ověření |
|---|---|---|---|---|
| RQ5-041 | V | podmínky „n = 12“; poznámka „90 % při n = 12 není celé číslo ..., vnitřní nekonzistence zdroje“ | podmínky „n = 10 odpovídajících (2 z 12 respondentů otázku vynechali, App. B.3); 90 % = 9/10“; poznámka jen „Malý vzorek (n = 10).“ | Doslova ze zdroje (arXiv 2305.00550, App. B.3): „two respondents skipped the "Stat. Sign." question in P3.“ Tab. 3: „Stat. Sign. 0% 10% 90%“. Kontrolor má pravdu, nekonzistence zdroje neexistuje. |
| RQ5-053 | V | venue „arXiv preprint“, recenzovano „ne“, rok 2026 | venue „NDSS 2027 (DOI 10.14722/ndss.2027.230448; čten arXiv v4, 12. 10. 2026)“, recenzovano „ano“, rok 2027 | První strana arXiv v4 (12. 10. 2026): „Network and Distributed System Security (NDSS) Symposium 2027 ... https://dx.doi.org/10.14722/ndss.2027.230448“. Rok jsem změnil na rok sympozia; rozhodnutí je moje, kontrola rok neuvádí. Hodnoty řádku jsem znovu nekontroloval, kontrola je potvrdila a nebyly předmětem chyby. |
| RQ5-047 | V | podmínky „s post-gen. heuristikou“; umístění „řádek NetDiffusion (Used)“ | podmínky „bez post-gen. heuristiky (Not Used)“, s heuristikou (Used) 0,676 a 0,222 (pokles 32,4 a 75,6 p. b.); umístění „Tab. 4 (s. 15), Synthetic/Real, NetDiffusion, Not Used ...“; venue dle 046 | Obraz Tab. 4 na s. 15: Synthetic/Real, NetDiffusion, **Not Used 0.738 (DT) / 0.262 (DT)**, **Used 0.676 (DT) / 0.222 (DT)**; Netflow (NetShare) 0.396 (RF) / 0.140 (SVM); Real/Real 1.00 (SVM) / 0.978 (SVM). Text z `pdftotext` pořadí Not Used/Used u této tabulky zaměnil, proto původní chyba. Poznámka „26–72 p. b.“ platí dál (1 − 0,738 = 26,2; 0,978 − 0,262 = 71,6) a platí i pro Used (32,4; 75,6). |
| RQ5-052 | V | poznámka „Benigní uživatelé (falešné alerty) dominují výsledku víc než útočník“ | „Uživatelé snížili výnosy všech agentů, hlavním faktorem však byla politika útočníka (ANOVA, Sekce V); proti Exploratory nebyl vliv uživatelů vždy významný (Heuristic, Vejde w/ Noise).“ | Zdroj (arXiv 2609.16541): „The choice of Lore's policy, being either "Guided" or "Exploratory" was the most significant variable affecting the returns of all agents. ... The user agents were significant for most defender-attacker-policy combinations, though not for the combinations ("Heuristic", "Exploratory") and ("Vejde w/ Noise", "Exploratory").“ Číslo oddílu: text je v Sekci V (před Sekcí VI Discussion); „V-C“ z kontroly jsem číselně neověřoval. |
| RQ5-023 | V | poznámka „Hodnota 0,23 v tabulce patří detektoru Flash (klient 051, štítky Flash), ne GAE.“; metoda „GAE detektor, 3 sady štítků“ | poznámka „0,23 patří detektoru Flash u klienta 201 se štítky Flash; Flash u klienta 051 se štítky Flash má 0,24“; metoda „GAE se 2 sadami štítků (Nikulshin & Tahli, vlastní); Flash se 3“ | Obraz slajdu 21/27 (s. 25 PDF): Flash 051: Flash 0.24, N&T 0.38, Ours 0.39; Flash 201: Flash 0.23, N&T 0.84, Ours 0.84; GAE 201: N&T 0.52, Ours 0.24; GAE 501: 0.38 / 0.60; GAE 051: 0.14 / 0.13. GAE má jen dvě sady štítků. Hodnoty v poli `hodnota` byly správně. Text z `pdftotext` přiřazoval Flash řádky chybně, proto první revize chybu zanesla. |
| RQ5-004 | D | podmínky: „např. 3 vzorky SQL“, hvězdička obecně | hvězdička jen u Heartbleed, XSS, SQL a Infiltration; SQL: 3 testovací vzorky v Intermediate a Final, Original 21 toků; umístění „s. 5 PDF“ | Engelen (lirias), Tab. II: popisek „*Test sets of these classes are extremely small“, hvězdičky u Heartbleed, XSS, SQL, Infiltration (Web Brute Force bez); Tab. I: SQL 21 / 12 / 12. Řádky dat v textu tabulky jsou o jednu pozici posunuty vůči popiskům. Pořadí trojic jsem odvodil porovnáním s F1 v poli `hodnota` (XSS 0,18 → 0,25 → 0,79; SQL 0,11 → 0 → 0), sedí. Tab. II je na s. 5 PDF (ověřeno). Číslo strany ve sborníku (s. 11) neověřeno. |
| RQ5-006 | D | metoda „jednoduchý klasifikátor jen z Protocol a TTL“; limity „heuristiky nejsou důkaz bez surových dat“ | „oddělení tříd jen z Protocol a TTL (typ klasifikátoru zdroj neuvádí)“; limity: výrok o heuristikách ze Sekce 5.2 se tohoto výsledku netýká | Flood et al.: „it is possible to separate these classes with 98% accuracy using these features alone“, klasifikátor v té větě neuveden (random forest se v textu týká jiného experimentu s LUCID). Že limity ze Sekce 5.2 se týkají jen heuristických měr, jsem číselně nerozebíral, převzato z kontroly. |
| RQ5-008 | D | limity „jen jedna konfigurace“ | limity „-“; poznámka doplněna, že omezení je úsudek extraktora | Hledal jsem v textu Flood et al. omezení tohoto výsledku, nenašel jsem. Kapitola Caveats & Limitations je obecná. Důkaz absence, ne přímá citace. |
| RQ5-014 | D | umístění „Tab. 4:“ | „Sekce 7.3 (citace z textu) + Tab. 4 (hodnoty)“ | Jacobs et al.: věta „the classifier could not correctly classify a single ...“ je v textu Sekce 7.3. |
| RQ5-018 | D | chybí „při 100 FA“; „odhad autora 29/36“ | podmínky doplněny; „29/36 je výpočet extraktora (36 − 7), ne údaj autorů zdroje“ | Mahoney & Chan: „... at 100 false alarms“ ve Sekci 6.2. 29/36 jsem v textu neviděl, 7 legitimních z 36 ano. URL (TR CS-2003-02) beze změny, verzi RAID 2003 jsem neporovnával. |
| RQ5-019 | D | umístění „tabulky statistik redundance“ | „Sekce IV-A, Tab. I a II“ | Tavallaee: nadpis „IV. Statistical Observations, A. Redundant Records“, Tab. I (78,05 %, 93,32 %) a Tab. II (75,15 %, 88,26 %). |
| RQ5-022 | D | venue „CSET 2025 (slajdy)“, recenzovano „nejasné“ | ACSAC Workshops 2025, s. 551–561, DOI 10.1109/ACSACW69556.2025.00064; recenzovano „ano“; zmínka o HAL | Crossref potvrzuje titul, sborník a strany. Recenzovanost vyvozuji ze sborníkového článku, recenzní proces jsem neověřoval. HAL (hal-05474126) jsem neotevřel, jen přebírám z kontroly. |
| RQ5-032 | D | „Tab. 1 (s. 4)“ | „Tab. 1 (s. 5 PDF)“ | Popisek „Table 1: F1-Score results ...“ je na s. 5 PDF (arXiv). |
| RQ5-037 | D | hodnota: „nejlépe OC-SVM −17,85 %, nejhůř autoenkodér −37,49 %“ jako rozpětí modelů | jednotlivé běhy (trénink CIC-2018): −17,85 % a −37,49 %; průměry modelů AUROC: OC-SVM −25,89 %, autoenkodér −35,84 %, PCA −27,13 % | Verkerken (imec): „the model trained on the 2018 dataset only decreased 17.85% ... On average, the AUROC and accuracy still decreased respectively 25.89% and 17.84%“ (OC-SVM); autoenkodér: „decreased with 37.49% ... the AUROC score decreased on average by 35.84%“; PCA 27,13 % beze změny. Čísla oddílů 4.3 a 4.4 neověřoval jsem. |
| RQ5-040 | D | limity „malý vzorek praktiků (12)“ | „uzavřené otázky dotazníku mohou zavádět zkreslení (User-study: Limitations)“ | Sekce „User-study: Limitations“ říká, že uzavřené otázky mohou zavádět zkreslení a že praktici mohou mít doplňkové priority. Malý vzorek jako limitu tam autoři neuvádějí. |
| RQ5-044 | D | „z downstream metrik to nebylo zřejmé“ | doplněno „z předchozí práce [35]“ | DoppelGANger, Sekce 6.2: „... from downstream metrics, such as predictive accuracy in [35].“ |
| RQ5-046, 047 | D | venue „ACM SIGMETRICS 2024 (DOI 10.1145/3652963.3655071 ...)“ | „ACM POMACS 8(1), 2024, s. 1–32, DOI 10.1145/3639037; SIGMETRICS 2024 má jen 2stránkový abstrakt (10.1145/3652963.3655071)“ | Crossref: 10.1145/3639037 = „Proceedings of the ACM on Measurement and Analysis of Computing Systems“, vol. 8, s. 1–32; 10.1145/3652963.3655071 = „Abstracts of the 2024 ACM SIGMETRICS/IFIP PERFORMANCE ...“, s. 85–86. |
| RQ5-048 | D | venue „ACM SIGCOMM (abstrakt FloCon 2023)“; „Plný text nedostupný“ | „ACM SIGCOMM 2022, s. 458–472, DOI 10.1145/3544216.3544251; citovaný text je ze stránky SEI k prezentaci FloCon 2023“; poznámka upřesněna | Crossref potvrzuje SIGCOMM 2022 a s. 458–472. Že stránka SEI popisuje prezentaci FloCon 2023, a že je plný text hybrid OA, přebírám z kontroly (stránku SEI ani OpenAlex jsem neotevřel). Řádek zůstává V2. |
| RQ5-050 | D | limity „preprint“ (kontrola mluví o poli `riziko_zkreseni`; rozpor je v poli `limity_autoru`) | „-“ | Hlavička arXiv: „Preprint; Accepted at Machine Learning for CyberSecurity @ ECML PKDD 2024“. Pole „preprint“ v `limity_autoru` není limita autorů. Řádky 038 a 060 mají v tomto poli také „preprint“, ale ty skutečně jsou preprinty, nechal jsem je. |
| RQ5-051 | D | „per krok 0,05 % až 10 % bez uživatelů a až 17 % s uživateli“ (rozpětí) | příklady: 0,05 % (attemptRead), 10 % (attemptConnectToApplications) bez uživatelů, 17 % u attemptConnectToApplications s uživateli; „příklady, ne minimum a maximum“ | Nyberg, Sekce VI: „attemptConnectToApplications ... 10%, even without users, whereas attemptRead had a rate 0.05%. With users ... went up to 17%.“ Tvrzení o 1 % jako současném FP i FN rate z kontroly jsem neověřoval a nepřevzal. |
| RQ5-054 | D | umístění „Sekce 5“; „zdroj vztah nevysvětluje“ | „Sekce 4 (Discussion)“; „zdroj vztah mezi počty událostí a precision z Tab. 3 přímo neuvádí (Sekce 4 definuje TP a FP na úrovni hran)“ | Wang et al.: věta „despite a high TPR, the FPR of all models increases significantly ...“ je ve Sekci 4 (Evaluation Results), Sekce 5 je Related Work. Že Sekce 4 definuje TP/FP na úrovni hran, jsem viděl jen začátek definice (hrany grafu); zbytek z kontroly, proto jsem formulaci zmírnil. |
| RQ5-060 | D | „všechny verze: provoz s routerem a DNS resolverem (192.168.1.1) označený jako útok“ | „ve všech datasetech provoz mířící mimo testovací síť zaznamenaný jako útok; provoz s routerem a DNS resolverem ... označený jako útok (rozsah verzí zdroj neuvádí)“ | Raskovalov et al.: „In all datasets there are flows where traffic directed outside the test network is recorded as some form of attack ... There are also flows labeled as attacks that contain normal data exchange with network router and DNS resolver (IP: 192.168.1.1).“ |

Řádky 001, 002, 003 a další označené OK jsem neměnil. Poznámka k 003: kontrola upozornila, že „jediný split“ je inference. Do seznamu nutných oprav nepatřila, proto zůstalo beze změny, ale je to nepodložené v tom smyslu, že zdroj mluví jen o „random seeds“.

## 3. Opravy ve studii

| místo | původně | nově | souvisí s |
|---|---|---|---|
| záhlaví | verze 1.1, 2026-10-31 | verze 1.2, 2026-11-01, odkaz na kontrolu a revizi v2 | – |
| Abstrakt, bod 4 | „ztratí 26–72 p. b. přesnosti i u nejlepšího generátoru (046, 047)“ | NetDiffusion 26–72 p. b. i v nejlepší konfiguraci, NetShare 46–51 p. b. | 047, 046 (46–51 = 0,86 − 0,396 a 0,648 − 0,140, moje odvození) |
| Metodika, kód soaku | změna atribuce „necommitnutá“ | commitnuta v `a293d2b` (23:40 SEČ); běh v2 (start 18:57 SEČ) ji s velkou pravděpodobností nemá | kontrola S5 |
| Metodika, kontrola | „vlastní kontrola 0 / 47“ | doplněna druhá nezávislá kontrola (datum, vzorek 59 / 63, chybovost, verdikt) a co se změnilo; vlastní údaj 0 / 47 označen jako nepravdivý (audit trail zůstává v `revize-RQ5.md`) | protokol §9 |
| (b) Verkerken | „−17,9 až −37,5 % podle modelu“ | nejlepší a nejhorší jednotlivý běh −17,9 a −37,5 %; průměry modelů −25,9 až −35,8 % | 037 |
| (c) NetDiffusion | „TSTR 0,738 / 0,262“ | doplněno „bez post-gen. heuristiky (s ní 0,676 / 0,222)“ | 047 |
| (c) Nyberg | „range 0,05–17 % podle kroku“; výnosy bez uvedení hlavního faktoru | příklady 0,05 %, 10 %, 17 %; hlavním faktorem politika útočníka | 051, 052 |
| (e) absence CI | „90 % z 12 praktiků (procento nevychází)“ | „90 % z 10 odpovídajících praktiků (9/10)“ | 041 |
| S5 (tabulka) | „jen v necommitnuté pracovní kopii“ | commitnuto v `a293d2b` | kontrola S5 |
| Co z literatury: provozní události | „benigní aktivita dominuje nákladům“ | uživatelé náklady zvyšují, hlavním faktorem je politika útočníka; soak se tím nepotvrzuje ani nevyvrací | 052 |
| Z-5 | „TSTR ztrácí 20–72 p. b.“ | „26–72 p. b. (NetDiffusion, 047) a u DoppelGANger 20 % relativně (042)“ | 047, 042 |
| Z-7, důvody | „všechny zdroje jsou nerecenzované preprinty“ | „zdroje jsou preprinty kromě 053 (NDSS 2027); jedna skupina zdrojů; ...“ | 053 |
| Z-9, důvody | „12 praktiků, uvedených 90 % neodpovídá celému počtu“ | „10 odpovídajících praktiků, 9/10 = 90 %“ | 041 |
| Z-10 | „0,05–17 %“ jako rozpětí, bez výhrady k 052 | příklady, hlavní faktor politika útočníka, a výhrada, že „podhodnocení dopadu benigní aktivity“ je interpretace | 051, 052 |
| Hrozby validity: Extrakce | druhá kontrola „není nezávislá“ | doplněn výsledek 8,5 % a poznámka, že ani opravy nejsou nezávisle ověřeny | – |
| Hrozby validity: Preprinty | seznam 051–054 | 053 vyřazen, 022 a 053 uvedeny jako recenzované; Z-7 už „částečně“ na preprintech | 053 |
| Hrozby validity: Soak a stav kódu | „necommitnutá pracovní kopie“ | `a293d2b` | kontrola S5 |

Hypotézy H-1 až H-8: kontrola potvrdila H-1 a ostatní jsem po opravách prošel. H-4, H-6 a H-8 odkazují na RQ5-053 (nyní recenzovaný, jejich text se tím nezměnil) a H-5 na 051 (příklady místo rozpětí, text hypotézy rozpětí nepoužívá). Žádnou hypotézu jsem proto neměnil.

## 4. Přepočty rozsahů a mediánů

- Relativní pokles při přenosu mezi datasety (20 %, 30,5 %, 33 %, 69 %, 72 %, medián 33 %): beze změny. Verkerkenovo 30,5 % je AUROC průměr přes čtyři modely, tj. hodnota, kterou oprava 037 nezměnila. Opravené jsou jen jednotlivé běhy −17,9 a −37,5 %, které rozsahy a medián nepoužívaly.
- Rozpětí 20–72 % relativně v Z-3 a Syntéze: beze změny.
- „26–72 p. b.“: beze změny, ale už jen pro NetDiffusion. DoppelGANger (20 % relativně) a NetShare (46–51 p. b.) se uvádějí zvlášť.
- Podtémata (a) a (d) nepotřebují přepočet: žádný řádek, který používají, nezměnil hodnotu.

## 5. Změny jistoty závěrů

| Z-id | stará | nová | poznámka |
|---|---|---|---|
| Z-1 | vysoká | vysoká | beze změny; 022 je recenzovaný článek, důkaz je silnější, než studie uvádí |
| Z-5 | střední | střední | formulace sjednocena (p. b. vs relativně) |
| Z-7 | střední | střední | opraveno zdůvodnění (053 není preprint); jistotu nezvyšuji, zůstává nekonzistence (Theia) a jedna skupina zdrojů |
| Z-9 | střední | střední | odstraněna nepravdivá výhrada k 90 %; malý vzorek zůstává |
| Z-10 | nízká | nízká | formulace v tabulce i sekci o soaku přesněji drží zdroj |
| ostatní | – | beze změny | kontrola nenašla přesazení jistoty |

## 6. Souhrn chybovosti (poctivě)

- Druhá nezávislá kontrola ověřila 59 z 63 řádků (010, 029, 056, 059 mimo vzorek). Věcné chyby: **5 / 59 = 8,5 %** (95% Wilsonův interval 3,7–18,4 %), 5 / 63 = 7,9 %, pokud se mimo vzorek chyba nepředpokládá. Drobné chyby: 16. Řádků s jakoukoli chybou: 21 / 59 = 35,6 %. Chybných hodnot v poli `hodnota`: 0 / 59.
- Limit protokolu je 5 %, proto nelze verdikt PŘIJATO dát bez oprav. Dostali jsme PŘIJATO S OPRAVAMI, protože chyby jsou lokální a v textu kolem čísel.
- **První revize tvrdila 0 / 47 věcných chyb. Druhá kontrola našla v jejím vlastním vzorku 4 věcné chyby (023, 041, 047, 053) a pátá (052) byla také v řádku, který revize měnila.** Revize navíc sama zanesla chyby 023 a 041. Vlastní kontrola tedy chyby nezachytila a vlastní kontrole téhož autora se nedá věřit jako nezávislému ověření.
- **Tato druhá revize není nezávislá.** Všech 5 věcných a 16 drobných oprav jsem provedl a znovu ověřil já, tedy autor-revizor. Ve zdrojích jsem u všech pěti věcných chyb potvrdil, že kontrolor měl pravdu, a to doslovnou citací nebo obrazem tabulky. U 16 drobných chyb jsem zdroj otevřel u všech kromě částí 022 (HAL), 048 (stránka SEI, OpenAlex), 054 (zbytek definice TP/FP), 037 (čísla oddílů), 006 (Sekce 5.2), 004 (strana ve sborníku). Nebyl žádný případ, kdy se kontrolor mýlil.
- Naše pozorování: dvě z pěti věcných chyb (023, 041) vznikly právě při opravě, a to z rozpadlých tabulek a ze snahy „vysvětlit“ nesoulad poznámkou. Doporučení: po každé revizi nechat změněné řádky ověřit někým jiným, než kdo je změnil, a netvrdit vlastní nulovou chybovost jako nezávislou.

## 7. Co zůstává nevyřešené

- Nezávislé ověření samotných oprav (třetí kontrola) neproběhlo.
- Řádky mimo vzorek druhé kontroly: 010, 029, 056, 059 (nikdy nezávisle ověřeny v druhém kole).
- Ověření čísla strany ve sborníku (004: s. 11), čísla oddílů (037: Sekce 4.3, 4.4; 052: V-C), recenzního stavu 022 a plných textů 022, 048, 062 na HAL a OpenAlex.
- Pozn. k 051: tvrzení, že šum 1 % v simulátoru je současně FP i FN rate, jsem neověřil.
- Čísla soaku v2 se s velkou pravděpodobností váží na starou atribuci (podřetězec, delší okno lookalike); nová čísla vyžadují nový běh (mimo moji pravomoc).
- Pole `limity_autoru` je u 003 („jediný split“) inference extraktora.
