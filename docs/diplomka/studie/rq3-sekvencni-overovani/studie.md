# RQ3: Sekvenční ověřování, aktivní učení a hodnota informace při triáži a verifikaci alertů

Verze 1.0, 2026-10-31. Řídí se `00-protokol.md` (v1.0). Extrakce: `extrakce.csv` (57 řádků), dotazy: `hledani.csv`, neověřené zdroje: `neovereno.md`. Revidováno 2026-10-31 po nezávislé kontrole podle §9 protokolu (`kontrola-RQ3.md`, verdikt PŘIJATO S OPRAVAMI); všechny změny a původní hodnoty jsou v `revize-RQ3.md`.

## 1. Abstrakt s hlavními závěry

Otázka: jak sekvenční ověřování (Waldův SPRT, Threshold Random Walk), aktivní učení a hodnota informace mění počet kontrol, falešné poplachy a čas do rozhodnutí.

Přečetli jsme 30 zdrojů, z nich 27 vstoupilo do extrakce (26 × V3, 1 × V2). Hlavní zjištění:

1. Sekvenční testy rozhodují po jednotkách až desítkách pozorování a rychleji než Bro. TRW potřeboval v průměru 4,06 až 4,08 distinct cílových IP, Bro 21,4 až 36,9, Snort 6,0 až 14,1 (Jung 2004, 2 sítě; u ICSI je TRW vůči Snortu jen 1,5× rychlejší, u LBL 3×). Jung 2008 naměřil pro samotné TRW 10,0 až 18,5 prvních spojení a pro RBS+TRW 5,0 až 6,9; BotProbe 2 až 4 kola. Jednotky se liší (distinct IP, první spojení, kola), čísla nejsou srovnatelná. Jistota: nízká až střední (směr, rychlejší než Bro: střední; konkrétní rozsah a výhoda proti Snortu: nízká).
2. Nezávislé přehodnocení TRW (Alsaleh 2011) našlo na datasetu Class C 19 až 50 % falešných objevů podle parametrů (10 konfigurací); na datasetu Class B je podíl vůči stejnému kritériu mnohem nižší (< 1 %, nejvýše 24 % v exp. 8). Přidání znalosti o službách (stavový TRW, STRW) snížilo počet FP o 77 % (Class C, STRW2, přímo v textu) a o 94 % (Class B, jen vůči podmnožině FP z mapy služeb); souhrn autora říká „29 % a 77 % ve dvou datasetech“ a hodnotu 29 % v textu nelze k datasetu přiřadit. STRW zároveň hlásí o 43 % méně skenerů než TRW; „bez ztráty detekce“ je tvrzení autora, ne měření. Rozpor s původním článkem je uveden v §4. Jistota: nízká až střední.
3. Sekvenční test nemá přirozený strop počtu pozorování a nerozhoduje vždy: TRW ponechal v datasetu Class C více než 80 % vzdálených hostů nerozhodnutých, BotProbe 15,4 % uživatelů po 3 kolech. Evazi (úspěšná spojení na známé servery) autoři označují za snadnou, ale nezměřili ji. Jistota: střední (rozhodovací problém), nízká (evaze).
4. Aktivní učení s analytikem zvyšuje detekci při pevném rozpočtu: recall 0,868 při 200 vyšetřených entitách denně proti 0,737 při 1000 denně u čistě nesupervizovaného detektoru (AI², 3,6 mld. řádků logu; hodnoty ze 12., posledního týdne nasazení, ne průměr; v jiných týdnech jsou absolutní hodnoty mnohem nižší); 8× levnější štítky při F1 nad 89 % (Android malware). Jistota: střední, přenositelnost na síťové alerty je nepřímá.
5. Kaskáda levný filtr → drahý ověřovač šetří: Carbon Filter ve variantě clustering only zkrátil na ATLASv2 (jeden veřejný dataset, 491 alertů, z toho 50 škodlivých) čas z 5 024 s na 1 780 s (−65 %, odhad z dvou čísel); jiná komponenta (scoring model) odstranila 82,5 % resp. 84 % falešných alertů na zákaznických datech a ztratila 0 % (0 z 32 původních škodlivých alertů, horní hranice 95% CI zhruba 9 až 11 %) resp. 5,7 % (58 z 1 003 po bias-korekci) škodlivých. Obě čísla patří různým komponentám a nelze je spojovat. Jistota: nízká až střední pro směr, nízká pro velikost.
6. Externí přehodnocení často vychází hůř než původní tvrzení (NoDoze AUC 0,60 v ATLASv2 podle Carbon Filter, DeepCASE ~30 % slabých vysvětlení při nepoměru tříd). Jistota: nízká.
7. Aktivní ověření expozice zlepšilo přesnost v testbedu (99,64 % → 0 % nerelevantních alertů, jedna testbed), ale přináší doložená rizika: pád PLC vyžadující výpadek napájení, změna toku uživatelů u sond. Jistota: nízká (kvalita), střední (existence rizika).
8. Publikační obraz je zkreslený k benchmarkům: ze 87 jádrových studií přehledu (2015 až 2026) se 78 opírá o veřejné benchmarky (65) nebo simulaci (13). Přehled je preprint odeslaný do časopisu (nerecenzovaný). Jistota: nízká až střední.

Čeho není: nenašli jsme žádnou práci, která by změřila hodnotu informace (VOI) nebo bandit výběr kontroly přímo pro ověřování bezpečnostních alertů s metrikou počtu kontrol a FP. Nejbližší je Kim a Dán (entropie belief jako proxy, simulace) a AI² (rozpočet analytika). Nenašli jsme ani kvantifikované měření honeypot-confirmation.

## 2. Metodika a PRISMA

Strategie podle protokolu §3: WebSearch (24 dotazů, 4 negativní, viz `hledani.csv`), plný text stahován přes curl a převáděn `pdftotext -layout`, hodnoty čteny z tabulek a textu. WebFetch sám vracel u PDF jen binární text, proto bylo čtení z lokálně převedeného PDF. Období 2015 až 2026, starší práce označeny `seminal=ano` (TRW 2004, RBS 2004). Citační řetězení: u TRW (dopředu: Schechter 2004, Jung 2008, Alsaleh 2011, BotSniffer, BotProbe), u AI² (Chen 2023 navazuje), u Carbon Filter (NoDoze, RapSheet), u DeepCASE (AACT, imbalance 2025), u Kruegel 2004 (jen sekundárně). Systematické průchody referencí všech 5 klíčových prací jsme neudělali; je to omezení.

| Krok PRISMA | Počet | Poznámka |
|---|---:|---|
| Identifikováno (řádky výpisu, 24 dotazů × max. 10) | ~240 | tool vrací max. 10 výsledků; duplicity a ne-vědecké stránky neodfiltrovány strojově |
| Po deduplikaci (jedinečná odborná díla) | ~85 | odhad autora, ručně z výpisů, ne strojově |
| Po screeningu názvů/abstraktů | ~38 | zbytek: vendor blogy, přehledové stránky, nerelevantní oblast (sociální sítě, jiné domény) |
| Plný text zhodnocen (pokus o otevření) | 38 | 30 otevřeno, 8 nelze (V1/V0, `neovereno.md`) |
| Vyloučeno po čtení plného textu | 3 | Alahmadi 2022 (kvalitativní), CAGE-2 a OT-IR (POMDP odpovědi, bez metriky verifikace) |
| Zahrnuto do extrakce | 27 | |
| z toho V3 / V2 | 26 / 1 | V2 = NoDoze (jen oficiální stránka NDSS) |

Důvody vyloučení souhrnně: nedostupný plný text (8), žádná metrika triáže/ověřování (3), vendor materiál (mimo počty, samostatná tabulka), jiná doména bez přenosu (zbytek screeningu).

Rozdělení extrakčních řádků podle V: V3 = 56, V2 = 1, V1/V0 = 0 (V1/V0 jsou jen v `neovereno.md`). Řádky s číselnou hodnotou výsledku: zhruba 45 (zbytek jsou kvalitativní limity/evaze s popisem; sloupec `hodnota` je u nich označen "kvalitativně").

Nezávislá kontrola (§9 protokolu), 2026-10-31: druhý agent znovu stáhl zdroje a ověřil 48 z 57 řádků (84 %; povinně všechny řádky opírající závěry se střední jistotou, plus všechny řádky šesti klíčových zdrojů, plus systematický doplněk). Věcná chyba: 1 (2,1 %, metadata řádku 054), drobné chyby 12 (chybějící podmínky u čísel, umístění), neověřitelné 0. Verdikt PŘIJATO S OPRAVAMI. Po kontrole: provedeny opravy extrakce, přeformulovány závěry Z1, Z2, Z4, Z7, Z8, Z12, Z13; 9 řádků kontrola neověřila, proto je autor revize znovu otevřel a potvrdil (028, 032, 033, 047, 048, 050, 051, 055, 057; 048 jen na úrovni V2). Jedna oprava kontroly (010, Tab.5) se po novém ověření nepotvrdila. Původní hodnoty a podrobnosti: `revize-RQ3.md`.

Úrovně důkazu: E1 1 řádek (přehled bez kvantitativní syntézy), E3 většina, E4 6 řádků (provozní data: Carbon Filter, AACT, DeepCASE, kazuistika Samanis), E5 4 řádky (diskuse bez dat). E2 (více datasetů s replikací) nemá žádná práce v RQ3.

## 3. Výsledky podle podtémat

Všechna čísla odkazují na `extrakce.csv` (id RQ3-nnn). Čísla z různých prací nejsou sdružena (§8 protokolu): jednotky se liší (distinct IP, první spojení, kola sond, entity za den).

### (a) Waldův SPRT a sekvenční testy při detekci skenování a botnetů

Počet pozorování do rozhodnutí (rozsah, bez sdružování; různé jednotky):

| Práce | Metoda | Data | Pozorování do rozhodnutí | Baseline | id |
|---|---|---|---|---|---|
| Jung 2004 | TRW | LBL | 4,08 distinct IP | Bro 21,40; Snort 14,06 | 001 |
| Jung 2004 | TRW | ICSI | 4,06 | Bro 36,91; Snort 6,00 | 002 |
| Jung 2008 | RBS+TRW | Lab-II / ISP | 6,9 / 5,0 prvních spojení | TRW 18,5 / 10,0 | 015 |
| Schechter 2004 | reverzní SPRT + CBCRL | isp-03, isp-04 | 10 prvních spojení (pomalý HTTP skener) | virus throttle až 526 | 011 |
| Gu 2009 BotProbe | aktivní sondy + SPRT | vzorky botů | 2 až 4 kola | | 026 |
| Gu 2009 BotProbe | aktivní sondy + SPRT | 97 uživatelů | 75,3 % normálních po 2 kolech, 9,3 % po 3, 15,4 % nerozhodnuto | | 025 |

Přesnost a falešné poplachy:

| Práce | Metrika | Hodnota | id |
|---|---|---|---|
| Jung 2004, LBL | efficiency / effectiveness TRW; Bro; Snort | 0,963 / 0,960; 1,000 / 0,150; 0,615 / 0,126 | 003 |
| Jung 2004, ICSI | totéž | 1,000 / 0,992; 1,000 / 0,029; 1,000 / 0,029 | 004 |
| Jung 2004, LBL | FP TRW | 33, z toho 29 crawlery a proxy, 3 hosty s IDENT odpověďmi, 1 SMTP klient | 006 |
| Schechter 2004 (kompozit) | alarmy / detekce / efficiency / effectiveness | 34 / 11 / 0,324 / 0,917 (throttle 10 / 5 / 0,500 / 0,417) | 010 |
| Jung 2008 | FP za hodinu | 0,07 (Lab-II), 0,57 (ISP); nelze odvodit z Tab.3 (3 FP/137 h ≈ 0,02; 3 FP/10,5 h ≈ 0,29), zdroj to nevysvětluje | 014 |
| Gu 2008 BotSniffer | FPR | 0,0016 (11 z 6 848), cíl α = 0,005 | 023 |
| Alsaleh 2011, TRW, Class C | podíl FP z označených | 19 % až 50 % (47 % při výchozích parametrech); Class B: < 1 %, max. 24 % (exp. 8) | 018, 019 |
| Alsaleh 2011, STRW | odstraněno FP TRW | Class C (STRW2) 77 %; Class B 94 % (jen vůči podmnožině FP z mapy služeb); souhrn autora „29 % a 77 %“ bez přiřazení 29 % k datasetu; STRW hlásí o 43 % méně skenerů | 020, 022 |

Zjištění a protiklady:
- Rychlost je doložena napříč čtyřmi pracemi (TRW 4 až 18,5, RBS+TRW 5 až 6,9, CBCRL 10, BotProbe 2 až 4 kola; různé jednotky), vždy proti pevným prahům Bro/Snort nebo throttle; výhoda TRW proti Snortu je 1,5× (ICSI) až 3× (LBL), proti Bro 5× až 9×; porovnání jsou ale na stejných datech, na kterých se ladily parametry (riziko zkreslení střední až vysoké).
- Rychlé rozhodnutí má cenu v objemu: TRW označil ~14 000 skenerů proti 122 u Bro a operátoři nemohli blokovat tisíce adres denně (id 007). Vyšší TPR bez dalšího filtru jen přesouvá práci.
- TRW klasifikuje málo hostů: méně než 20 % rozhodnuto, přes 80 % čeká (id 021, dataset Class C).
- Limity modelu: oscilace úspěch/neúspěch nikdy nepřekročí práh (009); topologické červy test nezachytí (013); zavedení maximálního počtu pozorování řeší návrh v arXiv 1204.1935 (017, jen numerické experimenty bez reálných dat).
- Nezávislé přehodnocení (Alsaleh) našlo na Class C 19 až 50 % FP; příčina: přechodně nedostupné služby. Mapa služeb jako orákulum (STRW) FP snižuje, ale hlásí o 43 % méně skenerů; že detekce neutrpí, tvrdí autor, neměřil to.

### (b) Bayesovské sekvenční rozhodování, POMDP a bandit pro výběr kontroly

Přímých měření je málo. Literatura o POMDP v kyberbezpečnosti se soustředí na odpověď na útok (CAGE-2, OT, agentní IR), ne na výběr ověřovací kontroly. Dvě zahrnuté práce:
- Kim a Dán 2025 (HMM, aktivní učení, politiky MaxEntropy/Bayes pro výběr alertu k vyšetření): MSE belief až o 50 % nižší než u základních politik, redukce stavového prostoru zkrátila výpočet o 85 % (id 056). Simulace, E3.
- Hammar a Stadler 2022 (optimální zastavování): optimální strategie mají prahovou strukturu, v emulaci lepší než Snort IPS práh (057). Čísla jsou jen v grafech; o entropii belief ani MSE práce nic nepodává, nepodporuje proto Z12.
- Nepřímo: SPRT je speciální případ prahové strategie optimálního zastavování (extrapolace, nikdo to experimentálně nesrovnal na alertech).
- Agentní IR (Gao 2026) −15,1 % času obnovy, +33,6 % míry obnovy, simulace (055); mimo ověřování.

Vyhledávání bandit/VOI pro výběr hostů ke sondování nic přímého nenašlo (viz §9).

### (c) Aktivní učení a uncertainty sampling při triáži

| Práce | Doména | Efekt | id |
|---|---|---|---|
| Veeramachaneni 2016 (AI²) | logy webové platformy, 12 týdnů | recall 0,868 při k=200/den vs 0,737 u nesupervizovaného při k=1000 (hodnoty 12. týdne, nikoli průměr); 3,41× detekce, FP 5× nižší; 143 resp. 211 vs 42 z 318 útoků | 029, 030, 031 |
| Chen 2023 | Android malware, drift | 8× levnější štítky (50 vs 400 vzorků/měs. při F1 > 89 %); FNR 14 % → 9 %, FPR 0,86 % → 0,48 %; bez učení FNR 38 % za 7 let | 036, 037, 038 |
| ActDroid 2024 | Android | až 76 % méně štítků (z přehledu příspěvků v úvodu; abstrakt: potřeba jen 24 % trénovacích dat) | 039 |
| Ziai 2019 | KDD99 | F1 0,90 → 0,98 po 10 dotazech; selhání při prevalenci pod 0,01 % | 034, 035 |
| Klein 2021 (Jasmine) | NSL-KDD, UNSW-NB15 | F1 plně označeného GBM ~0,760 vs ALADIN ~0,720; samotné dotazy na anomálie jsou špatná strategie, smíšená strategie robustnější | 032, 033 |

Kritika: tři z prací jsou na zastaralých datasetech (KDD99, NSL-KDD); AI² počítá podvody na jedné platformě; Chen je malware s časovým driftem, ne síťový alert. Všichni předpokládají důvěryhodné štítky jednoho analytika (Ziai to přiznává). Úspora štítků je nejsilnější výsledek, ale měří se ve štítcích, ne v minutách analytika.

### (d) Automatické obohacení a verifikace alertů

| Práce | Metoda | Výsledek | id |
|---|---|---|---|
| AACT 2025 (Sophos MDR, 6 měsíců provozu) | učení z akcí analytiků | −61 % alertů zobrazených analytikům, FNR 1,36 %; offline 34 % odstraněno při FNR 1,5 % | 044, 045 |
| DeepCASE 2022 | kontext + štítkování shluků | 86,72 % událostí filtrováno, práce −90,53 %, podhodnocení rizika < 0,001 % | 046 |
| Replikace DeepCASE 2025 | 24,5 M Suricata alertů | při nepoměru tříd ~30 % vysvětlení má kosinovou podobnost ≤ 0,25 | 047 |
| NoDoze 2019 (V2, jen oficiální stránka NDSS, PDF nepřečteno) | provenance, 364 alertů | −86 % falešných poplachů | 048 |
| Carbon Filter 2024 (varianta clustering only) | kontext spuštění procesu | AUC 0,94 vs NoDoze 0,60 a RapSheet 0,90 na ATLASv2 | 043 |
| Kruegel 2004 | aktivní ověření (Nessus) uvnitř Snortu | 6 659 alertů, 24 relevantních; nerelevantních 99,64 % → 0 % | 049 |

SOAR a obohacovací kaskády jako takové (enrichment) nemají ve zdrojích nezávislé kvantitativní měření času; jediná data o času jsou provenance (Carbon Filter, Tab. 6: NoDoze 10,23 s na alert, RapSheet 53,98 s). Vendor tvrzení jsou jen v `neovereno.md`.

### (e) Kaskády: levný filtr → drahý ověřovač

| Práce | Úspora | Ztráta | id |
|---|---|---|---|
| Carbon Filter scoring, TAU | 82,5 % FP odstraněno | 0 % škodlivých ztraceno (po bias-korekci 108; původně 32 škodlivých, horní hranice 95% CI zhruba 9 až 11 %) | 040 |
| Carbon Filter scoring, MDR | 84 % FP odstraněno | 5,7 % škodlivých ztraceno (58 z 1 003 po bias-korekci; původně 88 škodlivých) | 041 |
| Carbon Filter (clustering only) + NoDoze, ATLASv2 (jiná komponenta než 040/041; 50 škodlivých z 491) | 5 024,2 s → 1 780,02 s (317 z 491 alertů potlačeno filtrem) | recall ztráta clusteringu nepublikována | 042 |
| AACT | 61 % alertů mimo frontu | FNR 1,36 % | 044 |
| Sudyana 2025 (flow → paket) | až 24× nižší výpočet | detekce 95 % (flow) a 100 % (paket) u neviděných útoků | 052 |

Ztráta recallu scoring modelu není nulová a liší se 0 až 5,7 % mezi datasety (id 040 vs 041; nulová ztráta je z 32 případů). Čísla času (042) a recallu (040, 041) pocházejí z různých komponent a jiného datasetu a nesmí se spojovat. Jde o preprinty a o jednu publikovanou práci (Sudyana, "až 24×" je maximum).

### (f) Aktivní ověřování a jeho rizika

Přínos: Kruegel 2004 (49), BotProbe (25, 26), STRW s aktivní mapou služeb (20, 22). Rizika:
- Samanis 2022: jeden PLC při Nmap s určitými příznaky vstoupil do poruchového stavu vyžadujícího vypnutí napájení, druhé zařízení selhalo při technice více nástrojů (053). Jde o kazuistiku, prevalenci neznáme.
- BotProbe: sondy mění tok uživatelů, autoři sami říkají, že "a more formal study of cost-benefit analysis and risk assessment is needed" (027), 15,4 % uživatelů zůstalo po 3 kolech nerozhodnuto (025).
- Kruegel: skener sám může mít FP a FN (049).
- Evaze: úspěšná "maskovací" spojení posouvají random walk pryč od rozhodnutí (008), pomalé skeny unikají (028).
- Randomizace volby: deterministické pořadí kontrol je zneužitelné; ARL politika ~50 % lepší než uniformní a ta mnohem lepší než priority Suricaty (050), u audit hry je předvídatelné pořadí nejhorší (051).

## 4. Syntéza

Kvantitativní souhrn (§8 protokolu) jsme nesdružovali: žádná metrika nemá ≥ 3 studie s totožnou definicí a srovnatelnými podmínkami. Rozsahy:
- pozorování do rozhodnutí: TRW 4,06 až 4,08 distinct IP (Jung 2004) a 10,0 až 18,5 prvních spojení (Jung 2008), RBS+TRW 5,0 až 6,9, CBCRL 10, BotProbe 2 až 4 kola (různé jednotky, 4 práce, nesdruženo);
- snížení pracovní zátěže analytika: 34 až 90,53 % (AACT offline 34 %, nasazení 61 %, DeepCASE 90,53 %, NoDoze 86 %, V2 jen abstrakt); různé definice a datasety, heterogenita velmi vysoká;
- úspora štítků: 8× (Chen), až 76 % (ActDroid), 5× méně vyšetřených entit při vyšším recallu (AI², přibližně z k = 200 vs 1000);
- ztráta recallu při kaskádě: 0 až 5,7 % (Carbon Filter scoring model; 0 % z 32 případů), FNR 1,36 % (AACT), < 0,001 % (DeepCASE, jiná definice).

Rozpory:
1. Jung 2004 říká o TRW "very few false positives"; Alsaleh 2011 naměřil 19 až 50 % falešných objevů. Možné vysvětlení (nepotvrzeno): Jung určuje "pravdu" heuristickou klasifikací a nepovažuje crawlery/proxy za chyby plánovače, Alsaleh používá mapu služeb jako přísnější ground truth a prostředí s přechodnými službami. Podobně Carbon Filter cituje NoDoze jako 84 %, NDSS stránka říká 86 %, a na ATLASv2 měří AUC jen 0,60.
2. Originální tvrzení DeepCASE (< 0,001 % podhodnocení) vs externí zjištění o slabých vysvětleních při nepoměru tříd. Důvod: odlišné datasety a různá míra nepoměru.
3. Alsaleh uvádí odstranění 29 % a 77 % FP (shrnutí) i 94 % (Class B, text, jen vůči podmnožině FP z mapy služeb); 77 % je v textu doloženo pro Class C, 29 % nelze k datasetu v textu přiřadit a disertace to nevysvětluje. Čísla nelze sloučit.
4. Uncertainty sampling je silný (Ziai F1 +0,08 za 10 dotazů, AI²), ale selhává při nízké prevalenci (Ziai, Nmap < 0,01 %) a driftu (Chen 2023). Jasmine to řeší směsí dotazů.

## 5. Závěry

| Z-id | Tvrzení | Důkazy | Jistota | Důvody snížení | Použitelnost pro Skákavku | Doporučená akce |
|---|---|---|---|---|---|---|
| Z1 | Sekvenční test rozhoduje o skeneru po jednotkách až desítkách pozorování: TRW 4,06 až 4,08 distinct IP (Jung 2004) a 10,0 až 18,5 prvních spojení (Jung 2008), RBS+TRW 5,0 až 6,9. Je rychlejší než Bro (21,4 až 36,9), vůči Snortu 1,5× (ICSI) až 3× (LBL). | 001, 002, 011, 015 | nízká až střední (směr vůči Bro: střední; rozsah a výhoda vůči Snortu: nízká) | stejná data pro ladění a test, 2 až 4 sítě, bez CI, hlasité cíle (červi, skenery), různé jednotky (distinct IP vs první spojení) | s úpravou | testovat SPRT nad sérií ověření (H1) |
| Z2 | Skutečná FPR sekvenčního testu závisí na modelu "neúspěch = skenování": 19 až 50 % FP při Alsalehově přehodnocení na datasetu Class C (v Class B < 1 %, max. 24 % vůči stejnému kritériu); kontext služeb snížil počet FP o 77 % (Class C) a 94 % (Class B, vůči podmnožině FP), souhrn autora uvádí 29 % a 77 %. STRW přitom hlásí o 43 % méně skenerů; ztráta detekce nebyla změřena. | 018, 019, 020, 022, 006 | nízká až střední | jedno nezávislé přehodnocení (disertace), rozsah 19 až 50 % z jednoho datasetu, jiná definice FP (FD rate), 29 % nepřiřazeno, „bez ztráty detekce“ je tvrzení autora | ano | brát znalost služeb jako povinný vstup (H2) |
| Z3 | Sekvenční test nerozhoduje vždy: TRW ponechal > 80 % hostů nerozhodnutých, BotProbe 15,4 % po 3 kolech; hrozí oscilace a nepohlcení. Nutný strop počtu kontrol a eskalace. | 021, 025, 009, 017 | střední | 017 jen simulace; 021 z disertace | ano | N_max + eskalace (H7) |
| Z4 | Cíl α se v jednom pozorování plnil: BotSniffer FPR 0,0016 < α 0,005. U RBS+TRW (0,07 až 0,57 FP/hod, 014) žádné α srovnáno není a údaj nesedí s Tab.3 zdroje. Protipříklad: Alsaleh naměřil u TRW 19 až 50 % FD (018, 019). | 023, 014, 018, 019 | nízká | malé n (5 pozitiv/dataset, 8 botnetových stop), ladění na stejných datech, vnitřní nesoulad 014, protipříklad Alsaleh | s úpravou | brát α, β jako nastavitelné parametry, ne jako záruku |
| Z5 | Aktivní učení s analytikem zvyšuje detekci při pevném rozpočtu a šetří štítky (AI², hodnoty 12. týdne: recall 0,868 při 200/den vs 0,737 při 1000/den; Chen 8×). | 029, 030, 031, 036, 037, 039 | střední | jiné domény (podvody, malware), jeden dataset u AI², preprinty | s úpravou | EVOI nebo entropie pro řazení plánů (H3) |
| Z6 | Uncertainty sampling selhává při velmi nízké prevalenci a při driftu; samotné dotazy na anomálie jsou špatné; směs je robustnější. | 035, 033, 038, 032 | nízká | zastaralé datasety (KDD99, NSL-KDD) | ano | míchat uncertainty + anomálie + náhodu (H8) |
| Z7 | Kaskáda levný filtr → drahý ověřovač šetří práci: Carbon Filter clustering only −65 % času na jednom datasetu (ATLASv2, 491 alertů, 2 časová čísla), scoring model odstranil 82,5 až 84 % FP na jiných datech; "až 24×" výpočet (Sudyana). Ztráta recallu scoring modelu 0 % (z 32 případů) až 5,7 %. Úspora času a ztráta recallu pocházejí z různých komponent a nesmí se spojovat. | 040, 041, 042, 044, 052 | nízká až střední (směr), nízká (velikost) | preprinty, různé komponenty, jiná definice ztráty, jeden veřejný dataset s 491 alerty a 50 škodlivými, ztráta recallu z 32 případů | s úpravou | filtr s měřenou ztrátou recallu per rodina (H4) |
| Z8 | Externí přehodnocení často vychází hůře než autorské tvrzení (NoDoze AUC 0,60 podle Carbon Filter; DeepCASE ~30 % slabých vysvětlení). | 043, 047 (048 jen V2 kontext) | nízká | nepřímé srovnání, jiná data | ano | nepřebírat čísla autorů, měřit na vlastním harnessu |
| Z9 | Aktivní ověření expozice výrazně sníží nerelevantní alerty v testbedu (99,64 % → 0 %), ale přenos na provoz není měřen. | 049, 020 | nízká | jedna testbed, syntetické útoky | ano s úpravou | ověření expozice před typováním (H5) |
| Z10 | Aktivní ověřování má doložená rizika: pád PLC vyžadující power cycle; sondy mění provoz uživatelů a nechávají část případů nerozhodnutou. | 053, 027, 025 | střední (existence), velmi nízká (prevalence) | kazuistika, malý počet zařízení | ano | passive-first pro OT/IoT, schválení a rozpočet sond |
| Z11 | Předvídatelné pořadí kontrol je zneužitelné; náhodnost a robustní politika zlepšují výsledek (~50 % vs uniformní). | 050, 051, 008 | nízká | modelové náklady (CVSS), simulace | s úpravou | randomizovat část výběru (H6) |
| Z12 | Entropie belief jako proxy hodnoty informace snižuje MSE o stavu útoku až o 50 % proti jednoduchým politikám (simulace). | 056 | nízká | pouze simulace, "až" | s úpravou | EVOI-proxy v plánovači (H3) |
| Z13 | Většina literatury stojí na benchmarcích a simulaci (78 z 87), málo na provozu; E2 evidence není. | 054 | nízká až střední | přehled je nerecenzovaný preprint odeslaný do ACM CSUR, autoři přehledu hodnotí i vlastní práce | ano | vlastní soak harness je důležitější než čísla z literatury |

## 6. Překlad do praxe

Parametry označené "extrapolace" nemají přímý důkaz v našem kontextu.

1. Sekvenční ověření per host: akumulovat výsledky ověřovacích kontrol (úspěch/neúspěch, shoda/neshoda) jako poměr věrohodností, α a β nastavit explicitně a zaznamenávat. Doložené řády: jednotky až desítky pozorování (TRW 4 až 18,5, RBS+TRW 5 až 7, CBCRL 10; 001, 011, 015; různé jednotky). Extrapolace: u nás je pozorováním ověřovací plán, ne spojení.
2. Povinný strop N_max a eskalace nerozhodnutých (Z3). Jung ponechal > 80 % nerozhodnuto, BotProbe 15,4 % po 3 kolech. Extrapolace pro hodnotu N_max (3 až 10 kontrol).
3. Kontext služeb jako orákulum: neúspěšné spojení na neexistující službu je důkaz, na přechodně nedostupnou službu ne (Z2). U nás: inventář expozice (už 100% spolehlivá cesta v soak v1) použít k tomu, aby `unmapped_passive_event` a podobné nepočítaly jako neúspěch skenu.
4. Rozpočet ověřování nenést FIFO: řadit plány podle odhadu hodnoty informace (entropie belief nebo nejistota Case Memory, Z5, Z12; Z12 stojí jen na jedné simulační práci, 056). V soak v2 (snapshot `status.md`) bylo z 48 333 897 plánů provedeno 2 061 617 (4,3 %), znovu využito 1 924 414 (4,0 %) a mimo rozpočet 44 179 698 (91,4 %; procenta vlastní výpočet). Při takové propustnosti rozhoduje pořadí. AI² ukazuje, že při 5× menším počtu vyšetřených entit lze dosáhnout vyššího recallu (jiná doména).
5. Kaskáda: levný pasivní skór před drahým aktivním ověřením, ale s prahem vázaným na měřenou ztrátu recallu v držené rodině útoků (Z7; literatura ztrátu clusteringu na ATLASv2 nepublikuje a scoring model měřil 0 % ztráty jen na 32 případech). Pro rodiny s nízkou detekcí (c2_beacon 12,8 %, rogue_device 8,0 % ve snapshotu v2) filtr nepřitvrzovat, protože v1 už ztrácí recall dříve než kaskáda.
6. Aktivní ověření: passive-first, per třída zařízení (OT/IoT/křehká) bez aktivního skenu bez schválení a rozpočtu (Z10); sondy označit, logovat, nerozhodnuté vracet jako "nerozhodnuto", ne jako zamítnuto. Naše invarianty (0 porušení rozpočtu, schválení, scope) toto už kryjí; stojí za to doplnit třídu zařízení.
7. Nepřebírat čísla z literatury (Z8): publikované FP redukce (82,5 až 99,64 % v extrakci: 040, 041, 049) pocházejí z malých testbed nebo jednoho zákaznického prostředí; Carbon Filter sám uvádí, že provenance triáž pro komerční EDR neškáluje.
8. Randomizace: část výběru kontrol (např. 10 až 20 %, extrapolace) losovat, aby pořadí nebylo předvídatelné a pro odhad nezkreslených FN (Z11).

Souvislost s našimi měřeními (`soak-findings.md` v1 a `status.md` v2, hodnoty se mění):
- FP u benigních lookalike: v2 authorized_scanner 44,6 % s falešným nálezem, flash_crowd 80,0 %, backup_burst 75,2 % [Wilson]. Odpovídá Jung 2004 (crawlery a proxy tvoří 29 z 33 FP u TRW, id 006) a Alsaleh (přechodné služby jako zdroj FP, id 018). Mapa služeb a kategorizace hostů ("friendly hosts", Jung) jsou doložené postupy.
- Bezpříčinné behaviorální nálezy: v1 210,7 na síť-den, v2 snapshot 1 255,9 na síť-den. Literatura o sekvenčních testech tento typ šumu (objemové anomálie) neřeší; je to jiná třída signálu.
- c2_beacon 4,7 % (v1) a 12,8 % (v2) detekováno, medián latence 360 až 420 min: SPRT práce o botnetech (BotSniffer 100 % na 8 stopách, BotProbe 100 % na IRC) nejsou srovnatelné s pomalým beaconingem; jde o IRC/HTTP boty bez evaze (id 024, 026).
- exploit_attempt: IDS vidí, správný typ 0 %. Kruegel 2004 (id 049) nabízí ověření expozice, ale měří jen filtrování nerelevantních alertů, ne typování.
- Kalibrace Case Memory: Brier 0,0107 (v1) a 0,0290 (v2), naivní referenční 0,25 v obou; přeúvěrnost v rozsahu 0,1 až 0,5 podle v1. Literatura o VOI vyžaduje kalibrované pravděpodobnosti; EVOI nad nekalibrovaným modelem je riziko (extrapolace, žádná práce to neměřila).

## 7. Hypotézy k empirickému ověření (soak harness)

Formát: změna → očekávaný efekt (rozsah z důkazů) → metrika → scénář/seedy → kritérium zamítnutí. Testovat A/B na stejných seedech, držené rodiny útoků, kotva CTU-13/IoT-23. Zveřejnit i neúspěch.

**H-1. Sekvenční akumulace ověření místo jednorázové kontroly.** Změna: per-host součet logaritmů věrohodností s nastavitelným α a β, rozhodnutí při překročení prahu. Očekávaný efekt: pokles počtu ověření na rozhodnutí a FP na lookalike oproti jednorázovému prahu (Z1: 4 až 18,5 pozorování podle práce, RBS+TRW 5 až 7; extrapolace do jiné jednotky; absolutní cíl ≤ 10 ověření je pracovní odhad, ne z důkazu). Metrika: medián a p90 počtu ověření na rozhodnutí, TPR a FP na síť-den. Scénář: port_scan_horizontal, port_scan_vertical, slow_scan a lookalike authorized_scanner, flash_crowd; ≥ 10 seedů. Zamítnutí: medián kontrol není ≥ 30 % nižší než baseline, nebo TPR slow_scan klesne o > 2 procentní body (Wilson 95 %).

**H-2. Kontext služeb pro neúspěšné spojení.** Změna: neúspěch na službě, která nikdy nebyla v inventáři expozice, se nepočítá do skenovacího skóre; neúspěch na známé, přechodně nedostupné službě se tlumí (STRW logika). Očekávaný efekt: řádově desítky procent méně FP skenovacích nálezů (Alsaleh: 77 % Class C, 94 % Class B vůči podmnožině FP, souhrn autora 29 až 77 %; Z2); TPR může klesnout (STRW hlásí o 43 % méně skenerů), proto se TPR měří. Metrika: FP nálezů skenu na síť-den u lookalike (authorized_scanner, flash_crowd, backup_burst, ntp_fanout), TPR rodin skenů. Zamítnutí: pokles FP < 20 % nebo TPR pokles > 2 p. b.

**H-3. Pořadí plánů podle hodnoty informace místo FIFO.** Změna: řazení ověřovacích plánů podle entropie belief nebo odhadu EVOI z Case Memory při stejném počtu provedených kontrol. Očekávaný efekt: víc potvrzených pravdivých nálezů na tisíc provedených kontrol (AI²: vyšší recall při 5× menším počtu vyšetřených, hodnoty 12. týdne, Z5; Kim a Dán: MSE až −50 %, Z12; zde konzervativní extrapolace ≥ 1,3×, bez přímého důkazu). Metrika: potvrzené TP na 1000 provedených kontrol, recall při fixním rozpočtu (1× a 0,5× aktuálního). Scénář: celý soak profil, 5 až 10 seedů. Zamítnutí: relativní zisk < 10 % nebo CI zahrnuje 0.

**H-4. Kaskáda s měřenou ztrátou recallu.** Změna: levný pasivní filtr vyřadí alerty s nízkým rizikem před drahým aktivním ověřením. Očekávaný efekt: úspora nákladu ověření v řádu desítek procent (Z7: −65 % času je z clustering-only varianty na jednom datasetu; 82,5 až 84 % FP odstraněno scoring modelem, jiná komponenta), ztráta recallu 0 až 5,7 % (0 % z 32 případů). Metrika: počet provedených aktivních ověření, recall podle rodiny, ztracené útoky v držené rodině. Zamítnutí: úspora < 30 % nebo ztráta recallu > 2 p. b. v jakékoli rodině s n ≥ 100.

**H-5. Ověření expozice před typováním exploit_attempt.** Změna: alert na exploit služby, která v inventáři neexistuje nebo není zranitelná, označit "irelevantní" a řadit níž (Kruegel: 99,64 % → 0 % nerelevantních v testbedu; extrapolace). Metrika: podíl exploit alertů odstraněných z fronty, TP ztracené. Zamítnutí: odstraněno < 30 % nebo ztráta TP > 2 p. b.

**H-6. Maskovací evaze a náhodnost výběru.** Změna A: nový scénář slow_scan_camouflage (úspěšná spojení na známé servery, Jung). Změna B: 10 až 20 % výběru kontrol losovat. Očekávaný efekt A: TPR klesne (kvalitativní doklad 008); očekávaný efekt B: menší pokles TPR u adaptivního útočníka, který zná pořadí (Z11, ~50 %). Metrika: TPR camouflage variant, TPR proti útočníkovi znajícímu pořadí. Zamítnutí A: pokles < 10 p. b. (evaze neúčinná, což je dobrá zpráva); zamítnutí B: žádný rozdíl v TPR proti informovanému útočníkovi.

**H-7. Strop počtu kontrol a eskalace.** Změna: N_max = 5 a 10, po něm eskalace na plný plán nebo analytika. Očekávaný efekt: podíl nerozhodnutých ≤ 10 % (bez stropu 15 až 80 %, Z3). Metrika: podíl nerozhodnutých, p90 času do rozhodnutí. Zamítnutí: podíl nerozhodnutých > 15 % nebo p90 času se nezlepší.

**H-8. Smíšený výběr (nejistota + anomálie + náhoda) pro vzácné rodiny.** Změna: alokovat rozpočet 50/25/25 místo jen anomálií. Očekávaný efekt: lepší recall vzácných rodin (c2_beacon, rogue_device), jen-anomálie nejhorší (Z6). Metrika: recall c2_beacon a rogue_device při fixním rozpočtu. Zamítnutí: smíšený výběr nepřekoná jen-anomálie (95 % CI překrývá 0).

**H-9. Kalibrace jako předpoklad VOI.** Změna: izotonická kalibrace Case Memory před výpočtem EVOI. Očekávaný efekt: nižší Brier a lepší H-3 (extrapolace, bez přímého důkazu). Metrika: Brier, výsledek H-3 s kalibrací a bez. Zamítnutí: kalibrace nezlepší H-3 o ≥ 5 % relativně.

## 8. Hrozby validity

- Konstrukční: nenašli jsme jedinou práci, která by měřila celou RQ (počet kontrol, FP i čas současně na alertech). Tvrzení Z1 až Z13 skládáme z částí, které jsou měřeny na různých úlohách (skenery, botnety, malware, podvody).
- Čtení: čísla z TRW, RBS a JCV jsou z `pdftotext -layout` převodu tabulek; sloupec "N" v Tab. 8 jsme přiřadili podle textu o 4,1 adrese a Snort "více než 13 IP"; kompozitní Tab. 4 u RBS má v převodu zlomené záhlaví. U sloupců, které jsme nemohli přiřadit s jistotou, je to v extrakci poznamenáno.
- Reprezentativnost: TRW a RBS pocházejí z let 2003 až 2004 (výzkumné laboratoře, ISP), BotSniffer/BotProbe z IRC botnetů 2007 až 2009. Dnešní provoz (šifrování, cloud, IoT) se liší. Aktuální práce o triáži jsou z velké části preprinty (Carbon Filter, AACT, imbalance DeepCASE, Jasmine, Ziai).
- Zkreslení publikací: negativní výsledky se objevují hlavně jako přehodnocení (Alsaleh, DeepCASE imbalance); příspěvky bez nasazení převažují (Z13).
- Sdílená data: AI², Chen a ActDroid nejsou síťové alerty; Jasmine a Ziai využívají zastaralá data.
- Nezávislá kontrola §9: provedena 2026-10-31 (48 z 57 řádků, 84 %; věcná chybovost 2,1 %, neověřitelných 0; PŘIJATO S OPRAVAMI). Zbývající riziko: pole `limity_autoru` a `riziko_zkresleni` byla kontrolována jen okrajově, venue NoDoze, Kim a Dán a Sudyana nebyla ověřována nad rámec titulní strany a řádek 048 zůstává V2. Kontrola ani revize nemají vlastní měření, jen znovu čtou zdroje.
- Chybějící citační řetězení: referenční seznamy všech klíčových prací nebyly systematicky procházeny dopředu ani dozadu.
- Citace v extrakci: citace jsou krátké úryvky z převodu textu; u dvou řádků jde o parafrázi po zalomení textu (id 017, 026).

## 9. Co NEBYLO nalezeno

- Přímé měření hodnoty informace (VOI), banditu nebo POMDP pro výběr ověřovací kontroly bezpečnostního alertu s metrikou počtu kontrol, FP a času. Nalezené POMDP práce řeší odpověď, ne ověřování.
- Kvantitativní měření honeypot-confirmation jako ověření alertu; jen starší koncepční poznámky.
- Nezávislé měření času analytika při SOAR obohacení (enrichment cascade) v recenzované práci; vendor čísla nepoužita.
- Prahová analýza evaze SPRT (útočník drží míru neúspěchu těsně pod prahem); jen kvalitativní úvahy (Jung, Ganesh).
- Veřejná studie ILAB (úspora štítků v uživatelském experimentu) a Sandia ALAT: nelze otevřít (V1).
- Studie, která měří, kolik analytik ušetří minut aktivním učením, ne jen štítků.
- Replikace AI² na síťových alertech.
- Kvantifikace rizika aktivního skenování: jen kazuistiky a laboratorní testy; prevalence pádů zařízení nezjištěna (ORDR "40 %" je vendor bez zdroje).
- Kvantifikace sekvenčního testu pro pomalý beaconing a lateral movement na tokových datech.
