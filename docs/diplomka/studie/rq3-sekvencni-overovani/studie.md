# RQ3: Sekvenční ověřování, aktivní učení a hodnota informace při triáži a verifikaci alertů

Verze 1.0, 2026-10-31. Řídí se `00-protokol.md` (v1.0). Extrakce: `extrakce.csv` (57 řádků), dotazy: `hledani.csv`, neověřené zdroje: `neovereno.md`. Nezávislá kontrola podle §9 protokolu dosud neproběhla (viz Hrozby validity).

## 1. Abstrakt s hlavními závěry

Otázka: jak sekvenční ověřování (Waldův SPRT, Threshold Random Walk), aktivní učení a hodnota informace mění počet kontrol, falešné poplachy a čas do rozhodnutí.

Přečetli jsme 30 zdrojů, z nich 27 vstoupilo do extrakce (26 × V3, 1 × V2). Hlavní zjištění:

1. Sekvenční testy rozhodují po jednotkách pozorování. TRW potřeboval v průměru 4,06 až 4,08 distinct cílových IP, Bro 21,4 až 36,9, Snort 6,0 až 14,1 (Jung 2004, 2 sítě). Kombinace RBS+TRW rozhodla po 5,0 až 6,9 prvních spojeních, aktivní sondy BotProbe po 2 až 4 kolech. Jistota: střední.
2. Nezávislé přehodnocení TRW (Alsaleh 2011) našlo 19 až 50 % falešných objevů podle parametrů. Přidání znalosti o službách (stavový TRW) odstranilo podle shrnutí autora 29 % a 77 % falešných poplachů ve dvou datasetech (v textu k druhému datasetu 94 %; rozdíl mezi těmito údaji v disertaci není vysvětlen), bez snížení detekce. Rozpor s původním článkem je uveden v §4. Jistota: střední.
3. Sekvenční test nemá přirozený strop počtu pozorování a nerozhoduje vždy: TRW ponechal více než 80 % vzdálených hostů nerozhodnutých, BotProbe 15,4 % uživatelů po 3 kolech. Evazi (úspěšná spojení na známé servery) autoři označují za snadnou, ale nezměřili ji. Jistota: střední (rozhodovací problém), nízká (evaze).
4. Aktivní učení s analytikem zvyšuje detekci při pevném rozpočtu: recall 0,868 při 200 vyšetřených entitách denně proti 0,737 při 1000 denně u čistě nesupervizovaného detektoru (AI², 3,6 mld. řádků logu); 8× levnější štítky při F1 nad 89 % (Android malware). Jistota: střední, přenositelnost na síťové alerty je nepřímá.
5. Kaskáda levný filtr → drahý ověřovač šetří čas (5 024 s → 1 780 s, tj. −65 %, odhad z dvou čísel), ale recall se ztrácí: 0 % škodlivých ztraceno na jednom, 5,7 % na druhém datasetu (Carbon Filter). Jistota: střední pro směr, nízká pro velikost.
6. Externí přehodnocení často vychází hůř než původní tvrzení (NoDoze AUC 0,60 v ATLASv2, DeepCASE ~30 % slabých vysvětlení při nepoměru tříd). Jistota: nízká.
7. Aktivní ověření expozice zlepšilo přesnost v testbedu (99,64 % → 0 % nerelevantních alertů, jedna testbed), ale přináší doložená rizika: pád PLC vyžadující výpadek napájení, změna toku uživatelů u sond. Jistota: nízká (kvalita), střední (existence rizika).
8. Publikační obraz je zkreslený k benchmarkům: ze 87 jádrových studií přehledu (2015 až 2026) se 78 opírá o veřejné benchmarky (65) nebo simulaci (13).

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
| Jung 2004, LBL | FP TRW | 33, z toho 29 crawlery a proxy | 006 |
| Schechter 2004 (kompozit) | alarmy / detekce / efficiency / effectiveness | 34 / 11 / 0,324 / 0,917 (throttle 10 / 5 / 0,500 / 0,417) | 010 |
| Jung 2008 | FP za hodinu | 0,07 (Lab-II), 0,57 (ISP) | 014 |
| Gu 2008 BotSniffer | FPR | 0,0016 (11 z 6 848), cíl α = 0,005 | 023 |
| Alsaleh 2011, TRW | podíl FP z označených | 19 % až 50 % (47 % při výchozích parametrech) | 018, 019 |
| Alsaleh 2011, STRW | odstraněno FP TRW | 29 % a 77 % (dva datasety), 94 % v dalším experimentu | 020, 022 |

Zjištění a protiklady:
- Rychlost je dobře doložena napříč čtyřmi pracemi (rozsah 2 až 10 pozorování), vždy proti pevným prahům Bro/Snort nebo throttle; porovnání jsou ale na stejných datech, na kterých se ladily parametry (riziko zkreslení střední až vysoké).
- Rychlé rozhodnutí má cenu v objemu: TRW označil ~14 000 skenerů proti 122 u Bro a operátoři nemohli blokovat tisíce adres denně (id 007). Vyšší TPR bez dalšího filtru jen přesouvá práci.
- TRW klasifikuje málo hostů: méně než 20 % rozhodnuto, přes 80 % čeká (id 021).
- Limity modelu: oscilace úspěch/neúspěch nikdy nepřekročí práh (009); topologické červy test nezachytí (013); zavedení maximálního počtu pozorování řeší návrh v arXiv 1204.1935 (017, jen numerické experimenty bez reálných dat).
- Nezávislé přehodnocení (Alsaleh) zvyšuje FP až na polovinu; příčina: přechodně nedostupné služby. Mapa služeb jako orákulum (STRW) FP snižuje a detekci neuberou.

### (b) Bayesovské sekvenční rozhodování, POMDP a bandit pro výběr kontroly

Přímých měření je málo. Literatura o POMDP v kyberbezpečnosti se soustředí na odpověď na útok (CAGE-2, OT, agentní IR), ne na výběr ověřovací kontroly. Dvě zahrnuté práce:
- Kim a Dán 2025 (HMM, aktivní učení, politiky MaxEntropy/Bayes pro výběr alertu k vyšetření): MSE belief až o 50 % nižší než u základních politik, redukce stavového prostoru zkrátila výpočet o 85 % (id 056). Simulace, E3.
- Hammar a Stadler 2022 (optimální zastavování): optimální strategie mají prahovou strukturu, v emulaci lepší než Snort IPS práh (057). Čísla jsou jen v grafech.
- Nepřímo: SPRT je speciální případ prahové strategie optimálního zastavování (extrapolace, nikdo to experimentálně nesrovnal na alertech).
- Agentní IR (Gao 2026) −15,1 % času obnovy, +33,6 % míry obnovy, simulace (055); mimo ověřování.

Vyhledávání bandit/VOI pro výběr hostů ke sondování nic přímého nenašlo (viz §9).

### (c) Aktivní učení a uncertainty sampling při triáži

| Práce | Doména | Efekt | id |
|---|---|---|---|
| Veeramachaneni 2016 (AI²) | logy webové platformy, 12 týdnů | recall 0,868 při k=200/den vs 0,737 u nesupervizovaného při k=1000; 3,41× detekce, FP 5× nižší; 143 resp. 211 vs 42 z 318 útoků | 029, 030, 031 |
| Chen 2023 | Android malware, drift | 8× levnější štítky (50 vs 400 vzorků/měs. při F1 > 89 %); FNR 14 % → 9 %, FPR 0,86 % → 0,48 %; bez učení FNR 38 % za 7 let | 036, 037, 038 |
| ActDroid 2024 | Android | až 76 % méně štítků | 039 |
| Ziai 2019 | KDD99 | F1 0,90 → 0,98 po 10 dotazech; selhání při prevalenci pod 0,01 % | 034, 035 |
| Klein 2021 (Jasmine) | NSL-KDD, UNSW-NB15 | F1 plně označeného GBM ~0,760 vs ALADIN ~0,720; samotné dotazy na anomálie jsou špatná strategie, smíšená strategie robustnější | 032, 033 |

Kritika: tři z prací jsou na zastaralých datasetech (KDD99, NSL-KDD); AI² počítá podvody na jedné platformě; Chen je malware s časovým driftem, ne síťový alert. Všichni předpokládají důvěryhodné štítky jednoho analytika (Ziai to přiznává). Úspora štítků je nejsilnější výsledek, ale měří se ve štítcích, ne v minutách analytika.

### (d) Automatické obohacení a verifikace alertů

| Práce | Metoda | Výsledek | id |
|---|---|---|---|
| AACT 2025 (Sophos MDR, 6 měsíců provozu) | učení z akcí analytiků | −61 % alertů zobrazených analytikům, FNR 1,36 %; offline 34 % odstraněno při FNR 1,5 % | 044, 045 |
| DeepCASE 2022 | kontext + štítkování shluků | 86,72 % událostí filtrováno, práce −90,53 %, podhodnocení rizika < 0,001 % | 046 |
| Replikace DeepCASE 2025 | 24,5 M Suricata alertů | při nepoměru tříd ~30 % vysvětlení má kosinovou podobnost ≤ 0,25 | 047 |
| NoDoze 2019 (V2) | provenance, 364 alertů | −86 % falešných poplachů | 048 |
| Carbon Filter 2024 | kontext spuštění procesu | AUC 0,94 vs NoDoze 0,60 a RapSheet 0,90 na ATLASv2 | 043 |
| Kruegel 2004 | aktivní ověření (Nessus) uvnitř Snortu | 6 659 alertů, 24 relevantních; nerelevantních 99,64 % → 0 % | 049 |

SOAR a obohacovací kaskády jako takové (enrichment) nemají ve zdrojích nezávislé kvantitativní měření času; jediná data o času jsou provenance (Carbon Filter, Tab. 6: NoDoze 10,23 s na alert, RapSheet 53,98 s). Vendor tvrzení jsou jen v `neovereno.md`.

### (e) Kaskády: levný filtr → drahý ověřovač

| Práce | Úspora | Ztráta | id |
|---|---|---|---|
| Carbon Filter, TAU | 82,5 % FP odstraněno | 0 % škodlivých ztraceno (108 z 108) | 040 |
| Carbon Filter, MDR | 84 % FP odstraněno | 5,7 % škodlivých ztraceno (58 z 1 003) | 041 |
| Carbon Filter + NoDoze, ATLASv2 | 5 024,2 s → 1 780,02 s (317 z 491 alertů potlačeno filtrem) | recall ztráta nepublikována samostatně | 042 |
| AACT | 61 % alertů mimo frontu | FNR 1,36 % | 044 |
| Sudyana 2025 (flow → paket) | až 24× nižší výpočet | detekce 95 % (flow) a 100 % (paket) u neviděných útoků | 052 |

Ztráta recallu není nulová a liší se 0 až 5,7 % mezi datasety stejného systému (id 040 vs 041). Jde o preprinty a o jednu publikovanou práci (Sudyana, "až 24×" je maximum).

### (f) Aktivní ověřování a jeho rizika

Přínos: Kruegel 2004 (49), BotProbe (25, 26), STRW s aktivní mapou služeb (20, 22). Rizika:
- Samanis 2022: jeden PLC při Nmap s určitými příznaky vstoupil do poruchového stavu vyžadujícího vypnutí napájení, druhé zařízení selhalo při technice více nástrojů (053). Jde o kazuistiku, prevalenci neznáme.
- BotProbe: sondy mění tok uživatelů, autoři sami říkají, že "a more formal study of cost-benefit analysis and risk assessment is needed" (027), 15,4 % uživatelů zůstalo po 3 kolech nerozhodnuto (025).
- Kruegel: skener sám může mít FP a FN (049).
- Evaze: úspěšná "maskovací" spojení posouvají random walk pryč od rozhodnutí (008), pomalé skeny unikají (028).
- Randomizace volby: deterministické pořadí kontrol je zneužitelné; ARL politika ~50 % lepší než uniformní a ta mnohem lepší než priority Suricaty (050), u audit hry je předvídatelné pořadí nejhorší (051).

## 4. Syntéza

Kvantitativní souhrn (§8 protokolu) jsme nesdružovali: žádná metrika nemá ≥ 3 studie s totožnou definicí a srovnatelnými podmínkami. Rozsahy:
- pozorování do rozhodnutí: 2 až 10 (4 práce, tři různé jednotky);
- snížení pracovní zátěže analytika: 34 až 90,53 % (AACT offline 34 %, nasazení 61 %, DeepCASE 90,53 %, NoDoze 86 %); různé definice a datasety, heterogenita velmi vysoká;
- úspora štítků: 8× (Chen), až 76 % (ActDroid), 5× méně vyšetřených entit při vyšším recallu (AI², přibližně z k = 200 vs 1000);
- ztráta recallu při kaskádě: 0 až 5,7 % (Carbon Filter), FNR 1,36 % (AACT), < 0,001 % (DeepCASE, jiná definice).

Rozpory:
1. Jung 2004 říká o TRW "very few false positives"; Alsaleh 2011 naměřil 19 až 50 % falešných objevů. Možné vysvětlení (nepotvrzeno): Jung určuje "pravdu" heuristickou klasifikací a nepovažuje crawlery/proxy za chyby plánovače, Alsaleh používá mapu služeb jako přísnější ground truth a prostředí s přechodnými službami. Podobně Carbon Filter cituje NoDoze jako 84 %, NDSS stránka říká 86 %, a na ATLASv2 měří AUC jen 0,60.
2. Originální tvrzení DeepCASE (< 0,001 % podhodnocení) vs externí zjištění o slabých vysvětleních při nepoměru tříd. Důvod: odlišné datasety a různá míra nepoměru.
3. Alsaleh uvádí odstranění 29 % a 77 % FP (shrnutí) i 94 % (text k druhému datasetu); jde o dvě různé míry/datasety a disertace je nesjednocuje. Čísla nelze sloučit.
4. Uncertainty sampling je silný (Ziai F1 +0,08 za 10 dotazů, AI²), ale selhává při nízké prevalenci (Ziai, Nmap < 0,01 %) a driftu (Chen 2023). Jasmine to řeší směsí dotazů.

## 5. Závěry

| Z-id | Tvrzení | Důkazy | Jistota | Důvody snížení | Použitelnost pro Skákavku | Doporučená akce |
|---|---|---|---|---|---|---|
| Z1 | Sekvenční test s nastavenými α a β rozhoduje o skeneru po ~4 až 10 pozorováních, výrazně dříve než pevné prahy Bro a Snort (4,06 až 4,08 vs 6,00 až 36,91). | 001, 002, 011, 015 | střední | stejná data pro ladění a test, 2 až 4 sítě, bez CI, hlasité cíle (červi, skenery) | s úpravou | testovat SPRT nad sérií ověření (H1) |
| Z2 | Skutečná FPR sekvenčního testu závisí na modelu "neúspěch = skenování": 19 až 50 % FP při Alsalehově přehodnocení, a kontext služeb odstraní 29 až 94 % těchto FP bez ztráty detekce. | 018, 019, 020, 022, 006 | střední | jedno nezávislé přehodnocení, dva až tři datasety, jiná definice FP (FD rate) | ano | brát znalost služeb jako povinný vstup (H2) |
| Z3 | Sekvenční test nerozhoduje vždy: TRW ponechal > 80 % hostů nerozhodnutých, BotProbe 15,4 % po 3 kolech; hrozí oscilace a nepohlcení. Nutný strop počtu kontrol a eskalace. | 021, 025, 009, 017 | střední | 017 jen simulace; 021 z disertace | ano | N_max + eskalace (H7) |
| Z4 | Cíl α a β se v pozorování plnil: BotSniffer FPR 0,0016 < α 0,005; RBS+TRW 0,07 až 0,57 FP/hod. | 023, 014 | nízká | malé n (5 pozitiv/dataset, 8 botnetových stop), ladění na stejných datech | s úpravou | brát α, β jako nastavitelné parametry, ne jako záruku |
| Z5 | Aktivní učení s analytikem zvyšuje detekci při pevném rozpočtu a šetří štítky (AI²: recall 0,868 při 200/den vs 0,737 při 1000/den; Chen 8×). | 029, 030, 031, 036, 037, 039 | střední | jiné domény (podvody, malware), jeden dataset u AI², preprinty | s úpravou | EVOI nebo entropie pro řazení plánů (H3) |
| Z6 | Uncertainty sampling selhává při velmi nízké prevalenci a při driftu; samotné dotazy na anomálie jsou špatné; směs je robustnější. | 035, 033, 038, 032 | nízká | zastaralé datasety (KDD99, NSL-KDD) | ano | míchat uncertainty + anomálie + náhodu (H8) |
| Z7 | Kaskáda levný filtr → drahý ověřovač zkracuje čas ověřování (−65 % ve dvou datasetových číslech, "až 24×" výpočet), ale recall klesá o 0 až 5,7 %. | 040, 041, 042, 044, 052 | střední (směr), nízká (velikost) | preprinty, jiná definice ztráty, dva datasety, 491 alertů | s úpravou | filtr s měřenou ztrátou recallu per rodina (H4) |
| Z8 | Externí přehodnocení často vychází hůře než autorské tvrzení (NoDoze AUC 0,60; DeepCASE ~30 % slabých vysvětlení). | 043, 047, 048 | nízká | nepřímé srovnání, jiná data | ano | nepřebírat čísla autorů, měřit na vlastním harnessu |
| Z9 | Aktivní ověření expozice výrazně sníží nerelevantní alerty v testbedu (99,64 % → 0 %), ale přenos na provoz není měřen. | 049, 020 | nízká | jedna testbed, syntetické útoky | ano s úpravou | ověření expozice před typováním (H5) |
| Z10 | Aktivní ověřování má doložená rizika: pád PLC vyžadující power cycle; sondy mění provoz uživatelů a nechávají část případů nerozhodnutou. | 053, 027, 025 | střední (existence), velmi nízká (prevalence) | kazuistika, malý počet zařízení | ano | passive-first pro OT/IoT, schválení a rozpočet sond |
| Z11 | Předvídatelné pořadí kontrol je zneužitelné; náhodnost a robustní politika zlepšují výsledek (~50 % vs uniformní). | 050, 051, 008 | nízká | modelové náklady (CVSS), simulace | s úpravou | randomizovat část výběru (H6) |
| Z12 | Entropie belief jako proxy hodnoty informace snižuje MSE o stavu útoku až o 50 % proti jednoduchým politikám (simulace). | 056, 057 | nízká | pouze simulace, "až" | s úpravou | EVOI-proxy v plánovači (H3) |
| Z13 | Většina literatury stojí na benchmarcích a simulaci (78 z 87), málo na provozu; E2 evidence není. | 054 | střední | autoři prehledu hodnotí i vlastní práce | ano | vlastní soak harness je důležitější než čísla z literatury |

## 6. Překlad do praxe

Parametry označené "extrapolace" nemají přímý důkaz v našem kontextu.

1. Sekvenční ověření per host: akumulovat výsledky ověřovacích kontrol (úspěch/neúspěch, shoda/neshoda) jako poměr věrohodností, α a β nastavit explicitně a zaznamenávat. Doložené řády: rozhodnutí po 4 až 10 pozorováních (001, 011, 015). Extrapolace: u nás je pozorováním ověřovací plán, ne spojení.
2. Povinný strop N_max a eskalace nerozhodnutých (Z3). Jung ponechal > 80 % nerozhodnuto, BotProbe 15,4 % po 3 kolech. Extrapolace pro hodnotu N_max (3 až 10 kontrol).
3. Kontext služeb jako orákulum: neúspěšné spojení na neexistující službu je důkaz, na přechodně nedostupnou službu ne (Z2). U nás: inventář expozice (už 100% spolehlivá cesta v soak v1) použít k tomu, aby `unmapped_passive_event` a podobné nepočítaly jako neúspěch skenu.
4. Rozpočet ověřování nenést FIFO: řadit plány podle odhadu hodnoty informace (entropie belief nebo nejistota Case Memory, Z5, Z12). V soak v2 (snapshot `status.md`) bylo z 48 333 897 plánů provedeno 2 061 617 (4,3 %), znovu využito 1 924 414 (4,0 %) a mimo rozpočet 44 179 698 (91,4 %; procenta vlastní výpočet). Při takové propustnosti rozhoduje pořadí. AI² ukazuje, že při 5× menším počtu vyšetřených entit lze dosáhnout vyššího recallu (jiná doména).
5. Kaskáda: levný pasivní skór před drahým aktivním ověřením, ale s prahem vázaným na měřenou ztrátu recallu v držené rodině útoků (Z7). Pro rodiny s nízkou detekcí (c2_beacon 12,8 %, rogue_device 8,0 % ve snapshotu v2) filtr nepřitvrzovat, protože v1 už ztrácí recall dříve než kaskáda.
6. Aktivní ověření: passive-first, per třída zařízení (OT/IoT/křehká) bez aktivního skenu bez schválení a rozpočtu (Z10); sondy označit, logovat, nerozhodnuté vracet jako "nerozhodnuto", ne jako zamítnuto. Naše invarianty (0 porušení rozpočtu, schválení, scope) toto už kryjí; stojí za to doplnit třídu zařízení.
7. Nepřebírat čísla z literatury (Z8): publikované FP redukce 84 až 97 % pocházejí z malých testbed; Carbon Filter sám uvádí, že provenance triáž pro komerční EDR neškáluje.
8. Randomizace: část výběru kontrol (např. 10 až 20 %, extrapolace) losovat, aby pořadí nebylo předvídatelné a pro odhad nezkreslených FN (Z11).

Souvislost s našimi měřeními (`soak-findings.md` v1 a `status.md` v2, hodnoty se mění):
- FP u benigních lookalike: v2 authorized_scanner 44,6 % s falešným nálezem, flash_crowd 80,0 %, backup_burst 75,2 % [Wilson]. Odpovídá Jung 2004 (crawlery a proxy tvoří 29 z 33 FP u TRW, id 006) a Alsaleh (přechodné služby jako zdroj FP, id 018). Mapa služeb a kategorizace hostů ("friendly hosts", Jung) jsou doložené postupy.
- Bezpříčinné behaviorální nálezy: v1 210,7 na síť-den, v2 snapshot 1 255,9 na síť-den. Literatura o sekvenčních testech tento typ šumu (objemové anomálie) neřeší; je to jiná třída signálu.
- c2_beacon 4,7 % (v1) a 12,8 % (v2) detekováno, medián latence 360 až 420 min: SPRT práce o botnetech (BotSniffer 100 % na 8 stopách, BotProbe 100 % na IRC) nejsou srovnatelné s pomalým beaconingem; jde o IRC/HTTP boty bez evaze (id 024, 026).
- exploit_attempt: IDS vidí, správný typ 0 %. Kruegel 2004 (id 049) nabízí ověření expozice, ale měří jen filtrování nerelevantních alertů, ne typování.
- Kalibrace Case Memory: Brier 0,0107 (v1) a 0,0290 (v2), naivní referenční 0,25 v obou; přeúvěrnost v rozsahu 0,1 až 0,5 podle v1. Literatura o VOI vyžaduje kalibrované pravděpodobnosti; EVOI nad nekalibrovaným modelem je riziko (extrapolace, žádná práce to neměřila).

## 7. Hypotézy k empirickému ověření (soak harness)

Formát: změna → očekávaný efekt (rozsah z důkazů) → metrika → scénář/seedy → kritérium zamítnutí. Testovat A/B na stejných seedech, držené rodiny útoků, kotva CTU-13/IoT-23. Zveřejnit i neúspěch.

**H-1. Sekvenční akumulace ověření místo jednorázové kontroly.** Změna: per-host součet logaritmů věrohodností s nastavitelným α a β, rozhodnutí při překročení prahu. Očekávaný efekt: medián počtu ověření na rozhodnutí ≤ 7 a pokles FP na lookalike oproti jednorázovému prahu (Z1: 4 až 10 pozorování; extrapolace do jiné jednotky). Metrika: medián a p90 počtu ověření na rozhodnutí, TPR a FP na síť-den. Scénář: port_scan_horizontal, port_scan_vertical, slow_scan a lookalike authorized_scanner, flash_crowd; ≥ 10 seedů. Zamítnutí: medián kontrol není ≥ 30 % nižší než baseline, nebo TPR slow_scan klesne o > 2 procentní body (Wilson 95 %).

**H-2. Kontext služeb pro neúspěšné spojení.** Změna: neúspěch na službě, která nikdy nebyla v inventáři expozice, se nepočítá do skenovacího skóre; neúspěch na známé, přechodně nedostupné službě se tlumí (STRW logika). Očekávaný efekt: 29 až 77 % méně FP skenovacích nálezů (Z2) při stejné TPR. Metrika: FP nálezů skenu na síť-den u lookalike (authorized_scanner, flash_crowd, backup_burst, ntp_fanout), TPR rodin skenů. Zamítnutí: pokles FP < 20 % nebo TPR pokles > 2 p. b.

**H-3. Pořadí plánů podle hodnoty informace místo FIFO.** Změna: řazení ověřovacích plánů podle entropie belief nebo odhadu EVOI z Case Memory při stejném počtu provedených kontrol. Očekávaný efekt: víc potvrzených pravdivých nálezů na tisíc provedených kontrol (AI²: vyšší recall při 5× menším počtu vyšetřených, Z5; Kim a Dán: MSE až −50 %, Z12; zde konzervativní extrapolace ≥ 1,3×). Metrika: potvrzené TP na 1000 provedených kontrol, recall při fixním rozpočtu (1× a 0,5× aktuálního). Scénář: celý soak profil, 5 až 10 seedů. Zamítnutí: relativní zisk < 10 % nebo CI zahrnuje 0.

**H-4. Kaskáda s měřenou ztrátou recallu.** Změna: levný pasivní filtr vyřadí alerty s nízkým rizikem před drahým aktivním ověřením. Očekávaný efekt: −50 až −65 % nákladu ověření (Z7: −65 % ve dvou číslech), ztráta recallu 0 až 5,7 %. Metrika: počet provedených aktivních ověření, recall podle rodiny, ztracené útoky v držené rodině. Zamítnutí: úspora < 30 % nebo ztráta recallu > 2 p. b. v jakékoli rodině s n ≥ 100.

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
- Nezávislá kontrola §9: dosud neprovedena. Nebyl spuštěn druhý agent s přečtením ≥ 30 % řádků V3/V2; do té doby jsou hodnoty zapsané v extrakci hodnotami jednoho čtenáře. Doporučeno ověřit nejdřív řádky, na nichž stojí Z1, Z2, Z5, Z7 (001, 002, 011, 015, 018 až 022, 029 až 031, 036, 040 až 042).
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
