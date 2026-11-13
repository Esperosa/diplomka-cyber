# Protokol systematické rešerše a metastudie (závazný)

Verze 1.0, 2026-10-31. Platí pro všechny studie RQ1–RQ6 v tomto adresáři. Předchozí návrhy jsou v `_predbezne/` a **nesmí se citovat jako důkaz**: vznikly ze shrnutí vyhledávače, ne z plných textů.

## 1. Účel
Podklad pro rozhodnutí, jak vylepšit korelační a ověřovací jádro programu Salticus (nižší šum, vyšší úspěšnost, univerzálnost). Studie musí být reprodukovatelná, každý závěr dohledatelný na konkrétní důkaz a každá nejistota přiznaná.

## 2. Výzkumné otázky
- **RQ1** Které metody korelace a agregace alertů do incidentů mají publikované měření snížení falešných poplachů a o kolik, za jakých podmínek?
- **RQ2** Které statistické postupy (adaptivní/sezónní baseline, detekce změn, řízení míry chyb FDR, kalibrace, konformní metody) mají doložený vliv na FPR/TPR u síťových anomálií?
- **RQ3** Jak sekvenční ověřování, aktivní učení a hodnota informace (VOI) mění počet potřebných kontrol, falešné poplachy a čas do rozhodnutí při triáži/verifikaci bezpečnostních alertů?
- **RQ4** Jaká je publikovaná výkonnost (TPR/FPR/latence, dataset) detekce beaconingu a C2, DNS tunelů, exfiltrace, lateral movementu a pivotingu, reverse/bind shellů a interaktivních relací z tokových a Zeek dat?
- **RQ5** Jak validní jsou benchmarky a syntetická/simulovaná data (známé chyby datasetů, sim-to-real mezera, přenos mezi datasety) a jak testovat bez cirkularity?
- **RQ6** Přináší dedukce/abdukce, pravděpodobnostní logika a LLM triáž empiricky měřitelné zlepšení při ověřování alertů a s jakými riziky?

## 3. Strategie hledání (reprodukovatelná)
- Zdroje: arXiv, ACM DL, IEEE Xplore (abstrakt + DOI), USENIX, NDSS/ACSAC/RAID/CCS/S&P (sborníky), Semantic Scholar, DBLP, Google Scholar (přes webové vyhledávání), technické zprávy NIST/ENISA, repozitáře dat (Zenodo, UNB, CTU).
- Období 2015–2026; starší jen zakládající práce, označit `seminal=ano`.
- Jazyk EN/CS.
- Každý dotaz se zapisuje do `hledani.csv`: `datum;zdroj;dotaz;pocet_vysledku;prohlizeno;poznamka`. Minimálně 15 dotazů na RQ, z toho aspoň 3 dotazy „proti“ (hledání negativních výsledků a kritiky: `limitations`, `fails`, `does not generalize`, `false positives`, `replication`).
- Citační řetězení: u každé zahrnuté práce projít odkazy dopředu i dozadu (alespoň u 5 klíčových).

## 4. Kritéria zahrnutí
Zahrnout, pokud: (a) obsahuje empirické měření na datech (reálných, veřejných či simulovaných s popsaným ground truth), (b) uvádí aspoň jednu metriku (TPR/recall, FPR, precision, F1, AUC, počet alertů před/po, čas), (c) popis metody je dost podrobný pro posouzení použitelnosti, (d) je dohledatelná v plném textu nebo oficiálním abstraktu s DOI/arXiv ID.
Vyloučit: čisté marketingové materiály výrobců (smí být v samostatné tabulce „tvrzení výrobců“, ne v závěrech), blogy bez dat, práce bez metriky, duplikáty (zachovat nejnovější verzi), práce, které nejdou ověřit.

## 5. Úrovně ověření zdroje (povinné u každého řádku)
- **V3** přečten plný text nebo oficiální PDF, hodnota nalezena v tabulce/textu (uvést sekci/tabulku/stranu a doslovnou citaci ≤ 25 slov).
- **V2** přečten oficiální abstrakt/stránka venue s číslem, plný text nedostupný.
- **V1** jen shrnutí vyhledávače nebo sekundární zdroj.
- **V0** nenalezeno / jen připomenutí z paměti.
Do závěrů smí **jen V3 a V2**; V1/V0 se uvedou v příloze „neověřeno“. Čísla se nikdy nepřepisují z paměti.

## 6. Úrovně důkazu (kvalita designu)
E1 systematický přehled/metastudie s kvantitativní syntézou; E2 kontrolovaný experiment s reálnými daty a více datasety, replikace; E3 experiment na jednom datasetu nebo simulaci; E4 provozní/případová zpráva, whitepaper s daty; E5 názor/koncept bez dat. Samostatně `riziko_zkreseni` (nízké/střední/vysoké) podle: duplicity v train/test, label leakage, jediný dataset, neuvedené FPR, ladění na testu, absence variance/CI, chybějící baseline.

## 7. Extrakční tabulka (`extrakce.csv`, oddělovač `;`, UTF-8)
Sloupce: `id;rq;citace;url_nebo_doi;rok;venue;recenzovano;seminal;dataset;typ_dat;metoda;baseline;metrika;hodnota;ci_nebo_sd;podminky;limity_autoru;E;riziko_zkreseni;V;umisteni_a_citace;pouzitelnost_pro_salticus;poznamka`.
`id` ve tvaru `RQ1-001`. `umisteni_a_citace` povinné u V3 (např. „Tab. 4, s. 9: ‚…‘“).

## 8. Syntéza
- Kvantitativní souhrn jen při ≥ 3 studiích se stejnou metrikou a srovnatelnými podmínkami; jinak rozsah (min–medián–max) bez sdružování. Žádný vážený průměr nesrovnatelných čísel. Vždy uvést počet studií, datasetů a heterogenitu.
- Každá studie končí tabulkou **Závěry**: `Z-id; tvrzení; důkazy (id řádků extrakce); jistota (vysoká/střední/nízká/velmi nízká); důvody snížení jistoty (zkreslení, nekonzistence, nepřímost, nepřesnost, publikační zkreslení); použitelnost pro Salticus (ano/s úpravou/ne); doporučená akce`.
- Tvrzení bez id důkazu se nesmí objevit v sekci Závěry. Rozpory mezi studiemi se uvádějí a vysvětlují, ne vyhlazují.
- Samostatná sekce **Co NEBYLO nalezeno** (mezery, nenalezené negativní výsledky) a **Hrozby validity**.
- Samostatná sekce **Překlad do praxe**: konkrétní parametry/postupy s odkazem na důkazy a s označením, co je extrapolace (a proč).
- Počty PRISMA: identifikováno → po deduplikaci → po screeningu názvů/abstraktů → plný text zhodnocen → zahrnuto → z toho V3/V2. Uvést i důvody vyloučení (souhrnně).

## 9. Nezávislá kontrola
Druhý kontrolor bez znalosti závěrů znovu načte vzorek ≥ 30 % řádků V3/V2 (včetně všech, na nichž stojí závěry vysoké jistoty) a porovná hodnoty se zdrojem. Chybovost > 5 % v uvedených hodnotách znamená, že se celá extrakce RQ musí projít znovu. Výsledek je v `kontrola-RQn.md`.

## 10. Empirické ověření (po rešerši)
Z každé studie vzejdou předregistrované hypotézy `H-n` ve formátu: změna → očekávaný efekt (rozsah z důkazů) → metrika → scénář/seedy → kritérium zamítnutí. Testuje se na soak harnessu (A/B na stejných seedech, držené rodiny útoků, kotva CTU-13/IoT-23). Zveřejní se i neúspěšné hypotézy.

## 11. Pravidla pro autory
Žádné vymyšlené odkazy ani hodnoty. Když zdroj nejde otevřít, napsat to. Nesrovnatelné metriky nesčítat. Vlastní odhady označit „odhad autora“ a uvést postup. Čeština, přesná terminologie, první použití zkratky vysvětlit.
