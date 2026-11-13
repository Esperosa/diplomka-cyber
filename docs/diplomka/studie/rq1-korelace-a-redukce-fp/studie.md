# RQ1: Korelace a agregace alertů do incidentů a měřené snížení falešných poplachů

Datum: 2026-10-31. Protokol: `docs/diplomka/studie/00-protokol.md` v1.0. Extrakce: `extrakce.csv` (58 řádků, všechny V3; 48 s číselnou hodnotou; řádky 057 a 058 přidány po nezávislé kontrole). Revize po kontrole: `revize-RQ1.md`, kontrolní zpráva `kontrola-RQ1.md`. Hledání: `hledani.csv` (36 dotazů, z toho 5 „proti“). Neověřené: `neovereno.md`.

Poznámka k souboru `extrakce.csv`: text sloupců je psán bez diakritiky (technické omezení zápisu). Čísla a citace v angličtině jsou beze změny.

## 1. Abstrakt a hlavní závěry

Otázka: které metody korelace a agregace alertů do incidentů mají publikované měření snížení falešných poplachů, o kolik a za jakých podmínek.

Co jsem zjistil (podrobnosti a id důkazů v oddíle 5):

1. **Redukce počtu alertů je ve studiích velká, ale skoro nikdy nejde s měřenou ztrátou recallu.** MAAC: 91,6 až 97,6 % na třech veřejných datasetech (RQ1-012 až 014). Julisch na reálných IDS: průměr 70 % (RQ1-017). Čísla spolu nejsou srovnatelná a nesčítám je.
2. **Redukce silně závisí na stacionaritě provozu.** U Julische klesla v měsících s novou událostí na 18 % a blízko 0 % (RQ1-019), v prostředí s opakujícím se benigním provozem dosáhla 93 až 95 % (RQ1-018). První výskyt nové události se potlačit nedá.
3. **Kontextové ověření (zda cíl vůbec je zranitelný, zda služba odpovídá) snižuje nerelevantní poplachy o 50 až 100 %** (ATLANTIDES, RQ1-024) a v honeypotu o 98 až 99 % (Kruegel, RQ1-022). Data jsou z let 2004 až 2007, u Telnetu metoda selhala (RQ1-025).
4. **Nejlépe změřené skórování rizika je RBA (risk-based alerting) nad alerty, ale přínos nese kombinace modulů, ne samotná akumulace:** vážená kombinace všech pěti modulů dosáhla AUROC 0,92 (SD 0,09, 8 datasetů) proti 0,72 u pravidla podle závažnosti a 0,50 bez prioritizace (RQ1-037). Kombinace jen Rule Level + Accumulation + Variety dosáhla 0,93 (RQ1-038). Samotná Accumulation má 0,72 až 0,81 (na úrovni závažnosti), samotná Variety 0,73 až 0,87 (nejlepší samostatný modul 0,87, SD 0,17). Skóre „vzácnosti“ (0,31 až 0,48) a „aperiodicity“ (0,47 až 0,57) je kolem náhody (RQ1-038). Při online (trailing) okně klesá kombinace na 0,75 (RQ1-040). Je to jediný preprint z 09/2026, bez replikace.
5. **Akademické měření skórování entit (UEBA) se sníženým FP jsem nenašel.** Práce RBA entitní modifikátory záměrně nehodnotí (RQ1-041). Beehive: z 784 odlehlých incidentů jen asi čtvrtina malware nebo podezřelé (RQ1-050).
6. **Metriky:** podle Axelssona potřebuje detektor při základní četnosti 2e-5 FPR řádu 1e-5, aby polovina až dvě třetiny poplachů byly pravé (RQ1-001). Erbacher (přehled, preprint) uvádí, že ML práce mívají FPR 1e-2 až 1e-3, a cituje to z jiné práce [22] (RQ1-003). FPR se proto musí vykazovat jako absolutní počet za den a ne jako poměr.
7. **Fúzi Zeek+Suricata s měřeným dopadem na přesnost jsem nenašel.** Jediné měření kombinace dvou IDS (Snort+Suricata) ukazuje klasický kompromis: OR zvyšuje senzitivitu i FP, AND zvyšuje specificitu a snižuje senzitivitu (RQ1-052).

Největší omezení: většina čísel je z preprintů, starých datasetů (DARPA, CIC-IDS) nebo jedné organizace. Studie nejsou kvantitativní metaanalýza.

## 2. Metodika a PRISMA

Postup podle protokolu: dotazy přes webové vyhledávání, každá kandidátní práce otevřena jako plný text (stažení PDF a převod na text), hodnoty čtené z textu a tabulek. Kde je tabulka po převodu nečitelná (rozbité sloupce), je to uvedeno v poznámce řádku a hodnota je buď vynechána, nebo označena jako odvozená.

| Krok PRISMA | Počet |
|---|---:|
| Dotazů | 36 (z toho 5 „proti“: omezení korelace, negeneralizace agregace, omezení RBA, selhání ML triáže, Zeek+Suricata ensemble) |
| Identifikováno (odkazy ve výsledcích vyhledávání) | ≈ 360 (36 dotazů × 10; počet po odstranění duplicit nespočítán, odhad ≈ 250) |
| Vybráno k plnému textu (podle názvu a shrnutí) | ≈ 45 jmenovaných kandidátů |
| Plný text získán a přečten | 30 |
| Z toho zahrnuto do extrakce | 26 |
| Z toho V3 / V2 | 26 / 0 |
| Plný text nedostupný (V1 nebo V0) | 13 V1 + 3 mezery V0 (`neovereno.md`) |

Vyloučeno po přečtení (4): Ning a spol. NDSS 2004 a Noel a spol. ACSAC 2004 (bez ověřitelné metriky FP), Iyengar 2020 (multi-senzor jen jako umístění), Tedesco 2013 (adaptivní omezování alertů, stejné téma jako Tedesco 2008). Kritéria protokolu §4: měření na datech, metrika, dostatečný popis, plný text.

Protokolové minimum „nejméně 15 dotazů a 3 proti“ je splněno.

**Nezávislá kontrola (protokol §9):** proběhla 2026-10-31 (`kontrola-RQ1.md`). Vzorek 56 z 56 řádků (100 %), všechny zdroje znovu staženy a přečteny v plném textu. Věcná chybovost 0/56 (0 %), drobných chyb 5 (řádky 006, 020, 043, 044, 049), neověřitelných 0. Verdikt kontroly: PŘIJATO S OPRAVAMI (limit chybovosti 5 % splněn, ale tři závěry a dva výroky přesazovaly důkaz). Po kontrole se změnilo: opraveno 5 řádků a doplněny 2 řádky (057, 058), upraveny závěry Z3, Z5, Z8, Z10, Z11, Z14, překlad do praxe, hypotézy H1-2, H1-7, H1-8 a abstrakt. Původní hodnoty chyb (audit trail) jsou v `revize-RQ1.md`, ne zde. Citační řetězení (dopředu a dozadu) jsem provedl jen volně: využil jsem seznamy literatury v RBA, DeepCASE a AlertBERT k nalezení Landauera, Kruegela a dalších; systematicky jsem je neprocházel. To je odchylka od protokolu §3.

## 3. Výsledky podle podtémat

### (a) Agregace, shlukování, deduplikace a korelační grafy

| Id | Metoda | Data | Metrika | Hodnota | Podmínky a limity |
|---|---|---|---|---|---|
| 012-014 | MAAC (sémantika popisu alertu + stádia útoku) | LLDOS 1.0, ISCX-IDS-2012, NDSec | alerty před/po | 1942 -> 164; 22 792 -> 853; 2259 -> 55 (91,6 / 96,3 / 97,6 %) | Snort 2.9; ztráta recallu neměřena; NDSec: kroky, které Snort nevidí, chybí i po korelaci |
| 015 | MAAC vs. Ning (ruční pravidla) | LLDOS 1.0 DMZ | detekce cest / falešné cesty | 100 % vs 56,18 %; 0 % vs 5,26 % | falešné cesty 20 % při top 5 |
| 016-020 | Julisch (shlukování + filtrace dle kořenové příčiny) | 4 reálné IDS, 12 měsíců | podíl alarmů pokrytý příčinami; budoucí snížení | <18 příčin = 90 % alarmů; průměr 70 %; IDS 3 až 95 %; IDS 6 únor 18 %; IDS 14 blízko 0 % | recall nemeřen; filtry zahazovaly i škodlivé příčiny |
| 031-032 | SAGE (sekvenční model -> attack graph) | CPTC-2018 Suricata | alerty -> grafy | 330 270 -> 93 grafů; T1 81 373 -> 53 | bez ground truth; zbývá několik grafů |
| 042-043, 057-058 | AlertBERT vs. časové okno (time-delta) | AIT-ADS-A (augmentace) | makro AUC seskupení (včetně šumu) | simultánní útoky: 0,926 vs 0,820; more-noise-2: 0,936 vs 0,973; more-noise-6: 0,936 vs 0,957; more-noise-11: 0,979 vs 0,972 (AlertBERT vs time-delta; ve 3 ze 4 konfigurací vede time-delta až o 0,04) | preprint; autoři výsledky označují za smíšené; metrika je kvalita seskupení |
| 044 | grafové seskupení vs. časové okno | AIT Log Data V2.0 | purity / silhouette | standardně 0,816 vs 0,304 / 0,974 vs 0,900; bez dnsteal purity 0,9985 vs 0,9565 a silhouette 0,446 vs 0,065 | jeden dataset |
| 055-056 | Tedesco: omezení průtoku + korelace | simulace záplavy | logované alerty | o řády méně; riziko zahození skutečných alertů | řeší DoS na IDS, ne FP |

Souhrn: rozsah snížení počtu položek k analytikovi je od ~0 % (Julisch, měsíce s novou událostí) do 97,6 % (MAAC NDSec). Medián nepočítám: sedm studií má pět různých metrik a různé jednotky (alerty, alarmy, grafy, AUC). Heterogenita je vysoká, datasetů ≥ 8, ale sdružený odhad by byl nesmyslný.

### (b) Skórování rizika a entit

| Id | Metoda | Data | Metrika | Hodnota | Limity |
|---|---|---|---|---|---|
| 037 | RBA, 5 hypotéz (CATS), vážená kombinace všech pěti modulů | 8 datasetů alertů, 1 reálný podnik | AUROC | 0,92 (SD 0,09) vs 0,72 (SD 0,21) vs 0,50; nejlepší samostatný modul 0,87 (SD 0,17) | preprint; pouze APT-like útoky; skóre alertů, ne entit |
| 038 | jednotlivé moduly | stejné | AUROC, Wilcoxon | Rule Level 0,72, Accumulation 0,72 až 0,81, Variety 0,73 až 0,87 (nad náhodou, p = 0,016; 0,012; 0,0039); Rarity 0,31 až 0,48, Aperiodicity 0,47 až 0,57 | Tab. 4 po revizi znovu přečtena a ověřena |
| 039 | top 10 % | AIT-ADS Suricata, 44 pravých / 9 142 falešných | pravé alerty v horních 10 % | 43 z 44 vs 28,6 z 44 | základní četnost ~0,5 % |
| 040 | citlivost | 8 datasetů | AUROC | trailing okno -17 p. b. (kombinace 0,75 místo 0,92); cílová IP 0,61 vs zdrojová 0,65 | centrované okno přidává zpoždění půl okna |
| 041 | co RBA nehodnotí | - | - | entitní modifikátory a skóre entit nehodnoceny | - |
| 050 | Beehive (shluky hostitelů) | EMC, 1,4 mld. logů/den, 14 dní | složení incidentů | 784 incidentů; 25,25 % malware nebo podezřelé, 39,41 % porušení politik, 35,33 % neznámý software; jen 8 překryv s nástroji | bez ground truth |
| 051 | MADE (prioritizace rizikových domén) | podnik, 1 měsíc | precision v top 100 při FPR | 97 % při 6e-5 | ranking domén, ne entit |

Výrobci (Splunk, Exabeam) uvádějí snížení o 50 až 95 %. Akademicky to nepodložil nikdo, koho jsem našel (viz `neovereno.md`, tabulka výrobců).

### (c) Korelace s kontextem

| Id | Metoda | Data | Hodnota | Limity |
|---|---|---|---|---|
| 021 | aktivní ověření zranitelnosti (Nessus u Snortu) | testbed, 6 659 alertů | nerelevantní 99,64 % -> 0 %; 24 TP zachováno | uměle navržený testbed |
| 022 | totéž | 2 honeypoty, 14 dní | 98,3 % a 99,4 % alertů neúspěšné útoky | honeypot s extrémní prevalencí skenů |
| 023 | omezení | - | hrubost CVE, tříhodnotová stupnice | verifikace nepomůže u nezachycených útoků |
| 024-025 | ATLANTIDES (kontext z výstupů služeb) | privátní data + DARPA 1999 | snížení FP 50 až 100 %, bez nových FN; Telnet pod 50 % | DARPA 1999 kritizována |

Kalendář údržby a asset kritičnost: nenalezena žádná akademická studie, která by to měřila samostatně (viz oddíl 9).

### (d) Reální SOC

| Id | Zdroj | Hodnota | Spolehlivost |
|---|---|---|---|
| 006-009 | Alahmadi 2022 (21 praktiků, 7 SOC; dotazník n=20) | výrok „99 % poplachů je FP“; 1 pravá hrozba ze 100 vyšetřených a 50 z 200 (n=10); rozlišení FP vs. benigní spouštěč; analytici korelují lépe než SIEM | kvalitativní, nenáhodný vzorek |
| 010 | přehled kybernetických evaluací | tier 1 ~10 min/listek, tier 2 až 2 h | anekdota z kontaktů |
| 027 | NoDoze | model: 20 min/poplach, úspora ~90 h | model, ne měření |
| 011 | přehled 119 záznamů | čísla jsou horní odhady; ML se mezi SOC nepřenáší | narativní přehled |

Publikované měření doby triáže na analytikovi jsem nenašel.

### (e) Více senzorů

| Id | Hodnota | Limity |
|---|---|---|
| 052 | 1oo2 (OR): vyšší senzitivita, nižší specificita než oba; 2oo2 (AND): vyšší specificita, nižší senzitivita | CIC-IDS2017, číselné hodnoty jen v obrázcích |
| 053 | jen 3 991 ze 177 504 blacklistovaných IP je v obou pravidlových sadách (2,2 %, odhad autora) | překryv pravidel, ne alertů |
| 054 | senzitivitu a specificitu na reálném provozu nelze změřit, pcap neoznačen | - |

Zeek+Suricata s `community_id`: žádné měření. Výrobce (Corelight) tvrdí výhody, bez dat.

### (f) Hodnocení a metriky

| Id | Zjištění |
|---|---|
| 001-002 | Axelsson: při základní četnosti 2e-5 dává i FPR 1e-5 a detekce 1,0 jen 66 % pravých poplachů; 100 FP/den je splněno při FPR 1e-5 |
| 003 | většina ML metod stále FPR řádu 1e-2, výjimečně 1e-3 |
| 004 | publikace porovnávají FPR počítané různými vzorci |
| 005 | poměr 1:100 a TPR 99 % při FPR 1 % dává 100 FP na 99 TP |
| 011 | provozní validace chybí; výsledky jsou horní odhady |

### Pomocné: kauzální a provenance korelace (hostitelské)

| Id | Zjištění | Limity |
|---|---|---|
| 026 | NoDoze: při 100 % TPR FPR 16 %, tj. >84 % méně falešných poplachů | 364 alertů, jen 50 pravých |
| 028 | RapSheet: 97,8 % falešných skupin odstraněno při 100 % pravých; FPR 2,2 % | jen 5 pravých skupin z 681 |
| 029 | 6 z 10 nejčastějších technik ATT&CK je samostatně benigních | - |
| 030 | HOLMES: 0 FP za 2 týdny benigní činnosti | hostitelská data |
| 033-035 | AI2: recall 86,8 % vs 7,9 % při k=200; 143 a 211 vs 42 z 318 | jedna platforma, labely od analytika |
| 045-049 | DeepCASE: 90,53 % úspora práce; AACT: 61 % živě při FNR 1,36 %, offline 34 % při FNR 1,5 % (offline hodnota je bez 728 834 dříve auto-uzavřených alertů, s nimi asi 74 %; jiný jmenovatel, ne nejistota) | spravovaný SOC, závisí na rozhodnutích analytiků |

Tyto práce jsou hostitelské nebo používají rozhodnutí analytiků jako labely. Přenos na síťovou telemetrii je extrapolace. Úlohy učení se z verdiktů patří hlavně do RQ3.

## 4. Syntéza

- **Vztah redukce a recallu:** z 26 zahrnutých prací jen ATLANTIDES (RQ1-024), AACT (048-049), DeepCASE (046), RapSheet/NoDoze (026, 028) měří něco, co se blíží ztrátě pravých poplachů. U agregace (MAAC, Julisch, SAGE) je ztráta recallu neměřená. Čísla redukce proto nejsou čísla zlepšení přesnosti.
- **Rozpor:** vysoké redukce 91 až 98 % (MAAC) proti Julischově průměru 70 % s měsíci 0 až 18 %. Vysvětlení: MAAC bere celý dataset naráz a slučuje podobné alerty, zatímco Julisch předpovídá budoucí měsíc z minulého. Je to jiný experiment, ne rozpor v pravdě.
- **Rozpor 2:** AlertBERT vs. časové okno. AlertBERT vede jen při simultánních útocích (makro AUC o více než 0,1). Ve třech ze čtyř konfigurací se zvýšeným šumem (more-noise-2 a more-noise-6, každá s variantou včetně a bez šumu) je v makro AUC lepší prosté časové okno, až o 0,04. V nejhlučnější konfiguraci (more-noise-11) vede AlertBERT těsně (0,979 vs 0,972). Autoři výsledky sami označují za smíšené. Prosté časové okno je tedy srovnatelná nebo lepší základní linie, kterou práce musí překonat.
- **Kontext:** nejsilnější snížení FP (98 až 100 %) pochází z ověření úspěšnosti útoku proti stavu cíle. Je to jiný typ informace než další alert, a proto neklesá pod nulu u skenerů a nevhodně zacílených exploitů. Selhává u protokolů s proměnlivým výstupem (Telnet).
- **Sdružování:** kvantitativní souhrn podle protokolu §8 jsem nedělal. Studie se stejnou metrikou a srovnatelnými podmínkami nejsou aspoň tři (AUROC jen RBA; snížení počtu alertů má pět různých definic).

## 5. Závěry

| Z-id | Tvrzení | Důkazy | Jistota | Důvody snížení jistoty | Použitelnost pro Skákavku | Doporučená akce |
|---|---|---|---|---|---|---|
| Z1 | Agregace a shlukování snižují počet položek pro analytika o desítky procent až o více než 90 %, podle datasetu | 012, 013, 014, 017, 018, 031, 032 | střední | různé metriky, starší datasety, bez recallu | s úpravou | agregovat podle klíče (entita, typ, okno), vždy vykazovat redukci spolu s recallem po rodinách |
| Z2 | Redukce klesá k 0 až 18 % při nové nebo neopakující se události (nelze potlačit první výskyt) | 019 | střední | jeden autor, 4 IDS, rok 2001 | ano | první výskyt a skokové změny nikdy nepotlačovat |
| Z3 | Filtrace a agregace bez měření recallu mohou skrýt pravé útoky (Julisch filtroval i škodlivé příčiny a kvantifikaci bezpečnosti filtrace považuje za neřešitelnou) | 020, 056 | střední | jedna práce z roku 2003 a jedna z roku 2008, kvalitativní | ano | každá potlačovací vrstva musí mít měřenou ztrátu recallu na držené rodině útoků |
| Z3b | Provozní studie, které ztrátu měří, uvádějí dva různé ukazatele: míru falešně negativních (FNR) určenou vzorkováním 1,36 až 1,5 % (AACT) a podhodnocení rizikové úrovně pod 0,01 % u automaticky klasifikované části (DeepCASE). Nejde o stejnou veličinu a nelze je sloučit do jednoho rozsahu | 046, 048, 049 | nízká | různé definice, dvě firmy, FNR určená vzorkováním, preprint (AACT) | s úpravou | měřit FNR vzorkováním po rodinách útoků, ne přebírat čísla |
| Z4 | Ověření oproti stavu cíle (zranitelnost, služba) snižuje nerelevantní poplachy o 50 až 100 %; selhává u variabilních protokolů | 021, 022, 023, 024, 025 | střední | data 2004 až 2007, testbed a honeypot | s úpravou | použít pasivní inventář Skákavky k degradaci (ne mazání) alertů na neexistující služby |
| Z5 | Kombinace modulů Rule Level + Accumulation + Variety (AUROC 0,93; všech pěti modulů 0,92) prioritizuje lépe než samotná závažnost (0,72). Samotná Variety dosahuje 0,73 až 0,87 (okno 1 h 0,87), samotná Accumulation 0,72 až 0,81, tedy na úrovni závažnosti. Při online (trailing) okně klesá kombinace na 0,75 | 037, 038, 039, 040 | nízká | jediný preprint bez replikace, převaha testbedů, jen alerty ne entity, SD 0,09 až 0,21 | ano | implementovat jako kombinaci s Variety, test A/B na stejných seedech, počítat s online poklesem |
| Z6 | Vzácnost a aperiodicita samy nepomáhají (kolem náhody) | 038 | nízká | tabulka po převodu nečitelná | s úpravou | nezačínat modulem vzácnosti jako hlavním signálem |
| Z7 | Akademické měření UEBA / entitního skórování s FP před a po jsem nenašel; výrobci tvrdí 50 až 95 % | 041, 050 | velmi nízká | absence důkazu, ne důkaz absence | s úpravou | vlastní měření (H2) |
| Z8 | AlertBERT vede nad prostým časovým oknem jen při simultánních útocích. Při zvýšeném šumu je časové okno srovnatelné nebo lepší (makro AUC, ve 3 ze 4 případů až o 0,04), v nejhlučnější konfiguraci vede AlertBERT těsně. Grafové seskupení (044) vedlo v jednom datasetu, ale bez dnsteal je rozdíl purity malý (0,9985 vs 0,9565) | 042, 043, 044, 057, 058 | velmi nízká | preprinty, smíšené výsledky, jedna rodina datasetů, jiná metrika než FP | s úpravou | držet časové okno jako baseline, kterou graf musí překonat, a ověřit na vlastních šumových scénářích |
| Z9 | Kauzální a provenance korelace odstraní 84 až 98 % falešných skupin při zachování všech pravých, ale na desítkách pravých případů | 026, 028, 030 | nízká | n = 50 a 5 pravých, hostitelská data | ne (jiná telemetrie) | použít jen jako argument; síťové analogie testovat |
| Z10 | Učení z verdiktů analytika odstraňuje 61 % alertů živě při FNR 1,36 % (AACT). Offline 34 % při FNR 1,5 % je počítáno bez 728 834 dříve auto-uzavřených alertů, s nimi asi 74 %; jde o různé jmenovatele, ne o rozsah nejistoty | 048, 049, 045, 046 | nízká | jedna firma (AACT), preprint, závislost na labelech | s úpravou | přenést do RQ3 / Case Memory; ověřit FNR vzorkováním |
| Z11 | Při základní četnosti útoku 2e-5 (Axelsson) vyžaduje polovina až dvě třetiny pravých poplachů FPR řádu 1e-5. Erbacher (sekundárně, citace [22]) uvádí, že ML detektory mají 1e-2 až 1e-3. Metriky se v literatuře počítají nesourodě | 001, 002, 003, 004, 005 | vysoká (matematika při uvedeném předpokladu), střední (stav literatury, jedna věta z přehledu) | Axelsson 2000 má staré předpoklady | ano | vykazovat FP za síť-den jako absolutní číslo vedle FPR |
| Z12 | Praktici SOC uvádějí vysoké podíly falešných poplachů a rozlišují FP a benigní spouštěč | 006, 007, 008, 009 | nízká | n = 21 a n = 20, anekdoty | ano | zachovat samostatnou kategorii benigních lookalike |
| Z13 | Kombinace dvou IDS: OR zvyšuje senzitivitu i FP, AND zvyšuje specificitu a snižuje senzitivitu; fúzi Zeek+Suricata nikdo neměřil | 052, 053, 054 | nízká | jeden dataset, kvalitativní | s úpravou | měřit v soaku (H5) |
| Z14 | Autoři narativního přehledu (011) uvádějí, že publikovaná čísla je třeba brát jako horní odhady a že modely z jednoho SOC se v jiných nepřenášejí. Řádky 004 (nesrovnatelné definice FPR) a 019 (nestacionarita v jednom IDS) to podporují jen nepřímo, přenos mezi prostředími žádný řádek neměří | 011, 004, 019 | nízká | narativní přehled (preprint 2026), žádné přímé měření přenosu | ano | všechna čísla z této studie brát jako hypotézy, ne jako očekávané výsledky |

## 6. Překlad do praxe (Skákavka)

Označení: **[důkaz]** má odkaz; **[extrapolace]** je můj odhad a vysvětluje, proč.

1. **Agregační klíč a okno.** Spojovat nálezy podle (entita, typ nálezu, okno) a předkládat počet výskytů a první i poslední čas. Okna 1 min, 1 h, 1 den jsou ta, která testuje RBA (RQ1-037, 040) a Julischova filtrace po měsících (017). Parametr „nikdy nepotlačit první výskyt typu nálezu pro entitu“ plyne z Z2 [důkaz 019]. Konkrétní okno pro Skákavku je [extrapolace]: RBA pracuje s alerty, ne s nálezy.
2. **Kombinace modulů jako pořadí, ne jako bránu.** Skóre = vážený součet závažnosti pravidla, počtu nálezů na entitu v okně a počtu odlišných typů nálezů v okně [důkaz 037, 038]. Samotná akumulace závažnost nepředčí (0,72 až 0,81 vs 0,72), podstatná je rozmanitost typů a kombinace [038]. Rarity/aperiodicity nepoužít jako hlavní složky [038]. RBA pro tříčlennou pipeline uvádí průměrné váhy 12,5 % Rule Level, 35 % Accumulation, 52,5 % Variety (Příloha D, RQ1-038). Začít jimi a ladit na soaku, přenos vah do Skákavky je [extrapolace].
3. **Online variant.** Použít trailing okno; počítat s poklesem AUROC o 17 p. b. (kombinace 0,75 místo 0,92, tedy na úroveň pravidla dle závažnosti 0,72) proti centrovanému oknu [důkaz 040]. Centrované okno pouze pro zpětné přehodnocení incidentu (zpoždění půl okna).
4. **Kontextová degradace.** Alert nebo nález na službu, která podle inventáře na hostiteli neexistuje (nebo na neexistující port), snížit na „informace“ a zaznamenat do auditu, ne mazat [důkaz 021, 022, 024; Kruegel upozorňuje na FN při špatném inventáři, 023]. Prakticky: Skákavka má pasivní inventář, takže nepotřebuje Nessus; kvalita inventáře je tím pádem limit [extrapolace].
5. **Kalendář údržby a známé okno (patch, záloha, replay kolektoru).** Žádná zdrojová studie neměří; je to [extrapolace] z kontextového ověření [021-025] a z rozlišení benigního spouštěče v SOC [008]. Potlačení musí být jen pro označené okno a typ, ne pro celou entitu, a musí mít měřenou ztrátu recallu na útoku vloženém do okna (H3).
6. **Vykazování metrik.** Pro každou změnu uvést: FP za síť-den (absolutně), FPR na tok, precision@k pro denní rozpočet k, recall po rodinách s Wilsonovým intervalem a velikost redukce [důkaz 001-005, 033, 039, 051].
7. **Základní linie.** Vždy porovnávat s prostým časovým oknem a s pořadím podle závažnosti [důkaz 037, 042-044, 057-058].
8. **Více senzorů.** Dokud nebude změřeno, nepřidávat „2 senzory = potvrzení“ jako pevné pravidlo. Použít AND jen pro třídy s vysokým FP, OR pro třídy s kritickým dopadem [důkaz 052; volba tříd je extrapolace].
9. **Učení z verdiktů (RQ3).** Případová paměť se 726 660 verdikty operátora (soak v2) je analogie k AACT [048]; očekávat řádově desítky procent (AACT: 61 % živě při FNR 1,36 %, offline 34 % bez dříve uzavřených alertů a asi 74 % s nimi) pouze jako hypotézu.

## 7. Hypotézy k ověření v soak harnessu

Kontext našich měření (z `soak-findings.md` a `status.md`, čteno, nic neměněno):
- Soak v2 (seed 20261031, 3,5 h): 5 302 629 behaviorálních nálezů bez přičitatelné příčiny = 1 108 / síť-den; z toho unexpected_traffic 2 456 734 (46 %), inductive_volume_anomaly 1 944 442 (37 %), packet_rate_spike 531 725 (10 %) (podíly vlastní výpočet). V1: 210,7 / síť-den a 75 % inductive_volume_anomaly.
- Benigní lookalike události s falešným nálezem: patch_window 99,2 %, collector_replay 97,3 %, log_corruption 94,8 %, sensor_crash 93,0 %, service_crash 91,7 %, batch_job 86,3 %, flash_crowd 79,9 %, backup_burst 75,1 %; software_update 0 %, retry_storm 0 %.
- Ověřování: ze 41 651 550 plánů je mimo rozpočet 37 873 005 (≈ 91 %, vlastní výpočet).
- exploit_attempt: detekováno 71,6 %, správný typ 0,0 % (IDS vidělo 550 z 1146).
- Poměr nálezů k tokům: 5 302 629 / 373 546 434 ≈ 1,4 % (vlastní odhad; jednotka je nález, ne alert, a Axelssonova míra se vztahuje na události; řádově je to však o tři až čtyři řády nad 1e-5 [extrapolace]).

Co z literatury odpovídá našim číslům: (i) Julisch: několik příčin dominuje (u nás dva typy nálezů tvoří ~83 % FP), (ii) Alahmadi: rozlišení benigního spouštěče odpovídá našim tvrdým negativům, (iii) Axelsson: absolutní FP/den je správná metrika, (iv) Kruegel/ATLANTIDES: exploit_attempt je typ, kde kontext (existuje služba?) má nejvíc co vzít.

Formát: změna -> očekávaný efekt -> metrika -> scénář/seedy -> kritérium zamítnutí. Všechny testy A/B na stejných seedech a držených rodinách útoků (protokol §10).

| H | Změna | Očekávaný efekt (z důkazů) | Metrika | Scénář | Zamítnutí |
|---|---|---|---|---|---|
| H1-1 | Agregace nálezů podle (entita, typ, okno 1 h) s „první výskyt vždy viditelný“ | pokles počtu položek o desítky %; v prostředí s opakujícím se provozem 70 až 95 %, u nových událostí 0 až 18 % (017-019) | položky / síť-den; recall po rodinách | soak v2 shodné seedy, 10 archetypů | pokles < 50 % FP/síť-den, nebo pokles recallu u libovolné rodiny > 2 p. b. (mimo Wilson CI) |
| H1-2a | Pořadí nálezů: kombinace Rule Level + Accumulation + Variety (trailing okno 1 h) vs. pořadí dle závažnosti | trailing kombinace ≈ 0,75 vs ≈ 0,72 (037, 040; centrované okno 0,93), čeká se malý rozdíl | AUROC pravý nález vs FP; pravé nálezy v horních 10 % | všechny seedy; ≥ 8 nezávislých archetypů/seedů | AUROC ≤ AUROC dle závažnosti nebo rozdíl není významný (Wilcoxon p > 0,05) |
| H1-2b | Samotná Variety (okno 1 h) vs. pořadí dle závažnosti | ≈ 0,87 vs ≈ 0,72 (038) | AUROC | stejné | rozdíl vs. závažnost není významný (p > 0,05) |
| H1-2c | Negativní kontrola: samotná Accumulation vs. pořadí dle závažnosti | ≈ 0,72 až 0,81 vs ≈ 0,72, tedy bez zřetelného rozdílu (038) | AUROC | stejné | zamítnutí, pokud Accumulation významně překoná závažnost (pak je naše prostředí jiné než RBA) |
| H1-3 | Negativní kontrola: moduly vzácnosti a aperiodicity | AUROC ≈ 0,31 až 0,57, tedy kolem náhody (038) | AUROC | stejné | zamítnutí, pokud AUROC > 0,70 (pak je naše prostředí jiné než RBA) |
| H1-4 | Kontextová degradace (nález na neexistující službu = info) | 50 až 100 % snížení FP bez nových FN u přesně znalých prostředí (024); selhání u proměnlivých protokolů (025) | podíl nálezů degradován; recall exploit_attempt a web_exploit | seedy s exploit_attempt, webové archetypy | recall pokles > 1 p. b. nebo snížení < 30 % |
| H1-5 | Potlačení benigních oken (patch_window, collector_replay, sensor_crash, log_corruption) podle kalendáře/události | snížení FP v těchto oknech o ≥ 50 % [extrapolace z 021-025, 008] | FP v oknech; recall útoku vloženého do okna | soak v2 s provozními událostmi + injektovaný útok v okně | pokles FP < 50 % nebo recall útoku v okně klesne > 5 p. b. |
| H1-6 | Politika dvou senzorů: AND (Suricata + Zeek důkaz) pro třídy s vysokým FP, OR pro kritické | AND: vyšší specificita, nižší senzitivita; OR opačně (052) | FP/síť-den, recall po rodinách | soak v2, CTU-13 / IoT-23 kotva | AND nezlepší specificitu nebo sníží recall > 5 p. b. bez přínosu FP |
| H1-7 | Seskupení nálezů do incidentů grafem entit vs. časovým oknem | purity 0,82 vs 0,30 v jednom datasetu, bez dnsteal 0,9985 vs 0,9565 (044). U AlertBERT vs. časové okno smíšené výsledky: při zvýšeném šumu je okno srovnatelné nebo lepší, těsný náskok AlertBERT jen v nejhlučnější konfiguraci (043, 057, 058) | purity, silhouette, incidenty/den; apt_chain jako rodina | rodiny apt_chain, lateral_movement | purity grafu ≤ purity okna + 0,05 |
| H1-8 | Auto-uzavření pod prahem naučeným z verdiktů operátora (Case Memory) | AACT: 61 % při FNR 1,36 % živě. Offline 34 % při FNR 1,5 % je z fronty bez dříve auto-uzavřených alertů, s nimi asi 74 %, jde o různé jmenovatele (048, 049). Podíl uzavřených počítat vždy ze stejného jmenovatele | podíl uzavřen; FNR vzorkem | soak v2 s operátorskými verdikty | FNR > 2 % nebo podíl < 20 % při FNR ≤ 2 % |
| H1-9 | Metodika: vykazovat FP absolutně za síť-den vedle FPR/tok | zajistit srovnatelnost (001-005) | FP/síť-den, FPR/tok, precision@k | všechna měření RQ1 | (nejde o hypotézu o efektu; kontrola, že každá zpráva obsahuje obě veličiny) |

Neúspěšné hypotézy se zveřejní stejně jako úspěšné.

## 8. Hrozby validity

- **Publikační zkreslení:** pozitivní výsledky převažují; nenašel jsem žádnou replikační ani negativní studii agregace (dotazy „proti“ nic nevrátily).
- **Preprinty:** 9 z 26 zdrojů jsou nerecenzované preprinty (včetně klíčových RBA, AlertBERT, GraphCtx, AACT, MAAC), RBA je z 09/2026.
- **Starost datasetů:** DARPA 1999/2000, ISCX-IDS-2012, CIC-IDS2017 mají známé problémy (viz RQ5); AIT-ADS je testbed s nízkým šumem.
- **Malé počty pravých případů:** NoDoze 50 TP, RapSheet 5 pravých skupin, žádné intervaly spolehlivosti.
- **Hostitelská vs. síťová telemetrie:** NoDoze, RapSheet, HOLMES jsou hostitelské; přenos na Zeek/Suricata je extrapolace.
- **Metriky nejsou srovnatelné:** počty alertů, alarmů, grafů, skupin, AUC, purity.
- **Převod PDF:** v tabulkách RBA (Tab. 4) a DeepCASE (Tab. I) se sloupce rozpadly; kde jsem pořadí odvozoval, je to uvedeno. Axelssonův exponent 1e-5 se v převodu ztratil a čtu ho z věty „on the order of 1 [10^-5]“.
- **Kontrola druhým kontrolorem (protokol §9) proběhla** (`kontrola-RQ1.md`, 56 z 56 řádků, věcná chybovost 0 %, 5 drobných chyb, verdikt PŘIJATO S OPRAVAMI). Opravy jsou zapsány v `revize-RQ1.md`. Nezkontrolovanými zůstaly detaily: „po 1 měsíci ručního režimu“ (045), „labely od analytika“ (033), číslování sekcí Tedesco (056), venue Kruegel (021-023) a tvrzení „nezávislá validace chybí“ (017, v extrakci nahrazeno tvrzením autora o podhodnocení).
- **Citační řetězení** nebylo provedeno systematicky (viz oddíl 2).
- **Moje vlastní výpočty** jsou označeny „vlastní výpočet“ (např. 3 991 / 177 504; 44 / 9 186; podíly z status.md).

## 9. Co NEBYLO nalezeno

- Akademické měření UEBA / entitního risk scoringu s FP před a po v SOC (RBA práce entity nehodnotí; vendor údaje jsou jen v `neovereno.md`).
- Měřená fúze Zeek + Suricata přes `community_id` s dopadem na precision/recall (jen Corelight a blogy).
- Samostatné měření vlivu kalendáře údržby a kritičnosti aktiva na FP (vendor tvrzení bez dat).
- Replikace nebo negativní studie agregace alertů na nezávislém datasetu.
- Měřená doba triáže na alert v terénní studii (jen anekdota 10 min a modelové předpoklady 10 až 40 min).
- Měření odolnosti skórovacích schémat proti vyhýbání (evasion) (RBA to diskutuje jen slovně).
- Plné texty: Landauer TOPS 2022 (agregace), Marchetti 2016, Kokulu CCS 2019, Oprea DSN 2015, Ning CCS 2002 (viz `neovereno.md`).
- Intervaly spolehlivosti u většiny prací.
