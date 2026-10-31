# RQ6: Dedukce, abdukce, pravděpodobnostní logika a LLM triáž při ověřování alertů

Verze 1.0, 2026-10-31. Postup podle `../00-protokol.md`. Extrakce: `extrakce.csv` (51 řádků, RQ6-001 až RQ6-051), hledání: `hledani.csv` (29 dotazů), neověřené a vyloučené zdroje: `neovereno.md`. Nezávislá kontrola podle §9 protokolu zatím neproběhla (patří do `kontrola-RQ6.md`), takže všechny závěry jsou do té doby předběžné.

## Abstrakt

Otázka: přinášejí dedukce a abdukce, pravděpodobnostní logika a triáž pomocí velkých jazykových modelů (LLM) měřitelné zlepšení při ověřování alertů a jaká mají rizika? Z 36 zahrnutých prací (35 s plným textem, úroveň V3, 1 s oficiální stránkou artefaktu, úroveň V2) vychází toto:

1. **LLM bez kontextu ověřování nezvládne.** Když model dostane jen text alertu, má na škodlivé podmnožině přesnost 0 % u všech čtyř testovaných modelů (RQ6-009). Na síťových tocích je zero-shot LLM zhruba na úrovni náhody (makro precision 48,6–50,9 %), zatímco Random Forest dosahuje F1 92 % (RQ6-021).
2. **I agenti s nástroji na realistickém interaktivním benchmarku propouštějí útoky.** Na Alert-Bench (1247 alertů, GPT-4.1) zmešká každý z pěti publikovaných přístupů 40,4–70,2 % útočných alertů a 26 z 225 útoků nezachytí žádný z nich (RQ6-002, RQ6-008). Na průmyslových alertech (SecAlertBench) mají LLM v průměru FPR 44 % (RQ6-050, V2). Vysoké přesnosti, 88–98 %, vycházejí jen na malých kurátorovaných sadách s 35 až 100 alerty (RQ6-013, RQ6-014).
3. **Nejsilněji doložený mechanismus selhání.** Když dotaz agenta nevrátí žádný záznam, agent útok zamítne v 98,6 % případů, kdežto při aspoň jednom vráceném záznamu v 30,3 % (RQ6-003). Sebe-revize ve stejném kontextu rozhodnutí častěji pokazí, než opraví (16 oprav proti 79 zhoršením, RQ6-004).
4. **Zlepšení přináší struktura, ne větší model.** Oddělené adjudikace, trojstavový verdikt (útok / benigní / nejisté) a předem dané dotazy snižují míru zmeškaných útoků (FNR) na 3,1–4 % (RQ6-006, RQ6-010). Tyto výsledky ale vždy měřili autoři navrhovaného systému na vlastním benchmarku.
5. **LLM vrstva je nové útočné rozhraní.** Prompt injection vložená do obsahu logů uspěje v průměru u 26,6 % (naivní prompt) a u 83,4 % (LogInject) případů. U sumarizace dosahuje 96 % a ani vrstvené obrany neklesnou pod 8,4–11,8 % (RQ6-023, RQ6-024). Fine-tuning na otrávených štítcích vytvoří zadní vrátka se 100% úspěšností (RQ6-025).
6. **Kauzální kontext (provenance) snižuje FP, ale publikovaná čísla jsou nadsazená.** Hodnocení autorů hlásí snížení falešných alarmů o 84 % (NoDoze) a o 97,8 % (RapSheet) při zachování 100 % TPR, jenže prahy byly zvolené dodatečně (RQ6-031, RQ6-032). Nezávislá hodnocení naměřila v průmyslu FPR přes 23 % u tří z pěti systémů (RQ6-043). ADP stejného systému kolísá mezi běhy z 1,00 pod 0,1 (RQ6-041) a jednoduchá neuronová síť překonává složité GNN na 8 z 9 datasetů (RQ6-040).
7. **Bayesovská kombinace doplňkové evidence a spolehlivosti senzoru** snížila falešné alarmy z 1,58 % na 0,74 % za cenu poklesu predikce o 3 p.b. (RQ6-046). Stavová evidence z hostů zvýšila poměr konfidence mezi skutečnými a ostatními alerty 8–15krát (RQ6-047). Obě studie jsou staré a malé.
8. **Pro Datalog, Markovskou logiku (MLN), ProbLog ani formální abdukci jsem nenašel žádné publikované měření přínosu pro ověřování alertů**, které by šlo ověřit. Jediná abduktivní studie má F1 diagnózy 0,12–1,0 a opírá se o ručně doplněná fakta (RQ6-049).

Důsledek pro Skákavku: deduktivní a pravděpodobnostní jádro dává smysl hlavně tam, kde kombinuje doplňkovou evidenci a explicitní benigní vysvětlení. LLM do verdiktní cesty nepatří. Nejvýš by mohlo shrnovat už rozhodnuté a strukturované nálezy.

## Metodika a PRISMA

**Zdroje a dotazy.** 29 dotazů přes WebSearch (pokrývá Google Scholar, arXiv, USENIX, NDSS, IEEE, ACM), z toho 5 dotazů „proti“ (unreliable, fails, missed attacks, poor performance, prompt injection) a 3 opakované dotazy na MLN a ProbLog, které ověřují mezeru. Citační řetězení proběhlo u Alert-Bench → AIDA (plný text), ORTHRUS → Flash, Simpler → Kairos/Orthrus/Nodlink, NoDoze → RapSheet a Kairos → Unicorn.

**Čtení.** Plné texty jsem stáhl jako PDF z arXiv, USENIX, NDSS a z institucionálních stránek a převedl je nástrojem `pdftotext`. Hodnoty jsem četl přímo z tabulek a textu. U každého řádku V3 je uvedeno místo v textu a doslovná citace.

**PRISMA** (počty identifikovaných záznamů jsou odhad autora: vyhledávač ukazuje nejvýš 10 odkazů na dotaz, deduplikace byla ruční):

| krok | počet |
|---|---:|
| identifikováno (zobrazené odkazy, 29 dotazů) | ~284 |
| po deduplikaci | ~190 |
| po screeningu názvů a abstraktů | 72 |
| pokus o plný text | 48 |
| plný text nebo oficiální abstrakt získán a zhodnocen | 42 |
| vyloučeno po zhodnocení | 6 (mimo téma 1, bez metriky 2, jen návrh 1, duplikát 1, nevyextrahováno 1) |
| **zahrnuto** | **36** |
| z toho V3 / V2 | 35 / 1 |
| neověřeno (V1, v `neovereno.md`) | 18 |

Hlavní důvody vyloučení jsou nedostupný plný text (Ning 2002, Kruegel 2003), chybějící metrika (ASP log, PIDSMaker), téma mimo otázku (ProvSyn) a duplicita (zkrácená verze Alert-Bench).

**Extrakce:** 51 řádků (50 V3, 1 V2), z toho 50 s číselnou hodnotou. Úrovně důkazu: E2 5, E3 42, E4 4. Zdrojů je 36 (některé mají víc řádků).

## Výsledky podle podtémat

### (a) Pravidlové a logické odvozování (expertní systémy, Datalog, ontologie, MulVAL, attack grafy)

| id | práce | data | výsledek | slabina |
|---|---|---|---|---|
| RQ6-048 | MulVAL (Datalog, 2005, seminal) | OVAL, simulace | pokrývá 84 % chyb Red Hat, analýza v sekundách pro tisíce strojů | neměří ověřování alertů ani FP |
| RQ6-033 | HOLMES (pravidla TTP nad provenancí) | DARPA TC E2 + živý test | precision = recall = 1 | práh vybrán z intervalu mezi maximem benigních a minimem útočných podgrafů **testovacích** dat |
| RQ6-034 | SAGE (automat → attack grafy) | CPTC-2018 | 330 270 alertů → 93 grafů | jen komprese, FP neměřeny |
| RQ6-032 | RapSheet (ATT&CK pravidla + kauzální graf) | Symantec EDR, 58 096 alertů | precision surových EDR pravidel 1,9 %; řazení odstraní 97,8 % falešných grafů při 100 % TPR | práh volen dodatečně |

Pravidla nad ATT&CK technikami mají sama o sobě velmi nízkou precision (1,9 %, RQ6-032). Přínos vzniká až propojením pravidel kauzálními vazbami a fázemi útoku. Pro čistý Datalog nebo ontologické korelátory jsem měření FP nenašel (viz Co NEBYLO nalezeno).

### (b) Bayesovské sítě, Markovská logika, ProbLog

| id | práce | data | metoda | výsledek |
|---|---|---|---|---|
| RQ6-046 | Tabia & Leray 2010 | 2 měsíce reálných alertů Snort, 9 webových útoků | BN s virtuální evidencí spolehlivosti IDS | false alarm 1,58 % → 0,74 % (29 → 13 za den), predikce 76,9 % → 73,9 % |
| RQ6-047 | Zhai et al. 2004 (seminal) | 5 laboratorních scénářů | BN z alertů a stavové evidence z hostů (Tripwire, skenery) | poměr konfidence skutečné/ostatní 1,807 → 14 až 27,8 |

Obě studie ukazují stejný směr: doplňková evidence, která nepochází z téhož detektoru, odděluje skutečné alerty od falešných. Obě jsou ale malé (jeden zdroj alertů, pět scénářů) a starší patnácti let. Pro MLN jsem po třech dotazech nenašel nic, pro ProbLog jen nečtenou diplomovou práci s negativním výsledkem (V1).

### (c) Abdukce a „nejlepší vysvětlení“

| id | práce | výsledek | slabina |
|---|---|---|---|
| RQ6-047 | Zhai et al.: hypotézy zmeškaných útoků | 6 z 10 hypotéz byly skutečné útoky, které Snort přehlédl | 5 scénářů |
| RQ6-049 | Ramkumar et al. 2025: iForest + abdukce v ASP | F1 diagnózy IoT-23 0,51–1,00, CICIoT2023 0,12–1,00; podle autorů abdukce odfiltrovala FP detektoru anomálií | kontextová fakta doplněna ručně, P = R = F1 ve všech řádcích (nejasná agregace) |

Abdukce rozlišující benigní a útočná vysvětlení má zatím jen demonstrační důkazy. Přímé srovnání s jiným způsobem ověřování na stejných datech v literatuře chybí.

### (d) Kauzální přístupy a grafy proveniencie (NoDoze, Unicorn, ATLAS, Kairos, MAGIC, Flash, ORTHRUS)

**Výsledky, které hlásí autoři vlastních systémů:**

| id | systém | metrika | hodnota |
|---|---|---|---|
| RQ6-031 | NoDoze | snížení falešných alarmů / FPR při 100 % TPR | 84 % (PDF; web NDSS uvádí 86 %) / 16 % |
| RQ6-036 | Unicorn | precision a recall (DARPA, úroveň grafu) | 0,98–1,0 / 1,0 |
| RQ6-037 | ATLAS | precision a recall (úroveň entit) | 91,06 % / 97,29 % |
| RQ6-035 | Kairos | precision po časových oknech | 0,438–1,000; po „úpravě“ (přeštítkování „fake FP“) až 1,000 |
| RQ6-039 | MAGIC | FPR a precision (CADETS, uzly) | 0,22 % (to je 759 FP uzlů) / 94,4 % |

**Nezávislá a kritická hodnocení:**

| id | práce | zjištění |
|---|---|---|
| RQ6-040 | Bilot et al. 2025 (E2) | jednoduchá NN dosahuje SOTA na 8 z 9 DARPA datasetů; metrika ADP rozlišuje Kairos 0,01 a ORTHRUS 1,00 |
| RQ6-041 | tatáž | ORTHRUS na E3-THEIA: ADP 1,00 v nejlepším a pod 0,1 v nejhorším z 5 opakování |
| RQ6-042 | tatáž | s prahem z validační místo testovací sady klesne precision ORTHRUS na E3-CLEARSCOPE až na 0 % |
| RQ6-038 | ORTHRUS | na E3-CADETS označí Flash 2394 uzlů (13 TP), precision pod 1 %; ORTHRUS 48 uzlů (25 TP), precision 52 % |
| RQ6-043 | Xiao et al. 2026 (průmysl) | na hostu s denně novými procesy mají 3 z 5 systémů FPR přes 23 %, Kairos pod 12 %, ORTHRUS pod 1 % |
| RQ6-044 | tatáž | shlukování podobných FP (Louvain) sníží FPR u Nodlink z ~25 % na ~10 % a ruční práci o 2/3 |
| RQ6-045 | Goyal et al. 2023 | mimikry útoky obejdou 5 systémů ve 100 % případů |

Kauzální kontext pomáhá, protože FP se dá posoudit podle vztahu k dalším událostem. Velikost přínosu ale silně závisí na tom, jak autoři definují ground truth (Kairos přeštítkuje, ATLAS počítá na úrovni událostí), jak volí práh (HOLMES, NoDoze, RapSheet ho ladí dodatečně) a kolik běhů změří (žádná původní studie neměřila nestabilitu, RQ6-041). Škálování: CORTEX i ostatní práce uvádějí paměť a latenci, ale žádná z přečtených neověřila FP na více než jednom podniku.

### (e) LLM v triáži SOC

**Interaktivní a realistické benchmarky:**

| id | benchmark | data | výsledek |
|---|---|---|---|
| RQ6-001/002 | Alert-Bench | 1247 alertů, AIT replay přes SIEM, GPT-4.1 | nejlepší F1 0,744; FNR 40,4–70,2 % |
| RQ6-003 | Alert-Bench | totéž | prázdný výsledek dotazu → zamítnutí útoku v 98,6 % (ReAct) |
| RQ6-004/005 | Alert-Bench | totéž | sebe-revize F1 0,665 → 0,550 a 0,669 → 0,371; 5,5× víc tokenů nezlepší F1 |
| RQ6-050 | SecAlertBench (V2) | 8322 alertů ze 3 podnikových SOC, 16 LLM | průměr TPR 79,7 %, FPR 44,1 % |
| RQ6-018 | ExCyTIn-Bench | Azure, 57 tabulek Sentinelu | nejlepší odměna 0,606 (Claude-Opus-4.5), GPT-4o 0,293 |
| RQ6-017 | CyberSOCEval | 1197 otázek (malware, CTI) | 23–34 % a 43–53 %; reasoning modely nepřinesly očekávaný skok |
| RQ6-016 | SIR-Bench (AWS) | 794 případů | vlastní agent 97,1 % TP, ale jen 73,4 % FP rejection |

**Malé nebo kurátorované sady:**

| id | studie | n | výsledek |
|---|---|---:|---|
| RQ6-009/010 | Eilertsen et al. | 1 scénář × 100 běhů | bez workflow 0 %, s workflow 81–100 %, max FNR 4 % |
| RQ6-013/014 | SIABench | 100 a 35 alertů | 75–98 % a 51–97 %; slabé modely eskalují benigní alerty (GPT-4o-mini FP 14/30) |
| RQ6-011/012 | CORTEX | několik tisíc produkčních tras | FPR 24,9 % → 14,2 %, latence 44,6 → 152,4 s |

**Síťová data:** zero-shot LLM se pohybuje kolem náhody (RQ6-021). S gramatikou, domenovými příznaky a kalibrací dosáhne makro-F1 ~0,78 na 200 tocích, s víc toky výkon klesá (RQ6-022).

**Halucinace a spolehlivost:** u CTI klesá recall při generování typu APT na 0,02 a fine-tuning recall dokonce zhoršil (0,72 → 0,58), modely jsou nekonzistentní a překonfidentní (RQ6-019, RQ6-020). SIABench uvádí halucinace mezi třemi nejčastějšími příčinami selhání slabých modelů (RQ6-015). Míru halucinací jako samostatnou metriku na alertech neměří žádná z přečtených prací. Měří se nepřímo přes FNR, recall a hodnocení „grounded“ tras (Alert-Bench, SIR-Bench).

**Guardrails a strukturovaný výstup:** trojstavový verdikt v JSON a striktní instrukce „nevymýšlej data“ (RQ6-010), oddělený soudce (RQ6-007) a vstupní filtrace s ověřením výstupu (RQ6-024). Strukturovaný výstup podle obecné NLP studie zhoršuje úvahové úlohy, u klasifikace je JSON režim srovnatelný nebo lepší (RQ6-051, bez čísel v textu).

**Rizika:** prompt injection přes logy (RQ6-023, RQ6-024) a otrávené štítky (RQ6-025).

**Ne-LLM srovnání:** gradient boosting učený na rozhodnutích analytiků (AACT) uzavřel v produkci 61 % alertů při FNR 1,36 % (RQ6-030). Proti takové laťce musí každá LLM triáž obstát.

### (f) Interpretovatelnost a důvěra analytiků

| id | studie | design | výsledek |
|---|---|---|---|
| RQ6-029 | Alahmadi et al. | dotazník 20 + rozhovory 21 lidí ze 7 SOC | 55 % analytiků spoléhá na tacitní znalost; „99 % FP“ jsou podle autorů hlavně benigní spouštěče, ne chyba detektoru |
| RQ6-027 | Rastogi et al. | dotazník 248 + rozhovory 24 + pilot | analytici přijímají i méně přesné výstupy, pokud jsou vysvětlené; pilot: triáž 4,1 → 3,3 min |
| RQ6-028 | ICCA 2025 | 24 účastníků, 4 strategie vysvětlení | přesnost 65 → 82 %; přirozený jazyk zvyšuje vnímanou důvěru víc než přesnost (nadměrná důvěra u nováčků) |
| RQ6-026 | Bono (Microsoft) RCT | 167 analytiků, 25 e-mailů | F1 +77 % (+48 % pro agenta s přesností 0,8), analytici agentovi „nerazítkovali“ škodlivé verdikty |

Vysvětlení zvyšují důvěru spolehlivěji než přesnost. Jediná randomizovaná studie (RCT) má střet zájmů a testovala agenta, který měl na korpusu 100% přesnost.

## Syntéza

- **Kvantitativní sdružení neprovádím.** Žádná metrika se neopakuje ve ≥ 3 srovnatelných studiích se stejnými podmínkami (protokol §8). Uvádím rozsahy.
- **FNR LLM triáže:** min 3,1 % (AIDA, vlastní systém autorů) – medián přibližně 40 % (5 přístupů na Alert-Bench; hodnoty 40,4–70,2 %) – max 100 % (baseline bez kontextu, RQ6-009). 3 studie, 2 datasety. Heterogenita je extrémní a dá se vysvětlit kontextem (bez logů / s logy), architekturou a velikostí sady.
- **Rozpor mezi SIABench (až 98 %) a Alert-Bench (≤ 0,744 F1)** vysvětlují tři rozdíly: velikost a obtížnost sady (100 alertů proti 1247 s 18 % útoků), možná kontaminace veřejných dat (CIC-IDS2017, TII-SRC-23) a pasivní versus interaktivní zadání. Neberu ho jako nekonzistenci metody, ale jako nepřímost malých benchmarků.
- **Snížení FP kontextovým řazením (provenance), při plném TPR podle autorů:** 60 % (Louvain, 25 → 10 %), 84 % (NoDoze), 97,8 % (RapSheet). 3 studie, 3 různé typy dat, všechny s prahem voleným dodatečně, takže horní hranice je nadsazená.
- **Pravděpodobnostní kombinace evidence:** 2 studie (2004, 2010), relativní snížení falešných alarmů o 53 % (Tabia), zlepšení poměru konfidence 8–15× (Zhai). Ke sdružení to nestačí.
- **Publikační zkreslení:** u systémů provenance je silné. Původní práce hlásí precision a recall blízko 1, nezávislá měření ukazují FPR přes 23 % a nestabilitu. U LLM vycházejí negativní výsledky nově a z větší části od nezávislých týmů (Alert-Bench, Mezzi, Houssel).

## Závěry

| Z-id | tvrzení | důkazy | jistota | důvody snížení | použitelnost | doporučená akce |
|---|---|---|---|---|---|---|
| Z1 | LLM, které dostane jen alert bez kontextu z logů, nerozpozná útoky (0 % na škodlivé podmnožině) a na tocích je na úrovni náhody | RQ6-009, RQ6-021, RQ6-022 | střední | malé sady, jeden scénář | ano | LLM nedávat do detekce ani verdiktu nad toky |
| Z2 | Agenti LLM s nástroji na realistickém interaktivním benchmarku propouštějí ≥ 40 % útočných alertů, na podnikových alertech mají průměrnou FPR ~44 % | RQ6-001, RQ6-002, RQ6-008, RQ6-050 | nízká | jeden scénář, jeden model, SecAlertBench jen V2 | ano | LLM triáž neautomatizovat bez nezávislého ověření FNR |
| Z3 | Prázdný výsledek vyhledávání vede agenty k zamítnutí útoku (98,6 % proti 30,3 %), u benigních alertů je vliv ≤ 2,8 p.b. | RQ6-003 | střední | jedna studie, ale velké n a benigní kontrola | ano | v Skákavce nikdy nepovažovat neprovedené nebo prázdné ověření za benigní důkaz (H-3) |
| Z4 | Sebe-revize ve stejném kontextu a víc výpočtu (vzorkování, reasoning modely) kvalitu triáže nezlepší, často ji zhorší | RQ6-004, RQ6-005, RQ6-017 | nízká | jeden benchmark + nepřímá úloha | ano | žádné smyčky „zkontroluj se“ |
| Z5 | Strukturovaný workflow s oddělenou adjudikací a trojstavovým verdiktem snižuje FNR na 3–4 % | RQ6-006, RQ6-007, RQ6-010, RQ6-011 | nízká | autoři hodnotí vlastní návrh na vlastním benchmarku | s úpravou | principy převzít do deterministického plánovače, ne do LLM |
| Z6 | Obsah logů lze zneužít k prompt injection: úspěšnost bez obrany 26,6–96 %, se zbytkem 8,4–11,8 %; otrávené štítky vytvoří zadní vrátka se 100% úspěšností | RQ6-023, RQ6-024, RQ6-025 | střední (že riziko existuje) / nízká (velikost) | syntetické logy, preprinty | ano | do LLM nepouštět řetězce, které ovládá útočník (H-6) |
| Z7 | LLM jsou u CTI nekonzistentní a překonfidentní, fine-tuning může recall zhoršit | RQ6-019, RQ6-020 | nízká | jeden dataset, 3 modely | ano | konfidenci LLM nepoužívat jako pravděpodobnost |
| Z8 | Kontextové řazení podle kauzálního grafu snižuje FP o 60–98 % při plném TPR, ovšem s prahem voleným dodatečně | RQ6-031, RQ6-032, RQ6-044 | nízká | dodatečný práh, jeden podnik na studii | s úpravou | otestovat řazení podle vzácnosti kontextu (H-4) |
| Z9 | Publikované výsledky detektorů nad grafy proveniencie nezávislé hodnocení nepotvrzuje: FPR > 23 % v průmyslu, ADP kolísá 1,0 → < 0,1, s poctivým prahem precision až 0 %, jednoduchá NN je lepší na 8/9, mimikry obejdou detekci ve 100 % | RQ6-040, RQ6-041, RQ6-042, RQ6-043, RQ6-045, RQ6-033, RQ6-035 | střední | konzistentní napříč 4 nezávislými týmy, část E2 | ano (metodicky) | prahy jen z vývojových seedů, ≥ 5 seedů, hlásit rozptyl (H-5) |
| Z10 | Bayesovská kombinace doplňkové evidence a spolehlivosti senzoru snižuje falešné alarmy (relativně −53 % při −3 p.b. predikce) a zvyšuje separaci skutečných alertů | RQ6-046, RQ6-047 | nízká | 2 malé a staré studie | ano | spolehlivost telemetrie jako virtuální evidence (H-2) |
| Z11 | Abdukce (hypotézy zmeškaných útoků, diagnóza příčiny) funguje jen demonstračně: 6/10 hypotéz správně, F1 0,12–1,0 s ručními fakty | RQ6-047, RQ6-049 | velmi nízká | ruční fakta, malé n | s úpravou | benigní vysvětlení zavést a změřit v soaku (H-1) |
| Z12 | Vysvětlení zvyšují důvěru analytiků víc než přesnost a prezentace v přirozeném jazyce vede k nadměrné důvěře | RQ6-027, RQ6-028, RQ6-029 | nízká | malé n, pilot, sebehodnocení | s úpravou | vysvětlení stavět na evidenci a protipříkladech, ne na volném textu |
| Z13 | Ne-LLM model učený na rozhodnutích analytiků uzavřel v produkci 61 % alertů při FNR 1,36 % | RQ6-030 | nízká | jeden výrobce, štítky analytiků | ano | laťka pro jakoukoli „chytrou“ triáž |

## Překlad do praxe (Skákavka)

Napojení na naše měření (soak v2, `F:\bakula-soak\run-v2-72h\status.md`, 3,5 h, 566 sítí):

- Provozní události generují falešné nálezy téměř vždy: patch_window 99,2 %, collector_replay 97,3 %, log_corruption 94,8 %, sensor_crash 93,0 %, service_crash 91,7 %. To odpovídá nálezu průmyslového hodnocení, že detektory selhávají na stále se měnících benigních aktivitách (Z9, RQ6-043), i tomu, že analytici tytéž případy označují jako „benigní spouštěče“ (RQ6-029). Literatura tu nepřináší detektor, přináší evidenci: spolehlivost senzoru (Z10) a explicitní benigní vysvětlení (Z11).
- 68 % plánů ověřování ve v1 bylo mimo rozpočet. Alert-Bench ukazuje, že neprovedené nebo prázdné ověření se snadno změní na zamítnutí útoku (Z3). Pomalé rodiny útoků, které nejvíc trpí (c2_beacon detekováno 12,5 %, rogue_device 7,4 %, cryptomining 24,7 %), jsou přesně ty, kde ověření nic nevrátí.
- Case Memory má Brier 0,0107, ale je podkonfidentní pro p ≥ 0,6 a překonfidentní pro 0,1–0,5. Literatura o LLM ukazuje, že ani LLM konfidenci nejde brát jako pravděpodobnost (Z7). Izotonická kalibrace, kterou plánujeme, je proto správná i pro případný budoucí LLM výstup (extrapolace).
- `soak verify` 30/30 dává bitovou shodu, takže máme determinismus, který většina PIDS nemá (Z9). Na rozptyl mezi seedy to ale neodpovídá a ten je třeba měřit zvlášť.

Konkrétní postupy:

1. **Verdikt jen deterministický, trojstavový:** útok / benigní / neověřeno. Stav „neověřeno“ se nikdy nezmění na benigní jen uplynutím času nebo prázdným dotazem (Z3, Z5).
2. **Oddělení navrhování od rozhodování:** hypotézu navrhuje korelace, potvrzuje ji nezávislá evidence jiného typu (aktivní ověření, stav hostu, inventář), nikdy opakované čtení stejné evidence (Z4, Z5, Z10).
3. **Katalog benigních vysvětlení** jako konkurenčních hypotéz: údržbové okno, výpadek nebo pád senzoru, přehrání kolektoru, poškozený log, záloha, dávková úloha, autorizovaný skener. Každé má pozorovatelný předpoklad (kalendář, zdraví telemetrie, duplicitní ID záznamů) a vyhrává jen tehdy, když ho podpoří evidence (Z11, Z10).
4. **Spolehlivost senzoru jako virtuální evidence:** při výpadku, poškození nebo replay se váha pozorování z postiženého senzoru sníží. Výchozí cíl podle RQ6-046 je zhruba poloviční počet falešných alarmů za cenu ≤ 3 p.b. detekce.
5. **Shlukování podobných nálezů** podle (pravidlo, role, služba) před prezentací. Podle RQ6-044 to sníží ruční práci asi o 2/3 při stejném FPR. Je to extrapolace z procesů na hostu na síťové nálezy.
6. **Metodika hodnocení:** prahy jen z vývojových seedů, test na držených seedech, ≥ 5 seedů s udáním rozptylu. Hlásit i precision na úrovni hypotéz a počet položek k prověření (Z9, RQ6-038, RQ6-039: FPR 0,22 % může znamenat 759 FP).
7. **LLM, pokud vůbec:** jen pro shrnutí již rozhodnutých nálezů ze strukturovaných polí (výčtové typy, čísla) a nikdy z polí, která ovládá útočník (DNS qname, HTTP User-Agent, SNI, payload). Žádná sebe-revize, žádný fine-tuning na štítcích analytiků bez kontroly otrávení (Z1, Z6, Z7). To vše je extrapolace, protože LLM shrnutí strukturovaných síťových nálezů nikdo neměřil.

## Hypotézy k empirickému ověření (soak harness, A/B na stejných seedech)

Společné podmínky: soak v2, seed 20261031 a 4 další seedy (vývoj: 2, test: 3 držené), stejné archetypy, držené rodiny útoků, kotva CTU-13/IoT-23. Intervaly jsou Wilsonovy 95 %. Zveřejní se i zamítnuté hypotézy.

- **H-1 (benigní vysvětlení).** Změna: přidat konkurenční benigní hypotézy pro patch_window, sensor_crash, collector_replay a log_corruption (bod 3). Očekávaný efekt: relativní pokles podílu těchto událostí s falešným nálezem o 60–98 % (rozsah ze Z8: 60 %, 84 %, 97,8 %; horní hranice je nadsazená). Metrika: sloupec „z toho s falešným nálezem“ a „nálezy připsatelné jen jim“ v tabulce benigních lookalike; detekce po rodinách. Kritérium zamítnutí: relativní pokles < 30 % u ≥ 3 ze 4 událostí, nebo pokles detekce kterékoli rodiny o víc než 2 p.b. s nepřekrývajícími se intervaly.
- **H-2 (spolehlivost senzoru).** Změna: virtuální evidence spolehlivosti v cyklech s výpadkem nebo poškozením telemetrie (bod 4). Očekávaný efekt: −40 až −60 % FP na síť-den v degradovaných cyklech (RQ6-046: −53 %) při poklesu detekce ≤ 3 p.b. (RQ6-046: −3,0 p.b.). Metrika: FP/síť-den v degradovaných a zdravých cyklech, detekce. Kritérium zamítnutí: pokles FP < 25 % nebo pokles detekce > 5 p.b.
- **H-3 (prázdné ověření není benigní).** Změna: hypotéza bez provedeného nebo s prázdným ověřením zůstane „neověřeno“ a dostane prioritu v plánovači (bod 1). Očekávaný efekt podle Z3 (98,6 % vs 30,3 % zamítnutí): vzestup detekce pomalých rodin (c2_beacon, fleet_beacon, cryptomining, rogue_device) o ≥ 10 p.b. Metrika: detekce po rodinách, podíl útoků uzavřených bez evidence, FP/síť-den. Kritérium zamítnutí: žádná ze čtyř rodin nezlepší detekci s nepřekrývajícím se intervalem, nebo FP/síť-den vzroste o víc než 20 %.
- **H-4 (vzácnost kontextu).** Změna: váhovat `inductive_volume_anomaly` a `packet_rate_spike` historickou četností kontextu (role zdroje, cílová služba, hodina v týdnu) ve stylu NoDoze. Očekávaný efekt: −30 až −84 % FP těchto typů (84 % je hodnota NoDoze na hostových událostech; přenos na toky je extrapolace) při stejné detekci ddos_volume a exfiltration. Kritérium zamítnutí: pokles < 30 % nebo pokles detekce ddos_volume či exfiltration o víc než 2 p.b.
- **H-5 (přenos na držené seedy).** Změna: žádná; jde o metodickou hypotézu, že efekty H-1 až H-4 naměřené na vývojových seedech přetrvají na držených seedech aspoň v polovině velikosti. Očekávání podle Z9: část efektů zmizí (ADP kolísalo 1,0 → < 0,1, poctivý práh shodil precision na 0 %). Metrika: poměr efekt_test / efekt_vývoj a směrodatná odchylka mezi seedy. Kritérium zamítnutí (pro danou změnu): poměr < 0,5 nebo efekt menší než dvojnásobek směrodatné odchylky mezi seedy. Takovou změnu označíme za neprokázanou.
- **H-6 (podmínka pro jakékoli LLM).** Změna: do útoků v soaku vkládat řetězce řízené útočníkem (DNS qname, HTTP UA, SNI) s instrukcemi pro LLM a pustit nad nálezy experimentální shrnutí. Očekávaný efekt: úspěšnost injekce 26,6–96 % bez obrany a 8,4–11,8 % s obranou (Z6). Metrika: podíl shrnutí, která útok vynechají nebo zjemní. Kritérium: hypotéza „LLM nad syrovými poli je bezpečné“ se zamítne při úspěšnosti > 1 %, a pak zůstane LLM omezeno na strukturovaná výčtová pole.

## Hrozby validity

- **Výběr zdrojů:** vyhledávání ukazuje jen prvních 10 odkazů na dotaz. Počty identifikovaných záznamů jsou odhad. ACM DL a IEEE Xplore jsem neprohledával přímo, starší logické práce (Ning, Kruegel, Zhou) zůstaly V1.
- **Recenze:** většina LLM prací jsou preprinty z let 2025–2026 a rychle se mění. Například CyberSOCEval má mezi verzemi odlišná čísla.
- **Střet zájmů:** Microsoft (RQ6-026, RQ6-018), AWS (RQ6-016), Sophos (RQ6-030), autoři AIDA hodnotí vlastní návrh (RQ6-006).
- **Nepřímost:** literatura o provenance pracuje s hostovými audit logy, Skákavka s toky, Zeekem a aktivním ověřováním. Přenos čísel je extrapolace a hypotézy jsou podle toho formulované se širokými rozsahy.
- **Ground truth:** přeštítkování (Kairos), počítání na úrovni událostí (ATLAS), štítky analytiků (AACT) a hypotetické alerty (Eilertsen) mění význam metrik. Srovnání napříč tabulkami není přímé.
- **Extrakce:** pořadí sloupců v Tab. II u RQ6-028 jsem odvodil z textu, protože záhlaví se v PDF neextrahovalo. NoDoze uvádí 84 % v PDF a 86 % na webu NDSS. Řádky extrakce zatím nezávisle nezkontroloval druhý agent (§9 protokolu).
- **Vlastní data:** soak je simulace. Shoda našich FP u provozních událostí s literaturou může vycházet ze stejné konstrukce generátoru, ne ze stejného jevu.

## Co NEBYLO nalezeno

- **Markovská logika (MLN):** žádná práce s měřením na alertech (3 dotazy). Literatura místo toho používá HMM a Markovovy řetězce.
- **ProbLog a pravděpodobnostní logické programování:** žádné měření přínosu pro ověřování alertů, jen nečtená diplomová práce s negativním výsledkem (V1).
- **Datalog a ontologické korelátory:** žádné ověřitelné měření snížení FP. MulVAL měří jen pokrytí a čas.
- **Abdukce s benigními vysvětleními ve velkém měřítku:** žádné srovnání s jiným ověřováním na stejných datech.
- **Míra halucinací jako samostatná metrika u triáže alertů:** nikdo ji neměří přímo, jen nepřímo přes FNR a ukotvení tras.
- **Nezávislá replikace pozitivních LLM výsledků** (CORTEX, AIDA, Eilertsen, SIR-Bench): žádná.
- **LLM nad síťovými nálezy typu Zeek/flow v roli ověřovatele (ne detektoru):** žádné měření.
- **Kontrolovaná studie automatizační předpojatosti** s LLM vysvětlením a záměrně chybným doporučením, s kontrolní skupinou: nenalezena. Jediná RCT měla bezchybného agenta.
- **Škálování provenance triáže na víc podniků:** všechny studie vycházejí z jednoho prostředí.
