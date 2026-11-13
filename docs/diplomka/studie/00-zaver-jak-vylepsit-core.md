# Závěrečná studie: jak vylepšit korelační a ověřovací jádro Skákavky (nižší šum, vyšší úspěšnost, univerzálnost)

Verze 1.1, 2026-11-01. Revize podle `revize-metodiky-a-rizik.md` (K1 až K23) a `revize-rozsahu-a-nakladu.md` (P, Q, U, B, E, M), log změn v `revize-00.md`. Souhrnná (meta)studie nad revidovanými studiemi RQ1 až RQ6 podle `00-protokol.md` v1.0. Zdrojový kód se neměnil, nic se nespouštělo kromě čtení souborů a `git log`, procesy `bakula-soak-*` zůstaly bez zásahu.

Konvence:
- `RQn-xxx` je id řádku v `rqN-*/extrakce.csv`.
- `RQn Zk` je závěr v tabulce Závěry revidované `rqN-*/studie.md`. Jistota je převzatá beze změny nebo snížená, nikdy zvýšená.
- `[v1]` = `docs/diplomka/eval/soak-findings.md`.
- `[v2b]` = `F:\Projekty\bakula-soak\run-v2b\status.md`, **snímek 2026-11-01 00:03 SEČ** (1,00 h běhu, 190 sítí, 1 586 virtuálních síť-dnů, seed 20261101). Všechna čísla označená [v2b] jsou z tohoto snímku. Soubor se přepisuje: při revizi metodiky jsem četl snímek po 1,25 h (234 sítí), při dalších revizích měl soubor 9,50 h. Pozdější snímky jsem do čísel nepřebíral. Snímkové hodnoty nejsou stacionární (K11, bod 5).
- `[A01]` až `[A35]` jsou nálezy auditu kódu `01-analyza-kodu-a-zdroje-sumu.md`. Ručně jsem je ověřil jen tam, kde je uvedeno „ověřeno“.
- „vlastní výpočet“ = aritmetika nad uvedeným souborem. „odhad autora“ = číslo bez důkazu, s popsaným postupem. „volba autora“ = parametr návrhu experimentu, ne tvrzení o světě.

---

## 1. Shrnutí pro rozhodnutí

1. **Doloženo s vysokou jistotou (aritmetika a audity datasetů):** při nízké základní četnosti útoků převáží falešné poplachy i při malé FPR (RQ1 Z11, RQ5 Z-6a; RQ1-001, RQ5-030, RQ5-055). Detektory se na benchmarcích opírají o artefakty generátoru (RQ5 Z-2; RQ5-006, -013 až -016). Čísla různých studií jsou nesrovnatelná kvůli poměru tříd (RQ4 Z15). Pro soak z toho plyne: nejdřív opravit harness a hlásit FP/síť-den, precision a artefaktové baseline.
2. **Doloženo se střední jistotou:** agregace snižuje počet položek o desítky procent až přes 90 %, ale k 0 až 18 % u nových událostí, a ztrátu recallu nikdo neměří (RQ1 Z1, Z2, Z3). Aktivní ověření zranitelnosti a ověření podle odpovědi služby snižují nerelevantní poplachy o 50 až 100 % (RQ1 Z4, data 2004 až 2007). Na degradaci podle pasivního inventáře se to nepřenáší (K3). Publikovaná čísla lateral movementu a provenance se v nezávislém hodnocení nepotvrdila (RQ4 Z9, RQ6 Z9; jistotu sjednocuji na střední, viz §3). Sekvenční test nerozhoduje vždy, ani se stropem kontrol, a potřebuje eskalaci (RQ3 Z3).
3. **Jen nízká jistota (hypotézy, ne očekávání):** per-entity baseline a rozpočet alertů (RQ2 Z4), zmrazení baseline (RQ2 Z3), RBA kombinace s rozmanitostí (RQ1 Z5, online jen AUROC 0,75 proti 0,72), EVOI a aktivní učení pro pořadí kontrol (RQ3 Z5 střední, ale v jiných doménách; RQ3 Z12 nízká), bayesovská spolehlivost senzoru (RQ6 Z10), kaskáda s měřenou ztrátou recallu (RQ3 Z7).
4. **Nedoloženo (literatura mlčí):** VOI nebo bandit pro výběr ověřovací kontroly (RQ3 §9), měřená fúze Zeek+Suricata (RQ1 Z13), reverse shell a interaktivní relace z toků (RQ4 Z13, žádný recenzovaný TPR/FPR), sezónní baseline proti statickému prahu na tocích (RQ2 §9), FDR při tisících entit (RQ2 Z6a velmi nízká), Datalog, MLN a ProbLog v ověřování (RQ6 §Co nebylo nalezeno), přímé měření cirkularity (RQ5).
5. **LLM zatím nedávat do verdiktní cesty:** důvodem je hlavně riziko prompt injection přes logy (RQ6 Z6, střední pro existenci) a chybějící nezávislá replikace. FNR 40,4 až 70,2 % (RQ6-002) pochází z jednoho preprintu s jedním modelem a týž zdroj uvádí u cíleného agenta AIDA FNR 3,1 % (RQ6-006). Jistota obou je nízká.
6. **Naše data [v2b, snímek 2026-11-01 00:03]:**
   - Šum tvoří tři typy nálezů, 91,6 % FP (`unexpected_traffic` 43,3 %, `inductive_volume_anomaly` 37,7 %, `packet_rate_spike` 10,6 %; vlastní výpočet). V [v1] dávají `inductive_volume_anomaly` a `packet_rate_spike` 97 %.
   - Závislost FP na velikosti sítě je silná, ale zmatená s archetypem a XXL jí neodpovídá (§4.1 D2).
   - Plánovač nechává 88,5 % plánů mimo rozpočet. Je to smíšený jev: zčásti rozpočet jádra, zčásti plánování harnessu (A32).
   - Exploit má správný typ 0,0 % a exfiltrace 0,0 % zdrojového pořadí. To jsou strukturální chyby kódu (§4.4).
7. **Doporučené pořadí (§5.x, §5A):** nejdřív levné změny na největší zdroje šumu bez čekání na plnou bránu G0: G0-min → R5 packet rate → R7-lite historie klíče → R4-lite stav nálezů + R3 Suricata → R13 `unexpected_traffic`. Potom G0-plné, R2, kalibrace, kontext, identita.
   - **Odloženo** s odůvodněním v §5.x: RBA (R9), EVOI/SPRT/pivot (R10 mimo R10-lite), FDR v produkci, auto-uzavírání, LLM, rozšíření detekce mimo zapojení `score_source_hosts`.
   - Soak v3 má 8 primárních předregistrovaných hypotéz s Holmovou korekcí (§7.4), ostatní jsou průzkumné.
8. **Efekty v §5 jsou hypotézy.** Kde chybí důkaz, píšu „bez podkladu“. Provozní laťka 14denního plánu (pokles zobrazených nálezů a FP/síť-den ≥ 70 %, minimálně 50 %) je volba autora práce, ne očekávání z literatury.

---

## 2. Metodika souhrnu

### 2.1 Jak se RQ1 až RQ6 spojily

- **Vstupem byly jen revidované závěry:** tabulky Závěry v `studie.md` po revizi (`revize-RQn*.md`; u RQ5 po druhé revizi `revize-RQ5-v2.md`). Číslo přebírám z textu studie a u každého uvádím id řádku. Vybrané řádky jsem porovnal s `extrakce.csv` (RQ1-040, RQ2-019, RQ3-021, RQ4-014, RQ6-046: hodnoty sedí) a ověřil, že citovaná id v extrakcích existují (kontrola 23 id: vše nalezeno). Vzorek je malý (K10). Při revizi metodiky jsem prošel 24 řádků proti textu tvrzení a našel 4 nesoulady interpretace (RQ3-025, RQ6-002, RQ1-024, RQ2-019; ≈ 17 %). Ve v1.1 jsou opravené (K1 až K4). Odhadovaná chybovost interpretace souhrnu je proto kolem 15 % (§8.1).
- **Audit kódu (01):** používám ho jako popis mechanismu. Tvrzení, na kterých stojí doporučení, jsem ověřil přímo v kódu, viz §4.4.
- **Prior art (09):** je to rychlá rešerše, převážně abstrakty a snippety. Používám ho jen v §8 k opatrnému vymezení novosti.
- **Naměřená data:** soak v1 [v1] a snímek v2b [v2b].

### 2.2 Pravidla převodu důkazu na doporučení

| dimenze | stupně | zdroj |
|---|---|---|
| jistota důkazu | vysoká / střední / nízká / velmi nízká / žádná | revidovaná tabulka Závěry. Když dvě RQ hodnotí tentýž zdroj různě, platí **nižší** jistota |
| použitelnost | ano / s úpravou / ne | sloupec použitelnosti v Závěrech; „ne“ jen jako argument |
| náročnost | S ≤ 1 den, M 2 až 5 dnů, L 1 až 3 týdny | audit 01 (odhad autora auditu) |
| naměřený blokér | ano / ne | soak [v1]/[v2b] nebo ověřená chyba v kódu |

Třídy doporučení:
- **P1 „opravit“:** naměřený blokér, nebo chyba harnessu doložená vysokou či střední jistotou z RQ5. Literatura tu dokládá problém, ne velikost efektu opravy.
- **P2 „zavést a ověřit“:** jistota aspoň střední pro směr a použitelnost ano nebo s úpravou.
- **P3 „testovat jako hypotézu“:** jistota nízká.
- **P4 „průzkumné“:** jistota velmi nízká nebo žádná.

Pořadí v §5 se řídí třídou a v rámci třídy náročností a závislostmi. Očekávaný efekt uvádím jen v rozsahu důkazu a vždy s jednotkou zdroje. Přenos na jednotku Skákavky (nález × cyklus, incident) je vždy extrapolace.

### 2.3 Co se do závěrů nepustilo

- Adresář `_predbezne/` (protokol §1).
- Řádky V1/V0 ze souborů `neovereno.md` a tvrzení výrobců (Splunk, Exabeam, Dynatrace, Vectra, Corelight a další, viz RQ1 §3b, RQ2 §10, RQ4 §10).
- **Čísla soak v2** (`run-v2-72h`), přestože je citují hypotézy v RQ1 až RQ6. Důvod: v2 je z analýzy vyřazeno a RQ5 (Metodika) ukazuje, že v2 s velkou pravděpodobností běžel s atribucí podle podřetězce a s oknem lookalike událostí prodlouženým o 2 cykly. Kde RQ studie stavěly hypotézu na v2, přepočítávám kontext na [v1] a [v2b].
- Přenos CIC-IDS-2017 → 2018 jako důkaz driftu (RQ2 Z8a).
- Řádky vyřazené revizemi: RQ4-033 a RQ4-034 (Lee a Lee), RQ3-048 jako důkaz (jen V2, kontext), RQ2-034 až 037 jako důkaz (CALIBURN, autor opravil popis kódu).
- Kvantitativní odhady auditu 01 (např. „−90 %“) nejsou důkaz. Uvádím je jako „odhad autora auditu“.

---

## 3. Mapa důkazů

| # | tvrzení | RQ a id důkazů | jistota po revizi | použitelnost pro Skákavku |
|---|---|---|---|---|
| M1 | Při základní četnosti 2·10⁻⁵ potřebuje polovina až dvě třetiny pravých poplachů FPR řádu 10⁻⁵. Při poměru 1:100 dává TPR 99 % a FPR 1 % 100 FP na 99 TP | RQ1 Z11 (RQ1-001 až 005), RQ5 Z-6a (RQ5-030, -055) | vysoká (matematika) | ano: hlásit FP/síť-den absolutně a precision při realistické četnosti |
| M2 | Detektory se na benchmarcích opírají o artefakty (TTL, adresy, porty, velikosti) a triviální pravidla dosahují špičkových výsledků | RQ5 Z-2 (RQ5-006, -007, -013 až -016, -018, -039) | vysoká | ano: artefaktové baseline v soaku |
| M3 | Veřejné datasety mají měřené vady v řádu desítek procent dat (jednotky se liší) | RQ5 Z-1 (RQ5-001, -002, -019, -022, -060) | vysoká | ano: kotvu CTU-13/IoT-23 hlásit per scénář s kontrolou štítků |
| M4 | Poměr útok:benign v publikacích sahá od 1:1 po 1:747 500; při malém podílu pozitiv vychází nízká precision | RQ4 Z15 (RQ4-025, -027, -035, -039, -043, -044) | vysoká | ano |
| M5 | Výsledky lateral movementu na LANL/OpTC jsou při jednotném předzpracování v provozním bodě o řády horší (AP Argus 32,27 → 0,09 %). AUC se přitom skoro nemění (Argus 99,83 → 98,44), propad AUC je až na přísně štítkovaných LM událostech (OpTC 43 až 53, RQ4-040) | RQ4 Z9 (RQ4-039, -040: vysoká), RQ2 Z9 (RQ2-027, -050: střední), RQ5 Z-8 (RQ5-024, -025: střední) | **střední** (sjednoceno na nejnižší, viz rozpor R-1) | ano: nepřebírat čísla |
| M6 | Agregace/shlukování snižuje počet položek o desítky % až přes 90 % podle datasetu | RQ1 Z1 (RQ1-012 až -014, -017, -018, -031, -032) | střední | s úpravou: vždy s recallem po rodinách |
| M7 | U nové nebo neopakující se události klesá redukce k 0 až 18 % | RQ1 Z2 (RQ1-019) | střední | ano: první výskyt nepotlačovat |
| M8 | Filtrace bez měření recallu může skrýt útoky | RQ1 Z3 (RQ1-020, -056) | střední | ano |
| M9 | Ověření proti stavu cíle snižuje nerelevantní poplachy. Aktivní ověření zranitelnosti (Kruegel, RQ1-021, -022) dosáhlo 98 až 100 % v testbedu a honeypotu. Ověření podle odpovědi služby, tedy výstupního provozu (ATLANTIDES, RQ1-024), dosáhlo 50 až 100 %. Selhává u variabilních protokolů (RQ1-025). Degradace podle pasivního inventáře, kterou navrhuje R6, je jiný mechanismus a přímý podklad nemá (K3) | RQ1 Z4 (RQ1-021 až -025) | střední (pro uvedené mechanismy) / žádná (pro inventář) | s úpravou: degradovat, ne mazat |
| M10 | Znalost služeb snižuje FP sekvenčního testu skenů (77 % Class C), STRW ale hlásí o 43 % méně skenerů a ztráta detekce nebyla změřena | RQ3 Z2 (RQ3-018 až -020, -022, -006) | nízká až střední | ano |
| M11 | Sekvenční test rozhoduje po jednotkách až desítkách pozorování a je rychlejší než Bro | RQ3 Z1 (RQ3-001, -002, -011, -015) | nízká až střední | s úpravou |
| M12 | Sekvenční test nerozhoduje vždy. U TRW zůstalo > 80 % vzdálených hostů nerozhodnuto, protože udělali příliš málo pokusů (RQ3-021). U BotProbe zůstalo 15,4 % nerozhodnuto **i se stropem** 3 kol (RQ3-025). Strop omezuje náklady, ale nerozhodnutost neřeší, proto je nutná eskalace nebo trojstavový verdikt (K1) | RQ3 Z3 (RQ3-021, -025, -009, -017) | střední | ano |
| M13 | Aktivní učení zvyšuje detekci při pevném rozpočtu (AI²: recall 0,868 při 200/den vs 0,737 při 1000/den, 12. týden) a šetří štítky (8×) | RQ3 Z5 (RQ3-029 až -031, -036, -037, -039) | střední (jiné domény) | s úpravou |
| M14 | Uncertainty sampling selhává při velmi nízké prevalenci a driftu; samotné dotazy na anomálie jsou špatné | RQ3 Z6 (RQ3-032, -033, -035, -038) | nízká | ano |
| M15 | Entropie belief jako proxy VOI snižuje MSE až o 50 % (simulace) | RQ3 Z12 (RQ3-056) | nízká | s úpravou |
| M16 | Předvídatelné pořadí kontrol je zneužitelné, randomizace pomáhá | RQ3 Z11 (RQ3-050, -051, -008) | nízká | s úpravou |
| M17 | Kaskáda levný filtr → drahý ověřovač šetří práci (−65 % času, 82,5 až 84 % FP), ztráta recallu 0 až 5,7 % (různé komponenty, nesčítat) | RQ3 Z7 (RQ3-040 až -042, -044, -052) | nízká až střední (směr), nízká (velikost) | s úpravou |
| M18 | Aktivní ověřování má doložená rizika (pád PLC, změna provozu uživatelů) | RQ3 Z10 (RQ3-053, -027, -025) | střední (existence) / velmi nízká (prevalence) | ano: passive-first u OT/IoT |
| M19 | RBA: kombinace Rule Level + Accumulation + Variety AUROC 0,93 (pět modulů 0,92) vs závažnost 0,72; při trailing okně 0,75 | RQ1 Z5 (RQ1-037 až -040) | nízká | ano jako pořadí, test A/B |
| M20 | Vzácnost a aperiodicita samy kolem náhody (AUROC 0,31 až 0,57) | RQ1 Z6 (RQ1-038) | nízká | s úpravou: nepoužít jako hlavní signál |
| M21 | Prosté časové okno je proti AlertBERT srovnatelné nebo lepší při zvýšeném šumu | RQ1 Z8 (RQ1-042, -043, -057, -058, -044) | velmi nízká | s úpravou: okno jako baseline |
| M22 | Per-entity testování a denní rozpočet alertů jsou spojeny s nízkým počtem FP; násobné snížení jen ve 2 nečistých srovnáních | RQ2 Z4 (RQ2-018, -024; -023, -025) | nízká | s úpravou |
| M23 | Adaptivní baseline (Holt-Winters) se adaptuje na anomálii; detekováno 64 z 67 vložených útoků, FPR neuvedeno. Že tím mine právě pozdější útok, je inference (K4) | RQ2 Z3 (RQ2-019) | nízká | ano: zmrazení / gating |
| M24 | Složitá sezónní/CUSUM struktura nad rezidui nemá doložený přínos | RQ2 Z2 (RQ2-001, -002, -053) | nízká | ano: začít jednoduše |
| M25 | Benchmarky časových řad jsou často řešitelné jednoduchým pravidlem, bez jasného vítěze | RQ2 Z1a (RQ2-012 až -015, -046, -051) | střední (nesíťová data) | ano: triviální baseline |
| M26 | Jednoduchý robustní práh bývá při nízké FPR srovnatelný nebo lepší | RQ2 Z1b (RQ2-021), RQ5 Z-12 (RQ5-007, -028, -053) | nízká (RQ2) / střední (RQ5, jiné úlohy) | s úpravou (viz rozpor R-4) |
| M27 | Parametry detektorů mění FPR/F1 o desítky procent až násobně | RQ2 Z5a (RQ2-004, -005, -016, -017) | střední | ano: ladit jen na dev seedech |
| M28 | Velká část alarmů z objemových řad pochází z legitimního provozu | RQ2 Z10 (RQ2-003) | nízká | ano |
| M29 | Při porušení výměnnosti klesá konformní pokrytí a kalibrace; rekalibrace potřebuje štítky z nové distribuce (~100) | RQ2 Z7 (RQ2-041 až -043, -045) | nízká | ano |
| M30 | BH nad konformními p-hodnotami drží průměrný FDR u iid dat; pro síťové entity nedoloženo | RQ2 Z6a (RQ2-028 až -030, -033) | střední (iid) / velmi nízká (síť) | s úpravou, P4 |
| M31 | Supervizované IDS ztrácí výkon při časovém posunu (směr) | RQ2 Z8a (RQ2-038 jen UGR'16, RQ2-044) | střední (směr) / nízká (škála) | s úpravou |
| M32 | Vysoké AUC beaconingu neimplikuje provozní použitelnost (při FPR 1 % 2 ze 3 metod 0 %) | RQ4 Z1 (RQ4-001, -002), RQ5 Z-7 (RQ5-026, -053) | nízká (RQ4) / střední (RQ5, obecně AUROC vs AP) | ano: TPR při pevném FPR |
| M33 | RITA skóre je pod ~12 spojení na dvojici prázdné | RQ4-014 (Sohail, velmi nízká kvalita, RQ4 §9) | velmi nízká | s úpravou |
| M34 | FP DNS exfiltrace jsou převážně legitimní bezpečnostní služby (12 z 18); bez whitelistu ≤ 1 nová FP doména/den po 2 dnech | RQ4 Z7 (RQ4-023, -024) | střední (whitelist neměřen) | ano |
| M35 | DGA v provozu 69 FP/h; po 17 měsících FNR > 10× kvůli novým rodinám | RQ4 Z6b, Z8 (RQ4-027 až -030) | střední | ano |
| M36 | First-seen hrana sama: FPR 4,4 %; Hopper s identitou a kauzální cestou 9 FP/den při TPR 94,5 % | RQ4 Z10, Z11 (RQ4-035, -036, -038, -043, -045 až -047) | střední | s úpravou: vyžaduje identitu |
| M37 | Stepping-stone/pivot detekce selhává při zpoždění 1 s (4 z 8 metod AUC 0,56 až 0,64); při chaffu 300 % 4 z 8 metod 0,59 až 0,64 | RQ4 Z12a (RQ4-048, -049) / Z12b (RQ4-050) | střední / nízká | s úpravou |
| M38 | Reverse shell/interaktivní relace z toků: **žádný recenzovaný TPR/FPR nenalezen**; jediné číslo je z endpointu | RQ4 Z13 (RQ4-056) | velmi nízká (absence) | ne: vlastní cíle |
| M39 | Kombinace dvou IDS: OR zvyšuje senzitivitu i FP, AND naopak; Zeek+Suricata neměřeno | RQ1 Z13 (RQ1-052 až -054) | nízká | s úpravou |
| M40 | LLM bez cíleného šetření: 0 % na škodlivé podmnožině; zero-shot nad toky kolem náhody | RQ6 Z1a (RQ6-009), Z1b (RQ6-021, -022) | nízká | s úpravou: ne do verdiktu |
| M41 | Pět publikovaných přístupů s GPT-4.1 propouští na Alert-Bench 40,4 až 70,2 % útoků. Jde o jeden preprint a jeden model (RQ6-001 až -003 jsou z téže práce). Týž zdroj uvádí u cíleného agenta AIDA FNR 3,1 % (RQ6-002, -006, autoři hodnotí vlastní návrh). SecAlertBench uvádí FPR 44 % (jen V2) | RQ6 Z2 (RQ6-001, -002, -008, -050), RQ6 Z5 (RQ6-006) | nízká | ano: neautomatizovat bez nezávislé replikace |
| M42 | Prázdný výsledek dotazu souvisí se zamítnutím útoku (98,6 % vs 30,3 %, asociace) | RQ6 Z3 (RQ6-003) | nízká | ano: „neověřeno“ ≠ benigní |
| M43 | Sebe-revize ve stejném kontextu kvalitu zhoršila | RQ6 Z4 (RQ6-004, -005, -017) | nízká | ano |
| M44 | Prompt injection přes logy je reálné riziko | RQ6 Z6 (RQ6-023 až -025) | střední (existence) / nízká (velikost) | ano |
| M45 | Bayesovská kombinace doplňkové evidence a spolehlivosti senzoru: falešné alarmy 1,58 → 0,74 %, predikce −3 p. b. | RQ6 Z10 (RQ6-046, -047) | nízká | ano |
| M46 | Abdukce s benigními vysvětleními jen demonstračně | RQ6 Z11 (RQ6-047, -049) | velmi nízká | s úpravou |
| M47 | Nezávislá hodnocení provenance detektorů původní výsledky nepotvrzují (3 týmy) | RQ6 Z9 (RQ6-040 až -043, -045) | střední | ano (metodicky) |
| M48 | Učení z verdiktů analytika: 61 % alertů uzavřeno živě při FNR 1,36 % (jedna firma) | RQ1 Z10 (RQ1-048, -049), RQ3 Z7 (RQ3-044), RQ6 Z13 (RQ6-030) | nízká | s úpravou: laťka, FNR vzorkem |
| M49 | Přenos mezi datasety: relativní pokles 20 až 72 % | RQ5 Z-3 (RQ5-013, -034 až -038) | střední | s úpravou: kotvu hlásit odděleně |
| M50 | Distribuční podobnost syntetiky nezaručuje úlohovou užitečnost | RQ5 Z-5 (RQ5-042 až -047, -049) | střední | ano: doménové testy soaku |
| M51 | Statistická významnost, rozptyl a držené sady v NIDS literatuře chybějí (2 z 30) | RQ5 Z-9 (RQ5-027, -040, -041) | střední | ano |
| M52 | Přimíchání reálného pozadí snižuje detekce a zvyšuje podíl legitimních | RQ5 Z-4 (RQ5-017, -018) | nízká | ano: hybridní soak |
| M53 | Vysvětlení zvyšují důvěru víc než přesnost | RQ6 Z12 (RQ6-027 až -029) | nízká | s úpravou |

### Rozpory mezi studiemi a jejich vysvětlení

- **R-1, jistota téhož zdroje (Larroche):** RQ4 Z9 hodnotí nadsazení výsledků LANL/OpTC jako vysokou jistotu, RQ2 Z9 je po revizi snížila na střední, protože jde o jeden preprint jednoho autora (RQ2-027, -050), a RQ5 Z-8 je střední. Jde o tytéž řádky z téže práce (RQ4-039 = RQ2-027/050 = RQ5-024). Podle pravidla 2.2 přebírám **střední**. RQ4 navíc opírá jistotu o deterministickou re-evaluaci a 10 běhů, což je argument pro přesnost čísel, ne pro jejich nezávislou replikaci.
- **R-2, vzácnost:** RQ1 Z6 (RBA moduly vzácnosti a aperiodicity kolem náhody, RQ1-038) proti RQ6 Z8a a hypotéze RQ6 H-4 (řazení podle vzácnosti kontextu ve stylu NoDoze, −84 %, RQ6-031). Vysvětlení: jde o jiné veličiny. RBA měří vzácnost signatury alertu v čase, NoDoze vzácnost přechodů v kauzálním grafu hostu s prahem voleným dodatečně. Pro toky Skákavky přímý důkaz není. RQ6 H-4 proto ponechávám jako P3 s RQ1-038 jako negativním priorem.
- **R-3, NoDoze:** 84 % v PDF (RQ6-031, RQ1-026), 86 % na stránce NDSS (RQ3-048, V2) a AUC 0,60 v cizím hodnocení na ATLASv2 (RQ3-043). Vysvětlení: jiné metriky a datasety a dodatečný práh. Žádné z čísel nepřebírám jako očekávaný efekt.
- **R-4, jednoduchý práh:** RQ2 Z1b (nízká, jediné síťové měření) proti RQ5 Z-12 (střední, tři zdroje, různé úlohy). Obě studie se shodují ve směru. RQ5 má vyšší jistotu, protože zobecňuje přes úlohy, ne kvůli síťovému měření prahu. Pro práh na tocích platí nízká jistota, pro povinnost triviální baseline v hodnocení střední.
- **R-5, adaptace:** adaptivní baseline se otráví (RQ2-019), adaptivní kalibrace prahu FPR zlepšuje (RQ2-045). RQ2 to vysvětluje jako adaptaci úrovně proti adaptaci prahu. Plyne z toho gating úrovně a adaptivní kalibrace prahu.
- **R-6, statistika:** hypotézy RQ6 (a část RQ1 až RQ4) počítají s Wilsonovými intervaly, RQ5 (S9, Z-9) ukazuje, že útoky v jedné síti nejsou nezávislé. Pro soak v3 platí clusterový bootstrap přes sítě (RQ5). Wilson zůstává jen informativně.
- **R-7, seedy:** RQ6 navrhuje 2 vývojové a 3 testovací seedy, RQ5 10 ladicích (20261031 až 20261040) a 10 držených (20261101 až 20261110). Seed 20261101 už použil běh v2b, který v této studii analyzuji, takže není „neviděný“. Sjednocuji na RQ5 s posunem: držené **20261102 až 20261111**, rozdělené na H1 a H2 a každá část použitá jen jednou. 20261101 slouží jen k diagnostice (§7.2, upraveno podle K19).
- **R-8, AACT 34 / 61 / 74 %:** jiné jmenovatele (RQ1 Z10), ne nejistota. Jako laťku přebírám jen živou hodnotu 61 % při FNR 1,36 % (RQ1-048).
- **R-9, kontext stojí detekci:** RQ1 Z4 uvádí 50 až 100 % snížení FP bez nových FN (ATLANTIDES, RQ1-024), RQ3 Z2 ukazuje, že STRW se znalostí služeb hlásí o 43 % méně skenerů (RQ3-020). Vysvětlení: jiné úlohy (exploit vs sken) a ztráta detekce u STRW nebyla změřena. Důsledek: každá kontextová vrstva musí mít měřený recall (RQ1 Z3).
- **R-10, časové rozdělení:** TESSERACT ukazuje velký vliv, BRIDGE zanedbatelný (−0,009 F1, RQ5-038). RQ5 to vysvětluje rychlostí změny distribuce. V soaku s epizodami v řádu dnů a týdnů se čeká spíš malý vliv, ale nebylo to měřeno.

---

## 4. Diagnóza našich dat ve světle literatury

Odděluji **[N] naměřeno** (soubor), **[I] interpretace** (s odkazem na důkaz) a **[S] spekulace** (bez důkazu).

### 4.1 Co naše data ukazují

Jednotkou D1 a D3 je **nález × cyklus**. Každý cyklus se tentýž stav vydá znovu (A14), což nafukuje FP i připsané nálezy. Atribuce oknem ±2 cykly (S5) přesouvá nálezy z FP do „připsaných“, takže FP podhodnocuje a precision nadsazuje. Směr výsledného zkreslení neznám (K14). Sloupce v1 a v2b nejsou srovnatelné: jiný generátor (11 proti 19 rodinám, 5 proti 10 archetypům, v1 bez provozních událostí) a jiný mix velikostí (K15). Rozdíl 210,7 proti 932,1 proto neznamená zhoršení enginu.

| # | jev | soak v1 | soak v2b (snímek 2026-11-01 00:03, 1,00 h) |
|---|---|---|---|
| D1 | behaviorální FP bez příčiny (nález × cyklus) | 210,7 / síť-den, 75 % `inductive_volume_anomaly`, 22 % `packet_rate_spike` [v1] | 932,1 / síť-den; `unexpected_traffic` 43,3 %, `inductive_volume_anomaly` 37,7 %, `packet_rate_spike` 10,6 %, `unmapped_passive_event` 5,8 % (podíly: vlastní výpočet z [v2b]) |
| D2 | závislost na velikosti sítě | – | S 63,54 FP/síť-den (15 zařízení, n = 45 sítí), M 299,32, L 2 337,68, XL 3 891,38 (840, n = 42), XXL 2 201,31 (2 701, n = 5) [v2b]. Sklon ≈ 1,0 jsem původně spočetl jen ze dvou bodů (S a XL), což je slabé (K11). XXL je nižší než XL, takže monotónní linearita neplatí. Velikost je zmatená s archetypem: Cloud 10 959,99 při 451 zařízeních, Enterprise 1 418,19 při 853. Sklon kolem 1 je navíc triviální očekávání při konstantním FP na zařízení. Správný odhad je regrese log FP proti log zařízení s efektem archetypu a clusterovým CI, zvlášť po typech FP (úkol E0) |
| D3 | precision behaviorálních nálezů (nález × cyklus) | – | ≈ 17 % = 306 415 / (306 415 + 1 478 364) (vlastní výpočet z [v2b]). Dokud ji E0 nepřepočítá na incidenty a placebo, nepoužívat ji jako výsledek (K14) |
| D4 | základní četnost | – | 3 655 pozorovatelných útoků na 1 586 síť-dnů ≈ 2,3 / síť-den; síť-dnů bez útoku 8,0 [v2b] |
| D5 | ověřování mimo rozpočet (smíšený jev: rozpočet 10/2 v produkčním `verification_exec.rs` a plánování v soaku bez historie, A32; podíl obou určí E0, K9) | 68 % ze 74,1 M plánů [v1] | 8 767 737 z 9 909 464 = 88,5 % (vlastní výpočet z [v2b]) |
| D6 | exploit_attempt | detekováno 68,8 %, správný typ 0,0 %, IDS vidělo 2 301 z 5 061 [v1] | 65,8 % / 0,0 %, IDS 138 z 339 [v2b] |
| D7 | exfiltrace, zdrojové pořadí | 0,0 % → 42,1 % s egress [v1] | 0,0 % → 37,2 % [30,6; 44,2] s egress [v2b] |
| D8 | c2_beacon | detekováno 4,7 %, typ 0,3 % [v1] | 11,7 % [8,4; 15,9], typ 6,7 %, medián latence 450 min [v2b] |
| D9 | rogue_device | 0,2 % [v1] | 16,8 % (n = 101) [v2b]. Podle velikosti: S 42 % (n = 19), M 28 % (n = 29), L 5 % (n = 20), XL 0 % (n = 31), XXL 0 % (n = 2). Snímek po 1,25 h má podle revize metodiky XL 4 % (n = 55, K6). Malá n nedovolují tvrdit trend, nanejvýš S proti L + XL + XXL |
| D10 | lateral_movement, správný typ | 12,5 % [v1] | 52,1 % [46,1; 58,0] [v2b] |
| D11 | provozní a benigní lookalike s FP | – (v1 je nemá) | patch_window 97,7 %, collector_replay 93,8 %, service_crash 89,6 %, batch_job 74,9 %, log_corruption 71,4 %, flash_crowd 64,8 %, backup_burst 62,3 %, authorized_scanner 42,7 %, sensor_crash 0,0 %, retry_storm 0,0 %, software_update 0,0 % [v2b]. Flash_crowd, backup_burst a authorized_scanner nejde vysvětlit zdravím senzoru a jen zčásti kalendářem (K22) |
| D12 | kalibrace Case Memory | Brier 0,0107; pásmo 0,1 až 0,5 překonfidentní, p ≥ 0,6 podkonfidentní [v1] | Brier 0,0203; [0,5; 0,6) predikce 0,534 → skutečnost 0,327, [0,8; 0,9) 0,867 → 0,997; 82,2 % predikcí v koši [0,9; 1,0) (vlastní výpočet) [v2b] |
| D13 | identita | falešné rozdělení 8,7 %, sloučení 1,7 % [v1] | 32,8 % / 20,8 % [v2b] |
| D14 | kotva CTU-13/IoT-23 | ablace A porazí triviální baseline v 6 z 20 scénářů [v1] | totéž, 6 z 20 [v2b]. IoT-23 má zdrojový lift 0,00× v 6 ze 7 scénářů se škodlivým provozem a 10,75× u Capture-3-1. U 3 honeypotů bez škodlivého provozu metrika není definovaná [v2b]. Ve v1.0 tu bylo chybně „0,00× ve všech“ (K5) |
| D15 | zdraví harnessu | 0 panik, halda bez trendu [v1] | 0 panik; halda +78,14 MiB/h (R² 0,80), „podezření na únik“ [v2b] |

### 4.2 Co literatura očekává

- **D1, D2, D11: šum z objemových anomálií a provozních událostí.** [I] Velká část alarmů z objemových řad pochází z legitimního provozu (M28, RQ2-003, nízká). Analytici v SOC rozlišují „benigní spouštěč“ (M12/RQ1 Z12, RQ6-029). Detektory selhávají na stále se měnících benigních aktivitách (RQ6-043, součást M47). Literatura tedy směr očekává, velikost ne: jednotky se liší (RQ2 §7). [N] Mechanismy jsou v kódu, každý jen pro svůj typ:
   - `inductive_volume_anomaly`: průřezové z-skóre bez paměti (`anomaly.rs:334-398`, A02).
   - `packet_rate_spike`: maximum podílu přes toky (`anomaly.rs:249`, práh 2 800 pps / 40 Mbit/s, ověřeno), které roste s počtem toků. Spočtená pravděpodobnost p ≈ 0,0025 na tok je jen analytický odhad autora auditu (A04).
   - `unexpected_traffic` (největší typ ve [v2b]) s mechanismem maxima nesouvisí. Má vlastní mechanismus: inventář a stav spojení (A08, A09), viz R13.
   
   [I] Mechanismus „maximum přes toky“ proto vysvětluje nanejvýš růst `packet_rate_spike` s velikostí, ne sklon celku (K11).
- **D3, D4: základní četnost.** [I] Při realistické četnosti (odhad autora RQ5: 0,01 až 0,1 útoku/síť-den, RQ5 S4) by precision byla řádově nižší než 17 % (M1). Soak má 2,3 útoku/síť-den a jen 8 síť-dnů bez útoku, takže precision i FP/síť-den jsou mimo provozní režim.
- **D8: beacon.** [I] Nízká detekce při omezeném FP odpovídá literatuře: při FPR 1 % 0 až 77 % podle metody (RQ4-001, -002), u fúze na reálných capturech 13,2 % (RQ4-012). RQ5 však upozorňuje, že náš beacon restartuje fázi na začátku každého cyklu, takže periodicita je artefakt generátoru (RQ5, Co platí pro soak, bod C2). Literatura tu směr očekává, ale srovnání není čisté.
- **D10: lateral.** [I] Lateral je při přísném štítkování těžký i pro grafové metody (M5, RQ5-025). Náš „správný typ“ 52,1 % je proto spíš optimistický (S5 benevolentní atribuce).
- **D12: kalibrace.** [I] Pod posunem se kalibrace degraduje a rekalibrace potřebuje štítky z cílové distribuce (M29, nízká). Brier je dominován košem [0,9; 1,0) (82,2 %), tedy statickými expozicemi (A33). Výborný Brier neříká nic o behaviorálních typech.
- **D14: kotva.** [I] Triviální baseline často dorovná složitou metodu (M26, RQ5 Z-12, střední). Že ablace A prohraje ve 14 z 20 scénářů, literatura spíš očekává. Mechanismus v kódu: kotva předává prázdné `known_services` (`src/eval/dataset_replay.rs:137`, ověřeno), takže ablace A se blíží pravidlu „aspoň 3 toky na klíč“ (RQ5 S11).
- **Drift** se v 1h snímku [v2b] měřit nedá. FP/síť-den podle délky běhu (24 h 2 729,78 vs 720 h 198,73) je zmatené velikostí sítě (průměr 403 vs 40 zařízení) [N]. Neinterpretuji to jako učící křivku.

### 4.3 Co je záhadné (bez vysvětlení v literatuře ani v auditu)

- (Zrušeno ve v1.1: „záhada“ IoT-23 s liftem 0,00× ve všech scénářích stála na chybně přečtené tabulce, K5. Capture-3-1 má 10,75×, viz D14. Lift 0,00× v 6 scénářích IoT-23 (6 až 21 222 škodlivých toků) zůstává nevysvětlený, bez dalšího rozboru ho ale neoznačuji za záhadu.)
- [N] CTU-13 Botnet-44: F1 ablace A 0,001 proti triviální baseline 0,998 [v2b]. Rozdíl je extrémní a příčinu jsem nedohledal.
- [N] rogue_device: S 42 % (n = 19) proti L + XL + XXL 1 z 53 (vlastní výpočet z [v2b]; malá n, K6). [S] Pokud rozdíl přetrvá, souvisí nejspíš se vzorkováním toků (S3: `flow_sampling()` = 300 / počet zařízení, minimum 0,08, `netmodel.rs:879-881`, ověřeno) a s identitou (D13). Netestováno.
- [N] Archetyp Cloud má 10 959,99 FP/síť-den při 451 zařízeních v průměru, Enterprise 1 418,19 při 853 [v2b]. Velikost to nevysvětluje. [S] Může jít o churn kontejnerů (role `container`) a `unexpected_traffic`. Neověřeno.
- [N] log_corruption má 71,4 % s FP, přestože rozbité toky mají podle auditu náhodný port (A29). [I] Vysvětlení je atribuce podle okna, viz 4.4.

### 4.4 Co může být artefakt simulace nebo měření (RQ5 S1 až S11, audit A28 až A35)

Ověřeno v kódu (stav pracovního stromu 2026-11-01):

| artefakt | doklad (ověřeno) | dopad na naše čísla | oprava |
|---|---|---|---|
| S1: benigní odchozí cíle jen z 12 `externals`, útočné z `public_ip()` | `public_ip()` losuje 1. oktet z {45, 61, 77, 91, 103, 154, 178, 193, 198}, `soak/traffic.rs:392-400` | po otevření egress (R2) by „nový externí cíl“ triviálně oddělil útoky (M2) | RQ5 H-1 před R2 |
| S2: platné Suricata alerty jen z útoků | benigní pravdy `ids_visible: false`, `traffic.rs:903` | precision IDS cesty (R3) by v soaku byla 1 z konstrukce | benigní alerty v generátoru |
| S3: útočné toky se nevzorkují | `netmodel.rs:879-881` | útok je ve velkých sítích relativně hlasitější | RQ5 H-3 |
| S5: atribuce útoku v okně [start−2, konec+2] na libovolné klíčové IP | `soak/episode.rs:52`, `:710-711`; přesná shoda IP `mentions_ip` `:164` (oprava A28 je v kódu) | „detekováno“ je nafouknuté u rodin s mnoha klíčovými IP | placebo okna (RQ5 H-4) |
| A29: lookalike s oknem dostane každý nepřipsaný nález v [start, konec] | `soak/episode.rs:734-746`: okno už bez +2 cyklů, ale stále bez kontrafaktuálu | sensor_crash 0,0 % [v2b] odpovídá predikci A29, že prodloužené okno nafukovalo FP. Hodnoty log_corruption 71,4 % a collector_replay 93,8 % jsou ale stále z části artefakt [I] | kontrafaktuál `mask_truth` (A29) |
| A30/S7: `expected_types` obsahují typy, které nevzniknou | `findings.rs:28-57`: `SERVICE_RULES` nemají pravidlo pro `suricata_alert` (ověřeno, grep bez výskytu) | 0,0 % typu u exploitu je z konstrukce, ne měření schopnosti | R3 a hlášení „nedosažitelné z konstrukce“ |
| A06: `history` v soaku chybí | `is_timeout_like` převádí `history` na malá písmena a počítá `r`/`t` jako timeout (`passive/anomaly.rs:482-496`, ověřeno) | zdroj FP na reálném Zeeku v simulaci není vidět (RST jako timeout) | oprava kódu + kotva |
| S9: Wilson přes útoky | `stats.rs`, `report.rs` (podle RQ5, neověřoval jsem) | intervaly v [v2b] jsou pravděpodobně příliš úzké | clusterový bootstrap |
| S10: jeden seed pro ladění i hlášení | [v2b] seed 20261101 | – | držené seedy (§7) |
| S11: kotva bez inventáře | `dataset_replay.rs:137` `HashSet::new()` | D14 | dodat pasivní inventář |
| reprodukovatelnost buildu | [v2b] uvádí commit `15e6fd5`, který je předkem `a293d2b` (commit 23:40 SEČ, běh od 23:03 SEČ) | podle popisu běhu v2b odpovídá opravené verzi `a293d2b`. Konzistentní s tím je sensor_crash 0,0 % a 0 panik. Binárka byla ale postavená z necommitnutého stromu, takže to **nelze nezávisle ověřit** | do status zapisovat hash a příznak „dirty“ |

[I] Strukturální chyby jádra, které dávají D6 a D7 bez ohledu na harness a k D5 přispívají spolu s plánováním harnessu (A32, K9) (ověřeno v kódu):
- filtr scope jen podle cíle (`passive/zeek.rs:173-175`, `passive/suricata.rs:69-70`, A10),
- klasifikace Suricaty podle klíčových slov a portu 80 (`passive/suricata.rs:111-124`, A11),
- utilita plánovače bez aktuální pravděpodobnosti (`verification_planner.rs:53-62`, A23),
- rozpočet 10 kontrol na běh a 2 na cíl (`verification_exec.rs:38-46`) a no-op `passive_extended_observation` (`verification_exec.rs:79`, A23, A24),
- `finding_id` bez času (`findings.rs:815-826`, A14),
- odhad Case Memory jen podle typu nálezu (`case_memory.rs:209-232`, A21),
- prázdné `contradicting_evidence` (`hypothesis.rs:156`, A20),
- nepoužité `time_window_s` (`correlation.rs:6-46`, A16),
- `score_source_hosts` je definovaná v `passive/anomaly.rs:110` jako `pub(crate)` a volá ji jen `src/eval` (A19; upřesněno podle revize rozsahu). Zapojení do produkce je tedy levné, levné ale nejsou prahy.

---

## 5. Doporučení (top 12 + R13)

Pořadí realizace je v §5.x a v §5A. Oddíly 5.g až 5.f jsou řazené tematicky. Společný protokol měření (podrobně §7):
- **Párové A/B:** u pasivních změn přes jednou vygenerovanou a uloženou telemetrii. Kde to nejde, na stejných `(seed, network_id)` se zablokovanou zpětnou vazbou zásahů do generátoru (K20). Generátor je deterministický (`soak verify` 30/30 [v1]).
- **Statistika:** párový rozdíl na síť, 95% clusterový bootstrap přes sítě stratifikovaný podle seedu a archetypu (B = 2 000, RQ5 Překlad bod 4).
- **Seedy:** ladění na L, rozhodování na V, potvrzení na držených H, každá část H jen jednou (§7.2). Kotva je rozdělená na vývojovou a testovací část, testovací se k ladění nepoužije.
- **Ochranné kritérium:** je odvozené z výpočtu síly (§7.4a, P0). Ve v1.0 bylo „≤ 2 p. b. per rodina s ≥ 100 útoky“, což je nesplnitelné (K17).

### 5.g Metodika měření

**R1 (P1): oprava harnessu a reportu, rozdělená na G0-min a G0-plné (revize rozsahu P1).**

Ve v1.0 R1 blokovala všechny ostatní body. To bylo chybně: snížení šumu se dá měřit na surových počtech nálezů za síť-den párově A/B, protože atribuce ovlivňuje „detekováno“, ne počet nálezů, a v obou ramenech je stejná.
- **G0-min** (≈ 3 dny, odhad z revize rozsahu) je jediná podmínka pro R5, R7-lite, R4-lite, R3 a R13:
  - FP/síť-den absolutně po typech,
  - zobrazené nálezy/síť-den,
  - `S_quiet`,
  - `noop_share`,
  - hash buildu a příznak dirty ve status,
  - párování A/B přes jednou vygenerovanou telemetrii (§7.3),
  - metriky enginu (§5A.3).
- **G0-plné** (≈ 8 až 12 dnů, odhad z revize rozsahu) běží souběžně a je podmínkou pro R2, R3 (precision IDS), R6 a finální fázi E3 (§7.3). Obsahuje body níže.
- **Změna (G0-plné):**
  - `soak/episode.rs:700-760`: placebo okna pro útoky a kontrafaktuální běh s `mask_truth` pro lookalike (A29, A31, RQ5 S5).
  - `soak/traffic.rs:1194-1216`: počítadlo „doručeno do telemetrie“ za `degrade` (S6).
  - `soak/traffic.rs:105-200`: `expected_types` sladit s cestou enginu a zvlášť hlásit „nedosažitelné z konstrukce“ (A30).
  - `soak/report.rs` a `soak/stats.rs`:
    - clusterový bootstrap (S9),
    - FP/síť-den absolutně, precision a precision přepočtená na četnost 0,01 až 0,1 útoku/síť-den (odhad autora RQ5),
    - recall při pevném FP/síť-den, AP,
    - `executed_by_method` a `noop_share` (A24),
    - kalibrace zvlášť pro behaviorální a statické typy (A33),
    - tři artefaktové baseline (RQ5 Překlad bod 1).
  - Generátor: S1 (benigní egress i na nové adresy z `public_ip()`), S2 (benigní Suricata alerty), S3 (stejné vzorkování), `S_quiet` (`attack_rate = 0`), volba `start_at_zero`.
  - `main.rs`: přepínač `--engine`. Do status zapisovat hash buildu a příznak dirty.
  - Opravit trend haldy +78 MiB/h [v2b] nebo omezit délku běhů.
- **Důkazy pro:** RQ5 Z-2 (vysoká), Z-6a (vysoká), Z-7 (střední), Z-8 (střední), Z-9 (střední), Z-12 (střední); RQ1 Z11 (vysoká); RQ4 Z15 (vysoká); M51.
- **Očekávaný efekt:** na FP enginu žádný. Na vykázaných číslech: placebo míra ≥ 20 % u rodin s mnoha klíčovými IP a ≤ 5 % u rodin s jednou (odhad autora RQ5 H-4, opřený o RQ5-053, -025). Odchozí FP po S1 vzrostou aspoň 1,5× (odhad autora RQ5 H-1). Šířka CI vzroste aspoň 1,5× (odhad autora RQ5 H-7).
- **Rizika a negativní důkazy:** po opravě atribuce může vykázaná detekce klesnout a FP vzrůst (A28). To je žádoucí, ale znamená to, že nová čísla nejdou srovnat s [v1] ani [v2b]. Proto zachovat i starou metriku.
- **Závislosti:** žádné. **Náročnost:** G0-min S, G0-plné M až L (realisticky 1,5 až 3 týdny, P1).
- **Hypotézy:** průzkumné X01 až X05 (§7.4b) = RQ5 H-1, H-3, H-4, H-5, H-7 a kontrafaktuál A29. Měří velikost artefaktů a o změně enginu nerozhodují.
- **Měření:**
  - Engine beze změny, rameno A = harness dnes, B = opravený harness, seedy L (§7.2).
  - E0 navíc rozloží `unexpected_traffic` podle příčiny (R13) a odhadne závislost FP na velikosti regresí s efektem archetypu (D2).
  - Cirkularita: tento krok je jediný, kde se smí dívat na výsledky L bez předregistrace, protože se nemění engine.

### 5.d Telemetrie a nástroje

**R2 (P1): scope `src ∈ S ∨ dst ∈ S` a směr toku (A10), současně s odstraněním S1.**
- **Změna:** `passive/zeek.rs:46-48, 102-106, 173-178`; `passive/suricata.rs:69-73`; `passive/mod.rs` (`in_scope` → `in_scope_flow` se `Direction`); `soak/episode.rs:487-492`. Pravidla závislá na inventáři (`unexpected_traffic`) pouštět jen na interní cíle.
- **Důkazy pro:** naměřený blokér: exfiltrace 0,0 % zdrojového pořadí, s egress 42,1 % [v1] a 37,2 % [v2b]. Literatura kvantitativní cíl nedává (RQ4 §3c, §9). Riziko filtrace: RQ1 Z3 (střední).
- **Očekávaný efekt:** bez podkladu. Hodnota ≈ 37 % [v2b] pochází z diagnostického skóre `score_source_hosts` nad všemi toky, ne z produkčního detektoru po R2. Je to horní reference téže metriky, ne očekávaný efekt změny (K16). Detekce C2/mining s externím cílem: bez podkladu. R2 není snížení šumu, ale rozšíření detekce, a počet nálezů nejspíš zvýší (revize rozsahu P5).
- **Rizika:**
  - Nové FP z `retry_storm` a `software_update` (dnes 0,0 % jen proto, že se zahodí, [v2b], A10).
  - Bez S1 by engine mohl detekovat útok podle novosti externí adresy, což je artefakt (M2, RQ5 S1).
  - Bez příznaku směru vyrobí každé odchozí spojení na internet `unexpected_traffic`. Před R2 proto napsat test: syntetický odchozí tok na veřejnou IP nesmí `unexpected_traffic` vytvořit (Q1).
  - Toky se zdrojem mimo scope může útočník nebo skener použít k vyrobení neomezeného počtu klíčů a nafouknout stav nálezů a Case Memory (B2). Proto strop kardinality (top N podle skóre, zbytek do agregátu „externí šum“), TTL a metrika velikosti stavu.
- **Závislosti:** G0-plné (S1 a S2 musí být opravené dřív). **Náročnost:** S v kódu, ≈ 3 dny s testy (revize rozsahu Q2). Do 14denního jádra nepatří (§5A).
- **H:** průzkumná X06.
- **Měření:**
  - Metriky: zdrojové pořadí exfiltrace, detekce a typ C2/exfil/mining/fleet_beacon, FP/síť-den podle typu (zvlášť odchozí), negativní kontrola u rodin jen s příchozím externím zdrojem (ssh_bruteforce, credential_stuffing, web_exploit, ddos_volume) s rozdílem < 2 p. b. (RQ5 H-1).
  - Zamítnutí: zdrojové pořadí exfiltrace < 20 % (RQ4 H4-5), nebo artefaktová baseline (a) „odchozí na adresu mimo `externals`“ má v rameni B vyšší precision než engine.

**R3 (P1): mapování alertů Suricaty a pravidlo nálezu `ids_alert` (A11, A12).**
- **Změna:** `passive/suricata.rs:111-124` (`classify_signature`): mapovat podle `alert.category` a prefixu signatury (ET EXPLOIT/SCAN/MALWARE/DOS) na typ a techniku ATT&CK, zrušit větev `dst_port == Some(80)`. `findings.rs:28-57`: přidat pravidlo `ids_alert` pro službu, host i unmapped. Do `NormalizedEvent` přidat `category`, `signature_id`.
- **Důkazy pro:** naměřený blokér: typ 0,0 % při IDS viditelnosti 138 z 339 [v2b]. Pravidla nad technikami mají sama nízkou precision (1,9 %, RQ6-032), takže alert slouží jako signál, ne jako verdikt. Kombinace senzorů: RQ1 Z13 (nízká).
- **Očekávaný efekt:** při dnešním generátoru a výhradně IDS cestě je referenční mez správného typu exploit_attempt ≈ 40 % (138/339 = 40,7 %, vlastní výpočet z [v2b]). Nejde o strop: typ mohou dát i ne-IDS signály a opravy S2 a S6 změní viditelnost (K13). Přínos je hlavně srozumitelnost pro správce, ne nižší počet nálezů (P6).
- **Rizika:** kvůli S2 by precision IDS cesty v soaku byla 1 z konstrukce. Typ nálezu se proto smí měřit hned (G0-min), precision `ids_alert` až po benigních alertech (G0-plné). „2 senzory = potvrzení“ nezavádět jako pevné pravidlo (M39).
- **Závislosti:** G0-min (typ), G0-plné (precision). **Náročnost:** S, ≈ 2 dny (Q2).
- **H:** primární P6 (§7.4a).
- **Měření:**
  - Metriky: správný typ exploit_attempt a web_exploit, FP `ids_alert`/síť-den na benigních alertech, kotva CTU-13 (alert logy, pokud existují; jinak jen soak).
  - Zamítnutí: typ exploit < 0,9 × podíl viditelný IDS (kritérium auditu, krok 3), nebo FP `ids_alert` na benigních alertech > FP, které nahradí (volba autora).

**Zeek zdroje a identita (součást R8):** pro lateral movement bez identity (Kerberos/NTLM) není měřená FPR (RQ4 §9). Hopper s 9 FP/den stojí na přepnutí přihlašovacích údajů (M36). Do ingestu doporučuji `dhcp.log` (identita) a `dns.log`/`ssl.log` (R11), `kerberos.log`/`ntlm.log` jen jako P4, protože měření chybí. Oprava `is_timeout_like` (A06, ověřeno) je chyba kódu bez potřeby literatury. Měří se jen na kotvě, protože soak `history` negeneruje.

### 5.a Snížení šumu

**R4 (P2): perzistentní stav nálezu, deduplikace mezi detektory a agregace do incidentů s nepotlačitelným prvním výskytem. Dvě etapy: R4-lite teď, incidenty později (P4).**

`build_finding_id` (`findings.rs:815-826`) je bez času, a tedy stabilní. Problém není ID, ale chybějící perzistentní stav za ním, takže pipeline vydá nález v každém cyklu znovu (upřesněno podle revize rozsahu).
- **R4-lite** (≈ 6 až 8 dnů včetně migrace, Q2):
  - `first_seen`, `last_seen`, `occurrences` v `Finding` (`#[serde(default)]`) a nový `finding_state.rs`.
  - Znovuvydání při změně stadia, Δp ≥ 0,1, **nové zdrojové IP nebo novém typu na stejném klíči** nebo po klidu (B1).
  - **Strop kardinality a TTL** stavu (nejstarší a nejslabší stavy do agregátu, metrika velikosti tabulky; B2, M6).
  - Agregace `unmapped` podle `(dst, port, typ, den)`.
  - První výskyt vždy zobrazit.
- **Plná R4** (incidenty, `cause_key`, `incident_id`): až po 14denním jádru.
- **Změna (plná):**
  - `findings.rs:815-826` (`build_finding_id`) a `model.rs` `Finding` + `first_seen`, `last_seen`, `occurrences`, `src_key`, `incident_id`; nový `finding_state.rs` (znovuvydání jen při Δp ≥ 0,1, změně stadia nebo po klidu; parametry z auditu, volba autora).
  - `Signal.cause_key` pro sloučení závislých detektorů jednoho agregátu (A18).
  - Agregace `unmapped` podle `(dst, port, typ, den)` (A13, `findings.rs:102-121`).
  - Baseline seskupení = prosté časové okno (M21).
- **Důkazy pro:** RQ1 Z1 (střední, desítky % až > 90 %), Z2 (střední, první výskyt), Z3 (střední, měřit recall), Z8 (velmi nízká, okno jako baseline); RQ6 Z8b (nízká, shlukování −2/3 ruční práce, RQ6-044).
- **Očekávaný efekt:** v literatuře 70 % průměr (RQ1-017), 93 až 95 % v prostředí s opakujícím se provozem (RQ1-018), 0 až 18 % u nových událostí (RQ1-019). Jednotka je alarm IDS, ne nález × cyklus. Pro metriku nálezů × cyklů je to bez podkladu. Audit odhaduje −80 až −95 % z poměru opakování 20 až 48× denně (A14, odhad autora auditu).
- **Rizika:**
  - **Deduplikace může zakrýt nový útok** na hostu s už otevřeným nálezem (audit (e), B1). Zábradlí: znovuvydání při novém zdroji nebo typu a regresní scénář „útok na hostu s otevřeným nálezem“ (§5A.3).
  - Filtry skrývající útok (RQ1 Z3).
  - Agregace v korelačních enginech může zvýšit latenci detekce (K22). Proto práh TTD.
  - Vyčerpání paměti stavem bez stropu (B2).
- **Závislosti:** G0-min. **Náročnost:** R4-lite M (6 až 8 dnů), plná R4 L.
- **H:** primární P3 (§7.4a), odvozeno z RQ1 H1-1.
- **Měření:**
  - Metriky: zobrazené nálezy a FP stavy/síť-den, `reemissions_per_state`, typovaná detekce, medián TTD.
  - Zamítnutí: viz P3 v §7.4a (práh je tam uvedený přímo).
  - Cirkularita: parametry TTL a Δp fixovat na L.

**R5 (P2): robustní `packet_rate_spike` (A04).**
- **Změna:** `passive/anomaly.rs:249, 444-466` (+ literál v `correlation_v2.rs:269`): agregovaná rychlost služby Σpkts/okno a p95 jen přes toky s ≥ 10 pakety a ≥ 1 s. Prahy přesunout do `passive/thresholds.rs` s verzí (A05).
- **Důkazy pro:** mechanismus je z kódu (ověřeno: práh na maximu přes toky). Literatura: jednoduchý robustní práh (M26, nízká), legitimní provoz jako zdroj alarmů (M28, nízká).
- **Očekávaný efekt:** bez podkladu v literatuře. Audit odhaduje −90 až −98 % (postup: z parametrů generátoru p ≈ 0,0025 na tok a P(spike) = 1 − (1 − p)^N; analytický odhad, ne měření).
- **Rizika:** přeladění na lognormální rozdělení generátoru (A34, RQ5 S8, M50). Proto prahy odvodit z rozdělení p95 na **vývojové části kotvy** (§7.2) a v shadow režimu z reálné sítě správce, ne z parametrů generátoru (B6).
- **Závislosti:** jen G0-min. Jde hned, nečeká na G0-plné (P2). **Náročnost:** S, ≈ 2 dny (Q2).
- **H:** primární P1 (§7.4a).
- **Měření:**
  - Metriky: packet_rate_spike FP/síť-den na L a na `S_quiet`, detekce ddos_volume, FP na benigních tocích testovací části kotvy (jen jednou, ve finálním E3).
  - Zamítnutí: viz P1 v §7.4a.

**R13 (P2, nové ve v1.1 podle K12): `unexpected_traffic` a `unmapped_passive_event`. Diagnostika příčin, pak čerstvost inventáře, stav spojení a agregace.**

`unexpected_traffic` je největší typ FP ve [v2b] (43,3 %) a ve v1.0 neměl vlastní doporučení.
- **Diagnostika (E0, bez změny enginu):** rozpad `unexpected_traffic` a `unmapped_passive_event` podle příčiny:
  - IP cíle změněná od posledního skenu (DHCP churn),
  - host při skenu mimo provoz (ve [v2b] 64 371 zařízení-cyklů mimo provoz),
  - restart enginu se ztrátou inventáře (398 restartů [v2b]),
  - stav spojení (S0/REJ proti SF s `resp_bytes > 0`),
  - archetyp (Cloud a kontejnery, §4.3).
  
  Hypotéza zastaralého inventáře z auditu je neověřená (A08, A09, §8.2). Teprve rozpad rozhodne, které z kroků níže dávají smysl.
- **Změna:**
  - `passive/anomaly.rs:18-42, 174-206`: rozdělit na `unknown_open_service` (SF s daty) a pokusy (S0/REJ přičíst zdroji jako signál, ne cíli).
  - `passive/mod.rs:58-66`: dnes `known_services` = jen otevřené služby posledního nmapu (ověřeno). Nahradit perzistentním inventářem s časem posledního ověření a stavem `inventory_cold` po restartu. V tomto stavu nálezy závislé na inventáři nevydávat, jen sbírat (A09).
  - Agregace na `(dst, port, typ, den)` přes R4-lite (A13).
  - Po R2 pouštět jen na interní cíle (Q1).
- **Důkazy pro:**
  - Literatura přímý podklad nemá. Kontextová degradace podle inventáře je bez přímého podkladu (M9, K3).
  - Mechanismus je z kódu (A08, A09, `known_services` ověřeno).
  - Naměřeno: 640 487 nálezů, 43,3 % FP, a 86 157 `unmapped`, 5,8 % [v2b].
- **Očekávaný efekt:** bez podkladu. Audit odhaduje −70 až −90 % pro `unexpected` + `unmapped` (odhad autora auditu, podmíněný potvrzením hypotézy zastaralého inventáře).
- **Rizika:**
  - Provoz na neznámou interní IP je zároveň vstup detekce `rogue_device` (16,8 % [v2b]). Proto ho nepotlačovat, ale převést na signál `unknown_device`.
  - Ve stavu `inventory_cold` je engine slepý k nově otevřeným službám. Proto stav časově omezit a zobrazit v UI.
  - Útočník může využít okno po restartu.
- **Závislosti:** G0-min, R4-lite (agregace). **Náročnost:** diagnostika S, změna M (odhad autora).
- **H:** primární P4 (§7.4a).

**R6 (P2/P3): kontextová brána a benigní vysvětlení jako konkurenční hypotézy (včetně kontextové degradace exploitů).**
- **Změna:** nový `context_gate.rs` (`gate(signal, calendar, health) → Keep | Discount | Explain`; Discount, ne mazání):
  - zdraví senzoru jako virtuální evidence,
  - stav `service_unavailable` místo `connection_timeout_burst` (A07, `anomaly.rs:220`),
  - watermark pro `collector_replay`,
  - kalendář s TTL a schválením člověkem,
  - kontextová degradace alertu nebo nálezu na službu, která v inventáři neexistuje nebo není zranitelná.
  
  Pro kalendář v soaku dostane brána jen 50 % oken (návrh auditu (c), simulace neúplné dokumentace).
- **Rozdělení (revize rozsahu P9):**
  - **R6a** (≈ 2 dny): `service_unavailable` místo `connection_timeout_burst` a zdraví senzoru jako snížení váhy.
  - **R6b** (M, odloženo za 14denní jádro): kalendář, allowlisty s TTL, schvalování a UI pro aktivní výjimky.
  
  Každé zlevnění musí mít v UI zobrazitelný důvod a seznam „potlačeno“ s počítadlem (U2). Nikdy mazání.
- **Důkazy pro:** RQ1 Z4 (střední, ale pro aktivní ověření zranitelnosti a pro odpověď služby, ne pro inventář, viz M9 a K3), RQ3 Z2 (nízká až střední), RQ3 Z9 (nízká, 99,64 → 0 % v testbedu), RQ6 Z10 (nízká, −53 % falešných alarmů při −3 p. b.), RQ6 Z11 (velmi nízká), M28, RQ1 Z12 (nízká).
- **Očekávaný efekt:**
  - spolehlivost senzoru: −53 % falešných alarmů za cenu −3 p. b. predikce v jedné studii (RQ6-046; jednotka alarm IDS za den),
  - kontextová degradace podle pasivního inventáře: **bez přímého podkladu**. ATLANTIDES (RQ1-024, 50 až 100 %) analyzuje odpovědi služeb v otevřeném textu, ne inventář, a Skákavka tento obsah z toků nemá (K3),
  - kalendář a benigní vysvětlení: bez podkladu. Hranice −30 % je pracovní odhad autora RQ6 (RQ6 H-1), který zde slouží jako zamítací práh, ne jako opora (K16).
- **Rizika:**
  - Útočník v okně údržby nebo na allowlistu (RQ1-020, Z3). Proto TTL, schválení, audit a v UI zobrazené aktivní výjimky (B7).
  - Kontext stojí detekci (R-9: STRW −43 % skenerů). Kvalita inventáře je limit (RQ1-023).
  - flash_crowd (64,8 %), backup_burst (62,3 %) a authorized_scanner (42,7 %) s FP [v2b] R6a neřeší. Řešit je musí R7-lite, R13 nebo R6b (K22).
- **Závislosti:** R6a jen G0-min; R6b G0-plné (kontrafaktuál) a R2 (egress FP). **Náročnost:** R6a S, R6b M.
- **H:** R6a = průzkumná X11 (není v 14denním jádru). Průzkumné X10 (RQ6 H-1 + RQ1 H1-5), X12 (RQ1 H1-4 + RQ3 H-5, přesunuto do P3 podle K3).
- **Měření:**
  - Scénář `S_ops` (zvýšená frekvence provozních událostí) a seedy s exploit_attempt.
  - Metrika `lookalike_incremental_fp` z kontrafaktuálu (ne atribuce oknem, viz 4.4); útok vložený do okna údržby; recall exploit_attempt a web_exploit.
  - Zamítnutí (z RQ1 H1-5, RQ6 H-1, H-2, RQ1 H1-4): pokles inkrementálních FP < 30 % u ≥ 3 ze 4 událostí; recall útoku v okně klesne > 5 p. b.; u spolehlivosti senzoru pokles FP < 25 % nebo detekce > 5 p. b.; u degradace exploitů pokles recallu > 1 p. b.

**R7 (P3): baseline na entitu se sezónním tvarem role, gatingem a zmrazením při alarmu (A02, A03). Nejdřív R7-lite (revize rozsahu P3).**
- **R7-lite** (≈ 4 až 5 dnů, jde hned po G0-min):
  - V `passive/anomaly.rs:334-398` nahradit průřezové z-skóre bez paměti robustním mediánem a MAD přes **historii téhož klíče** `(dst_ip, proto, port)`.
  - Minimální počet toků a pozorování na klíč. Bez historie (méně než N_min pozorování, volba autora, ladí se na L) nález nevzniká, jen se sbírá.
  - Gating: vzorky s otevřeným nálezem nebo |z| > 3 se do historie neučí (RQ2 Z3).
  - Absolutní `composite_signal` (`anomaly.rs:366-369`) vypnout nebo vázat na historii.
  - Sezónní tvar role, shrinkage a peer group odložit. Důkazy jsou stejné jako níže (nízká jistota), efekt je bez podkladu.
- **Plná R7 – změna:** nový `baseline.rs` (`RobustEwma` úrovně entity × tvar role [hodina × typ dne], shrinkage k peer group, gating |z| > 3 a oken s otevřeným incidentem). Nový detektor místo `inductive_outlier_events` (`passive/anomaly.rs:334-398`), trait `detect_signals` v `passive/detector.rs`.
- **Důkazy pro:** RQ2 Z4 (nízká), Z3 (nízká, zmrazení), Z2 (nízká, nezavádět CUSUM/HW), Z5a (střední, citlivost parametrů), RQ2-026 (4 týdny historie per uživatel).
- **Negativní a chybějící důkazy:** robustní z-skóre/STL na tocích ani sezónní baseline proti statickému prahu nikdo neměřil (RQ2 §9 body 1 a 6). Peer-group prior pro zařízení nenalezen (RQ2 §9 bod 2).
- **Očekávaný efekt:** RQ2 H1 uvádí 3 až 8× jako odhad autora (extrapolace z RQ2-018, -024; nelze oddělit od jiného detektoru). Audit odhaduje −90 % pro inductive (odhad autora auditu).
- **Rizika:** studený start, útočník přítomný od začátku, pomalý drift do EWMA (audit (b)). Identita 32,8 % falešných rozdělení [v2b] baseline resetuje.
- **Závislosti:** R7-lite jen G0-min; plná R7 R4 a R8. **Náročnost:** R7-lite M, plná R7 L (10 až 15 dnů, Q2).
- **H:** R7-lite = primární P2 (§7.4a). Průzkumné X13 (RQ2 H1, plná R7), X14 (RQ2 H4), X15 (RQ2 H8).
- **Měření:**
  - Seedy L; `S_long` (720 a 1440 h); varianta `start_at_zero` pro c2_beacon a insider_hoarding.
  - Metriky: inductive FP/síť-den, závislost FP na počtu zařízení regresí s efektem archetypu (D2), FP podle hodiny dne, detekce perzistentních rodin.
  - Zamítnutí: pokles FP < 2× nebo pokles TPR kterékoli rodiny > 5 p. b. (RQ2 H1); zlepšení TPR perzistentních rodin zmrazením < 2 p. b. (RQ2 H4); detekce `start_at_zero` < 80 % standardní varianty (audit).
  - Cirkularita: tvar role nesmí brát parametry `diurnal` z generátoru (S8). Učí se z dat a ověřuje na kotvě.

**R8 (P3): vícesignálová identita (A26).**
- **Změna:** `identity.rs:68-116` (MAC, hostname, otisk služeb, DHCP lease z `dhcp.log`, ARP/SNMP z kontextových adaptérů).
- **Důkazy pro:** naměřeno: falešné rozdělení 32,8 %, sloučení 20,8 % [v2b]. Literatura pro efekt: žádná recenzovaná, jen dokumentace výrobců v prior art (09, bod 6, nízká důvěra). Nepřímo M36 (identita jako předpoklad lateral detekce).
- **Očekávaný efekt:** bez podkladu. Audit uvádí cíl < 10 % (odhad autora auditu).
- **Rizika:** MAC randomizace (09, jen snippet). Chybné sloučení otráví baseline.
- **Závislosti:** G0-min. **Náročnost:** M až L (8 až 12 dnů, Q2). Do 14 dnů ne. Nejdřív jedna diagnostická tabulka v E0: kolik FP `inductive_volume_anomaly` a `unexpected_traffic` vzniká kvůli identitě (revize rozsahu P8). Identita v generátoru je syntetická a o MAC randomizaci ani DHCP v reálné síti nic neříká.
- **H:** průzkumná X16.
- **Měření:** falešné rozdělení a sloučení, vliv na X13. Zamítnutí: falešné rozdělení se nesníží aspoň o polovinu (volba autora).

### 5.e Učení a kalibrace, prioritizace

**R9 (P3, ODLOŽENO z core plánu, revize rozsahu P7): pořadí podle RBA kombinace (závažnost + akumulace + rozmanitost, trailing okno) a denní rozpočet alertů.**

Proč odloženo:
- důkaz je nízký a pochází z jediného preprintu,
- očekávaný online rozdíl je malý (AUROC 0,75 proti 0,72, RQ1-040),
- čtení Tab. 4 je sporné (RQ1-038).

Náhrada v jádru je RBA-light bez předregistrované H: řazení zobrazených nálezů podle (závažnost, počet výskytů z R4-lite, počet distinktních typů na hostu) a pevný denní limit „zobrazených nových“ s počítadlem potlačených. Původní návrh zůstává jako průzkumná X17 a X18:
- **Změna:** `decision.rs:564-624` (`rank_finding`) a `triage.rs:87-126` nahradit řazením incidentů. Skóre = vážený součet; výchozí váhy RBA 12,5 / 35 / 52,5 % (RQ1-038, přenos je extrapolace). Rozpočet = percentil historických alertů za 30 dní (RQ2-023 až -025).
- **Důkazy pro:** RQ1 Z5 (nízká), Z6 (nízká, bez vzácnosti), RQ2 Z4 (nízká).
- **Očekávaný efekt:** online AUROC ≈ 0,75 vs 0,72 podle závažnosti (RQ1-040), tedy malý rozdíl. Rozmanitost sama 0,73 až 0,87 (RQ1-038). Rozpočet: Hopper 95 % detekce při 5/den (RQ2-025), jiná úloha (loginy).
- **Rizika:** jediný preprint bez replikace. Při rozporu kontrolora a revizora v Tab. 4 RBA (RQ1-038, revize-RQ1 §E) mohou být čísla pro Accumulation a Variety nepřesná.
- **Závislosti:** R4. **Náročnost:** M.
- **H:** průzkumné X17 (RQ1 H1-2a, H1-2b, H1-2c, H1-3), X18 (RQ2 H2).
- **Měření:**
  - Metriky: AUROC pravý vs falešný incident, pravé incidenty v horních 10 %, detekce při rozpočtech 5, 11, 25/den (RQ2 H2).
  - Zamítnutí: AUROC kombinace ≤ AUROC podle závažnosti nebo Wilcoxon p > 0,05 (RQ1 H1-2a). Negativní kontroly H1-2c a H1-3: zamítnutí, pokud samotná akumulace významně překoná závažnost nebo vzácnost dosáhne AUROC > 0,70; naše prostředí je pak jiné než RBA. RQ2 H2: detekce rodiny klesne > 10 p. b. při rozpočtu ≤ 10/den.

**R12 (P3): kalibrace a podmíněné učení Case Memory, monitorování driftu. Rozděleno na R12a a R12b (revize rozsahu P12).**
- **Změna:**
  - **R12a** (≈ 4 dny, po R4-lite): `IsotonicCalibrator` z `src/eval/calibration.rs` do knihovny a kalibrace zvlášť pro behaviorální typy, pooly s minimem vzorků. Rekalibrace bez rozdělení typů je zbytečná, protože 82,2 % predikcí v koši [0,9; 1,0) tvoří převážně statické expozice (A33, K22).
  - **R12b** (odloženo): `case_memory.rs:209-232` → `estimate_ctx` s hierarchickým backoffem a časovým rozpadem (A21); LR tabulky pro výsledky kontrol (A22).
  - Rekalibrace po ~100 verdiktech z nové distribuce (RQ2-043).
  - **Auto-uzavírání alertů: škrtnuto.** Pro správce bez SOC je tichá ztráta nálezu horší než šum (B4). Nanejvýš „sbalit“, nikdy „uzavřít“. RQ1 H1-8 zůstává jen jako průzkumná X20 bez nasazení.
- **Důkazy pro:** RQ2 Z7 (nízká), RQ2 Z11 (velmi nízká, velikost zlepšení Brier nespolehlivá), RQ3 Z5 (střední, jiné domény), RQ1 Z10 / RQ6 Z13 (nízká, AACT jako laťka), RQ2 Z8a (střední pro směr driftu), RQ4 Z8 (střední, nové rodiny).
- **Očekávaný efekt:** ECE klesne v pásmech nad- a podkonfidence. Velikost je bez podkladu (RQ2 H5: ≥ 30 % je odhad autora RQ2). Naměřený výchozí stav: [0,5; 0,6) 0,534 → 0,327, [0,8; 0,9) 0,867 → 0,997 [v2b].
- **Rizika:** kalibrace na simulátoru převezme jeho artefakty (A34). Malá kalibrační množina vede k nulové síle (RQ2-031). Otrávení LR tabulek (guard [v2b] zachytil 99,9 % falešných záznamů).
- **Závislosti:** G0-min (kalibrace zvlášť), R4-lite. **Náročnost:** R12a M, R12b M až L.
- **H:** R12a = primární P8 (§7.4a). Průzkumné X19 (RQ3 H-9), X20 (RQ1 H1-8, bez nasazení), X21 (RQ2 H6, H7 + RQ4 H4-8).
- **Měření:**
  - Kalibrace na seedech L, ECE a Brier na V a jednou na H, leave-one-archetype-out.
  - Zamítnutí: viz P8 v §7.4a.

**FDR (BH/BY nad per-entity konformními p-hodnotami):** P4, **v produkci ne**. Pro síťové entity velmi nízká jistota (RQ2 Z6a), malá kalibrační množina vede k nulové síle (RQ2 Z6b). Jen průzkumně (RQ2 H3), až po plné R7. BH se v tomto plánu používá jen jako statistická korekce průzkumných testů (§7.4b), ne jako vrstva enginu.

### 5.b Žebřík proklepávání (sekvenční ověřování, rozpočet, pivoting)

**R10 (P3/P4): sekvenční bayesovské ověřování incidentu s EVOI, stropem, fondy a trojstavovým verdiktem. V core plánu zůstává jen R10-lite. EVOI, SPRT, fondy a pivot jsou ODLOŽENY jako budoucí práce (revize rozsahu P10).**
- **R10-lite** (≈ 3 dny, volitelné v 14denním plánu):
  - neplánovat kontroly, které `LocalRunner` stejně neprovede (no-op `passive_extended_observation`, `verification_exec.rs:79`),
  - deduplikace plánů,
  - perzistentní idempotence na (cíl, metoda) s TTL napříč běhy,
  - trojstavový verdikt, ve kterém se „neověřeno“ nikdy nezmění na benigní (RQ6 Z3).
  
  Matematika nepotřebná. Cílí přímo na D5.
- **Proč je zbytek odložen:**
  - Pro EVOI ve výběru ověřovací kontroly není podklad (RQ3 §9) a potřebuje kalibrované p (R12a).
  - Pivot nemá žádný důkaz a nese bezpečnostní riziko: sondy přes scope, vyvolání sondování třetí strany útočníkem (B3). Pivot je z plánu škrtnutý.
  - Aktivní L1/L2 kontroly budou ve výchozím stavu vypnuté, jen pro hosty v `scope_policy`, s rate limitem a zákazem u OT/IoT bez schválení (U3).
- **Původní návrh (budoucí práce) – změna:**
  - `verification_planner.rs:53-62` (`utility`) nahradit EVOI závislou na p a modelech výsledků `P(o|H)`, `P(o|¬H)` (`VerificationCandidate` + `outcomes`).
  - Odstranit no-op `passive_extended_observation` (`verification_exec.rs:79`) a zavést skutečné L1/L2 kontroly (periodicita, connect/banner, ARP).
  - `verification_exec.rs:38-46, 170-255`: fondy `passive` / `active_cheap` / `approval` / `human`, globální výběr přes incidenty podle EVOI/nákladu, perzistentní idempotence s TTL.
  - `pipeline/mod.rs:1412-1432`: výsledek kontroly změní posterior v tomtéž běhu.
  - `hypothesis.rs:156`: plnit `contradicting_evidence`.
  - SPRT prahy s α, β jako parametry, N_max = 5 a 10, eskalace nerozhodnutých.
  - 10 až 20 % výběru losovat (RQ3 Překlad bod 8, extrapolace).
  - Verdikt útok / benigní / neověřeno; „neověřeno“ se nikdy nezmění na benigní uplynutím času ani prázdným dotazem.
  - Kontext služeb pro neúspěšná spojení skenu (STRW logika).
- **Pivoting:** pivot jen v rámci scope, BFS hloubky ≤ 2, ≤ 5 pivotů na incident, ≤ 30 % fondu `active_cheap`. Parametry jsou z návrhu auditu, odhad autora auditu; důkaz pro ně neexistuje (RQ3 §9; prior art 09 bod 4 zná jen útočné pentest agenty).
- **Důkazy pro:** RQ3 Z1 (nízká až střední), Z2 (nízká až střední), Z3 (střední, strop), Z4 (nízká, α jako parametr, ne záruka), Z5 (střední, jiné domény), Z6 (nízká, smíšený výběr), Z11 (nízká), Z12 (nízká); RQ6 Z3 (nízká), Z5 (nízká, struktura s trojstavem); M18 (rizika aktivního ověření).
- **Očekávaný efekt:**
  - Sekvenční test: jednotky až desítky pozorování do rozhodnutí (4 až 18,5, RQ3-001, -015) v jednotce spojení, ne ověřovacích plánů. Pro nás bez podkladu.
  - Strop a eskalace: i se stropem zůstává nerozhodnuto 15,4 % (BotProbe, strop 3 kola, RQ3-025). U TRW zůstalo > 80 % hostů nerozhodnuto, protože udělali příliš málo pokusů (RQ3-021). Strop omezuje náklady, nerozhodnutost neřeší, proto je nutná eskalace a trojstavový verdikt. (Ve v1.0 tu bylo chybně „bez stropu 15 až 80 %“, K1.)
  - EVOI pořadí proti FIFO: **bez podkladu** pro ověřování alertů (RQ3 §9). RQ3 H-3 uvádí ≥ 1,3× jako konzervativní extrapolaci autora RQ3 z AI² (jiná doména).
  - Naměřený výchozí stav: 88,5 % plánů mimo rozpočet [v2b].
- **Rizika:** EVOI nad nekalibrovaným modelem (RQ3 Překlad, extrapolace). Evaze maskovacími spojeními (RQ3-008). Aktivní sondy u OT/IoT (M18). Prázdné ověření jako falešný benigní důkaz (M42).
- **Závislosti:** R10-lite jen G0-min; budoucí R10 R4 (incidenty) a R12 (kalibrace). **Náročnost:** R10-lite S až M, budoucí R10 L (měsíc a víc, Q2).
- **H:** R10-lite = primární P5 (§7.4a). Průzkumné (budoucí práce): X22 (RQ3 H-3 + H-8), X23 (RQ3 H-1 + H-7), X24 (RQ3 H-2), X25 (RQ6 H-3), X26 (RQ3 H-4), X27 (RQ3 H-6). Pivot (dříve V3-H28) škrtnut.
- **Měření (budoucí R10):**
  - Metriky: potvrzené TP na 1 000 provedených kontrol při rozpočtu 1× a 0,5×, `noop_share`, podíl incidentů rozhodnutých do k cyklů, `wrong_resolution_rate`, p90 času, podíl nerozhodnutých.
  - Zamítnutí: relativní zisk EVOI < 10 % nebo CI obsahuje 0 (RQ3 H-3). Pro strop a eskalaci: podíl nerozhodnutých **po eskalaci** > 15 % (eskalace nerozhodnutost neřeší) nebo p90 času do rozhodnutí se proti bez stropu nezlepší (RQ3 H-7, přeformulováno podle K1). Medián kontrol na rozhodnutí není ≥ 30 % nižší nebo TPR slow_scan klesne > 2 p. b. (RQ3 H-1). Žádná ze 4 pomalých rodin nezlepší detekci nebo FP vzroste > 20 % (RQ6 H-3).
  - Cirkularita: modely výsledků (LR) se učí jen na L z Case Memory, ne z generátoru. Scénář slow_scan_camouflage má napsat jiný autor nebo vzniknout replayem (RQ5 S7).

### 5.c Rozšíření pokrytí detekce

**R11 (P3/P4): beaconing, DNS, lateral/pivot, reverse shell, source-centric detektory do produkce. V core plánu zůstává jen zapojení `score_source_hosts` jako signálu, ve výchozím stavu vypnutého a měřeného na kotvě (≤ 1 den). Ostatní je ODLOŽENO (revize rozsahu P11).** Beacon nelze na soaku čistě měřit kvůli artefaktu periodicity (RQ5). Pro pivot a reverse shell nemáme podklad. Do diplomky se nepíšou jako cíle.
- **Změna:**
  - `score_source_hosts` (definovaná v `passive/anomaly.rs:110`, `pub(crate)`, volaná jen z `src/eval`) jako detektor produkující signály.
  - Nový `detectors/beacon.rs`: periodicita přes cykly, okna ≥ 24 h a ≥ 12 spojení na dvojici.
  - DNS: per-host agregace, α = 2·10⁻⁵ na doménu jako start (RQ4-023), whitelist bezpečnostních služeb jako A/B.
  - Lateral: first-seen hrana jako rys, alert až s přepnutím identity nebo cestou ≥ 2 hopů.
  - Pivot: korelace časování interaktivních řetězců s testem pod zpožděním a chaffem.
  - Reverse shell: jen průzkumný detektor s vlastními cíli.
- **Důkazy pro:** RQ4 Z1 (nízká, TPR při pevném FPR), M33 (velmi nízká, minimum spojení), RQ4 Z6b (střední), Z7 (střední), Z10 (střední), Z11 (střední), Z12a (střední), Z12b (nízká), Z13 (velmi nízká, absence).
- **Naměřený signál:** zdrojové pořadí C2 45,6 % (s egress 53,4 %) [v2b] a 67,6 % [v1] ukazuje, že zdrojový signál v datech je.
- **Očekávaný efekt:**
  - beacon: bez podkladu pro toky; horní reference MORTON 77 % při FPR 1 % na DNS (RQ4-002),
  - lateral: FP řádově níž při TPR ≥ 90 % (Hopper vs rare-edge, RQ4-047), ale s identitou, kterou Zeek bez Kerberos/NTLM nemá,
  - pivot: ~80 % TPR při FPR < 0,1 % bez evaze (RQ4-048), pokles při zpoždění 1 s a chaffu (RQ4-049, -050),
  - **reverse shell: pro toky nebyl nalezen žádný recenzovaný TPR/FPR (RQ4 Z13); jediné číslo (99,94 % při FPR 10⁻⁵) je z endpointu (RQ4-056) a nepřenáší se.**
- **Rizika:** beacon v soaku má fázi resetovanou každým cyklem (artefakt RQ5), takže zisk na soaku nemusí platit na kotvě. Legitimní beaconing (aktualizace, monitoring) je nutné filtrovat (RQ4-015, V2).
- **Závislosti:** R2, R7, R8. **Náročnost:** L.
- **H:** průzkumné (budoucí práce) X29 (RQ4 H4-1 + H4-2), X30 (RQ4 H4-3), X31 (RQ4 H4-4 + RQ1 H1-7), X32 (RQ4 H4-6), X33 (reverse shell).
- **Měření:**
  - Metriky: TPR@FP/síť-den pevné (RQ4 H4-1), přírůstek detekce c2_beacon, FP/síť-den; v simulátoru doplnit lookalike AV/CDN a beacon jitter 0/10/25/50/100 % (RQ4 Překlad bod 8).
  - Zamítnutí (z RQ4): přírůstek detekce < 5 p. b. nebo FP > +10 % (H4-2); > 3 nové FP domény/den po 2 dnech nebo B nesníží FP oproti A (H4-3); pokles FP lateral < 50 % nebo TPR < 85 % (H4-4); TPR při chaff 0 < 60 % nebo žádný pokles při chaff 200 % (H4-6).
  - Cirkularita: fleet_beacon je držená rodina (§7). Je ale příbuzná c2_beacon, na které se ladí, takže je slabá (K19). Na kotvě se beacon hlásí jen na testovací části (§7.2), která se k ladění nepoužije.

### 5.f Dedukce, abdukce a LLM (s pojistkami)

- Deterministické jádro: trojstavový verdikt, oddělení návrhu hypotézy (korelace) od potvrzení nezávislou evidencí jiného typu (aktivní kontrola, stav hostu, inventář), nikdy opakované čtení stejné evidence (RQ6 Z4, Z5, Z10; nízká). Implementace je součást R6 (benigní vysvětlení) a R10 (trojstav, „neověřeno“ ≠ benigní).
- Formální logika (Datalog, MLN, ProbLog) a abdukce: žádné měření přínosu (RQ6 Z11 velmi nízká, Co nebylo nalezeno). Nezavádět jako jádro, nanejvýš katalog benigních vysvětlení s pozorovatelnými předpoklady (P4).
- **LLM:** zatím mimo verdiktní cestu. Důvody jsou riziko prompt injection (RQ6 Z6, střední pro existenci) a chybějící nezávislá replikace. Měření selhání (RQ6 Z1a, Z1b, Z2) mají nízkou jistotu a pocházejí převážně z jednoho preprintu a jednoho modelu. Týž zdroj uvádí cílený agent AIDA s FNR 3,1 % (RQ6-006, autoři hodnotí vlastní systém). Selhání LLM tedy prokázáno není (K2). V core plánu je LLM nulová práce (B5). Volitelně jen shrnutí již rozhodnutých nálezů ze strukturovaných výčtových polí, nikdy z polí ovládaných útočníkem (qname, User-Agent, SNI, payload) (RQ6 Z6). Bez sebe-revize (RQ6 Z4), bez konfidence LLM jako pravděpodobnosti (RQ6 Z7), bez fine-tuningu na štítcích analytiků bez kontroly otrávení (RQ6-025).
- **H:** průzkumná X34 (RQ6 H-6), z plánu soak v3 škrtnutá (B5). Spouští se jen tehdy, když se LLM vrstva vůbec zavádí: do soaku vložit řetězce s instrukcemi v qname, UA a SNI. Hypotéza „LLM nad syrovými poli je bezpečné“ se zamítne při úspěšnosti injekce > 1 % (RQ6 H-6).

### 5.x Souhrnná tabulka pořadí (přeřazeno ve v1.1)

Ve v1.0 bylo pořadí seřazené podle metodické čistoty (P1 až P4), a oprava největších zdrojů šumu tím čekala na bránu G0 (revize rozsahu P1, P13). Ve v1.1 je pořadí podle poměru efekt/cena a závislostí. Jistota důkazů se tím nemění. Dny jsou odhad z revize rozsahu (Q2) pro jednoho vývojáře včetně testů a migrace, nikdo je neověřil.

| pořadí | R | jistota hlavního důkazu | dny | naměřený blokér | stav |
|---:|---|---|---:|---|---|
| 1 | G0-min (část R1) | vysoká (RQ5 Z-2, Z-6a) pro potřebu měření | 3 | ano | core, 14 dní |
| 2 | R5 packet rate | nízká (M26), mechanismus z kódu | 2 | ano (A04; 22 % FP v1, 10,6 % v2b) | core |
| 3 | R7-lite historie klíče | nízká (RQ2 Z3, Z4) | 4 až 5 | ano (A02; 75 % FP v1, 37,7 % v2b) | core |
| 4 | R4-lite stav nálezů | střední (RQ1 Z1 až Z3) | 6 až 8 | ano (A14) | core |
| 5 | R3 Suricata | nízká (RQ1 Z13) | 2 | ano (0,0 % typu) | core |
| 6 | R13 `unexpected_traffic` (diagnostika + agregace) | žádná přímá, mechanismus z kódu | diag. 1, změna M | ano (43,3 % FP v2b) | core (diagnostika), změna po rozpadu |
| 7 | R10-lite | – (oprava kódu) | 3 | smíšený (D5, A32) | volitelně v 14 dnech |
| 8 | R6a server dole + zdraví senzoru | nízká (RQ6 Z10) | 2 | částečně (D11) | po 14 dnech |
| 9 | G0-plné (zbytek R1) | vysoká / střední (RQ5) | 8 až 12 | ano (S1 až S11) | souběžně, podmínka E2 a finálního E3 |
| 10 | R2 egress | – ; riziko RQ1 Z3 střední | 3 | ano (0,0 % zdrojového pořadí) | po G0-plné |
| 11 | R12a kalibrace behaviorálních typů | nízká (RQ2 Z7) | 4 | ano (D12) | po R4-lite |
| 12 | R6b kalendář a allowlisty | nízká až velmi nízká | M | – | později |
| 13 | R8 identita | žádná recenzovaná | 8 až 12 | ano (D13) | později, po diagnostice |
| 14 | R7 plná baseline | nízká | 10 až 15 | – | později |

**Odloženo nebo škrtnuto (s odůvodněním):**

| položka | rozhodnutí | důvod |
|---|---|---|
| R9 RBA jako modul | odloženo; v jádru jen RBA-light řazení bez H | nízká jistota, jeden preprint, očekávaný rozdíl AUROC 0,75 vs 0,72 (RQ1-040), sporná Tab. 4 (RQ1-038) |
| EVOI, SPRT, fondy (R10 mimo lite) | odloženo jako budoucí práce | pro výběr ověřovací kontroly bez podkladu (RQ3 §9), potřebuje kalibraci, L |
| pivot (R10) | škrtnuto | žádný důkaz, bezpečnostní riziko (B3) |
| FDR v produkci | škrtnuto | velmi nízká jistota pro síťové entity (RQ2 Z6a), nulová síla při malé kalibraci (RQ2 Z6b) |
| auto-uzavírání (R12) | škrtnuto | tichá ztráta nálezu je pro správce bez SOC horší než šum (B4); laťka AACT je z jedné firmy (M48, nízká) |
| LLM | škrtnuto z plánu, X34 jen podmíněně | riziko injection (RQ6 Z6), bez replikace (K2), nulová práce (B5) |
| R11 mimo zapojení `score_source_hosts` | odloženo | beacon nelze na soaku čistě měřit (RQ5), pivot a reverse shell bez podkladu (RQ4 Z12b, Z13) |
| hybridní soak CTU-13 + injekce, `slow_scan_camouflage` | odloženo z v3 | drahé, vázané na odložené R10 (revize rozsahu E6) |

---

## 5A. Plán na 14 dní (realizační jádro)

Předpoklady:
- jeden vývojář a jeden stroj, na kterém běží `bakula-soak-*`. Do těchto procesů se nezasahuje a A/B běhy se pouští jen ve volném okně (revize rozsahu E4),
- commit po logických celcích, push až po dokončené sekci,
- dny jsou odhad z revize rozsahu upravený autorem (přidaná diagnostika R13), ne měření.

### 5A.1 Nejmenší sada změn a pořadí

| den | práce | výstup a kontrola |
|---:|---|---|
| 1 | G0-min: FP/síť-den a zobrazené nálezy/síť-den po typech, `S_quiet`, `noop_share`, hash a dirty ve status, čítače rozpadu `unexpected_traffic` podle příčiny (R13). Základní běh A: současný engine, 3 seedy L × 40 sítí (§7.2) | uložená čísla A, rozpad R13 |
| 2 | Uložení telemetrie seedu pro replay A/B (§7.3), přepínač emise stará/nová a shadow režim, metriky enginu (§5A.3), test načtení starých dat | přepínač funguje, replay dává bitově shodné A |
| 3 | R5: agregát služby a p95 přes toky s ≥ 10 pakety a ≥ 1 s, prahy do `passive/thresholds.rs` s verzí, jednotkové testy | commit |
| 4 | R5: prahy z p95 na L a na vývojové části kotvy (ne z parametrů generátoru), A/B běh 1 | tabulka packet_rate FP před/po, ddos_volume |
| 5 | R7-lite: historie klíče, medián/MAD, N_min, vypnutí absolutního `composite_signal` | commit + testy |
| 6 | R7-lite: gating, A/B běh 2, typovaná detekce po rodinách | tabulka inductive FP před/po |
| 7 | **Go/no-go:** pokud R5 + R7-lite nesníží FP těchto dvou typů aspoň o 50 %, zastavit a zjistit proč | zápis rozhodnutí |
| 8 | R4-lite: pole v `Finding` (`serde(default)`), migrace uložených nálezů, verze schématu | commit + test migrace |
| 9 | R4-lite: stavový modul, znovuvydání při změně stadia, Δp, novém zdroji nebo typu, po klidu; strop kardinality a TTL | regresní test „útok na hostu s otevřeným nálezem“ |
| 10 | R4-lite: agregace `unmapped` (dst, port, typ, den); R3 `classify_signature` podle kategorie a prefixu, pravidlo `ids_alert` | commit |
| 11 | UI: sloupce první/poslední/počet, filtr „nové dnes“, seznam potlačených s důvodem. R13: rozhodnutí podle rozpadu z dne 1 (nejméně agregace přes R4-lite) | ruční kontrola UI |
| 12 | A/B běh 3: celé jádro B proti A na L a V, statistika podle §7.4a | hlavní tabulka |
| 13 | Volitelně R10-lite, nebo opravy z běhu 3. Jednorázové potvrzení na **H1** (20261102 až 20261104, §7.2) | tabulka potvrzení |
| 14 | Shadow běh nového enginu na pasivních datech jedné reálné sítě lokálně (bez odesílání dat kamkoli), dokumentace prahů a změn, zápis neúspěchů | zpráva o poklesu zobrazených nálezů a ztrátě detekce |

### 5A.2 Laťka a poctivé očekávání

- **Laťka (volba autora práce, ne důkaz):** zobrazené nálezy/síť-den a FP/síť-den klesnou o ≥ 70 %, minimálně o 50 %. Pod 50 % se výsledek zveřejní jako negativní a přepínač se vrátí.
- **Bez falešného optimismu:**
  - Ve [v2b] tvoří `inductive_volume_anomaly` a `packet_rate_spike` dohromady jen 48,3 % FP (vlastní výpočet). I kdyby R5 a R7-lite oba typy úplně odstranily, celkové FP klesnou o méně než 50 %. Laťku na mixu v2b lze splnit jen spolu s R4-lite (opakované vydávání) a R13 (`unexpected_traffic`). Na mixu [v1] (97 % FP v těchto dvou typech) stačí R5 a R7-lite.
  - Po −70 % by FP na úrovni [v2b] byly ≈ 280 / síť-den (vlastní výpočet). To je stále daleko od provozního cíle (§5A.3).
- **Ztráta detekce:**
  - Hlásí se typovaná detekce po rodinách s párovým rozdílem a intervalem (§7.4a), ne jen „detekováno (jakýkoli nález)“.
  - Atribuce oknem (S5) je v obou ramenech stejná, takže párový rozdíl je interpretovatelný. Absolutní detekce je ale nadsazená, dokud G0-plné nezavede placebo.
  - Deduplikace může nový útok zakrýt (B1), proto regresní test a práh TTD.
  - Rodiny s n < 100 na rameno se hlásí jen popisně, protože o nich nic potvrdit nelze (§7.4a, výpočet síly).

### 5A.3 Praktické předpoklady nasazení

| oblast | co udělat | zdroj |
|---|---|---|
| migrace dat | nová pole s `#[serde(default)]`, verze schématu stavů a Case Memory, jednorázový převod, test načtení starých souborů | M1 |
| zpětná kompatibilita a shadow režim | přepínač stará/nová emise; v shadow režimu engine počítá obě varianty, loguje rozdíl a zobrazuje starou, dokud se nová nepotvrdí; zároveň rollback | M2 |
| UI | první/poslední výskyt a počet; filtr „nové dnes“; seznam potlačených a zlevněných s důvodem (pravidlo, zdraví senzoru, `inventory_cold`); aktivní výjimky | M3, U2, U4, B7 |
| regresní testy | ke každé R jednotkový test a jeden zlatý scénář; `soak verify` (30/30 deterministických [v1]) jako regrese; test „útok na hostu s otevřeným nálezem“; test „odchozí tok na veřejnou IP nevytvoří `unexpected_traffic`“ | M4, B1, Q1 |
| metriky enginu | nálezy za cyklus podle typu, zobrazené nové nálezy/den, velikost stavové tabulky, `noop_share`, latence cyklu, RSS a halda; musí být hotové před R4-lite (únik +78 MiB/h [v2b] by v produkci proces ukončil) | M6 |
| strop a TTL stavu nálezů | strop počtu stavů na síť (top N podle skóre, zbytek do agregátu), TTL, metrika velikosti; proti vyčerpání paměti a pozornosti útokem s mnoha klíči | B2 |
| riziko deduplikace | znovuvydání při novém zdroji, novém typu, změně stadia a Δp; první výskyt vždy viditelný | B1, RQ1 Z2 |
| provozní cíl | počet zobrazených nových položek za den na 100 zařízení. Návrh z revize rozsahu je ≤ 10. Je to rozhodnutí o zadání, které musí určit autor práce (§8.3); do té doby se hlásí absolutní hodnota | U1 |
| dokumentace | krátký změnový záznam a popis prahů s verzí po každé R | M5 |
| reálná síť | shadow běh na pasivních datech jedné sítě lokálně; žádná data ani osobní údaje do externích služeb | M7 |

---

## 6. Co nedělat

| praktika | proč | důkaz |
|---|---|---|
| LLM jako ověřovatel nebo verdikt (zatím) | riziko prompt injection; bez nezávislé replikace. Selhání (FNR 40,4 až 70,2 %) je z jednoho preprintu a jednoho modelu, týž zdroj uvádí u AIDA 3,1 % | RQ6 Z6 (střední, existence), RQ6 Z2, Z5 (nízká), RQ6-002, -006 |
| Smyčky „zkontroluj se“ a víc vzorkování | sebe-revize zhoršila F1 | RQ6 Z4 (nízká) |
| Posílat do LLM pole řízená útočníkem | prompt injection prokázána | RQ6 Z6 (střední, existence) |
| Brát prázdné nebo neprovedené ověření jako benigní | asociace se zamítnutím útoku | RQ6 Z3 (nízká) |
| Vzácnost nebo aperiodicitu jako hlavní signál | AUROC 0,31 až 0,57 | RQ1 Z6 (nízká) |
| Zavádět CUSUM/Holt-Winters bez A/B; adaptovat baseline bez gatingu | bez doloženého přínosu; otrávení baseline | RQ2 Z2, Z3 (nízká) |
| Potlačovat první výskyt, mazat místo degradace, filtrovat bez měření recallu | redukce u nových událostí 0 až 18 %; filtry zahodily škodlivé příčiny | RQ1 Z2, Z3 (střední) |
| Allowlist nebo kalendář bez TTL, schválení a auditu | útočník se schová do okna | RQ1-020; audit (c) |
| Pevné pravidlo „2 senzory = potvrzení“ | AND snižuje senzitivitu | RQ1 Z13 (nízká) |
| Hodnotit jen AUC/AUROC | AUC neříká nic o provozním bodu | RQ4 Z1 (nízká), RQ5 Z-7 (střední; obecný jev AUROC vs AP) |
| Ladit prahy na testovacích seedech nebo volit práh dodatečně | nadsazené výsledky provenance; precision až 0 % s validačním prahem | RQ6 Z9 (střední), Z9b, RQ5 Z-9 |
| Přebírat čísla z literatury jako cíl | nadsazení a nesrovnatelné jednotky | RQ1 Z14 (nízká), RQ3 Z8 (nízká), RQ4 Z9 (střední, sjednoceno podle R-1), RQ4 Z15 (vysoká) |
| Učit prahy nebo kalibraci jen ze syntetiky | augmentace nepomáhá; distribuční shoda neznamená užitečnost | RQ5 Z-11 (nízká), Z-5 (střední) |
| Deterministické pořadí kontrol | zneužitelné | RQ3 Z11 (nízká) |
| Výběr k ověření jen podle anomálie nebo jen nejistoty | selhání při nízké prevalenci | RQ3 Z6 (nízká) |
| Aktivní sken OT/IoT bez schválení a rozpočtu | pád PLC | RQ3 Z10 (střední, existence) |
| FDR vrstvu teď | pro síťové entity velmi nízká jistota, malá kalibrace vede k nulové síle | RQ2 Z6a, Z6b |
| Wilson jako jediný interval | útoky v síti nejsou nezávislé | RQ5 S9, Z-9 |
| Citovat soak v2 jako důkaz | pravděpodobně stará atribuce | RQ5 Metodika |
| Používat CIC-IDS-2017 → 2018 jako drift | dvě kolekce, ne časový posun | RQ2 Z8a |
| Slibovat detekci reverse shellu z toků s čísly | žádný recenzovaný TPR/FPR | RQ4 Z13 |
| Auto-uzavírat alerty | tichá ztráta nálezu; laťka z jedné firmy | M48 (nízká), revize rozsahu B4 |
| Zavádět pivot a aktivní L1/L2 sondy ve výchozím stavu | bez podkladu, riziko sond přes scope a vyvolání útočníkem | RQ3 §9, M18, revize rozsahu B3 |
| Používat držené seedy nebo testovací část kotvy opakovaně | přestávají být držené | RQ5 Z-9, K19 |

---

## 7. Experimentální plán „soak v3“

### 7.1 Co musí harness opravit (brána G0, ve v1.1 rozdělená)

**G0-min** je podmínkou primárních P1 až P4, P6 a P7 (§5A, den 1 a 2):
- FP/síť-den a zobrazené nálezy/síť-den po typech,
- `S_quiet`, `noop_share`,
- hash a příznak dirty,
- metriky enginu,
- rozpad `unexpected_traffic`,
- uložení telemetrie pro replay A/B (§7.3),
- přepínač `--engine`.

**G0-plné** (body níže) je podmínkou průzkumných X01 až X06 a finálního E3:

1. S1 (benigní egress na nové externí adresy), S2 (benigní Suricata alerty), S3 (stejné vzorkování útoků).
2. S4: scénář `S_quiet` a `attack_rate` volitelný, většina síť-dnů bez útoku ve vybraných bězích.
3. S5: placebo okna. A29: kontrafaktuál `mask_truth`. A31: detekce nad pozadím.
4. S6: „doručeno do telemetrie“ za `degrade`.
5. S7/A30: `expected_types` + „nedosažitelné z konstrukce“.
6. S9: clusterový bootstrap. S10: rozdělení seedů (níže).
7. S11: kotva s inventářem a s event-level a host-level metrikami.
8. A32: soak plánuje stejnou funkcí jako produkce (s historií).
9. A33: kalibrace zvlášť pro behaviorální a statické typy. Metriky `executed_by_method`, `noop_share`.
10. Přepínač `--engine`. Status zapisuje hash buildu a příznak dirty. Únik haldy [v2b] opravit, nebo běhy omezit na ≤ 6 h wall-clock (volba autora).
11. Hlášení: FP/síť-den absolutně, precision, precision při 0,01 až 0,1 útoku/síť-den, recall při pevném FP, AP.

### 7.2 Seedy, držené rodiny, kotva (přepracováno podle K19 a revize rozsahu E3)

Rozdělení je pevné a zapíše se commitem před E0. Žádná sada se nepřesouvá.

| sada | seedy | sítí na seed | použití |
|---|---|---:|---|
| L (ladění) | 20261031, 20261032, 20261033 | 40 | volba prahů a parametrů; smí se opakovat |
| V (validace) | 20261034, 20261035, 20261036 (rezerva 20261037 až 20261040) | 40 | rozhodnutí ponechat nebo zahodit změnu, Holmova korekce (§7.4a) |
| diagnostika | 20261101 | – | už viděn v [v2b]; jen diagnostika E0, nikdy rozhodnutí |
| H1 (držená) | 20261102, 20261103, 20261104 | 40 | **jednou**, potvrzení 14denního jádra (§5A, den 13) |
| H2 (držená) | 20261105 až 20261111 | 40 | **jednou**, finální E3 soaku v3 |

- **Původ seedů:** dosud nepoužité jsou všechny kromě 20260131 (v1), 20261031 (v2) a 20261101 (v2b). Seed 20261031 je v L. Běh v2 se nepoužívá jako důkaz a ladění na tomtéž seedu je přípustné.
- **3 seedy po 40 sítích** odpovídají návrhu z revize rozsahu (E3). Sítě stratifikovat podle velikosti (S, M, L a část XL), aby rameno bylo rychlé.
- **Držené rodiny:** fleet_beacon a ics_attack (RQ5 H-6), mimo veškeré ladění. Obě jsou slabé (K19):
  - fleet_beacon je příbuzná c2_beacon, na které se ladí,
  - ics_attack měl 11 pozorovatelných útoků [v2b] a vzniká jen v Industrial, takže se hlásí jen popisně.
- **Nezávislý zdroj útoků:** generátor píše tentýž autor jako engine a G0 ho ještě mění. Držené seedy proto chrání jen před přeladěním na konkrétní náhodu, ne před spoluadaptací generátoru a enginu (K19). Jako zdroj s jiným autorem doplnit aspoň jeden pcap replay (RQ5 S7). `slow_scan_camouflage` je odložený (§5.x).
- **Kotva CTU-13/IoT-23 rozdělená předem:**
  - vývojová část: CTU-13 Botnet-42 až Botnet-48. Smí sloužit k odvození rozdělení p95 a ke kontrole vedlejších účinků (B6).
  - testovací část: CTU-13 Botnet-49 až Botnet-54 a všech 10 scénářů IoT-23. K ladění se **nepoužije** a vyhodnotí se jednou, ve finálním E3.
  
  Kotva je primární pro tvrzení o detekční schopnosti (RQ5 Překlad bod 5). Hlásí se per scénář a nikdy se nesčítá se soakem.

### 7.3 Pořadí experimentů a párování

**Párování:**
- U pasivních změn (R5, R7-lite, R4-lite, R3, R13, R12a) se telemetrie seedu vygeneruje jednou a uloží. Varianty enginu se pak přes ni pouští opakovaně (revize rozsahu E3). Ramena tak mají bitově stejný vstup a párová korelace je vysoká, což je podmínka síly v §7.4a.
- Pokud harness generování a zpracování oddělit neumí, je to úkol G0-min (den 2). Do té doby se běží na stejném `(seed, network_id)` s vypnutou zpětnou vazbou zásahů do generátoru, jinak se ramena rozejdou: blok mění provoz útočníka, zadrženo je až 80,2 % u ssh_bruteforce [v2b] (K20).
- U změn se zpětnou vazbou (R10, aktivní kontroly) se hlásí divergence ramen.

| fáze | obsah | seedy | rozhodnutí |
|---|---|---|---|
| E0 | G0-min, rozpad R13, regrese FP vs velikost s efektem archetypu (D2), výpočet síly z diskordantních párů | L, diagnostika 20261101 | bez rozhodnutí o enginu |
| E1 (14 dní) | postupně R5 → R7-lite → R4-lite → R3 → R13, každá změna proti předchozímu stavu; nakonec celé jádro proti v1 | ladění L, rozhodnutí V, potvrzení H1 jednou | P1, P2, P3, P4, P6, P7 s Holmem na V |
| E2 | G0-plné a průzkumné X01 až X06; R10-lite (P5), R12a (P8), R6a (X11), R2 (X06) | L, V | P5, P8 s Holmem na V |
| E3 (finále v3) | finální konfigurace proti v1; ablace po jednom (leave-one-out) pro oddělení efektů místo kumulativního skládání (K20); držené rodiny; testovací kotva; přeladění L proti H2 (X35) | **H2 jednou**, testovací kotva jednou | potvrzení všech ponechaných primárních H s Holmem |

Neúspěšné hypotézy se zveřejní (protokol §10).

### 7.4a Předregistrace: 8 primárních hypotéz

**Společná statistika (K18):**
- Každá primární H má jednu primární metriku a jeden odhad.
- Odhad: poměr R = Σ_sítí metrika_B / Σ_sítí metrika_A (síť-den jako jmenovatel v obou ramenech), u P6 a P8 podíl a ECE.
- Interval: 95% clusterový bootstrap přes sítě, stratifikovaný podle seedu a archetypu, B = 2 000.
- **Práh se vždy vztahuje k mezi intervalu**, ne k bodovému odhadu, pokud není řečeno jinak.
- **Holm-Bonferroni** na α = 0,05 přes primární H, které se v dané fázi rozhodují. Korekce platí už při rozhodování na V v E1 a E2, nejen ve finále. Mez intervalu se bere na Holmem upravené hladině.
- Ladění na L korekci nemá, protože o ničem nerozhoduje.

**P0, výpočet síly a ochranné kritérium G (K17).** Ve v1.0 bylo kritérium „horní mez poklesu typované detekce ≤ 2 p. b. per rodina s ≥ 100 útoky“ nesplnitelné:
- Párová ztráta = (b − c) / n, kde b jsou útoky ztracené v B a c získané.
- I při nulové diskordanci (b = c = 0) je jednostranná 95% horní mez ztráty ≈ 3/n (pravidlo tří). Pro n = 100 to je 3 p. b. > 2 p. b. (výpočet autora).
- Clusterový interval je navíc širší. RQ5 H-7 čeká aspoň 1,5×, což je odhad autora RQ5.

Platí proto:
- **G-a (agregát):** horní mez 95% CI párové ztráty typované detekce sloučené přes všechny rodiny ≤ 2 p. b. Při 3 × 40 sítích čekám ≈ 2 300 útoků na rameno (odhad autora: 3 655 útoků na 190 sítí ve [v2b] lineárně přepočteno na 120 sítí), tedy 3/n ≈ 0,13 p. b. při nulové diskordanci.
- **G-b (per rodina, n ≥ 100 útoků na rameno):** horní mez ≤ 5 p. b., Holm přes rodiny. Podle lineárního přepočtu z [v2b] (odhad autora) dosáhne n ≥ 100 zhruba 10 z 19 rodin: c2_beacon, credential_stuffing, exfiltration, exploit_attempt, lateral_movement, port_scan_horizontal, port_scan_vertical, slow_scan, ssh_bruteforce, web_exploit.
- **G-c:** rodiny s n < 100 se hlásí popisně s intervalem. O nich se nic nepotvrzuje.

Výpočet síly se po E0 přepočítá z naměřené diskordance a design effectu. Pokud G-a nebo G-b nejsou při 3 × 40 sítích splnitelné ani při nulové ztrátě, zvýší se počet sítí ve V, ne mez.

G platí pro P1 až P7. Hypotéza je podpořena, jen když platí její práh **a** G.

| H | změna | primární metrika (odhad) | podpora H | zamítnutí | původ prahu |
|---|---|---|---|---|---|
| P1 | R5 robustní packet rate | FP `packet_rate_spike`/síť-den (R) | horní mez R ≤ 0,50 a G | horní mez R > 0,50, nebo porušení G, nebo detekce ddos_volume klesne (horní mez ztráty > 5 p. b.) | volba autora: polovina dolní meze odhadu auditu −90 % |
| P2 | R7-lite historie klíče | FP `inductive_volume_anomaly`/síť-den (R) | horní mez R ≤ 0,50 a G | horní mez R > 0,50 nebo porušení G | RQ2 H1 („pokles < 2× zamítá“) |
| P3 | R4-lite stav nálezů | zobrazené nálezy/síť-den (R) | horní mez R ≤ 0,50, G a nárůst mediánu TTD ≤ 1 cyklus (30 min) | horní mez R > 0,50, porušení G, nárůst mediánu TTD > 1 cyklus, nebo selže regresní test „útok na hostu s otevřeným nálezem“ | RQ1 H1-1 (pokles < 50 % zamítá); TTD volba autora (K22) |
| P4 | R13 `unexpected_traffic` | FP `unexpected_traffic` + `unmapped_passive_event`/síť-den (R) | horní mez R ≤ 0,70, G a detekce rogue_device nepoklesne (popisně, n < 100) | horní mez R > 0,70 nebo porušení G | volba autora: pokles ≥ 30 %, konzervativní, protože hypotéza zastaralého inventáře je neověřená |
| P5 | R10-lite | podíl plánů mimo rozpočet | `noop_share` = 0 (bodově, deterministické) a horní mez podílu mimo rozpočet ≤ 0,50 | podíl mimo rozpočet > 0,50 (horní mez), nebo klesne počet útoků s potvrzující kontrolou (horní mez ztráty > 5 p. b.) | volba autora; výchozí stav 88,5 % [v2b] |
| P6 | R3 Suricata | správný typ exploit_attempt / podíl útoků viditelných IDS | dolní mez poměru ≥ 0,90 a G | dolní mez < 0,90 | audit, krok 3 |
| P7 | celé 14denní jádro proti v1 | zobrazené nálezy/síť-den a FP/síť-den (obě R) | horní mez obou R ≤ 0,50 (minimum laťky) a G; cíl laťky (bodově R ≤ 0,30) se hlásí zvlášť | horní mez kterékoli R > 0,50 nebo porušení G | laťka autora práce (§5A.2) |
| P8 | R12a kalibrace behaviorálních typů | ECE behaviorálních typů (poměr B/A) | horní mez poměru ECE ≤ 0,70 a horní mez rozdílu Brier ≤ 0 | horní mez poměru ECE > 0,70 nebo Brier se zhorší | RQ2 H5 (≥ 30 %, odhad autora RQ2) |

### 7.4b Průzkumné hypotézy

Průzkumné hypotézy o ničem nerozhodují. Hlásí se s intervalem a s BH korekcí q = 0,10. Prahy jsou uvedené přímo (K18).

| X | změna (zdroj) | metrika | práh, při kterém se hypotéza označí za nepodpořenou |
|---|---|---|---|
| X01 | S1 oprava (RQ5 H-1) | FP/síť-den odchozích typů B/A; detekce 8 rodin s externím cílem | 95% CI poměru obsahuje 1 nebo horní mez < 1,1, a zároveň horní mez poklesu detekce < 2 p. b. u všech 8 rodin |
| X02 | S3 vzorkování (RQ5 H-3) | detekce ve vrstvách XL, XXL | horní mez rozdílu < 2 p. b. |
| X03 | placebo atribuce (RQ5 H-4) | placebo míra per rodina | < 5 % u všech rodin |
| X04 | věrnost pozadí (RQ5 H-5) | KS D toků na host a hodinu proti vývojové kotvě | KS D ≤ 0,1 pro Campus a Smb |
| X05 | design effect (RQ5 H-7) a kontrafaktuál A29 | poměr šířek CI; `lookalike_incremental_fp` proti atribuci oknem | poměr < 1,1 u všech rodin; rozdíl < 5 p. b. (volba autora) |
| X06 | R2 egress (RQ4 H4-5) | zdrojové pořadí exfiltrace | < 20 % |
| X10 | R6b benigní vysvětlení a kalendář (RQ6 H-1, RQ1 H1-5) | inkrementální FP 4 provozních událostí; útok v okně | pokles < 30 % u ≥ 3 ze 4, nebo detekce útoku v okně −5 p. b. |
| X11 | R6a spolehlivost senzoru a server dole (RQ6 H-2) | FP v degradovaných cyklech | pokles < 25 % nebo detekce −5 p. b. |
| X12 | degradace exploitu podle inventáře (RQ1 H1-4, RQ3 H-5; P3 podle K3) | podíl degradovaných; detekce exploit/web | snížení < 30 % nebo detekce −1 p. b. |
| X13 | plná R7 (RQ2 H1) | FP inductive/síť-den | pokles < 2× nebo TPR kterékoli rodiny −5 p. b. |
| X14 | zmrazení baseline (RQ2 H4) | TPR perzistentních rodin | zlepšení < 2 p. b. |
| X15 | peer prior (RQ2 H8) | FP dny 0 až 14 po onboardingu | pokles < 20 % (odhad autora RQ2) |
| X16 | R8 identita | falešné rozdělení | pokles < 50 % relativně (volba autora) |
| X17 | R9 RBA (RQ1 H1-2a, b, c, H1-3) | AUROC pravý vs falešný stav | kombinace: AUROC ≤ AUROC dle závažnosti nebo Wilcoxon p > 0,05; negativní kontroly: akumulace významně nad závažností nebo vzácnost AUROC > 0,70 znamená jiné prostředí než RBA |
| X18 | rozpočet alertů (RQ2 H2) | detekce při 5, 11, 25 za den | detekce rodiny −10 p. b. při rozpočtu ≤ 10/den |
| X19 | kalibrace jako předpoklad EVOI (RQ3 H-9) | zisk X22 s kalibrací | zisk < 5 % relativně |
| X20 | auto-uzavření, jen měření (RQ1 H1-8) | podíl sbalených, FNR vzorkem | FNR > 2 % nebo podíl < 20 % při FNR ≤ 2 % |
| X21 | posun a drift (RQ2 H6, H7, RQ4 H4-8) | empirická FPR / nominál po posunu archetypu; FNR po nových rodinách | split-konformní FPR ≤ 1,2 × α i po posunu (posun není problém); žádný pokles výkonu po 8 virtuálních týdnech; nárůst FNR < 2× po nových rodinách |
| X22 | EVOI a smíšený výběr (RQ3 H-3, H-8) | potvrzené TP na 1 000 kontrol | zisk < 10 % nebo CI obsahuje 0 |
| X23 | SPRT, strop a eskalace (RQ3 H-1, H-7; K1) | kontroly na rozhodnutí; nerozhodnuté po eskalaci | medián kontrol není ≥ 30 % nižší, TPR slow_scan −2 p. b., nebo nerozhodnutých po eskalaci > 15 % |
| X24 | kontext služeb u skenu (RQ3 H-2) | FP skenu na lookalike; TPR skenů | pokles FP < 20 % nebo TPR −2 p. b. |
| X25 | „neověřeno“ ≠ benigní (RQ6 H-3) | detekce c2_beacon, fleet_beacon, cryptomining, rogue_device | žádná ze 4 nezlepší detekci s nepřekrývajícím se intervalem, nebo FP/síť-den +20 % |
| X26 | kaskáda (RQ3 H-4) | počet aktivních kontrol; detekce | úspora < 30 % nebo detekce −2 p. b. u rodiny s n ≥ 100 |
| X27 | kamufláž a randomizace (RQ3 H-6) | TPR camouflage; TPR proti informovanému útočníkovi | pokles TPR camouflage < 10 p. b. (evaze neúčinná); randomizace bez rozdílu TPR |
| X29 | beacon (RQ4 H4-1, H4-2) | TPR při FPR 10⁻³; detekce c2_beacon | pořadí metod stejné jako podle AUC na všech seedech; přírůstek detekce < 5 p. b. nebo FP +10 % |
| X30 | DNS whitelist (RQ4 H4-3) | nové FP domény/den | > 3 nové FP domény/den po 2 dnech, nebo B nesníží FP proti A |
| X31 | lateral (RQ4 H4-4, RQ1 H1-7) | FP lateral/síť-den; TPR; purity | pokles FP < 50 % nebo TPR < 85 %; purity grafu ≤ purity okna + 0,05 |
| X32 | pivot pod chaffem (RQ4 H4-6) | TPR při FP 0,4 % | TPR při chaff 0 < 60 % nebo žádný pokles při chaff 200 % |
| X33 | reverse shell | TPR a FP vlastní | bez prahu z literatury (RQ4 Z13), jen popis |
| X34 | LLM injekce (RQ6 H-6), jen při zavedení LLM | podíl zkreslených shrnutí | > 1 % zamítá „LLM nad syrovými poli je bezpečné“ |
| X35 | přeladění a přenos (RQ5 H-6, H-8, RQ6 H-5) | rozdíl L − H2; efekt_H2 / efekt_L; držené rodiny | rozdíl L − H2 mimo CI kolem nuly u > 2 z 19 rodin; poměr efektů < 0,5 nebo efekt < 2 SD mezi seedy; zlepšení držených rodin ≥ zlepšení laděných nebo rozdíl < 2 p. b. |
| X36 | hybridní pozadí (RQ5 H-2), odloženo | FP/síť-den, detekce | FP v 0,5 až 2× syntetiky a detekce ± 5 p. b. (syntetika postačuje) |
| X37 | split podle cíle na kotvě (RQ4 H4-7) | PR-AUC | rozdíl < 0,02 |

### 7.5 Rozpočet výpočtů (odhad autora, rozsah, K21)

Postup:
- Propustnost [v2b] je 0,05 sítě/s při 20 vláknech s mixem do XXL. 40 sítí ≈ 800 s ≈ 13 min na generování jednoho seedu (vlastní výpočet). Sítě stratifikované bez XXL budou nejspíš rychlejší (odhad autora).
- Cena replaye pasivní části zatím není známá. V [v2b] tvoří fáze `hypothesis_plan_exec` v průměru 177,53 ms z 556,22 ms cyklu, takže replay bez ověřování může být řádově levnější. Změří se v G0-min.
- Propustnost ve [v2b] s časem klesá a halda roste (+78 MiB/h, R² 0,80), proto jde o spodní mez.

| fáze | běhy | odhad |
|---|---|---|
| E0 | generování 3 L + diagnostika 20261101, harness A/B | ≈ 1 až 3 h |
| E1 (14 dní) | generování 3 L + 3 V + 3 H1 jednou; ≈ 30 replayů variant | ≈ 2 h generování + jednotky až desítky hodin replayů |
| E2 | G0-plné mění generátor, takže generování znovu: 3 L + 3 V; replaye | ≈ 1,5 h + replaye |
| E3 | 7 H2 × 2 ramena + leave-one-out ablace + testovací kotva (16 scénářů, průchod všech 23 trvá 122 s [v2b]) | ≈ 3 h + ablace |

Celkem odhadem desítky hodin místo ≈ 180 h ve v1.0. Po E0 se odhad přepočítá z naměřené ceny replaye.

---

## 8. Hrozby validity, otevřené otázky, neověřené položky, mezery literatury

### 8.1 Hrozby validity této studie

- **Druhotnost:** pracuji se závěry jiných studií. Plné texty jsem znovu nečetl a ověřil jsem jen existenci id a pět hodnot v extrakci (§2.1).
- **Chybovost interpretace (K10):** revize metodiky našla 4 nesoulady ve 24 řádcích (≈ 17 %). Odhadovaná chybovost interpretace souhrnu je proto kolem 15 %, nad hranicí 5 % z protokolu §9. Před použitím v diplomce je nutné znovu projít všechna tvrzení s jistotou střední a vyšší. Pět ověření zdroje přes URL navržených v revizi metodiky (RQ6-002, RQ3-025, RQ1-024, RQ4-039, RQ1-038) zatím neproběhlo.
- **Jeden vyhledávač ve všech RQ**, převaha preprintů 2025 a 2026, citační řetězení jen částečné (odchylka od protokolu §3 přiznaná v RQ1 až RQ4).
- **Nepřímost:** většina důkazů jsou alerty, hostové logy nebo ML klasifikátory, ne korelační engine nad toky (RQ5 Hrozby, RQ6 Nepřímost). Každý přenos efektu je extrapolace.
- **Soak v2b** je 1h snímek (190 sítí, 2026-11-01 00:03 SEČ) s přepisovaným souborem. Snímková čísla nejsou stacionární (K11: FP/síť-den mezi snímkem 1,00 h a 1,25 h z 932 na 1 043 podle revize metodiky). Vazbu na `a293d2b` nelze nezávisle ověřit (§4.4). Intervaly jsou Wilsonovy (S9).
- **Shoda našich FP s literaturou** může vycházet z konstrukce generátoru, ne ze stejného jevu (RQ6 Hrozby, RQ5 S8).
- **Autor auditu kódu, studií RQ a této souhrnné studie není nezávislý.** Tato studie neprošla kontrolou podle protokolu §9.

### 8.2 Co nebylo ověřeno nezávislou kontrolou

- **RQ1:** řádky RQ1-057 a RQ1-058 (doplněny po kontrole); detaily RQ1-033, -045, -056, -021 až -023 (revize-RQ1 §E). Rozpor v čtení Tab. 4 RBA (RQ1-038) mezi kontrolorem a revizorem dopadá na R9 a X17. Závěry Z6, Z7, Z9, Z12, Z13 nebyly nezávisle prověřeny.
- **RQ2:** 16 řádků ověřil jen autor revize (mimo jiné RQ2-006 až -011, -020, -034, -035, -037, -043, -045, -047, -048, -049, -053). Na RQ2-043 stojí rekalibrace po ~100 štítcích v R12. RQ2-044 přečten z obrázku.
- **RQ3:** RQ3-028, -032, -033, -047, -048, -050, -051, -055, -057 ověřil jen autor revize. Na RQ3-050 a -051 stojí randomizace v R10.
- **RQ4:** opravené hodnoty 17 řádků po kontrole druhý kontrolor znovu nekontroloval. RQ4-015 a -051 jsou jen V2.
- **RQ5:** druhou revizi nedělal nezávislý kontrolor, opravené řádky (mimo jiné 023, 041, 047, 052, 053) nejsou nezávisle ověřeny; mimo vzorek zůstaly RQ5-010, -029, -056, -059. Fakta o kódu soaku (S1 až S11) jsem zčásti ověřil sám (§4.4); S8 a S9 ne.
- **RQ6:** 25 z 51 řádků bez nezávislé kontroly, mimo jiné RQ6-004, -005 (sebe-revize), -047 (Zhai, opora M45 a M46), -049, -019, -020, -027 až -029, -036, -037, -039.
- **Audit 01:** neověřil jsem A35 (paniky; v [v2b] 0), hypotézu zastaralého inventáře u `unexpected_traffic`, chování na reálném Zeeku (A06 plyne z kódu) ani S8 a S9.

### 8.3 Otevřené otázky

1. Poměr nákladů `C_FN/C_FP`, rozpočet poplachů a **provozní cíl** (zobrazené nové položky za den na 100 zařízení; revize rozsahu navrhuje ≤ 10, U1) jsou rozhodnutí o zadání, ne inženýrská volba (audit, Otevřené otázky 2).
2. Realistická četnost útoků na síť-den pro SOHO a SMB není v literatuře (RQ5).
3. Korelovanost signálů pro součet LLR je třeba změřit na `S_quiet` (audit, Otevřené otázky 3).
4. Nevysvětlené jevy z §4.3: Botnet-44, Cloud FP a lift 0,00× v 6 scénářích IoT-23. Původní „záhada IoT-23 ve všech scénářích“ je zrušená (K5).
5. Zda zisk na soaku přetrvá na kotvě (RQ5 Z-3: přenos klesá o 20 až 72 % u ML klasifikátorů).
6. Příčiny `unexpected_traffic` (rozpad v E0, R13) a zda závislost FP na velikosti přetrvá po kontrole archetypu (D2).

### 8.4 Mezery literatury jako možná novost (opatrně)

„Nenalezeno“ znamená jen, že to nenašly tyto rešerše. Prior art (09) je rychlá rešerše převážně z abstraktů.

Ve v1.1 je oddíl zúžený (K23).

- **Výběr ověřovací kontroly nad tokovými alerty se ground truth:** měření podle VOI/EVOI nebo banditu s metrikou počtu kontrol, FP a času jsme nenašli (RQ3 §9; 09 bod 3). Sousední linie ale existují a 09 je neprohledala:
  - nákladově citlivé modelování detekce a odezvy (revize metodiky uvádí Lee et al., J. Computer Security 2002),
  - rozhodovací a herně teoretické enginy odezvy (revize metodiky uvádí RRE, DSN 2009).
  
  Obě reference jsem převzal z revize metodiky a neověřoval je. Případná novost je jen v ověřovací kontrole (ne v odezvě) nad toky. EVOI je navíc v tomto plánu odložené (§5.x), takže novost by vyžadovala budoucí práci.
- **Měřená fúze Zeek + Suricata** (`community_id`) s dopadem na precision a recall: nenalezeno (RQ1 §9).
- **Reverse shell a interaktivní relace z toků s TPR/FPR:** nenalezeno (RQ4 Z13). Jde o mezeru literatury, ne o cíl této práce (§5.x).
- **Benigní vysvětlení:** kauzální benigní kontext existuje u provenance na hostech (NoDoze, RQ6-031, R-2, R-3). Nenalezeno je jen jeho použití **pro toky a provozní události** (výpadek senzoru, replay kolektoru, patch) s měřením na ground truth (RQ6).
- **Peer-group prior pro nová zařízení a sezónní baseline proti statickému prahu na tocích s FPR:** nenalezeno (RQ2 §9).
- **Přímé měření cirkularity a design effect intervalů v NIDS evaluacích:** nenalezeno (RQ5). Soak s placebem, kontrafaktuálem a clusterovým bootstrapem by mohl být metodický příspěvek.
- **Ochrana učení z verdiktů proti otrávení u Beta posteriorů:** nenalezeno (09 bod 5, jen abstrakty a snippety).
- **LLM nad strukturovanými síťovými nálezy v roli ověřovatele:** neměřeno (RQ6).

---

## 9. Příloha: sloučené a deduplikované hypotézy RQ1 až RQ6

Ve v1.1 jsou sloučené hypotézy rozdělené na 8 primárních (P1 až P8, §7.4a) a průzkumné (X, §7.4b). Dřívější čísla V3-H01 až V3-H37 jsou v posledním sloupci kvůli dohledatelnosti.

Priorita: **1** = primární (rozhoduje se s Holmem), **2** = průzkumná po 14denním jádru (E2, E3), **3** = průzkumná, budoucí práce, **4** = podmíněná nebo škrtnutá.

| nová H | původní hypotézy | priorita | poznámka | dříve |
|---|---|---|---|---|
| P1 | (audit krok 4) | 1 | bez literatury, R5 | V3-H09 |
| P2 | RQ2 H1 (varianta lite) | 1 | R7-lite | část V3-H13 |
| P3 | RQ1 H1-1 | 1 | R4-lite, s prahem TTD | V3-H08 |
| P4 | – (nové podle K12) | 1 | R13 `unexpected_traffic` | – |
| P5 | (audit, žebřík; oprava no-op) | 1 | R10-lite | – |
| P6 | (audit krok 3; souvisí s RQ1 H1-6) | 1 | R3 | V3-H07 |
| P7 | (laťka autora práce) | 1 | celé jádro proti v1 | – |
| P8 | RQ2 H5 | 1 | R12a | část V3-H19 |
| X01 | RQ5 H-1 | 2 | před R2 | V3-H01 |
| X02 | RQ5 H-3 | 2 | | V3-H02 |
| X03 | RQ5 H-4 | 2 | | V3-H03 |
| X04 | RQ5 H-5 | 2 | jen měření | V3-H04 |
| X05 | RQ5 H-7 + kontrafaktuál A29 (audit) | 2 | | V3-H05 |
| X06 | RQ4 H4-5 | 2 | R2 | V3-H06 |
| X10 | RQ6 H-1, RQ1 H1-5 | 2 | R6b | V3-H10 |
| X11 | RQ6 H-2 | 2 | R6a | V3-H11 |
| X12 | RQ1 H1-4, RQ3 H-5 | 3 | přesunuto podle K3 | V3-H12 |
| X13 | RQ2 H1 (plná), RQ6 H-4 (vzácnost kontextu jako varianta) | 3 | RQ6 H-4 s negativním priorem RQ1-038 (rozpor R-2) | V3-H13 |
| X14 | RQ2 H4 | 2 | | V3-H14 |
| X15 | RQ2 H8 | 3 | | V3-H15 |
| X16 | (audit krok 9, identita) | 3 | | V3-H16 |
| X17 | RQ1 H1-2a, H1-2b, H1-2c, H1-3 | 3 | R9 odloženo; H1-2c a H1-3 jsou negativní kontroly | V3-H17 |
| X18 | RQ2 H2 | 3 | | V3-H18 |
| X19 | RQ3 H-9 | 3 | | část V3-H19 |
| X20 | RQ1 H1-8 | 4 | auto-uzavírání škrtnuto, jen měření (B4) | V3-H20 |
| X21 | RQ2 H6, RQ2 H7, RQ4 H4-8 | 3 | potřebuje `S_long` a posun archetypů | V3-H21 |
| X22 | RQ3 H-3, RQ3 H-8 | 3 | EVOI odloženo | V3-H22 |
| X23 | RQ3 H-1, RQ3 H-7 | 3 | přeformulováno podle K1 | V3-H23 |
| X24 | RQ3 H-2 | 3 | | V3-H24 |
| X25 | RQ6 H-3 | 2 | trojstav je součástí R10-lite | V3-H25 |
| X26 | RQ3 H-4 | 3 | | V3-H26 |
| X27 | RQ3 H-6 | 3 | nezávislý autor scénáře | V3-H27 |
| – | (audit, pivot) | 4 | škrtnuto (B3) | V3-H28 |
| X29 | RQ4 H4-1, RQ4 H4-2 | 3 | | V3-H29 |
| X30 | RQ4 H4-3 | 3 | vyžaduje AV/CDN lookalike | V3-H30 |
| X31 | RQ4 H4-4, RQ1 H1-7 | 3 | | V3-H31 |
| X32 | RQ4 H4-6 | 3 | | V3-H32 |
| X33 | (RQ4 Z13, bez hypotézy v RQ4) | 4 | | V3-H33 |
| X34 | RQ6 H-6 | 4 | jen při zavedení LLM (B5) | V3-H34 |
| X35 | RQ5 H-6, RQ5 H-8, RQ6 H-5 | 2 | ve finálním E3 na H2 | V3-H35 |
| X36 | RQ5 H-2 | 3 | hybrid odložen (E6) | V3-H36 |
| X37 | RQ4 H4-7 | 3 | jen testovací kotva | V3-H37 |
| – (metodický požadavek, ne H) | RQ1 H1-9 | 1 | splněno G0-min | – |
| – (P4, po plné R7) | RQ2 H3 (FDR) | 4 | jistota velmi nízká (RQ2 Z6a), v produkci ne | – |
| – (zahrnuto v P6 / R3) | RQ1 H1-6 (politika dvou senzorů) | 3 | AND/OR testovat až s benigními alerty (S2) | – |

Pokrytí: všech 50 původních hypotéz je zařazeno (RQ1: 11, RQ2: 8, RQ3: 9, RQ4: 8, RQ5: 8, RQ6: 6).

---

## Dodatek A (2026-11-01): požadavek autora práce a jeho dopad na plán

**Požadavek (závazný):** Skákavka je produkční nástroj, ne důkaz konceptu. Podezření má **co nejvíce automaticky ověřit a buď vyloučit, nebo potvrdit**. Člověku se zobrazuje jen to, co po automatickém ověření přežilo, nebo co má vysoký dopad.

### A.1 Tři skupiny výstupu (definice metriky)
1. **Zachyceno**: všechno, co engine detekuje; zůstává v logu s důvodem a důkazy.
2. **Automaticky vyřešeno**: potvrzeno nebo vyloučeno ověřením; u každého záznam důvodu (která kontrola, jaká data, jaká jistota), vratné.
3. **Čeká na člověka**: neověřitelné nebo vysoký dopad (zásah do sítě). Provozní cíl „nových položek za den na 100 zařízení“ platí **jen pro tuto skupinu**; pracovní hodnota ≤ 10 (rozhodnutí zadavatele, ne měřený údaj).

### A.2 Bezpečné automatické zavírání (mantinely z evidence)
- Důkazy ukazují, že zavírání má cenu: AACT v provozu uzavřel 61 % alertů při 1,36 % zmeškaných (RQ1-048/049, jistota nízká); Carbon Filter ztratil 0 až 5,7 % škodlivých alertů, na 32 a 88 případech (RQ3, revize). Nezávislá přeměření vycházejí hůř než původní tvrzení (RQ3, RQ6).
- Proto povinně: (a) důvod do auditu a vratnost; (b) **náhodný vzorek automaticky zavřených nálezů** na kontrolu a měřenou míru omylu (vlastní metrika „zavřeno omylem“); (c) žádné automatické zavření nejzávažnějších typů bez doloženého neškodného vysvětlení; (d) rozlišit „vyvráceno“ od „nic nenalezeno“: prázdný výsledek dotazu **není** důkaz neškodnosti (RQ6: při prázdném dotazu agent zamítá útok v 98,6 % případů).
- Metriky: zobrazené položky za síť-den, **míra zavřeno omylem** (recall automatického zavírání) a latence rozhodnutí.

### A.3 Ověřování okamžitě, ne v čase
Důvod, proč dnes čekáme na další cykly, je chybějící historie. Okamžitá rozhodnutí umožní (seřazeno od nejlevnějšího a nejbezpečnějšího): (1) **uložená historie toků** (retrospektivní baseline hosta a skupiny podobných zařízení); (2) kontext (inventář, DHCP/ARP, kalendář záloh a údržby, tikety); (3) reputace a znalosti (CISA KEV, EPSS, pasivní DNS, otisky TLS); (4) cílená kontrola na vyžádání se schválením (krátký záznam, nmap/httpx na port); (5) EDR a logy přihlášení (nejsilnější, nejdražší integrace). Pro (1) a (2) nebyl nalezen v literatuře přímý důkaz efektu v našem nastavení; předpokládaný efekt je hypotéza k měření (H-A1, H-A2).

### A.4 Přeřazení plánu na 14 dní (nahrazuje pořadí v §5A tam, kde se liší)
1. G0-min: minimální oprava měření a přepínač staré/nové emise.
2. **Paměť nálezů a deduplikace** (stav, TTL a strop proti vyčerpání paměti).
3. **Kontextové vyloučení a okamžité ověření z historie** (jádro automatizace).
4. Robustní packet rate a odlehčený `inductive_volume_anomaly` (největší zdroje šumu).
5. `unexpected_traffic` (diagnostika, rozdělení úspěšných spojení a pokusů).
6. Až poté aktivní kontroly se schválením a pivoting po souvisejících zařízeních; pivoting se zde nevypouští (je jádro produktu), jen se řadí za bezpečnější kroky.
Každý krok: párové A/B na stejných seedech, sledovat zobrazené položky, falešné poplachy, **zavřeno omylem** a recall rodin.

### A.5 Nové hypotézy
- **H-A1** (historie toků): retrospektivní baseline z uložené historie sníží zobrazené položky o víc než ... (rozsah se určí z E0 měření; bez podkladu v literatuře, odhad autora neuvádím).
- **H-A2** (kontextové vyloučení): známé záloha/patch/restart/výpadek senzoru se vyloučí s mírou omylu ≤ 2 % (kritérium zamítnutí: horní mez 95% intervalu > 5 %).
- **H-A3** (měřená chyba automatiky): náhodný audit zavřených nálezů udrží míru omylu pod předem stanovenou mezí; jinak se příslušná kontrola vypne.
