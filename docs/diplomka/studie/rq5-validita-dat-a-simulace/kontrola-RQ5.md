# Nezávislá kontrola RQ5 (protokol §9)

Datum kontroly: 2026-10-31. Kontrola extrakce proti čerstvě otevřeným zdrojům. Soubory `extrakce.csv` ani `studie.md` nebyly měněny.

## Verdikt: VRÁTIT K PŘEPRACOVÁNÍ

Věcná chybovost je 6 / 51 = 11,8 % (limit 5 %). Věcné chyby jsou i u dvou závěrů s vysokou jistotou (Z-6: RQ5-032, Z-7: RQ5-053, 054). Opravy jsou lokální a levné, ale protokol §9 při překročení 5 % vyžaduje projít extrakci RQ znovu.

## Vzorek a výběr

- Kontrolováno 51 z 63 řádků (81 %; minimum bylo 30 % a 20 řádků).
- (a) Povinná část: všechny řádky, o které se opírají závěry s jistotou vysoká nebo střední v tabulce Závěry (Z-1, Z-2, Z-3, Z-5, Z-6, Z-7, Z-8, Z-9, Z-12): 001, 002, 006, 007, 013, 014, 015, 016, 018, 019, 022, 023, 024, 025, 026, 027, 028, 030, 031, 032, 034, 035, 036, 037, 038, 039, 040, 041, 042 až 047, 049, 053, 054, 055, 060, 062, 063.
- (b) Doplněno: 003, 004, 005 (Engelen, citované v souhrnu studie) a každý třetí z ostatních řádků (005, 010, 017, 029, 050, 056, 059).
- Nekontrolováno (12 řádků): 008, 009, 011, 012, 021, 033, 048, 051, 052, 057, 058, 061.
- Postup: 4 nezávislé průchody (skupiny A až D), každý stáhl zdroj znovu (curl, pdftotext nebo přímé načtení stránky do nových adresářů). Starší texty z `rq5pdf` sloužily jen k orientaci. Kontrolor nevycházel ze závěrů studie.

## Tabulka kontrolovaných řádků

| id | výsledek | poznámka (opravená hodnota a umístění) |
|---|---|---|
| RQ5-001 | OK | Citace doslovné (Úvod, Sekce III-A). Venue „DLS“ ve zdroji nepotvrzeno; dblp uvádí IEEE S&P Workshops 2021. |
| RQ5-002 | OK | Abstrakt doslovně. |
| RQ5-003 | OK | Tab. II, s. 5: Bot 0,60 / 0,53 / 0,99; vážené F1 0,99. |
| RQ5-004 | VĚCNÁ CHYBA | Řádky tabulky záměněny. Tab. II (s. 5), F1 Original → Intermediate → Final: Web Attack XSS 0,18 → 0,25 → 0,79; Web Attack SQL 0,11 → 0,00 → 0,00; Infiltration 0,81 → 0,66 → 0,91; Web Brute Force 0,77 → 0,78 → 0,95 (0,93 je Heartbleed). Extrakce: „SQL 0,18 → 0,79“ je ve skutečnosti XSS; „Infiltration 0,11 → 0,00“ je ve skutečnosti SQL; Infiltration se zlepšila (0,81 → 0,91), ne zhoršila; Brute Force je 0,95. Umístění je s. 5, ne 4. |
| RQ5-005 | DROBNÁ CHYBA | Počty toků 5 499 → 1 742 a „téměř 70 %“ sedí. F1 DoS Slowhttptest není „0,99 beze změny“: 0,98 / 0,98 / 0,99. |
| RQ5-006 | OK | Sekce 3.2 doslovně. |
| RQ5-007 | OK | Tab. 2, Sekce 3.1: 0,997 / 0,997 / 1,000, n = 10. |
| RQ5-010 | OK | Sekce 5.2. Hodnota „3 %“ je citace jiného zdroje, ne měření autorů. |
| RQ5-013 | OK | Tab. 5: 0,722 / 0,000 / 0,130, průměr 0,282; 4 480 příznaků; počty toků sedí. |
| RQ5-014 | OK | Tab. 4: 1,000 → 0,000. |
| RQ5-015 | OK | Sekce 7.4: F1 0,990 jen z TCP options. |
| RQ5-016 | OK | 79 / 177 (45 %), 43 FA. Zdroj je tech. report CS-2003-02; verze RAID 2003 nesrovnána. |
| RQ5-017 | OK | 76 / 18 / 32 / 25 při 100 FA; odhad poklesu 58 až 76 % správně. |
| RQ5-018 | OK | Tab. 12: 7 / 36 (S), 1 / 2 (C). |
| RQ5-019 | DROBNÁ CHYBA | Hodnoty sedí (Tab. I, II). Citace není v abstraktu, ale v Sekci I. Opravit umístění. |
| RQ5-020 | DROBNÁ CHYBA | Hodnoty sedí (98 % / 86 %, 21 učících). Citace je v Sekci I, ne v abstraktu. |
| RQ5-022 | OK | Slajd 9/27 včetně 28,24 % a 1,6 % po třech průchodech. |
| RQ5-023 | VĚCNÁ CHYBA | Hodnota „0,23 (Flash)“ je přiřazena špatně: na slajdu 21/27 je 0,23 F1 detektoru Flash (klient 051), ne GAE (201). GAE host 201: 0,52 (N&T) vs 0,24 (vlastní štítky). Navíc u GAE host 501 jde směr opačně (0,38 vs 0,60), takže „víc než dvojnásobek“ platí jen pro host 201. |
| RQ5-024 | OK | Tab. 5: Pikachu AUC 78,28; Euler AP 0,02; Argus AP 0,09. U Pikachu nebylo AP publikováno. |
| RQ5-025 | OK | Tab. 6: Argus AUC 43,23 / 79,75, AP 0,01 / 3,36; publikováno 99,7 a 80,74. |
| RQ5-026 | OK | Tab. 2: AUC 0,9300, AP 0,0240. |
| RQ5-027 | OK | 90 % a 73 %; alfa 0,832; 22 %; 4 NIDS články. |
| RQ5-028 | OK | Tab. 5 ověřena obrazově: 0,968 / 0,882 vs 0,998 / 0,996. |
| RQ5-029 | OK | Tab. 1 ověřena obrazově: DREBIN recall −12,2 %, OPSEQS −16,9 %. Poznámka „tabulka se rozpadla“ neplatí, tabulku lze číst. |
| RQ5-030 | OK | Citace doslovná. |
| RQ5-031 | OK | Tab. 1, řádek realistic: 0,91 → 0,58, 0,83 → 0,32. |
| RQ5-032 | VĚCNÁ CHYBA | Čísla 0,96 a 0,32 jsou v Tab. 1 správně, ale závěr „poměr tříd v testu sám o sobě ztrojnásobí F1“ neplatí. ALG2, test 10 % mw: trénink 10 % = 0,32, trénink 90 % = 0,30. Test 90 % mw: trénink 10 % = 0,33, trénink 90 % = 0,96. Při nezměněném tréninku (10 %) test 90 % dává 0,33, tedy přibližně 0,32. Skok na 0,96 vyžaduje 90 % malwaru i v tréninku. |
| RQ5-034 | OK | 94,63 % vs 29,35 %; 10,83 % a 40,24 %; 9 z 16. |
| RQ5-035 | DROBNÁ CHYBA | Hodnoty sedí (Obr. 1a, Tab. 4). Abstrakt říká „high degree of asymmetry“; „highly asymmetrical“ je v textu Sekce 5. |
| RQ5-036 | OK | Sekce VII, Tab. VI (botnet 80,0, DoS 38,1). |
| RQ5-037 | VĚCNÁ CHYBA | Accuracy −25,63 % je průměr přes všechny modely. AUROC −27,13 % platí jen pro PCA (Sekce 4.1). Průměr přes modely je −30,45 % (Sekce 5.2; OC-SVM −17,85 %, AE −37,49 %). |
| RQ5-038 | OK | Tab. 12: −0,0093; LODO 0,5577 vs 0,8296. Časový split je jediný seed. |
| RQ5-039 | OK | 96× (Gotham) až 435× (WUSTL-IIoT-2021). |
| RQ5-040 | DROBNÁ CHYBA | Citáty sedí. Zdroj říká proceedings „2017 až 2021“, ne 2017 až 2022. |
| RQ5-041 | OK s poznámkou | Tab. 3: 90 % sedí doslovně, ale při n = 12 je 90 % nemožné (10/12 = 83 %, 11/12 = 91,7 %). Vnitřní nekonzistence zdroje, uvádět opatrně. |
| RQ5-042 | OK | Sekce 5.2: 43 % a 80 %. |
| RQ5-043 | DROBNÁ CHYBA | Spearman AR = 1,00 jen na GCUT; na WWT 0,80 (stejně jako DG). Pole dataset „GCUT, WWT“ zkresluje. |
| RQ5-044 | OK | Sekce 6.2. „Downstream metrics“ se týká předchozí práce [35], ne vlastních měření. |
| RQ5-045 | OK | Tab. 3 a 4: 14,08 %, 0,07 %, 99,77 %, 92,57 %. Citace je v textu pod Tab. 4. |
| RQ5-046 | OK | Tab. 1, Tab. 3: 0,396 / 0,140 vs 0,86 / 0,648, JSD 0,16. Venue POMACS/SIGMETRICS 2024 z arXiv verze nepotvrzeno. |
| RQ5-047 | DROBNÁ CHYBA | Hodnoty sedí (0,738 / 0,262 vs 1,00 / 0,978). Ztráta je 26,2 až 71,6 p. b., tedy „26 až 72“, ne 73. Citace je složena z rozbité tabulky. |
| RQ5-049 | DROBNÁ CHYBA | Citace doslovná. „41 až 76 %“ platí vůči baselinům kromě REaLTabFormer (Sekce 7.2). |
| RQ5-050 | DROBNÁ CHYBA | Abstrakt přesně. Zdroj je přijat na workshop (ML for CyberSecurity @ ECML PKDD 2024), pole „recenzováno: ne“ je nepřesné. |
| RQ5-053 | VĚCNÁ CHYBA | „Učené modely AUROC 0,868 až 0,997 při AP ≤ 0,062“ platí jen pro dataset Trace (Tab. IV). Na Theia má Theseus AP 0,551 a AUROC 0,994. Zobecnění na všechny datasety je nepravdivé. Allowlist s nejlepším F1 a MCC na všech 4 datasetech sedí. |
| RQ5-054 | VĚCNÁ CHYBA | „OilRig AUC 0,951 při precision 0,048“ je EULER (TPR 1,000, FPR 0,070), ne ARGUS. ARGUS OilRig: FPR 0,115, precision 0,030, AUC 0,942. Údaj Sandworm (528 vs 1 529 202, 2 896×) sedí, jde o události, ne alerty. |
| RQ5-055 | OK | Sekce 5.3: 66 % a 58 %. |
| RQ5-056 | OK | Tab. 4 (vážené Pr/Rc/F1): RF 0,97, ID3 0,98, KNN 0,96. Naive Bayes F1 0,04 sedí. |
| RQ5-059 | OK | Abstrakt: 17 oborů, 329 článků. |
| RQ5-060 | DROBNÁ CHYBA | Duplicitní toky s různými štítky autoři uvádějí u NF-ToN-IoT, ne u ToN-IoT. „Bot-IoT 99,99 % útoků“ je jen ilustrativní poznámka. „Bez kvantifikace“ neplatí: Tab. 1 uvádí 21 978 630 → 18 902 360 toků (přibližně 14 %). |
| RQ5-062 | OK | V2 pravdivé; abstrakt a metadata (LNCS 13857, CRiSIS 2022, vyd. 2023) sedí. |
| RQ5-063 | OK | V2 pravdivé; abstrakt (přes Semantic Scholar) a IEEE CNS 2022 sedí. |

## Chybovost

- Ověřeno 51 řádků (NEOVĚŘITELNÉ 0, tedy 0 %; všechny URL fungovaly a plný text byl dostupný).
- OK: 35. DROBNÁ CHYBA: 10. VĚCNÁ CHYBA: 6 (004, 023, 032, 037, 053, 054).
- Věcná chybovost 6 / 51 = 11,8 %. S drobnými chybami je u 16 / 51 (31 %) řádků nějaká nepřesnost.
- Převažující vzorec: správně nalezený zdroj a doslovná citace, ale špatně přenesená hodnota (záměna řádku nebo detektoru v tabulce, platnost jen pro jeden dataset, nesprávně převzatý závěr).

## Nutné opravy v extrakci a studii

1. RQ5-004: opravit hodnoty podle Tab. II (viz výše). V `studie.md` (Abstrakt bod 1, tabulka (a)) opravit „Infiltration 0,11 → 0,00“ na: SQL 0,11 → 0,00, Infiltration 0,81 → 0,91. Zmizí tvrzení, že „F1 jednotlivých tříd klesalo“ u Infiltration.
2. RQ5-023: odstranit „0,23 (Flash)“ u GAE; uvést 0,52 vs 0,24 jen pro host 201 a poznamenat opačný směr u host 501.
3. RQ5-032: přepsat poznámku. Skok 0,32 → 0,96 vyžaduje změnu poměru v tréninku i testu. V `studie.md` opravit Abstrakt bod 5, tabulku (e) („F1 0,32 → 0,96 jen změnou poměru“) a Z-6.
4. RQ5-037: AUROC −30,45 % (průměr), nebo označit 27,13 % jako PCA. Opravit i Abstrakt a tabulku (b).
5. RQ5-053: „AUROC 0,868 až 0,997 při AP ≤ 0,062“ jen na Trace. Opravit v tabulkách (e) a Z-7.
6. RQ5-054: OilRig 0,951 / 0,048 je EULER; ARGUS má 0,942 / 0,030.
7. RQ5-005 (F1 0,98 → 0,99), 019 a 020 (umístění: Sekce I), 035 (citace), 040 (2017 až 2021), 043 (jen GCUT), 047 (72 p. b.; v `studie.md` Z-5 „20 až 73“ na „20 až 72“), 049 (kromě REaLTabFormer), 050 (workshop ECML PKDD 2024), 060 (viz výše), 041 (poznámka k n = 12).
8. RQ5-001: u venue „DLS“ doložit zdroj, nebo opravit na „IEEE S&P Workshops 2021“.
9. Nekontrolovaných 12 řádků (008, 009, 011, 012, 021, 033, 048, 051, 052, 057, 058, 061) je třeba při přepracování projít, protože vzorec chyb (záměna sloupce a řádku) se může vyskytovat i tam.

## Přesazené závěry (jistota vyšší než důkaz)

- **Z-6 (vysoká)**: část „F1 0,32 → 0,96“ je chybně interpretovaná (RQ5-032). Zbývá analytický důkaz base rate (030, 055) a časová nekonzistence (031), ale ta je o malwaru. Doporučeno rozdělit: base rate / FP na TP zůstává vysoká, F1 inflace poměrem tříd v testu snížit na nízkou nebo vypustit.
- **Z-7 (vysoká)**: tvrzení „AUROC 0,87 až 0,997 při AP ≤ 0,06“ platí jen na datasetu Trace (053), RQ5-054 je s chybou. Zbývá 026 (AUC 0,93 při AP 0,024) a Trace. Všechny tři zdroje jsou nerecenzované preprinty, u Z-8 (také preprinty) je přitom jistota střední. Doporučeno snížit na střední.
- **Z-1 (vysoká)**: formulace „artefakty a chyby štítkování v řádu desítek procent toků“ míchá různé jednotky: toky (25,9 %), záznamy (duplicity 75 až 78 %, což není chyba štítku), procesy (40 %). 060, 062, 063 jsou kvalitativní. Jádro (měřené vady) je podložené, formulaci je třeba zpřesnit podle jednotek. Jistota může zůstat vysoká.
- **Z-3 (střední)**: rozpětí 20 až 72 % míchá accuracy, MCC, F1 a AUROC a opírá se o opravovaný údaj 037; jádro (propad při přenosu) platí. Při opravě 037 se rozpětí nemění, ale medián v tabulce (b) je třeba přepočítat.
- **Z-5 (střední)**: „TSTR ztrácí 20 až 73 p. b.“ (správně 72) a rank korelace AR „téměř perfektní“ platí jen na GCUT (043). Důkazy 046 a 049 mají omezení (konkurenční autoři, výjimka REaLTabFormer). Zůstává střední, po opravě čísel.
- **Z-2, Z-9, Z-12**: nalezeny žádné přesazení. U Z-9 uvést opatrně, že 90 % praktiků při n = 12 není celé číslo (041).

## Kontrola 6 z 11 tvrzení o zkresleních soak harnessu proti kódu (`src/soak/`)

Zkontrolováno: S1, S2, S3, S5, S6, S11 (soubor:řádek ze studie).

| # | výsledek | nález v kódu |
|---|---|---|
| S1 | ČÁSTEČNĚ SEDÍ, tvrzení je přehnané | `traffic.rs:392` `public_ip()` existuje, první oktet z {45, 61, 77, 91, 103, 154, 178, 193, 198}. Benigní egress (`model.externals`) generuje `netmodel.rs:825–833` s prvními oktety {34, 52, 104, 142, 185, 203, 13}, tedy skutečně odlišné sady. Ale nejde o „12 pevných adres“ (generují se náhodně na síť) a studie neuvádí řádek. Hlavně: `public_ip()` používá i benigní provoz. Benigní externí klienti webových serverů (`traffic.rs:1095`, `let client = public_ip(rng)`) a cíle benigních událostí (`traffic.rs:902`, `target_external: Some(public_ip(rng))` u `Kind::Benign`) berou IP ze stejného poolu jako útočníci. Oddělení tedy platí jen pro benigní odchozí provoz a příchozí benigní klienti se mísí s útočníky. Studie to musí upřesnit a H-1 bude mít menší efekt, než se čeká. |
| S2 | ČÁSTEČNĚ SEDÍ | Všech 13 volání `alert(` v `emit_truth` je pod `if truth.ids_visible` (řádky 1329 až 2184), takže alerty vznikají jen u pravd s `ids_visible`. `traffic.rs:903` je správně `Kind::Benign` s `ids_visible: false`. Řádek 2593 ale NENÍ benigní: je to testovací fixture `Kind::Attack(Family::SshBrute)` s `ids_visible: false`. Citace 2593 jako důkaz „benigní pravdy mají false“ je chybná (řádek odstranit nebo nahradit). Věcně tvrzení o konstrukci platí. |
| S3 | SEDÍ | `netmodel.rs:878–881` (`flow_sampling()`, komentář „utoky se nevzorkuji“). `sampling` se používá jen v benigních generátorech (`traffic.rs:984, 990, 1054, 1090`), útočné emitery ho nepoužívají. |
| S5 | SEDÍ | `episode.rs:710–711`: `window_ok = cycle + ATTRIBUTION_LATENCY >= start && cycle <= end + ATTRIBUTION_LATENCY`, `ATTRIBUTION_LATENCY = 2` (`episode.rs:52`); okno [start−2, konec+2]. `finding_mentions` a přesné `mentions_ip` (`episode.rs` kolem řádků 164 až 190) sedí. Pozn.: text v `report.rs:294` popisuje okno jen jako „+2 cykly“ za koncem, kód je symetrický. |
| S6 | SEDÍ | `push` (`traffic.rs:1194` a dál) zvyšuje `flows_emitted` (1206) před vyhodnocením `blocked`; `degrade(&mut out, …)` se volá až po generování (`traffic.rs:1189`, definice 2449). `episode.rs:1101` vynechává jen útoky s `flows_emitted == 0`, takže útok s plně zablokovanými či ztracenými toky vstupuje do jmenovatele. Text v `report.rs:294` („nezablokovaný, bez výpadku“) tedy popisuje jinou definici než kód. |
| S11 | SEDÍ | `src/eval/dataset_replay.rs:137`: `let known_services: HashSet<AggKey> = HashSet::new();`, `AggKey = (String, String, u16)` na řádku 28, předáno do `detector.detect(..., &known_services)` (153). Údaj „ablace A porazí baseline v 6 z 20 scénářů“ jsem neověřoval. |

Nad rámec 6 tvrzení: `runner.rs:69` má výchozí `run_seed: 20_260_131`; seed 20261031 ze S10 musí pocházet z CLI nebo konfigurace běhu. Jen k potvrzení při opravě S10, neověřoval jsem.
