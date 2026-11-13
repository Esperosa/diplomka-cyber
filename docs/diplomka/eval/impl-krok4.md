# Implementace, krok 4: oprava zbytků kroku 3, předregistrovaný slepý test, výchozí režim a dlouhý běh

Datum 2026-11-04. Kód: commity od `686e9fa` (větev `main`, nepushnuto). Všechna soak čísla jsou ze simulace.

Pořadí práce je pevné: A (oprava zbytků jen na ladicích seedech 20261102 až 20261104), B (předregistrace prahů, zamčená commitem PŘED slepým testem), C (slepý test na držených seedech 20261201 a 20261301 a jednou na zamčené testovací části kotvy), D (výchozí `engine.mode = v3` jen při splnění G1 až G5), E (dlouhý běh).

## A) Rozhodnutí o grafu (ladicí seedy, před commitem slepého testu)

Párové A/B ramen `s4` (preset s grafem) a `s4-nograph` (`--v3-off graph`) na ladicích seedech 20261102 až 20261104, 3 × 40 sítí (120 párů, 1 236 virtuálních síť-dní), `--counterfactual`, `tools/soak_ab.py`. Všech 6 ramen doběhlo bez panik, `ERROR` a `WARN`. V logu `s4-20261104.log` je asi na 1 MB úsek 1 011 nulových bajtů (pravděpodobně po obnovení běhu), závěrečný řádek i výstupy ramene jsou úplné.

| metrika | bez grafu | s grafem | změna | 95% CI |
|---|---:|---:|---:|---|
| zobrazené FP na síť-den | 14,2 | 14,8 | +3,7 % | +2,0 až +6,2 % |
| z toho `pivot_chain` | 0,0 | 0,5 | | |
| kontrafaktuální zobrazená detekce, apt_chain (n = 70) | 95,7 % | 97,1 % | +1,4 p. b. | +0,0 až +4,7 |
| totéž, fleet_beacon (n = 44) | 68,2 % | 75,0 % | +6,8 p. b. | +0,0 až +15,4 |
| totéž, lateral_movement (n = 190) | 75,3 % | 76,3 % | +1,1 p. b. | +0,0 až +3,0 |
| totéž, c2_beacon (n = 215) | 89,3 % | 88,8 % | −0,5 p. b. | −1,3 až +0,0 |
| detekce nad pozadím placeba, c2_beacon (n = 134) | | | −4,5 p. b. | −9,2 až −0,8 |

Ostatní rodiny beze změny. Čistě graf přidá čistě 5 kontrafaktuálně detekovaných útoků z celkem 2 480 (+0,2 p. b. souhrnně), všechny v rodinách pod n = 100 nebo s dolní mezí 0, a zvýší FP s intervalem vylučujícím nulu. Orientačně proti `s2` z kroku 3 (starší binárka): `s4` / `s2` = 1,047 s grafem, 1,010 bez něj.

**Rozhodnutí:** graf (`pivot_chain`) se z `V3Features::recommended()` vypouští a zůstává volitelný. Rameno `s4` slepého testu je tedy preset bez grafu a bez peer baseline.

## B) Předregistrace (zamčeno commitem před slepým testem)

Tato sekce se po spuštění slepého testu nemění. Výsledky se zapisují do sekce C a vyhodnocují přesně podle těchto pravidel.

### Ramena slepého testu

Jedna binárka (release, `CARGO_TARGET_DIR=F:/claude-tmp/target-soak`, commit uvedený v C), stejný harness jako při ladění, párově po sítích:

| rameno | konfigurace |
|---|---|
| `legacy` | `--engine legacy` |
| `s2` | stav po kroku 2: `--engine v3 --v3-off egress,beacon,interactive,graph,profile` |
| `s4` | výchozí preset v3 po kroku 4 (`V3Features::recommended()` v commitu slepého testu; rozhodnutí o grafu padne v části A na ladicích seedech a je zapsané před tímto commitem) |

Společné volby: `--block-size 2 --no-legs --no-feedback`, rodiny `all`, žádná kalibrace.

- **Běh 1× (hlavní):** seedy 20261201 a 20261301, každý `--max-networks 40`, `--counterfactual`, šum 1× (výchozí). Ramena `legacy`, `s2`, `s4`.
- **Běh 10× a 50×:** stejné seedy, prvních 16 sítí každého (`--max-networks 16`, 32 sítí), `--noise 10` a `--noise 50`, bez kontrafaktuálu (zobrazení a FP na něm nezávisí). Ramena `s2` a `s4`.
- **XXXL:** stejné seedy, `--size xxxl --max-networks 3 --threads 1 --block-size 1`, bez kontrafaktuálu, rameno `s4`, každý seed zvlášť a bez jiných mých běhů současně (6 sítí).
- **Kotva:** zamčená testovací část (`behavior_anchor_test_once`, `scenarios(Part::Test, true)`), jednou, s výchozím presetem.

### Prahy

Metriky jsou ty z `tools/soak_ab.py` (poměr součtů na virtuální síť-den, párový bootstrap po sítích stratifikovaný po seedech, B = 2000). Rozhoduje **bodový odhad**; 95% interval se uvádí vždy. Jedinou výjimkou je G3, kde rozhoduje horní mez intervalu.

| práh | definice | splněno, když |
|---|---|---|
| G1a | zobrazené FP na síť-den (`output.displayed_fp`), běh 1×, `s4` proti `legacy` | relativní změna ≤ −90 % |
| G1b | totéž, `s4` proti `s2` | `s4` / `s2` ≤ 1,10 |
| G1c | totéž, běh 10× (32 sítí), `s4` proti `s2` | `s4` / `s2` ≤ 1,5 |
| G1d | totéž, běh 50× (32 sítí), `s4` proti `s2` | `s4` / `s2` ≤ 2,5 |
| G2a | kontrafaktuální zobrazená detekce (`cf_detected_displayed`) po rodinách, běh 1×, `s4` − `legacy` | každá rodina s n ≥ 100 útoky (součet obou seedů): rozdíl ≥ −5 p. b. |
| G2b | totéž souhrnně (součet detekovaných / součet útoků přes všechny rodiny) | rozdíl ≥ −2 p. b. |
| G3 | zavřeno omylem, sjednocená kontrafaktuální definice (krok 3 C1): (kontext `auto_closures_wrong_cf` + žebřík `ladder_refuted_wrong_cf`) / (`auto_closures` + `ladder_refuted`), `s4`, běh 1× | horní mez Wilsonova 95% intervalu ≤ 5 % |
| G4 | XXXL: `cycle_p99_s` každé ze 6 sítí a peak haldy procesu (jedna síť najednou) | max p99 < 3 s a peak < 1,5 GiB |
| G5 | všechna ramena v3 všech běhů slepého testu | 0 panik a 0 porušených invariantů |
| G6 | zamčená testovací část kotvy | bez prahu: hlásí se škodliví a neškodní hosté s nálezem po scénářích |

**Rozhodnutí:** v3 se stane výchozím jen při splnění všech G1 až G5. Při nesplnění kteréhokoli zůstává `legacy` výchozí, v3 volitelné a v sekci C se uvede, který práh selhal a proč. Prahy se dodatečně nemění, slepé běhy se neopakují s jiným nastavením a po pohledu na výsledek se nic neladí.

Poznámka k měření času (G4): stroj sdílí jiné úlohy mimo tuto práci (lokální jazykový model, jiný Python proces), které v době kroku 4 zpomalují běhy zhruba 1,5 až 2× proti kroku 3. Čas se proto měří s jedním vláknem a bez mých dalších běhů; zátěž cizích procesů ovlivnit nemohu a uvádím ji.

## C) Výsledky slepého testu

Binárka z commitu `eea4060` (zapsáno ve všech `final-report.md`), skript `F:\Projekty\bakula-soak\ab\k4\blind\run-blind.ps1`, běh 2026-11-04 18:45 až 20:10, vše s nízkou prioritou. Všech 16 soak běhů doběhlo (log `blind.log`), v logech není žádná panika, `ERROR` ani `WARN`. Jediná hlášení `VAROVANI ... nelze naparsovat JSON` patří k záměrně poškozeným řádkům alertů ze simulátoru (`src/soak/episode.rs`), mají ve všech ramenech stejného seedu stejný počet a zpracují se bez pádu. Vyhodnocení `tools/soak_gates.py` beze změny prahů, plný výstup v `F:\Projekty\bakula-soak\ab\k4\blind\gates.txt`.

### G1: zobrazené FP na síť-den

| práh | srovnání | sítí | hodnoty | změna / poměr | 95% CI | výsledek |
|---|---|---:|---|---:|---|---|
| G1a | `s4` vs `legacy`, 1× | 80 | 753,6 → 17,6 | −97,7 % | −98,3 až −96,6 % | splněno (≤ −90 %) |
| G1b | `s4` vs `s2`, 1× | 80 | 17,4 → 17,6 | 1,010 | 1,006 až 1,017 | splněno (≤ 1,10) |
| G1c | `s4` vs `s2`, 10× | 32 | 33,4 → 34,5 | 1,031 | 1,020 až 1,057 | splněno (≤ 1,5) |
| G1d | `s4` vs `s2`, 50× | 32 | 38,5 → 41,7 | 1,083 | 1,055 až 1,144 | splněno (≤ 2,5) |

### G2: kontrafaktuální zobrazená detekce, `s4` − `legacy` (80 sítí)

| rodina | n | legacy | s4 | rozdíl (p. b.) | 95% CI | práh |
|---|---:|---:|---:|---:|---|---|
| apt_chain | 42 | 90,5 % | 100,0 % | +9,5 | +2,1 až +18,8 | (n < 100) |
| c2_beacon | 106 | 3,8 % | 88,7 % | +84,9 | +78,4 až +90,9 | OK |
| credential_stuffing | 100 | 93,0 % | 95,0 % | +2,0 | −2,9 až +7,2 | OK |
| cryptomining | 73 | 5,5 % | 95,9 % | +90,4 | +83,3 až +96,8 | (n < 100) |
| ddos_volume | 57 | 94,7 % | 93,0 % | −1,8 | −6,1 až +0,0 | (n < 100) |
| dns_tunnel | 55 | 27,3 % | 98,2 % | +70,9 | +54,7 až +83,8 | (n < 100) |
| exfiltration | 70 | 2,9 % | 92,9 % | +90,0 | +75,9 až +100,0 | (n < 100) |
| exploit_attempt | 124 | 13,7 % | 35,5 % | +21,8 | +10,2 až +36,5 | OK |
| fleet_beacon | 34 | 50,0 % | 70,6 % | +20,6 | +3,7 až +41,7 | (n < 100) |
| ics_attack | 3 | 100,0 % | 33,3 % | −66,7 | −66,7 až −66,7 | (n < 100) |
| insider_hoarding | 29 | 100,0 % | 100,0 % | +0,0 | +0,0 až +0,0 | (n < 100) |
| lateral_movement | 93 | 89,2 % | 86,0 % | −3,2 | −13,4 až +4,8 | (n < 100) |
| port_scan_horizontal | 121 | 76,0 % | 90,9 % | +14,9 | +3,2 až +25,7 | OK |
| port_scan_vertical | 178 | 21,9 % | 94,4 % | +72,5 | +59,2 až +83,6 | OK |
| ransomware | 29 | 100,0 % | 100,0 % | +0,0 | +0,0 až +0,0 | (n < 100) |
| rogue_device | 43 | 11,6 % | 97,7 % | +86,0 | +71,4 až +97,7 | (n < 100) |
| slow_scan | 98 | 85,7 % | 100,0 % | +14,3 | +7,1 až +24,1 | (n < 100) |
| ssh_bruteforce | 231 | 95,2 % | 96,5 % | +1,3 | −1,5 až +4,4 | OK |
| web_exploit | 87 | 87,4 % | 92,0 % | +4,6 | +0,0 až +9,8 | (n < 100) |
| **souhrnně** | 1 573 | 57,5 % | 89,1 % | +31,6 | +28,1 až +35,3 | OK (≥ −2) |

G2a splněno (všech 6 rodin s n ≥ 100 nad −5 p. b.), G2b splněno. Pod prahem n je výrazný jen pokles `ics_attack` (3 útoky, 3 → 1 detekovaný); vzhledem k n ho nelze zobecnit, ale je to kandidát na samostatnou kontrolu.

### G3, G4, G5

| práh | výsledek | 95% CI | splněno? |
|---|---|---|---|
| G3 zavřeno omylem (`s4`, 1×) | 10 / 875 = 1,14 % | Wilson 0,62 až 2,09 % | ano (horní mez ≤ 5 %) |
| G4 XXXL p99 cyklu | max 4,01 s; po sítích 2,70 / 3,22 / 3,13 s (seed 20261201) a 1,67 / 2,58 / 4,01 s (seed 20261301) | | **ne** (práh < 3 s, překročen u 3 ze 6 sítí) |
| G4 XXXL peak haldy | 449 a 410 MiB | | ano (< 1 536 MiB) |
| G5 ramena v3 | 294 sítí, 0 panik, 0 porušených invariantů (legacy 80 sítí, 0 / 0) | | ano |

### G6: zamčená testovací část kotvy (bez prahu)

Spuštěno jednou (krok skriptu slepého testu, 20:08 až 20:10, `cargo test --release --lib behavior_anchor_test_once -- --ignored`, výstup `F:\Projekty\bakula-soak\ab\k4\blind\anchor.out`). Podruhé jsem ji nespouštěl. Hosté s libovolným behaviorálním nálezem (škodliví / neškodní):

| scénář | toků | škodliví s nálezem | neškodní s nálezem | typy |
|---|---:|---:|---:|---|
| ctu13/Botnet-43 | 229 265 | 0 / 1 | 0 / 8 | |
| ctu13/Botnet-45 | 229 289 | 0 / 1 | 0 / 13 | |
| ctu13/Botnet-48 | 114 077 | 0 / 1 | 0 / 13 | |
| ctu13/Botnet-50 | 229 364 | 0 / 10 | 0 / 17 | |
| ctu13/Botnet-51 | 228 760 | 0 / 10 | 0 / 14 | |
| ctu13/Botnet-53 | 228 811 | 0 / 3 | 0 / 14 | |
| ctu13/Botnet-54 | 229 653 | 0 / 1 | 0 / 16 | |
| iot23/CTU-Honeypot-Capture-5-1 | 1 374 | 0 / 0 | 0 / 10 | |
| iot23/CTU-Honeypot-Capture-7-1-Somfy-01 | 130 | 0 / 0 | 1 / 3 | interactive_session |
| iot23/CTU-IoT-Malware-Capture-8-1 | 10 403 | 0 / 1 | 0 / 1 | |
| iot23/CTU-IoT-Malware-Capture-21-1 | 3 286 | 1 / 1 | 0 / 2 | beacon_periodic, interactive_session |
| iot23/CTU-IoT-Malware-Capture-44-1 | 237 | 1 / 1 | 0 / 1 | egress_volume_anomaly, interactive_session |

Souhrnně 2 z 30 škodlivých hostů a 1 ze 112 neškodných. Na CTU-13 (27 škodlivých, 95 neškodných) behaviorální vrstva s výchozím presetem nenahlásí nic, ani škodlivé, ani neškodné hosty. Na IoT-23 zachytí 2 ze 3 škodlivých za cenu 1 ze 17 neškodných. Na reálných datech je vrstva tedy tichá a málo citlivá. Simulace ukazuje víc, ale přenos na reálný provoz z CTU-13 tímto potvrzený není.

### Rozhodnutí

**G1 až G5 nesplněny, selhal G4** (p99 času cyklu na XXXL 4,01 s proti prahu < 3 s; paměť v limitu). Podle pravidla z B tedy `legacy` zůstává výchozí a v3 zůstává volitelné (`--engine v3`). Část D se neprovádí a dlouhý běh E jako ověření výchozího režimu nemá podklad. Slepé běhy se neopakují a prahy se nemění.

Proč G4 selhal: měřil jsem podle předregistrace (jedno vlákno, jedna síť najednou, bez mých dalších běhů). Překročení přišlo u 3 ze 6 sítí (3,13, 3,22 a 4,01 s), takže nejde o jednu odlehlou hodnotu. Cizí zátěž stroje popsaná výše čas zvyšuje a nedá se z měření oddělit. Proto nevím, jestli by na nezatíženém stroji v3 práh splnilo. Pro výchozí režim to ale nic nemění: o něm rozhoduje výsledek změřený podle pravidel. Další krok je profil cyklu v3 na XXXL (kde roste p99) a nové předregistrované měření na nových seedech po případné optimalizaci.

## E) Dlouhý běh v3 (volitelný režim, ne ověření výchozího)

Uživatel chce dlouhý komplexní běh v3 bez ohledu na G4. Výchozí režim zůstává `legacy`, běh tedy měří v3 jako volitelný režim.

- Binárka z commitu `b3a6dd0` (kód shodný s `eea4060` slepého testu), kopie `F:\Projekty\bakula-soak\bin\bakula-soak-v3-k4-b3a6dd0.exe`. Spuštěno 2026-11-04 20:12:17, PID 7212, priorita BelowNormal, výstup `F:\Projekty\bakula-soak\run-v3-72h`, stdout a stderr `F:\Projekty\bakula-soak\run-v3-72h.out` a `.err`, příkaz v `F:\Projekty\bakula-soak\run-v3-72h.cmd.txt`.
- Příkaz: `soak run --out F:\Projekty\bakula-soak\run-v3-72h --seed 20261105 --wall-hours 72 --threads 12 --engine v3 --noise-mix 1:0.6,10:0.3,50:0.1 --xxxl-share 0.015 --cf-share 0.2 --families all`. Výchozí preset v3 je bez grafu (A), nohy jsou zapnuté (kotva jen vývojová část, `is_dev` v `src/eval/anchor.rs`), zpětná vazba zapnutá, blok 16 sítí.
- Navázání po přerušení: stejný příkaz s `--resume` (zachová seed, velikost bloku i délku epizod).
- Noha broker (H5) nemá Redis (spojení odmítnuto), hlásí se jako nedostupná. Ostatní nohy běží.
- Binárka je starší než oprava ve F, takže časy cyklu v tomto běhu jsou zatížené zápisem varování parseru na stderr. Výsledky detekce to neovlivňuje.

## F) Profil cyklu v3 na XXXL (jen ladicí seedy, po slepém testu)

Držené seedy 20261201 a 20261301 jsem nepoužil. Profil běžel na ladicích seedech 20261102 až 20261104, `--size xxxl --max-networks 3 --threads 1 --block-size 1 --no-legs --no-feedback --engine v3`. Stroj byl zatížený během E a cizími procesy, proto jsem kromě reálného času měřil i CPU čas vlákna (`BAKULA_SOAK_CYCLE_TRACE=1`, `GetThreadTimes`). Podíl CPU na reálném čase byl za celé běhy jen 0,28 až 0,45.

Nálezy:

1. **Ustálená zátěž ve skórování harnessu.** Fáze `scoring` (hodnocení proti ground truth, ne práce enginu) brala 0,5 až 0,8 s v každém pozdním cyklu, z toho téměř vše učící smyčka, která pro každý nález volala `CaseMemory::estimate`. Ta prochází všechny záznamy paměti a pro každý alokuje klíč zdroje. Paměť se během smyčky nemění, takže teď se odhad počítá jednou za typ. Medián cyklu na seedu 20261102 klesl z přibližně 1,0 s na 0,35 až 0,6 s.
2. **Synchronní zápis na stderr uvnitř cyklu.** Parser alertů vypisuje varování za každý poškozený řádek a simulátor poškozené řádky záměrně vkládá. Na zatíženém disku F: (kam zapisuje i SQLite noha ops-stress běhu E) jeden takový cyklus trval 14,6 s reálně při 0,23 s CPU. Starý build měl na seedu 20261104 p99 cyklu jedné sítě 10,45 s, nový 0,71 s. Soak počítá poškozené řádky sám (`corrupt_alert_lines`), proto jeho textová varianta parseru teď mlčí. Souborová produkční cesta varuje dál. Ve slepém XXXL běhu bylo takových varování 101 a 49, takže tento mechanismus mohl k selhání G4 přispět. Verdikt G4 se tím nemění.
3. **Zbylé špičky jsou skutečná práce:** nárůst provozu (seed 20261102, síť 2, cyklus 14: 113 tisíc toků, 1,86 s CPU, hlavně `report`, `detect` a `history_end`), simulovaný restart enginu se serializací stavu (0,6 až 0,9 s) a jednorázově žebřík s Case Memory (1,0 s).

Výsledky (`networks.jsonl` bez časových polí) jsou se starou binárkou bajtově stejné na všech 9 sítích. p99 cyklu po sítích v reálném čase na zatíženém stroji:

| seed | před (`b3a6dd0`) | po (`d6b56f1`) | nejhorší cyklus po, CPU |
|---|---|---|---:|
| 20261102 | 1,64 / 1,22 / 3,52 s | 1,09 / 0,59 / 3,46 s | 1,86 s |
| 20261103 | 2,30 / 2,26 / 1,94 s | 1,51 / 1,55 / 0,94 s | 0,92 s |
| 20261104 | 10,45 / 1,46 / 1,48 s | 0,71 / 1,10 / 1,44 s | 1,08 s |

CPU čas nejhoršího cyklu je po opravě ve všech 9 sítích nejvýš 1,86 s, tedy pod cílem 3 s. Jediné překročení v reálném čase (3,46 s) je cyklus s 1,86 s CPU, zbytek je čekání na zatíženém stroji. Měření na nezatíženém stroji zatím nemám, protože běh E trvá do 2026-11-07 asi 20:12. Do té doby je CPU čas jen náhradní ukazatel, ne splněný cíl. Případné nové předregistrované měření G4 musí proběhnout na nových seedech a na nezatíženém stroji.
