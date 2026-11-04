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
