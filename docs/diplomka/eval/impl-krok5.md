# Implementace, krok 5: pokrytí hrozeb a poruch, křivky skrytosti a registr slepých míst

Datum 2026-11-04. Výchozí stav: krok 4 hotov, `legacy` zůstává výchozí (G4 nesplněn), v3 je volitelné (`--engine v3`, preset bez grafu). Všechna soak čísla jsou ze simulace.

Cíl: změřit, jak široké spektrum útoků a provozních poruch engine pozná, včetně opatrných a špatně rozlišitelných variant, a poctivě zapsat, co nepozná. Tvrzení „odhalí vše“ dát nejde. Výstupem je měřené pokrytí s intervaly, křivky detekce proti skrytosti a registr slepých míst.

Nové techniky útoku se nevymýšlejí. Existující rodiny se jen parametricky mění (tempo, rozptyl, počet zdrojů, doba, objem, denní doba, míchání s legitimním provozem) a skládají do kampaní z existujících emitorů. Přibývají provozní poruchy a neškodné lookalike podle auditu (`audit-pokryti.md`, sekce 6b a 8C). Skutečné útoky pokrývají veřejné datasety.

Pořadí práce: A předregistrace (tato sekce, zamčená commitem před prvním během), B harness, C veřejné datasety, D plán laboratoře, E měření na ladicích seedech, F případné obecné opravy (jen na ladicích datech), G jeden běh na držených seedech, H výsledky a registr slepých míst.

## A) Předregistrace (zamčeno commitem před prvním měřicím během)

Sekce A se po prvním měřicím běhu nemění. Případná oprava chyby v harnessu se zapisuje do sekce H jako odchylka s důvodem. Prahy, seedy ani definice se po pohledu na držená data nemění.

### A1. Seedy

| účel | seedy | sítí na seed |
|---|---|---:|
| ladění a opravy (E, F) | 20261411, 20261412, 20261413 | 40 |
| držené, jen jeden běh (G) | 20261401, 20261501 | 40 |

Seedy kroků 1 až 4 (20261102 až 20261104, 20261201, 20261301) se v kroku 5 nepoužívají. Seed 20261105 patří běžícímu 72h běhu v3.

### A2. Svět „pokrytí“ (`--coverage tuning | full`)

Výchozí svět (`--coverage off`) zůstává bit po bitu stejný. Všechna rozšíření mají vlastní náhodný proud odvozený ze seedu sítě, takže nemění plán ani provoz výchozího světa (kontroluje test a `soak verify`).

**Osy skrytosti.** Každý útok dostane nezávisle na každé ose výchozí úroveň s pravděpodobností 0,4, jinak rovnoměrně jednu z ostatních úrovní. Úrovně označené (H) jsou jen ve `full`, tedy držené. Ladicí svět je nevidí.

| osa | úrovně | výchozí | význam |
|---|---|---|---|
| intenzita | spojitě 0,10 až 1,0 (`tuning`); 0,05 až 1,0 (`full`) | 3 pásma jako dosud | škáluje počty toků a objemy v emitoru rodiny |
| tempo τ | 0,5×, 2×, 4×; (H) 0,25×, 8× | 1× | počet toků za čas ×τ, délka útoku ×1/τ (celková práce zachována) |
| rozptyl časů | 0,15; 0,3; (H) 0,5 | 0 | posun času toku o ±rozptyl × 600 s |
| zdroje | 3; (H) 10 | 1 | toky útočníka rozdělené na N adres (vnější útočník: další veřejné adresy, vnitřní: další klienti) |
| doba trvání | 0,5×, 2×, 4× | 1× | délka útoku |
| objem | 0,25×, 0,5×, 2× | 1× | bajty toků útoku |
| mimo pracovní dobu | ano s p = 0,3 | ne | začátek v místní noci 0 až 5 h |
| míchání s provozem | ano s p = 0,3 | ne | vnitřní útočník je jeden z 20 % nejvytíženějších klientů a ve stejném okně běží neškodná událost (záloha, aktualizace nebo flash crowd) |

**Index skrytosti** S ∈ [0, 1] je průměr šesti složek. Výchozí úroveň má složku 0, hlučnější varianta také 0, skrytější kladnou:

- intenzita: 1 − intenzita;
- tempo: min(1, max(0, −log₂ τ / 2)), tedy 0,5× → 0,5 a 0,25× → 1;
- rozptyl: rozptyl / 0,5;
- zdroje: log₁₀ N;
- objem: min(1, max(0, −log₂ v / 2));
- míchání: 0 nebo 1.

Doba trvání a denní doba do indexu nevstupují, protože jejich směr vůči skrytosti není jednoznačný. Hlásí se zvlášť. Pásma S jsou pětiny Q1 až Q5. Hranice jsou kvintily S z plánu ladicího světa (seedy z A1, `--coverage tuning`). Spočítají se jen z vygenerovaného plánu, bez jakéhokoli výsledku detekce, a zapíšou se do sekce H dřív, než se vyhodnotí první detekce. Křivka skrytosti je detekce po pásmech S a po úrovních každé osy.

**Kampaně.** Na síť Poisson(0,3 × dny) kampaní. Fáze jsou existující rodiny se sdíleným útočníkem. Vnější útočník je společný pro vstupní fáze, oběť vstupní fáze se stává vnitřním útočníkem dalších fází. Mezi fázemi je prodleva 0 až 24 cyklů. Šablony (rodiny v pořadí):

| šablona | fáze | sada |
|---|---|---|
| K-T1 | port_scan_horizontal → ssh_bruteforce → lateral_movement → exfiltration | ladicí |
| K-T2 | credential_stuffing → c2_beacon → exfiltration | ladicí |
| K-T3 | exploit_attempt → c2_beacon → lateral_movement → dns_tunnel | ladicí |
| K-H1 | web_exploit → c2_beacon → ransomware | držená |
| K-H2 | slow_scan → exploit_attempt → cryptomining | držená |
| K-H3 | slow_scan → web_exploit → lateral_movement → exfiltration | držená |

Kampaň s jedinou drženou rodinou je držená celá a v ladicím světě se nevyskytuje.

**Nové provozní poruchy a lookalike** (kombinace existujících vzorů toků, nikdy útok). Na síť Poisson(0,9 × dny × √velikost):

| porucha | co se v datech stane | sada |
|---|---|---|
| dns_outage | DNS server nedostupný 1 až 6 cyklů: dotazy klientů bez odpovědi, opakování, část klientů zkouší veřejný resolver | ladicí |
| dhcp_renumber | hromadné přečíslování podsítě (30 až 80 % dynamických zařízení), jeden server dostane novou adresu a klienti chvíli volají starou | ladicí |
| link_flapping | výpadek linky se 3 až 10× opakuje po 1 až 2 cyklech (opakovaná retry bouře) | ladicí |
| misconfig | špatně nastavené zařízení: broadcast bouře (UDP 137/138/1900/5353) a spojení bez odpovědi na servery jiné podsítě | ladicí |
| backup_failed | záloha selhává: krátká přerušená spojení na 445 a opakované pokusy po několik cyklů | ladicí |
| cert_expired | vypršelý certifikát serveru: klienti dostávají RST na 443, opakují | držená (H) |
| segment_power_loss | výpadek napájení podsítě 1 až 3 cykly, pak hromadný start (DHCP, DNS, NTP, kontrola aktualizací) | držená (H) |
| vpn_reconnect_storm | po výpadku se stovky vzdálených klientů znovu připojují k VPN (krátká neúspěšná a úspěšná spojení) | držená (H) |
| cloud_migration | servery a klienti začnou trvale komunikovat s novým blokem cloudových adres, první cykly velký přenos ven | držená (H) |

**Souběhy.** Každý útok (i fáze kampaně) dostane s p = 0,25 souběžnou provozní poruchu se stejným začátkem. Ta se vybírá ze všech 18 provozních druhů (9 stávajících a 9 nových, v ladicím světě bez držených). Senzorové poruchy (sensor_crash, collector_replay, log_corruption) mají dohromady váhu 1/3. Souběh se po běhu určuje z překryvu oken, takže se započtou i náhodné souběhy.

**Sady.** Ladicí běhy: `--coverage tuning --families tuning` (bez 8 držených rodin z kroku 3, bez držených úrovní os, bez držených poruch a kampaní). Držené běhy: `--coverage full --families all`.

### A3. Ramena a běh

Jedna binárka (release, `CARGO_TARGET_DIR=F:/claude-tmp/target-soak`), commit zapsaný v sekci H. Párově po sítích:

| rameno | konfigurace |
|---|---|
| `legacy` | `--engine legacy` |
| `v3` | `--engine v3` (výchozí preset v3 po kroku 4, bez grafu a bez peer baseline) |

Společné volby: `--block-size 2 --no-legs --no-feedback --counterfactual`, šum 1×, žádná kalibrace, `--max-networks 40`. Kvůli běžícímu 72h běhu: nejvýš 6 vláken, priorita Idle, nejvýš 2 ramena současně, před spuštěním kontrola zatížení.

### A4. Metriky

- **Detekce útoku** = kontrafaktuální zobrazená detekce (`cf_displayed`): útoku je připsán zobrazený behaviorální nález, který ve světě bez útoků v tom cyklu chybí nebo není zobrazen. Jednotkou je útok s aspoň jedním emitovaným tokem.
- **Interval:** Wilsonův 95% interval pro podíl. U souhrnných čísel a párových rozdílů se navíc uvádí bootstrap po sítích stratifikovaný po seedech (B = 2000), protože útoky jedné sítě nejsou nezávislé.
- **Křivka skrytosti:** detekce po pásmech S a po úrovních os, zvlášť pro obě ramena, s Wilsonovými intervaly.
- **FP poruchy:** podíl výskytů poruchy s aspoň jedním zobrazeným nálezem připsaným poruše (shoda klíčových IP v okně, u poruch bez klíčových IP okno samo), Wilson. Dále zobrazené FP na síť-den v daném světě.
- **Souběh:** detekce útoků s překrývající se provozní poruchou proti útokům bez ní, zvlášť senzorové poruchy.
- **Kampaň:** zachycena, když je detekována aspoň jedna fáze; „včas“, když je detekována první fáze.
- **Zavřeno omylem:** definice G3 z kroku 4 (kontext `auto_closures_wrong_cf` + žebřík `ladder_refuted_wrong_cf`) / (`auto_closures` + `ladder_refuted`). Navíc po útocích: podíl útoků, u nichž byl některý připsaný nález automaticky zavřen nebo vyvrácen.

### A5. Leave-one-family-out (LOFO)

Detektory vznikaly v krocích 1 až 4 se znalostí všech rodin. Skutečné „naladit bez rodiny“ by znamenalo zopakovat čtyři kroky vývoje pro každou rodinu, a to nejde. Předregistruji proto náhradu, která simuluje neznámou rodinu ve třech vrstvách:

1. **Bez signatury:** započítají se jen útoky s `ids_visible = false` (pro neznámou rodinu IDS pravidlo neexistuje).
2. **Bez vlastních detektorů:** detekce se počítá jen z nálezů, jejichž typ nepatří do množiny D(X) typů zavedených pro rodinu X, ani mezi typy založené na signatuře (`suricata_alert`, `egress_ids_alert`).
3. **Bez naučených verdiktů:** počítá se jen první útok rodiny X v každé síti. Učení z verdiktů (paměť případů, žebřík) na X ještě nemá žádný verdikt.

| rodina X | D(X), typy zavedené pro X |
|---|---|
| c2_beacon | `beacon_periodic` |
| exfiltration | `egress_volume_anomaly`, `long_lived_tunnel` |
| ssh_bruteforce | `source_volume_outlier`, `connection_timeout_burst` |
| port_scan_vertical | `scan_attempts`, `connection_timeout_burst` |
| lateral_movement | `multi_target_pattern`, `pivot_chain` |
| dns_tunnel | `egress_volume_anomaly`, `source_volume_outlier` |

Měří se na ladicích bězích (rodiny jsou ladicí) a jednou na držených. Kontrola: na ladicích seedech se jednou pustí skutečná ablace `--v3-off beacon` a její detekce c2_beacon se srovná s náhradou LOFO. Ukáže se tak, nakolik náhrada (vynechání typů z výsledku) odpovídá skutečnému vypnutí detektoru.

### A6. Prahy (vyhodnocení na držených seedech, rameno `v3`; rozhoduje bodový odhad, intervaly se uvádějí vždy)

| práh | definice | splněno, když |
|---|---|---|
| K1 | detekce v pásmu Q5 (nejskrytější) proti Q1 | poměr Q5 / Q1 ≥ 0,5 |
| K2 | párově `v3` − `legacy`, souhrnná detekce na světě `full` a zvlášť v pásmech Q4 a Q5 dohromady | oba rozdíly ≥ 0 |
| K3 | podíl výskytů s zobrazeným FP: držené nové poruchy (pooled) proti laděným novým poruchám (pooled, stejný běh) | držené ≤ laděné + 10 p. b. |
| K4 | detekce útoků se souběžnou nesenzorovou poruchou proti útokům bez souběhu | rozdíl ≥ −10 p. b. |
| K5 | LOFO: generická detekce pro každou ze 6 rodin | „zobecňuje“, když bod ≥ 50 % a dolní mez Wilsona ≥ 30 %; jinak slepé místo |
| K6 | zavřeno omylem (G3) na světě `full` | horní mez Wilsona ≤ 5 % |
| K6b | podíl útoků s automaticky zavřeným připsaným nálezem: držené rodiny proti laděným | držené ≤ laděné + 5 p. b. |
| K7 | kampaně zachycené aspoň v jedné fázi | ≥ 90 % |
| K8 | panika a porušené invarianty ve všech ramenech | 0 a 0 |

Prahy rozhodují o tom, co smí práce tvrdit („engine je odolný proti skrytosti v rozsahu …“). O výchozím režimu nerozhodují, ten zůstává podle kroku 4.

### A7. Pravidlo pro neznámé a nově vzniklé nálezy

- Ve vyhodnocení se nález, který nelze připsat žádné pravdě (útok ani neškodná událost), počítá jako FP. Nikdy se tiše nevyřazuje a nikdy se nepovažuje za „automaticky vyřešený správně“.
- V enginu nesmí automatické zavírání (kontext, paměť, žebřík) zavřít nález, jehož kombinace (typ, entita) se v síti vyskytuje poprvé, pokud k tomu nemá doložené neškodné vysvětlení. To odpovídá M7 / RQ1-019 a Dodatku A (c) v `00-zaver-jak-vylepsit-core.md`. Měří se počet takových zavření u útoků na ladicích bězích. Je-li nenulový, smí se jen obecně opravit (F), ne ladit na rodinu.

### A8. Registr slepých míst

Do registru (sekce H) jde každá buňka (rodina × úroveň osy, pásmo S, porucha, souběh, šablona kampaně, LOFO rodina) podle těchto pravidel:

- **slepé místo:** n ≥ 20 a detekce < 50 %;
- **slabé místo:** n ≥ 20 a detekce 50 až 70 %;
- **FP slepé místo:** porucha s podílem výskytů se zobrazeným FP > 20 % (n ≥ 20);
- **nedostatečná data:** n < 20 (uvádí se, nehodnotí).

U každého slepého místa se uvádí, jaký obecný signál by ho mohl zachytit a jestli jde o vlastnost simulace (např. senzor nefunguje, takže data nejsou).

### A9. Veřejné datasety (C)

- **CIC-IDS2017:** oficiální stažení (UNB CIC) vyžaduje registrační formulář se jménem a e-mailem. Podle pravidel práce se osobní údaje do externích služeb neposílají, proto se použije veřejně stažitelná přegenerovaná verze Engelen a kol. (WTMC 2021, opravené toky a štítky téhož záznamu), soubor `dataset.zip` po jednotlivých dnech přes HTTP Range.
- **UNSW-NB15:** oficiální sdílená složka UNSW. Bez přihlášení se stahuje jen tehdy, když to jde. Jinak se zapíše jako otevřený bod a nic se neobchází.
- Do repa se nic nestahuje. Výřezy leží v `F:\bakula-datasets\` s SHA-256 v `dataset-registry.md`. Kód je čte z cesty v proměnné `BAKULA_EXTERNAL_DATASETS`.
- **Výřez** = všechny toky v okně [první tok skupiny štítků − 30 min, poslední tok + 30 min], nejvýš 3 h od začátku okna. Neškodné výřezy jsou dvě hodinová okna pondělí CIC-IDS2017. Rozdělení je pevné po skupinách štítků (ne po tocích):
  - vývojová část: CIC `tue-ftp-patator`, `wed-dos-slow` (slowloris, Slowhttptest), `fri-botnet`, `mon-benign-am`; UNSW první výřez s kategoriemi Reconnaissance a Exploits;
  - testovací část (zamčená, otevře se jednou v G): CIC `tue-ssh-patator`, `wed-dos-hulk-goldeneye`, `thu-web`, `thu-infiltration`, `fri-portscan`, `fri-ddos`, `mon-benign-pm`; UNSW druhý výřez s ostatními kategoriemi.
- Metrika je stejná jako u kotvy kroku 3 (hosté s nálezem, škodliví a neškodní, po scénářích), behaviorální vrstva s výchozím presetem v3.

## B) Harness (commity `ada1b47`, `c4598de`)

- `src/soak/coverage.rs`: svět pokrytí `--coverage off|tuning|full` podle A2. Obsahuje:
  - variaci útoku (`Variation`, transformace toku v `traffic::push` přes `coverage::vary`):
    - tempo: akumulátor, při zpomalení každý k-tý tok, při zrychlení časová osa cyklu stlačená k-krát, takže periodicita zůstane;
    - rozptyl časů a objem;
    - rozdělení na víc zdrojů po řadě (každý zdroj si nechá rytmus původního proudu);
  - index skrytosti S;
  - kampaně (6 šablon, sdílený útočník, oběť vstupní fáze je útočníkem dalších fází);
  - 9 nových poruch (`Lookalike::COVERAGE`, 4 držené);
  - souběhy útok + provozní porucha (p = 0,25, senzorové poruchy 1/3);
  - záznamy `AttackRecord` a `FaultRecord` v `networks.jsonl`.
- `traffic.rs`: emitory nových poruch ze stávajících vzorů toků. Plánování benigních událostí je vytažené do `build_benign` beze změny pořadí náhody a `len_range` a `ids_share` jako čisté funkce.
- `episode.rs`: plán pokrytí po `plan_episode` (vlastní proud). Kampaň s vyřazenou rodinou se vyřadí celá. Stavy nových poruch: DNS dole, podsíť bez napájení, hromadné přečíslování přes `NetworkModel::renumber`. Klíčové IP zahrnují další zdroje, blok cloudu a starou adresu serveru. Záznamy po útocích obsahují i to, zda byl připsaný nález automaticky zavřen a zda šlo o první výskyt (typ, entita).
- `--v3-on` zapíná změny mimo preset (ablace F).
- `tools/soak_coverage.py` počítá:
  - křivky skrytosti, osy, rodiny × osy, souběhy, kampaně, LOFO, poruchy a registr slepých míst podle A8;
  - prahy K1 až K8 a párové rozdíly s bootstrapem po sítích.

**Zpětná kompatibilita.** Výchozí svět (`--coverage off`) dává bajtově stejný `networks.jsonl` (bez časových polí) jako binárka před krokem 5. Ověřeno na 6 sítích seedu 20261411, v3 s kontrafaktuálem: 0 rozdílů (`F:\claude-tmp\k5\scripts\cmp_networks.py`). `cargo test --lib soak::` prošlo (65 testů), včetně `run_stop_resume…verify_confirms_reproducibility`. Nové testy:

- tempo, rozptyl, objem, zdroje a index S;
- `off` nemění plán, `tuning` nemá držené části;
- každá nová porucha emituje toky;
- svět pokrytí je deterministický a má záznam o každé pravdě.

`cargo clippy --all-targets`: lib 89, lib test 97, bin 3, e2e 1. Nová varování v kódu kroku 5 jsou opravená, zbytek je ze stavu před krokem 5.

**Odchylka před ladicím během.** První ladicí běh (binárka `f8729af`) rozděloval toky mezi zdroje náhodně podle otisku toku. Rozbíjel tak pravidelnost každého zdroje (C2 ze 3 hostů vypadal jako náhodný šum, ne jako tři pravidelné majáky). To je chyba harnessu, ne vlastnost útoku. Oprava je rozdělení po řadě (`c4598de`). Ladicí běh se pustil znovu a čísla v E jsou jen z opravené binárky. Rozhodnuto na ladicích datech, držená data se neotevřela.

## C) Veřejné datasety

- Zdroje `src/eval/sources/cicids2017.rs` a `unsw_nb15.rs` (`ScenarioSource`, vzor iot23/ctu13) s testy parseru.
- Kotva `behavior_anchor::run_k5`: behaviorální vrstva na úrovni vnitřního hostu (jako G6) a pasivní detektory (ablace D) na úrovni cílové služby. Útoky zvenku behaviorální vrstva na vnitřních hostech nevidí.
- Rozdělení `[dev-k5]` a `[test-k5]` v `anchor-split.txt` se SHA-256, zamčení testem.
- Licence, velikosti a hashe jsou v `dataset-registry.md` (vlna 1), skripty výřezu v `tools/datasets/`.
- Ověřeno na oficiálních stránkách 2026-11-04. CIC-IDS2017 nemá výslovnou licenci, jen požadavek citace. Oficiální stažení chce formulář s osobními údaji, proto je použita veřejná přegenerovaná verze Engelen a kol. (334 MB ZIP, po dnech přes HTTP Range). UNSW-NB15 je volně pro akademický výzkum (komerčně po dohodě), staženo z oficiální sdílené složky (`UNSW-NB15_4.csv`, 97,6 MB).
- Obsahový filtr při práci nezasáhl.
- Dvě odchylky od A9 byly zjištěné a opravené před během jakéhokoli detektoru (podrobně v registru):
  1. Středeční okna CIC se překrývala, proto je hranice v mezeře mezi skupinami štítků.
  2. UNSW se dělí po čase, protože kategorie se v čase prolínají.

## D) Plán laboratoře a pasivního sběru

`docs/diplomka/eval/lab-plan.md` (commit `f8729af`): izolovaná laboratoř se standardními nástroji a runbookem pozemní pravdy, poruchy naostro, pasivní Zeek v domácí síti s pseudonymizací a souhlasem domácnosti, dotaz pro UHK. Zatím nic nenasazeno.

## E) Ladicí měření (seedy 20261411 až 20261413, binárka `c4598de`)

**Hranice pásem S** (A2) z plánu ladicího světa, 3 047 naplánovaných útoků ve 3 × 40 sítích, spočítané před pohledem na jakoukoli detekci: Q1 < 0,1718 ≤ Q2 < 0,2363 ≤ Q3 < 0,3053 ≤ Q4 < 0,3917 ≤ Q5. Platí beze změny i pro držený běh (`--edges 0.1718,0.2363,0.3053,0.3917`).

Svět `--coverage tuning --families tuning`, 3 × 40 sítí (120 párů, 3 042 útoků s emitovanými toky a kontrafaktuálem). Nástroj `tools/soak_coverage.py`, plné výstupy v `docs/diplomka/eval/k5/tuning-*.md`. Všech 12 ramen doběhlo, 0 panik a 0 porušených invariantů.

| metrika | legacy | v3 | rozdíl (95% CI, bootstrap po sítích) |
|---|---:|---:|---|
| kontrafaktuální zobrazená detekce | 56,6 % | 79,7 % | +23,1 p. b. (+20,6 až +25,7) |
| totéž v pásmech Q4 + Q5 | | | +23,3 p. b. (+19,8 až +26,8) |
| zobrazené FP na síť-den | 969,6 | 18,8 | |
| zavřeno omylem (G3) | – | 67 / 4 023 = 1,7 % (Wilson 1,3 až 2,1 %) | |
| útoky s automaticky zavřeným připsaným nálezem | 0,0 % | 0,9 % (0,6 až 1,3 %) | |

**Křivka skrytosti (v3):** Q1 80,2 %, Q2 80,0 %, Q3 78,6 %, Q4 81,4 %, Q5 78,5 %. U legacy je to 58,5 % → 52,9 %. Po jednotlivých osách (v3, n = 362 až 2 396 na úroveň) je detekce mezi 72 a 85 %. Nejsilněji působí:

- IDS signatura: bez ní 75,0 %, s ní 93,2 %;
- krátké trvání: doba 0,5× 72,2 %, 4× 84,6 %;
- nejnižší intenzita: 0 až 0,2 75,1 %.

Rozptyl, počet zdrojů, objem, denní doba ani míchání s provozem souhrnnou detekci neposunou o víc než 3 p. b. Plochá křivka ale neznamená, že skrytost nevadí. Detekce stojí hlavně na signálech, které osy harnessu nemění (nová vazba, nový cíl, pokusy bez odpovědi). Variace harnessu jsou jen parametrické a nevytvářejí útoky, které by tyto signály skutečně obcházely. To je omezení metody, ne důkaz odolnosti proti libovolné skrytosti.

**Rodiny (v3, n):**

| rodina | n | v3 | legacy |
|---|---:|---:|---:|
| ssh_bruteforce | 456 | 93,2 % | 88,6 % |
| credential_stuffing | 267 | 90,3 % | 85,0 % |
| rogue_device | 81 | 90,1 % | 34,6 % |
| exfiltration | 289 | 89,3 % | 13,8 % |
| ddos_volume | 104 | 88,5 % | 88,5 % |
| port_scan_vertical | 297 | 86,9 % | 57,9 % |
| dns_tunnel | 164 | 86,0 % | 42,1 % |
| c2_beacon | 388 | 78,4 % | 26,3 % |
| port_scan_horizontal | 316 | 77,2 % | 78,5 % |
| lateral_movement | 371 | 66,3 % | 71,2 % |
| exploit_attempt | 309 | 46,3 % | 24,6 % |

**Souběhy (v3):** bez souběhu 78,3 % (n = 711), s nesenzorovou poruchou 81,1 % (n = 2 118), se senzorovou poruchou 78,7 % (n = 934). Souběh s poruchou detekci nesnižuje. Senzorová porucha útok zakryje jen tehdy, když trvá déle než útok.

**Kampaně (v3, 276):**

- aspoň jedna fáze zachycena: 98,2 % (95,8 až 99,2 %);
- zachycena už první fáze: 67,0 %, nejméně u K-T3 (exploit na vstupu), 48,4 %;
- zachyceny všechny fáze: 38,8 %.

U legacy je to 89,1 %, 61,2 % a 11,2 %.

**LOFO (v3, první útok rodiny v síti, bez signatury, bez vlastních typů):**

| rodina | n | všemi signály | obecná detekce | verdikt |
|---|---:|---:|---:|---|
| ssh_bruteforce | 53 | 94,3 % | 92,5 % (82,1 až 97,0) | zobecňuje |
| dns_tunnel | 57 | 91,2 % | 57,9 % (45,0 až 69,8) | zobecňuje |
| lateral_movement | 68 | 66,2 % | 42,6 % (31,6 až 54,5) | slepé místo |
| c2_beacon | 67 | 67,2 % | 11,9 % (6,2 až 21,8) | slepé místo |
| port_scan_vertical | 61 | 86,9 % | 4,9 % (1,7 až 13,5) | slepé místo |
| exfiltration | 70 | 85,7 % | 2,9 % (0,8 až 9,8) | slepé místo |

Kontrola náhrady skutečnou ablací (`--v3-off beacon`): c2_beacon na stejných útocích s vypnutým detektorem periodicity dává 13,4 % proti náhradě 11,9 %. Náhrada tedy odpovídá skutečnému vypnutí detektoru (rozdíl 1,5 p. b.). Celkově c2_beacon klesne bez detektoru z 78,4 % na 34,8 % a souhrnná detekce o 5,7 p. b. (−6,6 až −4,9).

Závěr pro neznámé rodiny: obecné signály zachytí nové hádání hesel a DNS tunel. Neznámý maják, exfiltraci, vertikální sken a z větší části i pohyb v síti zachytí jen proto, že pro ně existuje vlastní detektor. Rodina, která by se podobala těmto čtyřem a neměla vlastní detektor ani signaturu, by s velkou pravděpodobností prošla.

**Poruchy a lookalike (v3, podíl výskytů s aspoň jedním zobrazeným FP):**

| porucha | podíl | pozn. |
|---|---:|---|
| misconfig | 97,0 % | nové, laděné |
| authorized_scanner | 94,3 % | |
| patch_window | 93,4 % | |
| backup_failed | 89,3 % | nové, laděné |
| dns_outage | 85,2 % | nové, laděné |
| collector_replay | 76,8 % | |
| dhcp_renumber | 75,6 % | nové, laděné |
| batch_job | 64,1 % | |
| service_crash | 62,4 % | |
| log_corruption | 46,2 % | |
| flash_crowd | 45,4 % | |
| backup_burst | 40,1 % | |
| device_onboarding | 16,1 % | |
| sensor_crash | 14,0 % | |
| device_decommission | 9,9 % | |
| ntp_fanout | 4,8 % | |
| software_update | 1,2 % | |
| link_flapping, retry_storm | 0,0 % | |

Část „FP“ jsou skutečné provozní problémy: špatná konfigurace, výpadek DNS, selhaná záloha, přečíslování. Správce o nich vědět chce, ale ne jako o útoku. Engine je teď neodliší od útoku a zobrazí je stejně. To je slepé místo výstupu (třídění „provozní problém“ proti „podezření na útok“), ne jen detektorů.

**Pravidlo A7:** 12 automatických zavření u útoků připadlo na první výskyt dvojice (typ, entita). Každé automatické zavření v enginu má doložené vysvětlení: buď kontext (kalendář, CMDB, monitoring), nebo vyvrácení žebříkem ověřování. Zavření bez vysvětlení engine neumí. Pravidlo je tedy splněno konstrukcí a těchto 12 jsou omylem zavřené útoky, které spadly do okna platného kontextu. Jsou započtené v G3.

## F) Obecné opravy na ladicích datech

Detektory jsem neměnil. Na ladicích seedech jsem změřil dvě existující obecné části mimo preset:

| ablace | detekce | zobrazené FP/síť-den | pozn. |
|---|---|---|---|
| `--v3-on graph` (nové vztahy, `pivot_chain`) | +2,0 p. b. (+1,4 až +2,6) | 18,8 → 22,7 (+21 %) | lateral_movement 66,3 → 79,5 %, kampaně „všechny fáze“ 38,8 → 47,1 % |
| `--v3-off beacon` (kontrola LOFO) | −5,7 p. b. (−6,6 až −4,9) | 18,8 → 18,5 | c2_beacon 78,4 → 34,8 % |

Graf nových vztahů je jediná obecná změna, která ve světě skrytých útoků a kampaní pomáhá znatelně. Zavírá většinu slabého místa lateral_movement a v3 tím přestává být v pohybu po síti horší než legacy. Platí se za to +21 % zobrazených FP. Krok 4 graf vyřadil z presetu na výchozím světě (+0,2 p. b. detekce za +3,7 % FP). Ve světě pokrytí je výměna jiná. Preset ale neměním: držené rameno je podle A3 preset po kroku 4 a změna presetu by potřebovala vlastní předregistraci. Je to doporučení pro další krok. Opravy pro exploit_attempt (signatury a CVE) a pro třídění provozních problémů nejsou obecné změny detektoru podle zadání, proto zůstávají v registru slepých míst.

## G) Držený běh (seedy 20261401 a 20261501, jednou, binárka `c4598de`)

Svět `--coverage full --families all`, 2 × 40 sítí (80 párů, 2 856 útoků, z toho 745 z držených rodin). Hranice S jsou z E, prahy z A6 beze změny. Běh 2026-11-04 23:47 až 2026-11-05 00:50, priorita Idle. Plný výstup je v `docs/diplomka/eval/k5/held-legacy-v3.md`. Po pohledu na výsledek se nic neladilo a běh se neopakoval.

| práh | hodnota | splněno |
|---|---|---|
| K1 | Q5 / Q1 = 75,6 % / 80,1 % = 0,94 | ano |
| K2 | párově v3 − legacy: vše +16,5 p. b. (+14,1 až +19,0), Q4 + Q5 +13,6 p. b. (+10,3 až +16,9) | ano |
| K3 | zobrazené FP držených nových poruch 78,8 % proti laděným novým poruchám 66,3 % (+12,5 p. b.) | **ne** |
| K4 | souběh s nesenzorovou poruchou proti bez souběhu: −1,9 p. b. (78,2 % proti 80,9 %) | ano |
| K5 | LOFO zobecňuje 2 ze 6 (ssh_bruteforce 75,9 %, dns_tunnel 54,5 %) | 4 slepá místa |
| K6 | zavřeno omylem 185 / 3 165 = 5,8 %, Wilson 5,1 až 6,7 % | **ne** |
| K6b | útoky s automaticky zavřeným nálezem: držené rodiny 4,2 % proti laděným 1,0 % | ano (≤ +5 p. b.) |
| K7 | kampaně zachycené aspoň v jedné fázi 98,0 % (95,0 až 99,2 %) | ano |
| K8 | 0 panik, 0 porušených invariantů (160 sítí) | ano |

**Souhrn (v3 / legacy):** detekce 77,9 % / 61,4 %, zobrazené FP na síť-den 14,1 / 653,8.

**Křivka skrytosti (v3):** Q1 80,1 %, Q2 80,1 %, Q3 80,6 %, Q4 77,5 %, Q5 75,6 %. Držené krajní úrovně os (v3):

| osa | držená úroveň | detekce | srovnání |
|---|---|---:|---|
| tempo | 0,25× | 80,3 % | |
| tempo | 8× | 80,1 % | |
| rozptyl | 0,5 | 76,9 % | |
| zdroje | 10 | 73,6 % | 1 zdroj: 78,7 % |
| intenzita | pod 0,2 | 73,3 % | |

Ve držených rodinách:

| rodina | n | detekce |
|---|---:|---:|
| apt_chain | 59 | 98,3 % |
| insider_hoarding | 53 | 94,3 % |
| ransomware | 82 | 92,7 % |
| slow_scan | 201 | 86,1 % |
| web_exploit | 188 | 84,6 % |
| cryptomining | 125 | 79,2 % |
| fleet_beacon | 34 | 76,5 % |
| ics_attack | 3 | nedostatečná data |

**Kampaně:** zachycena první fáze 79,8 %, všechny fáze 41,9 %. Držené šablony: K-H1 100 %, K-H2 97,4 %, K-H3 94,6 % aspoň v jedné fázi.

**Proč selhal K6.** Ze 163 omylem zavřených nálezů kontextem jich 147 zavřel kontext „výpadek senzoru“ (v ladicím běhu 5 ze 47). Kontext výpadku senzoru nemá klíčové hosty a vysvětluje v celém svém okně jakýkoli nález. Ve světě `full` běží dlouhé držené útoky (těžba, kampaně, fleet) přes výpadky senzoru častěji a jejich nálezy po návratu dat kontext zavře. Je to obecná vada pravidla kontextu, ne vlastnost jedné rodiny. Ladicí svět ji neukázal, protože ladicí útoky jsou kratší. Opravu (výpadek senzoru vysvětluje jen typy způsobené mezerou v datech a jen v cyklech výpadku plus jeden po něm) jsem po pohledu na držená data neudělal a nepouštěl. Patří do dalšího kroku s novou předregistrací a novými seedy.

**Proč selhal K3.** Držené poruchy vyvolají zobrazené FP častěji než laděné:

| držená porucha | podíl výskytů se zobrazeným FP |
|---|---:|
| cloud_migration | 89,9 % |
| cert_expired | 89,1 % |
| vpn_reconnect_storm | 79,4 % |
| segment_power_loss | 58,6 % |

Engine pro ně nemá žádný kontext a nové vnější cíle nebo bouře neúspěšných spojení vypadají jako útok. Žádná z poruch se neladila, laděné nové poruchy mají vysoké FP také (66,3 %). Rozdíl je tedy hlavně v tom, jak moc daná porucha útok připomíná, ne v přeučení.

**Veřejné datasety (C).** Vývojová část proběhla jednou na začátku G (bez ladění), zamčená testovací část `behavior_anchor_k5_test_once` jednou hned po ní. Výstupy jsou v `F:\claude-tmp\k5\anchor-k5-dev.out` a `anchor-k5-test.out`.

| výřez | část | toků | škodlivých | behaviorální vrstva: škodliví / neškodní vnitřní hosté s nálezem | pasivní detektory D: TP / FP / FN / TN klíčů služby |
|---|---|---:|---:|---|---|
| tue-ftp-patator | dev | 102 995 | 3 984 | 0/0 z 0/13 | 1 / 2 555 / 0 / 2 724 |
| wed-dos-slow | dev | 95 251 | 10 843 | 0/0 z 0/13 | 1 / 2 301 / 0 / 2 643 |
| fri-botnet | dev | 135 702 | 1 509 | 0/0 z 7/6 | 1 / 3 031 / 2 / 3 387 |
| mon-benign-am | dev | 59 849 | 0 | 0/0 z 0/13 | 0 / 1 844 / 0 / 2 287 |
| unsw-h0 | dev | 138 993 | 30 525 | 0/0 z 0/15 | 275 / 17 118 / 544 / 10 194 |
| tue-ssh-patator | test | 122 372 | 2 988 | 0/0 z 0/13 | 1 / 2 922 / 0 / 3 338 |
| wed-dos-hulk-goldeneye | test | 211 284 | 166 709 | 0/0 z 0/13 | 1 / 1 403 / 0 / 1 795 |
| thu-web | test | 86 752 | 2 056 | 0/0 z 0/13 | 1 / 2 210 / 0 / 2 716 |
| thu-infiltration | test | 174 824 | 48 | 0/0 z 1/12 | 1 / 13 471 / 0 / 2 924 |
| fri-portscan | test | 225 719 | 139 741 | 0/0 z 5/9 | 999 / 2 292 / 1 / 3 122 |
| fri-ddos | test | 143 780 | 95 123 | 0/0 z 0/13 | 1 / 1 328 / 0 / 2 058 |
| mon-benign-pm | test | 35 878 | 0 | 0/0 z 0/12 | 0 / 1 082 / 0 / 1 427 |
| unsw-h2 | test | 132 138 | 29 411 | 0/0 z 0/23 | 272 / 18 134 / 542 / 10 209 |

Behaviorální vrstva (preset v3) nenahlásí na žádném výřezu nic. Dva až tři hodinové výřezy jsou na ni krátké (3 až 7 oken; periodicita a profil hostu potřebují aspoň den historie). Útoky v CIC-IDS2017 navíc jdou většinou zvenku na servery, ne z vnitřních hostů. Šest škodlivých vnitřních hostů (botnet, infiltrace, port scan) nezachytí.

Pasivní detektory (ablace D) na úrovni služby najdou napadenou službu skoro vždy (CIC recall 1/1 na výřez, port scan 999/1 000, UNSW 272/814 = 33 %). Jenže označí i většinu neškodných klíčů (přesnost 0,03 až 30 %). Na pondělních čistě neškodných výřezech označí 1 844 ze 4 131 a 1 082 z 2 509 klíčů. Bez paměti, kontextu a žebříku v3 jsou na reálných tocích nepoužitelné. Plnou cestu v3 nad těmito toky (s pamětí a kontextem) kotva zatím nemá. To je otevřený bod a přímé pokračování pro laboratoř (D).

## H) Registr slepých míst a co nezachytíme

Seřazeno podle dopadu. U každého je uvedený obecný signál, který by mohl pomoct, a zda jde o vlastnost simulace. Zdroj je držený běh, pokud není uvedeno jinak.

| # | slepé místo | měření (v3) | proč | obecný signál, který by mohl pomoct |
|---|---|---|---|---|
| 1 | Kontext „výpadek senzoru“ zavírá nálezy útoků | 147 omylem zavřených nálezů, K6 nesplněn | globální kontext bez klíčových hostů vysvětluje každý typ | omezit na typy z mezery v datech a na cykly výpadku |
| 2 | Neznámá rodina podobná majáku, exfiltraci, vertikálnímu skenu nebo pohybu v síti, bez vlastního detektoru a signatury | LOFO 0 až 47 % (c2 16 %, exfil 15 %, vertikální sken 0 %, lateral 47 %) | detekce stojí na detektoru rodiny | dlouhodobé součty drobných odchylek hostu proti jeho profilu a peer skupině; nové vztahy (graf: lateral +13 p. b. v ladění) |
| 3 | exploit_attempt | 49,6 % (n = 270), v ladění 46,3 % | bez IDS signatury jen pár toků na službu | IDS a CVE kontext, ne tokový detektor (mimo zadání kroku 5) |
| 4 | Provozní problémy se zobrazují jako podezření na útok | 12 z 18 neškodných druhů má zobrazené FP u > 20 % výskytů, nejvíc misconfig 96,8 %, authorized_scanner 93,4 %, cloud_migration 89,9 %, cert_expired 89,1 %, dns_outage 89,1 % | chybí třída „provozní problém“ a kontext pro nové poruchy | oddělit výstup „provozní problém“ (selhávající spojení mnoha klientů na jeden cíl) od podezření |
| 5 | c2_beacon se zrychleným tempem (2× až 8×, kratší trvání) | 36,8 až 43,6 % (n = 22 až 39) | detektor periodicity potřebuje ≥ 24 h | jen přes obecný profil hostu (nový stálý cíl), ne úpravou detektoru majáku |
| 6 | Útok rozložený na 10 zdrojů | 73,6 % proti 78,7 % u jednoho zdroje; c2 53,8 %, dns_tunnel 54,8 %, exploit 40,6 % | na zdroj připadá málo toků | součet přes skupinu nových zdrojů se stejným cílem |
| 7 | lateral_movement | 69,5 %, horší než legacy (74,9 %) | v3 potlačí část `unexpected_traffic`; graf je mimo preset | zapnout graf nových vztahů (v ladění +13,2 p. b. za +21 % FP), po předregistraci |
| 8 | Krátké útoky (doba 0,5×) | 68,7 % | málo cyklů na potvrzení | – (vlastnost útoku) |
| 9 | Reálná data | behaviorální vrstva 0 nálezů na 13 výřezech CIC a UNSW; na CTU-13 v kroku 4 také 0 | krátké výřezy, útoky zvenku, chybí plná cesta v3 v kotvě | laboratoř a pasivní domácí sběr (`lab-plan.md`), kotva s plnou cestou v3 |
| 10 | ics_attack | n = 3 | v síti je málo PLC | cílený běh průmyslových sítí |

Co engine podle měření spolehlivě zachytí (v3, držený běh, ≥ 80 % s dolní mezí ≥ 75 %):

- hádání hesel: ssh 90,2 %, credential stuffing 81,8 %;
- rogue zařízení 96,8 %;
- vícefázové kampaně aspoň v jedné fázi 98 %;
- apt_chain 98,3 %;
- insider 94,3 %;
- ransomware 92,7 %;
- slow_scan 86,1 %;
- web_exploit 84,6 %;
- vertikální sken 83,3 %;
- exfiltrace 82,4 %.

To ale platí jen v simulaci a díky vlastním detektorům těchto rodin.

Co z toho plyne pro tvrzení práce: v simulaci je v3 proti parametrické skrytosti (tempo 0,25× až 8×, rozptyl, objem, víc zdrojů, noc, míchání s provozem) a proti souběhu s provozními poruchami odolné v rozsahu K1, K2 a K4. Detekce v nejskrytější pětině je 94 % detekce v nejhlučnější. Odolnost proti neznámým rodinám doložená není: obecné signály zobecňují jen u 2 ze 6 vynechaných rodin. Automatické zavírání drží chybu pod 5 % jen v ladicím světě, v drženém ne (K6). Reálná veřejná data zatím odolnost nepotvrzují ani nevyvracejí, protože behaviorální vrstva na nich nemá dost historie.

### Odchylky od předregistrace (souhrn)

1. Harness: náhodné rozdělení toků mezi zdroje bylo nahrazeno rozdělením po řadě, po prvním ladicím běhu a před drženým během (B).
2. A9: hranice středečních výřezů CIC je v mezeře mezi skupinami štítků a UNSW se dělí po čase. Obojí bylo rozhodnuto před během jakéhokoli detektoru.
3. A9: pondělní neškodná okna jsem v A9 přesně nevymezil. Použita byla hodina 1 až 2 a 5 až 6 od prvního toku dne, rozhodnuto před během.
4. A5: kontrolní ablace `--v3-off beacon` proběhla na ladicích seedech, jak bylo předregistrováno. Ablace grafu `--v3-on graph` předregistrovaná nebyla, je jen popisná a na držených seedech neběžela.

### Co zůstává otevřené

- Oprava kontextu výpadku senzoru (bod 1), třída výstupu „provozní problém“ (bod 4) a zapnutí grafu (bod 7) jen s novou předregistrací a novými seedy. Držené seedy kroku 5 už jsou použité.
- Kotva veřejných datasetů s plnou cestou v3 (paměť, kontext, žebřík) a s delšími výřezy (celý den), aby behaviorální vrstva měla historii.
- CSE-CIC-IDS2018 a CICIoT2023 (oficiálně jen přes formulář s osobními údaji).
- Laboratoř a pasivní sběr podle `lab-plan.md`, dotaz pro UHK neodeslán.
- G4 (čas cyklu XXXL) z kroku 4 zůstává nesplněný, legacy zůstává výchozí.
- Audit pokrytí (`audit-pokryti.md`, bod 0) uvádí, že generátor změny IP zařízení chybí. Ve skutečnosti existuje: `NetworkModel::churn` přečísluje 1 % dynamických zařízení za cyklus. Krok 5 k tomu přidal hromadné přečíslování podsítě (`dhcp_renumber`).

## Commity kroku 5

`6428952` předregistrace, `ada1b47` svět pokrytí, `b414f00` zdroje CIC-IDS2017 a UNSW-NB15 a kotva k5, `f8729af` plán laboratoře, `c4598de` rozdělení zdrojů po řadě a `--v3-on`, `90243f3` hranice pásem S, `bebcf93` ladicí měření, a commit této sekce.
