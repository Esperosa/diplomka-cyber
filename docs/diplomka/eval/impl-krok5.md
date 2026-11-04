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
