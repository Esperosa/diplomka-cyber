# Implementace, krok 3: behaviorální vrstva v epizodě a v produkci, neškodné protějšky, XXXL, držená data

Datum 2026-11-01 až 2026-11-04. Kód: commity `333329a` a `2ef75f8` (detektory, z dřívějška), `08efd59` až `HEAD` tohoto kroku (větev `main`, nepushnuto). Měření: ladicí seedy 20261102, 20261103, 20261104, každý 40 sítí, `--block-size 2 --no-legs --no-feedback --counterfactual`, šum neškodných vzorů 1× (výchozí). Držené seedy (20261201, 20261301) ani testovací část kotvy se nespustily. Všechna soak čísla jsou ze simulace.

Commity: `08efd59` (bod 1), `06d77bc` (body 2 až 4 v generátoru: šum, XXXL a rodiny sdílejí stejné konfigurační struktury, proto jeden commit), `33d967c` (bod 4, kotva), `05af7f5` (měření pro bod 5), dokumentace zvlášť. Surové výstupy: `F:\bakula-soak\ab\k3\reports\`. Přepočet: `python tools/soak_ab.py --a <dirs> --b <dirs>`.

Ramena (stejný harness, stejný svět včetně neškodných vzorů 1×, párově po sítích, 120 sítí, 1 236 virtuálních síť-dnů):

| rameno | konfigurace |
|---|---|
| `legacy` | legacy |
| `s2` | v3 po kroku 2 (`--v3-off egress,beacon,interactive,graph,profile`) |
| `s3` | v3 po kroku 3, výchozí `V3Features::recommended()` (vše kromě peer baseline) |
| `s3-no<X>` | ablace: `s3` bez jedné části (`beacon`, `interactive`, `graph`, `profile`, `egress`) |

## Shrnutí

1. **Odchozí rodiny jsou poprvé vidět.** Kontrafaktuální zobrazená detekce `s2` → `s3`: c2_beacon 2,3 → 92,6 % (+90,2 p. b., 95% CI +84,5 až +95,1, n = 215), exfiltration 0,0 → 90,3 % (+90,3, +82,8 až +97,1, n = 103), cryptomining 2,2 → 91,0 % (+88,8, +81,5 až +95,8, n = 89), fleet_beacon 56,8 → 75,0 % (+18,2, +7,4 až +31,2, n = 44). Žádná rodina neklesla (všechny ostatní ±0 až +2,9 p. b.); lateral_movement 75,3 → 76,3 %, dns_tunnel 96,8 % beze změny, rogue_device 94,5 % beze změny. Správný typ u c2, exfiltrace a cryptominingu se zvedl stejně (typ = nález vrstvy).
2. **Cena jsou falešné poplachy: +12,3 %** zobrazených FP na síť-den (14,1 → 15,8, 95% CI +9,3 až +16,8 %), zobrazené položky +9,6 % (63,8 → 69,9). Nové FP jsou `beacon_periodic` 0,8, `pivot_chain` 0,5 a `egress_volume_anomaly` 0,4 na síť-den; staré typy se nezměnily. Proti legacy je `s3` pořád −97,8 % FP (734,3 → 15,8, CI −98,2 až −97,2 %).
3. **Neškodné pravidelné vzory vrstva většinou neukáže.** Při šumu 1× vznikne na vzorech 241 nálezů vrstvy na síť-den (většinou `beacon_periodic` na NTP, cronu, VPN, CI/CD a agentech), zobrazí se 1,1 (paměť nálezů a žebřík). Celkem zobrazené FP na vzorech 4,7 → 5,8 na síť-den, z toho 4,7 vydávají detektory kroku 1 a 2 (hlavně `unexpected_traffic` na NTP k bráně a monitoring). Při 10× a 50× šumu ale FP vrstvy na vzorech rostou skoro lineárně (16 sítí: 8,7 → 34,1 → 96,7 zobrazených na síť-den proti 6,4 → 14,1 → 10,8 u kroku 2); viz D. **Vrstva v současném nastavení neunese síť s hustým pravidelným provozem.**
4. **Automaticky vyřešené odlišné stavy 0,7 → 0,8 %** (`s2` 0,6 → `s3` 0,7 stavu na síť-den, +19,0 %, CI +4,4 až +33,4 %). Celý zisk dělá profil hostu (ablace: +22,0 %, CI +10,4 až +34,9 %). Absolutně je to dál malé.
5. **Zavřeno omylem (sjednocená kontrafaktuální definice, C1): 0,38 % → 0,50 %** (8/2 112 → 13/2 609; 95% CI 0,19 až 0,75 % a 0,29 až 0,85 %), pod mezí 2 %. Všechna omylná uzavření jsou vyvrácení žebříkem (kontext 0/535). Přesnost potvrzení žebříku ale klesla z 96,5 % (95,5 až 97,2) na 91,9 % (90,7 až 93,0).
6. **XXXL** (8 000 až 10 000 zařízení): paměť do 556 MiB na síť, p99 cyklu 1,2 až 1,9 s u dvou ze tří sítí. **Třetí síť má p99 12 s** kvůli jednomu cyklu plošného autorizovaného skenu (detekce v3 7,7 s), stejně v legacy (8,8 s); vrstva kroku 3 k tomu přidává do 0,2 s.
7. **Kotva (vývojová část):** na IoT-23 vrstva označí 4 z 5 škodlivých hostů a 1 ze 4 neškodných (honeypot s hodinovou periodicitou), na krátkých vyřezech CTU-13 0 z 8 škodlivých a 2 z 92 neškodných.

## 1) Zapojení behaviorální vrstvy

**Soak epizoda** (`src/soak/episode.rs`, `v3.rs`, `ladder_env.rs`):
- toky cyklu se dělí podle směru (`passive::egress::split_flows`): cíl v rozsahu jde do stávajících detektorů beze změny, odchozí (po vzorkování po dvojici) a čistě vnitřní toky do `behavior::run_window`,
- Suricata alerty se při zapnuté viditelnosti ven parsují v režimu `SrcOrDst`; alerty s cílem v rozsahu jdou dál stejně jako dřív (stejná množina jako `DstOnly`), odchozí do vrstvy (`egress_ids_alert`),
- nálezy vrstvy se přidají do reportu cyklu a projdou stejnou cestou jako ostatní: paměť nálezů, kontext, žebřík ověřování, zobrazení, atribuce. Síla signálu a protistrana (zdroj pro paměť a kontext) se berou z vrstvy, ne z `finding_signal`, protože služba `out/<cíl>/..` v reportu není,
- profil hostu je důkaz žebříku (`SoakEvidence::profile`, `ProdEvidence::profile`, společné `behavior::profile::case_verdict`) a učí se až po rozhodnutí cyklu; dvojice s poplachem (aktér a každý zdroj nálezu, oba směry, `frozen_pairs`) se neučí (RQ2 Z3),
- stav vrstvy (`BehaviorState`) přežije restart enginu (kv `behavior`),
- `expected_types` rodin doplněny o typy vrstvy podle mechanismu útoku (stejné pravidlo jako krok 2 A5): c2_beacon a fleet_beacon `beacon_periodic`, `egress_ids_alert`; exfiltration `egress_volume_anomaly`, `long_lived_tunnel`; dns_tunnel a insider_hoarding `egress_volume_anomaly`; lateral_movement a ransomware `pivot_chain`; cryptomining `long_lived_tunnel`, `beacon_periodic`, `egress_ids_alert`; apt_chain všechny. Legacy tyto typy nevydává, jeho čísla se nemění.

**Produkce** (`passive::load_and_normalize_with_behavior`, `pipeline/mod.rs`, `pipeline/v3.rs`): ve v3 s behaviorální vrstvou parsery drží toky a alerty se zdrojem v rozsahu; detektor a korelace dostávají jen záznamy s cílem v rozsahu (stejný vstup jako legacy), odchozí a vnitřní toky jdou přes `V3Session::set_behavior_flows` do `post_findings`. Stav vrstvy je v `engine-state.sqlite` (kv `behavior`), politika profilu žebříku se nastavuje podle `engine.profile()` i u uloženého žebříku. `load_and_normalize` (legacy) je beze změny; `engine.mode = legacy` výstup nemění (golden snapshot zelený).

**Přepínače:** `engine.mode = v3` a volby `egress`, `beacon`, `interactive`, `graph`, `profile` (`--v3-off`). `beacon` a `interactive` bez `egress` neběží, `profile` bez žebříku také ne. Výchozí `legacy` beze změny.

**Testy:** `behavior_layer_runs_in_episode_and_step2_has_none` (stejný svět, krok 2 nic z vrstvy nevydá, odchozí toky dojdou do vrstvy), integrační `v3_behavior_layer_reports_outbound_ids_alert_and_persists_state` (odchozí IDS alert ve v3 = `egress_ids_alert` na vnitřním hostu, stav uložen, legacy ho nevidí). Rychlý běh 20 sítí: 0 panik, 0 porušených invariantů.

## 2) Neškodné protějšky v generátoru

Modul `src/soak/benign_regular.rs`, přepínač `--noise <k>` (výchozí 1, 0 = vypnuto, měřeno 1, 10, 50). `k` násobí počet instancí vzorů (u DNS rekurze intenzitu); základní provoz se nemění. Vzory a zdroje hodnot:

| vzor | co dělá | parametry a zdroj |
|---|---|---|
| `monitoring_poll` | server dotazuje první službu až 40 serverů | perioda 10, 60, 300 s: Kubernetes `periodSeconds` 10 s, Prometheus `scrape_interval` 1 min, Nagios `check_interval` 5 min |
| `monitoring_agent` | ~20 % serverů posílá metriky na společný endpoint ven | 10, 15, 60 s: Telegraf `interval`/`flush_interval` 10 s, Datadog Agent 15 s |
| `ntp_sync` | brána k poolu ven, ~30 % klientů k bráně | 64 až 1024 s: RFC 5905 minpoll 6, maxpoll 10 |
| `dns_recursion` | DNS server ven k ~50 autoritativním serverům | cache miss ~15 % dotazů: Jung et al. 2002 (úspěšnost cache 80 až 87 %) |
| `update_check` | ~50 % hostů kontroluje aktualizace, 1 ze 7 stáhne velký balík | 22 h ± 20 %: Windows Update detection frequency; 12 h: apt-daily.timer s RandomizedDelaySec 12 h |
| `vpn_keepalive` | VPN nebo brána k protějšku | 20 s UDP 4500: RFC 3948 §4; 25 s UDP 51820: wg(8) PersistentKeepalive |
| `bastion_admin` | admin → jump (SSH), jump → 1 až 3 servery z pevné sady (řetěz A→B→C) | pracovní doba 8 až 17 h; relace 10 až 90 min (volba autora) |
| `remote_support` | relace ven na relay ~2× týdně | TCP 5938 (TeamViewer), 7070 (AnyDesk); 15 až 60 min |
| `ci_cd` | build server se ptá gitu venku a ~3× denně nasazuje na 3 až 12 serverů | 180 s: Argo CD `timeout.reconciliation`; 300 s: Jenkins `H/5` |
| `cdn_streaming` | ~5 % klientů streamuje, část videohovorů přes TURN | 20 až 120 min; 3 až 8 Mbit/s; UDP 3478 (RFC 8489) |
| `scheduled_backup` | noční záloha do cloudu | 1 až 3 h místního času, 1 až 50 GB (volba autora) |
| `script_polling` | cron skript volá API venku | `*/5`, `*/15`, hodinově; start na celou minutu (0 až 2 s) |

**Cirkularita (RQ5):** hodnoty jsou výchozí hodnoty protokolů a nástrojů, ne odvozené z prahů detektorů. Test `parameters_do_not_reference_detector_thresholds` hlídá, že modul na prahy neodkazuje, `every_kind_has_a_documented_source` hlídá tabulku zdrojů (`SOURCES`). Kde je hodnota volbou autora (délka relací, objem zálohy), je to v tabulce uvedeno. Riziko zůstává jen v opačném směru: autor detektorů zná generátor, takže detektory mohly být navrženy tak, aby tyto vzory snesly. Proti tomu je kontrola na reálných datech (bod 4), kde vzory nikdo nevybíral.

**Nezávislost světa:** každá instance má vlastní náhodný proud, vzory se emitují po všech ostatních tocích a před degradací telemetrie (ztráta, duplicita podle otisku toku). Test `regular_benign_noise_only_adds_flows` ověřuje na 12 sítích × 3 cyklech, že zapnutí šumu 10× žádný jiný tok nezmění ani neodstraní. Falešné poplachy na vzorech se počítají zvlášť (`regular_fp`, `vzor|typ nálezu`): nepřipsaný nález, jehož host a protistrana tvoří dvojici vzoru v tomto cyklu.

**Kontrola proti reálným datům** (vývojová část kotvy, `empirical_benign`): pravidelné dvojice (≥ 8 toků, CV mezer < 0,2) jsou i v reálném neškodném provozu. V CTU-13 je to 1 až 3 z 13 až 50 dvojic na scénář s mezerou 20 až 31 s a 234 s, v IoT-23 hodinová (3600 s) a dvouhodinová (7209 s) periodicita. Generátor tedy pravidelný neškodný provoz nepřehání. Ruční konstanty generátoru jsem empirickými kvantily nenahradil: vyřezy CTU-13 jsou krátké (1 až 6 půlhodinových oken) a IoT-23 má jeden až dva hosty na záznam, takže rozdělení velikostí a délek z nich nereprezentuje podnikovou síť. Kvantily jsou v `F:\bakula-soak\ab\k3\reports\anchor-dev.txt`.

## 3) Velké sítě (XXXL)

`--size xxxl`: síť Metro nebo Enterprise s 8 000 až 10 000 zařízeními a 150 až 240 podsítěmi /24 (`NetworkModel::generate_with`, nová třída `XXXL (>6000)`, v běžném mixu nevzniká). Pozadí se vzorkuje jako u ostatních velkých sítí (NetFlow 1:N, `flow_sampling` ≥ 0,08), odchozí toky vrstvy mají strop 200 000 na okno se vzorkováním po dvojici a 2 000 na dvojici, stavy vrstvy mají stropy (profil 50 000 hostů, 128 zvyků na host).

Měření: 3 sítě, 48 virtuálních hodin, jedno vlákno na rameno (tři ramena souběžně, nic jiného neběželo), bez kontrafaktuálu:

| rameno | zařízení | p99 cyklu (s) | čas sítě (s) | peak haldy procesu (MiB) |
|---|---:|---:|---:|---:|
| legacy | 9 955 / 8 080 / 8 721 | 1,54 / 1,06 / 8,82 | 88 / 64 / 66 | 368 |
| krok 2 | stejné | 1,77 / 1,13 / 11,58 | 93 / 71 / 82 | 468 |
| krok 3 | stejné | 1,86 / 1,21 / 11,96 | 101 / 78 / 89 | 556 |

- Paměť je v řádu stovek MiB na síť (peak haldy procesu s jednou sítí najednou), tedy v cíli.
- p99 cyklu je u dvou sítí 1,2 až 1,9 s, v cíli. **Třetí síť cíl nesplňuje (12 s).** Příčina je jediný cyklus, kdy čtyři autorizované skenery najednou projdou 8 700 hostů (95 800 toků na 8 706 cílů): detekce v3 v něm trvá 7,7 s, zásahy 1,8 s. Legacy má v tomtéž cyklu 8,8 s (report 4 s). Behaviorální vrstva na tom podíl nemá: její nejdelší cyklus je 0,12 až 0,2 s, průměr 0,055 s. Zkusil jsem nahradit lineární hledání cílů skeneru indexem, ale špička zůstala (12,8 s) a jedna z 10 kontrolních sítí změnila nálezy, takže jsem změnu vrátil. Skutečné horké místo v `detect_v3` při plošném skenu zůstává nenalezené (bez profileru).
- Krok 3 přidá k času sítě 8 až 10 % proti kroku 2 (vrstva a učení profilu).

## 4) Držená data bez nových rodin

**`--families tuning|held-out|all`** (`Family::held_out`, `FamilySet`) dělí EXISTUJÍCÍ rodiny. Pravidlo: ke každému mechanismu ladicí sady jedno „dvojče“ jiného tvaru a vícefázové rodiny jsou držené.

| ladicí (11) | držené (8) |
|---|---|
| port_scan_vertical, port_scan_horizontal, ssh_bruteforce, c2_beacon, ddos_volume, exfiltration, lateral_movement, rogue_device, exploit_attempt, dns_tunnel, credential_stuffing | fleet_beacon (dvojče c2_beacon), insider_hoarding (exfiltration), slow_scan (port_scan_*), web_exploit (exploit_attempt), apt_chain, ransomware, cryptomining, ics_attack |

Vyřazené útoky se z plánu odstraní, svět zbylých útoků a pozadí zůstává stejný (test `family_set_filters_attacks_without_changing_background`). **Výhrada:** kroky 1 a 2 i detektory kroku 3 (`2ef75f8`) vznikly a ladily se se všemi existujícími rodinami. Rozdělení proto slouží jen dalšímu ladění, ne jako slepý test. Skutečně slepý test jsou držené seedy 20261201 a 20261301 a testovací část kotvy.

**Rozdělení kotvy** (`src/eval/behavior_anchor.rs`, `docs/diplomka/eval/anchor-split.txt`): po scénářích, ne po tocích (toky scénáře jsou závislé). Rodiny botnetů s více scénáři (Neris, Rbot, Virut) mají scénář v obou částech, jednorázové se střídají. V IoT-23 mají obě části honeypot, Mirai a Torii.
- vývojová: CTU-13 42, 44, 46, 47, 49, 52; IoT-23 Honeypot-4-1, Malware-3-1, 20-1, 34-1, 42-1,
- testovací, zamčená: CTU-13 43, 45, 48, 50, 51, 53, 54; IoT-23 Honeypot-5-1, Honeypot-7-1-Somfy-01, Malware-8-1, 21-1, 44-1. SHA-256 seznamu `15b0127a…6d8fd7` je v kódu i v souboru. `scenarios(Part::Test, false)` vrací chybu, test hlídá shodu se souborem a to, že každý scénář v `labs/datasets` je v právě jedné části. Stávající kotva soak nohy (`eval::anchor`) teď prochází jen vývojovou část.

**Behaviorální detektory na označených tocích** (vývojová část, úroveň hostu uvnitř rozsahu, 30min okna, výchozí prahy; `cargo test --release --lib behavior_anchor_dev -- --ignored --nocapture`):

| data | škodliví hosté s nálezem | neškodní hosté s nálezem | poznámka |
|---|---|---|---|
| CTU-13 (6 scénářů) | 0 / 8 | 2 / 92 (`beacon_periodic`, Botnet-44) | vyřezy pokrývají 1 až 6 oken; beacon potřebuje historii, vrstva tu skoro nemá na čem pracovat |
| IoT-23 (5 záznamů) | 4 / 5 (`beacon_periodic` u všech čtyř, `interactive_session` 3×, `egress_volume_anomaly` 1×) | 1 / 4 (Honeypot-4-1: hodinová periodicita a relace) | malware 3-1 má dva škodlivé hosty, nález má jeden |

Čtení: na IoT-23 vrstva najde 4 z 5 infikovaných zařízení, ale neškodný honeypot s hodinovou pravidelnou komunikací označí taky, což je přesně třída falešných poplachů z bodu 2. Na CTU-13 vyřezech se nedá nic tvrdit, protože jsou kratší než doba, za kterou detektor periodicity posbírá řadu. Vzorky jsou malé (5 a 8 škodlivých hostů), intervaly spolehlivosti tu nemají smysl uvádět jinak než jako rozsah 0 až 100 %.

## 5) A/B na ladicích seedech

Plné tabulky: `reports/ab-s2-s3.md` (hlavní srovnání), `ab-legacy-s3.md`, `ab-legacy-s2.md`, `ab-s3-no<X>.md` (ablace, A = bez části, B = `s3`). 0 panik a 0 porušených invariantů ve všech ramenech.

### A. Krok 2 proti kroku 3 (`s2` → `s3`, 120 sítí)

| metrika na síť-den | `s2` | `s3` | změna (95% CI) |
|---|---:|---:|---|
| zobrazené položky | 63,8 | 69,9 | +9,6 % (+7,7 až +12,1) |
| zobrazené falešné poplachy | 14,1 | 15,8 | +12,3 % (+9,3 až +16,8) |
| odlišné FP stavy | 12,4 | 14,4 | +15,8 % (+12,0 až +21,7) |
| čeká na člověka, FP stavy | 10,4 | 11,5 | +10,4 % (+7,1 až +15,5) |
| automaticky vyřešené stavy | 0,6 | 0,7 | +19,0 % (+4,4 až +33,4) |
| plány a případy žebříku | 57,9 | 64,1 | mimo rozpočet 2,9 % → 2,6 % |

Kontrafaktuální zobrazená detekce po rodinách (rodiny ze zadání a ty, které se změnily; všechny ostatní beze změny):

| rodina | n | legacy | `s2` | `s3` | `s3` − `s2` (95% CI) | `s3` − legacy (95% CI) |
|---|---:|---:|---:|---:|---|---|
| c2_beacon | 215 | 2,8 % | 2,3 % | 92,6 % | +90,2 (+84,5 až +95,1) | +89,8 (+84,4 až +94,9) |
| exfiltration | 103 | 2,9 % | 0,0 % | 90,3 % | +90,3 (+82,8 až +97,1) | +87,4 (+78,7 až +95,5) |
| cryptomining | 89 | 2,2 % | 2,2 % | 91,0 % | +88,8 (+81,5 až +95,8) | +88,8 (+80,6 až +95,5) |
| fleet_beacon | 44 | 50,0 % | 56,8 % | 75,0 % | +18,2 (+7,4 až +31,2) | +25,0 (+7,3 až +41,9) |
| apt_chain | 70 | 92,9 % | 94,3 % | 97,1 % | +2,9 (0 až +9,4) | +4,3 (0 až +9,5) |
| insider_hoarding | 60 | 96,7 % | 95,0 % | 96,7 % | +1,7 (0 až +5,6) | 0 |
| lateral_movement | 190 | 71,1 % | 75,3 % | 76,3 % | +1,1 (0 až +3,0) | +5,3 (−3,1 až +12,4) |
| dns_tunnel | 125 | 29,6 % | 96,8 % | 96,8 % | 0 | +67,2 (+57,1 až +76,7) |
| rogue_device | 73 | 9,6 % | 94,5 % | 94,5 % | 0 | +84,9 (+76,6 až +93,1) |
| exploit_attempt | 278 | 18,3 % | 51,4 % | 51,4 % | 0 | +33,1 (+24,9 až +40,7) |

Proti legacy nemá `s3` žádnou rodinu horší (bodově nejmenší rozdíl 0 p. b.; dolní mez CI nejhůř −3,1 u lateral_movement). Proti `s2` žádná rodina neklesla ani o 0,1 p. b.

### B. Ablace: co přináší která část (A = `s3` bez části, B = `s3`)

| bez části | zobrazené FP / síť-den | změna FP (95% CI) | rodiny, které část nese (p. b., 95% CI) | automaticky vyřešené stavy | zavřeno omylem (C1) |
|---|---:|---|---|---|---|
| `beacon` | 15,0 → 15,8 | +5,3 % (+4,0 až +7,2) | c2_beacon +69,3 (+61,9 až +76,9), fleet_beacon +2,3 | −2,7 % (−13,0 až +6,2) | 0,44 → 0,50 % |
| `interactive` | 15,8 → 15,8 | 0,0 % (−0,1 až +0,2) | cryptomining +15,7 (+9,3 až +22,7) | +9,1 % (−6,0 až +25,4) | 0,66 → 0,50 % |
| `graph` | 15,3 → 15,8 | +3,5 % (+1,9 až +5,9) | fleet_beacon +6,8 (0 až +15,4), apt_chain +1,4, lateral +1,1 (0 až +3,0) | +8,5 % (−2,5 až +17,4) | 0,67 → 0,50 % |
| `profile` | 15,9 → 15,8 | −0,1 % (−0,3 až 0) | žádná (není detektor) | **+22,0 % (+10,4 až +34,9)** | 0,54 → 0,50 % |
| `egress` (vypne i beacon a interactive) | 14,6 → 15,8 | +8,4 % (+6,5 až +11,2) | exfiltration +90,3, c2_beacon +87,4, cryptomining +84,3, fleet_beacon +6,8 | +2,7 % (−15,6 až +15,6) | 0,61 → 0,50 % |

Čtení:
- **`beacon_periodic` je nejdražší část** (+0,8 FP na síť-den), ale bez něj c2_beacon spadne na 23,3 %. Zbytek c2 drží odchozí IDS alert a profil.
- **`interactive`** (`interactive_session`, `long_lived_tunnel`) je skoro zdarma (FP beze změny). U cryptominingu je `long_lived_tunnel` nejčastější typ (89 % útoků), ale bez něj detekci z větší části převezme `beacon_periodic` (65 %) a odchozí IDS alert (25 %), takže čistý přínos je +15,7 p. b.
- **`graph` (`pivot_chain`)** přidává +3,5 % FP a jen malý zisk recallu (fleet_beacon +6,8 s dolní mezí 0, lateral +1,1). `pivot_chain` se objeví u 19 % laterálních útoků, ale skoro vždy spolu s `multi_target_pattern` z kroku 2 (73 %), takže nový útok navíc zachytí zřídka. **Přínos grafu je na hraně a do dalšího kroku je to první kandidát na přísnější práh nebo vypnutí.**
- **`profile` nedetekuje, ale jako jediný přidává automatická rozhodnutí** (+22 % vyřešených stavů) a chybovost uzavírání nezvyšuje. Rozhodnutí z profilu: 1 913 kontrol s výsledkem „neškodné“ proti 2 634 „podezřelé“ (nový cíl zralého profilu). Vyvráceno přesto bylo jen 1 behaviorální `beacon_periodic` a 19 `pivot_chain`, protože vysoký dopad a zásada „nezjištěno ≠ neškodné“ drží většinu případů u člověka.

### C. Sjednocené „zavřeno omylem“

**Definice (C1):** podíl automatických uzavření, u nichž uzavřený nález kontrafaktuálně způsobil útok. Uzavření = buď automatické vyřešení kontextem v cyklu, nebo vyvrácení žebříkem. „Způsobil útok“ = nález v tomtéž cyklu chybí ve světě stejné sítě bez útoků. Jednotka je uzavírací událost, jmenovatel jsou všechny události obou mechanismů. Interval je Wilsonův 95%.

**Proč:** kontrafaktuál je intervenční definice příčiny (stejný svět bez útoku), na rozdíl od „široké“ atribuce (nález jen zmiňuje IP útoku v okně) a „příčinné“ (útok v cyklu posílal toky na cíl nálezu). Ty obě počítají i nálezy, které by bez útoku vznikly stejně (u kontextu 12,3 % proti 0,0 % kontrafaktuálně). Kontrafaktuál bez všech útoků se shoduje s leave-one-out v 98 až 99 % (krok 2, A1), takže je to přesná a ověřená náhrada. Jedna definice pro oba mechanismy navíc umožní srovnat kontext a žebřík na stejné škále.

| rameno | uzavření | omylem | podíl (95% CI) | kontext | žebřík |
|---|---:|---:|---|---:|---:|
| `s2` | 2 112 | 8 | 0,38 % (0,19 až 0,75) | 0/537 | 8/1 575 |
| `s3` | 2 609 | 13 | 0,50 % (0,29 až 0,85) | 0/535 | 13/2 074 |

Omylná vyvrácení v `s3` jsou hlavně `packet_rate_spike` u ransomwaru (6) a `inductive_volume_anomaly` u ransomwaru (3), ne nálezy vrstvy. Pro srovnání stará příčinná definice: kontext 3/535 = 0,56 %, žebřík 23/2 074 = 1,11 %.

### D. Falešné poplachy na neškodných protějšcích pravidelného provozu

Šum 1× je z A/B seedu 20261102 (40 sítí, s kontrafaktuálem), 10× ze samostatných běhů stejného seedu (40 sítí, bez kontrafaktuálu; zobrazení a FP na něm nezávisí). 50× je kvůli výpočetní ceně jen na prvních 16 sítích, proto mají 1× a 10× pro srovnání i řádek se stejnými 16 sítěmi (jsou mezi nimi tři velké sítě, takže čísla na síť-den jsou vyšší než u 40 sítí). FP na vzorech = nepřipsaný nález, jehož host a protistrana tvoří dvojici neškodného vzoru v tomto cyklu (`reports/noise-fp.md`).

| šum | sítí | toky vzorů / síť-den | FP na vzorech zobrazené, `s2` → `s3` | zobrazené FP celkem, `s2` → `s3` | největší zobrazené v `s3` (vzor\|typ, na síť-den) |
|---|---:|---:|---|---|---|
| 1× | 40 | 108 180 | 3,7 → 4,8 | 9,6 → 11,7 | ntp_sync\|unexpected_traffic 1,1, monitoring_poll\|source_volume_outlier 1,0 (oba z kroku 2) |
| 10× | 40 | 997 685 | 11,2 → 20,3 | 18,9 → 29,9 | ntp_sync\|unexpected_traffic 4,9 (krok 2), cdn_streaming\|egress_volume_anomaly 2,9, ntp_sync\|beacon_periodic 1,8 |
| 1× | 16 | 251 083 | 6,4 → 8,7 | 18,4 → 22,9 | monitoring_poll (krok 2), cdn_streaming\|egress_volume_anomaly 0,8 |
| 10× | 16 | 2 128 580 | 14,1 → 34,1 | 30,0 → 54,7 | cdn_streaming\|egress_volume_anomaly 7,4, ntp_sync\|beacon_periodic 3,7 |
| 50× | 16 | 6 558 158 | 10,8 → **96,7** | 37,6 → **135,2** | cdn_streaming\|egress_volume_anomaly 25,3, ntp_sync\|beacon_periodic 18,7, script_polling\|beacon_periodic 16,0, vpn_keepalive\|beacon_periodic 10,0 |

Čtení:
- **Při 1× vrstva přidá na vzorech jen ~1 zobrazený FP na síť-den.** Detektory kroku 2 dávají na stejných vzorech víc (NTP klientů na bránu bez inventarizované služby a monitoring jako `source_volume_outlier`).
- **Neúspěch: vrstva se šumem neškáluje.** Krok 2 drží zobrazené FP na vzorech při 50× zhruba na úrovni 10× (10,8 proti 14,1 na 16 sítích), protože jeho objemové baseline se pravidelnému provozu přizpůsobí. U kroku 3 rostou FP na vzorech zhruba lineárně s počtem instancí (8,7 → 34,1 → 96,7), protože každá nová dvojice zdroj-cíl je pro `beacon_periodic` a profil nová. Ochrany beaconu přes rozšířenost cíle (flotila) zaberou jen u společného cíle (agent, aktualizace), ne u NTP poolu, skriptu, VPN protějšku ani u streamování, kde má každá instance vlastní cíl.
- Nejhorší jednotlivý zdroj je `egress_volume_anomaly` na `cdn_streaming`. Detektor počítá jen nahrané bajty (`orig_bytes`), takže ho nespouští stahování videa, ale nejspíš videohovory přes TURN: jsou symetrické a hodinový hovor nahraje stovky MB až jednotky GB, což je pro host bez historie skok. Jako neškodný důkaz chybí znalost konferenčních služeb (reputace cíle, port 3478). Tohle je první kandidát na opravu v dalším kroku.
- Tyto parametry detektorů jsem v tomto kroku záměrně neladil, protože A/B měří stav detektorů z `2ef75f8`. Jinak by se ladilo na stejných vzorech, na kterých se měří.

### E. Čas cyklu a paměť

Na směsi sítí (120 sítí, 12 vláken, s kontrafaktuálem) je medián p99 cyklu `s2` 189 ms a `s3` 158 ms, maximum p99 6,5 s a 2,5 s. Ramena ale neběžela ve stejné zátěži stroje (během `s2` běžely testy), takže rozdíl časů mezi rameny není měřením kroku 3. Spolehlivé srovnání je XXXL v bodě 3 (stejná zátěž): krok 3 přidá 8 až 10 % času sítě a do 0,2 s na cyklus. CPU čas sítí legacy 1 093 min proti `s3` 250 min.

### Neúspěchy a co zůstává

- **FP +12,3 % proti kroku 2.** Recall odchozích rodin to vyvažuje, ale cíl „méně položek“ krok 3 nesplnil. Největší podíl má `beacon_periodic` (0,8) a `pivot_chain` (0,5).
- **Graf spojení má na hraně přínos** (bod B).
- **Přesnost potvrzení žebříku klesla z 96,5 % na 91,9 %.** Nové podezřelé důkazy (`profile:malicious` = nový cíl zralého profilu, pivot přes nálezy vrstvy) potvrzují i neškodné případy. Učení LR to mělo časem stáhnout, ale v epizodách délky 1 až 60 dní se to nestihne.
- **XXXL: jedna ze tří sítí má p99 cyklu 12 s** (bod 3), příčina mimo vrstvu kroku 3 zůstává nenalezená.
- **Kotva CTU-13** je pro detektory s historií nepoužitelná (vyřezy 1 až 6 oken), IoT-23 má malé vzorky. Testovací část se nespouštěla.
- **FP vrstvy při 10× a 50× šumu neškodných vzorů rostou s jeho objemem** (bod D). Hlavní je `egress_volume_anomaly` na videohovorech přes TURN (symetrický velký upload) a `beacon_periodic` na NTP, cronu a VPN s vlastním cílem.
- **Automatické vyřešení zůstává pod 1 % stavů.**
- Výchozí stav: krok 3 je ve `V3Features::recommended()` zapnutý, `engine.mode` zůstává `legacy`. O nasazení grafu rozhodne další krok.

## Testy a kvalita

- Nové testy:
  - zapojení: `behavior_layer_runs_in_episode_and_step2_has_none`, integrační `v3_behavior_layer_reports_outbound_ids_alert_and_persists_state`,
  - generátor: `regular_benign_noise_only_adds_flows`, `noise_zero_plans_nothing_and_counts_scale_with_noise`, `periodic_patterns_keep_phase_across_cycles`, `every_kind_has_a_documented_source`, `parameters_do_not_reference_detector_thresholds`, `regular_benign_noise_reaches_episode_and_fp_is_attributed_to_pattern`,
  - XXXL: rozšířený `archetype_mix_covers_all_kinds_sizes_and_roles` (třída jen vynucením, podsítě se neopakují, všechna zařízení v rozsahu),
  - rodiny: `family_sets_partition_existing_families`, `family_set_filters_attacks_without_changing_background`,
  - kotva: `split_is_disjoint_locked_and_matches_committed_list`, `periodic_inside_host_is_flagged_and_labels_stay_out_of_detection`, ruční `behavior_anchor_dev`.
- `cargo test --lib`: 459 testů prochází, 28 ignorovaných. Neprochází jen 6 známých výjimek: 5× `broker::*` (Redis) a `identity_lab` (Docker). Časování lease v `platform` tentokrát prošlo.
- Integrační testy procházejí kromě známých `broker_two_process` (Redis) a `e2e::autopilot_vytvori_vice_cyklu_a_automation_report` (httpx). `engine_v3` 2/2, golden snapshot zelený.
- `cargo clippy --all-targets`: lib 85, lib test 93, bin 3, e2e 1. To je stejně jako na `HEAD~2` před krokem 3 (`6035d0b`); nová varování v kódu kroku 3 jsou opravená.
- `cargo fmt` čisté.

## Studie tvrdily chybně (nebo neověřeně)

1. **01-analyza, A10/R2 a 00-zaver** tvrdily, že exfiltrace, C2 a cryptomining jsou slepé, protože parsery zahazují toky s cílem mimo rozsah. **Potvrzeno přímo:** jen se zapnutou viditelností ven (ablace `egress`) vzroste detekce o 84 až 90 p. b.
2. **RQ4 Z1 a Z2 (periodicita, nízká jistota)** říkají, že vysoká AUC detektorů beaconingu neznamená použitelnost při nízkém FPR. **Potvrzuje se to i tady:** na neškodných pravidelných vzorech při šumu 1× vznikne ~238 nálezů `beacon_periodic` na síť-den a v reálném neškodném provozu (CTU-13, IoT-23) pravidelné dvojice jsou. Použitelné je to jen díky paměti nálezů a žebříku (zobrazí se ~0,8 na síť-den), ne díky samotné periodicitě.
3. **RQ4 Z10 (nová hrana je rys, ne poplach)** se potvrzuje i pro řetěz nových hran: `pivot_chain` dává +3,5 % FP a recall skoro nepřidá.
4. **RQ5-053 (deterministický allowlist jako neškodný důkaz)** se v simulaci potvrzuje pro jinou úlohu (toky, ne procesy): profil hostu zvýší automaticky vyřešené stavy o 22 % a chybovost uzavírání nezvýší. Je to ale jen simulace. Na reálných datech se to ověřit nedalo, protože vyřezy kotvy jsou kratší než doba zrání profilu (3 dny).
5. **Krok 2 (`impl-krok2.md`) uváděl** „vyvráceno omylem příčinně 2,33 %“ jako hraniční. Sjednocená kontrafaktuální definice dává pro stav po kroku 2 0,38 % (0,19 až 0,75). Příčinná definice nadhodnocuje, protože počítá i nálezy, které by vznikly i bez útoku (u kontextu 12,3 % široce proti 0 % kontrafaktuálně).
6. **Neověřeno v krocích 1 a 2:** kotva soak nohy procházela všechny scénáře CTU-13/IoT-23 a žádná testovací část neexistovala. Ladění sice běželo s `--no-legs`, takže kotva k ladění reálně použitá nebyla, ale zamčená část vzniká až v tomto kroku.
7. **Neověřeno (RQ4 Z13, velmi nízká jistota):** pro interaktivní relace ze síťových toků studie neměla referenci. Tady `interactive` nese +15,7 p. b. u cryptominingu bez nárůstu FP, ale jen na simulátoru, jehož útoky autor zná. Reálné potvrzení chybí.
