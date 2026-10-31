# Studie 01: audit korelačního a rozhodovacího jádra, zdroje šumu a návrh engine v2

Stav kódu: pracovní strom `diplomka-cyber` k 31. 10. 2026 (bez změn zdrojového kódu). Data: soak v1 (dokončený), soak v2 (průběžný, 538 sítí, 3,25 h běhu; čísla se ještě změní).

## Shrnutí

1. Šum vzniká hlavně ve dvou funkcích: `inductive_outlier_events` (`src/passive/anomaly.rs:334-398`) a `packet_rate_spike` (`anomaly.rs:249`). Ani jedna nemá paměť, baseline ani sezónnost. První porovnává služby mezi sebou v jednom cyklu, druhá bere maximum podílu paketů a délky toku přes všechny toky. Obě proto hlásí vytížené služby, ne anomálie, a jejich počet roste zhruba lineárně s velikostí sítě (S 68,8 → XL 4 638 FP/síť-den při 15 → 855 zařízeních, sklon v log-log souřadnicích ≈ 1,0; `status.md` v2).
2. Korelace (`src/correlation.rs`) nic nekoreluje, jen mapuje událost na inventář přes `dst_ip+port` a ukládá `time_window_s`, které se nikde nepoužije. Neexistuje entita útočníka, časová posloupnost ani graf. Zdroj toku (`src_ip`) se do nálezu nedostane vůbec (`findings.rs:903-938`, `model.rs:470-481`).
3. Tři strukturální chyby úplně vypínají celé rodiny útoků: (a) filtr „cíl v scope“ v parserech Zeek i Suricata zahodí odchozí provoz (exfiltrace má v produkci 0 % zdrojového pořadí, alerty C2 se zahodí), (b) pro `suricata_alert` neexistuje pravidlo nálezu, takže exploity mají správný typ 0 %, (c) source-centric detektor `score_source_hosts` existuje, ale v produkci běží jen jako diagnostika.
4. Nálezy nemají čas ani perzistenci (`finding_id` bez času, `findings.rs:815-826`). Každý cyklus se tentýž stav vydá znovu a soak tak měří nálezy krát cykly, ne incidenty.
5. Ověřování: z 74,1 M plánů (v1) je 68 % mimo rozpočet, ve v2 dokonce 91 % (36,3 M z 40,0 M). Hlavní příčiny: plán vzniká pro každý nález v každém cyklu (≈ 50 plánů na cyklus ve v1, ≈ 181 ve v2), pro behaviorální typy existuje jen no-op `passive_extended_observation`, který spotřebovává rozpočet 10 kontrol, a pořadí určuje abeceda `finding_id`, ne EVOI.
6. Pravděpodobnost hypotézy se počítá jen na úrovni typu nálezu (`case_memory.rs:209-253`), nezávisí na síle důkazu, hostu ani kontextu. Behaviorální typy se z ověření neučí vůbec (`case_memory.rs:547-592`). Výborný Brier (0,0107) táhnou statické expozice: 81 % predikcí spadá do koše [0,9; 1,0).
7. Měřicí harness sám zkresluje: IP adresy přiřazuje podle podřetězce (`soak/episode.rs:163-174`, „10.0.0.1“ se najde v „10.0.0.15“), u událostí s časovým oknem připíše každý šum v okně dané události (`episode.rs:710-724`). Sensor crash přitom nevytváří žádná data (`traffic.rs:2370-2372`). Hodnoty 93 až 97 % FP u `sensor_crash`/`log_corruption`/`collector_replay` jsou proto z velké části artefakt atribuce.
8. Návrh engine v2: ingest se správným směrem, entita, příznaky, sezónní baseline (úroveň entity × tvar role), detektory produkující slabé signály s LLR, kontextová brána, deduplikace, akumulátor rizika na entitách s kill-chain sekvencí, eskalační žebřík ověřování s EVOI/SPRT a pivotováním, podmíněná Case Memory s tabulkami LR.
9. Prvních pět změn je malých (dny práce) a podle odhadu odstraní přes 90 % dnešních FP typu `packet_rate_spike` a nálezů opakovaných v cyklech. Také odblokují exploit a egress rodiny. Velké změny (baseline, RBA, žebřík) dávají smysl až po nich.
10. Každý odhad efektu v této studii je **odhad**, pokud není uveden zdroj. Ověřit se má párovým A/B soakem na stejných seedech (generátor je deterministický, `soak verify` 30/30). Přesný postup je v kapitole „Plán změn s měřením“.

## Metodika a zdroje dat

- Ručně jsem přečetl kód: `src/correlation.rs`, `src/correlation_v2.rs`, `src/passive/{anomaly,detector,thresholds,zeek,suricata,mod}.rs`, `src/fusion.rs`, `src/findings.rs`, `src/finding_kinds.rs`, `src/decision.rs` (bodování a rozhodnutí), `src/triage.rs` (část), `src/hypothesis.rs`, `src/verification_planner.rs`, `src/verification_exec.rs`, `src/case_memory.rs` (odhad a mapování výsledků), `src/case_history.rs` (hlavička), `src/identity.rs`, `src/report.rs` (okno, `attach_events`, `score_services`), `src/intel.rs` (`collect_intel`), `src/ops.rs` (`propose`), `src/model.rs` (struktury), `src/pipeline/mod.rs` (celý tok), `src/soak/episode.rs` (celý tok skórování), `src/soak/traffic.rs` (základní provoz, rodiny, provozní události, degradace), `src/soak/netmodel.rs` (inventář, churn, sampling), `src/soak/rng.rs`.
- Data: `docs/diplomka/eval/soak-findings.md`, `F:\bakula-soak\run80h\final-report.md` (v1: 15 664 sítí, 31 079 síť-dnů, commit `995ec76`), `F:\bakula-soak\run-v2-72h\status.md` (v2 průběžně: 538 sítí, 4 594 síť-dnů, jen čteno). Předchozí měření: `docs/diplomka/eval/source-centric-scoring-pr-auc.md`, `h4-isotonic-calibration-loso.md`, `ablation-d-multiscale.md`.
- Odvozená čísla: FP na síť-den podle typu = počet z reportu / virtuální síť-dny. Podíly počítám z reportu. Analytické odhady (například pravděpodobnost `packet_rate_spike` na benigním toku) vycházejí z parametrů generátoru v `traffic.rs` a jsou označené jako odhad.
- Nic jsem nespouštěl (žádné testy, soak ani build) a do procesů `bakula-soak-*` jsem nesahal.

### Výchozí čísla (rozpad FP na síť-den)

| typ | v1 počet | v1 / síť-den | v2 počet | v2 / síť-den |
|---|---:|---:|---:|---:|
| inductive_volume_anomaly | 4 945 921 | 159,1 | 1 871 685 | 407,4 |
| packet_rate_spike | 1 410 185 | 45,4 | 512 722 | 111,6 |
| unexpected_traffic | 4 382 | 0,14 | 2 451 868 | 533,7 |
| unmapped_passive_event | 38 | 0,001 | 240 098 | 52,3 |
| connection_timeout_burst | 109 384 | 3,5 | 89 545 | 19,5 |
| service_overload_risk | 79 744 | 2,6 | 30 480 | 6,6 |
| **celkem** | 6 549 654 | **210,7** | 5 196 398 | **1 131,1** |

Zdroj: `final-report.md` (v1), `status.md` (v2). Ve v1 to dělá 210,7 / 48 ≈ 4,4 FP nálezů na cyklus a síť.

## Nálezy auditu

Dopad: K = kritický (vypíná detekci nebo dominuje FP), V = vysoký, S = střední, N = nízký.

| id | soubor:řádek | popis | dopad | doporučení |
|---|---|---|---|---|
| A01 | `passive/anomaly.rs:25`, `:431-433`; `findings.rs:903-938`; `model.rs:470-481` | Agregace podle klíče `(dst_ip, proto, port)`. Ze zdrojů zůstane jen první viděný `representative_src_ip`, který se do `Finding.evidence` ani do jiného pole nedostane. Nález nikdy nepojmenuje útočníka. | K | Do `Finding` přidat `src_key` a `src_entities` (top-k zdroje s podíly), detektory vést i na úrovni zdroje. |
| A02 | `passive/anomaly.rs:334-398` | `inductive_volume_anomaly` = robustní z-skóre počtu toků a max pps **napříč službami v jednom běhu** (`:341-350`), plus absolutní `composite_signal` (`:366-369`: `count/10`, `max_pps/5000`, timeout×4, práh 2,4). Chybí historie, sezónnost i normalizace na roli. Vytížené služby (DNS, web, file) jsou outlier v každém cyklu. | K (75 % FP ve v1) | Nahradit odchylkou od vlastní sezónní baseline entity (kap. Návrh, b). |
| A03 | `passive/anomaly.rs:525-530` | Při MAD ≤ 1e-4 vrací z-skóre 0. V malých homogenních sítích se z-složka tiše vypne a rozhoduje jen absolutní `composite_signal`. | S | Při malém MAD použít mezeru vůči historické baseline. Nikdy nevracet „0 = normální“ jen kvůli chybějícímu rozptylu. |
| A04 | `passive/anomaly.rs:249`, `:444-466` | `packet_rate_spike` se spouští, když maximum přes toky `pkts/duration` ≥ 2 800 nebo `bytes·8/duration` ≥ 40 M. Duration má dolní mez 1 ms (`:446`). Jde o statistiku extrémů: s rostoucím počtem toků N roste šance na jeden krátký tok s absurdní rychlostí. | K (22 % FP ve v1) | Agregovaná rychlost služby (Σpkts/okno) a p95 jen přes toky s ≥ 10 pakety a ≥ 1 s, porovnané s baseline. |
| A05 | `passive/thresholds.rs:8-9` vs `anomaly.rs:249,262,304`, `correlation_v2.rs:269,279,312` | Modul tvrdí, že prahy jsou na jednom místě, ale literály 2 800 / 40 M / 4 800 / 90 M / 4 500 jsou opsané zvlášť. Žádný práh není kalibrovaný. | S | Prahy do konfigurace detektoru s verzí a kalibrovat je soakem (kap. f). |
| A06 | `passive/anomaly.rs:482-496` | `is_timeout_like`: `history` se převede na malá písmena, takže `R`/`T` (iniciátor) i `r`/`t` (odpovídač) se počítají jako timeout. Běžný Zeek tok ukončený RST tak vypadá jako timeout. Soak `history` negeneruje (`traffic.rs:432`), takže tento zdroj FP **v simulaci vůbec není vidět**. | V (reálná data) | Rozlišit velikost písmen, `RSTO`/`RSTR` po přenosu dat nebrat jako timeout, timeout definovat jako `S0`/`REJ`/`SH` bez dat. |
| A07 | `passive/anomaly.rs:220` | `connection_timeout_burst` (≥ 2 a ≥ 22 %) nerozliší „server je dole“ (mnoho klientů, jeden cíl) od „sken“ (jeden zdroj, mnoho cílů). | V | Klasifikovat podle rozložení zdrojů. Výpadek serveru převést na stav dostupnosti, ne na bezpečnostní signál. |
| A08 | `passive/anomaly.rs:26-34`, `:174-206` | `unexpected_traffic` = cíl není v aktuálním nmap seznamu otevřených služeb a má ≥ 3 toky. Ignoruje stav spojení (S0 je pokus, SF s odpovědí je skutečná služba), stáří inventáře i změny IP. | K (v2: 47 % FP) | Rozdělit na `unknown_open_service` (SF s daty) a pokusy (přičíst zdroji). Brát ohled na stáří inventáře a změny IP. |
| A09 | `passive/mod.rs:58-66`; `soak/episode.rs:405-413` | `known_services` = jen poslední nmap. Po restartu enginu je inventář prázdný, dokud neproběhne další sken. Všechny události pak skončí jako `unmapped`. | V (v2) | Perzistentní inventář s časem posledního ověření a stav „cold inventory“, který potlačí nálezy závislé na inventáři. |
| A10 | `passive/zeek.rs:46-48, 102-106, 173-178`; `passive/suricata.rs:69-73`; `soak/episode.rs:487-492` | Toky i alerty s cílem mimo scope se zahazují. Odchozí provoz (C2, exfiltrace, mining, beacony flotily) je pro engine neviditelný. Soak tento filtr věrně replikuje. | K | Ponechat tok, když `src ∈ scope ∨ dst ∈ scope`, a označit směr. Pravidla závislá na inventáři pouštět jen na interní cíle. |
| A11 | `passive/suricata.rs:111-124` | `classify_signature` se řídí klíčovými slovy a portem. Jakýkoli alert na port 80 (DDoS, SQLi, exploit) se stane `insecure_auth_possible`, ostatní spadnou do `suricata_alert`. Kategorie alertu (`alert.category`) ani prefix signatury (ET EXPLOIT/SCAN/MALWARE/DOS) se nepoužijí. | K | Mapovat podle kategorie a prefixu na technické typy a ATT&CK. Port 80 jako klasifikátor zrušit. |
| A12 | `findings.rs:28-57` | `SERVICE_RULES` nemají pravidlo pro `suricata_alert`, `zeek_notice` ani `multi_target_pattern`. Alert připojený ke službě jen zvedne skóre služby (`report.rs:446-454`) a jako nález zmizí. Proto mají exploity správný typ 0,0 % (v1 i v2) přesto, že IDS vidělo 2 301 z 5 061 útoků. | K | Přidat pravidlo `ids_alert` (mapované typy z A11) na službu, host i unmapped. |
| A13 | `findings.rs:102-121` | Pro každou nespárovanou událost vznikne jeden nález (`finding_id` obsahuje `event_id`, `:105`). Nic se neagreguje. | V (v2: 52/síť-den) | Agregovat podle `(dst_ip, dst_port, typ, den)` a počítat výskyty. |
| A14 | `findings.rs:815-826`; `model.rs:470-481` | `finding_id` nemá čas a `Finding` nemá `first_seen`/`last_seen`/`occurrences`. Deduplikace proběhne jen v rámci běhu, takže každý cyklus tentýž stav vydá znovu. | K (metrika i operátor) | Perzistentní stav nálezu s TTL a znovuvydání jen při změně. |
| A15 | `findings.rs:661`; `decision.rs:564-624`; `triage.rs:87-126` | Inductive má vždy `Severity::High` (severity události se ignoruje) a v `rank_finding` dostane 0,62+0,10+0,14+0,10+0,05 ≈ 1,0 (ořez). Nejhlučnější detektor má tak nejvyšší prioritu. Triage pak pro libovolný traffic-like nález (i `unexpected_traffic` Low) vydá akci High „agresivnější ochrana“. | V | Prioritu odvozovat z kalibrované pravděpodobnosti incidentu, ne z typu. |
| A16 | `correlation.rs:3-56` | „Korelace“ je jen lookup cíle v inventáři (`ip+port` → High, `ip` → Low, jinak `unmapped`). `time_window_s` se uloží (`:30, :38, :46`) a nikde nepoužije. Chyba na `:17`: tcp událost se spáruje s udp službou na stejném portu. Složitost O(E·H·S). | V | Nahradit entitním a časovým korelátorem (kap. Návrh). Lookup ponechat jen jako enrichment přes `HashMap`. |
| A17 | `report.rs:266-272`, `:330-400` | Pasivní okno je pevně ±1 h a `time_window_s = 3600`. Události bez služby spadnou do syntetické služby `host-only` (port 0), takže se míchá vrstva hostu a služby. Vyhledávání je lineární (`:338-342`). | S | Index `HashMap<service_id, idx>`, entita hostu jako samostatný objekt. |
| A18 | `fusion.rs:139-185`; `anomaly.rs:189, 228, 257, 286, 313, 376` | Fúze slučuje jen eventy různých senzorů se stejným `community_id`. Anomální eventy mají `src_port: None`, takže se nikdy nefúzují. Jedna příčina (jeden agregát služby) přitom vyprodukuje až 4 nálezy (`timeout`, `rate`, `overload`, `inductive`), které se počítají jako nezávislé. | V | Deduplikace mezi detektory podle společné příčiny (stejný agregát a okno) se slevou na závislost (kap. e). |
| A19 | `pipeline/mod.rs:862-870`; `passive/detector.rs:35-50`; `correlation_v2.rs:11-15, 347-422` | Produkce používá jen ablaci A. Okna a vazby podle zdroje (`multi_target_pattern`) existují jen v eval. Ablace B/C/D navíc vynechávají inductive. | S | Po zavedení signálů v2 tyto cesty sjednotit, ne udržovat čtyři. |
| A20 | `hypothesis.rs:107-162, 178-210, 214-223` | Platí 1 nález = 1 hypotéza. `contradicting_evidence` zůstává vždy prázdné (`:156`), `potential_impact` = mapa severity (`:146-150`), `probability` = bázová frekvence typu z paměti. Síla důkazu (skóre, počet signálů) se do pravděpodobnosti nepromítne. | K (rozhodování) | Hypotéza = incident (skupina signálů). Pravděpodobnost = prior(kontext) × Π LR. |
| A21 | `case_memory.rs:209-253` | `estimate` filtruje jen podle `finding_type`. `asset_key` se uloží, ale nepoužije. Chybí časový rozpad. Každé volání projde všechny záznamy (O(R)) a volá se pro každý nález v každém cyklu. | V (kvalita i výkon) | Podmíněný odhad s hierarchickým backoffem (typ → typ×role → typ×role×skóre), inkrementální čítače, poločas rozpadu. |
| A22 | `case_memory.rs:511-592` | Z výsledků ověření se učí jen expoziční a CVE typy. Behaviorální typy (97 % nálezů) se učí výhradně z operátorských verdiktů (v soaku z 10% vzorku, `episode.rs:796-828`). | K (učení) | Tabulky LR pro behaviorální kontroly (kap. Žebřík). |
| A23 | `verification_planner.rs:53-62, 116-125, 139-187` | Utilita = `gain × impact − náklady` a neobsahuje aktuální pravděpodobnost (EVOI má být maximální u p ≈ 0,5, ne u severity High). Pro behaviorální typy existuje jen `passive_extended_observation` se ziskem 0,2, který nic nedělá (`verification_exec.rs:79-81`). | K | EVOI z p a LR výsledků, skutečné behaviorální kontroly. |
| A24 | `verification_exec.rs:170-255`; `pipeline/mod.rs:1374-1381`; `soak/episode.rs:553-557` | Plány se zpracují v pořadí nálezů seřazených podle `finding_id` (prakticky abecedně podle typu), bez globálního řazení podle EVOI. No-op kontrola se počítá do `executed_total` (`:248`) a spotřebuje rozpočet 10/běh (`:38-46`). Cache platí jen v rámci volání (`:181`), takže se tatáž kontrola opakuje v každém cyklu. | K (68 %/91 % mimo rozpočet) | Globální fronta podle EVOI/nákladu, oddělené rozpočty pro pasivní a aktivní kontroly, perzistentní idempotence s TTL. |
| A25 | `pipeline/mod.rs:1412-1432` | Výsledky ověření nemění nálezy ani hypotézy (posterior se nepřepočítá), ovlivní jen Case Memory pro příště. | V | Smyčka: výsledek kontroly změní posterior incidentu ještě v tomtéž běhu. |
| A26 | `identity.rs:107-116`; `soak/netmodel.rs:1045-1056` | Bez MAC je identita jen IP, takže DHCP vyrobí nový asset a přidělení IP jinému zařízení assety sloučí. Hostname je v inventáři, ale nepoužije se. Ve v2 je MAC vidět jen v podsítích `< 1 + prefixes/6`. Výsledek ve v2: falešné rozdělení 37,1 %, falešné sloučení 24,2 % (`status.md`). | V (baseline potřebuje stabilní entitu) | Vícesignálový resolver: MAC, hostname, otisk služeb, DHCP lease, ARP/SNMP z kontextových adaptérů. |
| A27 | `decision.rs:732-742` | `has_passive_evidence` hledá v evidenci podřetězce „event“/„flow“, takže platí prakticky vždy. Bonusy 0,05 až 0,16 jsou ruční a ignorují Case Memory. | S | Nahradit kalibrovanou pravděpodobností. |
| A28 | `soak/episode.rs:163-174` | Atribuce nálezu k útoku hledá IP adresu jako **podřetězec** v titulku, zdůvodnění a evidenci („10.0.0.1“ ⊂ „10.0.0.15“, oktety 100 až 250 i 1 až 19). Nafukuje to TP i benigní atribuci a snižuje vykázané FP. | V (měření) | Tokenizovat IP (regex s hranicí) nebo porovnávat strukturovaná pole. |
| A29 | `soak/episode.rs:710-724`; `traffic.rs:2370-2372, 2433-2438` | U `window_scoped` událostí (sensor_crash, log_corruption, collector_replay) se jakýkoli nepřipsaný nález v okně `[start, end+2]` přičte dané události. Sensor crash data vůbec negeneruje, takže 93 % „s FP“ je běžný šum v cyklech po obnovení. | V (měření) | Kontrafaktuál: týž seed bez události, porovnat rozdíl nálezů. |
| A30 | `soak/episode.rs:66-79`; `traffic.rs:105-200` | `expected_types` obsahují typy, které v soak cestě vzniknout nemohou: `suricata_alert` (chybí pravidlo, A12), `multi_target_pattern` a `external_flow_observed` (jen ablace C a lanes). Statické typy (`high_risk_cve_exposure`) se z `behavioral` vyřazují. Exploit má proto 0 % „správný typ“ z konstrukce. | V (měření) | Seznam typů sladit s tím, co engine umí. Zvlášť hlásit „nedosažitelné z konstrukce“. |
| A31 | `soak/episode.rs:670-731` | FP se počítá jako nález × cyklus. „Detekováno (jakýkoli nález)“ nemá kontrafaktuál: vytížená oběť (web, DNS) má inductive nález i bez útoku. | V (měření) | Přidat metriku na úrovni incidentu a „detekce nad pozadím“ (kontrafaktuál). |
| A32 | `soak/episode.rs:607` vs `pipeline/mod.rs:1405-1409` | Soak plánuje bez historie (`plan_for_hypothesis`), produkce s historií. Cesta přes historii se soakem netestuje. | N | Soak volat stejnou funkcí jako produkci. |
| A33 | `final-report.md`, kalibrace | Brier 0,0107 táhne koš [0,9; 1,0) s n = 39,4 M z 48,4 M (81 %), tedy převážně statické expozice s jistým štítkem. Kalibrace behaviorálních typů zvlášť hlášená není. Pásmo 0,1 až 0,5 je ve v1 překonfidentní (0,137 → 0,065; 0,430 → 0,211). | V (měření) | Brier, ECE a spolehlivostní diagram zvlášť pro behaviorální a statické typy. |
| A34 | `soak/traffic.rs:1018-1036` | Benigní toky: duration lognormal (medián 0,5 s, σ 1,2), bajty lognormal (σ 1,0/1,4). Těžký chvost pps je vlastnost generátoru, která přesně krmí A04. Reálný Zeek se liší (vícepaketové toky, inactivity timeouty, `history`). | S (riziko přeladění na simulátor) | Kotvit rozdělení na CTU-13/IoT-23 (rozdělení duration a pkts), prahy ladit na směsi. |
| A35 | `soak/traffic.rs:1377`, `soak/episode.rs:838, 1004`, `soak/netmodel.rs:913, 1025` | `rng.range(0, len as u64 - 1)` při `len = 0` přeteče na `u64::MAX` a následuje index mimo rozsah. Odpovídá třem panikám ve v2 („len is 0 but the index is 6619503383716057201“). Konkrétní řádek jsem neověřil. | N (harness) | Hlídat `len == 0` nebo použít `pick`/`range(0..len)`. |

## Analýza šumu po typech

### inductive_volume_anomaly (v1 159,1 / síť-den, v2 407,4)

- **Kód:** `anomaly.rs:334-398` (volá `detect_connection_anomalies`, `:44`). Agregát `ConnectionAggregate::observe` (`:426-471`).
- **Model:** pro každý klíč služby s `count ≥ 3` se spočte `score = max(z(count), z(max_pps), 4·timeout_ratio)`, kde z je robustní z-skóre (0,6745·|x−medián|/MAD) přes **všechny služby téhož běhu** (`:341-350`). Nález vznikne, když `score ≥ 3,2` **nebo** `composite = 4·timeout_ratio + min(max_pps/5000, 2) + min(count/10, 2) ≥ 2,4` (`:366-369`).
- **Proč je citlivý:**
  1. *Průřezové srovnání bez paměti:* počet toků na službu má v reálné i simulované síti těžký chvost (DNS dostane ≈ 1,2× rychlost všech klientů, `traffic.rs:1042`). Medián a MAD určí desítky tichých služeb, takže DNS, web a file server jsou outlier v **každém** cyklu.
  2. *Absolutní `composite`:* stačí `count ≥ 24` (příspěvek 2,0) a k tomu buď `max_pps ≥ 2 000`, nebo `timeout_ratio ≥ 0,1`. Podmínka tedy prakticky zní „služba má ≥ 24 toků za 30 min a aspoň jeden rychlý nebo neúspěšný tok“, což splní každá středně vytížená služba ve dne.
  3. *Bez sezónnosti:* generátor má denní i týdenní profil a svátky (`traffic.rs:351-390`). Detektor ho nezná, takže denní špička je pro něj anomálie.
  4. *Bez normalizace velikosti:* počet vytížených služeb roste s počtem zařízení, a tím i počet FP (S → XL ×67 při ×57 zařízení, `status.md`).
  5. *Žádné ztlumení perzistence:* stejná služba se hlásí 20 až 48× denně (A14).
- **Náhrada:** detektor odchylky od vlastní sezónní baseline entity (kap. Návrh, b). Skóre = robustní z vůči očekávání `úroveň_entity × tvar_role[hodina, typ dne]`, s minimálním efektivním počtem vzorků a s gatingem (anomální vzorky se do baseline neučí). Výstup je `Signal` s LLR podle kalibrace, ne nález. Průřezovou složku ponechat jen jako slabý příznak „služba výrazně vybočuje z peer group stejné role“ (stejná role, ne celá síť).

### packet_rate_spike (v1 45,4 / síť-den, v2 111,6)

- **Kód:** `anomaly.rs:249` (práh), `:444-466` (výpočet), `findings.rs:534-570` (nález, severity High při `count ≥ 5`).
- **Model:** `max_pps = max_i (pkts_i / duration_i)` přes toky klíče s `duration > 1 ms`, práh 2 800 pps nebo 40 Mbit/s.
- **Proč je citlivý:** jde o **maximum** podílu dvou těžkochvostých veličin. U benigního toku v soaku je medián pkts ≈ 12 a duration 0,5 s, tedy medián ≈ 24 pps. Na 2 800 pps je potřeba ≈ 117× medián, ln(117) ≈ 4,8 při σ(ln pps) ≈ 1,7. Vychází p ≈ 0,0025 na tok (**odhad**). Pro službu s N toky za cyklus P(spike) ≈ 1 − (1−p)^N: N = 100 → 22 %, N = 500 → 71 %, N = 1 000 → 92 % (**odhad**). Pravidlo tak měří počet toků, ne rychlost. Na reálném Zeeku vzniká stejný artefakt u krátkých toků s 2 až 3 pakety a délkou v řádu ms.
- **Náhrada:** (1) agregovaná rychlost služby `Σpkts / délka okna` a `Σbytes·8 / okno` porovnaná s baseline, (2) p95 rychlosti jen přes toky s `pkts ≥ 10 ∧ duration ≥ 1 s`, (3) signál až při současné odchylce agregátu (z ≥ 4 vůči baseline) a nárůstu počtu zdrojů nebo poměru S0 (DDoS). DDoS v soaku zůstane viditelný: emituje ≥ 500 toků za cyklus (`traffic.rs:1503`), agregát vzroste o řád.

### connection_timeout_burst (v1 3,5 / síť-den, v2 19,5)

- **Kód:** `anomaly.rs:220` (≥ 2 timeout-like a ratio ≥ 0,22), `is_timeout_like` `:482-496`, nález `findings.rs:495-531`.
- **Proč je citlivý:** (1) neřeší, kdo timeouty způsobuje. `ServiceCrash` a `PatchWindow` vypnou server a klienti dostávají `S0` (`traffic.rs:1005-1006`, `episode.rs:377-393`), což dává 91,8 % a 99,2 % těchto událostí s FP (`status.md`). (2) Na reálných datech započítá i běžná ukončení RST (A06). (3) Malé N: 2 ze 9 toků už stačí.
- **Náhrada:** rozložit podle zdrojů. Mnoho zdrojů na jeden cíl a cíl neodpovídá nikomu znamená stav `service_unavailable` (provozní, propojený s kontextem zdraví). Jeden zdroj na mnoho cílů nebo portů znamená signál `scan_attempts` u zdroje. Jeden zdroj na jeden cíl s mnoha pokusy znamená `bruteforce_attempts` (ve spojení s portem 22/3389/445). Práh přes baseline poměru S0 dané služby.

### service_overload_risk (v1 2,6 / síť-den, v2 6,6)

- **Kód:** `anomaly.rs:303-304`: `overload_votes ≥ 3 ∧ count ≥ 4` nebo `max_pps ≥ 4 500 ∧ timeout_ratio ≥ 0,15`. Hlasy se přičítají za každý timeout-like tok **nebo** tok nad 2 500 pps / 35 Mbit/s (`:468-470`).
- **Proč je citlivý:** je to v podstatě součet stejných vstupů jako u timeout burst a packet rate (stejný artefakt maxima), takže jde o závislý duplikát (A18). Nález má vždy `High` (`findings.rs:626`).
- **Náhrada:** zrušit jako samostatný nález. Ze signálů `service_unavailable` a odchylky agregované rychlosti udělat odvozený stav „přetížení“ s kauzální vazbou na nárůst počtu zdrojů (DDoS) nebo na kontext (flash crowd).

### unexpected_traffic (v1 0,14 / síť-den, v2 533,7)

- **Kód:** `anomaly.rs:26-34, 174-206`; připojení ke službě `host-only` v `report.rs:348-378`; nález `findings.rs:455-492`.
- **Model:** cíl `(dst_ip, proto, port)` není mezi otevřenými službami posledního nmapu a má ≥ 3 toky za běh.
- **Proč je citlivý (a proč skok mezi v1 a v2):** v1 má sítě do 220 zařízení s malým churnem. Ve v2 rostou zdroje nesouladu inventáře a provozu: churn DHCP 1 %/cyklus, u mobilů 4 % (`netmodel.rs:990-1038`), inventář se obnovuje jen každý 4. cyklus (`traffic.rs:1147`), zařízení vypnutá při skenu (pády, patche) v inventáři chybí, restart enginu inventář smaže (`episode.rs:405-413`). Moje **hypotéza (neověřená)** je, že většinu 2,45 M tvoří provoz na IP, které mezitím připadly jinému zařízení (zastaralý inventář), a na služby zařízení, která byla při skenu dole. Před úpravou je nutné to rozpadem změřit (doporučení v plánu, krok 1).
- **Náhrada:** (1) rozlišit stav: SF s odpovědí (`resp_bytes > 0`) = `unknown_open_service`, pokusy S0/REJ = signál zdroje, (2) stáří inventáře: cíl, jehož IP se od posledního skenu změnila nebo jehož host byl při skenu dole, dostane stav „neověřený inventář“ a místo nálezu spustí L2 kontrolu (cílený connect na port), (3) deduplikace na `(dst, port)` za den.

### unmapped_passive_event (v1 ≈ 0, v2 52,3)

- **Kód:** `correlation.rs:42-49` (`unmapped`), `findings.rs:102-121` (nález pro každou událost).
- **Proč je citlivý:** jeden nález na událost (A13) a prázdný inventář po restartu (A09). Ve v2 je 1 148 restartů a až 3 cykly bez inventáře na každý (`status.md`, `traffic.rs:1147`).
- **Náhrada:** agregace na `(dst, port, typ)` s čítačem. Ve stavu `inventory_cold` nálezy nevydávat, jen sbírat. Opakovaný provoz na neznámou interní IP je signál `unknown_device` (vstup pro rogue detekci), ne nespárovaná událost.

### Provozní události: co je skutečný šum a co artefakt měření

| událost (v2) | s FP | mechanismus v kódu | odhad podílu artefaktu |
|---|---:|---|---|
| sensor_crash | 93,0 % | v cyklech výpadku žádná data (`traffic.rs:2370`, `degrade` `:2433-2438`), přičte se šum z `end+1, end+2` (`episode.rs:710-724`) | většina (**odhad**) |
| log_corruption | 95,1 % | rozbité toky mají náhodný port (1 až 65 000) nebo chybějící pole, takže zřídka dosáhnou ≥ 3 na klíč (`traffic.rs:2389-2423`). Opět atribuce podle okna. | většina (**odhad**) |
| collector_replay | 97,3 % | 200 až 3 000 toků se starými časy na první službu cíle (`traffic.rs:2336-2368`). Detektor časy nekontroluje, takže stoupnou počty a inductive se spustí. Část je reálná. | část (**odhad**) |
| patch_window | 99,2 % | velké stahování míří ven (mimo scope, takže se zahodí), ale patchované stroje padají, klienti dostávají S0 a vzniká timeout burst. | malý, FP je reálná |
| service_crash | 91,8 % | totéž přes S0 | malý, FP je reálná |
| batch_job, backup, flash_crowd | 86,7 / 75,4 / 79,7 % | objem na serveru, inductive a packet rate | malý, FP je reálná |
| software_update, retry_storm | 0,0 % | odchozí tok mimo scope, zahozený (A10) | „správně“, ale z nesprávného důvodu: po opravě A10 se ukážou |

Důsledek: po opravě A10 (egress) se objeví nové FP z `retry_storm` (S0 bouře ven) a `software_update` (velké stahování). Engine v2 je musí ošetřit kontextem dřív, než se A10 zapne do produkce.

## Co korelace skutečně dělá

1. **Detekce** (`passive::load_and_normalize`, `passive/mod.rs:38-76`): parsery vyfiltrují cíl v scope a čas v okně ±1 h kolem běhu (`report.rs:266-272`). `LegacyAnomalyDetector` agreguje toky podle `(dst_ip, proto, port)` přes **celé okno** bez časového dělení a vydá až šest typů událostí na klíč. Suricata alerty se klasifikují klíčovými slovy (A11).
2. **Fúze** (`fusion.rs:139-185`): události různých senzorů se stejným `community_id` a rozptylem do 900 s se sloučí (max severity). Anomální události mají `src_port = None`, takže `community_id = None` a fúzí projdou beze změny. Fúze se reálně týká jen dvojic Zeek notice a Suricata nad stejným tokem.
3. **„Korelace“** (`correlation.rs:3-56`): pro každou událost lineární hledání hostu a služby se stejnou `dst_ip` a portem. Výsledek je `CorrelationInfo{method: ip+port | ip-only | unmapped}`. Nespojuje události mezi sebou, nemá okno, entitu zdroje ani kauzalitu.
4. **Připojení** (`report.rs:330-400`): události se připojí ke službě, ke kontejneru `host-only`, nebo jdou do `unmapped_events`.
5. **Nálezy** (`findings.rs:76-99`): pro každou službu se projde 16 pravidel. Každé se ptá „existuje událost typu X?“ a vydá jeden nález se zdůvodněním. Deduplikace jen podle `finding_id` v běhu.
6. **Důvěra:** `Confidence` nálezu = `CorrelationInfo.confidence` (High jen při shodě `ip+port`), u inductive výchozí Medium. Skóre rozhodnutí (`decision.rs:564-650`) = ruční součet bonusů. Pravděpodobnost (`hypothesis.rs:214-223`) = Beta posterior frekvence typu v Case Memory. **Důvěra nikde nevyjadřuje „jak pravděpodobný je útok“ v závislosti na důkazech daného případu.**
7. **Kde se zahazuje informace:**
   - odchozí toky a alerty s externím cílem: `zeek.rs:173-178`, `suricata.rs:69-73` (A10),
   - zdroj toku: `anomaly.rs:431-433` (jen první), `findings.rs:903-938` (do nálezu nejde),
   - časová struktura: agregace přes celé okno, beacon periodicita (interval mezi toky) se nikde nespočítá,
   - stav spojení u `unexpected_traffic` (A08),
   - kategorie a ID signatury u Suricaty (`suricata.rs:79-84`: `signature_id` se dostane do `rule_id`, ale klasifikace ho nepoužije),
   - mezicyklová paměť: každý běh `run_pipeline` je bezstavový kromě Case Memory, historie ověření a identity.
8. **Slabiny:** jediný klíč (cíl), žádné okno, žádná sekvence, žádný graf, žádná paměť, žádné potlačení kontextem a nezávislé počítání závislých nálezů (A18). `correlation_v2` (okna, vazba podle zdroje) existuje, ale jen jako ablace (A19).

## Návrh engine v2

### Architektura a tok dat

```
 Zeek conn/notice/http     Suricata eve        Inventář (nmap, ARP/SNMP, DHCP)     Kontext (kalendář, allowlisty,
        |                        |                         |                         zdraví senzorů a služeb)
        v                        v                         |                                   |
 [1] Ingest a normalizace: scope = src∈S ∨ dst∈S, Direction, watermark (late), kvalita řádku      |
        | FlowRecord{dir, late, quality}                    |                                   |
        v                                                   v                                   |
 [2] Entity resolver (asset_id: MAC | hostname | otisk služeb | IP+lease) <----- identity.rs ---|
        |                                                                                       |
        v                                                                                       |
 [3] Extrakce příznaků per (entita, okno 30 min): out/in toky, distinct dst, bytes out,         |
     poměr S0, agregované pps, interval mezi toky k externím cílům ...                          |
        |                                    ^                                                  |
        v                                    | update (jen negatované vzorky)                   |
 [4] BaselineStore: úroveň entity (EWMA) × sezónní tvar role[hodina × typ dne], shrinkage       |
        | očekávání + rozptyl + n_eff                                                           |
        v                                                                                       |
 [5] Detektory -> Signal{src, dst, technique(ATT&CK), score, llr, okno}                         |
     (baseline odchylky, IDS mapping, beacon, fan-out, nové zařízení, expozice z inventáře)     |
        |                                                                                       |
        v                                                                                       |
 [6] Kontextová brána: vysvětlit/potlačit (údržba, patch, známý skener/záloha, výpadek          |
     senzoru, server dole, replay) -> Signal.suppressed_by / llr *= faktor  <-------------------+
        |
        v
 [7] Dedup a sloučení: (detector, entita, technika, příčinný agregát) v TTL, sleva na závislost
        |
        v
 [8] IncidentStore (RBA): log-odds na entitu s časovým rozpadem, graf entit z toků,
     kill-chain sekvence (před/po), otevření incidentu při p >= theta_open
        | Incident{p, stage, entities, signals}
        v
 [9] Žebřík ověřování: EVOI/SPRT, rozpočty, idempotence, pivotování po grafu
        |   ^                                                   |
        |   +--- výsledek kontroly -> Bayes update -------------+
        v                                                       v
 [10] Rozhodnutí: watch / investigate / escalate / propose block (ops.rs)    Case Memory:
                                                                             podmíněné báze, tabulky LR,
                                                                             verdikty incidentů
```

### (a) Detektory jako slabé signály, incident přes entity a čas (risk-based alerting)

- **Změna v kódu:**
  - `src/model.rs`: nové struktury (všechna pole s `#[serde(default)]` kvůli kompatibilitě JSON reportů):
    ```rust
    pub enum Direction { Inbound, Outbound, Internal, External }
    pub struct EntityRef { pub asset_id: Option<String>, pub ip: String, pub role: Option<String> }
    pub struct Signal {
        pub signal_id: String, pub detector_id: String, pub detector_version: u32,
        pub technique: Option<String>,        // ATT&CK, např. "T1046", "T1071"
        pub src: Option<EntityRef>, pub dst: Option<EntityRef>, pub service_key: Option<String>,
        pub window_start: DateTime<Utc>, pub window_end: DateTime<Utc>,
        pub score: f64, pub llr: f64,          // log-likelihood ratio po kalibraci
        pub cause_key: String,                 // společná příčina (agregát+okno) pro dedup
        pub suppressed_by: Option<String>, pub evidence: Vec<String>,
    }
    pub struct Incident {
        pub incident_id: String, pub root: EntityRef, pub entities: BTreeSet<String>,
        pub signal_ids: Vec<String>, pub first_seen: DateTime<Utc>, pub last_seen: DateTime<Utc>,
        pub log_odds: f64, pub probability: f64, pub stage: KillChainStage,
        pub status: IncidentStatus, pub version: u64,
    }
    ```
  - `src/passive/detector.rs`: nový trait vedle stávajícího, aby ablace zůstaly srovnatelné:
    `fn detect_signals(&self, flows: &[FlowRecord], ctx: &DetectionContext) -> Vec<Signal>`, kde `DetectionContext { baseline: &BaselineStore, inventory: &InventoryView, calendar: &ContextCalendar, now }`.
  - nový `src/incident.rs`: `IncidentStore::ingest(&mut self, signals: &[Signal], now) -> Vec<IncidentDelta>`. Akumulace: `log_odds(e,t) = logit(prior(role)) + Σ_d min(cap_d, max_{s∈d, t_s ∈ τ} llr_s · e^{−(t−t_s)/τ})`. Pro každý detektor d se počítá jen nejsilnější signál v okně (klesající výnos), za každou další ATT&CK taktiku je bonus (kap. d). Incident se otevře při `p ≥ θ_open`, zavře při `p < θ_close` po klidu delším než 24 h nebo při vyvrácení.
  - `src/findings.rs` zůstane jako vrstva prezentace: nález = projekce incidentu nebo expozice z inventáře. `generate_findings` se rozdělí na `exposure_findings(report)` (dnešní statické typy) a `incident_findings(&IncidentStore)`.
- **Očekávaný efekt:** FP incidenty místo nálezů × cykly. Pro behaviorální šum, který je z velké části perzistentní a jednodetektorový, **odhaduji** pokles operátorské zátěže o 1 až 2 řády. Jeden vytížený server s inductive každý cyklus (20 až 48×/den) dá nejvýš 1 incident, a to jen když LLR jednoho detektoru překročí θ_open. To se po kalibraci (f) nestane, protože `cap_d` jednoho slabého detektoru se nastaví pod θ_open. Detekce: útoky s více signály (sken, exploit, beacon) akumulují. Jednosignálové hlučné útoky (DDoS, ransomware) musí mít LLR detektoru nad θ_open.
- **Riziko:** útoky s jediným slabým signálem (low-and-slow exfiltrace, rogue device) mohou spadnout pod práh. Řešení je delší τ pro pomalé techniky a samostatný `cap` pro silné signály (IDS EXPLOIT, nové zařízení v citlivé podsíti). Volba τ a θ je nová svobodná proměnná, která se musí kalibrovat (f).
- **Měření soakem:** nové metriky v `soak/stats.rs`: `fp_incidents`, `fp_incidents_by_root_detector`, `incidents_per_100_devices_day`, `tp_incident_families` (incident obsahuje klíčovou entitu útoku, entita podle tokenizované IP), `ttd_incident`. Scénář: párový A/B (stejný `--seed`, stejné `--max-networks`, engine v1 vs v2), stratifikovaný podle velikosti. Kritérium: medián párového rozdílu FP incidentů/síť-den < 0 s 95% bootstrap CI pod nulou a typovaná detekce rodin nezhoršená o víc než 2 p. b. (Wilson).

### (b) Adaptivní baseline a sezónní profily

- **Změna v kódu:** nový `src/baseline.rs`:
  ```rust
  pub enum Feature { FlowsIn, FlowsOut, DistinctDstOut, BytesOut, S0Ratio, AggPps, DistinctSrcIn, ExtDestNew }
  pub struct BaselineStore {
      levels: HashMap<(EntityKey, Feature), RobustEwma>,          // úroveň entity
      shapes: HashMap<(GroupKey, Feature), [RobustEwma; 48]>,     // 24 h × {pracovní, víkend/svátek}
  }
  impl BaselineStore {
      pub fn expected(&self, e: &EntityKey, g: &GroupKey, f: Feature, t: DateTime<Utc>) -> Option<Expectation>; // median, scale, n_eff
      pub fn update(&mut self, e: &EntityKey, g: &GroupKey, f: Feature, t: DateTime<Utc>, x: f64, gate: Gate);
  }
  ```
  `RobustEwma` drží EWMA mediánu (stochastická aproximace kvantilu) a EWMA absolutní odchylky s poločasem 7 dnů pro úroveň a 28 dnů pro tvar. `GroupKey = (role, archetyp sítě nebo podsíť)`. Očekávání = `level_e × shape_g[bucket]`. Při `n_eff(e) < N_min` se použije shrinkage k peer group: `w·level_e + (1−w)·level_g`, kde `w = n_eff/(n_eff+k)`. **Gating:** vzorek s |z| > 3 nebo vzorek z okna s otevřeným incidentem se do úrovně neučí (ochrana proti otrávení baseline útočníkem), do tvaru se neučí nikdy z oken s kontextovou výjimkou. Paměť: 4 000 entit × 8 příznaků × 2 statistiky + skupiny × 48 košů ≈ jednotky MiB na síť (**odhad**). Plná matice 168 košů na entitu by dala desítky MiB. Persistence: `workspace/baseline.json` (produkce), v soaku v paměti epizody.
  - Klíč entity = `asset_id` z identity. Dokud je identita slabá (A26), použít `(ip, port)` pro služby a nést příznak `identity_unstable`, při kterém se baseline resetuje a zvedá se `N_min`.
- **Očekávaný efekt (odhad):** inductive v1 159,1 → < 15 / síť-den, v2 407 → < 40 (−90 % a víc). Zdůvodnění: dnešní FP plynou ze stabilní vlastnosti „služba je vytížená“, kterou úroveň entity absorbuje. Zbytek tvoří skutečné odchylky (flash crowd, backup, batch), které řeší kontext (c), a falešné odchylky při práhu z ≥ 4 a ~10² testech na síť a cyklus.
- **Riziko:** (1) studený start: 24h epizody (100 sítí ve v2) budou z velké části v učící fázi. Bez shrinkage k roli by detekce v prvních hodinách klesla. (2) Útočník přítomný od začátku (perzistentní C2) se naučí jako normální, proto je nutný příznak „vzácnost cíle v síti“ nezávislý na čase. (3) Pomalý drift (exfiltrace po malých dávkách) se do EWMA vstřebá, proto mít i dlouhé okno (kumulativní bytes out za 7 dnů vůči peer group). (4) Výkon pro 18 vláken soaku.
- **Měření soakem:** segment `dur|24h` až `dur|1440h` (už existuje) pro učící křivku FP a detekce podle délky epizody. Nová metrika `fp_by_hour_of_day` (FP podle lokální hodiny) by měla být plochá, dnes **očekávám** špičku přes den. Scénář „baseline poisoning“: rodina `c2_beacon` a `insider_hoarding` začínající v cyklu 0 (přidat do `plan_episode` volbu `start_at_zero`). Kritérium: detekce těchto variant ≥ 80 % detekce standardní varianty.

### (c) Kontext jako potlačení

- **Změna v kódu:** nový `src/context_gate.rs` (nebo rozšíření `src/context.rs`):
  ```rust
  pub struct ContextCalendar { windows: Vec<ContextWindow> }     // údržba, patch okna, zálohy, skenery
  pub struct ContextWindow { pub scope: EntitySelector, pub kind: ContextKind, pub start: DateTime<Utc>,
                             pub end: DateTime<Utc>, pub expected: Vec<Feature>, pub expires: DateTime<Utc>, pub approved_by: String }
  pub struct HealthState { pub sensor_gap: bool, pub ingest_lag_s: i64, pub inventory_age_cycles: u32,
                           pub services_down: BTreeSet<String> }
  pub fn gate(signal: &mut Signal, cal: &ContextCalendar, health: &HealthState) -> GateDecision; // Keep | Discount(f64) | Explain(String)
  ```
  - *Zdraví senzoru:* `sensor_gap = flows(cyklus) < 0,05 × očekávání(baseline síťového objemu)`. V následujících 2 cyklech mají baseline detektory poloviční LLR a do baseline se neučí.
  - *Watermark:* tok s `ts < watermark − 2 × CYCLE` dostane `late = true`, nevstupuje do objemových detektorů aktuálního okna, ale přepočítá se do svého historického okna (řeší `collector_replay`).
  - *Server dole:* služba bez jediného SF toku, ≥ 3 různí klienti se S0 (stav `service_unavailable`). Timeout signály ke stejnému cíli se vysvětlí, nevydají.
  - *Allowlisty s expirací* (autorizovaný skener, záloha, NTP, update servery). Vyžadují schválení člověkem (Pásmo B) a mají TTL, aby z nich nebyly trvalé slepé skvrny.
  - *Učení výjimek z Case Memory:* opakovaně vyvrácený incident se stejnou entitou, hodinou a technikou navrhne `ContextWindow` ke schválení. Automaticky se nezapíná.
- **Očekávaný efekt (odhad):** service_crash 91,8 % → < 20 %, patch_window 99,2 % → < 30 % (timeouty vysvětlené stavem „dole“), collector_replay 97,3 % → < 20 %, backup a batch_job (s kalendářem) → < 15 %. U sensor_crash a log_corruption se skutečný efekt ukáže až po opravě měření (A29).
- **Riziko:** útočník se schová do okna údržby nebo za allowlist (známá technika). Proto potlačení pouze zlevňuje (`Discount`), silné signály (IDS EXPLOIT, nové externí C2) ignorovat nesmí. Allowlist je cíl útoku na konfiguraci, proto audit (`ops.rs` audit chain) a TTL.
- **Měření soakem:** kontrafaktuální režim (nový): pro vybranou benigní událost se týž seed spustí s maskou `mask_truth = Some(id)` a podíl „s FP“ se počítá z rozdílu nálezů a incidentů mezi během s událostí a bez ní. Metrika `lookalike_incremental_fp` podle typu události. Kontext kalendáře v soaku: generátor zná okna údržby a backupu, takže `ContextCalendar` dostane 50 % z nich (simulace neúplné dokumentace), aby se změřil i efekt chybějícího kalendáře.

### (d) Kauzální a sekvenční řetěz (kill chain / ATT&CK)

- **Změna v kódu:** v `src/incident.rs`:
  ```rust
  pub enum KillChainStage { Recon, CredentialAccess, InitialAccess, Execution, CommandAndControl, LateralMovement, Collection, Exfiltration, Impact }
  pub struct Transition { pub from: KillChainStage, pub to: KillChainStage, pub max_gap: Duration, pub lr_bonus: f64 }
  fn sequence_bonus(incident: &Incident, new: &Signal, graph: &EntityGraph) -> f64;  // log(lr_bonus) nebo 0
  pub struct EntityGraph { edges: HashMap<(String, String), EdgeStats> }  // z toků: počet, úspěšnost (SF+data), první/poslední čas
  ```
  Signál dostane `technique` při vzniku: sken → Recon (T1046), bruteforce a credential stuffing → CredentialAccess (T1110), IDS EXPLOIT/web exploit → InitialAccess (T1190), beacon → C2 (T1071), fan-out na interní služby po úspěchu → LateralMovement (T1021), velký odchozí objem → Exfiltration (T1041), mining a šifrování SMB → Impact (T1496, T1486). Bonus platí jen při správném pořadí na téže entitě nebo přes hranu grafu: A skenuje B → A exploituje B (úspěšné SF) → B začne beaconovat → B fan-out. Výchozí `lr_bonus` 2 až 5 je **odhad**, který se kalibruje.
- **Očekávaný efekt (odhad):** vyšší typovaná detekce vícefázových útoků (apt_chain je už dnes 100 %, protože je hlasitý, takže přínos bude hlavně u tichých kombinací exploit → beacon a lateral → exfil). Hlavně pokles FP: izolovaný slabý signál bez předchůdce a následníka bonus nedostane.
- **Riziko:** příliš pevný řetěz minul by útoky mimo šablonu. Bonus proto jen přidává, absence řetězu nesnižuje. Graf zvětšuje paměť (hrany jen za 24 h a jen interní konce).
- **Měření soakem:** `apt_chain` a nové kombinované rodiny (generátor už umí exploit a lateral zvlášť). Metrika `stage_order_correct` (incident má stadia v pořadí ground truth) a `ttd_to_second_stage`. Ablace: engine v2 se `sequence_bonus = 0` vs zapnutým, párově.

### (e) Deduplikace a sloučení nálezů

- **Změna v kódu:**
  - `Signal.cause_key = hash(agregát klíč, okno)`: signály se stejným `cause_key` od různých detektorů (dnes timeout, rate, overload a inductive ze stejného `ConnectionAggregate`) se sloučí na `max(llr) + ρ·Σ zbytku`, kde ρ ≈ 0,2 je sleva na závislost. Je to zobecnění principu H2 z `fusion.rs` na detektory.
  - `Finding`: přidat `first_seen`, `last_seen`, `occurrences: u32`, `incident_id: Option<String>`, `detector_id`, `score`, `probability`, `src_key`. `finding_id` zůstane stabilní, nový stav se uloží do `workspace/finding-state.json`. Znovu se vydá jen při růstu pravděpodobnosti o Δ ≥ 0,1, změně stadia nebo po klidu delším než 6 h.
  - `fusion.rs`: zachovat cross-senzorovou fúzi (Zeek notice a Suricata `src_port` už mají, `zeek.rs:71-73`, `suricata.rs:76`). U anomálních agregátů fúzi neřešit přes `community_id`, ale přes `cause_key`.
- **Očekávaný efekt (odhad):** v metrice nálezů × cyklů −80 až −95 % pro perzistentní detektory (jeden stav místo 20 až 48 opakování denně), −20 až −40 % dalšího šumu díky sloučení závislých detektorů jedné příčiny.
- **Riziko:** změna, která není nárůstem (útok na už „otevřené“ službě), musí projít přes „Δ pravděpodobnosti“, jinak hrozí maskování.
- **Měření soakem:** zachovat starou metriku (srovnatelnost s v1) a přidat `unique_finding_states_per_day` a `reemissions_per_state`. Kritérium: typovaná detekce se nezmění (± Wilson CI) a FP stavy/síť-den klesnou o více než 80 %.

### (f) Kalibrace a rozhodnutí pro prahy

- **Změna v kódu:**
  - Přesunout `IsotonicCalibrator` (`src/eval/calibration.rs`) do knihovny jako `src/calibration.rs` s verzí. Mapovat `score → P(attack | detektor, role)` a `llr = logit(P) − logit(prior_role)`. Trénovat na směsi soak + CTU-13 + IoT-23 (A34) s rozdělením leave-one-archetype-out, aby se nepřeučilo na simulátor.
  - Prahy `θ_open`, `cap_d`, τ odvozovat z **rozpočtu poplachů** (návrh: ≤ 1 FP incident na 250 zařízení a den, tedy u XL ≈ 3,4 / den). Zvolit maximum recall při dodržení rozpočtu na validačních seedech. Práh na úrovni operátora převést na ztrátovou funkci: rozhodnutí „eskalovat“, když `p · C_FN > (1−p) · C_FP` (výchozí `C_FN/C_FP` = 20 je **odhad** k diskusi).
  - `decision.rs::rank_finding` nahradit řazením podle `p × impact` incidentu. `impact` z role aktiva (PLC, medical, DC, gateway > workstation), ne ze severity typu.
- **Očekávaný efekt:** prahy přestanou být ruční (A05). Rozpočet poplachů nebude záviset na velikosti sítě (dnes sklon ≈ 1,0, cíl sublineární nebo konstantní na 100 zařízení).
- **Riziko:** kalibrace na simulátoru převezme jeho artefakty (A34). Izotonická regrese přeučí malé N (`h4-isotonic-calibration-loso.md`, omezení). Řešení: monotónní, vyhlazená (pooly s minimem 50 vzorků), verzovaná, s rollbackem jako Case Memory.
- **Měření soakem:** ECE a Brier pro behaviorální typy zvlášť od statických (A33), spolehlivostní diagram incidentů, `alert_budget_compliance` = podíl sítí v rozpočtu, PR-AUC na úrovni (entita, den). Train/test podle seedů: kalibrace na `--seed A`, měření na `--seed B`.

### (g) Změny datového modelu

| struktura | soubor | změna |
|---|---|---|
| `ConnectionObservation` | `passive/mod.rs` | + `direction: Direction`, `late: bool`, `quality: u8` (rozbitý řádek) |
| `NormalizedEvent` | `model.rs:402` | + `technique: Option<String>`, `category: Option<String>`, `signature_id: Option<i64>` (Suricata) |
| `Signal` | `model.rs` (nové) | viz (a) |
| `Incident`, `KillChainStage`, `IncidentStatus` | `model.rs` (nové) | viz (a), (d) |
| `Finding` | `model.rs:470` | + `first_seen`, `last_seen`, `occurrences`, `src_key`, `detector_id`, `score`, `probability`, `incident_id` (serde default) |
| `HostReport` | `model.rs:254` | + `role: Option<String>`, `inventory_seen_at`, `identity_confidence` |
| `CaseRecord` | `case_memory.rs:88` | + `context: CaseContext { role, detector_id, score_bin, method, outcome_code }`, `incident_id` |
| `Estimate` | `case_memory.rs:141` | + `backoff_level` (z jaké úrovně hierarchie odhad je) |
| `SecurityHypothesis` | `hypothesis.rs:89` | `affected_assets` → `entities: Vec<EntityRef>`, + `log_odds`, `steps: Vec<VerificationStep>`; `contradicting_evidence` plnit vyvracejícími výsledky kontrol |
| `VerificationCandidate` | `verification_planner.rs:35` | + `outcomes: Vec<OutcomeModel{label, p_given_h, p_given_not_h}>`, `idempotency_ttl`, `pool: BudgetPool` |
| `RunReport` | `model.rs:84` | + `incidents: Vec<Incident>`, `signals_total`, `suppressed_total` |

## Žebřík ověřování

### Proč je dnes 68 % (v1) / 91 % (v2) mimo rozpočet

- Plán vzniká pro každý nález v každém cyklu (`pipeline/mod.rs:1401-1411`, `episode.rs:605-608`): v1 74,1 M / 1,49 M cyklů ≈ 50 plánů na cyklus, v2 40,0 M / 0,22 M ≈ 181 plánů na cyklus (`final-report.md`, `status.md`).
- Rozpočet je 10 kontrol na běh a 2 na cíl (`verification_exec.rs:38-46`). Vykoná se ≈ 8,3 na cyklus (v1 12,4 M / 1,49 M, v2 1,82 M / 0,22 M).
- Pro behaviorální typy vyhraje `passive_extended_observation` (utilita 0,2 × impact > 0), která se započítá jako vykonaná (`:248`) a nic nezjistí. **Odhaduji**, že většina z 12,4 M „vykonaných“ je tento no-op, protože behaviorální nálezy tvoří většinu plánů. Ověřit to má metrika `executed_by_method`.
- Pořadí určuje `finding_id` (abecedně podle typu: `connection_timeout_burst` < `high_risk_cve_exposure` < `identification_gap` < `inductive_volume_anomaly` < ...), ne užitek.
- Idempotence platí jen v rámci jednoho volání (`:181`), takže tatáž kontrola na tentýž asset se opakuje v každém cyklu.

### Návrh: sekvenční bayesovské ověřování incidentu

**Stav:** incident I s log-odds `L = logit(p)`. Každá kontrola c má model výsledků `o ∈ O_c` s `P(o|H)` a `P(o|¬H)`. Po výsledku: `L ← L + log(P(o|H)/P(o|¬H))`. Závislé kontroly (stejný zdroj dat) se slučují stejně jako v (e): max plus sleva.

**Užitek kontroly (EVOI):** pro rozhodnutí {eskalovat, nedělat nic} se ztrátami `C_FN`, `C_FP`:
`R(p) = min(p·C_FN, (1−p)·C_FP)`, `EVOI(c) = R(p) − Σ_o P(o)·R(p_o) − cost(c)`, kde `P(o) = p·P(o|H) + (1−p)·P(o|¬H)`.
EVOI je přirozeně nejvyšší kolem rozhodovací hranice a nulová, když je p blízko 0 nebo 1. To dnešní `utility` (`verification_planner.rs:53-62`) nesplňuje.

**Pravidla zastavení (SPRT, Wald):** s cílovou chybou α (falešná eskalace) a β (minutí):
- `L ≥ log((1−β)/α)` → **potvrdit a eskalovat** (návrh blokace do `ops.rs` s `finding_id`/`incident_id`, nebo člověk),
- `L ≤ log(β/(1−α))` → **vyvrátit**: zavřít, zapsat `Refuted` a dočasně potlačit stejné `(detektor, entita, technika)` na TTL 24 h, pokud nepřijde nový signál s LLR nad práh,
- jinak, je-li `max_c EVOI(c) > 0` a rozpočet volný → další krok. Jinak **zaparkovat** (watch) a přehodnotit při novém signálu nebo po T.

Výchozí α = 0,02, β = 0,1 jsou **odhad** k diskusi a kalibrují se soakem.

**Příčky:**

| příčka | co dělá | příklady (dostupné v kódu / nové) | náklad | schválení |
|---|---|---|---|---|
| L0 pasivní obohacení | dotaz do lokálních dat | baseline residuum, kalendář, identita a stáří inventáře, CVE cache (`cve_intel_relookup`), intel cache (`intel.rs`), IDS alerty v ±1 h, signály sousedů v grafu, vzácnost externího cíle (kolik interních hostů s ním mluví) | ~0 | ne |
| L1 pasivní čekání | skutečný test v čase (dnes no-op) | pokračuje vzor N cyklů? periodicita intervalů (CV < 0,2), následuje úspěšné spojení po S0? | čas (zpoždění) | ne |
| L2 levná aktivní | jeden požadavek na interní cíl v scope | TCP connect a banner na port, `read_only_content_inspection` (existuje), PTR/DNS lookup, dotaz ARP/MAC tabulky z kontextového adaptéru (identita) | nízký | ne (read-only) |
| L3 cílený sken | `nmap -sV -sC` na konkrétní porty (existuje: `nmap_targeted_followup`) | identifikace služby, ověření expozice | střední | ano |
| L4 hlubší | credentialed audit (Greenbone/Wazuh lanes), cílený pcap N minut, dotaz EDR | potvrzení kompromitace | vysoký | ano |
| L5 člověk | verdikt operátora | finální potvrzení nebo vyvrácení, návrh kontextové výjimky | velmi vysoký (pozornost) | — |

**Příklady modelů výsledků (počáteční priory, odhad, kalibrovat z Case Memory):**

| hypotéza | kontrola | výsledek → LR |
|---|---|---|
| C2 beacon H→X | L0 vzácnost X | 1 interní host → 3,0; > 20 hostů → 0,2 |
| | L0 intel X | shoda AbuseIPDB/URLhaus → 10; bez shody → 0,8 |
| | L1 periodicita 3 cyklů | CV < 0,2 → 5,0; zmizí → 0,4 |
| lateral A→{B…} | L0 role A (jump host, autorizovaný skener) | ano → 0,1 |
| | L1 úspěch po pokusech (SF s daty na nový cíl) | ano → 4,0; ne → 0,7 |
| exploit na S | L0 CVE na S odpovídá signatuře | ano → 6,0; služba není zranitelná → 0,3 |
| | L2 banner/verze S | shoda se zranitelnou verzí → 2,0 |
| objem na S | L0 kalendář (backup/patch) | v okně → 0,15 |
| | L0 počet zdrojů | 1 zdroj → 2,0 (exfil/insider); mnoho → 0,5 (flash crowd) |
| neznámé zařízení | L2 ARP/MAC z přepínače | MAC neznámá a mimo DHCP rozsah → 4,0; známý lease → 0,2 |

**Rozpočet:** tři fondy místo jednoho čítače: `passive` (L0/L1, bez limitu počtu, jen CPU a čas), `active_cheap` (L2, např. 10 za cyklus a 2 na cíl, rate limit jako dnes), `approval` (L3/L4, fronta ke schválení, denní strop), `human` (L5, např. 5 za den). Výběr kontrol přes **všechny otevřené incidenty**: hladový knapsack podle `EVOI/cost` ve fondu, ne podle pořadí nálezů.

**Idempotence:** klíč `hash(method, asset, params, evidence_epoch)`, kde `evidence_epoch` je verze incidentu. Cache se uloží do `VerificationHistory` (`case_history.rs`) s TTL podle metody (CVE lookup 24 h, HTTP GET 1 h, nmap 24 h, L1 periodicita s klouzavým oknem). Výsledek v cache změní posterior jen jednou na epochu incidentu.

**Pivotování (poskakování na související zařízení):**
1. Kořen = entita incidentu. Hrany = `EntityGraph` z toků v okně 24 h se směrem a úspěšností.
2. Kandidát pivotu v na hraně u→v dostane prior `p_v = p_u · τ(hrana)`, kde τ závisí na typu hrany: úspěšné spojení na zranitelnou službu (CVE ≥ 7) ≈ 0,3, úspěšné spojení na administrativní port ≈ 0,15, jen pokus ≈ 0,02 (**odhad**, kalibrovat).
3. Priorita pivotu = `EVOI(nejlepší kontrola na v) × impact(v)`. BFS s hloubkou ≤ 2, nejvýš 5 pivotů na incident, pivoty mohou čerpat nejvýš 30 % fondu `active_cheap`.
4. Směry: od oběti exploitu ke **zdroji** (kdo útočí, je zdroj interní?), od kompromitovaného hostu k jeho **novým cílům** po události (lateral), od beaconu k **ostatním hostům se stejným externím cílem** (flotila).
5. Pivot vytvoří podřízenou hypotézu ve stejném incidentu (sdílené `incident_id`), ne nový nález.

**Vazba na Case Memory:**
- `CaseRecord.context` (g) a odhad `estimate_ctx(finding_type, ctx)` s hierarchickým backoffem: (typ, role, koš skóre) → (typ, role) → typ → globální prior. Použije se první úroveň s `n_eff ≥ MIN_CASES`.
- Tabulky LR: `likelihood(method, hypothesis_type, outcome) -> Option<(P(o|H), P(o|¬H))>` z párů (výsledek kontroly, pozdější verdikt incidentu). Beta-binomický odhad s priorem z tabulky výše.
- Časový rozpad záznamů (poločas 30 dní) proti driftu a inkrementální čítače místo průchodu všemi záznamy (A21).
- Poisoning guard zůstane (rate limit, strop zdroje, kontradikce) a nově platí i pro LR tabulky.
- Verdikt incidentu se zapíše jednou za incident, ne za každý nález × cyklus.

**Co v dnešním kódu chybí (konkrétně):**
1. pravděpodobnost na úrovni případu (dnes jen typová, `hypothesis.rs:214-223`),
2. modely výsledků kontrol a LR (`VerificationCandidate` je nemá),
3. skutečné behaviorální kontroly (L1 periodicita, L2 connect/banner, ARP lookup) místo no-op,
4. EVOI závislé na p (`verification_planner.rs:53-62`),
5. globální výběr přes incidenty a oddělené fondy (`verification_exec.rs:183-252`),
6. perzistentní idempotence (`:181`),
7. zpětný zápis výsledku do posterioru téhož běhu (`pipeline/mod.rs:1412-1432`),
8. učení behaviorálních typů z ověření (`case_memory.rs:547-592`),
9. pivoting a graf entit (neexistuje),
10. vazba návrhu blokace na incident (soak volá `BlockIpRequest{finding_id: None}`, `episode.rs:981-987`).

**Očekávaný efekt (odhad):** podíl no-op kontrol → 0. Počet plánů klesne z ≈ 50 až 181 na cyklus na počet otevřených incidentů (jednotky). „Mimo rozpočet“ v dnešním smyslu zanikne, místo toho se měří podíl incidentů rozhodnutých (potvrzeno/vyvráceno) do 4 cyklů. Cíl: více než 60 %.

**Měření soakem:** `checks_by_method_and_pool`, `noop_share`, `incidents_resolved_within_k_cycles`, `checks_per_resolved_incident`, `wrong_resolution_rate` (vyvráceno, ale byl útok, a naopak), `pivot_hit_rate` (pivot na entitu, která je v ground truth klíčovou entitou útoku), `approval_queue_len`. Scénář: rodiny `lateral_movement`, `apt_chain`, `fleet_beacon` (pivot), `exploit_attempt` s CVE na oběti (L0 a L2). Ablace: žebřík vypnutý (jen RBA) vs zapnutý, párově.

## Plán změn s měřením (TOP 10)

Pořadí podle (efekt na FP a detekci) / (náročnost). Náročnost: S ≤ 1 den, M 2 až 5 dnů, L 1 až 3 týdny (**odhad**). Všechny efekty jsou **odhad**, pokud není uveden zdroj.

| # | změna | soubory a funkce | efekt (odhad) | náročnost | závisí na |
|---:|---|---|---|---|---|
| 1 | **Opravit měření**: tokenizovaná atribuce IP (A28), kontrafaktuál pro benigní události (A29) a detekce nad pozadím (A31), metriky na úrovni incidentů a stavů, `executed_by_method`, rozpad `unexpected_traffic`/`unmapped` podle příčiny (stáří inventáře, změna IP, restart), kalibrace behaviorálních typů zvlášť (A33), sladit `expected_types` (A30), přepínač `--engine` v soak CLI | `soak/episode.rs:163-174, 670-760`, `soak/stats.rs`, `soak/report.rs`, `soak/traffic.rs:105-200`, `main.rs` (SoakCommand) | bez přímého efektu na FP. Bez něj nelze ostatní body změřit. Vykázané FP mohou po opravě atribuce **vzrůst** (atribuce dnes nafukuje) | S až M | – |
| 2 | **Scope podle src ∨ dst a směr toku** (A10). Pravidla závislá na inventáři pouštět jen na interní cíle | `passive/zeek.rs:173-178, 46-48, 102-106`, `passive/suricata.rs:69-73`, `passive/mod.rs` (`in_scope_flow`), `soak/episode.rs:487-492` | zdrojové pořadí exfiltrace 0 % → ≈ 42 % (v1, změřeno variantou „s egress“) / 31 % (v2). Alerty C2 s externím cílem (v1: IDS vidělo 692) se začnou parsovat. Riziko: nové FP z `retry_storm`/`software_update` | S | 1 |
| 3 | **Mapování alertů Suricaty a pravidlo nálezu** (A11, A12): kategorie a prefix signatury → typ a technika, zrušit klasifikaci podle portu 80 | `passive/suricata.rs:111-124`, `findings.rs:28-57` (nové `rule_ids_alert`) | správný typ exploitů 0,0 % → strop ≈ podíl viditelný IDS: 45,5 % (v1: 2 301/5 061), 47,6 % (v2: 520/1 093). Lepší typování i u web_exploit, ics, credential_stuffing, ransomware | S | 1 |
| 4 | **Robustní packet rate** (A04): agregát Σpkts/okno a p95 přes toky ≥ 10 pkt a ≥ 1 s | `passive/anomaly.rs:249, 444-466`, `correlation_v2.rs:269` | packet_rate_spike −90 až −98 % (v1 45,4 → < 2; v2 111,6 → < 5 / síť-den); DDoS beze změny (agregát ≥ 500 toků/cyklus) | S | 1 |
| 5 | **Perzistence a deduplikace nálezů** (A14, A18): `first_seen`/`last_seen`/`occurrences`, znovuvydání jen při Δp nebo po klidu, `cause_key` mezi detektory | `model.rs:470`, `findings.rs:797-826`, nový `finding_state.rs`, `fusion.rs` | v metrice nálezů × cyklů −80 až −95 % pro perzistentní typy; v1 210,7 → ≈ 15 až 40 stavů / síť-den ještě před baseline | M | 1 |
| 6 | **Čerstvost inventáře, agregace unexpected/unmapped, stav po restartu** (A08, A09, A13) | `passive/anomaly.rs:174-206`, `findings.rs:102-121, 455-492`, `passive/mod.rs:58-66`, `report.rs:330-400` | v2: unexpected 533,7 a unmapped 52,3 / síť-den, −70 až −90 %, **pokud** se potvrdí hypotéza zastaralého inventáře (bod 1 ji ověří) | S až M | 1 |
| 7 | **Sezónní baseline na entitu** místo průřezového inductive (A02, A03) | nový `baseline.rs`, `passive/anomaly.rs:334-398` → nový detektor, `detector.rs` (trait se `Signal`) | inductive −90 % a víc (v1 159 → < 15, v2 407 → < 40). FP/100 zařízení přestane růst s velikostí sítě (dnes sklon ≈ 1,0) | L | 1, 5, částečně 9 (identita) |
| 8 | **Kontextová brána** (zdraví senzoru, watermark, server dole, kalendář, allowlisty s TTL) (A07) | nový `context_gate.rs`, `passive/anomaly.rs:220`, `soak/traffic.rs` (kalendář pro harness) | service_crash 91,8 → < 20 %, patch_window 99,2 → < 30 %, collector_replay 97,3 → < 20 %, timeout burst −60 % | M | 1, 2 (egress FP), 7 |
| 9 | **Source-centric a egress detektory do produkce a lepší identita**: `score_source_hosts` jako signál, fan-out s úspěchem (lateral), beacon periodicita přes cykly, nové zařízení, vícesignálová identita (hostname, otisk služeb, ARP/SNMP) (A01, A19, A26) | `passive/anomaly.rs:110-172` (z dead_code do detektoru), nový `detectors/beacon.rs`, `identity.rs:68-116` | C2 12,8 % → 40 až 60 %, rogue 7,8 % → ≥ 50 %, cryptomining 25 % → ≥ 50 %, lateral typ 64,8 % (v2) → ≥ 85 %; falešné rozdělení identity 37,1 % → < 10 % (v2). Opora: zdrojové pořadí C2 67,6 % (v1) dokládá, že signál existuje | L | 2, 7 (baseline pro fan-out) |
| 10 | **RBA incidenty + kalibrace + žebřík ověřování + podmíněná Case Memory** (A15, A20 až A25, A27) | nový `incident.rs`, `calibration.rs` (z `eval`), `verification_planner.rs` (EVOI z p), `verification_exec.rs` (fondy, globální výběr, perzistentní idempotence), `case_memory.rs` (`estimate_ctx`, LR tabulky), `decision.rs`/`triage.rs` (řazení podle p×impact) | FP incidenty dalších −50 % proti stavu po bodech 1 až 9. Rozpočet poplachů nezávislý na velikosti sítě. No-op kontroly 0 %, rozhodnuté incidenty do 4 cyklů > 60 % | L | 5, 7, 8, 9 |

### Jak měřit (společný protokol)

1. **Párový A/B:** generátor je deterministický podle `(seed, network_id)` (`soak verify` 30/30 bit po bitu, `soak-findings.md`). Pro každou změnu spustit `soak run --seed S --max-networks N --no-legs --engine {v1,v2-krok-k}` se stejnými S a N. Síť i_A a i_B mají identický provoz i útoky. Statistika: párový rozdíl na síť, medián a 95% bootstrap CI, Wilsonovy intervaly pro podíly (už v reportu).
2. **Sady seedů:** `S_dev` (ladění prahů), `S_test` (měření, nikdy neladit), `S_quiet` (nová volba `attack_rate = 0`: čisté FP; dnes má v2 jen 20 síť-dnů bez útoku), `S_long` (`--episode-hours 720` a 1440: drift a otrávení baseline), `S_ops` (zvýšená frekvence provozních událostí).
3. **Primární metriky:** FP incidenty / 100 zařízení / den (stratifikace S až XXL), log-log sklon FP vůči počtu zařízení (cíl < 0,3), typovaná detekce po rodinách, medián TTD, `lookalike_incremental_fp` (kontrafaktuál), ECE behaviorálních pravděpodobností, `noop_share`, rozhodnuté incidenty.
4. **Ochranné metriky:** typovaná detekce žádné rodiny neklesne o víc než 2 p. b. (dolní mez Wilson CI v2 ≥ horní mez v1 − 2 p. b.), invarianty soaku 0, p99 doby cyklu ≤ dnešní (v2 5,2 s).
5. **Kotva na reálných datech:** CTU-13/IoT-23 noha (`legs`) přepočítat i na úrovni zdroje (PR-AUC). Dnešní ablace A poráží triviální baseline jen v 6 z 20 scénářů (`final-report.md`).

### Konkrétní kritéria po krocích

| krok | scénář | metrika | cíl |
|---|---|---|---|
| 1 | `S_test`, v1 engine, stará vs nová atribuce | rozdíl FP / síť-den, rozdíl detekce | zdokumentovat velikost artefaktu A28/A29 |
| 2 | `S_test` | zdrojové pořadí exfiltrace, detekce C2/exfil/mining, nové FP od retry_storm/software_update | exfil pořadí ≥ 30 %, nové FP zapsat jako vstup pro krok 8 |
| 3 | `S_test` | správný typ exploit_attempt, web_exploit | ≥ 0,9 × podíl viditelný IDS |
| 4 | `S_test` + `S_quiet` | packet_rate_spike FP / síť-den, detekce ddos_volume | FP −90 %, ddos ≥ 94 % (v2 dnes 96,0 %) |
| 5 | `S_test` | stavy FP / síť-den, znovuvydání na stav | −80 %, detekce beze změny |
| 6 | `S_test` (v2 archetypy L až XXL) | unexpected + unmapped / síť-den, podle příčiny | −70 % |
| 7 | `S_test`, `S_long`, varianta „útok od cyklu 0“ | inductive FP, FP podle hodiny, detekce c2 a insider od nuly | −90 %, plochý profil, ≥ 80 % detekce standardní varianty |
| 8 | `S_ops` + kontrafaktuál | `lookalike_incremental_fp` po typech | service_crash < 20 %, patch < 30 % |
| 9 | `S_test` | detekce c2, rogue, crypto, lateral (typ), identita split/merge | viz tabulka TOP 10 |
| 10 | `S_test`, `S_quiet` | FP incidenty / 100 zařízení / den, ECE, rozhodnuté incidenty | ≤ 0,4, ECE < 0,05, > 60 % |

## Otevřené otázky a rizika

1. **Přeladění na simulátor:** packet rate artefakt (A04) je částečně důsledek zvolených lognormálních rozdělení (A34). Prahy a kalibrace se musí ověřit na CTU-13/IoT-23. Sedm z 23 scénářů má málo toků, takže reálná kotva je slabá.
2. **Rozpočet poplachů a recall:** rozpočet 1 FP / 250 zařízení / den je návrh, ne norma. Hodnotu `C_FN/C_FP` musí určit autor práce (rozhodnutí o zadání, ne inženýrská volba).
3. **Podmíněná nezávislost v Bayesovi:** součet LLR předpokládá nezávislost signálů. Slevy (ρ, max na detektor) jsou heuristika, korelovanost signálů je potřeba změřit (párová korelace LLR na `S_quiet`).
4. **Otrávení baseline a kontextu:** útočník přítomný od začátku, schovaný v okně údržby nebo na allowlistu. Gating a „Discount, ne Ignore“ riziko zmenšují, ale neodstraní.
5. **Studený start:** krátké epizody (24 h) budou po kroku 7 vypadat hůř. Je nutné reportovat detekci podle stáří baseline.
6. **Identita jako základ baseline:** při 37 % falešného rozdělení (v2) bude baseline často začínat znovu od nuly. Krok 9 (identita) je proto ve skutečnosti předpoklad kroku 7 pro velké sítě.
7. **Aktivní ověřování a pivotování:** zůstává v mezích scope, schvalování a rate limitů (A9 guardrail). Pivot nikdy nesmí na externí cíl. Právní a etický rámec aktivních kontrol v cizí síti řeší zadání.
8. **Výkon:** stav na entitu (baseline, graf, incidenty) pro 4 000 zařízení × 18 vláken soaku. Ve v2 už je trend RSS +116 MiB/h, „podezření na únik“ (`status.md`). Nové struktury proto potřebují ohraničenou velikost (TTL hran, strop entit).
9. **Srovnatelnost s v1:** nové metriky na úrovni incidentů se s v1 přímo srovnat nedají. Proto zachovat i starou metriku nálezů × cyklů.
10. **Průběžná čísla v2:** 538 sítí. Čísla per archetyp (např. Industrial 20 sítí, ICS 39 útoků) mají široké intervaly.

## Co jsem nezkontroloval

- `src/lanes.rs` (zdroj `external_flow_observed`, flow-rate lanes), `src/context.rs`, `src/simulation.rs`, `src/validation.rs`, `src/automation.rs`, `src/eval/*` (kromě dokumentace kalibrace a PR-AUC), `src/server.rs` a UI.
- `src/enforcement.rs` a `src/ops.rs` jsem prošel jen v místech návrhu a schvalování blokace, ne celý životní cyklus a sweep.
- `src/verification.rs` (harness scénářů) a `src/case_history.rs` jen hlavičkově.
- `src/soak/netmodel.rs` jen inventář, churn a sampling. `soak/legs.rs`, `kernel.rs`, `runner.rs` a `report.rs` téměř vůbec.
- Neověřil jsem rozpad `unexpected_traffic` ve v2 podle příčiny (hypotéza zastaralého inventáře a změn IP je neověřená), přesný řádek tří panik ve v2 (A35) ani příčinu růstu RSS.
- Nic jsem nespouštěl: žádné testy, build ani soak. Všechny analytické odhady (např. p ≈ 0,0025 u packet rate) jsou výpočty z parametrů generátoru, ne měření.
- Neověřoval jsem chování na reálném Zeeku s polem `history` (A06). Plyne z kódu, ne z měření.
