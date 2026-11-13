# Implementace, krok 8: koncová telemetrie (EDR-like) jako další druh důkazu

Datum 2026-11-11. Výchozí stav: krok 7 (`78ba3e1`), preset `recommended()` = sestava kroku 7, výchozí režim `legacy`. Rešerše: `studie/08-endpoint-telemetrie.md`. Salticus je síťová detekce, krok 8 přidává vrstvu, která čte VÝSTUPY hotových nástrojů (Sysmon a Windows log v JSON, Wazuh alerts, osquery results). Žádný vlastní agent.

Cíl: slepá místa z registru kroku 7 (exploit_attempt 35,5 %, lateral_movement, pomalé a nenápadné c2 majáky) a bezpečné zavření falešných poplachů známým procesem.

## A) Návrh

### A1. Model a identita

- `EndpointEvent` (`src/endpoint/model.rs`): zdroj, odkaz na host (`HostRef`: hostname, IP, MAC, id agenta), čas události, druh (`ProcessCreate`, `NetConnect`, `Logon`, `FileCreate`, `ServiceInstall`, `Persistence`, `Integrity`, `ProcessAccess`, `Alert`) a otisk obsahu. Všechna textová pole se oříznou na 512 znaků.
- Identita: `HostDirectory` mapuje hostname, IP a MAC na host z inventáře. Jednoznačná shoda aspoň jednoho identifikátoru bez sporu = `Unique`. Spor nebo víc kandidátů = `Ambiguous`. Neznámý = `Unknown`. Ambiguous a Unknown události se počítají do pokrytí, ale do verdiktu nevstupují (ani jako podezřelé, ani jako neškodné).
- Spojení s toky: pětice nebo Community ID v1 + čas s tolerancí 120 s; posun hodin agenta se odhaduje mediánem z aspoň 5 jednoznačných dvojic (ořez ±600 s).

### A2. Pravidla (závazná, testovaná)

1. Neškodný koncový signál NIKDY sám nezavře nález. Pro chráněný nález není důkaz vůbec (`Undetermined`). Pro ostatní je to jedna kontrola žebříku (L1, `endpoint`, LR 0,3) a vyvrácení dál vyžaduje posteriori ≤ 0,03 a tedy aspoň jeden další neškodný důkaz.
2. Chybějící telemetrie z hosta je viditelná: `endpointCoverage` (kryté, tiché, neznámé hosty, podíl) v reportu. Host bez agenta dává `Unavailable`, ne neškodné.
3. Nedůvěryhodný vstup: řádek ≤ 64 KiB, dávka ≤ 8 MiB a ≤ 50 000 událostí, ≤ 4 096 událostí na host v uložení, ≤ 2 000 událostí na host a cyklus (rate limit), událost z budoucnosti o víc než 1 h a starší než 24 h se odmítne, parser nepanikaří (fuzz test).
4. Deduplikace podle otisku, řazení podle času události.
5. Neškodné: známý podepsaný proces (cesta pod systémovou nebo programovou složkou + výrobce ze seznamu, nebo `Signed=true`) s pravidelným spojením na protistranu nálezu (≥ 6 spojení, variační koeficient intervalu < 0,2, vzor starší než 6 h a starší než nález). Může snížit prioritu nechráněného nálezu přes žebřík s auditní stopou (důvod v rozhodnutí, vzorek auditu druhu `ladder`).
6. Podezřelé: podezřelý proces u hosta nálezu zvýší jistotu (`endpoint`, LR 12) a posune případ k potvrzení. Navíc vzniká samostatný nález `endpoint_alert` (chráněný typ, vždy zobrazen), když host sám má podezřelé indikátory se součtem váhy ≥ 3 (silný 3, střední 2, slabý 1): web server spouští shell, kódovaný příkaz, stažení přes nástroj systému, nepodepsaný proces z dočasné složky, přístup k LSASS, instalace nepodepsané služby, vzdálené přihlášení + vzdálené spuštění, série neúspěšných přihlášení, pravidelné spojení nepodepsaného procesu, změna kritického souboru, Wazuh pravidlo úrovně ≥ 10.
7. Ochrana: přepínač `endpoint` je platný jen s `protect`. `endpoint_alert` je chráněný typ (nikdy automaticky zavřen ani vyvrácen).

### A3. Zapojení

`V3Features::endpoint` (výchozí vypnuto, mimo `recommended()`), `CheckId::Endpoint` a `LadderEvidence::endpoint` ve `verify_ladder`, typ `endpoint_alert` v `protection`, produkce v `pipeline/v3.rs` (události z `engine-state.sqlite`, tabulka `endpoint_events`), REST `POST /api/endpoint/ingest?format=sysmon|wazuh|osquery` (oprávnění `findings.write`, CSRF, limit těla) a CLI `endpoint ingest`. Bez přepínače je chování bajtově beze změny.

### A4. Simulace

`--endpoint on|off`, `--endpoint-coverage <procenta>`, `--endpoint-agent honest|silent|ok`. Generátor (`soak/endpoint_sim.rs`) odvozuje události z existujících rodin (bez nové techniky): exploit a webexploit (web server spouští shell), lateral (vzdálené přihlášení + služba), c2, fleet_beacon, dns_tunnel a cryptomining (pravidelné spojení nepodepsaného procesu), exfil a insider (velké spojení nepodepsaného procesu), ssh_bruteforce a credential_stuffing (série neúspěšných přihlášení), ransomware (soubory + proces z dočasné složky); benigní: aktualizace, záloha, monitoring a pravidelné vzory (podepsané procesy), správcovské nástroje (PsExec od správce: falešné podezření), šum. Agent: pokrytí hostů, výpadky, posun hodin, duplicity, zpoždění, kompromitovaný agent (`silent` nic neposílá, `ok` posílá jen „vše v pořádku“ z podepsaného procesu na protistranu útoku). Generátor píše autor, takže měří zapojení a invarianty, ne zisk na reálném provozu (viz studie 08, bod 4).

## B) Předregistrace prahů (zamčeno commitem před prvním měřicím během)

Seedy: ladicí 20261102, 20261103, 20261104 (po 40 sítích) a nové 20262201, 20262202 (po 40 sítích). Držené 20261901, 20262001, 20262101, 20262102, 20261201, 20261301 se nepoužijí; mega běh (seed 20261108) také ne. Výsledky proto nejsou držené a nepovolují změnu výchozího režimu, jen rozhodnutí, zda je vrstva za přepínačem připravena na držený běh. Rameno `v3k7` = `recommended()`, svět `--coverage full --families all`, `--no-legs --no-feedback --counterfactual --block-size 2`, 1 rameno najednou, nejvýš 4 vlákna, priorita Idle.

Ramena: `off`, `on100`, `on60`, `on30` (pokrytí agenty 100, 60, 30 % hostů), `comp-silent` a `comp-ok` (pokrytí 100 %, kompromitovaný agent). Párově podle sítí, bootstrap po sítích (B = 2000), Wilsonovy intervaly.

| práh | definice | splněno, když |
|---|---|---|
| E1 | recall exploit_attempt, `on100` − `off`, párově | ≥ +10 p. b. a dolní mez intervalu > 0 |
| E2 | recall lateral_movement, `on100` − `off` | ≥ +8 p. b., dolní mez > 0 |
| E3 | recall c2_beacon, `on100` − `off` | ≥ +8 p. b., dolní mez > 0 |
| E4 | detekce souhrnně, `on100` − `off` | ≥ 0 p. b. |
| E5 | zobrazené FP na síť-den, `on100` / `off` | ≤ 1,10 |
| E6 | všechny zobrazené položky na síť-den, `on100` / `off` | ≤ 1,15 |
| E7 | zavřeno omylem, počet útoků s omylem zavřeným nálezem, `on100` | ≤ `off` |
| E8 | zavřeno omylem, `comp-ok`: počet útoků s omylem zavřeným nálezem | ≤ `off` + 1 % útoků a detekce `comp-ok` − `off` ≥ −1 p. b. |
| E9 | `comp-silent`: detekce − `off` | ≥ −1 p. b. (mlčící agent nesmí zhoršit síťovou cestu) |
| E10 | chráněná automatická zavření a zavření chráněného nálezu koncovým signálem | 0 |
| E11 | monotónnost pokrytí: recall souhrn `on100` ≥ `on60` ≥ `on30` ≥ `off` − 0,5 p. b. | splněno |
| E12 | fuzz parserů (100 000 náhodných a poškozených řádků na formát) a limity | 0 paniků, limity drženy |
| E13 | determinismus: stejný seed dvakrát bit po bitu; legacy a v3 bez `endpoint` bajtově beze změny, golden snapshot zelený | shoda |
| E14 | paniky a porušené invarianty ve všech ramenech | 0 a 0 |

Rozhodnutí: když E1 až E14 projdou, vrstva je „připravena na držený běh“ (výchozí zůstává vypnutý, `recommended()` se nemění). Neúspěšný práh se zapíše poctivě a změna kódu po prvním měřicím běhu se zapíše jako odchylka (sekce D), práh se nemění.

## C) Implementace

| blok | soubory | co |
|---|---|---|
| model, parsery | `src/endpoint/{mod,model,sysmon,wazuh,osquery}.rs` | `EndpointEvent` (9 druhů), parsery Sysmon (ID 1, 3, 10, 11, 13; Security 4624, 4625, 4688, 7045; rozložení Event/System, winlogbeat, ploché), Wazuh alerts (vnořené Windows události, syscheck, selhání SSH, úroveň pravidla), osquery results (sockets, procesy, perzistence, přihlášení, file_events). Pole se ořezávají na 512 znaků, IP se ověřují, `Ok(None)` pro ID, které nás nezajímá. auditd a Velociraptor: neimplementováno (jen návrh adaptéru ve studii 08). |
| korelace | `src/endpoint/correlate.rs` | `HostDirectory` (identita Unique, Ambiguous, Unknown), `EndpointStore` (deduplikace otiskem, řazení podle času události, limity: události na host 4 096, hostů 20 000, 2 000 událostí na host a cyklus, budoucnost +1 h, stáří 24 h), `assess` (verdikt hosta z indikátorů s vahami, neškodné vzory jen pro známý podepsaný proces s pravidelností a stářím, smazané při jakémkoli podezření), `EndpointView::signal` (Suspicious, Benign, NoSignal, NoCoverage), pokrytí (`EndpointCoverage`), `link_flows` (Community ID nebo trojice + tolerance 120 s), `estimate_skew` (medián aspoň z 5 dvojic, ořez ±600 s), `alert_finding`. |
| perzistence a příjem | `src/endpoint/persist.rs`, `server.rs`, `main.rs` | tabulka `endpoint_events` v `engine-state.sqlite` (UNIQUE otisk, strop 500 000 řádků, stáří), `POST /api/endpoint/ingest?format=` (`findings.write`, CSRF, tělo ≤ 8 MiB), CLI `endpoint ingest --workspace --format --file` (po dávkách). |
| jádro | `engine.rs`, `verify_ladder.rs`, `protection.rs`, `pipeline/v3.rs`, `model.rs` | `V3Features::endpoint` (mimo `recommended()`, platí jen s `protect` a `memory`), `CheckId::Endpoint` (L1, cena 0,1; LR 12 podezřelé, 0,3 neškodné), nedostupné (`Unavailable`) bez pokrytí, u chráněného případu neškodný signál = `Undetermined`; typ `endpoint_alert` v chráněných typech; `RunReport.endpointCoverage`; produkce načte události, přiřadí identitu proti inventáři, přidá nálezy a předá pohled žebříku. |
| simulace | `src/soak/endpoint_sim.rs`, `episode.rs`, `ladder_env.rs`, `main.rs` | `--endpoint on|off`, `--endpoint-coverage %`, `--endpoint-agent honest|silent|ok`; generátor odvozený z rodin a benigních vzorů (viz A4), počítadla `endpoint_*` v `k7`. |
| vyhodnocení | `tools/soak_k8.py` | párové rozdíly s bootstrapem po sítích, prahy E1 až E11. |

**Testy.** Jednotkové (`endpoint::correlate::tests`: identita, sklad, shell z web serveru, neškodný vzor jen starý a čistý, chybějící telemetrie není neškodná, spojení s toky a posun hodin; `endpoint::tests`: vzorové záznamy, neplatné záznamy, limity dávky, ořez polí, UTF-8; `endpoint::persist::tests`), ladder (`endpoint_benign_never_refutes_protected_case`, `endpoint_benign_alone_does_not_refute_unprotected_case`, `endpoint_benign_with_other_benign_evidence_can_refute_with_audit_reason`, `endpoint_suspicious_raises_belief_and_missing_coverage_changes_nothing`), fuzz parserů (`fuzz_parsers_never_panic`, 20 000 průchodů na formát, v měření 100 000 přes `SALTICUS_FUZZ_N`), soak (`endpoint_world_is_inert_without_switch_deterministic_and_keeps_protection`: svět s agenty bez přepínače je bit po bitu v3, determinismus, 0 chráněných zavření a 0 zavření chráněného koncovým signálem v režimech honest 100 %, honest 30 %, silent a ok).

## D) Měření

Čtyři ladicí seedy 20261102 až 20261104 a 20262201, 20262202, 40 sítí každý (200 sítí, 6 362 útoků), párově proti `off`, engine v3 s presetem kroku 7, `--endpoint on`. Podrobné tabulky: `k8/vysledky.md` (přepočet `python tools/soak_k8.py`). Drženy zůstaly seedy kroku 7 a ICS, nebyly použity.

| rameno | detekce | FP/síť-den | zobrazeno/síť-den | zavřeno omylem | útoky s omylem zavřeným nálezem |
|---|---:|---:|---:|---:|---:|
| off | 83,9 % | 15,1 | 140,4 | 1,4 % | 41 |
| on100 (všichni hosté mají agenta) | 90,7 % | 16,0 | 145,2 | 1,1 % | 25 |
| on60 | 88,2 % | 15,7 | 143,1 | 1,8 % | 44 |
| on30 | 86,5 % | 15,3 | 141,4 | 2,3 % | 62 |
| comp-silent (kompromitovaný agent mlčí) | 83,9 % | 15,3 | 140,6 | 1,4 % | 45 |
| comp-ok (kompromitovaný agent hlásí „v pořádku“) | 83,9 % | 16,0 | 142,0 | 1,6 % | 50 |

Párově `on100` − `off`: detekce +6,8 p. b. (+6,1 až +7,5), exploit_attempt +33,6 (+29,5 až +37,8), lateral_movement +11,3 (+9,0 až +13,9), c2_beacon +8,7 (+6,4 až +11,0), pomalé c2 (≤ 0,5×) +5,0 (+1,3 až +9,4); FP poměr 1,060, zobrazeno 1,034.

### Prahy

| práh | výsledek |
|---|---|
| E1 až E11 | splněno (hodnoty v `k8/vysledky.md`) |
| E12 fuzz parserů a limity | splněno: test `fuzz_parsers_never_panic` prošel (0 paniků), limity drženy |
| E13 determinismus a kompatibilita | splněno: `endpoint_world_is_inert_without_switch_deterministic_and_keeps_protection`, golden snapshot zelený, výstup `legacy` a v3 bez přepínače shodný s krokem 7 |
| E14 paniky a porušené invarianty | 0 a 0 ve všech ramenech |

Plná sada `cargo test --lib`: 529 prošlo, 6 selhalo. Pět selhání je v testech brokeru (neběží Redis, `connection refused`), šestý (`parse_mode_and_disable_list`) očekával popis sestavy bez přepínače `endpoint` a byl opraven. Clippy hlásí stejné styly varování jako před krokem (collapsible_if, sort_by_key a další); jejich počet nebyl porovnán s krokem 7.

### Omezení měření

- Simulovaná koncová telemetrie vychází z parametrických variant existujících rodin útoků. Kvalita indikátorů proti skutečným záznamům (Sysmon, Wazuh) tím není dokázána; veřejné záznamy slouží jen k testům parserů.
- `comp-ok`: kompromitovaný agent, který hlásí „v pořádku“, zvyšuje počet útoků s omylem zavřeným nálezem z 41 na 50 (v povoleném limitu, ale není nulový). Chráněné nálezy se tím nezavřou (E10: 0).
- Přínos klesá s pokrytím agenty, bez agentů (`off`) je výsledek shodný s krokem 7.

## E) Registr slepých míst po kroku 8

| slepé místo | před krokem 8 | po kroku 8 (`on100`, simulace) | kategorie |
|---|---|---|---|
| exploit_attempt | detekce kolem 40 % správného typu | +33,6 p. b. proti `off` | (a) uzavřeno měřeným účinkem, jen u hostů s agentem |
| lateral_movement | kolem 67 % | +11,3 p. b. | (a) u hostů s agentem |
| c2_beacon (pomalé tempo ≤ 0,5×) | 37 až 61 % | +5,0 p. b. (+1,3 až +9,4) | (b) zmírněno, zbývá mezera |
| host bez agenta nebo kompromitovaný agent | nepokryto | pokrytí a mlčící agent viditelné v reportu (`endpoint_covered_host_cycles`), mlčící agent síťovou cestu nezhoršuje | (c) vynucené omezení: koncový „neškodný“ signál nikdy sám nezavře chráněný nález |
| kvalita indikátorů na skutečných záznamech | nezměřeno | nezměřeno (jen simulace a testy parserů) | otevřené, vyžaduje veřejné záznamy nebo vlastní laboratoř |

Zbývá: změřit přínos v dlouhém běhu s presetem kroku 8 (`endpoint` zapnuto) a na držených seedech, zvážit zapnutí v `recommended()` až po tomto běhu.
