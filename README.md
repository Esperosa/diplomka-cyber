# Skákavka

Skákavka je program pro síťovou detekci a vyhodnocení hrozeb. Spojuje aktivní inventář služeb, kontext zranitelností a pasivní síťové události (Suricata EVE JSON, logy Zeeku) do nálezů, které lze zpětně prověřit. Nález nevzniká jako jediné skóre. Program k němu vede hypotézy o tom, co se děje, ověřuje je v kontrolovaných krocích, pamatuje si, jak dopadly podobné případy, a zásahy do sítě navrhuje, ale provede je jen po schválení.

Název balíčku, binárky (`bakula-program`), konfigurace (`bakula.toml`) a proměnných prostředí zůstává z dřívějšího pracovního názvu *Bakula*. Jde o tentýž projekt.

Veřejná softwarová příloha prací na FIM UHK. Kód je v `src/`, testy v `tests/`, webové UI v `ui/` (zdroje v `ui-src/`), dokumentace v `docs/`.

## Co program dělá

- **Inventář a kontext:** hosty a služby z aktivního zjišťování, normalizace služeb, přiřazení CPE a veřejného CVE/CVSS kontextu.
- **Pasivní události:** import ze Suricaty a Zeeku, sloučení pozorování téhož toku z více senzorů (Community ID) s korekcí závislosti zdrojů.
- **Hypotézy:** každý nález nese hypotézy o příčině, včetně neškodných vysvětlení, s vyjádřenou nejistotou.
- **Verzované ověřování:** plán kontrol (pasivních, čistě čtecích i aktivních) podle očekávané hodnoty informace, v mezích zadaného rozsahu. Pravidla a prahy mají verze, takže lze zpětně určit, podle čeho se rozhodlo.
- **Paměť případů:** uložené výsledky dřívějších případů ovlivňují řazení a zavírání nálezů. Nález s chráněnými rysy se automaticky nezavírá.
- **Schválené zásahy:** návrhy blokování (`enforce.block_ip`) schvaluje operátor, výchozí režim je simulace (dry-run). Audit je append-only s hash-řetězem.
- **Report:** validační stopa, manifest s kontrolními hashi, webové UI a HTTP API.

## Architektura

Stručně: ingest (aktivní inventář, Zeek, Suricata, koncová telemetrie) → normalizace a identita zařízení → korelace a fúze → hypotézy → plánovač ověření → rozhodnutí, triage a paměť případů → report, UI, API a schvalované zásahy. Dlouhé běhy a měření obstarává simulační soak harness.

Podrobněji:

- [Technický návrh](docs/diplomka/BAKULA_kompletni_technicky_navrh_diplomova_prace.md)
- [Model hrozeb](docs/diplomka/threat-model.md)
- [Produkční plán](docs/diplomka/produkcni-plan.md)
- [Souhrn výsledků a hypotéz](docs/diplomka/souhrn-vysledku-a-hypotez.md)
- [Soak harness](docs/diplomka/eval/soak-harness.md)
- [Analýza pipeline](docs/ANALYZA_PIPELINE_A_AUTOPILOT.md), [konektory a lane](docs/CONNECTORS_A_LANES.md), [enterprise backendy](docs/ENTERPRISE_BACKENDS.md)

## Sestavení a spuštění

Vyžaduje Rust toolchain (edice 2024) a pro UI Node.js s npm. Nmap, Suricata, Zeek a ProjectDiscovery `httpx`/`nuclei` jsou potřeba jen pro příslušné volitelné scénáře.

```powershell
npm install
npm run build:ui
cargo build --release
cargo test
npm run test:ui
cargo run -- demo e2e --workspace .\workspace
cargo run -- server spust --workspace .\workspace
```

Webové UI se poté otevře na `http://127.0.0.1:8080`. Přehled příkazů vypíše `cargo run -- --help`; hlavní skupiny jsou `simulace`, `beh`, `autopilot`, `monitor`, `overeni`, `evaluace`, `server`, `config`, `readiness`, `platform`, `broker`, `demo`, `endpoint` a `soak`.

Šest testů, které čtou lokální neveřejný workspace `workspace_fullstack`, je označeno `#[ignore]`. Kde workspace existuje, spustí je `cargo test -- --include-ignored`.

### Docker

```bash
cp .env.example .env   # vyplňte BAKULA_API_TOKEN
docker compose up --build
```

Kompozice sestaví image z [`Dockerfile`](Dockerfile), spustí Redis (broker pro distribuované workery) a server s `--require-api-token`. Bez platného `BAKULA_API_TOKEN` se kompozice zastaví, místo aby běžela bez autentizace. Workspace přežívá restarty v named volume. Aktivní skenování (`--spustit-nmap`) potřebuje `nmap`, který image obsahuje. `httpx` a `nuclei` v image nejsou, připojte je jako volume a nastavte `--httpx-bin` a `--nuclei-bin`.

## Konfigurace

- Soubor `bakula.toml`: `config init` ho vytvoří, `config validate` zkontroluje.
- Proměnné prostředí (vzor v [`.env.example`](.env.example)): `BAKULA_API_TOKEN`, `BAKULA_ENFORCEMENT_MODE` (`dry_run` je výchozí, skutečné blokování zapne jen hodnota `enforce`), `BAKULA_PROTECTED_RANGES`, `BAKULA_LOG`, `BAKULA_LOG_FORMAT`.
- CVE kontext: `--provider nvd` nebo `vulners` s klíčem v `NVD_API_KEY` nebo `VULNERS_API_KEY`; `ABUSEIPDB_API_KEY` pro intel enrichment. Bez nich (`--provider demo`) report používá ukázkový kontext, ne reálný.
- Logy jdou přes `tracing` na stderr, metriky na `/api/metrics` (Prometheus).

## Bezpečnostní model

- Nic neblokuje a nespouští aktivní akci, dokud to provozovatel výslovně nezapne. Plán ověření se vždy jen zapisuje, vykonání kontrol je za `--execute-verification` a kontroly vyžadující schválení se nespustí samy.
- Rozsah (`--scope`) se kontroluje při plánování i při vykonání. Cíle mimo rozsah se vyřadí a vykážou.
- Zásahy mění jen vlastní tabulku `inet bakula` v nftables, bloky mají časový limit (strop 24 h) a loopback, link-local, multicast a nakonfigurované chráněné rozsahy nelze zablokovat ani na výslovnou žádost.
- API: výchozí režim bez tokenu je jen pro lokální použití, pro provoz zapněte `--require-api-token`. Mutující endpointy chrání hlavička proti CSRF a token se porovnává v konstantním čase.
- Audit je append-only a `/api/audit/verify` ověří, že historie nebyla změněna.
- Aktivní skenování používejte jen v prostředí, ke kterému máte oprávnění. Hlášení zranitelností a pravidla použití jsou v [SECURITY.md](SECURITY.md). Šablony webových kontrol jsou v `resources/nuclei-templates/controlled/`.

## Datasety a zdroje

Měření používají veřejné datasety a vlastní simulaci. Přesné URL, kontrolní součty výřezů a odchylky jsou v [registru datasetů](docs/diplomka/dataset-registry.md). Licence jsou uvedeny tak, jak je zapsáno v registru:

| Dataset | Licence podle registru |
|---|---|
| IoT-23 (Stratosphere IPS / CTU) | CC BY-NC-SA 4.0, pro výzkum |
| CTU-13 (Stratosphere IPS / CTU) | CC BY-NC-SA 4.0, pro výzkum |
| CIC-IDS2017 (přegenerovaná verze Engelen a kol.) | bez výslovné licence, obě stránky žádají citaci (Sharafaldin, Lashkari, Ghorbani, ICISSP 2018; Engelen a kol., IEEE SPW/WTMC 2021) |
| UNSW-NB15 | „Free use of the UNSW-NB15 dataset for academic research purposes is hereby granted in perpetuity. Use for commercial purposes should be agreed by the authors.“ Citovat pět článků z oficiální stránky |

V repozitáři jsou jen malé výřezy IoT-23. Ostatní datasety se nedistribuují a stahují se podle registru. Seznam zdrojů a licencí včetně Rust závislostí je v [NOTICE.md](NOTICE.md), literární podklady studií v `docs/diplomka/studie/`.

## Metodika testování

- **Soak harness:** `bakula-program soak run` spouští dlouhé běhy nad simulovanými sítěmi s ground truth (rodiny útoků, neškodné protějšky, výpadky telemetrie). Běží produkční funkce, ne zjednodušený model. `soak verify` znovu přehraje náhodné bloky a porovná otisky bit po bitu. Popis je v [soak-harness.md](docs/diplomka/eval/soak-harness.md).
- **Deterministické seedy:** síť i epizoda vznikají ze seedu běhu a čísla sítě, takže každé měření jde zopakovat.
- **Držené sady:** ladění probíhá na ladicích seedech, hodnocení na seedech, které se při ladění nepoužily, a na zamčených testovacích částech veřejných datasetů, spuštěných jednou.
- **Intervaly:** podíly se uvádějí s 95% Wilsonovým intervalem, srovnání ramen jsou párová po sítích.
- **Předregistrované prahy:** prahy se zapisují a zamykají commitem před měřením. Odchylky se zapisují zvlášť a nesplněné prahy se uvádějí.

Postup podle kroků je v [`docs/diplomka/eval/`](docs/diplomka/eval/) (`impl-krok1.md` až `impl-krok8.md`).

## Aktuální stav

<!-- STATUS:BEGIN -->
_Tento blok generuje `tools/readme_status.py` z dokumentů v `docs/diplomka/eval/` a z gitu. Ručně se neupravuje._

- Poslední commit: `384ec6d` ze dne 2026-11-13 (docs: sjednocení formulací o revizích a rozhodnutích o rozsahu, neutrální pracovní cesty)
- Počet unit testů knihovny (`cargo test --lib -- --list`): 566

- Výkon sítí XXXL (G4, držené seedy): p99 cyklu 1,08 s a 0,43 s, práh < 3 s, splněno.

- Předregistrované prahy kroku 7 (B6): splněno 15 z 18; nesplněno: L1; ostatní (hlásí se, bez prahu): 2
- Předregistrované prahy kroku 8 (E1 až E11): splněno 11 z 11

#### Krok 7: držené seedy 20261901 a 20262001 (svět k7)

| rameno | sítí | útoků | detekce mikro | FP/síť-den | zobrazeno/síť-den | zavřeno omylem (G3) |
|---|---|---|---|---|---|---|
| v3k6 | 80 | 2934 | 77,9 (74,7 až 81,2) | 28,4 | 153,8 | 1,4 % (1,0 až 2,0) [30/2153] |
| legacy | 80 | 2934 | 62,6 (59,5 až 65,5) | 919,0 | 8993,1 | – % (0,0 až 100,0) [0/0] |
| v3k7 | 80 | 2934 | 80,3 (77,2 až 83,2) | 29,9 | 183,7 | 1,4 % (0,9 až 2,2) [17/1232] |

Detekce a podíl zavřených omylem jsou s 95% Wilsonovým intervalem v závorce; FP/síť-den jsou falešné poplachy na síť a virtuální den.

#### Detekce po rodinách útoků (držený běh, Wilsonův 95% interval)

| rodina | n | v3k6 | legacy | v3k7 |
|---|---|---|---|---|
| apt_chain | 59 | 94,9 % (86,1 až 98,3) | 96,6 % (88,5 až 99,1) | 94,9 % (86,1 až 98,3) |
| c2_beacon | 257 | 67,7 % (61,8 až 73,1) | 35,8 % (30,2 až 41,8) | 71,2 % (65,4 až 76,4) |
| credential_stuffing | 183 | 86,9 % (81,2 až 91,0) | 86,3 % (80,6 až 90,6) | 87,4 % (81,8 až 91,5) |
| cryptomining | 118 | 83,9 % (76,2 až 89,4) | 41,5 % (33,0 až 50,5) | 86,4 % (79,1 až 91,5) |
| ddos_volume | 73 | 84,9 % (75,0 až 91,4) | 83,6 % (73,4 až 90,3) | 84,9 % (75,0 až 91,4) |
| dns_tunnel | 120 | 73,3 % (64,8 až 80,4) | 44,2 % (35,6 až 53,1) | 76,7 % (68,3 až 83,3) |
| exfiltration | 202 | 89,1 % (84,1 až 92,7) | 18,8 % (14,0 až 24,8) | 88,6 % (83,5 až 92,3) |
| exploit_attempt | 276 | 33,0 % (27,7 až 38,7) | 25,4 % (20,6 až 30,8) | 35,5 % (30,1 až 41,3) |
| fleet_beacon | 46 | 73,9 % (59,7 až 84,4) | 63,0 % (48,6 až 75,5) | 80,4 % (66,8 až 89,3) |
| ics_attack | 10 | 70,0 % (39,7 až 89,2) | 80,0 % (49,0 až 94,3) | 80,0 % (49,0 až 94,3) |
| insider_hoarding | 45 | 88,9 % (76,5 až 95,2) | 86,7 % (73,8 až 93,7) | 91,1 % (79,3 až 96,5) |
| lateral_movement | 220 | 72,7 % (66,5 až 78,2) | 72,7 % (66,5 až 78,2) | 86,8 % (81,7 až 90,7) |
| port_scan_horizontal | 224 | 75,4 % (69,4 až 80,6) | 77,7 % (71,8 až 82,6) | 77,2 % (71,3 až 82,2) |
| port_scan_vertical | 240 | 86,7 % (81,8 až 90,4) | 52,9 % (46,6 až 59,1) | 87,5 % (82,7 až 91,1) |
| ransomware | 86 | 89,5 % (81,3 až 94,4) | 89,5 % (81,3 až 94,4) | 89,5 % (81,3 až 94,4) |
| rogue_device | 45 | 95,6 % (85,2 až 98,8) | 33,3 % (21,4 až 47,9) | 95,6 % (85,2 až 98,8) |
| slow_scan | 188 | 84,0 % (78,1 až 88,6) | 87,8 % (82,3 až 91,7) | 85,1 % (79,3 až 89,5) |
| ssh_bruteforce | 341 | 92,4 % (89,1 až 94,7) | 89,4 % (85,7 až 92,3) | 93,0 % (89,7 až 95,2) |
| web_exploit | 201 | 82,6 % (76,7 až 87,2) | 79,6 % (73,5 až 84,6) | 83,1 % (77,3 až 87,6) |

#### Krok 8, vyhodnocení (5 seedů x 40 sítí)

| rameno | sítí | útoků | detekce | FP/síť-den | zobrazeno/síť-den | zavřeno omylem | útoky s omylem zavřeným nálezem |
|---|---|---|---|---|---|---|---|
| off | 200 | 6362 | 83,9 (82,9 až 84,8) | 15,1 | 140,4 | 1,4 % (1,1 až 1,9) | 41 |
| on100 | 200 | 6362 | 90,7 (89,9 až 91,4) | 16,0 | 145,2 | 1,1 % (0,8 až 1,6) | 25 |
| on60 | 200 | 6362 | 88,2 (87,3 až 88,9) | 15,7 | 143,1 | 1,8 % (1,3 až 2,3) | 44 |
| on30 | 200 | 6362 | 86,5 (85,6 až 87,3) | 15,3 | 141,4 | 2,3 % (1,9 až 2,8) | 62 |
| comp-silent | 200 | 6362 | 83,9 (82,9 až 84,8) | 15,3 | 140,6 | 1,4 % (1,1 až 1,9) | 45 |
| comp-ok | 200 | 6362 | 83,9 (83,0 až 84,8) | 16,0 | 142,0 | 1,6 % (1,2 až 2,1) | 50 |

#### Dlouhý běh (soak, závěrečný report)

- Simulovaných sítí: 7 988  virtuálních síť-dnů: 77 770  cyklů: 3 732 960
- Porušené invarianty: 0, paniky: 0
- Falešné poplachy bez přiřaditelné příčiny: 101 137 895 (1300 na síť-den; interní měřicí metrika, nejde o zobrazené položky)
- Sítě XXXL (> 6000 zařízení): 118 sítí, detekce 78,5 % (76,7 až 80,1) z 2313 útoků

| rodina | útoků | detekováno (jakýkoli nález) | správný typ nálezu |
|---|---|---|---|
| apt_chain | 5448 | 98,2 % (97,8 až 98,5) | 97,2 % (96,8 až 97,6) |
| c2_beacon | 23751 | 85,5 % (85,1 až 86,0) | 70,4 % (69,8 až 70,9) |
| credential_stuffing | 16156 | 94,2 % (93,9 až 94,6) | 85,0 % (84,4 až 85,5) |
| cryptomining | 10851 | 92,0 % (91,5 až 92,5) | 81,6 % (80,9 až 82,3) |
| ddos_volume | 7385 | 90,4 % (89,7 až 91,1) | 86,5 % (85,7 až 87,3) |
| dns_tunnel | 10695 | 96,2 % (95,8 až 96,5) | 90,3 % (89,7 až 90,8) |
| exfiltration | 17588 | 92,8 % (92,4 až 93,1) | 89,9 % (89,5 až 90,4) |
| exploit_attempt | 25572 | 74,6 % (74,0 až 75,1) | 42,5 % (41,9 až 43,1) |
| fleet_beacon | 3468 | 93,5 % (92,6 až 94,3) | 74,3 % (72,9 až 75,8) |
| ics_attack | 671 | 87,2 % (84,4 až 89,5) | 55,6 % (51,8 až 59,3) |
| insider_hoarding | 4998 | 96,0 % (95,4 až 96,5) | 94,3 % (93,6 až 94,9) |
| lateral_movement | 22355 | 96,8 % (96,5 až 97,0) | 91,1 % (90,7 až 91,5) |
| port_scan_horizontal | 18263 | 94,9 % (94,5 až 95,2) | 90,6 % (90,1 až 91,0) |
| port_scan_vertical | 22339 | 89,7 % (89,3 až 90,1) | 85,6 % (85,1 až 86,1) |
| ransomware | 7197 | 98,4 % (98,1 až 98,6) | 97,7 % (97,4 až 98,1) |
| rogue_device | 5454 | 98,5 % (98,1 až 98,8) | 97,5 % (97,0 až 97,9) |
| slow_scan | 17839 | 97,2 % (97,0 až 97,4) | 93,9 % (93,5 až 94,2) |
| ssh_bruteforce | 29601 | 94,0 % (93,7 až 94,2) | 88,4 % (88,0 až 88,7) |
| web_exploit | 16995 | 91,5 % (91,1 až 92,0) | 80,6 % (80,0 až 81,2) |

#### Známá slepá místa (registr po kroku 7)

| # | slepé místo | stav | měření (držený `v3k7`) |
|---|---|---|---|
| 1 | Kontext zavírá útoky | **zadrženo** | zavřeno omylem 17 / 1 232 = 1,4 %; ztráta viditelnosti kontextem 0 útoků |
| 2 | Vyvrácení žebříkem skryje útok | **částečně** | 14 útoků ztratilo viditelnost vyvrácením (krok 6: 15) |
| 3 | Tiché zapomenutí (24 h bez výskytu) | zůstává | 39 útoků (`quiet`), krok 6: 63 |
| 4 | c2_beacon bez detektoru majáku | **nezobecňuje** | LOFO 30,8 % (19,9 až 44,3) |
| 5 | exploit_attempt | zůstává (b) | 35,5 % (30,1 až 41,3; n = 276), nejslabší i ve všech úrovních os |
| 6 | Krátký útok (doba 0,25× až 0,5×) | zůstává (b) | c2 0,25× 54,5 %, port_scan_horizontal 0,5× 48,1 % |
| 7 | Rozložený útok (10 a 30 zdrojů) | **částečně** | osa zdrojů v (a); exploit_attempt × 3 zdroje 24,5 %, dns_tunnel × 10 58,1 % |
| 8 | Provozní poruchy jako podezření | zůstává | K3p: držené varianty 77 až 100 % výskytů s FP ve frontě podezření |
| 9 | Nová cloudová služba více klientů (`saas_group`) | **vědomá cena** | 85,7 % výskytů s FP (krok 6: 75,0 %) |
| 10 | Zátěž analytika | **nové** | 183,7 zobrazených na síť-den (krok 6: 153,8) |
| 11 | Habituace dvojic útoku bez poplachu | zůstává | 160 útoků |
| 12 | ics_attack | (b) | 69,2 % (58,3 až 78,4), n = 78 |
| 13 | Výpadek senzoru a nezralý profil | **viditelné** | `coverageStatus`: `telemetry_gap`, `immature_profiles`; nálezy v okně jsou chráněné (P4) |
| 14 | Reálná data po zrání profilu | otevřené | D4: IoT-23 jen studený start |
<!-- STATUS:END -->

Po každém pushnutí spusťte `python tools/readme_status.py` a výsledek commitněte. Skript přepisuje jen blok mezi značkami. `python tools/readme_status.py --check` blok nezapisuje a vrátí 1, když je zastaralý. Test skriptu: `python tools/test_readme_status.py`.

## Licence

Zdrojový kód je pod licencí MIT, viz [LICENSE](LICENSE). Datasety, písma a externí nástroje mají vlastní licence, viz [NOTICE.md](NOTICE.md).
