# Fingerprinting služeb a pasivní analýza síťového provozu

Veřejná softwarová příloha mé bakalářské práce na FIM UHK. Prototyp v Rustu spojuje aktivní inventář služeb, kontext zranitelností a vybrané pasivní síťové události do nálezů, které lze zpětně prověřit.

**Role:** návrh a implementace prototypu, webového rozhraní, testů a ověření vydaného balíčku.  
**Stack:** Rust, Axum, TypeScript/CSS, Nmap, Suricata, Zeek, CPE/CVE/CVSS.  
**Stav:** vzešlo z bakalářské práce, nyní rozvíjené v navazující diplomové práci směrem k produkční kvalitě (bezpečnostní opravy, Docker nasazení, cross-run identita napříč běhy – viz [produkční plán](docs/diplomka/produkcni-plan.md)); žádné reálné nasazení ještě neproběhlo a některé vrstvy (distribuovaný multi-host provoz na Postgres, multi-tenant, vlastní packet-path enforcement) zůstávají vědomě odložené s konkrétními spouštěcími podmínkami.

## Co projekt řeší

Samotný seznam otevřených portů nevysvětluje, co na nich běží ani které události se k nim vztahují. Projekt proto skládá několik kroků do jedné kontrolovatelné cesty:

1. Inventář hostů a služeb z aktivního zjišťování.
2. Normalizace služeb a přiřazení CPE a veřejného CVE/CVSS kontextu.
3. Import událostí ze Suricata EVE JSON a logů Zeeku.
4. Korelace událostí k hostům/službám, skórování a triage nálezů.
5. Report s validační stopou a manifestem s kontrolními hashi.

Kód je v `src/`, testy v `tests/`, statické UI v `ui/` a jeho zdroje v `ui-src/`. Podrobnější architektura, workflow a limity jsou v [docs](docs/).

## Jak si projekt ověřit

Před zveřejněním prošly lokálně `cargo fmt --check`, `npm run build:ui`, `npm run test:ui`, `cargo test` a `cargo build --release`. Release [`v0.1.0-thesis`](https://github.com/Esperosa/service-fingerprinting-passive-analysis/releases/tag/v0.1.0-thesis) byl navíc ověřen z balíčku staženého z GitHubu: spuštění EXE, demo E2E běh a odpověď serveru na UI a health endpoint. Přesné kroky a hash balíčku jsou v [protokolu ověření](docs/RELEASE_VERIFICATION_2026-04-23.md).

Při každém pushi a pull requestu běží [CI](.github/workflows/ci.yml): `cargo fmt --check`, `cargo clippy` (informativně), `cargo test` a `npm run build:ui`. Šest unit testů, které čtou lokální neveřejný workspace `workspace_fullstack`, je označeno `#[ignore]`; kde tento workspace existuje, spustí se příkazem `cargo test -- --include-ignored`.

### Rychlý start ze zdrojů

Vyžaduje Rust toolchain a Node.js/npm. Nmap a další externí nástroje jsou potřeba jen pro příslušné volitelné scénáře.

```powershell
npm install
npm run build:ui
cargo test
npm run test:ui
cargo run -- demo e2e --workspace .\workspace
cargo run -- server spust --workspace .\workspace
```

Webové UI se poté otevře na `http://127.0.0.1:8080`.

### Nasazení (Docker)

```bash
cp .env.example .env   # vyplň BAKULA_API_TOKEN (viz níže)
docker compose up --build
```

To postaví image z [`Dockerfile`](Dockerfile), spustí Redis (broker pro
distribuované worker procesy, H5) a server s `--require-api-token`
zapnutým ve výchozím stavu kompozice – bez platného `BAKULA_API_TOKEN` se
`docker compose up` spolehlivě zastaví (fail-closed), namísto tichého běhu
bez autentizace. Workspace (`runs/`, `platform.sqlite`,
`identity-registry.json`) přežívá restarty v named volume `bakula-workspace`.

Pro rychlé vyzkoušení bez tokenu (jen lokálně, ne přes nedůvěryhodnou síť):

```bash
docker compose run --rm -p 8080:8080 bakula server spust --workspace /data/workspace --host 0.0.0.0
```

Lokálně neověřeno (vývojové prostředí této práce má rozbité Docker Desktop –
daemon se nespustí), ale CI (`.github/workflows/ci.yml`, job „Docker build
smoke test") image skutečně sestaví, spustí kontejner a ověří odpověď na
`/api/health` na reálném Linuxu – první běh po tomto Dockerfile prošel.

Aktivní skenování (`--spustit-nmap`) potřebuje `nmap` (v image je přes apt);
volitelné web kontroly (`--web-fingerprint`/`--web-checks`) potřebují
`httpx`/`nuclei` z [ProjectDiscovery](https://github.com/projectdiscovery) –
nejsou v image zabalené (vlastní release/checksum cyklus), mountni je do
kontejneru nebo nastav `--httpx-bin`/`--nuclei-bin`. Reálný CVE kontext
potřebuje `--provider nvd` nebo `vulners` + odpovídající API klíč v
proměnné prostředí (`NVD_API_KEY`, `VULNERS_API_KEY`, `ABUSEIPDB_API_KEY`
pro intel enrichment) – bez nich (`--provider demo`) report ukazuje
smyšlený CVE kontext, ne reálný.

## Provozní vrstva: ověřování, zásahy, audit

Vše níže je **bezpečné ve výchozím stavu** – nic nespouští ani neblokuje, dokud to provozovatel výslovně nezapne.

| Co | Jak se zapíná | Čeho se drží |
|---|---|---|
| Plán ověření (`verification_plans` v reportu) | vždy, jen zápis | žádná aktivní akce |
| Vykonání vybraných kontrol | `--execute-verification` | scope se kontroluje znovu při vykonání, kontroly vyžadující schválení (aktivní sken) se nikdy nespustí samy, rozpočet `--verification-max-checks`, odstup mezi kontrolami na stejný cíl, stejná kontrola se nespouští dvakrát |
| Inkrementální čtení logů | `--incremental-ingest` (u `monitor --continuous` automaticky) | čte jen nové řádky, kurzor se posune až po uloženém běhu, rotace logu je vidět |
| Zásahy `enforce.block_ip` | API `/api/enforcement/*`, tlačítka v UI | navrhuje analytik, schvaluje operátor/admin; **dry-run je výchozí**, skutečné `nft` jen s `BAKULA_ENFORCEMENT_MODE=enforce` |
| Audit | vždy | append-only, hash-řetěz (`/api/audit/verify` ověří, že historie nebyla změněna) |

Zásahy upravují **výhradně vlastní** tabulku `inet bakula` v nftables (jen `drop` nad dvěma sety s časovým limitem, takže blok vyprší i při pádu aplikace). Loopback, link-local, multicast a rozsahy z `BAKULA_PROTECTED_RANGES` (brána, DNS, management) nejdou zablokovat ani na výslovnou žádost; TTL má strop 24 h. Nezávislá kontrola každou minutu odstraní prvky v jádře bez aktivní akce a označí akce, jejichž prvek v jádře chybí. `enforce` má smysl jen tam, kde `bakula` běží přímo na bráně s právem `CAP_NET_ADMIN` – v kontejneru bez `--network host` by se blokovala jen síť kontejneru.

Logy jdou na stderr přes `tracing` (`BAKULA_LOG=debug`, `BAKULA_LOG_FORMAT=json`), metriky na `/api/metrics` (Prometheus). API tokeny platformy vypršejí po 90 dnech (`platform token issue --ttl-days N`, `0` = bez vypršení).

**Pojmenování:** projekt vznikal pod pracovním názvem *Bakula*. Ten zůstává v technických identifikátorech – crate a binárka `bakula-program`, konfigurace `bakula.toml`, ID šablon `bakula-*` a název ZIP balíčku ve vydání – aby odpovídaly ověřenému release `v0.1.0-thesis` a odkazům v práci. Jde o tentýž projekt.

## Rozsah a bezpečnost

Repozitář obsahuje demo a referenční data pro lokální ověření, ale ne historické soukromé workspaces, lokální logy, build cache ani zdrojové texty bakalářské práce. Aktivní skenování používejte jen v prostředí, ke kterému máte oprávnění; šablony pro webové kontroly jsou v `resources/nuclei-templates/controlled/`.

Tento kořenový URL repozitáře je stabilní odkaz uvedený v příloze práce. Zdrojový kód je pod licencí MIT, viz [LICENSE](LICENSE); externí nástroje mají vlastní licence.
