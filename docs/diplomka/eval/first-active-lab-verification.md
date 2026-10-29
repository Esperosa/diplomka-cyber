# První reálná aktivní verifikace proti autorizovanému lab cíli (Deliverable 7)

**Status: implementováno a testováno (29. 10. 2026).** Nový modul `src/lab.rs`. Navazuje na Deliverable 5 (`verification_planner.rs` — VOI selekce kandidátů, bez exekuce) — tohle je první krok, který skutečně NĚCO aktivně provede, ne jen vybere.

## Proč ne hned Mininet/Containerlab

Plný síťový emulační lab (návrh sekce 8.2) je velká infrastrukturní investice (WSL2 s Linux network namespace capabilities). Rozumný předstupeň: ověřit, že aktivní overení (`nmap.rs` + `webscan.rs`) vůbec funguje end-to-end proti reálnému cíli, než se investuje do topologické emulace. Mininet/Containerlab přijde, až bude potřeba testovat topologii/segmentaci (víc hostů, VLAN, firewall pravidla) — ne pro "sken jednoho vlastního kontejneru na localhostu".

**Lab cíl: OWASP Juice Shop** (`bkimminich/juice-shop`, Docker, `127.0.0.1:3000` jen) — návrh sekci 8.2 ho jmenuje přímo jako záměrně zranitelnou aplikaci určenou ke skenování. Vlastní instance, žádné povolení třetí strany potřeba.

## Oprava prostředí nutná k tomu, aby šlo cokoliv reálně testovat

- **Správné `httpx`/`nuclei` binárky nebyly na stroji nainstalované** — na PATH byl jiný nástroj se stejným jménem `httpx` (Python HTTP klient, ne ProjectDiscovery recon nástroj). Tohle přesně odpovídalo předem potvrzené nesouvisející chybě v `tests/e2e.rs` (`autopilot_vytvori_vice_cyklu_a_automation_report`). Stáhnuty a ověřeny checksumem přesné verze z `tools/projectdiscovery/*_checksums.txt` (httpx 1.9.0, nuclei 3.7.1) z oficiálních GitHub releases, nainstalovány do `C:\Users\Creator\tools\projectdiscovery\`, cesty se předávají explicitně (`WebScanConfig.httpx_bin`/`.nuclei_bin`), ne přes PATH.
- **TCP-connect health check nestačí pro HTTP aplikaci** — port může přijímat spojení dřív, než je Express aplikace v kontejneru skutečně připravená odpovídat. První běh testu selhal (`httpx` vrátil prázdný výstup) přesně z tohoto důvodu. Opraveno na skutečný HTTP GET health check (`wait_for_http_health`).

## Co bylo skutečně naměřeno (ne předpoklad)

- **nmap**: port 3000 open, service `tcpwrapped` (Juice Shop neprozrazuje verzi/typ na nmap `-sV` úrovni).
- **httpx**: title `"OWASP Juice Shop"`, status 200 — potvrzeno reálným HTTP probe.
- **nuclei**: **1 reálný nález** — `bakula-prometheus-metrics-exposed` na `/metrics`, ručně potvrzeno (`curl http://127.0.0.1:3000/metrics` vrací 200 a skutečné aplikační metriky, včetně LLM token počítadel — tahle verze Juice Shopu má AI funkce).

**Důležitá korekce vlastního předpokladu:** před implementací jsem (a nezávislý Plan-agent review) předpokládal, že žádná z 8 kurátorovaných nuclei šablon (cílených na admin panely jako Swagger/Grafana/Actuator) na Juice Shopu nesedne, a 0 nálezů bude správný nulový výsledek — stejný vzorec jako honestní nulový výsledek v Deliverable 3. **Reálné měření to vyvrátilo.** Test byl napsán na předpokládaný výsledek, pak opraven na změřenou realitu, jakmile se ukázala. Přesně tohle je důvod, proč dělat aktivní verifikaci, a ne jen teoreticky odhadovat, co cíl vystavuje.

## Rozsah (vědomě odloženo)

- **Nenapojeno na `verification_planner.rs`** — žádná `SecurityHypothesis` o Juice Shopu ještě neexistuje, na kterou by se planner měl vztahovat. Tenhle krok jen naměřil a zapsal syrová fakta; napojení na hypotézu/planner je navazující krok.
- **Nezapojeno do CI** — vyžaduje Docker + nainstalované nmap/httpx/nuclei binárky, nastavení v CI by bylo netriviální (stahování Docker image, nmap capabilities v CI sandboxu) pro to, co je explicitně předstupeň, ne finální architektura. Lokální test, podobně jako broker/Redis testy, ale bez CI service kontejneru.
