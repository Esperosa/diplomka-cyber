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
- **nuclei**: **1 reálný nález** — `salticus-prometheus-metrics-exposed` na `/metrics`, ručně potvrzeno (`curl http://127.0.0.1:3000/metrics` vrací 200 a skutečné aplikační metriky, včetně LLM token počítadel — tahle verze Juice Shopu má AI funkce).

**Důležitá korekce vlastního předpokladu:** před implementací jsem (a nezávislá revize) předpokládal, že žádná z 8 kurátorovaných nuclei šablon (cílených na admin panely jako Swagger/Grafana/Actuator) na Juice Shopu nesedne, a 0 nálezů bude správný nulový výsledek — stejný vzorec jako honestní nulový výsledek v Deliverable 3. **Reálné měření to vyvrátilo.** Test byl napsán na předpokládaný výsledek, pak opraven na změřenou realitu, jakmile se ukázala. Přesně tohle je důvod, proč dělat aktivní verifikaci, a ne jen teoreticky odhadovat, co cíl vystavuje.

## Deliverable 8 — zavření smyčky na reálných datech

`build_hypotheses_from_lab_scan()` propojuje lab sken se **stejnou nezměněnou produkční logikou** jako kdekoliv jinde v projektu (`score_services` → `build_report` → `generate_findings` → `hypothesis::build_hypothesis` pro každý `Finding`). Poprvé v celé diplomce je celý pipeline **Observation → Finding → Hypothesis → Verification Planner** demonstrovaný společně na reálně změřeném nálezu, ne na syntetické fixtuře:

- Test `full_pipeline_plans_next_verification_for_real_metrics_exposure_finding` postaví hypotézu z reálného `prometheus-metrics-exposed` nálezu a definuje 3 kandidáty na další ověření (přečíst obsah endpointu / širší nuclei rescan / eskalovat na člověka — čísla jsou poctivé odhady, ne měřená, přesně stejná disciplína jako ve `verification_planner.rs`).
- `plan_verification()` správně vybral nejlevnější a nejinformativnější krok (`inspect_metrics_content`) před pomalejším rescanem a před eskalací s nejnižším odhadovaným information gain.

## Deliverable 11 — skutečné vykonání vybraného kandidáta

`execute_inspect_metrics_content()` skutečně provede GET na `/metrics` (ne odhad) a extrahuje konkrétní citlivě vyhlížející metriky. **Poprvé v celé diplomce je celý cyklus Observation → Finding → Hypothesis → Planner → EXEKUCE uzavřen na reálných datech**, ne jen navržen. Naměřeno: 7 citlivých metrik (`juiceshop_llm_input_tokens_total`, `file_uploads_count`, `file_upload_errors` a další) — konkrétní, čitelný důkaz hodnoty vybrané verifikace, ne jen "endpoint je dostupný" (to už potvrdil nuclei v Deliverable 7).

## Rozsah (vědomě odloženo)

- **Nezapojeno do CI** — vyžaduje Docker + nainstalované nmap/httpx/nuclei binárky, nastavení v CI by bylo netriviální (stahování Docker image, nmap capabilities v CI sandboxu) pro to, co je explicitně předstupeň, ne finální architektura. Lokální test, podobně jako broker/Redis testy, ale bez CI service kontejneru.
