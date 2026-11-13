# SALTICUS — kompletní koncepce, technický návrh a výzkumný plán

**Typ dokumentu:** sjednocený záznam celého brainstormingu o projektu Salticus, návrh cílové architektury a podklad pro diplomovou práci  
**Datum:** 28. října 2026  
**Projekt:** [`Esperosa/service-fingerprinting-passive-analysis`](https://github.com/Esperosa/service-fingerprinting-passive-analysis)  
**Status:** koncepční návrh; neznamená, že popsané nové funkce už existují v kódu  
**Rozsah:** pouze Salticus; nesouvisející témata z konverzace nejsou zahrnuta.

> **Jak dokument číst:** Oddíly „Současný stav“ popisují poznatky ze statického auditu repozitáře diskutovaného v chatu. Oddíly „Cílový stav“ jsou návrhy toho, co chceme vybudovat. Oddíly „Ověření“ říkají, čím budeme prokazovat, že daná vlastnost opravdu funguje. Číselné výkonnostní hodnoty jsou *návrhové cíle*, nikoliv naměřené výsledky.

---

## 1. Záměr a ambice

Salticus má vyrůst z původního bakalářského proof of conceptu zaměřeného na fingerprinting služeb a pasivní analýzu v **distribuovanou, bezpečnou, self-hosted platformu pro inventarizaci, detekci, ověřování, prevenci a řízenou reakci na síťové hrozby**. Projekt bude zároveň technickým a experimentálním základem diplomové práce.

Nejde jen o spojení Nmapu a Suricaty s hezkým dashboardem. Hlavní přidaná hodnota má být **korelační a rozhodovací engine řízený nejistotou**: ze všech dostupných signálů vytváří hypotézy, měří jejich důkazní sílu a nejistotu, volí nejefektivnější další ověření, aktualizuje závěr a dlouhodobě se z výsledků kontrol učí.

Cílové vlastnosti:

1. Zvládat sítě se stovkami, tisíci i větším množstvím zařízení; žádný pevný softwarový limit počtu hostů. Skutečné limity tvoří propustnost, stavové kapacity, počet událostí za sekundu, síťová topologie, uložiště a přidělené prostředky. **„Nekonečná škálovatelnost“ není fyzikálně ani provozně možná**; chceme horizontální škálovatelnost bez umělé hranice v datovém modelu.
2. Pracovat na jednom serveru i jako víceuzlový cluster, s oddělenou řídicí a datovou rovinou.
3. Pokrýt aktivní i pasivní monitoring, DNS, firewall, IPS, správu pravidel, síťovou segmentaci a bezpečnou reakci.
4. Vyhnout se závislosti na jediném dodavateli; přijímat telemetrii z existujících switchů, AP, controllerů a nástrojů.
5. Minimalizovat falešné poplachy, prodlevu do prvního správného podezření a do potvrzení, přitom omezovat síťovou zátěž aktivních kontrol.
6. Každý důležitý závěr vysvětlit konkrétními důkazy, zdroji, verzí pravidla/modelu, časem a nejistotou.
7. Zachovat bezpečnost a fungování lokální ochrany i při výpadku centrálního controlleru.
8. Umožnit zlepšování detekcí a šablon na základě ověřených výsledků bez nekontrolovaného automatického přepisování produkčních pravidel.
9. Ověřit analytiku na rozsáhlých globálních datech a aktivní bezpečnostní funkce v izolované autorizované laboratoři.

**Významné omezení:** síťová ochrana bez agentů v koncových OS nemůže vidět všechny lokální procesy, offline aktivity, šifrovaný obsah ani některé útoky uvnitř hosta. Salticus může velmi významně doplnit endpoint ochranu, ale nelze poctivě slíbit, že v každém prostředí plně nahradí antivirus/EDR.

---

## 2. Co už v Bakule máme (podle probíraného auditu repozitáře)

Projekt obsahuje reálnou implementaci, nejen README:

| Oblast | Současná existence | Hlavní mezera vůči cíli |
|---|---|---|
| Aktivní inventarizace | Nmap, XML parser, follow-up a forenzní zpřesnění | Adaptivní distribuované plánování a bezpečnostní limity |
| Web a TLS fingerprinting | `httpx`, řízené `nuclei` šablony, webové proby | Lepší validace identity a bezpečné template governance |
| CVE/CPE | NVD a další intel zdroje, EPSS, KEV, cache | Expirace, provenance, deduplikace, přesnější rizikový model |
| Pasivní data | Suricata EVE, Zeek notice/http/conn | Streamovací sběr s checkpointy místo načítání celých souborů |
| Toky a síťový kontext | NetFlow/IPFIX a ntopng snapshoty; SNMP/LLDP/CDP/ARP/FDB/VLAN kontext | Živé collectory a kvalitní model identity a topologie |
| Integrace | LibreNMS, Meraki, UniFi, Aruba, Omada; auditní Greenbone/Wazuh/NAPALM/Netmiko/scrapli | U části integrací jde o import snapshotu, ne skutečný dlouhodobý collector |
| Korelace | Přiřazení eventu hostu/službě, skóre, diff běhů, triage | Není to plnohodnotný temporal/graph correlation engine |
| Automatizace | Periodické běhy, role agentů, paralelní fáze | Není to distribuovaný autonomní agentní systém s robustní správou úloh |
| Uložení | Souborové workspaces/reporty, SQLite platform, rozpracovaný PostgreSQL | Jednotná persistence dlouhodobých entit, HA a konzistence |
| Broker | Redis Streams | Recovery pending messages, opakované doručení, idempotence |
| API/UI | Axum server, TypeScript UI, RBAC základy | Bezpečné výchozí nastavení autentizace, session a audit |
| Testy | Rust testy, E2E, scénáře, CI, uložené ověřovací artefakty | Reálná zátěž, dlouhodobý provoz, chaos/failure testy, srovnání s konkurencí |

**Zásadní rozlišení:** stávající produkt je už poměrně široká **integrační analytická pipeline**, ale cílový systém je **nepřetržitá distribuovaná bezpečnostní platforma**. Mezi těmito stavy je významná architektonická práce.

### 2.1 Konkrétní nálezy v kódu probírané v konverzaci

- [`src/correlation.rs`](https://github.com/Esperosa/service-fingerprinting-passive-analysis/blob/main/src/correlation.rs): funkce `correlate_events()` páruje event podle IP, portu a protokolu s otevřenou službou, jinak podle IP nebo jej označí jako unmapped. Nepopisuje samostatný časový graf, kauzální posloupnosti ani dlouhodobý stav hypotéz. **Pozor:** projekt má další heuristiky v jiných souborech; tento závěr se týká konkrétního základního korelátoru, nikoli tvrzení, že nikde jinde žádná analýza není.
- [`src/report.rs`](https://github.com/Esperosa/service-fingerprinting-passive-analysis/blob/main/src/report.rs): `normalize_inventory()` dává hostům `host_key` podle IP a služby identifikuje pomocí `IP/proto/port`; při DHCP, NAT a přesunech zařízení to není stabilní identita. `score_services()` používá ručně nastavené multiplikátory pro CVSS, CPE, confidence, pasivní signály, KEV a EPSS. Tato čísla nejsou automaticky kalibrovanou pravděpodobností skutečné kompromitace.
- [`src/decision.rs`](https://github.com/Esperosa/service-fingerprinting-passive-analysis/blob/main/src/decision.rs): existuje risk ranking a návrhy úloh jako `spawn-agent`, ale `rank_finding()` sčítá konstanty (severity, confidence, CVE, traffic atd.). Chybí explicitní probabilistický model a optimalizace informační hodnoty ověření.
- [`src/model.rs`](https://github.com/Esperosa/service-fingerprinting-passive-analysis/blob/main/src/model.rs): `Confidence` je `Low | Medium | High`, chybí oddělení pravděpodobnosti hypotézy, nejistoty poznání, kvality senzoru a potenciální škody.
- [`src/automation.rs`](https://github.com/Esperosa/service-fingerprinting-passive-analysis/blob/main/src/automation.rs): role `planner`, `inventory`, `followup`, `forensic`, `live-observer`, `correlator`, `validation`, `remediation` atd. a jejich závislosti už existují. Konsensus vychází z heuristických vah a signálů (např. hustota nálezů), ne z nezávisle kalibrovaných úsudků autonomních agentů.
- [`src/passive/suricata.rs`](https://github.com/Esperosa/service-fingerprinting-passive-analysis/blob/main/src/passive/suricata.rs): `fs::read_to_string()` načítá celý soubor; parser pracuje s některými `alert` poli i bez explicitního ověření `event_type`. ID založené na `flow_id` a času v sekundách může být nedostatečné pro jednoznačné rozlišení všech událostí. Potřebný je streaming, deduplikace, zachování originální události a příslušného typu.
- [`src/passive/zeek.rs`](https://github.com/Esperosa/service-fingerprinting-passive-analysis/blob/main/src/passive/zeek.rs): dávkové načtení logů; není robustní kontinuální ingest, checkpoint/rotace/restart. Větší část normalizace je dobrý základ.
- [`src/lanes.rs`](https://github.com/Esperosa/service-fingerprinting-passive-analysis/blob/main/src/lanes.rs): `collect_lanes()` čte řadu JSON snapshotů souborově. To není totéž jako samostatné live collectory.
- [`src/server.rs`](https://github.com/Esperosa/service-fingerprinting-passive-analysis/blob/main/src/server.rs) a [`src/model.rs`](https://github.com/Esperosa/service-fingerprinting-passive-analysis/blob/main/src/model.rs): byla probírána potenciálně nebezpečná konfigurace API bez povinné autentizace, včetně `anonymous-admin` ve větvi bez platformní DB a anonymního čtení za určitých podmínek. Před nasazením nutno reprodukovat testy pro všechny kombinace konfigurace a uzavřít fail-closed.
- [`src/storage.rs`](https://github.com/Esperosa/service-fingerprinting-passive-analysis/blob/main/src/storage.rs), [`src/platform.rs`](https://github.com/Esperosa/service-fingerprinting-passive-analysis/blob/main/src/platform.rs), [`src/external_sql.rs`](https://github.com/Esperosa/service-fingerprinting-passive-analysis/blob/main/src/external_sql.rs): reporty/workspace soubory, SQLite a částečný PostgreSQL jsou rozdělené. Existující DB rozhraní není jednotná produkční persistence. Souborový `runs/index.json` není vhodná sdílená transakční evidence clusteru.
- [`src/platform.rs`](https://github.com/Esperosa/service-fingerprinting-passive-analysis/blob/main/src/platform.rs): v probírané implementaci `claim_due_job()` vybírá `queued/scheduled/failed`, nikoli expirované `running`; při pádu workeru tak může zůstat job zaseknutý.
- [`src/broker.rs`](https://github.com/Esperosa/service-fingerprinting-passive-analysis/blob/main/src/broker.rs): Redis Streams `XREADGROUP` je začátek, ale pro crash recovery potřebujeme práci s pending entries (`XAUTOCLAIM` nebo ekvivalent), DLQ a idempotenci.
- Frontend podle dřívější kontroly ukládá API token do `localStorage`; pro produkci zvážit bezpečné serverové session, `HttpOnly` cookies a CSRF ochranu, resp. vhodný enterprise OIDC model.

**Ověřovací status:** tyto nálezy jsou ze statické inspekce diskutované v chatu. Nejde o čerstvé penetrační ověření ani zaručeně stále aktuální stav posledního commitu. Před implementací je nutné zafixovat SHA revize a každý nález reprodukovat testem.

---

## 3. Cílová distribuovaná architektura

Oddělit **data plane**, **control plane**, **analytics plane** a **management plane**.

```text
                         ┌───────────────────────────────┐
                         │      SALTICUS CONTROL PLANE     │
                         │ Policies / RBAC / Scheduler   │
                         │ Rules / Template Registry     │
                         │ Config / Audit / Orchestration│
                         └──────────────┬────────────────┘
                                        │ mTLS + signed policy bundles
         ┌──────────────────────────────┼──────────────────────────────┐
         ▼                              ▼                              ▼
┌───────────────────┐        ┌──────────────────┐          ┌──────────────────┐
│ Gateway / Firewall│        │ Passive Sensors  │          │ Active Probers   │
│ nftables / IPS    │        │ Zeek / Suricata  │          │ Nmap/httpx/etc. │
│ DNS filtering     │        │ Flow / Controller│          │ scoped safe tests│
│ local policy cache│        │ local buffer     │          │ budgets         │
└─────────┬─────────┘        └────────┬─────────┘          └────────┬─────────┘
          └───────────────────────────┼───────────────────────────────┘
                                      ▼
                          ┌──────────────────────┐
                          │ Ingest + Durable Log  │
                          │ Kafka / Redpanda etc. │
                          └──────────┬───────────┘
                                     ▼
                      ┌──────────────────────────┐
                      │ Stream Normalization      │
                      │ Dedup / Identity / Timing │
                      └─────────────┬────────────┘
                                    ▼
                      ┌───────────────────────────┐
                      │ Stateful Correlation       │
                      │ Temporal + Graph + Rules   │
                      └─────────────┬─────────────┘
                                    ▼
                      ┌───────────────────────────┐
                      │ Hypotheses / Uncertainty   │
                      │ Decision + Verification    │
                      └─────────────┬─────────────┘
                                    ▼
                     ┌────────────────────────────┐
                     │ Incidents / Responses / UI │
                     │ Evidence / Audit / Learning│
                     └────────────────────────────┘
```

### 3.1 Zásady horizontální škálovatelnosti

- Žádná pevná interní hranice počtu sledovaných hostů.
- Jednotná `tenant_id`, `site_id`, `sensor_id`, `asset_id`; všude tenant isolation.
- Horizontální rozdělení ingestu a worků podle tenant/site/asset nebo flow key. Partitions musí zachovat lokální pořadí relevantních událostí; mezi partition řešit cross-asset korelaci zvlášť.
- Durable event log s replayem, watermarky, retry, poison-message handling a monitorováním consumer lagu.
- Stateful stream processing s checkpointy, event time, out-of-order handling a přesně definovanou semantikou doručování (prakticky at-least-once + idempotence výstupů; ne slíbené magické end-to-end exactly-once).
- Krátkodobý stav ve škálovatelných lokálních state stores; dlouhodobá fakta a entity v transakční persistenci; objemné raw artefakty v objektovém úložišti.
- Při změně počtu workerů řízené rebalancování, předání checkpointů a testy konzistence.
- Backpressure, bounded queues, load shedding s explicitní informací o ztrátě pokrytí; kritické signály dostávají prioritu.
- Každý datový tok musí mít měřitelný limit EPS, velikost zpráv, CPU/GB na milion eventů, RAM pro state a storage retention.
- Senzory pokračují ve sběru/lokální ochraně při výpadku centrály; bezpečné doručení po obnovení (omezený buffer, overflow policy).
- Pro firewall nelze zaměňovat škálování control plane a linkovou propustnost data plane: konkrétní gateway je limitována NIC, CPU, offloadem, pravidly a aktivními relacemi.

### 3.2 Úložiště

Zavést stabilní doménové rozhraní `PlatformRepository` a jasnou separaci:

| Store | Doporučený obsah |
|---|---|
| PostgreSQL (v clusteru zvolená HA konfigurace) | tenanty, účty, role, assets, identifikátory, politiky, plány, joby, incidenty, hypotézy, auditní metadata |
| Time-series / sloupcové analytické úložiště dle benchmarku | velké objemy normalizovaných flow/event dat, agregace a historické dotazy |
| Durable log | krátko-/střednědobý replay událostí, doručení mezi komponentami |
| S3-kompatibilní objektové úložiště | raw PCAP, logy, reporty, přílohy důkazů, model artefakty |
| Lokální sensor/worker state | checkpointy, retry state, dočasná cache a policy cache |

Konkrétní databázová technologie pro masové události se vybere po benchmarku. PostgreSQL read replicas samy neřeší horizontální škálování zápisu.

**Navržené entity:** `assets`, `asset_identifiers`, `asset_relationships`, `services`, `observations`, `evidence`, `hypotheses`, `hypothesis_updates`, `findings`, `incidents`, `scan_jobs`, `sensor_checkpoints`, `intel_cache`, `verification_runs`, `rules`, `templates`, `model_versions`, `audit_log`, `policies`, `policy_deployments`.

Identita hosta není IP. IP/MAC/hostname/DHCP/controller ID/certifikát/account/port jsou **časově platné důkazy o identitě**, nikoli univerzálně spolehlivý jednotlivý klíč. Řešit DHCP, NAT, VLAN, přemístění, spoofing, více síťových rozhraní a nejednoznačné vazby.

### 3.3 Spolehlivost a bezpečnost infrastruktury

- Povinné přihlášení; fail-closed autorizace; RBAC/ABAC, minimální oprávnění, MFA/OIDC, správa tajemství, rotace certifikátů a tokenů.
- mTLS mezi senzory, workery a controllerem; podepsané policy bundles, pravidla a aktualizace; žádná implicitní důvěra podle síťové adresy.
- Izolace tenantů a bezpečnostní domény managementu oddělené od chráněných sítí.
- Verze konfigurace, dvoufázová validace změn, canary rollout, automatický rollback, test konfliktních pravidel.
- Audit nezměnitelných akcí, provenance důkazů, kontrola integrity a časová synchronizace.
- HA/DR architektura, test obnovy ze záloh, chaos testing, mitigace split-brain a výpadků brokeru/databáze.
- Bezpečnostní pravidla lokálního gateway nesmí být závislá na dostupnosti cloudového/centrálního API.
- Přísné sandboxování externích analyzátorů a šablon; limity CPU/RAM/IO, timeouty, síťový scope a schvalovací politika.

---

## 4. Vlastní firewall, DNS, IPS a řízená reakce

### 4.1 Firewall

Salticus má obsahovat spravovanou distribuovanou firewallovou rovinu. Návrh pro Linux gateway: **nftables/conntrack** jako výchozí enforcement, případně eBPF/XDP pro vybrané rychlé cesty (až po profilu a benchmarku). Rozhodování v paketové cestě musí být lokální a deterministické. Rust control agent sestavuje, kontroluje, podepisuje a atomicky aplikuje verzovanou politiku; nikdy nečeká na LLM či vzdálenou DB pro každý paket.

Schopnosti: stateful L3/L4 ACL, zónové politiky, VLAN/segmenty, NAT, bezpečné address/domain sets, IPv4/IPv6, rate limits, logging, předvídatelný fail-open/fail-closed **podle služby a rizika**, HA failover, test vlastních pravidel, dry-run/canary/rollback.

### 4.2 DNS

Lokální DNS recursive/forwarding služba s filtrováním (např. Unbound + RPZ a vlastní management). Policy podle zařízení/skupiny/segmentu, interní zóny, cache, DNSSEC dle režimu, audit bez nadměrného sběru osobních údajů, aktualizace kategorií/IOC, TTL a expirace blokací. U zařízení používajících DoH/DoT nebo externí resolver je viditelnost omezená; ochrana vyžaduje vhodnou síťovou politiku a nesmí předstírat stoprocentní DNS dohled.

### 4.3 IPS

Suricata v IPS režimu je možný blokovací modul, ale její provozní integrace vyžaduje zvláštní performance testy, validaci rule updates, policy rollback a měření falešných blokací. Zeek je typicky analytický senzor, nikoliv inline packet enforcement. Při poškození nebo přetížení IPS musí být přesně definované chování a fallback.

### 4.4 Response / SOAR

Řízené reakční playbooky: DNS block, IP/domain block, izolace segmentu/VLAN, disable konkrétního portu v autorizovaném switchi, omezení egress, zvýšení monitorovací úrovně, vytvoření incidentu. Každá akce: scope, oprávnění, očekávaný dopad, maximální doba, výjimky pro kritické služby, schválení podle rizika, log, expiration a rollback. Automatická destruktivní opatření nepouštět pouze na základě neověřeného AI skóre.

### 4.5 Kdy jsme konkurent Fortinet/FortiGate a kdy ne

FortiGate je především síťové bezpečnostní zařízení/gateway; Salticus má být širší analytická a řídicí platforma se samostatným enforcement modulem. Výhoda může vzniknout v vendor-neutral korelaci, vysvětlitelnosti a adaptivním ověřování, nikoliv pouze tím, že přidáme vlastní firewall. Přímé tvrzení „lepší než Fortinet/Microsoft/Vectra/Splunk/Wazuh“ vyžaduje srovnatelné nezávislé testy. Produkt musí mít jasně deklarované pokrytí a slepá místa.

---

## 5. Nové jádro: Uncertainty-Driven Security Intelligence Engine

**Hlavní inovace:** `Observation → Identity/Context → Temporal Correlation → Hypothesis → Uncertainty → Verification Planning → Evidence Update → Decision → Case Memory → Calibrated Learning`.

### 5.1 Vstupní evidence

Společná struktura obsahuje `tenant_id`, `site_id`, `sensor_id`, `event_id`, `event_time`, `received_at`, `asset_refs`, `flow/session_id`, typ signálu, raw reference, integritu, kvalitu zdroje, coverage/health senzoru, privacy classification a schema version. Stejný tok pozorovaný Suricatou, Zeekem a firewallem **nejsou tři nezávislé důkazy**. Důkazy musí být propojené provenance grafem a deduplikované nebo korektně statisticky zohledněné.

### 5.2 Temporal/graph correlation

- Per-asset a per-flow rychlá korelace, časová okna, out-of-order tolerantní event-time zpracování.
- Graph vazeb mezi zařízeními, službami, uživateli, doménami, tokem a bezpečnostními událostmi.
- Detekce vícestupňových scénářů (discovery → podezřelá autentizace → lateral movement → egress) včetně jejich časové posloupnosti.
- Sezónní a per-role baseline: zařízení, denní/týdenní rytmus, komunikační partneři, objem, porty, DNS, certifikáty.
- Posouzení změny služby, expozice, topologie, patch state, CVE/KEV/EPSS kontextu.
- Negativní důkazy a chybějící observabilita: „neviděl jsem“ není „nestalo se“, pokud senzor byl mimo provoz či mimo cestu toku.
- U každého závěru vysvětlení: které signály jsou nezávislé, které souvisejí, co hypotéze odporuje a co zůstává neznámé.

### 5.3 Hypotézy a nejistota

Nahradit jednoduché `Low/Medium/High` detailnějším modelem:

1. **Aleatorická nejistota** — přirozená proměnlivost provozu (noise, fluctuace).
2. **Epistemická nejistota** — neznalost/nezjištěné informace, kterou lze snížit další kontrolou.
3. **Identity uncertainty** — která fyzická/logická entita událost vytvořila.
4. **Observation uncertainty** — spolehlivost/coverage/čas senzorů.
5. **State uncertainty** — verze služby, konfigurace, skutečná zranitelnost.
6. **Interpretation uncertainty** — jestli indikátor znamená útok, administraci nebo normální provoz.

`hypothesis_probability` (kalibrovaná pravděpodobnost), `uncertainty`, `potential_impact`, `asset_criticality`, `time_sensitivity` a `verification_cost` jsou odlišné veličiny. **Nesměšovat důvěru v identitu s pravděpodobností kompromitace ani s prioritou incidentu.** Pokud nejsou odhady kalibrované, raději vracet ordinální skóre než falešně přesné procento.

### 5.4 Verification Planner a multi-agentní systém

Planner vybírá nejlepší další **autorizovanou, nejlépe nedestruktivní** kontrolu. Kandidáti: doplnění historického Zeek/flow kontextu, DNS či certifikátových údajů, dotaz na controller/management API, ověření verze produktu, cílený Nmap follow-up, bezpečná Nuclei šablona, konfigurace služby. Těžké nebo invazivní testy vyžadují vyšší oprávnění a explicitní schválení.

Výběr podle *Expected Value of Information* a očekávaného snížení rizika chybného bezpečnostního rozhodnutí:

```text
utility(action) = expected_decision_loss_reduction
                - execution_cost
                - network_overhead
                - disruption_risk
                - delay_penalty
```

Realistický VOI se počítá nad pravděpodobnými výsledky testu, ne jako libovolný bonus za „aktivní kontrolu“. Akce musí mít `deadline`, `budget`, `scope`, `rate limit`, `max retries`, `disruption class`, `approval`, `evidence output` a idempotency key.

Agentní role: planner, asset-identity-verifier, passive-context-hunter, service-verifier, vulnerability-verifier, traffic-forensics, correlation-worker, hypothesis-validator, incident-responder, reporter. Nejdřív definovat kontrakty a bezpečnost; LLM pouze navrhuje a vysvětluje, **není nezbytné v kritické paketové cestě**.

### 5.5 Fast / Deep / Verification paths

| Cesta | Obsah | Návrhový cíl, nikoliv měření |
|---|---|---|
| Fast Path | deterministická pravidla, lokální stav a krátká korelace | p95 do 250 ms *od přijetí události* v definovaném zatížení |
| Deep Path | graf, historie, behaviorální model a více zdrojů | p95 do 1 s u prioritních nových incidentů, pokud jsou data dostupná |
| Verification Path | aktivní scan, management dotaz, odbornější ověření | sekundy až minuty podle konkrétní bezpečné kontroly |

Oddělit **time to first suspicion**, **time to decision**, **time to verification**, **time to mitigation** a event ingestion latency. Neměřit jen trvání jedné funkce. Rychlé lokální blokovací pravidlo nesmí čekat na komplexní cloudovou analytiku.

### 5.6 Učení a Case Memory

Zaznamenávat každou hypotézu, její předchozí stav, podpůrné/rozporné důkazy, vybranou ověřovací akci, náklady, výsledek, pozdější lidské či laboratorní potvrzení a verzi detektoru. Učit **kvalitu rozhodování**, nikoliv počet vygenerovaných alertů. Template Registry spravuje verze, účinnost na různých třídách zařízení, false positives, regresní sady, důvěru a bezpečnost akce.

**Bezpečnost učení:** neumožnit přímé samoučení z neověřených vlastních predikcí. Oddělit trénovací a produkční data, zpřístupnit shadow modely, offline validaci, canary rollout, review a rollback. Prověřovat poisoning, sensor spoofing, drift, změny legitimního provozu a nekvalitní ground truth.

---

## 6. Přesná struktura navrženého kódu

Navrhovat Rust workspace s menšími `crates`; crate není automaticky server:

```text
salticus/
├── crates/
│   ├── salticus-schema/         # verzované eventy, hypotézy, evidence, policy
│   ├── salticus-ingest/         # konektory, parsery, checkpointy, dedup
│   ├── salticus-identity/       # asset resolution, historické ID a topologie
│   ├── salticus-correlation/    # temporal / graph / CEP / pravidla
│   ├── salticus-hypothesis/     # pravděpodobnosti a nejistoty
│   ├── salticus-verification/   # VOI, agent contracts, scope a budgets
│   ├── salticus-learning/       # Case Memory, kalibrace, templates
│   ├── salticus-policy/         # firewall/DNS/IPS policies, verze, rollout
│   ├── salticus-storage/        # repository interfaces, DB a objects
│   └── salticus-evaluation/     # offline replay, metriky, porovnávání
├── services/
│   ├── ingest-gateway/
│   ├── correlation-worker/
│   ├── verification-worker/
│   ├── controller/
│   ├── gateway-agent/
│   ├── sensor-agent/
│   └── api/
├── labs/
│   ├── datasets/
│   ├── replay/
│   ├── virtual-networks/
│   ├── scenarios/
│   └── benchmarks/
└── docs/
```

Příklad základních kontraktů (schematicky, ne kompletní kompilovatelný crate):

```rust
struct Observation {
    id: Uuid,
    tenant_id: Uuid,
    sensor_id: Uuid,
    event_time: DateTime<Utc>,
    received_at: DateTime<Utc>,
    source_asset_id: Option<Uuid>,
    target_asset_id: Option<Uuid>,
    flow_id: Option<String>,
    event_type: String,
    evidence_ref: String,
    source_quality: f32,
}

struct SecurityHypothesis {
    id: Uuid,
    affected_assets: Vec<Uuid>,
    hypothesis_type: String,
    supporting_evidence: Vec<Uuid>,
    contradicting_evidence: Vec<Uuid>,
    probability: Option<f64>, // pouze je-li kalibrováno
    uncertainty: f64,
    potential_impact: f64,
    model_version: String,
}

struct VerificationProposal {
    hypothesis_id: Uuid,
    method: String,
    target_asset_id: Uuid,
    estimated_information_gain: f64,
    estimated_network_cost: f64,
    estimated_runtime_ms: u64,
    disruption_risk: f64,
    requires_approval: bool,
}
```

---

## 7. Světová data: maximální geografické, síťové a technické pokrytí

Neomezovat se na 2–3 univerzitní datasety. Vybudovat **data registry**, které průběžně eviduje dataset, verzi, původ, licenci, URL, region, období, senzor, data modality, štítky, známé nedostatky, validaci, velikost, hash a dostupnost. Neznamená to bezhlavě stahovat celé petabajty: začít indexací, reprezentativními výřezy, streamingem a prioritizací diverzity.

### 7.1 Veřejné datasety a jejich role

| Zdroj | Co typicky nabízí | Jak ho použít | Poznámka |
|---|---|---|---|
| [IoT-23 / Stratosphere IPS, ČVUT](https://www.stratosphereips.org/datasets-iot23) | 23 scénářů IoT, Zeek logy a štítky; benign/malicious | C2, botnet, flow korelace a behaviorální změny | Štítky a scénáře posoudit kriticky |
| [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) | PCAP, flow a logy; testbed uvádí 420 klientů a 30 serverů | větší síť a různé typy útoků | Síť je testbed, ne anonymní vzorek globálního internetu |
| [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) | PCAP a labelované flow | referenční IDS benchmark | risk leakage a dataset artifacts |
| [CICIoT2023](https://www.unb.ca/cic/datasets/iotdataset-2023.html) | IoT PCAP a flow features | IoT a průmyslové/heterogenní chování | nesrovnávat neslučitelné labely bez mapování |
| [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) | flow, PCAP a features | external generalization | jiné generování a starší provoz |
| [LANL Cyber Security Datasets](https://csr.lanl.gov/data/cyber1/) | rozsáhlá enterprise autentizační a procesní telemetrie | víceúčelový korelační graf a insider/lateral movement | data nejsou stejné jako síťový PCAP; cca 1,65 mld událostí bývá uváděno u části korpusu |
| [MAWI Working Group Traffic Archive](https://mawi.wide.ad.jp/mawi/) | dlouhodobé síťové trace na internetových linkách | drift, geografická/časová diverzita, výkonnostní replay | citlivost k anonymizaci, štítky útoků často chybí |
| [CESNET DataSets](https://www.cesnet.cz/) | vybrané veřejné flow/time-series výzkumné korpusy | velké časové řady, drift a load testy | konkrétní TimeSeries26, licenční podmínky a aktuální download nutno ověřit u datasetu |
| [CAIDA Datasets](https://www.caida.org/catalog/datasets/) | internetové trace, topologie, DDoS a další záznamy | globální provozní charakteristiky a síťová heterogenita | část přístupu je omezená/smluvní |
| [UCSD Network Telescope / CAIDA](https://www.caida.org/projects/network_telescope/) | unsolicited internet traffic do nepoužívaného adresního prostoru | scanning, internet-wide anomalies | nejsou to endpoint události s kompletní ground truth |
| [CTU / Stratosphere public datasets](https://www.stratosphereips.org/datasets-overview) | botnetové a malware traffic scénáře | nezávislé testy detekcí a behaviorální modely | kontrolovat duplicity mezi korpusy |
| [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/) | PCAP a laboratorní rozbory malware provozu | malé realistické incidenty a reprodukovatelné scénáře | licence, původ a citlivost vzorků |
| [MITRE ATT&CK](https://attack.mitre.org/) | taxonomie technik, nikoli syrová síťová telemetrie | scénáře, mapování TTP a coverage | ATT&CK není ground truth PCAP |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | exploatované CVE | rizikové obohacení | není dataset skutečného síťového provozu |
| [FIRST EPSS](https://www.first.org/epss/) | statistická pravděpodobnost exploatace CVE v definovaném horizontu | priorizace zranitelností | není probability kompromitace konkrétního hosta |
| [NVD](https://nvd.nist.gov/) | CVE/CPE/CVSS a metadata | enrichment a verifikace | důležité cache a provenance |
| [URLhaus](https://urlhaus.abuse.ch/) | malware-associated URLs | DNS/URL threat intel; kontrola false positives | feed nemusí obsahovat každou hrozbu |
| [abuse.ch ThreatFox](https://threatfox.abuse.ch/) | IOC | korelace threat intel | expirace a kvalita indikátorů |
| [AlienVault OTX](https://otx.alienvault.com/) | IOC/pulses | rozšíření pokrytí | ověřit omezení API a licenci |
| [OpenPhish](https://openphish.com/) | phishing feed | DNS/URL ochrana | licence a frekvence aktualizací |
| [CERT/CSIRT a další veřejné reporty](https://www.enisa.europa.eu/) | anonymizované incidentní zprávy | scénáře a validace hypotéz | většinou nejde o strojově labelované packet logy |

**Další zdroje z brainstormingu k ověření:** dataset DEDALE (dříve uváděn rozsah ~2,8 TB) a CESNET TimeSeries26 (dříve uváděno ~5,46 miliardy záznamů a >278 tisíc pseudonymizovaných IP). Bez ověření konkrétního oficiálního vydání, podmínek a schématu na těchto přesných číslech nebudeme stavět výzkumná tvrzení. Podobně čísla o LANL a CSE-CIC je nutné citovat z konkrétní verze zdroje.

### 7.2 Není vše jedna „tréninková databáze“

**Oddělit modality:** PCAP, NetFlow/IPFIX, DNS, HTTP metadata, Zeek logs, Suricata alerty, host authentication/process logs, topologie, CVE/Intel, agregované časové řady. Neslévat jejich záznamy do jednoho plochého CSV se smyšleným jednotným štítkem.

**Dataset registry fields:** `dataset_id`, `release_version`, `source`, `region`, `time_range`, `license`, `access_class`, `hash`, `sampled_bytes`, `modalities`, `label_schema`, `ground_truth_quality`, `identity_scope`, `privacy_constraints`, `known_leakage_risks`, `transforms`, `test_split`.

Předzpracování: schema adapter, normalizace časů a IP identity, deduplication, provenance, validace, citlivost, kontrola label leakage, oddělení trénování a testování podle **datasetu/scénáře/hosta/času**. Vyhodnocení na neviděném datasetu a jiném období je nutné; náhodné rozdělení jednotlivých flow často vytváří nerealisticky dobré výsledky.

**Zdroje bez útokových štítků:** dobré pro baseline, drift, throughput a unsupervised analýzu; nelze z nich automaticky získat precision/recall bez validované pravdy.

---

## 8. Testování bez vlastních stovek serverů

### 8.1 Offline replay

`bakula-replay`: ingest PCAP → offline Zeek (`zeek -r`) / Suricata (`-r`) → normalized event log → engine → incidenty → nezávislý evaluator. Replay musí umět původní timing, zrychlení, zpoždění, reorder, duplicitní zprávy, ztrátu senzoru, clock skew, změnu IP, NAT a selhání workeru. **Referenční štítky nedávat do analytické pipeline; pouze evaluatoru.**

### 8.2 Virtuální laboratorní síť

- [Mininet](https://mininet.org/) pro stovky lehkých linuxových síťových namespaces a virtuální topologii.
- [Containerlab](https://containerlab.dev/) pro síťovou topologii, router/switch kontejnery a pravidla.
- Docker/Podman/KVM pro skutečné služby a izolované systémy; plnohodnotné VM používat jen pro menší relevantní podmnožiny.
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) pro záměrně zranitelnou aplikaci v kontrolované síti.
- Vlastní scénáře DNS/firewall/IPS, DHCP změny, VLAN segmentace, různé firmware a víceúrovňový provoz.

Stovky simulovaných identit **neznamenají** stovky reálných OS ani tisíc fyzických zařízení. Kombinovat reálnou síťovou emulaci pro funkční testy a syntetické logické identity pro velké objemy událostí.

### 8.3 Omezené veřejné cíle

[`scanme.nmap.org`](https://scanme.nmap.org/) je Nmapem určený k omezenému testování Nmapu podle tam uvedených pravidel (typicky nanejvýš kolem 12 skenů denně, žádné exploity či DoS). **Nesmí být cílem opakovaného multiagentního skenování nebo zátěžových testů.** Cizí systémy skenovat jen s výslovným souhlasem a v povoleném rozsahu.

### 8.4 Hardware

Dříve zvažovaná konfigurace vývojového PC: Intel i7-13700K / 64 GB RAM. Je vhodná pro Rust vývoj, replay, vybrané virtuální topologie, modely a výkonnostní testy. Netvrdit bez měření, že tato konfigurace zvládne konkrétní počet EPS nebo rychlost IPS. Velké korpusy procesovat po částech, streamingem a s uloženými hashi/verzemi výřezů.

---

## 9. Co opravdu musíme otestovat — kompletní testovací matice

| Vrstva | Funkční test | Selhání/bezpečnost | Výkon a kvalita |
|---|---|---|---|
| Ingest | Zeek, Suricata, IPFIX, DNS, API, PCAP | rotace logu, malformed input, duplicate, out-of-order, restart | EPS, lag, drop count, bytes/event |
| Identita | DHCP, MAC, IP, NAT, VLAN, switch link, certifikát | spoofing, collisions, stale assignment | false merges/splits, lookup p95 |
| Korelace | single event, time-window, multi-stage, graph | missing sensor, false evidence, poisoned input | precision/recall, p95/p99 latency |
| Hypotézy | update pozitivním/negativním důkazem | conflicting data, uncertainty explosion | Brier/ECE, calibration by class |
| Planner | volba pasivního vs aktivního ověření | budget exhaustion, unsafe template, authorization | decision loss, VOI realized, scans avoided |
| Active | nmap, httpx, safe nuclei, controller verify | timeout, rate limit, scope escape, host crash | time/verification, network cost, result quality |
| Firewall | rules, NAT, zones, stateful connections | bad policy, failover, rollback, bypass, IPv6 | throughput Gbps, PPS, latency, drops |
| DNS | resolver, RPZ, policies, cache, DNSSEC | resolver failure, DoH bypass, stale feed | query p95/p99, cache hit, FP block |
| IPS | alert/drop integration, rule update | overload, crash, false block, fallback | packets/s, p99, detection/block precision |
| Broker | jobs/event log/consumer group | killed worker, broker outage, pending recovery | backpressure, consumer lag, replay integrity |
| Database | transactions, history, migrations | crash, failover, restore, split-brain | write/read throughput, query p95 |
| API/UI | identity, scopes, role boundaries | IDOR, CSRF, injection, session theft | concurrent users, response p95 |
| Multi-tenant | site/tenant isolation | cross-tenant event or policy leakage | per-tenant quotas, noisy neighbor |
| Case Learning | dataset versioning, template metrics | poisoning, overfit, regressions | before/after, cross-dataset generalization |
| HA/DR | sensor autonomy, controller failover | network partition, recovery, disk full | RPO/RTO, uptime, loss windows |
| Supply chain | builds, images, dependencies, updates | unsigned bundle, compromised template | reproducibility, vulnerability scan |

### 9.1 Metodika srovnání

**Ablation study** (vždy stejný replay a stejné štítky):

A. Pouze pasivní pravidla.  
B. Pasivní + aktivní signály.  
C. + historické baseline, temporal/graph korelace.  
D. + typované nejistoty a adaptivní Verification Planner.  
E. + verzované učení / kalibrace / templates.

Metriky: `precision`, `recall`, `F1`, PR-AUC při nevyvážených datech, false incidents per asset-day, MTTD, time-to-first-suspicion, time-to-verified-decision, MTTR, Brier score, ECE, confidence interval, CPU/GB per 1M events, ingest p95/p99, memory/asset, dropped events, bandwidth/verification, action safety, RPO/RTO a throughput IPS/DNS. Dodat rovněž **coverage a missing-data indicator**.

### 9.2 Cíle, nikoliv garance

Fast Path p95 < 250 ms od přijetí události a prioritní Deep Path p95 < 1 s jsou hypotézy/výkonnostní cíle, nikoliv dokázaná vlastnost. Latenci měřit při konkrétní EPS, počtu assetů, rozložení eventů, době retence a počtu workerů. „Nejlepší na světě“ nesmí být marketingové tvrzení bez srovnatelného benchmarku.

### 9.3 Co replay nikdy sám neprokáže

Skutečnou propustnost fyzické gateway při vysokých rychlostech; spolehlivost proprietárních switchů a controllerů; dlouhodobou životnost hardwaru; kompletní chování produkčního HA clusteru; útoky bez příslušné viditelnosti; dopad aktivního skenování na konkrétní zákaznické OT/IoT zařízení. Tyto oblasti vyžadují specializovaný testbed, partnerskou autorizovanou síť nebo externí měření.

---

## 10. Technické priority a závislosti (bez umělého omezení na „malou první verzi“)

Neplánujeme produkt jako jednoduchou jednoserverovou aplikaci, kterou později komplikovaně přepíšeme. **Cílové kontrakty navrhnout distribuovaně hned**; jednotlivé funkce lze postupně ověřovat na jedné vývojové stanici.

**P0 — konstrukční a bezpečnostní základy**

- Zafixovat aktuální commit a testy, reprodukovat statické nálezy.
- Uzavřít API a identitu, role, audit, session management, tenant isolation.
- Stabilní asset identity + event/evidence schema + provenance.
- Oddělit storage interfaces a provést konzistentní migrace.
- Spolehlivý scheduler/broker (leases, pending reclaim, idempotence, DLQ).
- Ingest jako kontinuální proces s checkpointy a event-time semantikou.

**P1 — analytické jádro**

- Temporal/graph correlator, dlouhodobé baseline, source-aware evidence fusion.
- Hypothesis engine s rozlišenými nejistotami, kalibrovanými výstupy.
- Verification Planner s VOI, hard safety/authorization constraints.
- Multiagent orchestrace s jasnými kontrakty a sdíleným stavem.
- Reprodukovatelný `salticus-evaluation` a dataset registry.

**P2 — distribuovaná ochrana a reakce**

- Gateway agent, nftables policy compiler, firewall, DNS RPZ, Suricata IPS, audit a rollback.
- Lokální autonomie enforcementu a reakční playbooky.
- Multi-site/multi-tenant provoz, canary, HA a DR testy.
- Senzorové a controller collectory s health/coverage metrikami.

**P3 — adaptivní zlepšování a měřitelné předčení referenčních systémů**

- Case Memory, analytika užitečnosti ověřování, detekce driftu.
- Offline trénink, kalibrace, verzované detekční šablony, shadow/canary.
- Cross-region/cross-dataset benchmark, reálné negativní scénáře, slepá místa.
- Externě opakovatelné srovnání vybraných funkcí s konkurenty.

---

## 11. Návrh diplomové práce

**Pracovní název:** *Distribuovaná platforma pro adaptivní korelaci bezpečnostních událostí s aktivním ověřováním řízeným nejistotou*.

Alternativně: *Uncertainty-Driven Active–Passive Security Correlation in Distributed Networks*.

**Výzkumný problém:** Jak kombinací časové korelace pasivní telemetrie, aktivního fingerprintingu a adaptivního plánování ověřování snížit chybná bezpečnostní rozhodnutí, čas do potvrzení a náklady na aktivní kontroly při zachování škálovatelnosti?

**Výzkumné hypotézy:**

- H1: spojení pasivní a aktivní telemetrie zvýší kvalitu rozhodnutí proti samotné pasivní vrstvě za definovaných nákladů.
- H2: temporal/graph evidence fusion s korekcí závislosti zdrojů sníží falešné incidenty oproti prostému scoringu eventů.
- H3: typovaná nejistota a VOI-based planner dosáhne stejné či vyšší přesnosti s menším počtem aktivních kontrol oproti pravidelnému plošnému skenu.
- H4: verzované učení a kalibrace z ověřených případů zlepší přenositelnost na neviděná data oproti statickým heuristikám.
- H5: rozdělení workerů a stavu umožní s přidáním hardwaru zvýšit propustnost bez disproporčního růstu latence.

**Očekávané výstupy:** implementace enginu, reprodukovatelný eval framework, dataset registry, ablation study, statistické vyhodnocení, model hrozeb, dokumentace limitů a praktická demonstrace cíleného ověřování. Celá komerčně srovnatelná NGFW/IPS/DNS platforma je širší dlouhodobá produktová ambice, nikoliv automaticky nutná podmínka splnění diplomky. Rozsah a návaznost na bakalářskou práci musí schválit vedoucí a škola; není možné garantovat schválení jen na základě technického návrhu.

**Význam vůči bakalářské práci:** bakalářský prototyp se zaměřoval na fingerprinting, pasivní analýzu a počáteční rozhodování podle nejistoty. Diplomová práce musí přinést měřitelně nové algoritmy, kontinuální datový model, adaptivní výběr ověření a nezávislé experimentální vyhodnocení, nikoli jen větší aplikaci či přepsaný kód.

---

## 12. Kritická rizika a otevřená rozhodnutí

1. **Rozsah produktu versus rozsah diplomky:** obrovská platforma není jeden akademický experiment; oddělit výzkumné jádro od ostatních subsystémů.
2. **Nerealistická představa 100% detekce:** bez endpoint telemetrie a bez dešifrování není úplné pozorování možné; modelovat coverage a neznámé oblasti.
3. **False positives při blokování:** nutné explicitní policy a minimální dopad, nejlépe vratná opatření.
4. **Nezávislost důkazů:** tři alerty nad jedním flow nejsou tři nezávislá potvrzení.
5. **Nekalibrovaná čísla:** ručně stanovený score není pravděpodobnost. Kalibrovat na nezávislých datech.
6. **Data leakage a rozdílné dataset modality:** miliarda řádků neznamená miliardu kvalitně označených incidentů.
7. **Data governance:** licence, GDPR, redakce PII, audit původu, omezení redistribuce, retention.
8. **Adversarial learning / poisoning:** nepustit automatické učení z neověřených událostí do enforcementu.
9. **Výkonnost:** události za sekundu a datová šířka jsou důležitější než prostý počet hostů.
10. **Produktová odpovědnost:** firewall/IPS je kritická infrastruktura; nutné bezpečnostní revize, testy změn a spolehlivý rollback.
11. **Měření proti konkurenci:** výhra v jednom veřejném datasetu neprokazuje vyšší bezpečnost celkově.
12. **Nedostatek skutečných aktivních cílů:** historické PCAP nelze znovu oskenovat; pro active verification je potřeba vlastní reprodukovatelný lab nebo výslovný souhlas majitele sítě.

---

## 13. Praktický plán bez rozpočtu na velkou infrastrukturu

1. Zamrazit revizi Bakuly a vytvořit automatický import aktuálních integračních testů a event schémat.
2. Vytvořit metadata registry globálních datasetů; stáhnout pouze reprezentativní veřejné výřezy s dostupnou licencí a dokumentovanými štítky.
3. Postavit `salticus-evaluation`: replay, ablation konfigurace, labeling adaptery a měření p95/p99/quality/cost.
4. Spustit reprodukovatelný baseline experiment současného `src/correlation.rs` a `src/decision.rs` (to je pevná referenční úroveň).
5. Vyvinout nový schema/identity/temporal correlation modul a porovnávat proti baseline.
6. Přidat hypotézy a měření nejistoty; nejdříve s transparentními pravidly, následně s kalibrovanými modely.
7. Postavit lokální Mininet/Containerlab prostředí pro autorizované Nmap/httpx/Nuclei ověřování a integrovat Verification Planner.
8. Synteticky škálovat ingest na 500, 5 000, 50 000 logických identit, ale vždy měřit EPS, RAM/CPU, latenci a objem storage; čísla nejsou garancí dostupného výkonu.
9. Až analytické výsledky budou přesvědčivé, integrovat gateway enforcement + DNS + IPS do nezávislých, důsledně testovaných částí platformy.
10. Opakovat dlouhodobé failure/chaos testy, security review, cross-dataset experimenty a připravit výsledky diplomky.

---

## 14. Stručný slovník

- **Active scanning:** vlastní autorizované dotazy na host/službu, např. Nmap nebo bezpečný web check.
- **Passive monitoring:** čtení existujícího provozu, logů nebo metadat bez záměrného dotazování cíle.
- **Correlation:** propojování událostí, identit a času za účelem rozpoznání souvisejícího jevu.
- **Hypotéza:** dočasný ověřitelný závěr typu „toto zařízení pravděpodobně provozuje rizikovou službu“.
- **Confidence vs uncertainty:** jak moc závěru věříme versus co nevíme a jak spolehlivý je odhad.
- **VOI (Value of Information):** očekávaná užitečnost dalšího testu vzhledem k ceně a riziku.
- **Evidence provenance:** dohledatelný původ, čas, integrita a závislost důkazů.
- **False positive / false negative:** falešný alarm / přehlédnutý skutečný jev.
- **Calibration:** zda uváděné pravděpodobnosti odpovídají skutečné četnosti výskytu.
- **EPS:** events per second — počet zpracovaných událostí za sekundu.
- **p95/p99:** 95./99. percentil latence; odpovídá tomu, jak rychlý je systém i v pomalejší části případů.
- **Backpressure:** mechanismus, který brání nekontrolovanému zahlcení pipeline.
- **Idempotence:** opakované doručení stejného úkolu nezmění výsledek nesprávně ani nevytvoří duplicity.
- **Control plane:** centrální politiky, konfigurace, distribuce úloh a správa.
- **Data plane:** samotný síťový provoz a jeho lokální povolení či blokování.
- **Replay:** reprodukovatelné přehrání historických událostí do testované implementace.
- **Ablation study:** porovnání variant systému s vypnutými/zapnutými komponentami, aby se změřil přínos každé části.
- **Case Memory:** historie hypotéz, ověření, správných a chybných rozhodnutí.
- **Canary rollout:** postupné nasazení nové verze na malou část infrastruktury s možností rychlého návratu.

---

## 15. Závěrečné rozhodnutí brainstormingu

**Salticus se má dál vyvíjet jako bezpečnostní platforma postavená kolem adaptivního korelačního enginu řízeného nejistotou.** Jejím cílem není produkovat maximum alertů nebo spouštět maximum skenů, ale **maximalizovat počet správných a včasných bezpečnostních rozhodnutí při co nejnižších nákladech, síťové zátěži a riziku chybného zásahu**.

Distribuovaný firewall, DNS, IPS a reakční playbooky tvoří provozní ochranu. Globální datasety, reprodukovatelné replaye, virtuální testbedy a kontrolované experimenty tvoří způsob, jak prokázat kvalitu a zlepšování. Všechny větší změny musí být měřitelné proti stávající baseline, nikoliv jen přidané podle pocitu.

**Poznámka k úplnosti:** dokument sjednocuje relevantní myšlenky a technická zjištění z celé zde uvedené konverzace o Bakule. Nejde o doslovný přepis všech promluv; opakování a průběžné rozpory byly vyřešeny ve prospěch přesného, realizovatelného cílového návrhu.
