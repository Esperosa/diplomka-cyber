# Enterprise backend vrstva

Tato dokumentace shrnuje klicove doplnky nad puvodni platformni vrstvu:

- Redis Streams durable queue broker
- quorum-aware rolling upgrade management

## PostgreSQL vrstva: odstranena (31.10.2026)

`external_sql.rs` (452 radku Postgres CRUD pro users/tokens/jobs/nodes/
ha_policy, plus vlastni `bakula-program external-sql ...` CLI podstrom)
byl **smazan**, ne opraven/otestovan. Rozhodnuto po 2-kolove 3-agentni
debate (`docs/diplomka/produkcni-plan.md`, "Druhe kolo zmeny ramce"):
modul mel 0 testu, 0 CI coverage, nebyl volan z `server.rs` ani
`broker.rs`, a `jobs` tabulka nemela `spec_json`/`claimed_by`/
`claim_until`/`attempts` sloupce ani claim/mark funkce - nebyla to
nahradni implementace `platform.rs`'s SQLite store, jen oddelena
administrativni vrstva, co nikdo nevyuzival a nikdy nemohla spoustet
workery bez reimplementace poloviny `platform.rs`. Testovat kod, ktery
nemuze nikdy fungovat, by byl ztraceny cas - smazani bylo shoda vsech 3
agentu (Opus comprehensive, pragmatik, skeptik) v obou kolech debaty.

Skutecna Postgres migrace (pro realny multi-host H5, viz
`docs/diplomka/produkcni-plan.md`) zustava odlozena na konkretni trigger
(2. realny control-plane uzel) - az se stane aktualni, postavi se znovu
jako soucast `PlatformRepository` traitu nad `platform.rs`'s existujicim
schema, ne jako samostatna paralelni vrstva.

## Redis Streams

Implementace je v [broker.rs](../src/broker.rs).

Smysl:

- oddelit dorucovani jobu od DB
- mit durable broker mezi schedulerem a workerem
- umoznit vice workerum cist z jedne fronty

Aktualni model:

- DB zustava zdrojem pravdy pro stav jobu
- Redis slouzi jako durable delivery vrstva
- worker po prevzeti zpravy jeste claimne job v DB lease mechanismem

**Stav: skutecne testovano.** 5 unit testu primo v `broker.rs` + samostatny
test se 2 REALNYMI OS procesy (`tests/broker_two_process.rs`), vsechny
overeny proti zivemu Redisu (ne jen zkompilovano). DLQ, connection reuse a
`claimed_by` fencing viz `docs/diplomka/produkcni-plan.md`.

## HA / rolling upgrades

Implementace je v [platform.rs](../src/platform.rs).

Doplneny byly:

- `ha_policy`
- verze a desired verze uzlu
- `ready`, `drain_state`, `upgrade_state`
- quorum-aware kandidatni vyber
- `advance_rollout`
- `mark_node_ready`

To umoznuje:

- drzet quorum pri postupnem upgrade
- nevybirat dalsi uzel, pokud uz probiha upgrade nebo by se rozbilo minimum ready uzlu

**Stav (produkcni gap audit, 30.10.2026): 0 dedikovanych testu, jen CLI.**
`advance_rollout`/`mark_node_ready`/quorum vyber nemaji v `platform.rs`'s
testovaci sade (12 testu) jediny primy test - vsech 12 testuje job
claim/lease/backoff, ne HA. `/api/platform/ha` (`server.rs`) je jen cteni
(`ha_status`) - zapis (`advance`, `mark-ready`) je dosazitelny vyhradne pres
CLI podstrom `platform ha ...`, overeny jen nepřímo v
`tests/e2e.rs::platform_rbac_scheduler_cluster_and_server_work_end_to_end`.

## Poctiva hranice

Tohle je vyrazne silnejsi nez puvodni prototyp, ale stale to neni kompletní náhrada za:

- Kubernetes control plane
- etcd/raft quorum manager
- service mesh
- cloud load balancer orchestration
- multi-AZ failover stack

**Oprava (produkcni gap audit, 30.10.2026, upraveno 31.10.2026 po smazani
PostgreSQL vrstvy):** predchozi veta tady tvrdila, ze celá tahle vrstva je
"realny, auditovatelny a otestovany krok" - to byla nepravda pro 2 ze 3
casti. Presne podle toho, co je skutecne overeno:

- **Redis Streams broker**: skutecne testovano (5 unit testu + 2-proces test
  proti zivemu Redisu).
- **PostgreSQL vrstva**: odstranena (viz vyse) - nebyla produkcni krok,
  byla netestovany, nezapojeny kod, ktery nikdy nemohl fungovat.
- **HA/rolling upgrades**: 0 dedikovanych testu, zapis jen pres CLI, zadny
  HTTP write endpoint - funguje (overeno v e2e testu), ale netestovano
  izolovane a nedosazitelne z API.
