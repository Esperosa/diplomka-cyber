# Enterprise backend vrstva

Tato dokumentace shrnuje tri klicove doplňky nad puvodni platformni vrstvu:

- PostgreSQL external SQL backend
- Redis Streams durable queue broker
- quorum-aware rolling upgrade management

## PostgreSQL

Implementace je v [external_sql.rs](../src/external_sql.rs).

Pouziva tabulky:

- `users`
- `api_tokens`
- `jobs`
- `nodes`
- `ha_policy`

Smysl:

- oddelit control-plane metadata od lokalniho workspace
- ziskat externi SQL backend vhodny pro centralnejsi nasazeni

**Stav (produkcni gap audit, 30.10.2026): nezapojeny prototyp, 0 testu.**
`external_sql.rs` dnes neni volan z `server.rs` ani `broker.rs` - dosazitelny
je jen pres vlastni `bakula-program external-sql ...` CLI podstrom. Modul
nema jediny `#[test]`. `.github/workflows/ci.yml` nema Postgres service,
takze se tahle vrstva v CI nemuze ani zkompilovat-a-spustit. `jobs` tabulka
navic nema `spec_json`/`claimed_by`/`claim_until`/`attempts` sloupce ani
claim/mark funkce - neni to nahradni implementace `platform.rs`'s SQLite
store, je to oddelena administrativni vrstva (users/tokens/nodes/ha_policy),
co dnes nikdo nevyuziva. Pred jakymkoliv tvrzenim o produkcni pripravenosti
teto casti potrebuje bud minimalni test + Postgres CI service, nebo ji
zretelne oznacit jako neintegrovany prototyp pro budouci Faze 2 (viz
`docs/diplomka/produkcni-plan.md`).

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

**Oprava (produkcni gap audit, 30.10.2026):** predchozi veta tady tvrdila, ze
celá tahle vrstva je "realny, auditovatelny a otestovany krok" - to byla
nepravda pro 2 ze 3 casti. Presne podle toho, co je skutecne overeno:

- **Redis Streams broker**: skutecne testovano (5 unit testu + 2-proces test
  proti zivemu Redisu).
- **PostgreSQL vrstva**: 0 testu, 0 CI coverage, nezapojena do server/broker
  - nezintegrovany prototyp, ne produkcni krok.
- **HA/rolling upgrades**: 0 dedikovanych testu, zapis jen pres CLI, zadny
  HTTP write endpoint - funguje (overeno v e2e testu), ale netestovano
  izolovane a nedosazitelne z API.
