# 3 odložené bezpečnostní bugy — opraveno (Deliverable 6)

**Status: opraveno a testováno (29. 10. 2026).** Jediný Deliverable, který skutečně mění existující produkční logiku (`server.rs`, `platform.rs`, `broker.rs`) — na rozdíl od Deliverables 1-5, které stavěly nové moduly vedle starých. Všechny 3 bugy byly identifikovány už v úvodní analýze (`docs/diplomka/analyza-soucasneho-stavu.md`) a vědomě odloženy do bodu v testovací matici, kde na ně vyjde řada (Broker/Database/API-UI) — ten bod nastal po Deliverable 5.

## 1. Anonymous-readonly bypass (`server.rs`)

**Bug:** i při `auth_required=true` (bez platform DB) čtecí endpointy (`*.read`, `metrics.read`) procházely BEZ tokenu jako `anonymous-readonly`. API bylo pro čtení fakticky vždy neautentizované.

**Oprava:** odstraněna celá výjimka (`if read_only_request { return Ok(admin_context("anonymous-readonly")); }`) i mrtvá `is_read_only_permissions()` funkce. Bez platform DB teď fail-closed vyžaduje platný statický token pro **každý** požadavek (čtení i zápis), když je `auth_required=true`.

**Existující test `server_respektuje_api_token` kodifikoval bug jako očekávané chování** (`read_only` request bez tokenu → `assert_eq!(status, 200)`). Opraveno na `assert_eq!(status, 401)` — přesný případ, kdy oprava bezpečnostní chyby vyžaduje úpravu testu, který tu chybu asertoval jako správnou.

## 2. `claim_due_job` nezotavuje zaseknuté `running` joby (`platform.rs`)

**Bug:** `WHERE status IN ('queued', 'scheduled', 'failed')` — `'running'` chybělo. Job, jehož worker spadl mezi claim a dokončením, zůstal navždy zaseknutý (nikdy znovu nevybrán, i po vypršení `claim_until`).

**Oprava:** doplněno `'running'` do seznamu stavů. Existující podmínka `claim_until IS NULL OR claim_until <= now` už správně filtrovala — jen `running` chybělo úplně ze seznamu, takže se k ní nikdy nedostalo.

**Bonus nález:** stejný přesný bug (identický SQL fragment) existoval i ve **dvou dalších funkcích** — `list_due_job_ids()` (zaseknutý job by se neobjevil ani v monitoring přehledu) a `claim_job_by_id()` (ruční operátorský zásah by taky nenašel zaseknutý job). Objeveno náhodou při ověřování regresního testu (hromadný `sed` při dočasném vrácení bugu zasáhl všechny 3 výskyty), následně ověřeno a opraveno se stejnou rigor­ozitou — 4 testy včetně toho, že job se STÁLE platným claim_until se **nesmí** znovu rozdat (ne jen že zaseknutý job se zotaví).

## 3. Broker bez pending-recovery (`broker.rs`)

**Bug:** `XREADGROUP`/`XACK` bez `XAUTOCLAIM`. Konzument, který spadl mezi přečtením zprávy a ACK, zanechal zprávu navždy nedoručenou (Redis pending entries list, `XREADGROUP ... >` čte jen nové zprávy, nikdy PEL).

**Oprava:** nová `reclaim_stale()` (XAUTOCLAIM), zapojená do `claim_one()` — před čekáním na nové zprávy se nejdřív zkusí převzít starý needotknutý pending záznam. Signatura `claim_one` rozšířena o `min_idle_ms` parametr (explicitní, ne skrytá konstanta).

**Idempotence:** vědomě bez dalšího dedup mechanismu v brokeru — `platform::claim_job_by_id`/`claim_due_job` už mají vlastní gating podle stavu jobu v DB, takže dvojí převzetí stejné zprávy je bezpečný no-op. Zdokumentováno, ne fabrikován další mechanismus navíc.

**Testováno proti reálnému Redis** (dočasný Docker kontejner lokálně, CI dostal nový `redis:7-alpine` service container v `.github/workflows/ci.yml` — broker testy byly dřív 0, teď jsou to reálné, ne skippable testy). 3 testy: ACK odstraní zprávu z PEL; spadlý konzument → zprávu převezme jiný; `claim_one` preferuje starý pending záznam před novou zprávou ve streamu. Všechny 3 ověřeny jako skutečně odhalující regresi (dočasné vrácení bugu → testy spadnou, pak vráceno).

## Ověření

Všechny 3 opravy ověřeny metodou "dočasně vrať bug → test musí spadnout → vrať opravu → test musí projít" — ne jen "test prošel po opravě" (to by nedokázalo, že test něco skutečně hlídá). `cargo fmt`/`clippy`/`test` čisté (73/73 v lib, 11/12 v e2e — jediná chyba je předem potvrzený nesouvisející `httpx` problém v prostředí).
