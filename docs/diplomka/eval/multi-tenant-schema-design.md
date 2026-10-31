# Tvar multi-tenant schematu (design dokument, ne kod)

**Status: design dokument, zadny kod, zadna migrace. Vedome.** Rozhodnuto po
2-kolove 3-agentni debate 31.10.2026 (`docs/diplomka/produkcni-plan.md`,
"Druhe kolo zmeny ramce"): vsichni 3 agenti (Opus comprehensive, pragmatik,
skeptik) se shodli, ze samotny `tenant_id` sloupec/pole v kodu BY BYL horsi
nez nic - vytvarel by stejnou falesnou duveru jako neverifikovatelna
izolacni hranice (nikdo nema 2. realneho tenanta, proti kteremu by se dalo
overit, ze izolace skutecne funguje), jen o vrstvu driv. Tenhle dokument
existuje, aby se pri skutecne migraci (trigger: 2. realny tenant) nemuselo
schema navrhovat od nuly nebo migrovat 2x.

## Kde by `tenant_id` sel

Podle `docs/diplomka/BAKULA_kompletni_technicky_navrh_diplomova_prace.md`
(sekce 3.2, "Jednotna `tenant_id`, `site_id`, `sensor_id`, `asset_id`"):

- **`platform.rs`'s SQLite schema** (az bude Postgres, viz trigger nize):
  `users`, `api_tokens`, `jobs`, `nodes`, `ha_policy` - vsechny tabulky
  dostanou `tenant_id` sloupec, FK na novou `tenants` tabulku.
- **`model::RunReport`** - `tenant_id` pole na urovni celeho behu (ne per-
  `HostReport`/`Finding` - run uz dnes patri jednomu operatorovi/scope).
- **Redis stream keys** (`broker.rs`) - prefix `{tenant_id}.bakula.jobs`
  namisto globalniho `bakula.jobs`, aby fronty byly uz na urovni
  transportu oddelene (ne jen filtrovane v DB dotazu).
- **Workspace adresare** (`storage.rs`) - `{workspace_root}/{tenant_id}/runs/...`
  namisto flat `{workspace_root}/runs/...`.
- **`identity-registry.json`** (identity.rs cross-run stav) - per-tenant
  soubor, ne jeden globalni - cross-run identita nema zadny duvod sahat
  pres tenanty.

## Kde `tenant_id` NEJDE jen pridat jako sloupec

- **Enforcement vrstva** (nftables `enforce.block_ip` job, az bude
  postavena) - `tenant_id` musi byt soucasti autorizacniho rozhodnuti PRED
  tim, nez se vubec sestavi `nft` prikaz, ne jen zaznamenany vedle. Jinak
  jde o stejnou tridu chyby jako chybejici `--scope` kontrola u
  `run_forensic_followup_nmap` (opraveno 31.10.2026).
- **`verification_planner.rs`** - rozpoctove limity (A9 mantinely) musi byt
  per-tenant, ne globalni - jeden tenant nesmí vycerpat budget druheho.

## Proc izolace vyzaduje Postgres (ne jen sloupec v SQLite)

SQLite nema radkovou bezpecnost (row-level security) - vynucovani
`WHERE tenant_id = ?` by zavisel na tom, ze KAZDY dotaz v kodu tenhle
filtr nikdy nezapomene pridat. To je presne ten typ chyby, ktery zustane
neodhaleny, dokud neexistuje 2. tenant, jehoz data by unikla do pohledu
1. tenanta. Postgres `ROW LEVEL SECURITY` policy navazana na autentizovany
kontext vynucuje filtr na urovni DB, ne na urovni "doufam, ze jsem to
nezapomel v tomhle jednom z 30 dotazu".

## Trigger pro skutecnou implementaci

**2. realny tenant** (ne kalendarni datum). Az nastane, postup:

1. Postgres migrace (`PlatformRepository` trait nad existujicim
   `platform.rs` schema, viz `produkcni-plan.md` Faze 2) - `tenant_id`
   pridan primo do puvodnich migraci, ne jako dodatecny ALTER TABLE krok.
2. Testy, ktere EXPLICITNE zkousi pristoupit k datum 2. tenanta s
   autentizaci 1. tenanta na KAZDEM API endpointu - bez tehle sady testu
   tenant izolace neni verifikovana, jen implementovana.
3. Redis stream prefix a workspace adresare az po tomhle (zavisi na
   rozhodnutem schema).

## Co tenhle dokument NENI

Neni to zavazek, ze multi-tenant se postavi v urcitem terminu. Je to jen
to, aby rozhodnuti o TVARU bylo zapsane predem, az prijde realny trigger -
presne to, co vsichni 3 agenti v kole 2 oznacili jako jedinou bezpecnou
verzi "rozhodnout tvar ted" bez rizika falesne duvery z predcasneho kodu.
