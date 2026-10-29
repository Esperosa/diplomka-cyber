# H5 krok 1: korektnostní opravy jádra brokeru/platformy (Deliverable 24)

**Status: hotovo (29. 10. 2026).** První krok produkčního plánu (`docs/diplomka/produkcni-plan.md`) pro H5 — oprava reálných korektnostních mezer, které nezávislý 3-agentní audit našel v `src/platform.rs`/`src/broker.rs`/`src/main.rs`, PŘED skokem na skutečný multi-host test (ten je další fáze, vyžaduje Postgres migraci).

## Co bylo opraveno

1. **`claimed_by` fencing (kritický bug).** `mark_job_succeeded`/`mark_job_failed` dřív aktualizovaly `WHERE id = ?` bez kontroly, kdo job skutečně drží. Scénář: worker A převezme job, jeho lease vyprší (ale A stále pracuje, třeba na pomalém síťovém volání), worker B legitimně job znovu převezme, A dokončí svou už neplatnou práci a zapíše výsledek — **tiše přepíše to, co dělá B**. Oprava: obě funkce teď vyžadují `claimed_by: &str` a aktualizují jen `WHERE id = ? AND claimed_by = ?`, vrací `bool` (zda se fence uplatnil). Volající (`worker_cycle` v `platform.rs`, inline worker v `main.rs`) na `false` reagují chybou/logem, ne tichým pokračováním.
2. **Lease konfigurace navázaná na realitu.** `broker::claim_one`'s `min_idle_ms` parametr pro XAUTOCLAIM byl hardcoded `30_000` na dvou místech (`main.rs`), bez ohledu na skutečně nakonfigurovaný `--job-lease-s`/`--lease-s`. Teď se počítá z konfigurace (`lease_seconds * 1000`).
3. **Regresní test na fencing bug** (`mark_job_succeeded_is_fenced_against_stale_worker_after_job_was_reclaimed`): reprodukuje přesně ten scénář výše, ověřeno metodou "vrať bug → test spadne → vrať oprava → test projde" (bez fence spadl na param-count mismatch, s fence projde).
4. **Reálný souběžný test** (`concurrent_claim_due_job_never_double_claims_across_real_threads`): 4 OS vlákna soutěží o 20 jobů ve stejném SQLite souboru přes `claim_due_job`. Adresuje přímo obavu z nezávislého auditu ("atomicita claim-query pod konkurencí nikdy neověřena") — **ne** oddělené OS procesy (to je další krok, Fáze 2), ale reálná vláknová konkurence nad stejným souborem přes `TransactionBehavior::Immediate`.

## Naměřeno

- Souběžný test stabilní přes 3 opakované běhy (0 double-claimů ze 20 jobů × 4 vlákna).
- `TransactionBehavior::Immediate` v `claim_due_job`/`claim_job_by_id` skutečně poskytuje vzájemné vyloučení pro SELECT+UPDATE dvojici — potvrzeno měřením, ne jen čtením kódu.
- Broker testy (`broker::tests::*`) proti reálnému Redis kontejneru dál projdou beze změny (3/3).

## Honestní omezení

- **Vlákna v jednom procesu ≠ oddělené OS procesy.** SQLite souborové zámky by měly fungovat stejně i mezi procesy na jednom stroji, ale skutečný test se 2+ samostatně spuštěnými binárkami ještě neproběhl — to je příští, konkrétní krok (Fáze 1 pokračuje).
- **SQLite přes síťový souborový systém zůstává nefunkční** — žádná z těchto oprav neřeší skutečný multi-host blokátor (potřeba Postgres migrace, Fáze 2 produkčního plánu).
- **DLQ a connection pooling pro broker zatím nejsou postaveny** — zůstávají v `produkcni-plan.md` jako další položky Fáze 1.
