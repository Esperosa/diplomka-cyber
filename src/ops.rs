//! Provozni vrstva zasahu (Faze C, `docs/diplomka/produkcni-plan.md`): append-only
//! audit log s hash-retezem, zivotni cyklus `enforce.block_ip` akci
//! (proposed -> approved -> applied -> expired / rejected / failed), exekucni
//! rozhrani `NftExecutor` a nezavisly sweep, ktery porovnava zivy `nft` stav s
//! databazi (skeptikuv mantinel c. 2 z kola 2 debaty: jedna naplanovana "unblock"
//! uloha nestaci - kernel timeout je prvni vrstva, sweep druha).
//!
//! Bezpecnostni invarianty (vsechny testovane):
//! - **Dry-run je vychozi.** Skutecny `nft` se zavola jen kdyz `EnforcementMode::Enforce`
//!   (explicitni `BAKULA_ENFORCEMENT_MODE=enforce`); cokoliv jineho/preklep = dry-run.
//! - **Schvaleni je povinne** - akce nejde aplikovat bez stavu `approved`.
//! - **Chranene rozsahy se kontroluji znovu pri aplikaci**, ne jen pri navrhu.
//! - **Audit log je append-only** (SQLite triggery blokuji UPDATE/DELETE) a
//!   tamper-evident (`hash = sha256(prev_hash | pole zaznamu)`, `verify_audit_chain`).
//! - `bakula` meni vyhradne vlastni `table inet bakula`, nikdy cizi pravidla.

use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    enforcement::{
        BlockIpRequest, EnforcementRejection, ProtectedRanges, plan_block,
        render_nft_delete_element, render_setup_ruleset,
    },
    error::{BakulaError, Result},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    DryRun,
    Enforce,
}

impl EnforcementMode {
    /// Fail-closed: jen presne `enforce` zapne skutecne vykonani.
    pub fn parse(value: Option<&str>) -> Self {
        match value.map(|item| item.trim().to_ascii_lowercase()) {
            Some(item) if item == "enforce" => Self::Enforce,
            _ => Self::DryRun,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OpsConfig {
    pub mode: EnforcementMode,
    pub protected: ProtectedRanges,
    pub nft_bin: String,
}

impl OpsConfig {
    pub fn from_env() -> Self {
        let mode = EnforcementMode::parse(std::env::var("BAKULA_ENFORCEMENT_MODE").ok().as_deref());
        let additional = std::env::var("BAKULA_PROTECTED_RANGES")
            .unwrap_or_default()
            .split(',')
            .filter_map(|item| item.trim().parse::<IpNet>().ok())
            .collect::<Vec<_>>();
        Self {
            mode,
            protected: ProtectedRanges::with_additional(additional),
            nft_bin: std::env::var("BAKULA_NFT_BIN").unwrap_or_else(|_| "nft".to_string()),
        }
    }
}

// --- exekucni rozhrani ------------------------------------------------------

pub trait NftExecutor: Send + Sync {
    fn table_exists(&self) -> Result<bool>;
    fn apply_ruleset(&self, text: &str) -> Result<()>;
    fn run(&self, args: &[String]) -> Result<()>;
    fn list_elements(&self, set: &str) -> Result<Vec<String>>;
}

pub struct SystemNft {
    pub bin: String,
}

impl NftExecutor for SystemNft {
    fn table_exists(&self) -> Result<bool> {
        let status = Command::new(&self.bin)
            .args(["list", "table", "inet", "bakula"])
            .output()?
            .status;
        Ok(status.success())
    }

    fn apply_ruleset(&self, text: &str) -> Result<()> {
        let path = std::env::temp_dir().join(format!("bakula-nft-{}.nft", uuid::Uuid::new_v4()));
        std::fs::write(&path, text)?;
        let output = Command::new(&self.bin).arg("-f").arg(&path).output();
        let _ = std::fs::remove_file(&path);
        let output = output?;
        if output.status.success() {
            Ok(())
        } else {
            Err(BakulaError::Processing(format!(
                "nft -f selhal: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }

    fn run(&self, args: &[String]) -> Result<()> {
        let output = Command::new(&self.bin).args(args).output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(BakulaError::Processing(format!(
                "nft {} selhal: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }

    fn list_elements(&self, set: &str) -> Result<Vec<String>> {
        let output = Command::new(&self.bin)
            .args(["-j", "list", "set", "inet", "bakula", set])
            .output()?;
        if !output.status.success() {
            return Ok(Vec::new());
        }
        parse_set_elements(&String::from_utf8_lossy(&output.stdout))
    }
}

/// `nft -j list set` vraci prvky bud jako retezce, nebo jako `{"elem": {"val": ...}}`
/// (pokud maji timeout) - oba tvary jsou platne.
pub fn parse_set_elements(json: &str) -> Result<Vec<String>> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    let mut elements = Vec::new();
    let Some(items) = value.get("nftables").and_then(|item| item.as_array()) else {
        return Ok(elements);
    };
    for item in items {
        let Some(elem_list) = item
            .get("set")
            .and_then(|set| set.get("elem"))
            .and_then(|elem| elem.as_array())
        else {
            continue;
        };
        for elem in elem_list {
            if let Some(text) = elem.as_str() {
                elements.push(text.to_string());
            } else if let Some(text) = elem
                .get("elem")
                .and_then(|inner| inner.get("val"))
                .and_then(|val| val.as_str())
            {
                elements.push(text.to_string());
            }
        }
    }
    Ok(elements)
}

// --- datovy model ------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnforcementAction {
    pub id: i64,
    pub ip: String,
    pub ttl_seconds: u64,
    pub reason: String,
    pub finding_id: Option<String>,
    pub status: String,
    pub nft_command: Vec<String>,
    pub proposed_at: String,
    pub proposed_by: String,
    pub decided_by: Option<String>,
    pub decided_at: Option<String>,
    pub applied_at: Option<String>,
    pub expires_at: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub at: String,
    pub actor: String,
    pub action: String,
    pub subject: String,
    pub detail: String,
    pub hash: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SweepReport {
    pub expired: usize,
    pub drift_removed: Vec<String>,
    pub drift_missing: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposeError {
    Rejected(EnforcementRejection),
    AlreadyActive,
}

// --- store -------------------------------------------------------------------

pub struct OpsStore {
    path: PathBuf,
}

fn db_error(error: rusqlite::Error) -> BakulaError {
    BakulaError::Processing(format!("ops SQLite chyba: {error}"))
}

fn hash_entry(
    prev: &str,
    at: &str,
    actor: &str,
    action: &str,
    subject: &str,
    detail: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{prev}|{at}|{actor}|{action}|{subject}|{detail}"));
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl OpsStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let store = Self {
            path: path.to_path_buf(),
        };
        let conn = store.conn()?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                subject TEXT NOT NULL,
                detail TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
            BEGIN SELECT RAISE(ABORT, 'audit_log je append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
            BEGIN SELECT RAISE(ABORT, 'audit_log je append-only'); END;
            CREATE TABLE IF NOT EXISTS enforcement_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                ttl_seconds INTEGER NOT NULL,
                reason TEXT NOT NULL,
                finding_id TEXT,
                status TEXT NOT NULL,
                nft_command TEXT NOT NULL,
                proposed_at TEXT NOT NULL,
                proposed_by TEXT NOT NULL,
                decided_by TEXT,
                decided_at TEXT,
                applied_at TEXT,
                expires_at TEXT,
                error TEXT
            );
            ",
        )
        .map_err(db_error)?;
        Ok(store)
    }

    fn conn(&self) -> Result<Connection> {
        let conn = Connection::open(&self.path).map_err(db_error)?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(db_error)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(db_error)?;
        Ok(conn)
    }

    // --- audit ---

    pub fn audit(&self, actor: &str, action: &str, subject: &str, detail: &str) -> Result<i64> {
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let id = Self::audit_in_tx(&tx, actor, action, subject, detail)?;
        tx.commit().map_err(db_error)?;
        Ok(id)
    }

    fn audit_in_tx(
        tx: &rusqlite::Transaction<'_>,
        actor: &str,
        action: &str,
        subject: &str,
        detail: &str,
    ) -> Result<i64> {
        let prev: String = tx
            .query_row(
                "SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?
            .unwrap_or_default();
        let at = Utc::now().to_rfc3339();
        let hash = hash_entry(&prev, &at, actor, action, subject, detail);
        tx.execute(
            "INSERT INTO audit_log (at, actor, action, subject, detail, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![at, actor, action, subject, detail, prev, hash],
        )
        .map_err(db_error)?;
        Ok(tx.last_insert_rowid())
    }

    pub fn audit_list(&self, limit: usize) -> Result<Vec<AuditEntry>> {
        let conn = self.conn()?;
        let mut statement = conn
            .prepare(
                "SELECT id, at, actor, action, subject, detail, hash FROM audit_log
                 ORDER BY id DESC LIMIT ?1",
            )
            .map_err(db_error)?;
        let rows = statement
            .query_map([limit as i64], |row| {
                Ok(AuditEntry {
                    id: row.get(0)?,
                    at: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    subject: row.get(4)?,
                    detail: row.get(5)?,
                    hash: row.get(6)?,
                })
            })
            .map_err(db_error)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_error)
    }

    /// Prepocita cely retez; `false` = nekdo zasahl do historie (primym zapisem
    /// do souboru mimo triggery).
    pub fn verify_audit_chain(&self) -> Result<bool> {
        let conn = self.conn()?;
        let mut statement = conn
            .prepare(
                "SELECT at, actor, action, subject, detail, prev_hash, hash FROM audit_log ORDER BY id ASC",
            )
            .map_err(db_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            })
            .map_err(db_error)?;
        let mut expected_prev = String::new();
        for row in rows {
            let (at, actor, action, subject, detail, prev, hash) = row.map_err(db_error)?;
            if prev != expected_prev
                || hash != hash_entry(&prev, &at, &actor, &action, &subject, &detail)
            {
                return Ok(false);
            }
            expected_prev = hash;
        }
        Ok(true)
    }

    // --- zasahy ---

    const COLUMNS: &'static str = "id, ip, ttl_seconds, reason, finding_id, status, nft_command, \
        proposed_at, proposed_by, decided_by, decided_at, applied_at, expires_at, error";

    fn map_action(row: &rusqlite::Row<'_>) -> rusqlite::Result<EnforcementAction> {
        let command_json: String = row.get(6)?;
        Ok(EnforcementAction {
            id: row.get(0)?,
            ip: row.get(1)?,
            ttl_seconds: row.get::<_, i64>(2)? as u64,
            reason: row.get(3)?,
            finding_id: row.get(4)?,
            status: row.get(5)?,
            nft_command: serde_json::from_str(&command_json).unwrap_or_default(),
            proposed_at: row.get(7)?,
            proposed_by: row.get(8)?,
            decided_by: row.get(9)?,
            decided_at: row.get(10)?,
            applied_at: row.get(11)?,
            expires_at: row.get(12)?,
            error: row.get(13)?,
        })
    }

    pub fn get_action(&self, id: i64) -> Result<Option<EnforcementAction>> {
        let conn = self.conn()?;
        conn.query_row(
            &format!(
                "SELECT {} FROM enforcement_actions WHERE id = ?1",
                Self::COLUMNS
            ),
            [id],
            Self::map_action,
        )
        .optional()
        .map_err(db_error)
    }

    pub fn list_actions(&self) -> Result<Vec<EnforcementAction>> {
        let conn = self.conn()?;
        let mut statement = conn
            .prepare(&format!(
                "SELECT {} FROM enforcement_actions ORDER BY id DESC LIMIT 500",
                Self::COLUMNS
            ))
            .map_err(db_error)?;
        let rows = statement
            .query_map([], Self::map_action)
            .map_err(db_error)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_error)
    }

    /// Navrh nove akce. Vnoreny `Result`: vnejsi = infrastruktura (DB), vnitrni =
    /// rozhodnuti (odmitnuto mantinely / uz aktivni).
    pub fn propose(
        &self,
        request: &BlockIpRequest,
        protected: &ProtectedRanges,
        actor: &str,
    ) -> Result<std::result::Result<EnforcementAction, ProposeError>> {
        let plan = match plan_block(request, protected) {
            Ok(plan) => plan,
            Err(rejection) => {
                self.audit(
                    actor,
                    "enforcement.rejected",
                    &request.ip,
                    &format!("{rejection:?}: {}", request.reason),
                )?;
                return Ok(Err(ProposeError::Rejected(rejection)));
            }
        };

        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let active: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM enforcement_actions
                 WHERE ip = ?1 AND status IN ('proposed', 'approved', 'applied')",
                [&plan.ip],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if active > 0 {
            Self::audit_in_tx(
                &tx,
                actor,
                "enforcement.duplicate",
                &plan.ip,
                "AlreadyActive",
            )?;
            tx.commit().map_err(db_error)?;
            return Ok(Err(ProposeError::AlreadyActive));
        }
        let now = Utc::now().to_rfc3339();
        tx.execute(
            "INSERT INTO enforcement_actions
             (ip, ttl_seconds, reason, finding_id, status, nft_command, proposed_at, proposed_by)
             VALUES (?1, ?2, ?3, ?4, 'proposed', ?5, ?6, ?7)",
            params![
                plan.ip,
                plan.ttl_seconds as i64,
                plan.reason,
                plan.finding_id,
                serde_json::to_string(&plan.nft_command)?,
                now,
                actor
            ],
        )
        .map_err(db_error)?;
        let id = tx.last_insert_rowid();
        Self::audit_in_tx(
            &tx,
            actor,
            "enforcement.proposed",
            &plan.ip,
            &format!("id={id} ttl={}s {}", plan.ttl_seconds, plan.reason),
        )?;
        tx.commit().map_err(db_error)?;
        Ok(Ok(self
            .get_action(id)?
            .expect("prave vlozena akce existuje")))
    }

    /// `proposed` -> `approved` / `rejected`. Cokoliv jineho nez `proposed` je chyba.
    pub fn decide(&self, id: i64, approve: bool, actor: &str) -> Result<EnforcementAction> {
        let action = self
            .get_action(id)?
            .ok_or_else(|| BakulaError::Processing(format!("akce {id} neexistuje")))?;
        if action.status != "proposed" {
            return Err(BakulaError::Processing(format!(
                "akce {id} je ve stavu {}, rozhodnout lze jen 'proposed'",
                action.status
            )));
        }
        let status = if approve { "approved" } else { "rejected" };
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        tx.execute(
            "UPDATE enforcement_actions SET status = ?1, decided_by = ?2, decided_at = ?3
             WHERE id = ?4 AND status = 'proposed'",
            params![status, actor, Utc::now().to_rfc3339(), id],
        )
        .map_err(db_error)?;
        Self::audit_in_tx(
            &tx,
            actor,
            if approve {
                "enforcement.approved"
            } else {
                "enforcement.rejected_by_operator"
            },
            &action.ip,
            &format!("id={id}"),
        )?;
        tx.commit().map_err(db_error)?;
        Ok(self.get_action(id)?.expect("akce existuje"))
    }

    /// Schvalena akce -> skutecne vykonani (jen `Enforce`). V `DryRun` se jen
    /// zaznamena, co by se stalo, a akce zustava `approved`.
    pub fn apply_approved(
        &self,
        id: i64,
        mode: EnforcementMode,
        protected: &ProtectedRanges,
        executor: &dyn NftExecutor,
        actor: &str,
    ) -> Result<EnforcementAction> {
        let action = self
            .get_action(id)?
            .ok_or_else(|| BakulaError::Processing(format!("akce {id} neexistuje")))?;
        if action.status != "approved" {
            return Err(BakulaError::Processing(format!(
                "akce {id} je ve stavu {}, aplikovat lze jen 'approved'",
                action.status
            )));
        }

        // Mantinel: chranene rozsahy a TTL se overuji ZNOVU pri vykonani.
        let replan = plan_block(
            &BlockIpRequest {
                ip: action.ip.clone(),
                ttl_seconds: action.ttl_seconds,
                reason: action.reason.clone(),
                finding_id: action.finding_id.clone(),
            },
            protected,
        );
        let plan = match replan {
            Ok(plan) => plan,
            Err(rejection) => {
                return self.mark_failed(id, &action.ip, &format!("{rejection:?}"), actor);
            }
        };

        if mode == EnforcementMode::DryRun {
            self.audit(
                actor,
                "enforcement.dry_run",
                &action.ip,
                &format!("id={id} nft {}", plan.nft_command.join(" ")),
            )?;
            return Ok(action);
        }

        let outcome = (|| -> Result<()> {
            if !executor.table_exists()? {
                executor.apply_ruleset(&render_setup_ruleset())?;
            }
            executor.run(&plan.nft_command)
        })();
        match outcome {
            Ok(()) => {
                let now = Utc::now();
                let expires = now + chrono::Duration::seconds(action.ttl_seconds as i64);
                let mut conn = self.conn()?;
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(db_error)?;
                tx.execute(
                    "UPDATE enforcement_actions SET status = 'applied', applied_at = ?1, expires_at = ?2
                     WHERE id = ?3",
                    params![now.to_rfc3339(), expires.to_rfc3339(), id],
                )
                .map_err(db_error)?;
                Self::audit_in_tx(
                    &tx,
                    actor,
                    "enforcement.applied",
                    &action.ip,
                    &format!("id={id} ttl={}s", action.ttl_seconds),
                )?;
                tx.commit().map_err(db_error)?;
                Ok(self.get_action(id)?.expect("akce existuje"))
            }
            Err(error) => self.mark_failed(id, &action.ip, &error.to_string(), actor),
        }
    }

    fn mark_failed(
        &self,
        id: i64,
        ip: &str,
        reason: &str,
        actor: &str,
    ) -> Result<EnforcementAction> {
        let mut conn = self.conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        tx.execute(
            "UPDATE enforcement_actions SET status = 'failed', error = ?1 WHERE id = ?2",
            params![reason, id],
        )
        .map_err(db_error)?;
        Self::audit_in_tx(
            &tx,
            actor,
            "enforcement.failed",
            ip,
            &format!("id={id} {reason}"),
        )?;
        tx.commit().map_err(db_error)?;
        Ok(self.get_action(id)?.expect("akce existuje"))
    }

    /// Nezavisly sweep: (1) lokalne exspiruje akce po TTL, (2) v `Enforce` modu
    /// porovna zivy obsah vlastnich setu s databazi - prvek v kernelu bez
    /// aktivni akce se odstrani (drift), aktivni akce bez prvku se oznaci jako
    /// expirovana (kernel timeout / rucni zasah).
    pub fn sweep(
        &self,
        mode: EnforcementMode,
        executor: &dyn NftExecutor,
        now: DateTime<Utc>,
    ) -> Result<SweepReport> {
        let mut report = SweepReport::default();
        let actions = self.list_actions()?;

        for action in actions.iter().filter(|item| item.status == "applied") {
            let expired = action
                .expires_at
                .as_deref()
                .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
                .is_some_and(|expires| expires.with_timezone(&Utc) <= now);
            if expired {
                self.set_status(action.id, "expired")?;
                self.audit(
                    "sweep",
                    "enforcement.expired",
                    &action.ip,
                    &format!("id={}", action.id),
                )?;
                report.expired += 1;
            }
        }

        if mode != EnforcementMode::Enforce || !executor.table_exists()? {
            return Ok(report);
        }

        let still_active: Vec<std::net::IpAddr> = self
            .list_actions()?
            .iter()
            .filter(|item| item.status == "applied")
            .filter_map(|item| item.ip.parse().ok())
            .collect();

        let mut live: Vec<std::net::IpAddr> = Vec::new();
        for set in ["blocked_ips", "blocked_ips6"] {
            live.extend(
                executor
                    .list_elements(set)?
                    .iter()
                    .filter_map(|text| text.parse::<std::net::IpAddr>().ok()),
            );
        }

        for ip in live.iter().filter(|ip| !still_active.contains(ip)) {
            let text = ip.to_string();
            if let Some(command) = render_nft_delete_element(&text) {
                executor.run(&command)?;
                self.audit(
                    "sweep",
                    "enforcement.drift_removed",
                    &text,
                    "prvek v kernelu bez aktivni akce",
                )?;
                report.drift_removed.push(text);
            }
        }
        for action in self
            .list_actions()?
            .iter()
            .filter(|item| item.status == "applied")
        {
            let Ok(ip) = action.ip.parse::<std::net::IpAddr>() else {
                continue;
            };
            if !live.contains(&ip) {
                self.set_status(action.id, "expired")?;
                self.audit(
                    "sweep",
                    "enforcement.drift_missing",
                    &action.ip,
                    "aktivni akce nema prvek v kernelu (timeout nebo rucni zasah)",
                )?;
                report.drift_missing.push(action.ip.clone());
            }
        }
        Ok(report)
    }

    fn set_status(&self, id: i64, status: &str) -> Result<()> {
        self.conn()?
            .execute(
                "UPDATE enforcement_actions SET status = ?1 WHERE id = ?2",
                params![status, id],
            )
            .map_err(db_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Falesny `nft`: pamatuje si vykonane prikazy a obsah setu, nic nespousti.
    #[derive(Default)]
    struct FakeNft {
        table_present: Mutex<bool>,
        commands: Mutex<Vec<Vec<String>>>,
        rulesets: Mutex<Vec<String>>,
        elements: Mutex<Vec<String>>,
        fail_run: bool,
    }

    impl NftExecutor for FakeNft {
        fn table_exists(&self) -> Result<bool> {
            Ok(*self.table_present.lock().unwrap())
        }
        fn apply_ruleset(&self, text: &str) -> Result<()> {
            self.rulesets.lock().unwrap().push(text.to_string());
            *self.table_present.lock().unwrap() = true;
            Ok(())
        }
        fn run(&self, args: &[String]) -> Result<()> {
            if self.fail_run {
                return Err(BakulaError::Processing(
                    "nft simulovane selhani".to_string(),
                ));
            }
            self.commands.lock().unwrap().push(args.to_vec());
            // add element ... { 1.2.3.4 timeout 60s }
            if args.first().map(String::as_str) == Some("add")
                && let Some(last) = args.last()
            {
                let ip = last.trim_matches(|c| c == '{' || c == '}' || c == ' ');
                let ip = ip.split_whitespace().next().unwrap_or("");
                self.elements.lock().unwrap().push(ip.to_string());
            }
            if args.first().map(String::as_str) == Some("delete")
                && let Some(last) = args.last()
            {
                let ip = last
                    .trim_matches(|c| c == '{' || c == '}' || c == ' ')
                    .to_string();
                self.elements.lock().unwrap().retain(|item| item != &ip);
            }
            Ok(())
        }
        fn list_elements(&self, set: &str) -> Result<Vec<String>> {
            let all = self.elements.lock().unwrap().clone();
            Ok(all
                .into_iter()
                .filter(|item| item.contains(':') == (set == "blocked_ips6"))
                .collect())
        }
    }

    fn store() -> (tempfile::TempDir, OpsStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = OpsStore::open(&dir.path().join("ops.sqlite")).expect("open");
        (dir, store)
    }

    fn protected() -> ProtectedRanges {
        ProtectedRanges::with_additional(vec!["192.168.1.1/32".parse().unwrap()])
    }

    fn request(ip: &str) -> BlockIpRequest {
        BlockIpRequest {
            ip: ip.to_string(),
            ttl_seconds: 600,
            reason: "test".to_string(),
            finding_id: None,
        }
    }

    #[test]
    fn mode_parse_is_fail_closed() {
        assert_eq!(
            EnforcementMode::parse(Some("enforce")),
            EnforcementMode::Enforce
        );
        assert_eq!(
            EnforcementMode::parse(Some(" ENFORCE ")),
            EnforcementMode::Enforce
        );
        assert_eq!(
            EnforcementMode::parse(Some("enforc")),
            EnforcementMode::DryRun
        );
        assert_eq!(
            EnforcementMode::parse(Some("true")),
            EnforcementMode::DryRun
        );
        assert_eq!(EnforcementMode::parse(None), EnforcementMode::DryRun);
    }

    #[test]
    fn audit_chain_verifies_and_detects_tampering() {
        let (dir, store) = store();
        store.audit("a", "x", "s1", "d1").unwrap();
        store.audit("a", "y", "s2", "d2").unwrap();
        store.audit("b", "z", "s3", "d3").unwrap();
        assert!(store.verify_audit_chain().unwrap());

        // Obejiti triggeru primym zasahem (utocnik s pristupem k souboru).
        let conn = Connection::open(dir.path().join("ops.sqlite")).unwrap();
        conn.execute_batch("DROP TRIGGER audit_log_no_update;")
            .unwrap();
        conn.execute(
            "UPDATE audit_log SET detail = 'zfalsovano' WHERE id = 2",
            [],
        )
        .unwrap();
        assert!(!store.verify_audit_chain().unwrap());
    }

    #[test]
    fn audit_log_rejects_update_and_delete_via_triggers() {
        let (dir, store) = store();
        store.audit("a", "x", "s", "d").unwrap();
        let conn = Connection::open(dir.path().join("ops.sqlite")).unwrap();
        assert!(
            conn.execute("UPDATE audit_log SET detail = 'x'", [])
                .is_err()
        );
        assert!(conn.execute("DELETE FROM audit_log", []).is_err());
    }

    #[test]
    fn propose_rejection_is_audited_and_creates_no_action() {
        let (_dir, store) = store();
        let result = store
            .propose(&request("192.168.1.1"), &protected(), "alice")
            .unwrap();
        assert_eq!(
            result,
            Err(ProposeError::Rejected(EnforcementRejection::ProtectedRange))
        );
        assert!(store.list_actions().unwrap().is_empty());
        assert_eq!(
            store.audit_list(10).unwrap()[0].action,
            "enforcement.rejected"
        );
    }

    #[test]
    fn duplicate_active_proposal_is_refused() {
        let (_dir, store) = store();
        store
            .propose(&request("203.0.113.5"), &protected(), "alice")
            .unwrap()
            .unwrap();
        let second = store
            .propose(&request("203.0.113.5"), &protected(), "alice")
            .unwrap();
        assert_eq!(second, Err(ProposeError::AlreadyActive));
    }

    #[test]
    fn dry_run_never_calls_nft_even_when_approved() {
        let (_dir, store) = store();
        let nft = FakeNft::default();
        let action = store
            .propose(&request("203.0.113.5"), &protected(), "alice")
            .unwrap()
            .unwrap();
        store.decide(action.id, true, "bob").unwrap();
        let result = store
            .apply_approved(
                action.id,
                EnforcementMode::DryRun,
                &protected(),
                &nft,
                "bob",
            )
            .unwrap();
        assert_eq!(result.status, "approved");
        assert!(nft.commands.lock().unwrap().is_empty());
        assert!(nft.rulesets.lock().unwrap().is_empty());
        assert!(
            store
                .audit_list(10)
                .unwrap()
                .iter()
                .any(|e| e.action == "enforcement.dry_run")
        );
    }

    #[test]
    fn unapproved_action_cannot_be_applied() {
        let (_dir, store) = store();
        let nft = FakeNft::default();
        let action = store
            .propose(&request("203.0.113.5"), &protected(), "alice")
            .unwrap()
            .unwrap();
        let error = store
            .apply_approved(
                action.id,
                EnforcementMode::Enforce,
                &protected(),
                &nft,
                "bob",
            )
            .unwrap_err();
        assert!(error.to_string().contains("proposed"));
        assert!(nft.commands.lock().unwrap().is_empty());
    }

    #[test]
    fn enforce_installs_table_once_then_adds_element() {
        let (_dir, store) = store();
        let nft = FakeNft::default();
        for ip in ["203.0.113.5", "203.0.113.6"] {
            let action = store
                .propose(&request(ip), &protected(), "alice")
                .unwrap()
                .unwrap();
            store.decide(action.id, true, "bob").unwrap();
            let applied = store
                .apply_approved(
                    action.id,
                    EnforcementMode::Enforce,
                    &protected(),
                    &nft,
                    "bob",
                )
                .unwrap();
            assert_eq!(applied.status, "applied");
            assert!(applied.expires_at.is_some());
        }
        assert_eq!(nft.rulesets.lock().unwrap().len(), 1, "ruleset jen jednou");
        assert_eq!(nft.commands.lock().unwrap().len(), 2);
    }

    #[test]
    fn protected_range_is_rechecked_at_execution_time() {
        let (_dir, store) = store();
        let nft = FakeNft::default();
        let action = store
            .propose(&request("10.9.9.9"), &protected(), "alice")
            .unwrap()
            .unwrap();
        store.decide(action.id, true, "bob").unwrap();
        // Mezitim operator pridal rozsah do chranenych.
        let stricter = ProtectedRanges::with_additional(vec!["10.9.9.0/24".parse().unwrap()]);
        let result = store
            .apply_approved(action.id, EnforcementMode::Enforce, &stricter, &nft, "bob")
            .unwrap();
        assert_eq!(result.status, "failed");
        assert!(nft.commands.lock().unwrap().is_empty());
    }

    #[test]
    fn executor_failure_marks_action_failed_with_error() {
        let (_dir, store) = store();
        let nft = FakeNft {
            fail_run: true,
            ..Default::default()
        };
        let action = store
            .propose(&request("203.0.113.5"), &protected(), "alice")
            .unwrap()
            .unwrap();
        store.decide(action.id, true, "bob").unwrap();
        let result = store
            .apply_approved(
                action.id,
                EnforcementMode::Enforce,
                &protected(),
                &nft,
                "bob",
            )
            .unwrap();
        assert_eq!(result.status, "failed");
        assert!(result.error.unwrap().contains("simulovane selhani"));
    }

    #[test]
    fn sweep_expires_actions_past_ttl() {
        let (_dir, store) = store();
        let nft = FakeNft::default();
        let action = store
            .propose(&request("203.0.113.5"), &protected(), "alice")
            .unwrap()
            .unwrap();
        store.decide(action.id, true, "bob").unwrap();
        store
            .apply_approved(
                action.id,
                EnforcementMode::Enforce,
                &protected(),
                &nft,
                "bob",
            )
            .unwrap();
        let later = Utc::now() + chrono::Duration::seconds(601);
        let report = store.sweep(EnforcementMode::Enforce, &nft, later).unwrap();
        assert_eq!(report.expired, 1);
        assert_eq!(
            store.get_action(action.id).unwrap().unwrap().status,
            "expired"
        );
    }

    #[test]
    fn sweep_removes_kernel_elements_without_active_action() {
        let (_dir, store) = store();
        let nft = FakeNft::default();
        // Prvek v kernelu, o kterem databaze nevi (rucni `nft add element`).
        *nft.table_present.lock().unwrap() = true;
        nft.elements
            .lock()
            .unwrap()
            .push("198.51.100.77".to_string());
        let report = store
            .sweep(EnforcementMode::Enforce, &nft, Utc::now())
            .unwrap();
        assert_eq!(report.drift_removed, vec!["198.51.100.77".to_string()]);
        assert!(nft.elements.lock().unwrap().is_empty());
    }

    #[test]
    fn sweep_marks_active_action_missing_in_kernel() {
        let (_dir, store) = store();
        let nft = FakeNft::default();
        let action = store
            .propose(&request("203.0.113.5"), &protected(), "alice")
            .unwrap()
            .unwrap();
        store.decide(action.id, true, "bob").unwrap();
        store
            .apply_approved(
                action.id,
                EnforcementMode::Enforce,
                &protected(),
                &nft,
                "bob",
            )
            .unwrap();
        nft.elements.lock().unwrap().clear(); // kernel timeout / rucni smazani
        let report = store
            .sweep(EnforcementMode::Enforce, &nft, Utc::now())
            .unwrap();
        assert_eq!(report.drift_missing, vec!["203.0.113.5".to_string()]);
    }

    #[test]
    fn sweep_in_dry_run_never_touches_kernel() {
        let (_dir, store) = store();
        let nft = FakeNft::default();
        *nft.table_present.lock().unwrap() = true;
        nft.elements
            .lock()
            .unwrap()
            .push("198.51.100.77".to_string());
        let report = store
            .sweep(EnforcementMode::DryRun, &nft, Utc::now())
            .unwrap();
        assert!(report.drift_removed.is_empty());
        assert_eq!(nft.elements.lock().unwrap().len(), 1);
    }

    #[test]
    fn parse_set_elements_handles_both_shapes() {
        let json = r#"{"nftables":[{"metainfo":{}},{"set":{"name":"blocked_ips","elem":[
            "1.2.3.4", {"elem":{"val":"5.6.7.8","timeout":60,"expires":59}}]}}]}"#;
        assert_eq!(
            parse_set_elements(json).unwrap(),
            vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()]
        );
        assert!(
            parse_set_elements(r#"{"nftables":[{"set":{"name":"x"}}]}"#)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rejected_by_operator_cannot_be_applied_later() {
        let (_dir, store) = store();
        let nft = FakeNft::default();
        let action = store
            .propose(&request("203.0.113.5"), &protected(), "alice")
            .unwrap()
            .unwrap();
        let decided = store.decide(action.id, false, "bob").unwrap();
        assert_eq!(decided.status, "rejected");
        assert!(
            store
                .apply_approved(
                    action.id,
                    EnforcementMode::Enforce,
                    &protected(),
                    &nft,
                    "bob"
                )
                .is_err()
        );
        assert!(
            store.decide(action.id, true, "bob").is_err(),
            "rozhodnuti jde jen jednou"
        );
    }
}
