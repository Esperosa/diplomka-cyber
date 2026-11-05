//! Provozní audit automatických uzavření (krok 7, A3; docs/diplomka/eval/impl-krok7.md).
//!
//! Dřív `ContextGate::record_audit` volaly jen soak a testy: produkční cesta zavírala
//! bez lidské kontroly a vypnutí druhu kontextu nepřežilo běh. Tady:
//!
//! - každé automatické zavření (kontext podle druhu, vyvrácení žebříkem jako `ladder`)
//!   se s pravděpodobností `sample_rate` (deterministicky podle tajného klíče instalace
//!   a klíče nálezu) zařadí do vzorku pro člověka s termínem `deadline_s`;
//! - verdikty člověka přicházejí přes API do append-only tabulky `closure_reviews`
//!   (server jen vkládá, pipeline je při dalším běhu započte: žádný souběh zápisu stavu);
//! - druh se TRVALE vypne, když dolní mez Wilsonova 95% intervalu omylu > cíl
//!   (`error_target`) při aspoň `min_samples` recenzích. Dolní mez nad cílem je doklad,
//!   že omyl cíl překračuje (H-A3). NENÍ to certifikace horní meze: nevypnutý druh nemá
//!   prokázanou chybovost pod cílem. Obnovit druh smí jen člověk (řádek `enable`);
//! - fail-safe: vzorek po termínu nebo backlog nad `max_backlog` zastaví veškeré
//!   automatické zavírání (bez recenzí se po termínu nezavírá nic);
//! - každý krok jde do `finding_audit` (append-only).

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use crate::{
    context_gate::wilson_lower,
    error::{BakulaError, Result},
    finding_memory::FindingKey,
};

fn db_error(error: rusqlite::Error) -> BakulaError {
    BakulaError::Processing(format!("closure_audit SQLite chyba: {error}"))
}

/// Druh zavření žebříkem (vedle druhů kontextu).
pub const LADDER_KIND: &str = "ladder";

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditPolicy {
    pub sample_rate: f64,
    pub deadline_s: i64,
    pub max_backlog: usize,
    pub min_samples: u64,
    pub error_target: f64,
}

impl Default for AuditPolicy {
    /// Předregistrace A3: 10 %, 72 h, backlog 50, 30 recenzí, cíl 2 %.
    fn default() -> Self {
        Self {
            sample_rate: 0.10,
            deadline_s: 72 * 3600,
            max_backlog: 50,
            min_samples: 30,
            error_target: 0.02,
        }
    }
}

impl AuditPolicy {
    /// Politika z `closure-audit.json` ve workspace (chybí = výchozí). Neplatné hodnoty
    /// se oříznou do bezpečných mezí (nelze vypnout termín ani vzorkování).
    pub fn load(workspace: &std::path::Path) -> Result<Self> {
        let path = workspace.join("closure-audit.json");
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path)?;
        let mut policy: Self = serde_json::from_str(&text).map_err(BakulaError::Json)?;
        policy.sample_rate = policy.sample_rate.clamp(0.01, 1.0);
        policy.deadline_s = policy.deadline_s.clamp(3600, 30 * 86_400);
        policy.max_backlog = policy.max_backlog.clamp(1, 10_000);
        policy.min_samples = policy.min_samples.max(1);
        policy.error_target = policy.error_target.clamp(0.0, 0.5);
        Ok(policy)
    }
}

/// Jeden vzorek zavření čekající na člověka.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sample {
    pub id: u64,
    pub kind: String,
    pub key: FindingKey,
    pub finding_id: String,
    pub reason: String,
    pub closed_at: DateTime<Utc>,
    pub deadline: DateTime<Utc>,
}

/// Stav auditu (kv `closure_audit` v `engine-state.sqlite`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ClosureAudit {
    pub samples: Vec<Sample>,
    /// druh -> (recenzí, omylů)
    pub reviewed: BTreeMap<String, (u64, u64)>,
    pub disabled: BTreeSet<String>,
    pub next_id: u64,
    /// Poslední započtený řádek `closure_reviews`.
    pub applied_review: i64,
    secret: u64,
}

/// Souhrn pro report a API.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AuditStatus {
    pub pending: usize,
    pub overdue: usize,
    /// Fail-safe: automatické zavírání zastavené (backlog nebo termín).
    pub halted: bool,
    pub disabled: Vec<String>,
    pub reviewed: BTreeMap<String, (u64, u64)>,
}

/// Co se stalo při započtení recenzí (pro audit v paměti nálezů).
#[derive(Debug, Clone, PartialEq)]
pub enum AuditEvent {
    Reviewed {
        sample: Sample,
        wrong: bool,
        actor: String,
    },
    Disabled {
        kind: String,
        n: u64,
        wrong: u64,
    },
    Enabled {
        kind: String,
        actor: String,
    },
}

/// Vytvoří append-only tabulku recenzí (volá pipeline i server).
pub fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS closure_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            at INTEGER NOT NULL,
            action TEXT NOT NULL,
            sample_id INTEGER,
            kind TEXT,
            wrong INTEGER,
            actor TEXT NOT NULL,
            note TEXT NOT NULL
        );
        CREATE TRIGGER IF NOT EXISTS closure_reviews_no_update BEFORE UPDATE ON closure_reviews
        BEGIN SELECT RAISE(ABORT, 'closure_reviews je append-only'); END;
        CREATE TRIGGER IF NOT EXISTS closure_reviews_no_delete BEFORE DELETE ON closure_reviews
        BEGIN SELECT RAISE(ABORT, 'closure_reviews je append-only'); END;",
    )
    .map_err(db_error)
}

/// API: verdikt člověka ke vzorku (`wrong` = zavření skrylo útok).
pub fn submit_review(
    conn: &Connection,
    sample_id: u64,
    wrong: bool,
    actor: &str,
    note: &str,
    at: DateTime<Utc>,
) -> Result<i64> {
    migrate(conn)?;
    conn.execute(
        "INSERT INTO closure_reviews (at, action, sample_id, kind, wrong, actor, note)
         VALUES (?1, 'review', ?2, NULL, ?3, ?4, ?5)",
        params![
            at.timestamp(),
            sample_id as i64,
            wrong as i64,
            actor,
            note.chars().take(500).collect::<String>()
        ],
    )
    .map_err(db_error)?;
    Ok(conn.last_insert_rowid())
}

/// API: člověk vrací vypnutý druh do provozu (zapíše se do auditu).
pub fn submit_enable(
    conn: &Connection,
    kind: &str,
    actor: &str,
    note: &str,
    at: DateTime<Utc>,
) -> Result<i64> {
    migrate(conn)?;
    conn.execute(
        "INSERT INTO closure_reviews (at, action, sample_id, kind, wrong, actor, note)
         VALUES (?1, 'enable', NULL, ?2, NULL, ?3, ?4)",
        params![
            at.timestamp(),
            kind,
            actor,
            note.chars().take(500).collect::<String>()
        ],
    )
    .map_err(db_error)?;
    Ok(conn.last_insert_rowid())
}

/// Řádek `closure_reviews`: id, akce, vzorek, druh, omyl, autor.
type ReviewRow = (
    i64,
    String,
    Option<i64>,
    Option<String>,
    Option<i64>,
    String,
);

fn mix(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^ (x >> 33)
}

fn hash_text(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ b as u64).wrapping_mul(0x100_0000_01b3)
    })
}

impl ClosureAudit {
    /// Tajný klíč vzorkování (náhodný při prvním použití, pak perzistentní), aby
    /// útočník nemohl předpovědět, která zavření člověk uvidí.
    pub fn ensure_secret(&mut self) {
        if self.secret == 0 {
            self.secret = u64::from_le_bytes(
                uuid::Uuid::new_v4().as_bytes()[..8]
                    .try_into()
                    .expect("8 bajtu"),
            ) | 1;
        }
    }

    pub fn is_disabled(&self, kind: &str) -> bool {
        self.disabled.contains(kind)
    }

    pub fn overdue(&self, now: DateTime<Utc>) -> usize {
        self.samples.iter().filter(|s| s.deadline < now).count()
    }

    /// Smí se automaticky zavírat (žádný vzorek po termínu, backlog pod stropem)?
    pub fn auto_close_allowed(&self, policy: &AuditPolicy, now: DateTime<Utc>) -> bool {
        self.overdue(now) == 0 && self.samples.len() <= policy.max_backlog
    }

    pub fn status(&self, policy: &AuditPolicy, now: DateTime<Utc>) -> AuditStatus {
        AuditStatus {
            pending: self.samples.len(),
            overdue: self.overdue(now),
            halted: !self.auto_close_allowed(policy, now),
            disabled: self.disabled.iter().cloned().collect(),
            reviewed: self.reviewed.clone(),
        }
    }

    /// Zařadí zavření do vzorku (deterministicky podle klíče); vrací vzorek.
    pub fn maybe_sample(
        &mut self,
        policy: &AuditPolicy,
        kind: &str,
        key: &FindingKey,
        finding_id: &str,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Option<Sample> {
        self.ensure_secret();
        let roll = mix(self.secret
            ^ hash_text(&key.entity)
            ^ hash_text(&key.finding_type).rotate_left(17)
            ^ hash_text(&key.service).rotate_left(31)
            ^ (now.timestamp() as u64).wrapping_mul(0x9E37));
        if (roll % 1_000_000) as f64 >= policy.sample_rate * 1_000_000.0 {
            return None;
        }
        let sample = Sample {
            id: self.next_id + 1,
            kind: kind.to_string(),
            key: key.clone(),
            finding_id: finding_id.to_string(),
            reason: reason.chars().take(300).collect(),
            closed_at: now,
            deadline: now + chrono::Duration::seconds(policy.deadline_s),
        };
        self.next_id += 1;
        self.samples.push(sample.clone());
        Some(sample)
    }

    /// Započte nové řádky `closure_reviews`: recenze ke vzorkům, vypnutí druhu při
    /// překročení meze a ruční obnovení. Recenze neznámého vzorku se zahodí.
    pub fn apply_reviews(
        &mut self,
        conn: &Connection,
        policy: &AuditPolicy,
    ) -> Result<Vec<AuditEvent>> {
        migrate(conn)?;
        let mut stmt = conn
            .prepare(
                "SELECT id, action, sample_id, kind, wrong, actor FROM closure_reviews
                 WHERE id > ?1 ORDER BY id",
            )
            .map_err(db_error)?;
        let rows: Vec<ReviewRow> = stmt
            .query_map(params![self.applied_review], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })
            .map_err(db_error)?
            .collect::<std::result::Result<_, _>>()
            .map_err(db_error)?;
        let mut events = Vec::new();
        for (id, action, sample_id, kind, wrong, actor) in rows {
            self.applied_review = id;
            match action.as_str() {
                "review" => {
                    let Some(index) = sample_id
                        .and_then(|sid| self.samples.iter().position(|s| s.id as i64 == sid))
                    else {
                        continue;
                    };
                    let sample = self.samples.remove(index);
                    let wrong = wrong.unwrap_or(0) != 0;
                    let entry = self.reviewed.entry(sample.kind.clone()).or_default();
                    entry.0 += 1;
                    entry.1 += wrong as u64;
                    let (n, k) = *entry;
                    let kind = sample.kind.clone();
                    events.push(AuditEvent::Reviewed {
                        sample,
                        wrong,
                        actor,
                    });
                    if n >= policy.min_samples
                        && wilson_lower(k, n) > policy.error_target
                        && self.disabled.insert(kind.clone())
                    {
                        events.push(AuditEvent::Disabled { kind, n, wrong: k });
                    }
                }
                "enable" => {
                    if let Some(kind) = kind
                        && self.disabled.remove(&kind)
                    {
                        // nove pocitani po obnoveni (stare omyly by ho hned vypnuly)
                        self.reviewed.remove(&kind);
                        events.push(AuditEvent::Enabled { kind, actor });
                    }
                }
                _ => {}
            }
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(hours: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_767_571_200 + hours * 3600, 0).unwrap()
    }

    fn key(i: u32) -> FindingKey {
        FindingKey::new(
            &format!("10.0.0.{i}"),
            "inductive_volume_anomaly",
            "tcp/445",
        )
    }

    #[test]
    fn reviews_disable_kind_persistently_and_human_can_enable() {
        let conn = Connection::open_in_memory().unwrap();
        let policy = AuditPolicy {
            sample_rate: 1.0,
            min_samples: 3,
            ..AuditPolicy::default()
        };
        let mut audit = ClosureAudit::default();
        let ids: Vec<u64> = (0..3)
            .map(|i| {
                audit
                    .maybe_sample(&policy, "backup", &key(i), "f", "backup okno", at(0))
                    .unwrap()
                    .id
            })
            .collect();
        assert_eq!(audit.samples.len(), 3);
        for (n, id) in ids.iter().enumerate() {
            submit_review(&conn, *id, n < 2, "analytik", "", at(1)).unwrap();
        }
        submit_review(&conn, 999, true, "analytik", "neznamy", at(1)).unwrap();
        let events = audit.apply_reviews(&conn, &policy).unwrap();
        assert!(events.contains(&AuditEvent::Disabled {
            kind: "backup".into(),
            n: 3,
            wrong: 2
        }));
        assert!(audit.is_disabled("backup") && audit.samples.is_empty());
        // restart: serializace stavu, vypnuti plati, recenze se znovu nezapocitaji
        let mut audit: ClosureAudit =
            serde_json::from_str(&serde_json::to_string(&audit).unwrap()).unwrap();
        assert!(audit.is_disabled("backup"));
        assert!(audit.apply_reviews(&conn, &policy).unwrap().is_empty());
        submit_enable(&conn, "backup", "spravce", "oprava kalendare", at(2)).unwrap();
        let events = audit.apply_reviews(&conn, &policy).unwrap();
        assert!(matches!(&events[0], AuditEvent::Enabled { kind, .. } if kind == "backup"));
        assert!(!audit.is_disabled("backup"));
        // tabulka je append-only
        assert!(conn.execute("DELETE FROM closure_reviews", []).is_err());
    }

    #[test]
    fn overdue_sample_or_backlog_halts_auto_closing() {
        let policy = AuditPolicy {
            sample_rate: 1.0,
            max_backlog: 2,
            ..AuditPolicy::default()
        };
        let mut audit = ClosureAudit::default();
        assert!(audit.auto_close_allowed(&policy, at(0)));
        audit.maybe_sample(&policy, "backup", &key(1), "f", "r", at(0));
        assert!(audit.auto_close_allowed(&policy, at(71)));
        assert!(!audit.auto_close_allowed(&policy, at(73)), "termin 72 h");
        let mut audit = ClosureAudit::default();
        for i in 0..3 {
            audit.maybe_sample(&policy, "backup", &key(i), "f", "r", at(0));
        }
        assert!(
            !audit.auto_close_allowed(&policy, at(1)),
            "backlog nad stropem"
        );
        assert!(audit.status(&policy, at(1)).halted);
    }

    #[test]
    fn sampling_rate_is_close_to_policy_and_secret_dependent() {
        let policy = AuditPolicy::default();
        let mut a = ClosureAudit::default();
        let mut b = ClosureAudit::default();
        let mut hits_a = 0;
        let mut same = 0;
        for i in 0..2000 {
            let ha = a
                .maybe_sample(&policy, "backup", &key(i), "f", "r", at(0))
                .is_some();
            let hb = b
                .maybe_sample(&policy, "backup", &key(i), "f", "r", at(0))
                .is_some();
            hits_a += ha as u32;
            same += (ha && hb) as u32;
        }
        assert!((150..=250).contains(&hits_a), "{hits_a}");
        assert!(same < hits_a, "ruzne instalace vzorkuji ruzne");
    }

    #[test]
    fn policy_file_is_clamped_to_safe_bounds() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("closure-audit.json"),
            r#"{"sample_rate": 0.0, "deadline_s": 0, "max_backlog": 0}"#,
        )
        .unwrap();
        let policy = AuditPolicy::load(dir.path()).unwrap();
        assert!(policy.sample_rate >= 0.01 && policy.deadline_s >= 3600);
        assert!(policy.max_backlog >= 1);
    }
}
