//! Paměť nálezů v čase (engine v3, krok 1B; audit A14, R4-lite, Dodatek A).
//!
//! Problém (audit A14, 01-analyza): `finding_id` je stabilní, ale za ním není stav,
//! takže každý cyklus vydá tentýž nález znovu a soak měří nálezy × cykly. Tady má
//! nález stabilní identitu `(entita, typ, služba)`, životní cyklus a perzistenci:
//!
//! - stav: nový → otevřený → (vyřešený automaticky | potvrzený) → uzavřený →
//!   znovuotevřený; každý přechod je v auditu, automatické zavření je vratné,
//! - deduplikace: opakovaný stejný stav se nezobrazí znovu, ALE eskalace při změně
//!   příznaků (vyšší závažnost, nový dominantní zdroj, skok objemu) se zobrazí vždy,
//!   takže deduplikace nezakryje nový útok na hostu s otevřeným nálezem (riziko B1,
//!   RQ1 Z2: první výskyt vždy viditelný, RQ1 Z3: měřit ztrátu recallu),
//! - TTL (klid → uzavřeno, retence → smazáno) a STROP počtu položek s dávkovým
//!   vyřazením nejméně důležitých (ochrana před vyčerpáním paměti nekonečným počtem
//!   unikátních klíčů, riziko B2),
//! - perzistence do SQLite s verzí schématu (`PRAGMA user_version`) a obnova po restartu.

use std::collections::{BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

use crate::{
    error::{BakulaError, Result},
    model::Severity,
};

/// Verze schématu SQLite. Zvýšit + přidat krok do `migrate` při každé změně.
pub const SCHEMA_VERSION: i64 = 1;
/// Maximální délka složky klíče (ochrana paměti před extrémními vstupy).
const MAX_KEY_PART: usize = 200;

fn db_error(error: rusqlite::Error) -> BakulaError {
    BakulaError::Processing(format!("finding_memory SQLite chyba: {error}"))
}

fn clip(value: &str) -> String {
    if value.len() <= MAX_KEY_PART {
        return value.to_string();
    }
    let mut end = MAX_KEY_PART;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// Bez výskytu déle než tohle → uzavřeno (další výskyt = znovuotevřeno, zobrazí se).
    pub quiet_close_s: i64,
    /// Uzavřené a automaticky vyřešené položky starší než tohle se smažou.
    pub retention_s: i64,
    /// Strop počtu položek; při překročení se dávkově vyřadí nejméně důležité.
    pub max_entries: usize,
    /// Strop zapamatovaných dominantních zdrojů na položku.
    pub max_sources: usize,
    /// Eskalace při objemu ≥ faktor × dosavadní maximum (a aspoň `min_escalation_count`).
    pub volume_factor: f64,
    pub min_escalation_count: u32,
    /// Jak často se zapíše jen posun `last_seen` (stavové změny se zapisují vždy).
    pub persist_last_seen_every_s: i64,
    /// Eskalovat i tehdy, když otevřený stav dosud žádný dominantní zdroj neměl a teď se
    /// objeví (krok 2A: útok jednoho zdroje na službu s rozptýleným šumem se dřív
    /// schoval pod otevřený nález bez zdrojů).
    #[serde(default)]
    pub escalate_first_source: bool,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            // den klidu: opakovany vyskyt behem dne se nezobrazi znovu ('nove dnes', U4)
            quiet_close_s: 24 * 3600,
            retention_s: 7 * 86400,
            max_entries: 50_000,
            max_sources: 16,
            volume_factor: 4.0,
            min_escalation_count: 20,
            persist_last_seen_every_s: 90 * 60,
            escalate_first_source: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingState {
    New,
    Open,
    AutoResolved,
    Confirmed,
    Closed,
    Reopened,
    /// Vyvráceno ověřením (žebřík, krok 2B): opakování se nezobrazuje, eskalace ano.
    Refuted,
}

impl FindingState {
    pub fn label(self) -> &'static str {
        match self {
            FindingState::New => "new",
            FindingState::Open => "open",
            FindingState::AutoResolved => "auto_resolved",
            FindingState::Confirmed => "confirmed",
            FindingState::Closed => "closed",
            FindingState::Reopened => "reopened",
            FindingState::Refuted => "refuted",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "new" => FindingState::New,
            "open" => FindingState::Open,
            "auto_resolved" => FindingState::AutoResolved,
            "confirmed" => FindingState::Confirmed,
            "closed" => FindingState::Closed,
            "reopened" => FindingState::Reopened,
            "refuted" => FindingState::Refuted,
            _ => return None,
        })
    }

    /// Aktivní = nález platí a opakování se nezobrazuje (jen eskalace).
    fn active(self) -> bool {
        matches!(
            self,
            FindingState::New
                | FindingState::Open
                | FindingState::Confirmed
                | FindingState::Reopened
                | FindingState::Refuted
        )
    }
}

/// Stabilní identita nálezu v čase: entita (asset nebo IP), typ, služba (`proto/port`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FindingKey {
    pub entity: String,
    pub finding_type: String,
    pub service: String,
}

impl FindingKey {
    pub fn new(entity: &str, finding_type: &str, service: &str) -> Self {
        Self {
            entity: clip(entity),
            finding_type: clip(finding_type),
            service: clip(if service.is_empty() { "-" } else { service }),
        }
    }
}

/// `ip/proto/port` → (`proto/port`, `ip`); `ip/host-only` → (`host-only`, `ip`).
pub fn split_service_key(key: &str) -> (&str, &str) {
    match key.split_once('/') {
        Some((ip, rest)) => (rest, ip),
        None => ("-", key),
    }
}

/// Stabilní klíč nálezu. `entity_host` = asset id (identita) nebo IP cíle.
/// Pokusy (`scan_attempts`) jsou stav ZDROJE; nálezy bez hostu i služby (intel)
/// nesou vlastní `finding_id`, aby se navzájem neslily.
pub fn key_for_finding(
    finding: &crate::model::Finding,
    entity_host: &str,
    sources: &[String],
) -> FindingKey {
    let kind = finding.finding_type.as_str();
    let Some(service_key) = finding.service_key.as_deref() else {
        return FindingKey::new(
            finding.host_key.as_deref().map_or("-", |_| entity_host),
            kind,
            &finding.finding_id,
        );
    };
    let (service, _) = split_service_key(service_key);
    match (kind, sources.first()) {
        ("scan_attempts", Some(source)) => FindingKey::new(&format!("src:{source}"), kind, "-"),
        // IDS: stav na (sluzba, signatura), jina signatura = jiny stav (krok 2A)
        ("suricata_alert", _) => FindingKey::new(
            entity_host,
            kind,
            &format!(
                "{service}#{}",
                finding
                    .finding_id
                    .rsplit_once('#')
                    .map_or("", |(_, sid)| sid)
            ),
        ),
        ("unmapped_passive_event", _) => FindingKey::new(
            entity_host,
            kind,
            &format!(
                "{service}#{}",
                finding.finding_id.rsplit(':').next().unwrap_or("")
            ),
        ),
        _ => FindingKey::new(entity_host, kind, service),
    }
}

/// Jedno pozorování nálezu v cyklu.
#[derive(Debug, Clone)]
pub struct Observation<'a> {
    pub key: FindingKey,
    pub severity: Severity,
    /// Objem (počet událostí/toků), z něj se počítá eskalace objemu.
    pub count: u32,
    /// Dominantní zdroje (IP) s velkým podílem; prázdné = neznámé.
    pub sources: &'a [String],
    pub at: DateTime<Utc>,
    /// Vysvětlení počítá s nárůstem objemu (záloha, dávka): eskalace objemu se v jeho
    /// okně nezobrazí. U ostatních druhů (výpadek, patch) se objem zobrazí vždy.
    pub volume_explained: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Escalation {
    Severity,
    NewSource,
    Volume,
}

impl Escalation {
    pub fn label(self) -> &'static str {
        match self {
            Escalation::Severity => "severity",
            Escalation::NewSource => "new_source",
            Escalation::Volume => "volume",
        }
    }
}

/// Co se s pozorováním stalo (pro UI a metriky „tři skupiny výstupu“).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// Zobrazit: první výskyt.
    First,
    /// Zobrazit: znovu po uzavření nebo po skončení automatického vysvětlení.
    Reopened,
    /// Zobrazit: otevřený nález se změnil (může jít o nový útok na témže hostu).
    Escalated(Escalation),
    /// Nezobrazovat: tentýž stav už je otevřený.
    Suppressed,
    /// Automaticky vyřešeno s důvodem (vratné, v auditu).
    AutoResolved(String),
}

impl Disposition {
    pub fn displayed(&self) -> bool {
        matches!(
            self,
            Disposition::First | Disposition::Reopened | Disposition::Escalated(_)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub state: FindingState,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub last_displayed: Option<DateTime<Utc>>,
    pub occurrences: u64,
    pub max_severity: Severity,
    pub max_count: u32,
    pub sources: BTreeSet<String>,
    pub auto_reason: Option<String>,
    #[serde(skip)]
    persisted_last_seen: Option<DateTime<Utc>>,
    #[serde(skip)]
    dirty: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryStats {
    pub observed: u64,
    pub displayed_first: u64,
    pub displayed_reopened: u64,
    pub displayed_escalated: u64,
    pub suppressed: u64,
    pub auto_resolved: u64,
    pub closed_quiet: u64,
    pub purged: u64,
    pub evicted: u64,
    pub peak_entries: u64,
}

#[derive(Debug, Clone)]
struct AuditRow {
    at: DateTime<Utc>,
    actor: String,
    action: String,
    key: FindingKey,
    detail: String,
}

/// Paměť nálezů. Volitelně svázaná se SQLite (`attach`), jinak čistě v paměti.
#[derive(Debug)]
pub struct FindingMemory {
    cfg: MemoryConfig,
    entries: HashMap<FindingKey, Entry>,
    deleted: Vec<FindingKey>,
    audit: Vec<AuditRow>,
    pub stats: MemoryStats,
}

fn ts(value: DateTime<Utc>) -> i64 {
    value.timestamp()
}

fn from_ts(value: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(value, 0).unwrap_or_default()
}

fn severity_code(value: Severity) -> i64 {
    match value {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
    }
}

fn severity_from(code: i64) -> Severity {
    match code {
        2 => Severity::High,
        1 => Severity::Medium,
        _ => Severity::Low,
    }
}

/// Migrace schématu na `SCHEMA_VERSION`. Novější neznámá verze = chyba (nepřepisovat).
pub fn migrate(conn: &Connection) -> Result<()> {
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(db_error)?;
    if version > SCHEMA_VERSION {
        return Err(BakulaError::Processing(format!(
            "finding_memory: schema {version} je novejsi nez podporovane {SCHEMA_VERSION}"
        )));
    }
    if version < 1 {
        conn.execute_batch(
            "
            BEGIN;
            CREATE TABLE IF NOT EXISTS finding_state (
                entity TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                service TEXT NOT NULL,
                state TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                last_displayed INTEGER,
                occurrences INTEGER NOT NULL,
                max_severity INTEGER NOT NULL,
                max_count INTEGER NOT NULL,
                sources TEXT NOT NULL,
                auto_reason TEXT,
                PRIMARY KEY (entity, finding_type, service)
            );
            CREATE TABLE IF NOT EXISTS finding_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at INTEGER NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                entity TEXT NOT NULL,
                finding_type TEXT NOT NULL,
                service TEXT NOT NULL,
                detail TEXT NOT NULL
            );
            CREATE TRIGGER IF NOT EXISTS finding_audit_no_update BEFORE UPDATE ON finding_audit
            BEGIN SELECT RAISE(ABORT, 'finding_audit je append-only'); END;
            PRAGMA user_version = 1;
            COMMIT;
            ",
        )
        .map_err(db_error)?;
    }
    Ok(())
}

impl FindingMemory {
    pub fn new(cfg: MemoryConfig) -> Self {
        Self {
            cfg,
            entries: HashMap::new(),
            deleted: Vec::new(),
            audit: Vec::new(),
            stats: MemoryStats::default(),
        }
    }

    pub fn config(&self) -> &MemoryConfig {
        &self.cfg
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Diagnostika paměti: (záznamy, nezapsané řádky auditu, nezapsaná smazání).
    pub fn pending_counts(&self) -> (usize, usize, usize) {
        (self.entries.len(), self.audit.len(), self.deleted.len())
    }

    pub fn get(&self, key: &FindingKey) -> Option<&Entry> {
        self.entries.get(key)
    }

    /// Obnova po restartu: načte stav z SQLite (po migraci).
    pub fn load(conn: &Connection, cfg: MemoryConfig) -> Result<Self> {
        migrate(conn)?;
        let mut memory = Self::new(cfg);
        let mut stmt = conn
            .prepare(
                "SELECT entity, finding_type, service, state, first_seen, last_seen, last_displayed,
                        occurrences, max_severity, max_count, sources, auto_reason
                 FROM finding_state",
            )
            .map_err(db_error)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    FindingKey {
                        entity: row.get(0)?,
                        finding_type: row.get(1)?,
                        service: row.get(2)?,
                    },
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Option<String>>(11)?,
                ))
            })
            .map_err(db_error)?;
        for row in rows {
            let (key, state, first, last, displayed, occ, sev, max_count, sources, reason) =
                row.map_err(db_error)?;
            let Some(state) = FindingState::parse(&state) else {
                continue; // neznamy stav (poskozeny radek) se preskoci, ne pad
            };
            let sources: BTreeSet<String> = serde_json::from_str(&sources).unwrap_or_default();
            let last_seen = from_ts(last);
            memory.entries.insert(
                key,
                Entry {
                    state,
                    first_seen: from_ts(first),
                    last_seen,
                    last_displayed: displayed.map(from_ts),
                    occurrences: occ.max(0) as u64,
                    max_severity: severity_from(sev),
                    max_count: max_count.clamp(0, u32::MAX as i64) as u32,
                    sources,
                    auto_reason: reason,
                    persisted_last_seen: Some(last_seen),
                    dirty: false,
                },
            );
        }
        memory.stats.peak_entries = memory.entries.len() as u64;
        Ok(memory)
    }

    /// Zapíše změny (upsert změněných, smazání vyřazených, audit) v jedné transakci.
    pub fn flush(&mut self, conn: &mut Connection) -> Result<()> {
        migrate(conn)?;
        let tx = conn.transaction().map_err(db_error)?;
        {
            let mut upsert = tx
                .prepare_cached(
                    "INSERT INTO finding_state (entity, finding_type, service, state, first_seen,
                        last_seen, last_displayed, occurrences, max_severity, max_count, sources, auto_reason)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                     ON CONFLICT(entity, finding_type, service) DO UPDATE SET
                        state = excluded.state, last_seen = excluded.last_seen,
                        last_displayed = excluded.last_displayed, occurrences = excluded.occurrences,
                        max_severity = excluded.max_severity, max_count = excluded.max_count,
                        sources = excluded.sources, auto_reason = excluded.auto_reason",
                )
                .map_err(db_error)?;
            for (key, entry) in self.entries.iter_mut().filter(|(_, e)| e.dirty) {
                let sources = serde_json::to_string(&entry.sources).unwrap_or_else(|_| "[]".into());
                upsert
                    .execute(params![
                        key.entity,
                        key.finding_type,
                        key.service,
                        entry.state.label(),
                        ts(entry.first_seen),
                        ts(entry.last_seen),
                        entry.last_displayed.map(ts),
                        entry.occurrences as i64,
                        severity_code(entry.max_severity),
                        entry.max_count as i64,
                        sources,
                        entry.auto_reason,
                    ])
                    .map_err(db_error)?;
                entry.dirty = false;
                entry.persisted_last_seen = Some(entry.last_seen);
            }
            let mut delete = tx
                .prepare_cached(
                    "DELETE FROM finding_state WHERE entity = ?1 AND finding_type = ?2 AND service = ?3",
                )
                .map_err(db_error)?;
            for key in self.deleted.drain(..) {
                delete
                    .execute(params![key.entity, key.finding_type, key.service])
                    .map_err(db_error)?;
            }
            let mut audit = tx
                .prepare_cached(
                    "INSERT INTO finding_audit (at, actor, action, entity, finding_type, service, detail)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                )
                .map_err(db_error)?;
            for row in self.audit.drain(..) {
                audit
                    .execute(params![
                        ts(row.at),
                        row.actor,
                        row.action,
                        row.key.entity,
                        row.key.finding_type,
                        row.key.service,
                        row.detail
                    ])
                    .map_err(db_error)?;
            }
        }
        tx.commit().map_err(db_error)
    }

    fn log(
        &mut self,
        at: DateTime<Utc>,
        actor: &str,
        action: &str,
        key: &FindingKey,
        detail: String,
    ) {
        self.audit.push(AuditRow {
            at,
            actor: actor.to_string(),
            action: action.to_string(),
            key: key.clone(),
            detail,
        });
    }

    /// Zpracuje jedno pozorování. `explanation` = neškodné vysvětlení z kontextové brány
    /// (už prošlé jejími mantinely); `None` = bez vysvětlení.
    pub fn observe(&mut self, obs: &Observation<'_>, explanation: Option<&str>) -> Disposition {
        self.stats.observed += 1;
        let cfg = self.cfg;
        if !self.entries.contains_key(&obs.key) {
            self.ensure_capacity(obs.at);
        }
        let mut new_sources: Vec<String> = Vec::new();
        let (disposition, audit) = match self.entries.get_mut(&obs.key) {
            None => {
                let mut sources = BTreeSet::new();
                for source in obs.sources.iter().take(cfg.max_sources) {
                    sources.insert(clip(source));
                }
                let (state, disposition, audit) = match explanation {
                    Some(reason) => (
                        FindingState::AutoResolved,
                        Disposition::AutoResolved(reason.to_string()),
                        Some(("auto_resolve", reason.to_string())),
                    ),
                    None => (FindingState::New, Disposition::First, None),
                };
                self.entries.insert(
                    obs.key.clone(),
                    Entry {
                        state,
                        first_seen: obs.at,
                        last_seen: obs.at,
                        last_displayed: disposition.displayed().then_some(obs.at),
                        occurrences: 1,
                        max_severity: obs.severity,
                        max_count: obs.count,
                        sources,
                        auto_reason: explanation.map(ToString::to_string),
                        persisted_last_seen: None,
                        dirty: true,
                    },
                );
                (disposition, audit)
            }
            Some(entry) => {
                entry.occurrences += 1;
                if obs.at > entry.last_seen {
                    entry.last_seen = obs.at;
                }
                // eskalace: zmena priznaku proti zapamatovanemu stavu
                let mut escalation = None;
                if obs.severity > entry.max_severity {
                    escalation = Some(Escalation::Severity);
                }
                for source in obs.sources {
                    if !entry.sources.contains(source.as_str()) {
                        new_sources.push(clip(source));
                    }
                }
                if escalation.is_none()
                    && !new_sources.is_empty()
                    && (!entry.sources.is_empty() || cfg.escalate_first_source)
                {
                    escalation = Some(Escalation::NewSource);
                }
                if escalation.is_none()
                    && obs.count >= cfg.min_escalation_count
                    && obs.count as f64 >= cfg.volume_factor * entry.max_count.max(1) as f64
                {
                    escalation = Some(Escalation::Volume);
                }
                entry.max_severity = entry.max_severity.max(obs.severity);
                entry.max_count = entry.max_count.max(obs.count);
                for source in new_sources.drain(..) {
                    if entry.sources.len() < cfg.max_sources {
                        entry.sources.insert(source);
                    }
                }
                let previous = entry.state;
                // Objem v okne s neskodnym vysvetlenim (zaloha, davka) je ocekavany;
                // vyssi zavaznost nebo novy zdroj se ale zobrazi i v okne kontextu.
                let escalation = match (escalation, explanation) {
                    (Some(Escalation::Volume), Some(_)) if obs.volume_explained => None,
                    (value, _) => value,
                };
                use FindingState as S;
                let (state, disposition) = match (previous, explanation, escalation) {
                    // potvrzeny utok se automaticky nezavira
                    (S::Confirmed, _, Some(cause)) => (S::Confirmed, Disposition::Escalated(cause)),
                    (S::Confirmed, _, None) => (S::Confirmed, Disposition::Suppressed),
                    // vyvraceno overenim: totez se nezobrazi, zmena priznaku ano
                    (S::Refuted, _, Some(cause)) => (S::Reopened, Disposition::Escalated(cause)),
                    (S::Refuted, _, None) => (S::Refuted, Disposition::Suppressed),
                    (S::Closed, None, _) | (S::Closed, Some(_), Some(_)) => {
                        (S::Reopened, Disposition::Reopened)
                    }
                    (_, _, Some(cause)) => (S::Open, Disposition::Escalated(cause)),
                    (_, Some(reason), None) => (
                        S::AutoResolved,
                        Disposition::AutoResolved(reason.to_string()),
                    ),
                    (S::AutoResolved, None, None) => (S::Reopened, Disposition::Reopened),
                    (_, None, None) => (S::Open, Disposition::Suppressed),
                };
                entry.auto_reason = match &disposition {
                    Disposition::AutoResolved(reason) => Some(reason.clone()),
                    _ => None,
                };
                let changed = state != entry.state;
                entry.state = state;
                if disposition.displayed() {
                    entry.last_displayed = Some(obs.at);
                }
                let stale = entry.persisted_last_seen.is_none_or(|persisted| {
                    (entry.last_seen - persisted).num_seconds() >= cfg.persist_last_seen_every_s
                });
                if changed || disposition.displayed() || stale {
                    entry.dirty = true;
                }
                let audit = match &disposition {
                    Disposition::AutoResolved(reason) if previous != FindingState::AutoResolved => {
                        Some(("auto_resolve", reason.clone()))
                    }
                    Disposition::Reopened => Some(("reopen", format!("z {}", previous.label()))),
                    Disposition::Escalated(cause) => Some(("escalate", cause.label().to_string())),
                    _ => None,
                };
                (disposition, audit)
            }
        };
        match &disposition {
            Disposition::First => self.stats.displayed_first += 1,
            Disposition::Reopened => self.stats.displayed_reopened += 1,
            Disposition::Escalated(_) => self.stats.displayed_escalated += 1,
            Disposition::Suppressed => self.stats.suppressed += 1,
            Disposition::AutoResolved(_) => self.stats.auto_resolved += 1,
        }
        if let Some((action, detail)) = audit {
            self.log(obs.at, "engine", action, &obs.key, detail);
        }
        self.stats.peak_entries = self.stats.peak_entries.max(self.entries.len() as u64);
        disposition
    }

    /// TTL: aktivní položky bez výskytu > `quiet_close_s` → uzavřeno; uzavřené a
    /// automaticky vyřešené starší než `retention_s` → smazáno.
    pub fn sweep(&mut self, now: DateTime<Utc>) {
        let cfg = self.cfg;
        let mut closed: Vec<FindingKey> = Vec::new();
        let mut purge: Vec<FindingKey> = Vec::new();
        for (key, entry) in &mut self.entries {
            let quiet = (now - entry.last_seen).num_seconds();
            if entry.state.active() && quiet > cfg.quiet_close_s {
                entry.state = FindingState::Closed;
                entry.dirty = true;
                closed.push(key.clone());
            } else if !entry.state.active() && quiet > cfg.retention_s {
                purge.push(key.clone());
            }
        }
        self.stats.closed_quiet += closed.len() as u64;
        for key in closed {
            self.log(now, "engine", "close_quiet", &key, String::new());
        }
        self.stats.purged += purge.len() as u64;
        for key in purge {
            self.entries.remove(&key);
            self.deleted.push(key);
        }
    }

    /// Strop: při plné paměti dávkově (10 %) vyřadí nejméně důležité položky
    /// (nejdřív uzavřené a vyřešené, pak otevřené s nejnižší závažností a nejstarší).
    fn ensure_capacity(&mut self, now: DateTime<Utc>) {
        if self.entries.len() < self.cfg.max_entries {
            return;
        }
        let batch = (self.cfg.max_entries / 10).max(1);
        let mut ranked: Vec<(u8, Severity, DateTime<Utc>, FindingKey)> = self
            .entries
            .iter()
            .map(|(key, entry)| {
                let class = match entry.state {
                    FindingState::Closed => 0,
                    FindingState::AutoResolved | FindingState::Refuted => 1,
                    FindingState::Confirmed => 3,
                    _ => 2,
                };
                (class, entry.max_severity, entry.last_seen, key.clone())
            })
            .collect();
        ranked.sort();
        for (_, _, _, key) in ranked.into_iter().take(batch) {
            self.entries.remove(&key);
            self.log(now, "engine", "evict_capacity", &key, String::new());
            self.deleted.push(key);
            self.stats.evicted += 1;
        }
    }

    fn operator_transition(
        &mut self,
        key: &FindingKey,
        state: FindingState,
        actor: &str,
        action: &str,
        at: DateTime<Utc>,
    ) -> bool {
        let Some(entry) = self.entries.get_mut(key) else {
            return false;
        };
        let previous = entry.state;
        entry.state = state;
        if state != FindingState::AutoResolved {
            entry.auto_reason = None;
        }
        entry.dirty = true;
        self.log(at, actor, action, key, format!("z {}", previous.label()));
        true
    }

    /// Člověk nebo ověření potvrdí útok (už se automaticky nezavře).
    pub fn confirm(&mut self, key: &FindingKey, actor: &str, at: DateTime<Utc>) -> bool {
        self.operator_transition(key, FindingState::Confirmed, actor, "confirm", at)
    }

    /// Člověk uzavře (vyřešeno). Další výskyt → znovuotevřeno.
    pub fn close(&mut self, key: &FindingKey, actor: &str, at: DateTime<Utc>) -> bool {
        self.operator_transition(key, FindingState::Closed, actor, "close", at)
    }

    /// Ověření vyvrátilo hypotézu (žebřík, krok 2B): stav `Refuted` s důvodem v auditu.
    /// Vratné (`reopen`), změna příznaků se zobrazí jako eskalace.
    pub fn refute(&mut self, key: &FindingKey, reason: &str, at: DateTime<Utc>) -> bool {
        let Some(entry) = self.entries.get_mut(key) else {
            return false;
        };
        if entry.state == FindingState::Confirmed {
            return false; // potvrzeny utok automaticky nevyvracet
        }
        let previous = entry.state;
        entry.state = FindingState::Refuted;
        entry.auto_reason = Some(clip(reason));
        entry.dirty = true;
        self.log(
            at,
            "verify_ladder",
            "verify_refute",
            key,
            format!("z {}: {}", previous.label(), clip(reason)),
        );
        true
    }

    /// Záznam rozhodnutí žebříku bez změny stavu (eskalace člověku, potvrzení).
    pub fn note(&mut self, key: &FindingKey, action: &str, detail: &str, at: DateTime<Utc>) {
        if self.entries.contains_key(key) {
            self.log(at, "verify_ladder", action, key, clip(detail));
        }
    }

    /// Vrácení automatického zavření (vratnost, Dodatek A.2 a).
    pub fn reopen(&mut self, key: &FindingKey, actor: &str, at: DateTime<Utc>) -> bool {
        self.operator_transition(key, FindingState::Reopened, actor, "reopen_manual", at)
    }

    /// Počet položek podle stavu (pro metriky enginu a UI).
    pub fn counts_by_state(&self) -> std::collections::BTreeMap<&'static str, u64> {
        let mut counts = std::collections::BTreeMap::new();
        for entry in self.entries.values() {
            *counts.entry(entry.state.label()).or_default() += 1;
        }
        counts
    }
}

/// Záznam životního cyklu nálezu v reportu (pro UI: nový / opakovaný / vyřešený).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LifecycleRecord {
    pub finding_id: String,
    pub state: String,
    /// `first` | `reopened` | `escalated:<pricina>` | `suppressed` | `auto_resolved`
    pub disposition: String,
    pub displayed: bool,
    #[serde(default)]
    pub reason: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub occurrences: u64,
    /// Krok 6: zobrazený nález s důkazem provozní příčiny je ve frontě „provoz“
    /// (`ops_evidence`), ne mezi podezřeními na útok; nezavírá se.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ops_reason: Option<String>,
}

impl LifecycleRecord {
    pub fn new(
        finding_id: &str,
        disposition: &Disposition,
        entry: Option<&Entry>,
        at: DateTime<Utc>,
    ) -> Self {
        let (label, reason) = match disposition {
            Disposition::First => ("first".to_string(), None),
            Disposition::Reopened => ("reopened".to_string(), None),
            Disposition::Escalated(cause) => (format!("escalated:{}", cause.label()), None),
            Disposition::Suppressed => ("suppressed".to_string(), None),
            Disposition::AutoResolved(reason) => {
                ("auto_resolved".to_string(), Some(reason.clone()))
            }
        };
        Self {
            finding_id: finding_id.to_string(),
            state: entry.map(|e| e.state.label()).unwrap_or("new").to_string(),
            disposition: label,
            displayed: disposition.displayed(),
            reason,
            first_seen: entry.map(|e| e.first_seen).unwrap_or(at),
            last_seen: entry.map(|e| e.last_seen).unwrap_or(at),
            occurrences: entry.map(|e| e.occurrences).unwrap_or(1),
            ops_reason: None,
        }
    }
}

/// Načte audit z databáze (pro UI a testy vratnosti).
pub fn read_audit(conn: &Connection) -> Result<Vec<(String, String, FindingKey, String)>> {
    let mut stmt = conn
        .prepare(
            "SELECT actor, action, entity, finding_type, service, detail FROM finding_audit ORDER BY id",
        )
        .map_err(db_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                FindingKey {
                    entity: row.get(2)?,
                    finding_type: row.get(3)?,
                    service: row.get(4)?,
                },
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(db_error)?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(minutes: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_767_571_200 + minutes * 60, 0).unwrap()
    }

    fn key(entity: &str, kind: &str) -> FindingKey {
        FindingKey::new(entity, kind, "tcp/443")
    }

    fn obs<'a>(
        k: &FindingKey,
        minute: i64,
        sev: Severity,
        count: u32,
        src: &'a [String],
    ) -> Observation<'a> {
        Observation {
            key: k.clone(),
            severity: sev,
            count,
            sources: src,
            at: at(minute),
            volume_explained: true,
        }
    }

    #[test]
    fn repeated_same_state_is_shown_once_then_suppressed() {
        let mut memory = FindingMemory::new(MemoryConfig::default());
        let k = key("asset:1", "inductive_volume_anomaly");
        assert_eq!(
            memory.observe(&obs(&k, 0, Severity::High, 30, &[]), None),
            Disposition::First
        );
        for cycle in 1..48 {
            assert_eq!(
                memory.observe(&obs(&k, cycle * 30, Severity::High, 30, &[]), None),
                Disposition::Suppressed
            );
        }
        assert_eq!(memory.get(&k).unwrap().occurrences, 48);
        assert_eq!(memory.get(&k).unwrap().state, FindingState::Open);
        assert_eq!(memory.stats.displayed_first, 1);
    }

    /// Zábradlí B1: nový útok na hostu s už otevřeným nálezem se nesmí ztratit.
    #[test]
    fn new_attack_on_host_with_open_finding_escalates() {
        let mut memory = FindingMemory::new(MemoryConfig::default());
        let k = key("asset:7", "connection_timeout_burst");
        let normal = vec!["10.0.0.5".to_string()];
        memory.observe(&obs(&k, 0, Severity::Medium, 10, &normal), None);
        assert_eq!(
            memory.observe(&obs(&k, 30, Severity::Medium, 10, &normal), None),
            Disposition::Suppressed
        );
        // novy dominantni zdroj (utocnik)
        let attacker = vec!["10.0.0.5".to_string(), "203.0.113.9".to_string()];
        assert_eq!(
            memory.observe(&obs(&k, 60, Severity::Medium, 12, &attacker), None),
            Disposition::Escalated(Escalation::NewSource)
        );
        // vyssi zavaznost
        assert_eq!(
            memory.observe(&obs(&k, 90, Severity::High, 12, &attacker), None),
            Disposition::Escalated(Escalation::Severity)
        );
        // skok objemu (>= 4x maxima)
        assert_eq!(
            memory.observe(&obs(&k, 120, Severity::High, 60, &attacker), None),
            Disposition::Escalated(Escalation::Volume)
        );
        // jiny typ na stejnem hostu je jiny klic -> prvni vyskyt
        let other = key("asset:7", "packet_rate_spike");
        assert_eq!(
            memory.observe(&obs(&other, 120, Severity::Low, 1, &[]), None),
            Disposition::First
        );
    }

    #[test]
    fn quiet_finding_closes_and_recurrence_is_reopened_and_shown() {
        let mut memory = FindingMemory::new(MemoryConfig::default());
        let k = key("asset:2", "unexpected_traffic");
        memory.observe(&obs(&k, 0, Severity::Low, 3, &[]), None);
        memory.sweep(at(12 * 60));
        assert_eq!(
            memory.get(&k).unwrap().state,
            FindingState::New,
            "pul dne klidu: stale otevreny"
        );
        memory.sweep(at(24 * 60 + 1));
        assert_eq!(memory.get(&k).unwrap().state, FindingState::Closed);
        assert_eq!(
            memory.observe(&obs(&k, 25 * 60, Severity::Low, 3, &[]), None),
            Disposition::Reopened
        );
        // retence: uzavreny a stary -> smazan
        memory.sweep(at(25 * 60 + 24 * 60 + 1));
        memory.sweep(at(25 * 60 + 9 * 24 * 60));
        assert!(memory.get(&k).is_none());
        assert_eq!(memory.stats.purged, 1);
    }

    #[test]
    fn auto_resolution_is_reversible_and_audited_and_reopens_without_context() {
        let mut conn = Connection::open_in_memory().unwrap();
        let mut memory = FindingMemory::new(MemoryConfig::default());
        let k = key("asset:3", "inductive_volume_anomaly");
        let d = memory.observe(&obs(&k, 0, Severity::High, 30, &[]), Some("backup_window"));
        assert_eq!(d, Disposition::AutoResolved("backup_window".to_string()));
        assert!(!d.displayed());
        // stale vysvetleno -> zustava vyreseno, bez dalsiho auditu
        memory.observe(&obs(&k, 30, Severity::High, 30, &[]), Some("backup_window"));
        // vysvetleni skoncilo -> znovu otevreno a zobrazeno
        assert_eq!(
            memory.observe(&obs(&k, 60, Severity::High, 30, &[]), None),
            Disposition::Reopened
        );
        // rucni vraceni a potvrzeni
        assert!(memory.confirm(&k, "operator", at(61)));
        assert_eq!(
            memory.observe(&obs(&k, 90, Severity::High, 30, &[]), Some("backup_window")),
            Disposition::Suppressed,
            "potvrzeny nalez se automaticky nezavira"
        );
        memory.flush(&mut conn).unwrap();
        let audit = read_audit(&conn).unwrap();
        let actions: Vec<&str> = audit.iter().map(|row| row.1.as_str()).collect();
        assert_eq!(actions, vec!["auto_resolve", "reopen", "confirm"]);
        assert_eq!(audit[0].3, "backup_window");
    }

    #[test]
    fn capacity_cap_bounds_memory_under_unique_key_flood() {
        let cfg = MemoryConfig {
            max_entries: 1000,
            ..MemoryConfig::default()
        };
        let mut memory = FindingMemory::new(cfg);
        let important = key("asset:dc", "known_exploited_vulnerability");
        memory.observe(&obs(&important, 0, Severity::High, 1, &[]), None);
        for i in 0..20_000 {
            let k = FindingKey::new(
                &format!("198.51.{}.{}", i / 250, i % 250),
                "unmapped_passive_event",
                "tcp/1",
            );
            memory.observe(&obs(&k, 1 + i / 100, Severity::Low, 1, &[]), None);
            assert!(memory.len() <= 1000);
        }
        assert!(memory.stats.evicted >= 19_000);
        assert!(
            memory.get(&important).is_some(),
            "zavazny nalez se vyradi az posledni"
        );
        // dlouhe klice se orezou
        let long = FindingKey::new(&"x".repeat(10_000), "t", "s");
        assert_eq!(long.entity.len(), MAX_KEY_PART);
    }

    #[test]
    fn state_survives_restart_through_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine-state.sqlite");
        let k = key("asset:9", "packet_rate_spike");
        {
            let mut conn = Connection::open(&path).unwrap();
            let mut memory = FindingMemory::new(MemoryConfig::default());
            memory.observe(
                &obs(&k, 0, Severity::Medium, 5, &["10.1.1.1".to_string()]),
                None,
            );
            memory.observe(&obs(&k, 30, Severity::Medium, 5, &[]), None);
            memory.flush(&mut conn).unwrap();
        }
        let conn = Connection::open(&path).unwrap();
        let mut memory = FindingMemory::load(&conn, MemoryConfig::default()).unwrap();
        let entry = memory.get(&k).unwrap();
        assert_eq!(entry.state, FindingState::Open);
        assert_eq!(entry.occurrences, 2);
        assert!(entry.sources.contains("10.1.1.1"));
        // po restartu se tentyz stav znovu nezobrazi
        assert_eq!(
            memory.observe(&obs(&k, 60, Severity::Medium, 5, &[]), None),
            Disposition::Suppressed
        );
    }

    #[test]
    fn migration_creates_schema_and_rejects_future_version() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        migrate(&conn).unwrap(); // idempotentni
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let future = Connection::open_in_memory().unwrap();
        future.execute_batch("PRAGMA user_version = 99;").unwrap();
        assert!(migrate(&future).is_err());
        assert!(FindingMemory::load(&future, MemoryConfig::default()).is_err());
    }

    #[test]
    fn audit_table_is_append_only() {
        let mut conn = Connection::open_in_memory().unwrap();
        let mut memory = FindingMemory::new(MemoryConfig::default());
        let k = key("a", "t");
        memory.observe(&obs(&k, 0, Severity::Low, 1, &[]), Some("kalendar"));
        memory.flush(&mut conn).unwrap();
        assert!(
            conn.execute("UPDATE finding_audit SET detail = 'x'", [])
                .is_err()
        );
    }

    /// Krok 2A: otevřený nález bez dominantního zdroje (rozptýlený šum) a pak útok
    /// jednoho zdroje. Krok 1 eskaloval jen při změně ZNÁMÝCH zdrojů, takže útok zapadl.
    #[test]
    fn first_dominant_source_escalates_only_when_enabled() {
        let k = key("asset:9", "connection_timeout_burst");
        let attacker = vec!["203.0.113.9".to_string()];
        let mut step1 = FindingMemory::new(MemoryConfig::default());
        step1.observe(&obs(&k, 0, Severity::Medium, 3, &[]), None);
        assert_eq!(
            step1.observe(&obs(&k, 30, Severity::Medium, 3, &attacker), None),
            Disposition::Suppressed
        );
        let mut step2 = FindingMemory::new(MemoryConfig {
            escalate_first_source: true,
            ..MemoryConfig::default()
        });
        step2.observe(&obs(&k, 0, Severity::Medium, 3, &[]), None);
        assert_eq!(
            step2.observe(&obs(&k, 30, Severity::Medium, 3, &attacker), None),
            Disposition::Escalated(Escalation::NewSource)
        );
        // tentyz zdroj znovu = uz zname, potlaceno
        assert_eq!(
            step2.observe(&obs(&k, 60, Severity::Medium, 3, &attacker), None),
            Disposition::Suppressed
        );
    }

    #[test]
    fn ids_findings_are_keyed_by_signature() {
        let finding = |sid: &str| crate::model::Finding {
            finding_id: format!("finding:suricata_alert:10.0.0.1:10.0.0.1/tcp/80#{sid}"),
            finding_type: "suricata_alert".to_string(),
            title: String::new(),
            severity: Severity::High,
            confidence: crate::model::Confidence::High,
            host_key: Some("10.0.0.1".to_string()),
            service_key: Some("10.0.0.1/tcp/80".to_string()),
            rationale: String::new(),
            evidence: Vec::new(),
            recommendation: String::new(),
        };
        let a = key_for_finding(&finding("100"), "asset:1", &[]);
        let b = key_for_finding(&finding("200"), "asset:1", &[]);
        assert_ne!(a, b);
        assert_eq!(a.service, "tcp/80#100");
    }

    /// Krok 2B: vyvrácený nález se při opakování nezobrazí, při změně příznaků ano;
    /// potvrzený útok vyvrátit nejde; vše je v auditu a přežije restart.
    #[test]
    fn refuted_state_suppresses_repeats_but_shows_escalation() {
        let mut memory = FindingMemory::new(MemoryConfig::default());
        let k = key("asset:3", "inductive_volume_anomaly");
        memory.observe(&obs(&k, 0, Severity::Medium, 30, &[]), None);
        assert!(memory.refute(&k, "L0 history: totez kazdy den", at(1)));
        assert_eq!(memory.get(&k).unwrap().state, FindingState::Refuted);
        assert_eq!(
            memory.observe(&obs(&k, 30, Severity::Medium, 30, &[]), None),
            Disposition::Suppressed
        );
        assert_eq!(
            memory.observe(&obs(&k, 60, Severity::High, 30, &[]), None),
            Disposition::Escalated(Escalation::Severity)
        );
        let c = key("asset:4", "scan_attempts");
        memory.observe(&obs(&c, 0, Severity::Medium, 9, &[]), None);
        memory.confirm(&c, "verify_ladder", at(1));
        assert!(!memory.refute(&c, "x", at(2)), "potvrzene nevyvracet");
        let mut conn = Connection::open_in_memory().unwrap();
        memory.flush(&mut conn).unwrap();
        let audit = read_audit(&conn).unwrap();
        assert!(
            audit
                .iter()
                .any(|(_, action, _, _)| action == "verify_refute")
        );
        let back = FindingMemory::load(&conn, MemoryConfig::default()).unwrap();
        assert_eq!(back.get(&k).unwrap().state, FindingState::Reopened);
    }
}
