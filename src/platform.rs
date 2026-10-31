use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    error::{BakulaError, Result},
    model::AppConfig,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    Admin,
    Operator,
    Analyst,
    Viewer,
}

impl Role {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "admin" => Ok(Self::Admin),
            "operator" => Ok(Self::Operator),
            "analyst" => Ok(Self::Analyst),
            "viewer" => Ok(Self::Viewer),
            other => Err(BakulaError::Config(format!(
                "Neplatna role {other}. Povolené role: admin, operator, analyst, viewer."
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Analyst => "analyst",
            Self::Viewer => "viewer",
        }
    }

    pub fn permissions(&self) -> &'static [&'static str] {
        match self {
            Self::Admin => &["*"],
            Self::Operator => &[
                "runs.read",
                "verification.read",
                "metrics.read",
                "platform.read",
                "jobs.read",
                "jobs.write",
                "jobs.execute",
                "cluster.read",
                "cluster.manage",
                "enforcement.read",
                "enforcement.write",
                "enforcement.approve",
                "audit.read",
            ],
            Self::Analyst => &[
                "runs.read",
                "verification.read",
                "metrics.read",
                "platform.read",
                "jobs.read",
                "jobs.write",
                "cluster.read",
                "enforcement.read",
                "enforcement.write",
                "audit.read",
            ],
            Self::Viewer => &[
                "runs.read",
                "verification.read",
                "metrics.read",
                "platform.read",
                "jobs.read",
                "cluster.read",
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UserRecord {
    pub id: i64,
    pub username: String,
    pub role: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssuedToken {
    pub username: String,
    pub role: String,
    pub token_name: String,
    pub raw_token: String,
    pub created_at: DateTime<Utc>,
    /// `None` = token nikdy nevyprsi (jen na vyslovne pozadani, `--ttl-days 0`).
    pub expires_at: Option<DateTime<Utc>>,
}

/// Bezpecny vychozi zivot tokenu; delsi/neomezeny zivot musi operator zvolit
/// vedome (`platform token issue --ttl-days`).
pub const DEFAULT_TOKEN_TTL_DAYS: i64 = 90;

#[derive(Debug, Clone, Serialize)]
pub struct AuthIdentity {
    pub user_id: i64,
    pub username: String,
    pub role: String,
    pub token_name: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineJobSpec {
    pub workspace_root: String,
    pub nazev: String,
    pub scope: Vec<String>,
    #[serde(default = "default_ports")]
    pub ports: Vec<u16>,
    #[serde(default = "default_profile")]
    pub profile: String,
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default)]
    pub supplement_vulners: bool,
    #[serde(default)]
    pub freeze: bool,
    pub nmap_xml: Option<String>,
    #[serde(default)]
    pub nmap_followup_xml: Option<String>,
    pub suricata_eve: Option<String>,
    pub zeek_dir: Option<String>,
    #[serde(default)]
    pub porovnat_s: Option<String>,
    #[serde(default)]
    pub spustit_nmap: bool,
    #[serde(default)]
    pub web_fingerprint: bool,
    #[serde(default)]
    pub web_checks: bool,
    #[serde(default)]
    pub pentest: bool,
    #[serde(default)]
    pub aggressive_pentest: bool,
    #[serde(default)]
    pub httpx_bin: Option<String>,
    #[serde(default)]
    pub nuclei_bin: Option<String>,
    #[serde(default)]
    pub nuclei_templates: Option<String>,
    #[serde(default)]
    pub snmp_snapshot: Option<String>,
    #[serde(default)]
    pub librenms_snapshot: Option<String>,
    #[serde(default)]
    pub librenms_base_url: Option<String>,
    #[serde(default = "default_librenms_token_env")]
    pub librenms_token_env: String,
    #[serde(default)]
    pub meraki_snapshot: Option<String>,
    #[serde(default)]
    pub meraki_network_id: Option<String>,
    #[serde(default = "default_meraki_token_env")]
    pub meraki_api_key_env: String,
    #[serde(default = "default_meraki_timespan")]
    pub meraki_timespan_seconds: u32,
    #[serde(default)]
    pub unifi_snapshot: Option<String>,
    #[serde(default)]
    pub unifi_devices_url: Option<String>,
    #[serde(default)]
    pub unifi_clients_url: Option<String>,
    #[serde(default)]
    pub unifi_links_url: Option<String>,
    #[serde(default = "default_unifi_token_env")]
    pub unifi_api_key_env: String,
    #[serde(default)]
    pub aruba_snapshot: Option<String>,
    #[serde(default)]
    pub aruba_base_url: Option<String>,
    #[serde(default = "default_aruba_token_env")]
    pub aruba_token_env: String,
    #[serde(default)]
    pub aruba_site_id: Option<String>,
    #[serde(default)]
    pub omada_snapshot: Option<String>,
    #[serde(default)]
    pub omada_devices_url: Option<String>,
    #[serde(default)]
    pub omada_clients_url: Option<String>,
    #[serde(default)]
    pub omada_links_url: Option<String>,
    #[serde(default = "default_omada_token_env")]
    pub omada_access_token_env: String,
    #[serde(default)]
    pub ntopng_snapshot: Option<String>,
    #[serde(default)]
    pub flow_snapshot: Option<String>,
    #[serde(default)]
    pub greenbone_report: Option<String>,
    #[serde(default)]
    pub wazuh_report: Option<String>,
    #[serde(default)]
    pub napalm_snapshot: Option<String>,
    #[serde(default)]
    pub netmiko_snapshot: Option<String>,
    #[serde(default)]
    pub scrapli_snapshot: Option<String>,
    #[serde(default = "default_urlhaus_auth_env")]
    pub urlhaus_auth_env: String,
    #[serde(default = "default_abuseipdb_key_env")]
    pub abuseipdb_key_env: String,
    #[serde(default)]
    pub disable_circl: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobRecord {
    pub id: i64,
    pub name: String,
    pub status: String,
    pub next_run_at: DateTime<Utc>,
    pub schedule_interval_s: Option<i64>,
    pub claimed_by: Option<String>,
    pub claim_until: Option<DateTime<Utc>>,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub last_run_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeRecord {
    pub node_id: String,
    pub display_name: String,
    pub status: String,
    pub last_heartbeat: DateTime<Utc>,
    pub leader_until: Option<DateTime<Utc>>,
    pub capabilities: Vec<String>,
    pub software_version: Option<String>,
    pub desired_version: Option<String>,
    pub ready: bool,
    pub drain_state: String,
    pub upgrade_state: String,
    pub last_upgrade_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaPolicy {
    pub quorum_size: i64,
    pub min_ready_nodes: i64,
    pub rollout_batch_size: i64,
    pub target_version: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HaCandidate {
    pub node_id: String,
    pub current_version: Option<String>,
    pub target_version: Option<String>,
    pub eligible: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HaStatus {
    pub policy: Option<HaPolicy>,
    pub active_nodes: usize,
    pub ready_nodes: usize,
    pub upgrading_nodes: usize,
    pub quorum_ok: bool,
    pub candidates: Vec<HaCandidate>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformSnapshot {
    pub users: Vec<UserRecord>,
    pub jobs: Vec<JobRecord>,
    pub nodes: Vec<NodeRecord>,
    pub leader_node_id: Option<String>,
    pub leader_until: Option<DateTime<Utc>>,
    pub ha_status: Option<HaStatus>,
}

#[derive(Debug, Clone)]
pub struct ClaimedJob {
    pub id: i64,
    pub name: String,
    pub schedule_interval_s: Option<i64>,
    pub spec: PipelineJobSpec,
}

pub fn init_database(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let conn = open_connection(path)?;
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            expires_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            spec_json TEXT NOT NULL,
            schedule_interval_s INTEGER,
            next_run_at TEXT NOT NULL,
            claimed_by TEXT,
            claim_until TEXT,
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT,
            last_run_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS nodes (
            node_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            status TEXT NOT NULL,
            last_heartbeat TEXT NOT NULL,
            leader_until TEXT,
            capabilities_json TEXT NOT NULL,
            software_version TEXT,
            desired_version TEXT,
            ready INTEGER NOT NULL DEFAULT 1,
            drain_state TEXT NOT NULL DEFAULT 'ready',
            upgrade_state TEXT NOT NULL DEFAULT 'idle',
            last_upgrade_at TEXT
        );
        CREATE TABLE IF NOT EXISTS ha_policy (
            policy_key TEXT PRIMARY KEY,
            quorum_size INTEGER NOT NULL,
            min_ready_nodes INTEGER NOT NULL,
            rollout_batch_size INTEGER NOT NULL,
            target_version TEXT,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_tokens_hash ON api_tokens(token_hash);
        CREATE INDEX IF NOT EXISTS idx_jobs_due ON jobs(status, next_run_at);
        CREATE INDEX IF NOT EXISTS idx_nodes_last_heartbeat ON nodes(last_heartbeat);
        ",
    )
    .map_err(to_processing_error)?;
    add_column_if_missing(&conn, "nodes", "software_version", "TEXT")?;
    add_column_if_missing(&conn, "nodes", "desired_version", "TEXT")?;
    add_column_if_missing(&conn, "nodes", "ready", "INTEGER NOT NULL DEFAULT 1")?;
    add_column_if_missing(
        &conn,
        "nodes",
        "drain_state",
        "TEXT NOT NULL DEFAULT 'ready'",
    )?;
    add_column_if_missing(
        &conn,
        "nodes",
        "upgrade_state",
        "TEXT NOT NULL DEFAULT 'idle'",
    )?;
    add_column_if_missing(&conn, "nodes", "last_upgrade_at", "TEXT")?;
    Ok(())
}

pub fn init_platform_from_config(config: &AppConfig) -> Result<Option<PathBuf>> {
    let Some(path) = crate::config::resolve_platform_db_path(config) else {
        return Ok(None);
    };
    init_database(&path)?;
    Ok(Some(path))
}

pub fn create_or_update_user(path: &Path, username: &str, role: Role) -> Result<UserRecord> {
    let conn = open_connection(path)?;
    let now = now_string();
    conn.execute(
        "
        INSERT INTO users (username, role, enabled, created_at)
        VALUES (?1, ?2, 1, ?3)
        ON CONFLICT(username) DO UPDATE SET role = excluded.role, enabled = 1
        ",
        params![username, role.as_str(), now],
    )
    .map_err(to_processing_error)?;
    load_user_by_username(&conn, username)?
        .ok_or_else(|| BakulaError::Processing(format!("Uzivatel {username} nebyl ulozen.")))
}

pub fn issue_token(path: &Path, username: &str, token_name: &str) -> Result<IssuedToken> {
    issue_token_with_ttl(path, username, token_name, Some(DEFAULT_TOKEN_TTL_DAYS))
}

pub fn issue_token_with_ttl(
    path: &Path,
    username: &str,
    token_name: &str,
    ttl_days: Option<i64>,
) -> Result<IssuedToken> {
    let conn = open_connection(path)?;
    let user = load_user_by_username(&conn, username)?
        .ok_or_else(|| BakulaError::Processing(format!("Uzivatel {username} neexistuje.")))?;
    let raw_token = format!("bakula_{}_{}", username, Uuid::new_v4().simple());
    let token_hash = hash_token(&raw_token);
    let created_at = Utc::now();
    let expires_at = ttl_days
        .filter(|days| *days > 0)
        .map(|days| created_at + chrono::Duration::days(days));
    conn.execute(
        "
        INSERT INTO api_tokens (user_id, name, token_hash, enabled, created_at, expires_at)
        VALUES (?1, ?2, ?3, 1, ?4, ?5)
        ",
        params![
            user.id,
            token_name,
            token_hash,
            format_dt(created_at),
            expires_at.map(format_dt)
        ],
    )
    .map_err(to_processing_error)?;
    Ok(IssuedToken {
        username: user.username,
        role: user.role,
        token_name: token_name.to_string(),
        raw_token,
        created_at,
        expires_at,
    })
}

pub fn authenticate_token(path: &Path, raw_token: &str) -> Result<Option<AuthIdentity>> {
    let conn = open_connection(path)?;
    let token_hash = hash_token(raw_token);
    let row = conn
        .query_row(
            "
            SELECT users.id, users.username, users.role, api_tokens.name
            FROM api_tokens
            JOIN users ON users.id = api_tokens.user_id
            WHERE api_tokens.token_hash = ?1
              AND api_tokens.enabled = 1
              AND users.enabled = 1
              AND (api_tokens.expires_at IS NULL OR api_tokens.expires_at > ?2)
            ",
            params![token_hash, now_string()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()
        .map_err(to_processing_error)?;

    let Some((user_id, username, role_name, token_name)) = row else {
        return Ok(None);
    };
    let role = Role::parse(&role_name)?;
    conn.execute(
        "UPDATE api_tokens SET last_used_at = ?1 WHERE token_hash = ?2",
        params![now_string(), token_hash],
    )
    .map_err(to_processing_error)?;
    Ok(Some(AuthIdentity {
        user_id,
        username,
        role: role.as_str().to_string(),
        token_name,
        permissions: role
            .permissions()
            .iter()
            .map(|item| item.to_string())
            .collect(),
    }))
}

pub fn list_users(path: &Path) -> Result<Vec<UserRecord>> {
    let conn = open_connection(path)?;
    let mut stmt = conn
        .prepare("SELECT id, username, role, enabled, created_at FROM users ORDER BY username ASC")
        .map_err(to_processing_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok(UserRecord {
                id: row.get(0)?,
                username: row.get(1)?,
                role: row.get(2)?,
                enabled: row.get::<_, i64>(3)? != 0,
                created_at: parse_dt(&row.get::<_, String>(4)?).map_err(to_rusqlite_error)?,
            })
        })
        .map_err(to_processing_error)?;
    collect_rows(rows)
}

pub fn list_jobs(path: &Path) -> Result<Vec<JobRecord>> {
    let conn = open_connection(path)?;
    let mut stmt = conn
        .prepare(
            "
            SELECT id, name, status, next_run_at, schedule_interval_s, claimed_by, claim_until,
                   attempts, last_error, last_run_id, created_at, updated_at
            FROM jobs
            ORDER BY created_at DESC, id DESC
            ",
        )
        .map_err(to_processing_error)?;
    let rows = stmt
        .query_map([], map_job_row)
        .map_err(to_processing_error)?;
    collect_rows(rows)
}

pub fn list_nodes(path: &Path) -> Result<Vec<NodeRecord>> {
    let conn = open_connection(path)?;
    let mut stmt = conn
        .prepare(
            "
            SELECT node_id, display_name, status, last_heartbeat, leader_until, capabilities_json,
                   software_version, desired_version, ready, drain_state, upgrade_state, last_upgrade_at
            FROM nodes
            ORDER BY node_id ASC
            ",
        )
        .map_err(to_processing_error)?;
    let rows = stmt
        .query_map([], |row| {
            let capabilities_json: String = row.get(5)?;
            Ok(NodeRecord {
                node_id: row.get(0)?,
                display_name: row.get(1)?,
                status: row.get(2)?,
                last_heartbeat: parse_dt(&row.get::<_, String>(3)?).map_err(to_rusqlite_error)?,
                leader_until: row
                    .get::<_, Option<String>>(4)?
                    .map(|value| parse_dt(&value).map_err(to_rusqlite_error))
                    .transpose()?,
                capabilities: serde_json::from_str(&capabilities_json)
                    .map_err(|error| to_rusqlite_error(BakulaError::Json(error)))?,
                software_version: row.get(6)?,
                desired_version: row.get(7)?,
                ready: row.get::<_, i64>(8)? != 0,
                drain_state: row.get(9)?,
                upgrade_state: row.get(10)?,
                last_upgrade_at: row
                    .get::<_, Option<String>>(11)?
                    .map(|value| parse_dt(&value).map_err(to_rusqlite_error))
                    .transpose()?,
            })
        })
        .map_err(to_processing_error)?;
    collect_rows(rows)
}

pub fn snapshot(path: &Path) -> Result<PlatformSnapshot> {
    let nodes = list_nodes(path)?;
    let users = list_users(path)?;
    let jobs = list_jobs(path)?;
    let ha_status = ha_status(path, Some(&nodes)).ok();
    let leader = nodes
        .iter()
        .filter_map(|node| node.leader_until.map(|until| (node.node_id.clone(), until)))
        .filter(|(_, until)| *until > Utc::now())
        .max_by(|left, right| left.1.cmp(&right.1));
    Ok(PlatformSnapshot {
        users,
        jobs,
        nodes,
        leader_node_id: leader.as_ref().map(|item| item.0.clone()),
        leader_until: leader.map(|item| item.1),
        ha_status,
    })
}

pub fn upsert_node_heartbeat(
    path: &Path,
    node_id: &str,
    display_name: &str,
    capabilities: &[String],
) -> Result<NodeRecord> {
    let conn = open_connection(path)?;
    let now = now_string();
    let caps = serde_json::to_string(capabilities).map_err(BakulaError::Json)?;
    conn.execute(
        "
        INSERT INTO nodes (
            node_id, display_name, status, last_heartbeat, leader_until, capabilities_json,
            software_version, desired_version, ready, drain_state, upgrade_state, last_upgrade_at
        )
        VALUES (?1, ?2, 'follower', ?3, NULL, ?4, NULL, NULL, 1, 'ready', 'idle', NULL)
        ON CONFLICT(node_id) DO UPDATE SET
            display_name = excluded.display_name,
            last_heartbeat = excluded.last_heartbeat,
            capabilities_json = excluded.capabilities_json
        ",
        params![node_id, display_name, now, caps],
    )
    .map_err(to_processing_error)?;
    list_nodes(path)?
        .into_iter()
        .find(|item| item.node_id == node_id)
        .ok_or_else(|| BakulaError::Processing(format!("Node {node_id} nebyl ulozen.")))
}

pub fn register_managed_node(
    path: &Path,
    node_id: &str,
    display_name: &str,
    capabilities: &[String],
    software_version: &str,
    ready: bool,
) -> Result<NodeRecord> {
    let conn = open_connection(path)?;
    let caps = serde_json::to_string(capabilities).map_err(BakulaError::Json)?;
    conn.execute(
        "
        INSERT INTO nodes (
            node_id, display_name, status, last_heartbeat, leader_until, capabilities_json,
            software_version, desired_version, ready, drain_state, upgrade_state, last_upgrade_at
        )
        VALUES (?1, ?2, 'follower', ?3, NULL, ?4, ?5, ?5, ?6, 'ready', 'idle', NULL)
        ON CONFLICT(node_id) DO UPDATE SET
            display_name = excluded.display_name,
            last_heartbeat = excluded.last_heartbeat,
            capabilities_json = excluded.capabilities_json,
            software_version = excluded.software_version,
            desired_version = COALESCE(nodes.desired_version, excluded.software_version),
            ready = excluded.ready
        ",
        params![
            node_id,
            display_name,
            now_string(),
            caps,
            software_version,
            if ready { 1 } else { 0 }
        ],
    )
    .map_err(to_processing_error)?;
    list_nodes(path)?
        .into_iter()
        .find(|item| item.node_id == node_id)
        .ok_or_else(|| BakulaError::Processing(format!("Node {node_id} nebyl ulozen.")))
}

pub fn acquire_leader_lease(path: &Path, node_id: &str, ttl_seconds: i64) -> Result<bool> {
    let mut conn = open_connection(path)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(to_processing_error)?;
    let now = Utc::now();
    let current = tx
        .query_row(
            "
            SELECT node_id, leader_until
            FROM nodes
            WHERE leader_until IS NOT NULL
            ORDER BY leader_until DESC
            LIMIT 1
            ",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(to_processing_error)?;
    let can_take = match current {
        None => true,
        Some((leader_id, leader_until)) => {
            let until = parse_dt(&leader_until)?;
            leader_id == node_id || until <= now
        }
    };
    if can_take {
        tx.execute(
            "UPDATE nodes SET status = 'follower', leader_until = NULL WHERE node_id <> ?1",
            params![node_id],
        )
        .map_err(to_processing_error)?;
        tx.execute(
            "UPDATE nodes SET status = 'leader', leader_until = ?1, last_heartbeat = ?2 WHERE node_id = ?3",
            params![
                format_dt(now + chrono::Duration::seconds(ttl_seconds)),
                format_dt(now),
                node_id
            ],
        )
        .map_err(to_processing_error)?;
    } else {
        tx.execute(
            "UPDATE nodes SET status = 'follower', last_heartbeat = ?1 WHERE node_id = ?2",
            params![format_dt(now), node_id],
        )
        .map_err(to_processing_error)?;
    }
    tx.commit().map_err(to_processing_error)?;
    Ok(can_take)
}

pub fn set_ha_policy(
    path: &Path,
    quorum_size: i64,
    min_ready_nodes: i64,
    rollout_batch_size: i64,
    target_version: Option<&str>,
) -> Result<HaPolicy> {
    let conn = open_connection(path)?;
    let updated_at = Utc::now();
    conn.execute(
        "
        INSERT INTO ha_policy (policy_key, quorum_size, min_ready_nodes, rollout_batch_size, target_version, updated_at)
        VALUES ('default', ?1, ?2, ?3, ?4, ?5)
        ON CONFLICT(policy_key) DO UPDATE SET
            quorum_size = excluded.quorum_size,
            min_ready_nodes = excluded.min_ready_nodes,
            rollout_batch_size = excluded.rollout_batch_size,
            target_version = excluded.target_version,
            updated_at = excluded.updated_at
        ",
        params![
            quorum_size,
            min_ready_nodes,
            rollout_batch_size,
            target_version,
            format_dt(updated_at)
        ],
    )
    .map_err(to_processing_error)?;
    get_ha_policy(path)?.ok_or_else(|| {
        BakulaError::Processing("HA policy se nepodarilo nahrat po ulozeni.".to_string())
    })
}

pub fn get_ha_policy(path: &Path) -> Result<Option<HaPolicy>> {
    let conn = open_connection(path)?;
    conn.query_row(
        "
        SELECT quorum_size, min_ready_nodes, rollout_batch_size, target_version, updated_at
        FROM ha_policy
        WHERE policy_key = 'default'
        ",
        [],
        |row| {
            Ok(HaPolicy {
                quorum_size: row.get(0)?,
                min_ready_nodes: row.get(1)?,
                rollout_batch_size: row.get(2)?,
                target_version: row.get(3)?,
                updated_at: parse_dt(&row.get::<_, String>(4)?).map_err(to_rusqlite_error)?,
            })
        },
    )
    .optional()
    .map_err(to_processing_error)
}

pub fn ha_status(path: &Path, prefetched_nodes: Option<&[NodeRecord]>) -> Result<HaStatus> {
    let nodes = match prefetched_nodes {
        Some(items) => items.to_vec(),
        None => list_nodes(path)?,
    };
    let policy = get_ha_policy(path)?;
    let active_nodes = nodes
        .iter()
        .filter(|node| node.last_heartbeat > Utc::now() - chrono::Duration::minutes(5))
        .count();
    let ready_nodes = nodes
        .iter()
        .filter(|node| node.ready && node.drain_state == "ready")
        .count();
    let upgrading_nodes = nodes
        .iter()
        .filter(|node| node.upgrade_state == "upgrading")
        .count();
    let candidates = build_ha_candidates(&nodes, policy.as_ref());
    let quorum_ok = policy.as_ref().is_none_or(|policy| {
        ready_nodes as i64 >= policy.quorum_size && ready_nodes as i64 >= policy.min_ready_nodes
    });
    Ok(HaStatus {
        policy,
        active_nodes,
        ready_nodes,
        upgrading_nodes,
        quorum_ok,
        candidates,
    })
}

pub fn advance_rollout(path: &Path) -> Result<Vec<String>> {
    let status = ha_status(path, None)?;
    let Some(policy) = status.policy.as_ref() else {
        return Ok(Vec::new());
    };
    let selected = status
        .candidates
        .iter()
        .filter(|candidate| candidate.eligible)
        .take(policy.rollout_batch_size.max(0) as usize)
        .map(|candidate| candidate.node_id.clone())
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Ok(selected);
    }
    let conn = open_connection(path)?;
    let now = Utc::now();
    for node_id in &selected {
        conn.execute(
            "
            UPDATE nodes
            SET desired_version = ?1,
                ready = 0,
                drain_state = 'draining',
                upgrade_state = 'upgrading',
                last_upgrade_at = ?2
            WHERE node_id = ?3
            ",
            params![policy.target_version.clone(), format_dt(now), node_id],
        )
        .map_err(to_processing_error)?;
    }
    Ok(selected)
}

pub fn mark_node_ready(path: &Path, node_id: &str, software_version: &str) -> Result<NodeRecord> {
    let conn = open_connection(path)?;
    conn.execute(
        "
        UPDATE nodes
        SET software_version = ?1,
            desired_version = ?1,
            ready = 1,
            drain_state = 'ready',
            upgrade_state = 'idle',
            last_upgrade_at = ?2
        WHERE node_id = ?3
        ",
        params![software_version, now_string(), node_id],
    )
    .map_err(to_processing_error)?;
    list_nodes(path)?
        .into_iter()
        .find(|item| item.node_id == node_id)
        .ok_or_else(|| BakulaError::Processing(format!("Node {node_id} nebyl nalezen.")))
}

pub fn enqueue_job(
    path: &Path,
    name: &str,
    spec: &PipelineJobSpec,
    schedule_interval_s: Option<i64>,
    next_run_at: Option<DateTime<Utc>>,
) -> Result<i64> {
    let conn = open_connection(path)?;
    let now = Utc::now();
    let next = next_run_at.unwrap_or(now);
    let spec_json = serde_json::to_string(spec).map_err(BakulaError::Json)?;
    conn.execute(
        "
        INSERT INTO jobs (
            name, status, spec_json, schedule_interval_s, next_run_at, claimed_by, claim_until,
            attempts, last_error, last_run_id, created_at, updated_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, 0, NULL, NULL, ?6, ?6)
        ",
        params![
            name,
            if schedule_interval_s.is_some() {
                "scheduled"
            } else {
                "queued"
            },
            spec_json,
            schedule_interval_s,
            format_dt(next),
            format_dt(now),
        ],
    )
    .map_err(to_processing_error)?;
    Ok(conn.last_insert_rowid())
}

pub fn claim_due_job(
    path: &Path,
    node_id: &str,
    lease_seconds: i64,
    allow_scheduled_jobs: bool,
) -> Result<Option<ClaimedJob>> {
    let mut conn = open_connection(path)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(to_processing_error)?;
    let now = Utc::now();
    let maybe_job = tx
        .query_row(
            "
            SELECT id, name, spec_json, schedule_interval_s
            FROM jobs
            WHERE next_run_at <= ?1
              AND status IN ('queued', 'scheduled', 'failed', 'running')
              AND (claim_until IS NULL OR claim_until <= ?1)
              AND (?2 = 1 OR schedule_interval_s IS NULL)
            ORDER BY next_run_at ASC, id ASC
            LIMIT 1
            ",
            params![format_dt(now), if allow_scheduled_jobs { 1 } else { 0 }],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(to_processing_error)?;

    let Some((job_id, name, spec_json, schedule_interval_s)) = maybe_job else {
        tx.commit().map_err(to_processing_error)?;
        return Ok(None);
    };
    let spec = serde_json::from_str::<PipelineJobSpec>(&spec_json).map_err(BakulaError::Json)?;
    tx.execute(
        "
        UPDATE jobs
        SET status = 'running',
            claimed_by = ?1,
            claim_until = ?2,
            attempts = attempts + 1,
            updated_at = ?3,
            last_error = NULL
        WHERE id = ?4
        ",
        params![
            node_id,
            format_dt(now + chrono::Duration::seconds(lease_seconds)),
            format_dt(now),
            job_id
        ],
    )
    .map_err(to_processing_error)?;
    tx.commit().map_err(to_processing_error)?;
    Ok(Some(ClaimedJob {
        id: job_id,
        name,
        schedule_interval_s,
        spec,
    }))
}

pub fn list_due_job_ids(path: &Path) -> Result<Vec<i64>> {
    let conn = open_connection(path)?;
    let mut stmt = conn
        .prepare(
            "
            SELECT id
            FROM jobs
            WHERE next_run_at <= ?1
              AND status IN ('queued', 'scheduled', 'failed', 'running')
              AND (claim_until IS NULL OR claim_until <= ?1)
            ORDER BY next_run_at ASC, id ASC
            ",
        )
        .map_err(to_processing_error)?;
    let rows = stmt
        .query_map(params![format_dt(Utc::now())], |row| row.get::<_, i64>(0))
        .map_err(to_processing_error)?;
    collect_rows(rows)
}

pub fn claim_job_by_id(
    path: &Path,
    job_id: i64,
    node_id: &str,
    lease_seconds: i64,
) -> Result<Option<ClaimedJob>> {
    let mut conn = open_connection(path)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(to_processing_error)?;
    let now = Utc::now();
    let maybe_job = tx
        .query_row(
            "
            SELECT id, name, spec_json, schedule_interval_s
            FROM jobs
            WHERE id = ?1
              AND next_run_at <= ?2
              AND status IN ('queued', 'scheduled', 'failed', 'running')
              AND (claim_until IS NULL OR claim_until <= ?2)
            ",
            params![job_id, format_dt(now)],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(to_processing_error)?;
    let Some((job_id, name, spec_json, schedule_interval_s)) = maybe_job else {
        tx.commit().map_err(to_processing_error)?;
        return Ok(None);
    };
    let spec = serde_json::from_str::<PipelineJobSpec>(&spec_json).map_err(BakulaError::Json)?;
    tx.execute(
        "
        UPDATE jobs
        SET status = 'running',
            claimed_by = ?1,
            claim_until = ?2,
            attempts = attempts + 1,
            updated_at = ?3,
            last_error = NULL
        WHERE id = ?4
        ",
        params![
            node_id,
            format_dt(now + chrono::Duration::seconds(lease_seconds)),
            format_dt(now),
            job_id
        ],
    )
    .map_err(to_processing_error)?;
    tx.commit().map_err(to_processing_error)?;
    Ok(Some(ClaimedJob {
        id: job_id,
        name,
        schedule_interval_s,
        spec,
    }))
}

/// `claimed_by` fencing (Deliverable 24, produkcni-plan.md): bez tohohle WHERE
/// podminky muze stale worker (jehoz lease uz vyprsela a jiny worker job znovu
/// prevzal pres `claim_due_job`/`claim_job_by_id`) prepsat vysledek, co prave pise
/// NOVY vlastnik - klasicky lost-update/split-brain bug. Vraci `false`, pokud se
/// fence neuplatnil (job uz nikdo jiny prevzal) - volajici to musi zalogovat, ne tise
/// ignorovat, protoze to znamena, ze vysledek tohoto behu se NEZAPSAL.
pub fn mark_job_succeeded(
    path: &Path,
    job_id: i64,
    claimed_by: &str,
    run_id: &str,
    schedule_interval_s: Option<i64>,
) -> Result<bool> {
    let conn = open_connection(path)?;
    let now = Utc::now();
    let (status, next_run_at) = if let Some(interval) = schedule_interval_s {
        (
            "scheduled",
            Some(format_dt(now + chrono::Duration::seconds(interval))),
        )
    } else {
        ("succeeded", None)
    };
    let affected = conn
        .execute(
            "
        UPDATE jobs
        SET status = ?1,
            next_run_at = COALESCE(?2, next_run_at),
            claimed_by = NULL,
            claim_until = NULL,
            updated_at = ?3,
            last_run_id = ?4,
            last_error = NULL
        WHERE id = ?5 AND claimed_by = ?6
        ",
            params![
                status,
                next_run_at,
                format_dt(now),
                run_id,
                job_id,
                claimed_by
            ],
        )
        .map_err(to_processing_error)?;
    Ok(affected > 0)
}

/// Pocet po sobe jdoucich selhani jednorazoveho jobu, po kterem se automaticke
/// opakovani vzda a cely dalsi retry odlozi o `GIVE_UP_DELAY_S` - stejna
/// disciplina jako `broker.rs`'s DLQ (`max_delivery_attempts`, tam take 5).
const MAX_AUTOMATIC_RETRY_ATTEMPTS: i64 = 5;
const BASE_BACKOFF_S: i64 = 30;
const MAX_BACKOFF_S: i64 = 3600;
const GIVE_UP_DELAY_S: i64 = 30 * 24 * 3600;

/// Audit nalez (30.10.2026, produkcni gap analyza): jednorazovy job bez
/// naplanovaneho intervalu dostal po selhani `next_run_at = now` - zadny
/// backoff, zadny strop. `worker_loop` ho hned v dalsim cyklu (par sekund,
/// `idle_sleep`) znovu prevzal a znovu spustil - napr. aktivni sken proti
/// nedostupne siti se opakoval donekonecna, bez zpomaleni. Exponencialni
/// backoff (30s/60s/120s/240s) a po `MAX_AUTOMATIC_RETRY_ATTEMPTS` selhanich
/// odlozeni o ~30 dni (operator musi rucne znovu naplanovat) - zadny novy
/// stav/fronta potreba, `status='failed'` uz je dnesni terminalni stav.
fn failure_backoff_seconds(attempts: i64) -> i64 {
    if attempts >= MAX_AUTOMATIC_RETRY_ATTEMPTS {
        return GIVE_UP_DELAY_S;
    }
    let exponent = (attempts.max(1) - 1).clamp(0, 10);
    (BASE_BACKOFF_S.saturating_mul(1i64 << exponent)).min(MAX_BACKOFF_S)
}

/// Stejny `claimed_by` fence jako `mark_job_succeeded` - viz tamni komentar.
pub fn mark_job_failed(
    path: &Path,
    job_id: i64,
    claimed_by: &str,
    error: &str,
    schedule_interval_s: Option<i64>,
) -> Result<bool> {
    let conn = open_connection(path)?;
    let now = Utc::now();
    let (status, next_run_at) = if let Some(interval) = schedule_interval_s {
        (
            "scheduled",
            format_dt(now + chrono::Duration::seconds(interval.max(30))),
        )
    } else {
        let attempts: i64 = conn
            .query_row(
                "SELECT attempts FROM jobs WHERE id = ?1",
                params![job_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(to_processing_error)?
            .unwrap_or(0);
        (
            "failed",
            format_dt(now + chrono::Duration::seconds(failure_backoff_seconds(attempts))),
        )
    };
    let affected = conn
        .execute(
            "
        UPDATE jobs
        SET status = ?1,
            next_run_at = ?2,
            claimed_by = NULL,
            claim_until = NULL,
            updated_at = ?3,
            last_error = ?4
        WHERE id = ?5 AND claimed_by = ?6
        ",
            params![
                status,
                next_run_at,
                format_dt(now),
                truncate_error(error),
                job_id,
                claimed_by
            ],
        )
        .map_err(to_processing_error)?;
    Ok(affected > 0)
}

/// Audit nalez (30.10.2026, produkcni gap analyza): `claim_until` se nastavi
/// jen jednou, pri `claim_due_job`/`claim_job_by_id` - pokud skutecna prace
/// (napr. `nmap -sV` na /24 + nuclei) trva dele nez `lease_seconds`, jiny
/// worker uvidi vyprselou lease a job znovu prevezme a znovu spusti, ZATIM
/// CO puvodni worker jeste bezi - dve souvisle aktivni sondy proti stejne
/// siti najednou. `claimed_by` fence v `mark_job_succeeded`/`mark_job_failed`
/// chrani jen VYSLEDEK (ktery worker ho zapise), ne samotne dvojite spusteni.
/// `worker_cycle` ted behem exekuce periodicky prodluzuje lease na pozadi -
/// stejny fenced vzor jako ostatni mutace (`WHERE id = ? AND claimed_by = ?
/// AND status = 'running'`), takze cizi/uz prevzaty job se tise neprodlouzi.
pub fn renew_lease(path: &Path, job_id: i64, claimed_by: &str, lease_seconds: i64) -> Result<bool> {
    let conn = open_connection(path)?;
    let now = Utc::now();
    let affected = conn
        .execute(
            "
        UPDATE jobs
        SET claim_until = ?1,
            updated_at = ?2
        WHERE id = ?3 AND claimed_by = ?4 AND status = 'running'
        ",
            params![
                format_dt(now + chrono::Duration::seconds(lease_seconds)),
                format_dt(now),
                job_id,
                claimed_by
            ],
        )
        .map_err(to_processing_error)?;
    Ok(affected > 0)
}

pub fn worker_cycle<F>(
    path: &Path,
    node_id: &str,
    display_name: &str,
    capabilities: &[String],
    leader_ttl_seconds: i64,
    job_lease_seconds: i64,
    mut executor: F,
) -> Result<Option<String>>
where
    F: FnMut(PipelineJobSpec) -> std::result::Result<String, String>,
{
    upsert_node_heartbeat(path, node_id, display_name, capabilities)?;
    let is_leader = acquire_leader_lease(path, node_id, leader_ttl_seconds)?;
    let Some(job) = claim_due_job(path, node_id, job_lease_seconds, is_leader)? else {
        return Ok(None);
    };

    let stop_renewal = Arc::new(AtomicBool::new(false));
    let renewal_thread = {
        let path = path.to_path_buf();
        let node_id = node_id.to_string();
        let job_id = job.id;
        let stop_renewal = Arc::clone(&stop_renewal);
        // Obnovovat v tretinach leasy - i kdyz jedno obnoveni vypadne (docasny
        // DB lock), zbyva jeste rezerva pred vyprsenim puvodniho `claim_until`.
        let renew_interval = Duration::from_secs((job_lease_seconds / 3).max(1) as u64);
        // Regrese po nasazeni (e2e test, 30.10.2026): `thread::sleep(renew_interval)`
        // v jednom kuse znamenalo, ze `renewal_thread.join()` nize cekal az
        // `renew_interval` (desitky sekund na vychozi 120s lease) i u jobu, ktery
        // dobehl za zlomek sekundy - `worker_cycle` se tim zpomalil o desitky
        // sekund navic, coz posunulo i casovani leader-election v
        // `platform_rbac_scheduler_cluster_and_server_work_end_to_end` (node-a's
        // leader lease stihla vyprset nez test stihl zavolat node-b). Kratke
        // polling kroky nechaji `stop_renewal` zareagovat v radu ~100ms, ne
        // az po celem intervalu.
        let poll_step = Duration::from_millis(100);
        thread::spawn(move || {
            let mut elapsed = Duration::ZERO;
            while !stop_renewal.load(Ordering::Relaxed) {
                thread::sleep(poll_step);
                elapsed += poll_step;
                if stop_renewal.load(Ordering::Relaxed) {
                    break;
                }
                if elapsed >= renew_interval {
                    let _ = renew_lease(&path, job_id, &node_id, job_lease_seconds);
                    elapsed = Duration::ZERO;
                }
            }
        })
    };
    let executor_result = executor(job.spec);
    stop_renewal.store(true, Ordering::Relaxed);
    let _ = renewal_thread.join();

    match executor_result {
        Ok(run_id) => {
            let fenced =
                mark_job_succeeded(path, job.id, node_id, &run_id, job.schedule_interval_s)?;
            if !fenced {
                return Err(BakulaError::Processing(format!(
                    "Job {} ({}) dobehl uspesne, ale jeho lease uz drzi jiny worker - vysledek {run_id} se NEZAPSAL (claimed_by fence)",
                    job.id, job.name
                )));
            }
            Ok(Some(run_id))
        }
        Err(error) => {
            let fenced = mark_job_failed(path, job.id, node_id, &error, job.schedule_interval_s)?;
            if !fenced {
                return Err(BakulaError::Processing(format!(
                    "Job {} ({}) selhal ({error}), ale jeho lease uz drzi jiny worker - chybovy stav se NEZAPSAL (claimed_by fence)",
                    job.id, job.name
                )));
            }
            Err(BakulaError::Processing(format!(
                "Job {} ({}) selhal: {error}",
                job.id, job.name
            )))
        }
    }
}

pub fn worker_loop<F>(
    path: &Path,
    node_id: &str,
    display_name: &str,
    capabilities: &[String],
    leader_ttl_seconds: i64,
    job_lease_seconds: i64,
    mut executor: F,
    idle_sleep: Duration,
) where
    F: FnMut(PipelineJobSpec) -> std::result::Result<String, String>,
{
    loop {
        let _ = worker_cycle(
            path,
            node_id,
            display_name,
            capabilities,
            leader_ttl_seconds,
            job_lease_seconds,
            |spec| executor(spec),
        );
        thread::sleep(idle_sleep);
    }
}

fn load_user_by_username(conn: &Connection, username: &str) -> Result<Option<UserRecord>> {
    conn.query_row(
        "SELECT id, username, role, enabled, created_at FROM users WHERE username = ?1",
        params![username],
        |row| {
            Ok(UserRecord {
                id: row.get(0)?,
                username: row.get(1)?,
                role: row.get(2)?,
                enabled: row.get::<_, i64>(3)? != 0,
                created_at: parse_dt(&row.get::<_, String>(4)?).map_err(to_rusqlite_error)?,
            })
        },
    )
    .optional()
    .map_err(to_processing_error)
}

fn open_connection(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path).map_err(to_processing_error)?;
    conn.busy_timeout(Duration::from_secs(5))
        .map_err(to_processing_error)?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(to_processing_error)?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(to_processing_error)?;
    ensure_token_expiry_column(&conn)?;
    Ok(conn)
}

/// Migrace starsich DB: sloupec `expires_at` pridany az pozdeji. Stavajici
/// tokeny dostanou NULL (= neexpiruji) - operator je ma rotovat; automaticke
/// zneplatneni by tise rozbilo bezici integrace.
fn ensure_token_expiry_column(conn: &Connection) -> Result<()> {
    let table_exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'api_tokens'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(to_processing_error)?
        > 0;
    if !table_exists {
        return Ok(());
    }
    let has_column = conn
        .prepare("PRAGMA table_info(api_tokens)")
        .map_err(to_processing_error)?
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(to_processing_error)?
        .filter_map(|name| name.ok())
        .any(|name| name == "expires_at");
    if !has_column {
        conn.execute("ALTER TABLE api_tokens ADD COLUMN expires_at TEXT", [])
            .map_err(to_processing_error)?;
    }
    Ok(())
}

fn build_ha_candidates(nodes: &[NodeRecord], policy: Option<&HaPolicy>) -> Vec<HaCandidate> {
    let Some(policy) = policy else {
        return Vec::new();
    };
    let ready_nodes = nodes
        .iter()
        .filter(|node| node.ready && node.drain_state == "ready")
        .count() as i64;
    let upgrading_nodes = nodes
        .iter()
        .filter(|node| node.upgrade_state == "upgrading")
        .count() as i64;
    nodes
        .iter()
        .filter(
            |node| match (&node.software_version, &policy.target_version) {
                (_, None) => false,
                (Some(current), Some(target)) => current != target,
                (None, Some(_)) => true,
            },
        )
        .map(|node| {
            let mut eligible = true;
            let mut reason = None;
            if !node.ready || node.drain_state != "ready" || node.upgrade_state != "idle" {
                eligible = false;
                reason = Some("uzel neni v pripravenem stavu".to_string());
            } else if upgrading_nodes >= policy.rollout_batch_size {
                eligible = false;
                reason = Some("dosazen rollout batch limit".to_string());
            } else if ready_nodes - 1 < policy.quorum_size
                || ready_nodes - 1 < policy.min_ready_nodes
            {
                eligible = false;
                reason = Some("upgrade by porusil quorum nebo minimum ready uzlu".to_string());
            }
            HaCandidate {
                node_id: node.node_id.clone(),
                current_version: node.software_version.clone(),
                target_version: policy.target_version.clone(),
                eligible,
                reason,
            }
        })
        .collect()
}

fn add_column_if_missing(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<()> {
    let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
    match conn.execute(&sql, []) {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(_, Some(message)))
            if message.contains("duplicate column name") =>
        {
            Ok(())
        }
        Err(error) => Err(to_processing_error(error)),
    }
}

fn map_job_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobRecord> {
    Ok(JobRecord {
        id: row.get(0)?,
        name: row.get(1)?,
        status: row.get(2)?,
        next_run_at: parse_dt(&row.get::<_, String>(3)?).map_err(to_rusqlite_error)?,
        schedule_interval_s: row.get(4)?,
        claimed_by: row.get(5)?,
        claim_until: row
            .get::<_, Option<String>>(6)?
            .map(|value| parse_dt(&value).map_err(to_rusqlite_error))
            .transpose()?,
        attempts: row.get(7)?,
        last_error: row.get(8)?,
        last_run_id: row.get(9)?,
        created_at: parse_dt(&row.get::<_, String>(10)?).map_err(to_rusqlite_error)?,
        updated_at: parse_dt(&row.get::<_, String>(11)?).map_err(to_rusqlite_error)?,
    })
}

fn hash_token(raw_token: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(raw_token.as_bytes());
    format!("{:x}", digest.finalize())
}

fn now_string() -> String {
    format_dt(Utc::now())
}

fn format_dt(value: DateTime<Utc>) -> String {
    value.to_rfc3339()
}

fn parse_dt(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|item| item.with_timezone(&Utc))
        .map_err(|error| {
            BakulaError::Processing(format!("Nelze zpracovat datum/cas {value}: {error}"))
        })
}

fn truncate_error(value: &str) -> String {
    value.chars().take(4000).collect()
}

fn collect_rows<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>,
) -> Result<Vec<T>> {
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(to_processing_error)?);
    }
    Ok(items)
}

fn to_processing_error(error: rusqlite::Error) -> BakulaError {
    BakulaError::Processing(format!("SQLite chyba: {error}"))
}

fn to_rusqlite_error(error: BakulaError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
}

fn default_ports() -> Vec<u16> {
    vec![21, 22, 23, 80, 443, 8080]
}

fn default_profile() -> String {
    "bezny".to_string()
}

fn default_provider() -> String {
    "demo".to_string()
}

fn default_librenms_token_env() -> String {
    "LIBRENMS_TOKEN".to_string()
}

fn default_meraki_token_env() -> String {
    "MERAKI_DASHBOARD_API_KEY".to_string()
}

fn default_meraki_timespan() -> u32 {
    86400
}

fn default_unifi_token_env() -> String {
    "UNIFI_API_KEY".to_string()
}

fn default_aruba_token_env() -> String {
    "ARUBA_CENTRAL_TOKEN".to_string()
}

fn default_omada_token_env() -> String {
    "OMADA_ACCESS_TOKEN".to_string()
}

fn default_urlhaus_auth_env() -> String {
    "URLHAUS_AUTH_KEY".to_string()
}

fn default_abuseipdb_key_env() -> String {
    "ABUSEIPDB_API_KEY".to_string()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Jen 6 poli `PipelineJobSpec` nema `#[serde(default...)]` (workspace_root, nazev,
    /// scope, nmap_xml, suricata_eve, zeek_dir) - zbytek serde defaultuje, proto staci
    /// minimalni JSON, ne rucni vypis ~40 poli.
    fn minimal_spec() -> PipelineJobSpec {
        serde_json::from_str(
            r#"{"workspace_root":"ws","nazev":"test","scope":[],"nmap_xml":null,"suricata_eve":null,"zeek_dir":null}"#,
        )
        .expect("minimalni PipelineJobSpec")
    }

    fn db_with_user() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let db_path = temp.path().join("platform.sqlite");
        init_database(&db_path).expect("init db");
        create_or_update_user(&db_path, "alice", Role::Analyst).expect("user");
        (temp, db_path)
    }

    #[test]
    fn token_with_default_ttl_authenticates_and_has_expiry() {
        let (_temp, db) = db_with_user();
        let token = issue_token(&db, "alice", "t").expect("issue");
        assert!(token.expires_at.is_some());
        assert!(
            authenticate_token(&db, &token.raw_token)
                .expect("auth")
                .is_some()
        );
    }

    #[test]
    fn expired_token_is_rejected() {
        let (_temp, db) = db_with_user();
        let token = issue_token(&db, "alice", "t").expect("issue");
        let conn = open_connection(&db).expect("conn");
        conn.execute(
            "UPDATE api_tokens SET expires_at = ?1",
            params![format_dt(Utc::now() - chrono::Duration::seconds(5))],
        )
        .expect("expire");
        drop(conn);
        assert!(
            authenticate_token(&db, &token.raw_token)
                .expect("auth")
                .is_none(),
            "token po expiraci nesmi projit"
        );
    }

    #[test]
    fn ttl_zero_means_explicitly_non_expiring() {
        let (_temp, db) = db_with_user();
        let token = issue_token_with_ttl(&db, "alice", "forever", Some(0)).expect("issue");
        assert!(token.expires_at.is_none());
        assert!(
            authenticate_token(&db, &token.raw_token)
                .expect("auth")
                .is_some()
        );
    }

    #[test]
    fn legacy_database_without_expires_column_is_migrated_and_old_tokens_keep_working() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let db = temp.path().join("old.sqlite");
        init_database(&db).expect("init");
        create_or_update_user(&db, "alice", Role::Viewer).expect("user");
        let token = issue_token_with_ttl(&db, "alice", "old", Some(0)).expect("issue");

        // Simulace stare DB: sloupec expires_at neexistuje.
        let raw = Connection::open(&db).expect("raw");
        raw.execute_batch("ALTER TABLE api_tokens DROP COLUMN expires_at;")
            .expect("drop column");
        drop(raw);

        assert!(
            authenticate_token(&db, &token.raw_token)
                .expect("auth")
                .is_some(),
            "stary token (bez expirace) musi po migraci dal fungovat"
        );
        let after = issue_token(&db, "alice", "new").expect("issue po migraci");
        assert!(after.expires_at.is_some());
    }

    /// Regresni test na bezpecnostni bug: `claim_due_job` drive nevybiral joby ve
    /// stavu `running` (chybely v `status IN (...)`), i kdyz jejich `claim_until`
    /// davno vyprsel - job zasekly po padu workeru mezi claim a dokoncenim zustal
    /// navzdy nedostupny. Oprava doplnila `'running'` do seznamu stavu.
    #[test]
    fn claim_due_job_recovers_running_job_after_expired_lease() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let db_path = temp.path().join("platform.sqlite");
        init_database(&db_path).expect("init db");

        let job_id =
            enqueue_job(&db_path, "test-job", &minimal_spec(), None, None).expect("enqueue");

        let first_claim = claim_due_job(&db_path, "node-a", 60, true)
            .expect("claim ok")
            .expect("prvni claim musi najit job");
        assert_eq!(first_claim.id, job_id);

        // Simulace padu workeru: job zustava ve stavu 'running', ale jeho claim_until
        // je davno v minulosti - presne stav, ktery se pred opravou nikdy nezotavil.
        let conn = open_connection(&db_path).expect("open connection");
        let expired = Utc::now() - chrono::Duration::seconds(120);
        conn.execute(
            "UPDATE jobs SET claim_until = ?1 WHERE id = ?2",
            params![format_dt(expired), job_id],
        )
        .expect("force-expire claim");
        drop(conn);

        let recovered = claim_due_job(&db_path, "node-b", 60, true).expect("claim ok");
        assert!(
            recovered.is_some(),
            "job zasekly v 'running' s vyprselym claim_until musi byt znovu nalezen"
        );
        assert_eq!(recovered.unwrap().id, job_id);
    }

    /// Regresni test na bezpecnostni bug (Deliverable 24, produkcni-plan.md):
    /// `mark_job_succeeded`/`mark_job_failed` drive nemely `claimed_by` fence -
    /// stale worker (jehoz lease uz vyprsela a jiny worker job znovu prevzal) mohl
    /// prepsat vysledek, co prave pise NOVY vlastnik. Scenar: node-a prevezme job,
    /// jeho lease vyprsi, node-b job znovu prevezme a zacne pracovat, pak se node-a
    /// (opozdene, po padu/zpomaleni) pokusi dokoncit svou PUVODNI, uz neplatnou
    /// praci - tohle MUSI byt no-op (vraci false), ne tiche prepsani.
    #[test]
    fn mark_job_succeeded_is_fenced_against_stale_worker_after_job_was_reclaimed() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let db_path = temp.path().join("platform.sqlite");
        init_database(&db_path).expect("init db");

        let job_id =
            enqueue_job(&db_path, "test-job", &minimal_spec(), None, None).expect("enqueue");

        let first_claim = claim_due_job(&db_path, "node-a", 60, true)
            .expect("claim ok")
            .expect("node-a musi job prevzit");
        assert_eq!(first_claim.id, job_id);

        // Simulace: node-a lease vyprsela, aniz by node-a dokoncil praci.
        let conn = open_connection(&db_path).expect("open connection");
        let expired = Utc::now() - chrono::Duration::seconds(120);
        conn.execute(
            "UPDATE jobs SET claim_until = ?1 WHERE id = ?2",
            params![format_dt(expired), job_id],
        )
        .expect("force-expire claim");
        drop(conn);

        // node-b prevezme stejny job (legitimne, protoze lease vyprsela).
        let second_claim = claim_due_job(&db_path, "node-b", 60, true)
            .expect("claim ok")
            .expect("node-b musi job znovu prevzit po vyprseni node-a lease");
        assert_eq!(second_claim.id, job_id);

        // node-a (opozdene, uz bez platneho claimu) se pokusi dokoncit SVOJI,
        // uz neplatnou praci - fence to musi odmitnout.
        let node_a_fenced = mark_job_succeeded(&db_path, job_id, "node-a", "run-from-node-a", None)
            .expect("mark_job_succeeded nesmi vratit chybu, jen false");
        assert!(
            !node_a_fenced,
            "stale node-a nesmi moct dokoncit job, ktery uz drzi node-b"
        );

        // Status musi zustat 'running' (node-b stale pracuje), ne 'succeeded' s
        // vysledkem od node-a.
        let conn = open_connection(&db_path).expect("open connection");
        let status: String = conn
            .query_row(
                "SELECT status FROM jobs WHERE id = ?1",
                params![job_id],
                |row| row.get(0),
            )
            .expect("precist status");
        drop(conn);
        assert_eq!(
            status, "running",
            "job nesmi byt oznacen jako hotovy vysledkem od stale workeru"
        );

        // node-b (skutecny drzitel claimu) dokonci job legitimne - tohle MUSI projit.
        let node_b_fenced = mark_job_succeeded(&db_path, job_id, "node-b", "run-from-node-b", None)
            .expect("mark_job_succeeded nesmi vratit chybu");
        assert!(
            node_b_fenced,
            "skutecny drzitel claimu (node-b) musi byt schopen job dokoncit"
        );
    }

    #[test]
    fn claim_due_job_does_not_reclaim_job_with_still_valid_lease() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let db_path = temp.path().join("platform.sqlite");
        init_database(&db_path).expect("init db");

        enqueue_job(&db_path, "test-job", &minimal_spec(), None, None).expect("enqueue");
        claim_due_job(&db_path, "node-a", 300, true)
            .expect("claim ok")
            .expect("prvni claim musi najit job");

        // claim_until je 300s v budoucnu - job prave bezi, nesmi se dat nikomu jinemu.
        let not_reclaimed = claim_due_job(&db_path, "node-b", 300, true).expect("claim ok");
        assert!(
            not_reclaimed.is_none(),
            "job se stale platnym claim_until se nesmi znovu rozdat"
        );
    }

    /// Stejny bug (chybejici `'running'` v `status IN (...)`) byl i v `list_due_job_ids`
    /// - zaseknuty job by se nikdy neobjevil ani v seznamu "due" jobu k monitoringu.
    #[test]
    fn list_due_job_ids_includes_running_job_with_expired_lease() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let db_path = temp.path().join("platform.sqlite");
        init_database(&db_path).expect("init db");

        let job_id =
            enqueue_job(&db_path, "test-job", &minimal_spec(), None, None).expect("enqueue");
        claim_due_job(&db_path, "node-a", 60, true)
            .expect("claim ok")
            .expect("prvni claim musi najit job");

        let conn = open_connection(&db_path).expect("open connection");
        let expired = Utc::now() - chrono::Duration::seconds(120);
        conn.execute(
            "UPDATE jobs SET claim_until = ?1 WHERE id = ?2",
            params![format_dt(expired), job_id],
        )
        .expect("force-expire claim");
        drop(conn);

        let due_ids = list_due_job_ids(&db_path).expect("list due jobs");
        assert!(
            due_ids.contains(&job_id),
            "zasekly running job s vyprselym claim_until musi byt v seznamu due jobu"
        );
    }

    /// Stejny bug byl i v `claim_job_by_id` - rucni znovu-naroky konkretniho zasekleho
    /// jobu (napr. operatorsky zasah) by take nikdy nenaslo job ve stavu 'running'.
    #[test]
    fn claim_job_by_id_recovers_running_job_after_expired_lease() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let db_path = temp.path().join("platform.sqlite");
        init_database(&db_path).expect("init db");

        let job_id =
            enqueue_job(&db_path, "test-job", &minimal_spec(), None, None).expect("enqueue");
        claim_due_job(&db_path, "node-a", 60, true)
            .expect("claim ok")
            .expect("prvni claim musi najit job");

        let conn = open_connection(&db_path).expect("open connection");
        let expired = Utc::now() - chrono::Duration::seconds(120);
        conn.execute(
            "UPDATE jobs SET claim_until = ?1 WHERE id = ?2",
            params![format_dt(expired), job_id],
        )
        .expect("force-expire claim");
        drop(conn);

        let recovered = claim_job_by_id(&db_path, job_id, "node-b", 60).expect("claim ok");
        assert!(
            recovered.is_some(),
            "claim_job_by_id musi umoznit rucni znovu-naroky zasekleho 'running' jobu"
        );
    }

    /// Deliverable 24 (produkcni-plan.md, H5 krok 1): skutecny souvezny test, ne jen
    /// sekvencni simulace vyprseleho leasu. 4 OS vlakna soucasne bijou o 20 joby ve
    /// STEJNEM SQLite souboru pres `claim_due_job` (`TransactionBehavior::Immediate`
    /// ma dat vzajemne vyloucenou SELECT+UPDATE dvojici). Overuje presne tu obavu, co
    /// skeptik v produkcnim auditu vznesl - "atomicita claim-query pod konkurenci
    /// nikdy neverena" - jde o vlakna v jednom procesu, ne oddelene OS procesy (ty
    /// jsou dalsi krok, Faze 2 v produkcnim planu), ale SQLite zamykani souboru je
    /// stejny mechanismus, ktery by resil i konkurenci mezi procesy na jednom stroji.
    #[test]
    fn concurrent_claim_due_job_never_double_claims_across_real_threads() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let db_path = temp.path().join("platform.sqlite");
        init_database(&db_path).expect("init db");

        const JOB_COUNT: usize = 20;
        const WORKER_COUNT: usize = 4;

        let mut job_ids = Vec::with_capacity(JOB_COUNT);
        for index in 0..JOB_COUNT {
            let job_id = enqueue_job(
                &db_path,
                &format!("concurrent-test-job-{index}"),
                &minimal_spec(),
                None,
                None,
            )
            .expect("enqueue");
            job_ids.push(job_id);
        }

        let claimed_by: Arc<Mutex<HashMap<i64, String>>> = Arc::new(Mutex::new(HashMap::new()));
        let mut handles = Vec::with_capacity(WORKER_COUNT);
        for worker_index in 0..WORKER_COUNT {
            let db_path = db_path.clone();
            let claimed_by = Arc::clone(&claimed_by);
            handles.push(thread::spawn(move || {
                let node_id = format!("thread-worker-{worker_index}");
                loop {
                    match claim_due_job(&db_path, &node_id, 60, true) {
                        Ok(Some(job)) => {
                            let mut map = claimed_by.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                            if let Some(existing) = map.insert(job.id, node_id.clone()) {
                                panic!(
                                    "job {} byl prevzat dvakrat - driv '{existing}', ted '{node_id}' - claim neni atomicky",
                                    job.id
                                );
                            }
                            drop(map);
                            let fenced =
                                mark_job_succeeded(&db_path, job.id, &node_id, "run", None)
                                    .expect("mark_job_succeeded");
                            assert!(fenced, "vlastni claim musi byt schopen job dokoncit");
                        }
                        Ok(None) => break,
                        Err(error) => panic!("claim_due_job selhal: {error}"),
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().expect("worker vlakno nesmi panikarit");
        }

        let final_map = claimed_by
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(
            final_map.len(),
            JOB_COUNT,
            "vsech {JOB_COUNT} jobu musi byt prevzato presne jednou celkem, dostal jsem {}",
            final_map.len()
        );
        for job_id in &job_ids {
            assert!(
                final_map.contains_key(job_id),
                "job {job_id} nebyl nikdy prevzat zadnym vlaknem"
            );
        }
    }

    #[test]
    fn failure_backoff_seconds_grows_exponentially_then_gives_up() {
        assert_eq!(failure_backoff_seconds(1), 30);
        assert_eq!(failure_backoff_seconds(2), 60);
        assert_eq!(failure_backoff_seconds(3), 120);
        assert_eq!(failure_backoff_seconds(4), 240);
        assert_eq!(failure_backoff_seconds(5), GIVE_UP_DELAY_S);
        assert_eq!(failure_backoff_seconds(1000), GIVE_UP_DELAY_S);
        assert_eq!(failure_backoff_seconds(0), 30);
    }

    /// Audit nalez (30.10.2026, produkcni gap analyza): jednorazovy job bez
    /// backoffu po selhani dostal `next_run_at = now` - `worker_loop` ho hned v
    /// pristim cyklu znovu prevzal a znovu spustil, bez zpomaleni a bez stropu.
    #[test]
    fn mark_job_failed_delays_retry_of_a_one_shot_job_instead_of_retrying_immediately() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let db_path = temp.path().join("platform.sqlite");
        init_database(&db_path).expect("init db");

        let job_id =
            enqueue_job(&db_path, "test-job", &minimal_spec(), None, None).expect("enqueue");
        let claim = claim_due_job(&db_path, "node-a", 60, true)
            .expect("claim ok")
            .expect("prvni claim musi najit job");
        assert_eq!(claim.id, job_id);

        let before_fail = Utc::now();
        mark_job_failed(&db_path, job_id, "node-a", "simulovane selhani", None)
            .expect("mark_job_failed")
            .then_some(())
            .expect("mark_job_failed musi uspet (claimed_by fence sedi)");

        let conn = open_connection(&db_path).expect("open connection");
        let next_run_at: String = conn
            .query_row(
                "SELECT next_run_at FROM jobs WHERE id = ?1",
                params![job_id],
                |row| row.get(0),
            )
            .expect("precteni next_run_at");
        let next_run_at = parse_dt(&next_run_at).expect("parse next_run_at");

        assert!(
            next_run_at >= before_fail + chrono::Duration::seconds(29),
            "prvni selhani jednorazoveho jobu musi mit aspon ~30s backoff, ne okamzity retry (next_run_at={next_run_at}, before_fail={before_fail})"
        );
    }

    /// Po `MAX_AUTOMATIC_RETRY_ATTEMPTS` selhanich musi dalsi automaticky
    /// pokus zustat odlozeny o dny, ne o desitky sekund - jinak by se job bez
    /// konce dal znovu a znovu zkouset proti neopravitelne pricine selhani.
    #[test]
    fn mark_job_failed_gives_up_automatic_retry_after_max_attempts() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let db_path = temp.path().join("platform.sqlite");
        init_database(&db_path).expect("init db");

        let job_id =
            enqueue_job(&db_path, "test-job", &minimal_spec(), None, None).expect("enqueue");
        let conn = open_connection(&db_path).expect("open connection");
        conn.execute(
            "UPDATE jobs SET attempts = ?1 WHERE id = ?2",
            params![MAX_AUTOMATIC_RETRY_ATTEMPTS, job_id],
        )
        .expect("force attempts");
        drop(conn);

        let claim = claim_due_job(&db_path, "node-a", 60, true)
            .expect("claim ok")
            .expect("claim musi najit job");
        assert_eq!(claim.id, job_id);

        let before_fail = Utc::now();
        mark_job_failed(&db_path, job_id, "node-a", "trvale selhani", None)
            .expect("mark_job_failed")
            .then_some(())
            .expect("mark_job_failed musi uspet");

        let conn = open_connection(&db_path).expect("open connection");
        let next_run_at: String = conn
            .query_row(
                "SELECT next_run_at FROM jobs WHERE id = ?1",
                params![job_id],
                |row| row.get(0),
            )
            .expect("precteni next_run_at");
        let next_run_at = parse_dt(&next_run_at).expect("parse next_run_at");

        assert!(
            next_run_at >= before_fail + chrono::Duration::days(1),
            "po dosazeni max attempts se musi dalsi pokus odlozit o dny, ne o desitky sekund (next_run_at={next_run_at})"
        );
    }

    #[test]
    fn renew_lease_extends_claim_until_and_is_fenced_against_wrong_owner() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let db_path = temp.path().join("platform.sqlite");
        init_database(&db_path).expect("init db");

        let job_id =
            enqueue_job(&db_path, "test-job", &minimal_spec(), None, None).expect("enqueue");
        claim_due_job(&db_path, "node-a", 60, true)
            .expect("claim ok")
            .expect("claim musi najit job");

        assert!(
            !renew_lease(&db_path, job_id, "node-b", 300).expect("renew_lease (wrong owner)"),
            "renew_lease musi byt fencovane na spravneho claimed_by"
        );

        let before_renew = Utc::now();
        assert!(
            renew_lease(&db_path, job_id, "node-a", 300).expect("renew_lease (owner)"),
            "renew_lease spravnym vlastnikem musi uspet"
        );

        let conn = open_connection(&db_path).expect("open connection");
        let claim_until: String = conn
            .query_row(
                "SELECT claim_until FROM jobs WHERE id = ?1",
                params![job_id],
                |row| row.get(0),
            )
            .expect("precteni claim_until");
        let claim_until = parse_dt(&claim_until).expect("parse claim_until");
        assert!(
            claim_until >= before_renew + chrono::Duration::seconds(299),
            "renew_lease musi posunout claim_until dopredu o novou lease_seconds (claim_until={claim_until}, before_renew={before_renew})"
        );
    }

    /// Audit nalez (30.10.2026, produkcni gap analyza): bez periodickeho
    /// obnovovani by `claim_until` vyprselo v polovine dlouhe exekuce a jiny
    /// worker by job prevzal podruhe, ZATIM CO prvni worker jeste bezi - dve
    /// souvisle aktivni sondy proti stejne siti najednou. Test spusti
    /// `worker_cycle` s executorem delsim nez `lease_seconds` a soucasne se
    /// z druheho "workera" opakovane snazi job ukradnout `claim_due_job`.
    #[test]
    fn worker_cycle_renews_lease_during_long_executor_preventing_concurrent_double_claim() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let db_path = temp.path().join("platform.sqlite");
        init_database(&db_path).expect("init db");
        let job_id =
            enqueue_job(&db_path, "test-job", &minimal_spec(), None, None).expect("enqueue");

        let lease_seconds = 2;
        let worker_db_path = db_path.clone();
        let worker = thread::spawn(move || {
            worker_cycle(
                &worker_db_path,
                "node-a",
                "Node A",
                &[],
                60,
                lease_seconds,
                |_spec| {
                    thread::sleep(Duration::from_millis(3500));
                    Ok("run-ok".to_string())
                },
            )
        });

        // Cekej, az worker vlakno job skutecne prevezme (status='running'),
        // misto pevneho sleep odhadu - heartbeat+leader-lease+claim maji
        // vlastni promennou DB latenci, kterou nahodny sleep nemusi pokryt.
        for _ in 0..100 {
            let conn = open_connection(&db_path).expect("open connection");
            let status: String = conn
                .query_row(
                    "SELECT status FROM jobs WHERE id = ?1",
                    params![job_id],
                    |row| row.get(0),
                )
                .expect("precteni status");
            drop(conn);
            if status == "running" {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }

        let mut stolen = false;
        for _ in 0..14 {
            if claim_due_job(&db_path, "node-b", 60, true)
                .expect("claim_due_job (node-b)")
                .is_some()
            {
                stolen = true;
                break;
            }
            thread::sleep(Duration::from_millis(250));
        }

        let outcome = worker.join().expect("worker vlakno nesmi panikarit");
        assert!(
            matches!(outcome, Ok(Some(ref run_id)) if run_id == "run-ok"),
            "worker_cycle musi uspet s ocekavanym run_id: {outcome:?}"
        );
        assert!(
            !stolen,
            "bez obnovovani leasy (puvodni lease_seconds={lease_seconds}) by jiny worker job behem {}ms dlouhe exekuce ukradl",
            3500
        );
    }

    /// Regrese po nasazeni (e2e test, 30.10.2026): prvni verze obnovovaciho
    /// vlakna delala `thread::sleep(renew_interval)` v jednom kuse, takze
    /// `renewal_thread.join()` v `worker_cycle` cekal az `renew_interval`
    /// (desitky sekund na vychozi 120s lease) i u jobu, ktery dobehl za
    /// zlomek sekundy - zpomalilo to KAZDE `worker_cycle` volani, ne jen ty
    /// dlouhe. Ověřeno primo zmerenim: rychly executor nesmi `worker_cycle`
    /// zpomalit o vic nez malou rezervu nad polling krok.
    #[test]
    fn worker_cycle_does_not_block_on_lease_renewal_when_executor_finishes_quickly() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let db_path = temp.path().join("platform.sqlite");
        init_database(&db_path).expect("init db");
        enqueue_job(&db_path, "test-job", &minimal_spec(), None, None).expect("enqueue");

        let started_at = std::time::Instant::now();
        let outcome = worker_cycle(&db_path, "node-a", "Node A", &[], 60, 120, |_spec| {
            // Nenulove, ale kratke zpozdeni - da obnovovacimu vlaknu dost
            // casu, aby se stihlo spustit a zacit svuj sleep PRED tim, nez
            // hlavni vlakno dokonci executor a nastavi `stop_renewal`. Bez
            // tohoto zpozdeni je race tak uzky, ze test stary bug nezachyti
            // (obnovovaci vlakno casto ani nestihne zacit).
            thread::sleep(Duration::from_millis(50));
            Ok("run-ok".to_string())
        });
        let elapsed = started_at.elapsed();

        assert!(
            matches!(outcome, Ok(Some(ref run_id)) if run_id == "run-ok"),
            "worker_cycle musi uspet: {outcome:?}"
        );
        // Prah 10s (ne 1s) kvuli SQLite kontenci pri souběžném běhu celé
        // testovací sady - stará chyba (jednorazový sleep na celý
        // renew_interval) by zpomalila o desitky sekund (40s na lease=120),
        // takže i s rezervou na kontenci zůstává jasně odlišitelné.
        assert!(
            elapsed < Duration::from_secs(10),
            "rychly executor nesmi worker_cycle zpomalit na cekani na obnoveni leasy (trvalo {elapsed:?}, lease_seconds=120 by znacilo bug pri starem jednorazovem sleep)"
        );
    }
}
