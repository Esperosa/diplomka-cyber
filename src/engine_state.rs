//! Perzistentní stav jádra v3 mezi běhy (krok 1B/1C): SQLite soubor ve workspace
//! (`engine-state.sqlite`) s tabulkou `kv` (JSON hodnoty) a tabulkami paměti nálezů
//! (`finding_memory`). Plus perzistentní inventář s hysterezí (audit A09, R13):
//! po restartu enginu inventář nezmizí a host nebo služba, které chybí v jednom
//! skenu (výpadek, patch), se hned nezahodí.

use std::{
    collections::{BTreeMap, HashSet},
    path::Path,
    time::Duration,
};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    error::{SalticusError, Result},
    model::HostReport,
};

fn db_error(error: rusqlite::Error) -> SalticusError {
    SalticusError::Processing(format!("engine_state SQLite chyba: {error}"))
}

/// Úložiště stavu jádra (kv + paměť nálezů v téže databázi).
pub struct EngineStateStore {
    conn: Connection,
}

impl EngineStateStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path).map_err(db_error)?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(db_error)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(db_error)?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory().map_err(db_error)?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );",
        )
        .map_err(db_error)?;
        crate::finding_memory::migrate(&conn)?;
        Ok(Self { conn })
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub fn load<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "SELECT value FROM kv WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?;
        raw.map(|text| serde_json::from_str(&text).map_err(SalticusError::Json))
            .transpose()
    }

    pub fn save<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        let text = serde_json::to_string(value).map_err(SalticusError::Json)?;
        self.conn
            .execute(
                "INSERT INTO kv (name, value, updated_at) VALUES (?1, ?2, datetime('now'))
                 ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                params![name, text],
            )
            .map_err(db_error)?;
        Ok(())
    }
}

/// Kolik skenů za sebou smí host chybět, než se z inventáře vyřadí.
pub const HOST_GRACE_SCANS: u32 = 2;
/// Kolik skenů smí chybět služba přítomného hostu.
pub const SERVICE_GRACE_SCANS: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InventoryHost {
    host: HostReport,
    misses: u32,
    service_misses: BTreeMap<String, u32>,
}

/// Inventář přes skeny: drží poslední známý stav hostu, s hysterezí při chybění.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistentInventory {
    hosts: BTreeMap<String, InventoryHost>,
    scans: u64,
}

fn service_id(service: &crate::model::ServiceReport) -> String {
    format!("{}/{}", service.proto, service.port)
}

impl PersistentInventory {
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    pub fn scans(&self) -> u64 {
        self.scans
    }

    /// Sloučí nový sken. Host chybějící ve skenu zůstane `HOST_GRACE_SCANS` skenů,
    /// chybějící služba přítomného hostu `SERVICE_GRACE_SCANS` skenů.
    pub fn merge_scan(&mut self, scan: &[HostReport]) {
        self.scans += 1;
        let present: HashSet<&str> = scan.iter().map(|h| h.ip.as_str()).collect();
        for host in scan {
            match self.hosts.get_mut(&host.ip) {
                Some(entry) => {
                    let mut merged = host.clone();
                    let fresh: HashSet<String> = host.services.iter().map(service_id).collect();
                    let mut misses = BTreeMap::new();
                    for old in &entry.host.services {
                        let id = service_id(old);
                        if fresh.contains(&id) || old.port == 0 {
                            continue;
                        }
                        let count = entry.service_misses.get(&id).copied().unwrap_or(0) + 1;
                        if count <= SERVICE_GRACE_SCANS {
                            merged.services.push(old.clone());
                            misses.insert(id, count);
                        }
                    }
                    merged
                        .services
                        .sort_by(|l, r| l.port.cmp(&r.port).then(l.proto.cmp(&r.proto)));
                    entry.host = merged;
                    entry.misses = 0;
                    entry.service_misses = misses;
                }
                None => {
                    self.hosts.insert(
                        host.ip.clone(),
                        InventoryHost {
                            host: host.clone(),
                            misses: 0,
                            service_misses: BTreeMap::new(),
                        },
                    );
                }
            }
        }
        self.hosts.retain(|ip, entry| {
            if present.contains(ip.as_str()) {
                return true;
            }
            entry.misses += 1;
            entry.misses <= HOST_GRACE_SCANS
        });
    }

    /// Hosté pro report (včetně dočasně chybějících), seřazené podle IP.
    pub fn hosts(&self) -> Vec<HostReport> {
        self.hosts
            .values()
            .map(|entry| {
                let mut host = entry.host.clone();
                for service in &mut host.services {
                    service.events.clear();
                }
                host
            })
            .collect()
    }

    pub fn is_stale(&self, ip: &str) -> bool {
        self.hosts.get(ip).is_some_and(|entry| entry.misses > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, InventoryRecord, ServiceReport};

    fn service(port: u16) -> ServiceReport {
        ServiceReport {
            service_id: format!("svc:{port}"),
            service_key: format!("x/tcp/{port}"),
            proto: "tcp".to_string(),
            port,
            port_state: "open".to_string(),
            state_reason: None,
            inventory: InventoryRecord {
                service_name: "x".to_string(),
                product: None,
                version: None,
                extrainfo: None,
                detection_source: "nmap".to_string(),
                confidence: Confidence::High,
            },
            cpe: Vec::new(),
            cves: Vec::new(),
            events: Vec::new(),
            web_probe: None,
            active_checks: Vec::new(),
            score: 0.0,
            priorita: "nizka".to_string(),
        }
    }

    fn host(ip: &str, ports: &[u16]) -> HostReport {
        HostReport {
            host_id: format!("host:{ip}"),
            host_key: ip.to_string(),
            ip: ip.to_string(),
            hostname: None,
            mac: None,
            vendor: None,
            asset_id: None,
            identity_note: None,
            device_class: None,
            services: ports.iter().map(|p| service(*p)).collect(),
        }
    }

    #[test]
    fn host_missing_in_one_scan_is_kept_then_dropped_after_grace() {
        let mut inventory = PersistentInventory::default();
        inventory.merge_scan(&[host("10.0.0.1", &[22]), host("10.0.0.2", &[80])]);
        inventory.merge_scan(&[host("10.0.0.1", &[22])]);
        assert_eq!(
            inventory.hosts().len(),
            2,
            "pad pri skenu nesmi host smazat"
        );
        assert!(inventory.is_stale("10.0.0.2"));
        inventory.merge_scan(&[host("10.0.0.1", &[22])]);
        inventory.merge_scan(&[host("10.0.0.1", &[22])]);
        assert_eq!(inventory.hosts().len(), 1);
    }

    #[test]
    fn service_missing_once_is_kept_with_hysteresis() {
        let mut inventory = PersistentInventory::default();
        inventory.merge_scan(&[host("10.0.0.1", &[22, 443])]);
        inventory.merge_scan(&[host("10.0.0.1", &[22])]);
        assert_eq!(inventory.hosts()[0].services.len(), 2);
        inventory.merge_scan(&[host("10.0.0.1", &[22])]);
        assert_eq!(inventory.hosts()[0].services.len(), 1);
    }

    #[test]
    fn store_roundtrips_inventory_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine-state.sqlite");
        let mut inventory = PersistentInventory::default();
        inventory.merge_scan(&[host("10.0.0.9", &[3306])]);
        EngineStateStore::open(&path)
            .unwrap()
            .save("inventory", &inventory)
            .unwrap();
        let store = EngineStateStore::open(&path).unwrap();
        let back: PersistentInventory = store.load("inventory").unwrap().unwrap();
        assert_eq!(back.hosts().len(), 1);
        assert!(
            store
                .load::<PersistentInventory>("chybi")
                .unwrap()
                .is_none()
        );
    }
}
