//! Uložená historie toků (krok 2B, žebřík ověřování L0; Dodatek A.3 bod 1).
//!
//! Souhrn, ne surové toky: pro každý klíč (služba, zdroj) a metriku se drží maximum
//! za hodinu týdne (168 slotů) s číslem dne posledního zápisu, takže jde odpovědět
//! „stalo se to už dřív?“ (retrospektivní baseline hostu i skupiny) bez ukládání
//! conn.log. Plus komunikační hrany mezi vnitřními hosty (pro pivot L4).
//!
//! Ochrana proti učení z útoku (RQ2 Z3, nízká jistota: adaptivní baseline se adaptuje
//! na dlouhotrvající anomálii): hodnoty klíčů s alarmem v daném cyklu se nezapisují.
//! Ohraničení: strop klíčů a hran s vyřazením nejdéle neaktualizovaných.
//! Perzistence: tabulky `flow_history` a `flow_edge` v `engine-state.sqlite`,
//! zapisují se jen změněné sloty.
//!
//! Volba autora: 7 dní, maximum za hodinu, „opakuje se“ = aspoň 2 dny ve stejné hodině
//! (±1 h) s hodnotou ≥ 50 % současné. Přínos se měří A/B (H-A1), není z literatury.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Datelike, Timelike, Utc};
use rusqlite::{Connection, params};

use crate::error::{BakulaError, Result};

pub const SLOTS: usize = 168;
const MAX_KEYS: usize = 60_000;
const MAX_EDGES_PER_NODE: usize = 32;
const MAX_NODES: usize = 20_000;
/// Dny, po kterých slot zastará.
const HORIZON_DAYS: i64 = 7;

fn db_error(error: rusqlite::Error) -> BakulaError {
    BakulaError::Processing(format!("flow_history SQLite chyba: {error}"))
}

/// Metrika uložená v historii.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Metric {
    /// Počet toků na službu (cíl) za hodinu.
    ServiceFlows,
    /// Počet selhaných spojení na službu.
    ServiceFailures,
    /// Počet toků ze zdroje.
    SourceFlows,
    /// Distinktní cíle zdroje na správcovských portech.
    SourceFanout,
    /// Distinktní cíle pokusů bez odpovědi ze zdroje.
    SourceAttempts,
}

impl Metric {
    fn tag(self) -> &'static str {
        match self {
            Metric::ServiceFlows => "flows",
            Metric::ServiceFailures => "fail",
            Metric::SourceFlows => "sflows",
            Metric::SourceFanout => "fanout",
            Metric::SourceAttempts => "attempts",
        }
    }
}

pub fn key(entity: &str, metric: Metric) -> String {
    format!("{entity}#{}", metric.tag())
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Slot {
    value: f32,
    day: i64,
}

#[derive(Debug, Clone)]
struct Series {
    slots: Vec<Slot>,
    last_day: i64,
    dirty: HashSet<u8>,
}

impl Series {
    fn new() -> Self {
        Self {
            slots: vec![Slot::default(); SLOTS],
            last_day: 0,
            dirty: HashSet::new(),
        }
    }
}

/// Odpověď L0 na otázku „stalo se to už dřív?“.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Recurrence {
    /// Stejná hodnota (≥ 50 % současné) byla ve stejné hodině v `days` různých dnech.
    Seen { days: u32 },
    /// Historie je dost dlouhá (`history_days`), ale tak vysoká hodnota v ní není.
    New { history_days: u32 },
    /// Málo historie: nelze rozhodnout (není to důkaz ani pro, ani proti).
    Insufficient { history_days: u32 },
}

/// Historie toků: souhrny po hodinách týdne a komunikační hrany.
#[derive(Debug, Default)]
pub struct FlowHistory {
    series: HashMap<String, Series>,
    edges: HashMap<String, Vec<(String, i64)>>,
    dirty_edges: HashSet<String>,
    deleted: Vec<String>,
}

fn day_of(at: DateTime<Utc>) -> i64 {
    at.timestamp().div_euclid(86_400)
}

fn slot_of(at: DateTime<Utc>) -> usize {
    at.weekday().num_days_from_monday() as usize * 24 + at.hour() as usize
}

pub fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS flow_history (
            key TEXT NOT NULL,
            slot INTEGER NOT NULL,
            value REAL NOT NULL,
            day INTEGER NOT NULL,
            PRIMARY KEY (key, slot)
        );
        CREATE TABLE IF NOT EXISTS flow_edge (
            node TEXT PRIMARY KEY,
            peers TEXT NOT NULL
        );",
    )
    .map_err(db_error)
}

impl FlowHistory {
    pub fn len(&self) -> usize {
        self.series.len()
    }

    pub fn is_empty(&self) -> bool {
        self.series.is_empty()
    }

    /// Zapíše hodnotu metriky klíče v čase `at` (maximum za hodinu).
    pub fn record(&mut self, key: &str, at: DateTime<Utc>, value: f64) {
        if !value.is_finite() || value < 0.0 {
            return;
        }
        if !self.series.contains_key(key) && self.series.len() >= MAX_KEYS {
            self.evict(MAX_KEYS / 10);
        }
        let day = day_of(at);
        let slot = slot_of(at);
        let series = self
            .series
            .entry(key.to_string())
            .or_insert_with(Series::new);
        let cell = &mut series.slots[slot];
        let value = value as f32;
        if cell.day != day {
            *cell = Slot { value, day };
            series.dirty.insert(slot as u8);
        } else if value > cell.value {
            cell.value = value;
            series.dirty.insert(slot as u8);
        }
        series.last_day = series.last_day.max(day);
    }

    fn evict(&mut self, count: usize) {
        let mut by_age: Vec<(i64, String)> = self
            .series
            .iter()
            .map(|(k, s)| (s.last_day, k.clone()))
            .collect();
        by_age.sort();
        for (_, key) in by_age.into_iter().take(count.max(1)) {
            self.series.remove(&key);
            self.deleted.push(key);
        }
    }

    /// Stalo se to už dřív? Hodnoty ve stejné hodině dne (±1 h) v předchozích dnech
    /// (bez dneška), nejvýš 7 dní zpět.
    pub fn recurrence(&self, key: &str, at: DateTime<Utc>, value: f64) -> Recurrence {
        let Some(series) = self.series.get(key) else {
            return Recurrence::Insufficient { history_days: 0 };
        };
        let today = day_of(at);
        let hour = at.hour() as i64;
        let mut history_days: HashSet<i64> = HashSet::new();
        let mut seen_days: HashSet<i64> = HashSet::new();
        for (index, cell) in series.slots.iter().enumerate() {
            if cell.day == 0 || cell.day >= today || today - cell.day > HORIZON_DAYS {
                continue;
            }
            history_days.insert(cell.day);
            let slot_hour = (index % 24) as i64;
            let near = (slot_hour - hour)
                .rem_euclid(24)
                .min((hour - slot_hour).rem_euclid(24))
                <= 1;
            if near && f64::from(cell.value) >= 0.5 * value {
                seen_days.insert(cell.day);
            }
        }
        let history = history_days.len() as u32;
        if seen_days.len() >= 2 {
            Recurrence::Seen {
                days: seen_days.len() as u32,
            }
        } else if history >= 3 {
            Recurrence::New {
                history_days: history,
            }
        } else {
            Recurrence::Insufficient {
                history_days: history,
            }
        }
    }

    /// Zapamatuje komunikační hranu (oba směry, ohraničeně).
    pub fn record_edge(&mut self, a: &str, b: &str, at: DateTime<Utc>) {
        if a == b {
            return;
        }
        let day = day_of(at);
        for (from, to) in [(a, b), (b, a)] {
            if !self.edges.contains_key(from) && self.edges.len() >= MAX_NODES {
                continue;
            }
            let peers = self.edges.entry(from.to_string()).or_default();
            match peers.iter_mut().find(|(peer, _)| peer == to) {
                Some(slot) => {
                    if slot.1 != day {
                        slot.1 = day;
                        self.dirty_edges.insert(from.to_string());
                    }
                }
                None => {
                    if peers.len() >= MAX_EDGES_PER_NODE {
                        peers.sort_by_key(|(_, d)| std::cmp::Reverse(*d));
                        peers.truncate(MAX_EDGES_PER_NODE - 1);
                    }
                    peers.push((to.to_string(), day));
                    self.dirty_edges.insert(from.to_string());
                }
            }
        }
    }

    /// Sousedé uzlu podle komunikačních hran (nejčerstvější první, deterministicky).
    pub fn neighbors(&self, node: &str, at: DateTime<Utc>) -> Vec<String> {
        let today = day_of(at);
        let mut out: Vec<(i64, String)> = self
            .edges
            .get(node)
            .map(|peers| {
                peers
                    .iter()
                    .filter(|(_, day)| today - *day <= HORIZON_DAYS)
                    .map(|(peer, day)| (*day, peer.clone()))
                    .collect()
            })
            .unwrap_or_default();
        out.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        out.into_iter().map(|(_, peer)| peer).collect()
    }

    pub fn load(conn: &Connection) -> Result<Self> {
        migrate(conn)?;
        let mut history = Self::default();
        let mut stmt = conn
            .prepare("SELECT key, slot, value, day FROM flow_history")
            .map_err(db_error)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, f64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(db_error)?;
        for row in rows {
            let (key, slot, value, day) = row.map_err(db_error)?;
            if !(0..SLOTS as i64).contains(&slot) {
                continue; // poskozeny radek: preskocit
            }
            let series = history.series.entry(key).or_insert_with(Series::new);
            series.slots[slot as usize] = Slot {
                value: value as f32,
                day,
            };
            series.last_day = series.last_day.max(day);
        }
        let mut stmt = conn
            .prepare("SELECT node, peers FROM flow_edge")
            .map_err(db_error)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(db_error)?;
        for row in rows {
            let (node, peers) = row.map_err(db_error)?;
            let peers: Vec<(String, i64)> = serde_json::from_str(&peers).unwrap_or_default();
            history.edges.insert(node, peers);
        }
        Ok(history)
    }

    /// Zapíše změněné sloty, hrany a smazané klíče v jedné transakci.
    pub fn flush(&mut self, conn: &mut Connection) -> Result<()> {
        migrate(conn)?;
        let tx = conn.transaction().map_err(db_error)?;
        {
            let mut upsert = tx
                .prepare_cached(
                    "INSERT INTO flow_history (key, slot, value, day) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(key, slot) DO UPDATE SET value = excluded.value, day = excluded.day",
                )
                .map_err(db_error)?;
            for (key, series) in self.series.iter_mut() {
                for slot in series.dirty.drain() {
                    let cell = series.slots[slot as usize];
                    upsert
                        .execute(params![key, slot as i64, f64::from(cell.value), cell.day])
                        .map_err(db_error)?;
                }
            }
            let mut delete = tx
                .prepare_cached("DELETE FROM flow_history WHERE key = ?1")
                .map_err(db_error)?;
            for key in self.deleted.drain(..) {
                delete.execute(params![key]).map_err(db_error)?;
            }
            let mut edge = tx
                .prepare_cached(
                    "INSERT INTO flow_edge (node, peers) VALUES (?1, ?2)
                     ON CONFLICT(node) DO UPDATE SET peers = excluded.peers",
                )
                .map_err(db_error)?;
            for node in self.dirty_edges.drain() {
                if let Some(peers) = self.edges.get(&node) {
                    let text = serde_json::to_string(peers).unwrap_or_else(|_| "[]".into());
                    edge.execute(params![node, text]).map_err(db_error)?;
                }
            }
        }
        tx.commit().map_err(db_error)
    }
}

/// Souhrn jednoho okna toků pro zápis do historie (vstup `FlowHistory::ingest`).
#[derive(Debug, Default)]
pub struct WindowSummary {
    pub values: HashMap<String, f64>,
    pub edges: HashSet<(String, String)>,
}

impl WindowSummary {
    pub fn add(&mut self, key: String, value: f64) {
        *self.values.entry(key).or_default() += value;
    }

    pub fn max(&mut self, key: String, value: f64) {
        let entry = self.values.entry(key).or_default();
        *entry = entry.max(value);
    }
}

impl FlowHistory {
    /// Zapíše souhrn okna; klíče s alarmem v tomto okně (`frozen`) se nezapisují.
    pub fn ingest(&mut self, summary: &WindowSummary, frozen: &HashSet<String>, at: DateTime<Utc>) {
        let mut keys: Vec<(&String, &f64)> = summary.values.iter().collect();
        keys.sort_by(|a, b| a.0.cmp(b.0));
        for (key, value) in keys {
            let entity = key.rsplit_once('#').map_or(key.as_str(), |(e, _)| e);
            if frozen.contains(entity) {
                continue;
            }
            self.record(key, at, *value);
        }
        let mut edges: Vec<&(String, String)> = summary.edges.iter().collect();
        edges.sort();
        for (a, b) in edges {
            self.record_edge(a, b, at);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(day: i64, hour: i64) -> DateTime<Utc> {
        // 2026-01-05 je pondeli
        Utc.timestamp_opt(1_767_571_200 + day * 86_400 + hour * 3600, 0)
            .unwrap()
    }

    #[test]
    fn recurrence_needs_two_days_at_same_hour_and_history_for_new() {
        let mut h = FlowHistory::default();
        let k = key("10.0.0.5/tcp/80", Metric::ServiceFlows);
        assert_eq!(
            h.recurrence(&k, at(0, 9), 100.0),
            Recurrence::Insufficient { history_days: 0 }
        );
        for day in 0..4 {
            h.record(&k, at(day, 9), 120.0);
            h.record(&k, at(day, 3), 5.0);
        }
        // pondělní ráno po víkendu: totéž ve stejné hodině předchozích dnů
        assert_eq!(
            h.recurrence(&k, at(4, 9), 150.0),
            Recurrence::Seen { days: 4 }
        );
        // v noci takový objem nikdy nebyl
        assert_eq!(
            h.recurrence(&k, at(4, 2), 150.0),
            Recurrence::New { history_days: 4 }
        );
        // dnešek se nepočítá (žádné sebepotvrzení)
        let fresh = key("10.0.0.6/tcp/80", Metric::ServiceFlows);
        h.record(&fresh, at(4, 9), 150.0);
        assert!(matches!(
            h.recurrence(&fresh, at(4, 9), 150.0),
            Recurrence::Insufficient { .. }
        ));
    }

    #[test]
    fn frozen_keys_are_not_learned_and_state_survives_restart() {
        let mut h = FlowHistory::default();
        let mut summary = WindowSummary::default();
        summary.add(key("10.0.0.5/tcp/22", Metric::ServiceFlows), 900.0);
        summary.add(key("10.0.0.6/tcp/22", Metric::ServiceFlows), 10.0);
        summary
            .edges
            .insert(("10.0.0.9".to_string(), "10.0.0.5".to_string()));
        let frozen: HashSet<String> = ["10.0.0.5/tcp/22".to_string()].into_iter().collect();
        h.ingest(&summary, &frozen, at(0, 9));
        assert_eq!(h.len(), 1, "klic s alarmem se neuci");
        assert_eq!(h.neighbors("10.0.0.5", at(1, 0)), vec!["10.0.0.9"]);

        let mut conn = Connection::open_in_memory().unwrap();
        h.flush(&mut conn).unwrap();
        let back = FlowHistory::load(&conn).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back.neighbors("10.0.0.9", at(1, 0)), vec!["10.0.0.5"]);
    }

    #[test]
    fn history_is_bounded() {
        let mut h = FlowHistory::default();
        for i in 0..(MAX_KEYS + 500) {
            h.record(&format!("k{i}"), at((i / 1000) as i64, 1), 1.0);
        }
        assert!(h.len() <= MAX_KEYS);
        for i in 0..(MAX_EDGES_PER_NODE * 3) {
            h.record_edge("hub", &format!("n{i}"), at(1, 1));
        }
        assert!(h.neighbors("hub", at(1, 1)).len() <= MAX_EDGES_PER_NODE);
    }
}
