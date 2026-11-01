//! Detektor v3 (krok 1C): náhrada tří nejhlučnějších pravidel ablace A.
//!
//! Zdroj šumu podle auditu (01-analyza-kodu, A02, A04, A08, A13) a závěru studie
//! (00-zaver §5.a R5, R7-lite, R13; Dodatek A.4 body 4 a 5):
//!
//! - `packet_rate_spike` (A04): legacy bere MAXIMUM `pkts/duration` přes všechny toky
//!   klíče, tedy statistiku extrémů, která roste s počtem toků. Tady se počítá p95
//!   rychlosti jen přes „kvalifikované“ toky (≥ 10 paketů a ≥ 1 s) a agregovaný počet
//!   paketů za okno; obojí se porovná s historií téhož klíče (robustní z-skóre
//!   z mediánu a MAD), při studeném startu se skupinou podobných služeb (stejný
//!   protokol a port v síti). Důkazy: mechanismus z kódu (ověřeno), robustní práh
//!   M26 (nízká jistota); prahy jsou volba autora, ladí se jen na ladicích seedech.
//! - `inductive_volume_anomaly` (A02, A03): legacy srovnává služby mezi sebou v jednom
//!   cyklu a má absolutní pravidlo `count/10` (~24 toků). Tady je baseline klíče s
//!   historií po 3h pásmech dne (okno posledních 8 pozorování pásma, robustní z-skóre
//!   v log prostoru s dolní mezí MAD), minimální počet pozorování a ohraničený vliv
//!   anomálních vzorků (gating, RQ2 Z3 nízká jistota: zmrazení baseline při alarmu).
//!   Bez historie rozhoduje skupina podobných služeb; bez ní se jen sbírá (R7-lite).
//! - `unexpected_traffic` (A08, A09, A13): odděluje úspěšná spojení na neznámý port
//!   známého hostu (`unexpected_traffic` = neznámá otevřená služba) od pokusů S0/REJ,
//!   které se přičtou ZDROJI jako `scan_attempts` (i pomalé skeny přes okno 24 h).
//!   Provoz na adresu, kterou inventář nezná vůbec, se netřídí po tocích, ale jedním
//!   souhrnem na adresu (vstup pro `unmapped`, agregace A13). Inventář dodává volající
//!   (perzistentní s hysterezí, `engine_state::PersistentInventory`).
//!
//! Stav (`DetectorState`) je serializovatelný a ohraničený (strop klíčů a zdrojů, TTL).

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};

use crate::model::{NormalizedEvent, Severity};

use super::ConnectionObservation;
use super::anomaly::{
    ConnectionAggregate, aggregate_pattern_events, combine_optional, inductive_outlier_events,
    is_timeout_like, median_and_mad,
};

/// Správcovské porty pro rozptyl zdroje po hostech (SSH, Telnet, RPC, SMB, RDP, VNC, WinRM).
const ADMIN_PORTS: &[u16] = &[22, 23, 135, 139, 445, 3389, 5900, 5985, 5986];

/// Horní chvost binomického rozdělení P(X >= k | n, p) (přesně pro n <= 2000, jinak
/// normální aproximace se spojitostní korekcí).
pub(crate) fn binomial_tail(n: u32, k: u32, p: f64) -> f64 {
    if k == 0 {
        return 1.0;
    }
    if k > n {
        return 0.0;
    }
    let p = p.clamp(1e-12, 1.0 - 1e-12);
    if n > 2000 {
        let mean = n as f64 * p;
        let sd = (n as f64 * p * (1.0 - p)).sqrt();
        let z = (k as f64 - 0.5 - mean) / sd;
        return 0.5 * libm_erfc(z / std::f64::consts::SQRT_2);
    }
    // log P(X = i) postupně, součet od k (stabilní v log prostoru)
    let ln_p = p.ln();
    let ln_q = (1.0 - p).ln();
    let mut ln_choose = 0.0f64; // ln C(n, 0)
    let mut total = 0.0f64;
    for i in 0..=n {
        if i > 0 {
            ln_choose += ((n - i + 1) as f64).ln() - (i as f64).ln();
        }
        if i >= k {
            total += (ln_choose + i as f64 * ln_p + (n - i) as f64 * ln_q).exp();
        }
    }
    total.min(1.0)
}

/// Doplňková chybová funkce (Abramowitz-Stegun 7.1.26, chyba < 1,5e-7).
fn libm_erfc(x: f64) -> f64 {
    let t = 1.0 / (1.0 + 0.327_591_1 * x.abs());
    let poly = t
        * (0.254_829_592
            + t * (-0.284_496_736
                + t * (1.421_413_741 + t * (-1.453_152_027 + t * 1.061_405_429))));
    let erfc = poly * (-x * x).exp();
    if x >= 0.0 { erfc } else { 2.0 - erfc }
}

type ServiceKey = (String, String, u16);
/// (pocet, prvni cas, zdroje) uspesnych spojeni na neznamy port znameho hostu.
type SuccessTally = (u32, DateTime<Utc>, HashMap<String, u32>);
/// (pocet, prvni cas, porty) uspesnych spojeni na neznamou adresu.
type UnknownHostTally = (u32, DateTime<Utc>, HashMap<(String, u16), u32>);

/// (distinktní cíle, první čas) rozptylu zdroje na správcovských portech.
type FanoutTally = (HashSet<String>, DateTime<Utc>);

/// Které části v3 jsou zapnuté (zbytek je legacy logika ablace A).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3Switches {
    pub rate: bool,
    pub volume: bool,
    pub unexpected: bool,
    /// Krok 2A: obnova recallu (pokusy i na známé služby, timeouty podle rozložení
    /// zdrojů a binomického testu, rozptyl zdroje po hostech, odlehlý zdroj služby).
    pub recall: bool,
}

/// Prahy v3 (volba autora; verze kvůli dohledatelnosti, A05).
#[derive(Debug, Clone, Copy)]
pub struct V3Thresholds {
    /// Robustní z-skóre (jednostranné) pro alarm.
    pub z: f64,
    /// Minimální násobek proti mediánu historie (objem, rychlost).
    pub ratio_volume: f64,
    pub ratio_bytes: f64,
    pub ratio_rate: f64,
    /// Minimální přírůstek nad medián (pojistka u malých čísel, ne detekční pravidlo).
    pub min_excess_flows: f64,
    pub min_excess_bytes: f64,
    pub min_excess_pkts: f64,
    /// Minimální počet pozorování v historii klíče.
    pub n_min: usize,
    /// Okno pozorování na pásmo dne.
    pub window: usize,
    /// Dolní mez MAD v log prostoru (≈ 15 % relativní změny).
    pub mad_floor: f64,
    /// Skupina podobných služeb (studený start).
    pub peer_min: usize,
    pub peer_ratio: f64,
    pub peer_mad_floor: f64,
    /// Kvalifikovaný tok pro rychlost.
    pub qualified_min_pkts: u64,
    pub qualified_min_duration_s: f64,
    pub qualified_min_flows: usize,
    /// Pokusy: distinktní cíle zdroje v okně pro `scan_attempts`.
    pub scan_min_targets: usize,
    pub scan_window_cycles: u64,
    pub unexpected_min_success: u32,
    /// Dominantní zdroj: podíl a minimální počet toků.
    pub dominant_share: f64,
    pub dominant_min: u32,
    pub max_dominant: usize,
    /// Ohraničení stavu.
    pub max_services: usize,
    pub max_scanners: usize,
    pub max_targets_per_scanner: usize,
    pub service_ttl_cycles: u64,
    /// Timeouty (krok 2A, A07): běžná míra selhání spojení a hladina binomického testu.
    pub timeout_p0: f64,
    pub timeout_alpha: f64,
    /// Rozptyl zdroje po hostech (laterální pohyb): minimum distinktních cílů, násobek
    /// historie zdroje a minimum bez historie.
    pub fanout_min: usize,
    pub fanout_ratio: f64,
    pub fanout_cold_min: usize,
    /// Odlehlý zdroj služby (DNS tunel, hádání hesel): minimum zdrojů služby, násobek
    /// mediánu ostatních zdrojů a minimální přírůstek toků.
    pub outlier_min_sources: usize,
    pub outlier_ratio: f64,
    pub outlier_min_excess: f64,
}

impl V3Thresholds {
    /// Verze prahu (zmena prahu = nova verze, dohledatelna v `rule_id` udalosti).
    pub const VERSION: u32 = 1;
}

impl Default for V3Thresholds {
    fn default() -> Self {
        Self {
            z: 6.0,
            ratio_volume: 3.0,
            ratio_bytes: 5.0,
            ratio_rate: 3.0,
            min_excess_flows: 10.0,
            min_excess_bytes: 10.0e6,
            min_excess_pkts: 200.0,
            n_min: 4,
            window: 8,
            mad_floor: 0.15,
            peer_min: 5,
            peer_ratio: 4.0,
            peer_mad_floor: 0.25,
            qualified_min_pkts: 10,
            qualified_min_duration_s: 1.0,
            qualified_min_flows: 5,
            scan_min_targets: 8,
            scan_window_cycles: 48,
            unexpected_min_success: 3,
            dominant_share: 0.2,
            dominant_min: 5,
            max_dominant: 4,
            max_services: 20_000,
            max_scanners: 4_096,
            max_targets_per_scanner: 256,
            service_ttl_cycles: 7 * 48,
            timeout_p0: 0.06,
            timeout_alpha: 1e-3,
            fanout_min: 8,
            fanout_ratio: 4.0,
            fanout_cold_min: 12,
            outlier_min_sources: 6,
            outlier_ratio: 8.0,
            outlier_min_excess: 60.0,
        }
    }
}

const FEATURES: usize = 4;
const F_COUNT: usize = 0;
const F_BYTES: usize = 1;
const F_P95: usize = 2;
const F_PKTS: usize = 3;
const BANDS: usize = 8;
const MISSING: f32 = -1.0;

/// Kruhový buffer posledních pozorování (log1p hodnoty, `MISSING` = nedostupné).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Ring {
    values: Vec<[f32; FEATURES]>,
    head: u16,
}

impl Ring {
    fn push(&mut self, sample: [f32; FEATURES], cap: usize) {
        if self.values.len() < cap {
            self.values.push(sample);
        } else if !self.values.is_empty() {
            let at = self.head as usize % self.values.len();
            self.values[at] = sample;
            self.head = ((at + 1) % self.values.len()) as u16;
        }
    }

    fn feature(&self, feature: usize) -> Vec<f64> {
        self.values
            .iter()
            .map(|v| v[feature])
            .filter(|v| *v >= 0.0)
            .map(f64::from)
            .collect()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct KeyHistory {
    bands: Vec<Ring>,
    all: Ring,
    last_cycle: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SourceAttempts {
    /// (hash cíle, poslední cyklus)
    targets: Vec<(u64, u64)>,
    last_cycle: u64,
}

/// Perzistentní stav detektoru v3 (historie klíčů a pokusy zdrojů).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectorState {
    services: HashMap<String, KeyHistory>,
    scanners: HashMap<String, SourceAttempts>,
    cycle: u64,
    /// Historie počtu distinktních cílů zdroje na správcovských portech (krok 2A).
    #[serde(default)]
    fanout: HashMap<String, (Vec<f32>, u64)>,
}

impl DetectorState {
    pub fn tracked_services(&self) -> usize {
        self.services.len()
    }

    #[cfg(test)]
    pub fn tracked_scanners(&self) -> usize {
        self.scanners.len()
    }
}

/// Dominantní zdroje události (klíč: dst, proto, port, typ události).
pub type SourceMap = HashMap<(String, String, u16, String), Vec<String>>;

pub struct V3Output {
    pub events: Vec<NormalizedEvent>,
    pub sources: SourceMap,
}

#[derive(Default)]
struct CycleFeatures {
    count: u32,
    bytes: u64,
    pkts: u64,
    rates: Vec<f64>,
    sources: HashMap<String, u32>,
}

#[derive(Debug, Clone, Copy)]
struct Verdict {
    z: f64,
    ratio: f64,
    median: f64,
    basis: &'static str,
}

fn key_text(key: &ServiceKey) -> String {
    format!("{}/{}/{}", key.0, key.1, key.2)
}

fn hash_text(value: &str) -> u64 {
    value.bytes().fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
        (hash ^ byte as u64).wrapping_mul(0x100_0000_01b3)
    })
}

fn p95(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.total_cmp(b));
    let index = ((values.len() as f64 - 1.0) * 0.95).round() as usize;
    values[index.min(values.len() - 1)]
}

/// Robustní jednostranné z-skóre `x` (log1p) proti vzorku `history` (log1p).
fn robust(x: f64, history: &mut [f64], floor: f64) -> Option<(f64, f64)> {
    if history.is_empty() {
        return None;
    }
    let (median, mad) = median_and_mad(history);
    let scale = mad.max(floor);
    Some((0.6745 * (x - median) / scale, median))
}

fn is_attempt(connection: &ConnectionObservation) -> bool {
    let state = connection.conn_state.as_deref().unwrap_or_default();
    matches!(state, "S0" | "REJ" | "RSTOS0" | "SH" | "RSTRH")
        && connection.resp_bytes.unwrap_or(0) == 0
}

fn is_success(connection: &ConnectionObservation) -> bool {
    !is_attempt(connection) && connection.resp_bytes.unwrap_or(0) > 0
}

fn format_sources(sources: &[(String, u32)], total: u32) -> String {
    if sources.is_empty() {
        return "zdroje: rozptylene".to_string();
    }
    let parts: Vec<String> = sources
        .iter()
        .map(|(ip, n)| format!("{ip} ({:.0} %)", *n as f64 * 100.0 / total.max(1) as f64))
        .collect();
    format!("zdroje: {}", parts.join(", "))
}

#[allow(clippy::too_many_arguments)]
fn event(
    key: &ServiceKey,
    event_type: &str,
    severity: Severity,
    rule: &str,
    message: String,
    timestamp: DateTime<Utc>,
    count: u32,
    representative: Option<String>,
) -> NormalizedEvent {
    NormalizedEvent {
        event_id: format!("anomaly-v3:{event_type}:{}", key_text(key)),
        timestamp,
        src_ip: representative,
        src_port: None,
        dst_ip: key.0.clone(),
        proto: key.1.clone(),
        dst_port: Some(key.2),
        event_type: event_type.to_string(),
        severity,
        source: "zeek".to_string(),
        rule_id: Some(format!("heuristika-v3:{rule}@v{}", V3Thresholds::VERSION)),
        message,
        raw_ref: Some("conn.log".to_string()),
        count,
    }
}

/// Detekce v3 nad toky jednoho okna. `known_services`/`known_hosts` = (perzistentní)
/// inventář. Mění `state` (učení historie, pokusy zdrojů).
#[allow(clippy::too_many_arguments)]
pub(crate) fn detect_v3(
    connections: &[ConnectionObservation],
    known_services: &HashSet<ServiceKey>,
    known_hosts: &HashSet<String>,
    state: &mut DetectorState,
    switches: V3Switches,
    th: &V3Thresholds,
    now: DateTime<Utc>,
    peer_groups: &HashMap<String, String>,
) -> V3Output {
    state.cycle += 1;
    let cycle = state.cycle;
    let band = (now.hour() as usize / 3).min(BANDS - 1);

    let mut aggregates: HashMap<ServiceKey, ConnectionAggregate> = HashMap::new();
    let mut features: HashMap<ServiceKey, CycleFeatures> = HashMap::new();
    let mut legacy_unexpected: HashMap<ServiceKey, (u32, DateTime<Utc>)> = HashMap::new();
    let mut success_unknown_port: HashMap<ServiceKey, SuccessTally> = HashMap::new();
    let mut unknown_host: HashMap<String, UnknownHostTally> = HashMap::new();
    let mut attempts_by_source: HashMap<String, (Vec<ServiceKey>, DateTime<Utc>)> = HashMap::new();
    // krok 2A: zdroje selhání po klíči a distinktní cíle zdroje na správcovských portech
    let mut fail_sources: HashMap<ServiceKey, HashMap<String, u32>> = HashMap::new();
    let mut fanout: HashMap<String, (HashSet<String>, DateTime<Utc>)> = HashMap::new();

    for connection in connections {
        let Some(port) = connection.dst_port else {
            continue;
        };
        let key = (connection.dst_ip.clone(), connection.proto.clone(), port);
        aggregates
            .entry(key.clone())
            .or_insert_with(|| {
                ConnectionAggregate::new(connection.timestamp, connection.src_ip.clone())
            })
            .observe(connection);
        let item = features.entry(key.clone()).or_default();
        item.count += 1;
        let pkts = connection
            .total_pkts
            .or_else(|| combine_optional(connection.orig_pkts, connection.resp_pkts))
            .unwrap_or(0);
        item.pkts += pkts;
        item.bytes += connection
            .total_bytes
            .or_else(|| combine_optional(connection.orig_bytes, connection.resp_bytes))
            .unwrap_or(0);
        let duration = connection.duration_s.unwrap_or(0.0);
        if pkts >= th.qualified_min_pkts && duration >= th.qualified_min_duration_s {
            item.rates.push(pkts as f64 / duration);
        }
        if let Some(src) = &connection.src_ip {
            if let Some(n) = item.sources.get_mut(src) {
                *n += 1;
            } else if item.sources.len() < 4096 {
                item.sources.insert(src.clone(), 1);
            }
        }

        let known = known_services.contains(&key);
        if switches.recall
            && let Some(src) = &connection.src_ip
        {
            if is_timeout_like(connection) {
                let entry = fail_sources.entry(key.clone()).or_default();
                if entry.len() < 256 || entry.contains_key(src) {
                    *entry.entry(src.clone()).or_default() += 1;
                }
            }
            if ADMIN_PORTS.contains(&port)
                && known_hosts.contains(src)
                && src != &connection.dst_ip
                && (is_attempt(connection) || is_success(connection))
            {
                let entry = fanout
                    .entry(src.clone())
                    .or_insert_with(|| (HashSet::new(), connection.timestamp));
                entry.1 = entry.1.min(connection.timestamp);
                if entry.0.len() < 4096 {
                    entry.0.insert(connection.dst_ip.clone());
                }
            }
            // pokusy i na ZNÁMOU službu: horizontální sken otevřeného portu
            if switches.unexpected && known && is_attempt(connection) {
                let entry = attempts_by_source
                    .entry(src.clone())
                    .or_insert_with(|| (Vec::new(), connection.timestamp));
                entry.1 = entry.1.min(connection.timestamp);
                if entry.0.len() < 4096 {
                    entry.0.push(key.clone());
                }
            }
        }
        if known {
            continue;
        }
        if !switches.unexpected {
            let entry = legacy_unexpected
                .entry(key)
                .or_insert((0, connection.timestamp));
            entry.0 += 1;
            entry.1 = entry.1.min(connection.timestamp);
            continue;
        }
        if is_attempt(connection) {
            if let Some(src) = &connection.src_ip {
                let entry = attempts_by_source
                    .entry(src.clone())
                    .or_insert_with(|| (Vec::new(), connection.timestamp));
                entry.1 = entry.1.min(connection.timestamp);
                if entry.0.len() < 4096 {
                    entry
                        .0
                        .push((connection.dst_ip.clone(), connection.proto.clone(), port));
                }
            }
            continue;
        }
        if !is_success(connection) {
            continue;
        }
        if known_hosts.contains(&connection.dst_ip) {
            let entry = success_unknown_port.entry(key).or_insert((
                0,
                connection.timestamp,
                HashMap::new(),
            ));
            entry.0 += 1;
            entry.1 = entry.1.min(connection.timestamp);
            if let Some(src) = &connection.src_ip
                && (entry.2.len() < 256 || entry.2.contains_key(src))
            {
                *entry.2.entry(src.clone()).or_default() += 1;
            }
        } else {
            let entry = unknown_host.entry(connection.dst_ip.clone()).or_insert((
                0,
                connection.timestamp,
                HashMap::new(),
            ));
            entry.0 += 1;
            entry.1 = entry.1.min(connection.timestamp);
            if entry.2.len() < 64 {
                *entry.2.entry((connection.proto.clone(), port)).or_default() += 1;
            }
        }
    }

    let mut events: Vec<NormalizedEvent> = Vec::new();
    let mut sources: SourceMap = HashMap::new();

    // legacy vzory (timeout, loss; rate/overload jen bez v3 rate)
    for item in aggregate_pattern_events(&aggregates) {
        let replaced = switches.rate
            && matches!(
                item.event_type.as_str(),
                "packet_rate_spike" | "service_overload_risk"
            );
        if !replaced {
            events.push(item);
        }
    }
    if !switches.volume {
        events.extend(inductive_outlier_events(&aggregates));
    }
    if !switches.unexpected {
        for ((dst_ip, proto, port), (count, timestamp)) in legacy_unexpected {
            if count >= 3 {
                events.push(event(
                    &(dst_ip, proto, port),
                    "unexpected_traffic",
                    Severity::Low,
                    "unexpected_traffic",
                    format!(
                        "Pozorovan provoz na port {port}, ktery neni v aktivnim inventari jako otevrena sluzba."
                    ),
                    timestamp,
                    count,
                    None,
                ));
            }
        }
    }

    // --- objem a rychlost proti historii klice / skupine ---
    let mut keys: Vec<&ServiceKey> = features.keys().collect();
    keys.sort();
    let mut samples: HashMap<&ServiceKey, [f32; FEATURES]> = HashMap::new();
    for key in &keys {
        let item = &features[*key];
        let mut rates = item.rates.clone();
        let p95_value = if rates.len() >= th.qualified_min_flows {
            (1.0 + p95(&mut rates)).ln() as f32
        } else {
            MISSING
        };
        samples.insert(
            key,
            [
                (1.0 + item.count as f64).ln() as f32,
                (1.0 + item.bytes as f64).ln() as f32,
                p95_value,
                (1.0 + item.pkts as f64).ln() as f32,
            ],
        );
    }
    // skupina podobnych sluzeb pro studeny start: proto/port, s typem zarizeni (krok 2D)
    // proto/port v ramci peer skupiny cile (stejny typ a podsit), jinak jen proto/port
    let group_of = |ip: &str| -> &str { peer_groups.get(ip).map(String::as_str).unwrap_or("") };
    let mut peers: HashMap<(&str, &str, u16), Vec<[f32; FEATURES]>> = HashMap::new();
    for (key, sample) in &samples {
        peers
            .entry(("", key.1.as_str(), key.2))
            .or_default()
            .push(*sample);
        let group = group_of(&key.0);
        if !group.is_empty() {
            peers
                .entry((group, key.1.as_str(), key.2))
                .or_default()
                .push(*sample);
        }
    }

    let evaluate = |state: &DetectorState,
                    key: &ServiceKey,
                    sample: &[f32; FEATURES],
                    feature: usize,
                    ratio_min: f64|
     -> Option<Verdict> {
        let x = f64::from(sample[feature]);
        if x < 0.0 {
            return None;
        }
        let text = key_text(key);
        if let Some(history) = state.services.get(&text) {
            let band_values = history
                .bands
                .get(band)
                .map(|ring| ring.feature(feature))
                .unwrap_or_default();
            let (mut values, basis) = if band_values.len() >= th.n_min {
                (band_values, "historie_pasma")
            } else {
                (history.all.feature(feature), "historie_klice")
            };
            if values.len() >= th.n_min {
                let (z, median) = robust(x, &mut values, th.mad_floor)?;
                let ratio = (x - median).exp();
                return (z >= th.z && ratio >= ratio_min).then_some(Verdict {
                    z,
                    ratio,
                    median,
                    basis,
                });
            }
        }
        let collect = |group: &str| -> Vec<f64> {
            peers
                .get(&(group, key.1.as_str(), key.2))
                .map(|members| {
                    members
                        .iter()
                        .filter(|other| *other != sample)
                        .map(|other| f64::from(other[feature]))
                        .filter(|v| *v >= 0.0)
                        .collect()
                })
                .unwrap_or_default()
        };
        // nejdriv zarizeni stejneho typu a podsite, pri male skupine vsechny sluzby portu
        let own_group = group_of(&key.0);
        let mut values = if own_group.is_empty() {
            Vec::new()
        } else {
            collect(own_group)
        };
        let mut basis = "skupina_typu_zarizeni";
        if values.len() < th.peer_min {
            values = collect("");
            basis = "skupina_sluzeb";
        }
        if values.len() < th.peer_min {
            return None; // bez historie a bez skupiny: jen sbirat
        }
        let (z, median) = robust(x, &mut values, th.peer_mad_floor)?;
        let ratio = (x - median).exp();
        (z >= th.z && ratio >= th.peer_ratio.max(ratio_min)).then_some(Verdict {
            z,
            ratio,
            median,
            basis,
        })
    };

    let mut flagged: HashSet<ServiceKey> = HashSet::new();
    let mut dominant_by_key: HashMap<ServiceKey, Vec<String>> = HashMap::new();
    for key in &keys {
        let item = &features[*key];
        let sample = samples[*key];
        let mut dominant: Vec<(String, u32)> = item
            .sources
            .iter()
            .filter(|(_, n)| {
                **n >= th.dominant_min && **n as f64 >= th.dominant_share * item.count as f64
            })
            .map(|(ip, n)| (ip.clone(), *n))
            .collect();
        dominant.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        dominant.truncate(th.max_dominant);
        let source_text = format_sources(&dominant, item.count);
        let dominant_ips: Vec<String> = dominant.iter().map(|(ip, _)| ip.clone()).collect();
        if !dominant_ips.is_empty() {
            dominant_by_key.insert((*key).clone(), dominant_ips.clone());
        }
        let representative = dominant_ips.first().cloned();
        let first_seen = aggregates[*key].first_seen;

        if switches.volume {
            let by_count = evaluate(state, key, &sample, F_COUNT, th.ratio_volume)
                .filter(|v| item.count as f64 - (v.median.exp() - 1.0) >= th.min_excess_flows);
            let by_bytes = evaluate(state, key, &sample, F_BYTES, th.ratio_bytes)
                .filter(|v| item.bytes as f64 - (v.median.exp() - 1.0) >= th.min_excess_bytes);
            if let Some((feature, verdict)) = by_count
                .map(|v| ("toky", v))
                .or_else(|| by_bytes.map(|v| ("bajty", v)))
            {
                flagged.insert((*key).clone());
                events.push(event(
                    key,
                    "inductive_volume_anomaly",
                    if verdict.ratio >= 10.0 {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    "volume-baseline",
                    format!(
                        "Objem ({feature}) {:.1}x nad baseline ({}, z {:.1}, toku {}, bajtu {}); {source_text}.",
                        verdict.ratio, verdict.basis, verdict.z, item.count, item.bytes
                    ),
                    first_seen,
                    item.count,
                    representative.clone(),
                ));
                sources.insert(
                    (
                        key.0.clone(),
                        key.1.clone(),
                        key.2,
                        "inductive_volume_anomaly".into(),
                    ),
                    dominant_ips.clone(),
                );
            }
        }
        if switches.rate {
            let by_p95 = evaluate(state, key, &sample, F_P95, th.ratio_rate);
            let by_pkts = evaluate(state, key, &sample, F_PKTS, th.ratio_rate)
                .filter(|v| item.pkts as f64 - (v.median.exp() - 1.0) >= th.min_excess_pkts);
            if let Some((feature, verdict)) = by_p95
                .map(|v| ("p95 pps kvalifikovanych toku", v))
                .or_else(|| by_pkts.map(|v| ("pakety za okno", v)))
            {
                flagged.insert((*key).clone());
                events.push(event(
                    key,
                    "packet_rate_spike",
                    if verdict.ratio >= 10.0 {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    "rate-baseline",
                    format!(
                        "Rychlost ({feature}) {:.1}x nad baseline ({}, z {:.1}, paketu {}); {source_text}.",
                        verdict.ratio, verdict.basis, verdict.z, item.pkts
                    ),
                    first_seen,
                    item.count,
                    representative.clone(),
                ));
                sources.insert(
                    (
                        key.0.clone(),
                        key.1.clone(),
                        key.2,
                        "packet_rate_spike".into(),
                    ),
                    dominant_ips.clone(),
                );
                let aggregate = &aggregates[*key];
                if aggregate.timeout_ratio() >= 0.15 && aggregate.count >= 4 {
                    events.push(event(
                        key,
                        "service_overload_risk",
                        Severity::High,
                        "overload-baseline",
                        format!(
                            "Rychlost nad baseline a timeouty {:.0} % ukazuji na pretizeni; {source_text}.",
                            aggregate.timeout_ratio() * 100.0
                        ),
                        first_seen,
                        item.count,
                        representative.clone(),
                    ));
                }
            }
        }
    }

    // --- uceni historie s ohranicenym vlivem anomalnich vzorku ---
    if switches.volume || switches.rate {
        for key in &keys {
            let mut sample = samples[*key];
            let text = key_text(key);
            if flagged.contains(*key) {
                // gating: alarmovy vzorek se uci jen orezany na median + 3 MAD
                if let Some(history) = state.services.get(&text) {
                    for (feature, value) in sample.iter_mut().enumerate() {
                        let mut values = history.all.feature(feature);
                        if *value >= 0.0 && values.len() >= th.n_min {
                            let (median, mad) = median_and_mad(&mut values);
                            let cap = median + 3.0 * mad.max(th.mad_floor);
                            *value = (*value as f64).min(cap) as f32;
                        }
                    }
                } else {
                    continue; // prvni pozorovani je anomalie: neucit vubec
                }
            }
            let history = state.services.entry(text).or_default();
            if history.bands.len() < BANDS {
                history.bands.resize(BANDS, Ring::default());
            }
            history.bands[band].push(sample, th.window);
            history.all.push(sample, th.window);
            history.last_cycle = cycle;
        }
    }

    // --- neocekavany provoz: uspech na neznamy port, neznamy host, pokusy zdroje ---
    if switches.unexpected {
        let mut success: Vec<_> = success_unknown_port.into_iter().collect();
        success.sort_by(|a, b| a.0.cmp(&b.0));
        for (key, (count, timestamp, srcs)) in success {
            if count < th.unexpected_min_success {
                continue;
            }
            let mut dominant: Vec<(String, u32)> = srcs
                .into_iter()
                .filter(|(_, n)| *n as f64 >= th.dominant_share * count as f64)
                .collect();
            dominant.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            dominant.truncate(th.max_dominant);
            let ips: Vec<String> = dominant.iter().map(|(ip, _)| ip.clone()).collect();
            events.push(event(
                &key,
                "unexpected_traffic",
                Severity::Low,
                "unknown-open-service",
                format!(
                    "Uspesna spojeni ({count}) na port {}, ktery neni v inventari hostu jako otevrena sluzba; {}.",
                    key.2,
                    format_sources(&dominant, count)
                ),
                timestamp,
                count,
                ips.first().cloned(),
            ));
            sources.insert(
                (
                    key.0.clone(),
                    key.1.clone(),
                    key.2,
                    "unexpected_traffic".into(),
                ),
                ips,
            );
        }
        let mut unknown: Vec<_> = unknown_host.into_iter().collect();
        unknown.sort_by(|a, b| a.0.cmp(&b.0));
        for (ip, (count, timestamp, ports)) in unknown {
            if count < th.unexpected_min_success {
                continue;
            }
            let ((proto, port), _) = ports
                .iter()
                .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
                .map(|(k, v)| (k.clone(), *v))
                .unwrap_or((("tcp".to_string(), 0), 0));
            events.push(event(
                &(ip.clone(), proto, port),
                "unexpected_traffic",
                Severity::Low,
                "unknown-host",
                format!(
                    "Uspesna spojeni ({count}, {} portu) na adresu, kterou inventar nezna (nove nebo presunute zarizeni).",
                    ports.len()
                ),
                timestamp,
                count,
                None,
            ));
        }
        // pokusy: pricist zdroji (vcetne pomaleho skenu pres okno)
        let mut by_source: Vec<_> = attempts_by_source.into_iter().collect();
        by_source.sort_by(|a, b| a.0.cmp(&b.0));
        for (src, (targets, first_attempt)) in by_source {
            if !state.scanners.contains_key(&src) && state.scanners.len() >= th.max_scanners {
                evict_oldest_scanners(state, th.max_scanners / 10);
            }
            let record = state.scanners.entry(src.clone()).or_default();
            record.last_cycle = cycle;
            let mut hits: HashMap<(String, String, u16), u32> = HashMap::new();
            for target in &targets {
                *hits.entry(target.clone()).or_default() += 1;
                let hash = hash_text(&format!("{}/{}/{}", target.0, target.1, target.2));
                match record.targets.iter_mut().find(|(h, _)| *h == hash) {
                    Some(slot) => slot.1 = cycle,
                    None => {
                        if record.targets.len() >= th.max_targets_per_scanner {
                            record
                                .targets
                                .sort_by_key(|(_, last)| std::cmp::Reverse(*last));
                            record.targets.truncate(th.max_targets_per_scanner - 1);
                        }
                        record.targets.push((hash, cycle));
                    }
                }
            }
            record
                .targets
                .retain(|(_, last)| cycle.saturating_sub(*last) < th.scan_window_cycles);
            let distinct = record.targets.len();
            if distinct < th.scan_min_targets {
                continue;
            }
            let distinct_hosts: HashSet<&str> = targets.iter().map(|t| t.0.as_str()).collect();
            let top = hits
                .into_iter()
                .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
                .map(|(target, _)| target)
                .expect("aspon jeden pokus");
            events.push(event(
                &top,
                "scan_attempts",
                if distinct >= 50 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                "attempts-by-source",
                format!(
                    "Zdroj {src}: {} pokusu bez odpovedi v tomto okne na {} hostu, {distinct} distinktnich cilu za 24 h (sken nebo pruzkum).",
                    targets.len(),
                    distinct_hosts.len()
                ),
                first_attempt,
                targets.len() as u32,
                Some(src.clone()),
            ));
            sources.insert(
                (top.0.clone(), top.1.clone(), top.2, "scan_attempts".into()),
                vec![src],
            );
        }
    }

    if switches.recall {
        recall_events(
            &mut events,
            &mut sources,
            RecallInputs {
                aggregates: &aggregates,
                features: &features,
                fail_sources: &fail_sources,
                fanout: &fanout,
                flagged: &flagged,
                known_hosts,
            },
            state,
            th,
            cycle,
        );
    }

    // --- ohraniceni stavu ---
    if cycle.is_multiple_of(48) {
        state
            .services
            .retain(|_, h| cycle.saturating_sub(h.last_cycle) <= th.service_ttl_cycles);
        state
            .scanners
            .retain(|_, s| cycle.saturating_sub(s.last_cycle) <= th.scan_window_cycles);
        state
            .fanout
            .retain(|_, (_, last)| cycle.saturating_sub(*last) <= th.service_ttl_cycles);
    }
    if state.services.len() > th.max_services {
        let mut by_age: Vec<(u64, String)> = state
            .services
            .iter()
            .map(|(k, h)| (h.last_cycle, k.clone()))
            .collect();
        by_age.sort();
        let excess = state.services.len() - th.max_services + th.max_services / 10;
        for (_, key) in by_age.into_iter().take(excess) {
            state.services.remove(&key);
        }
    }

    // dominantni zdroje i pro legacy vzory (timeout, loss): pamet podle nich
    // eskaluje a kontext je porovna se zaznamem
    for item in &events {
        let Some(port) = item.dst_port else { continue };
        let key = (item.dst_ip.clone(), item.proto.clone(), port);
        if let Some(ips) = dominant_by_key.get(&key) {
            sources
                .entry((key.0, key.1, key.2, item.event_type.clone()))
                .or_insert_with(|| ips.clone());
        }
    }
    events.sort_by(|l, r| {
        l.timestamp
            .cmp(&r.timestamp)
            .then(l.event_id.cmp(&r.event_id))
    });
    V3Output { events, sources }
}

struct RecallInputs<'a> {
    aggregates: &'a HashMap<ServiceKey, ConnectionAggregate>,
    features: &'a HashMap<ServiceKey, CycleFeatures>,
    fail_sources: &'a HashMap<ServiceKey, HashMap<String, u32>>,
    fanout: &'a HashMap<String, (HashSet<String>, DateTime<Utc>)>,
    flagged: &'a HashSet<ServiceKey>,
    known_hosts: &'a HashSet<String>,
}

/// Krok 2A (obnova recallu a A07). Upraví legacy timeouty a přidá zdrojové události:
///
/// - `connection_timeout_burst` jen tehdy, když podíl selhání významně převyšuje běžnou
///   míru (binomický test, `timeout_p0`, `timeout_alpha`): 2 selhání z 8 toků je
///   náhoda, ne tlak. Podle rozložení zdrojů: jeden dominantní zdroj (≥ 50 % selhání)
///   = tlak zdroje (sken, hádání hesel), zůstává; mnoho převážně vnitřních klientů
///   bez skoku objemu = `service_unreachable` (služba nedostupná, provozní stav; RQ3
///   Z2: selhání na přechodně nedostupnou službu není důkaz skenu); mnoho vnějších
///   zdrojů = zůstává timeout (DoS).
/// - `multi_target_pattern`: zdroj mluví na správcovských portech s mnoha hosty proti
///   své historii (laterální pohyb jako rozptyl first-seen hran, RQ4 Z12a, nízká jistota).
/// - `source_volume_outlier`: jeden zdroj služby má mnohonásobek toků ostatních zdrojů
///   (DNS tunel, hádání hesel); peer srovnání zdrojů téhož cíle, RQ2 Z4 (nízká jistota).
fn recall_events(
    events: &mut Vec<NormalizedEvent>,
    sources: &mut SourceMap,
    input: RecallInputs<'_>,
    state: &mut DetectorState,
    th: &V3Thresholds,
    cycle: u64,
) {
    // 1. timeouty
    let mut kept = Vec::with_capacity(events.len());
    for mut item in events.drain(..) {
        if item.event_type != "connection_timeout_burst" {
            kept.push(item);
            continue;
        }
        let Some(port) = item.dst_port else {
            kept.push(item);
            continue;
        };
        let key = (item.dst_ip.clone(), item.proto.clone(), port);
        let Some(aggregate) = input.aggregates.get(&key) else {
            kept.push(item);
            continue;
        };
        let p = binomial_tail(aggregate.count, aggregate.timeout_like, th.timeout_p0);
        if p > th.timeout_alpha {
            continue; // selhani v mezich bezne miry
        }
        let failures = input.fail_sources.get(&key);
        let total: u32 = failures.map(|m| m.values().sum()).unwrap_or(0);
        let mut ranked: Vec<(&String, &u32)> =
            failures.map(|m| m.iter().collect()).unwrap_or_default();
        ranked.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let top_share = ranked
            .first()
            .map(|(_, n)| **n as f64 / total.max(1) as f64)
            .unwrap_or(0.0);
        let distinct = ranked.len();
        if let Some((top, n)) = ranked.first()
            && top_share >= 0.5
            && **n >= th.dominant_min
        {
            item.message = format!(
                "{} Tlak jednoho zdroje: {top} ({:.0} % selhani, p = {p:.1e}).",
                item.message,
                top_share * 100.0
            );
            item.src_ip = Some((*top).clone());
            sources.insert(
                (key.0.clone(), key.1.clone(), key.2, item.event_type.clone()),
                vec![(*top).clone()],
            );
        } else if distinct >= 3
            && !input.flagged.contains(&key)
            && ranked
                .iter()
                .filter(|(src, _)| input.known_hosts.contains(*src))
                .count()
                * 2
                >= distinct
        {
            // rozptylena selhani VNITRNICH klientu bez skoku objemu = vypadek sluzby;
            // rozptylena selhani mnoha vnejsich zdroju zustavaji timeouty (DoS)
            item.event_type = "service_unreachable".to_string();
            item.event_id = item
                .event_id
                .replacen("anomaly:timeout", "anomaly-v3:unreachable", 1);
            item.severity = Severity::Low;
            item.rule_id = Some(format!(
                "heuristika-v3:service-unreachable@v{}",
                V3Thresholds::VERSION
            ));
            item.message = format!(
                "Sluzba neodpovida {distinct} zdrojum ({} z {} spojeni selhalo, p = {p:.1e}), bez skoku objemu: nejspis vypadek, ne utok.",
                aggregate.timeout_like, aggregate.count
            );
        }
        kept.push(item);
    }
    *events = kept;

    // 2. rozptyl zdroje po hostech na spravcovskych portech
    let mut fan: Vec<(&String, &FanoutTally)> = input.fanout.iter().collect();
    fan.sort_by(|a, b| a.0.cmp(b.0));
    for (src, (targets, first)) in fan {
        let distinct = targets.len();
        let record = state.fanout.entry(src.clone()).or_default();
        let mut history: Vec<f64> = record.0.iter().map(|v| f64::from(*v)).collect();
        let flagged = if history.len() >= 4 {
            let (median, _) = median_and_mad(&mut history);
            distinct >= th.fanout_min
                && distinct as f64 >= th.fanout_ratio * median.max(1.0)
                && distinct as f64 - median >= th.fanout_min as f64
        } else {
            distinct >= th.fanout_cold_min
        };
        // alarmovy vzorek se do historie neuci (zmrazeni baseline pri alarmu, RQ2 Z3)
        if !flagged {
            if record.0.len() >= 16 {
                record.0.remove(0);
            }
            record.0.push(distinct as f32);
        }
        record.1 = cycle;
        if !flagged {
            continue;
        }
        events.push(NormalizedEvent {
            event_id: format!("anomaly-v3:multi_target_pattern:{src}"),
            timestamp: *first,
            src_ip: Some(src.clone()),
            src_port: None,
            dst_ip: src.clone(),
            proto: "tcp".to_string(),
            dst_port: None,
            event_type: "multi_target_pattern".to_string(),
            severity: if distinct >= 25 {
                Severity::High
            } else {
                Severity::Medium
            },
            source: "zeek".to_string(),
            rule_id: Some(format!(
                "heuristika-v3:admin-fanout@v{}",
                V3Thresholds::VERSION
            )),
            message: format!(
                "Zdroj {src} se v tomto okne pripojil na spravcovske porty {distinct} ruznych hostu (historie zdroje to nezna): mozny lateralni pohyb."
            ),
            raw_ref: Some("conn.log".to_string()),
            count: distinct as u32,
        });
    }
    if state.fanout.len() > th.max_scanners {
        let mut by_age: Vec<(u64, String)> = state
            .fanout
            .iter()
            .map(|(k, (_, last))| (*last, k.clone()))
            .collect();
        by_age.sort();
        let excess = state.fanout.len() - th.max_scanners + th.max_scanners / 10;
        for (_, key) in by_age.into_iter().take(excess) {
            state.fanout.remove(&key);
        }
    }

    // 3. odlehly zdroj sluzby (peer srovnani zdroju tehoz cile)
    let mut keys: Vec<&ServiceKey> = input.features.keys().collect();
    keys.sort();
    for key in keys {
        let item = &input.features[key];
        if item.sources.len() < th.outlier_min_sources {
            continue;
        }
        let mut counts: Vec<(&String, u32)> = item.sources.iter().map(|(s, n)| (s, *n)).collect();
        counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        let (top, top_n) = counts[0];
        let mut others: Vec<f64> = counts[1..].iter().map(|(_, n)| f64::from(*n)).collect();
        let (median, _) = median_and_mad(&mut others);
        let ratio = f64::from(top_n) / median.max(1.0);
        if ratio < th.outlier_ratio || f64::from(top_n) - median < th.outlier_min_excess {
            continue;
        }
        events.push(NormalizedEvent {
            event_id: format!("anomaly-v3:source_volume_outlier:{}:{top}", key_text(key)),
            timestamp: input.aggregates[key].first_seen,
            src_ip: Some(top.clone()),
            src_port: None,
            dst_ip: key.0.clone(),
            proto: key.1.clone(),
            dst_port: Some(key.2),
            event_type: "source_volume_outlier".to_string(),
            severity: if ratio >= 30.0 {
                Severity::High
            } else {
                Severity::Medium
            },
            source: "zeek".to_string(),
            rule_id: Some(format!(
                "heuristika-v3:source-outlier@v{}",
                V3Thresholds::VERSION
            )),
            message: format!(
                "Zdroj {top} poslal na {} {top_n} toku, {ratio:.0}x vic nez median ostatnich {} zdroju ({median:.0}).",
                key_text(key),
                counts.len() - 1
            ),
            raw_ref: Some("conn.log".to_string()),
            count: top_n,
        });
        sources.insert(
            (
                key.0.clone(),
                key.1.clone(),
                key.2,
                "source_volume_outlier".into(),
            ),
            vec![top.clone()],
        );
    }
}

fn evict_oldest_scanners(state: &mut DetectorState, count: usize) {
    let mut by_age: Vec<(u64, String)> = state
        .scanners
        .iter()
        .map(|(k, s)| (s.last_cycle, k.clone()))
        .collect();
    by_age.sort();
    for (_, key) in by_age.into_iter().take(count.max(1)) {
        state.scanners.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn flow(
        src: &str,
        dst: &str,
        port: u16,
        pkts: u64,
        dur: f64,
        state: &str,
        resp: u64,
    ) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: Utc.timestamp_opt(1_767_571_200, 0).unwrap(),
            src_ip: Some(src.to_string()),
            src_port: Some(40000),
            dst_ip: dst.to_string(),
            proto: "tcp".to_string(),
            dst_port: Some(port),
            duration_s: Some(dur),
            orig_bytes: Some(500),
            resp_bytes: Some(resp),
            total_bytes: Some(500 + resp),
            orig_pkts: Some(pkts / 2),
            resp_pkts: Some(pkts - pkts / 2),
            total_pkts: Some(pkts),
            conn_state: Some(state.to_string()),
            history: None,
            missed_bytes: Some(0),
        }
    }

    fn at(cycle: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_767_571_200 + cycle * 1800, 0).unwrap()
    }

    const ALL: V3Switches = V3Switches {
        rate: true,
        volume: true,
        unexpected: true,
        recall: false,
    };
    const RECALL: V3Switches = V3Switches {
        recall: true,
        ..ALL
    };

    fn busy_service(n: usize, cycle: i64) -> Vec<ConnectionObservation> {
        (0..n)
            .map(|i| {
                let mut f = flow(
                    &format!("10.0.0.{}", 10 + i % 40),
                    "10.0.0.2",
                    53,
                    4,
                    0.0012,
                    "SF",
                    300,
                );
                f.timestamp = at(cycle);
                f
            })
            .collect()
    }

    fn known() -> (HashSet<ServiceKey>, HashSet<String>) {
        (
            [("10.0.0.2".to_string(), "tcp".to_string(), 53u16)]
                .into_iter()
                .collect(),
            ["10.0.0.2".to_string()].into_iter().collect(),
        )
    }

    /// Regrese A02/A04: vytizena, ale STABILNI sluzba (velky pocet kratkych toku s
    /// absurdni max pps) nesmi byt anomalie po naucene historii; legacy ji hlasi vzdy.
    #[test]
    fn busy_stable_service_is_not_flagged_while_legacy_is() {
        let (services, hosts) = known();
        let mut state = DetectorState::default();
        let th = V3Thresholds::default();
        for cycle in 0..48 {
            let flows = busy_service(300 + (cycle as usize % 5) * 7, cycle);
            let out = detect_v3(
                &flows,
                &services,
                &hosts,
                &mut state,
                ALL,
                &th,
                at(cycle),
                &HashMap::new(),
            );
            assert!(
                !out.events.iter().any(|e| matches!(
                    e.event_type.as_str(),
                    "inductive_volume_anomaly" | "packet_rate_spike"
                )),
                "cyklus {cycle}: {:?}",
                out.events.iter().map(|e| &e.message).collect::<Vec<_>>()
            );
        }
        // legacy (ablace A): stejna sluzba mezi tremi tichymi je outlier v kazdem cyklu
        let mut mixed = busy_service(300, 0);
        for port in [80u16, 443, 8080] {
            for _ in 0..3 {
                mixed.push(flow("10.0.0.50", "10.0.0.3", port, 12, 0.5, "SF", 900));
            }
        }
        let legacy = super::super::anomaly::detect_connection_anomalies(mixed, &services);
        assert!(legacy.iter().any(|e| e.event_type == "packet_rate_spike"));
        assert!(
            legacy
                .iter()
                .any(|e| e.event_type == "inductive_volume_anomaly")
        );
    }

    #[test]
    fn volume_jump_against_own_history_is_flagged_with_dominant_source() {
        let (services, hosts) = known();
        let mut state = DetectorState::default();
        let th = V3Thresholds::default();
        for cycle in 0..16 {
            detect_v3(
                &busy_service(100, cycle),
                &services,
                &hosts,
                &mut state,
                ALL,
                &th,
                at(cycle),
                &HashMap::new(),
            );
        }
        let mut flows = busy_service(100, 16);
        for _ in 0..900 {
            let mut f = flow("10.0.0.99", "10.0.0.2", 53, 2, 0.002, "SF", 300);
            f.timestamp = at(16);
            flows.push(f);
        }
        let out = detect_v3(
            &flows,
            &services,
            &hosts,
            &mut state,
            ALL,
            &th,
            at(16),
            &HashMap::new(),
        );
        let hit = out
            .events
            .iter()
            .find(|e| e.event_type == "inductive_volume_anomaly")
            .expect("skok objemu");
        assert!(hit.message.contains("10.0.0.99"), "{}", hit.message);
        assert_eq!(
            out.sources[&(
                "10.0.0.2".to_string(),
                "tcp".to_string(),
                53,
                "inductive_volume_anomaly".to_string()
            )],
            vec!["10.0.0.99".to_string()]
        );
    }

    #[test]
    fn cold_start_without_history_or_peers_only_collects() {
        let (services, hosts) = known();
        let mut state = DetectorState::default();
        let out = detect_v3(
            &busy_service(5000, 0),
            &services,
            &hosts,
            &mut state,
            ALL,
            &V3Thresholds::default(),
            at(0),
            &HashMap::new(),
        );
        assert!(
            out.events
                .iter()
                .all(|e| e.event_type != "inductive_volume_anomaly")
        );
        assert_eq!(state.tracked_services(), 1);
    }

    #[test]
    fn rate_uses_p95_of_qualified_flows_not_the_max() {
        let (services, hosts) = known();
        let mut state = DetectorState::default();
        let th = V3Thresholds::default();
        // jeden kratky tok s absurdni rychlosti mezi normalnimi: zadny alarm
        for cycle in 0..10 {
            let mut flows: Vec<_> = (0..20)
                .map(|_| flow("10.0.0.5", "10.0.0.2", 53, 20, 2.0, "SF", 900))
                .collect();
            flows.push(flow("10.0.0.6", "10.0.0.2", 53, 3, 0.0011, "SF", 100));
            let out = detect_v3(
                &flows,
                &services,
                &hosts,
                &mut state,
                ALL,
                &th,
                at(cycle),
                &HashMap::new(),
            );
            assert!(
                out.events
                    .iter()
                    .all(|e| e.event_type != "packet_rate_spike")
            );
        }
        // skutecna zmena rychlosti vetsiny toku: alarm
        let flows: Vec<_> = (0..20)
            .map(|_| flow("10.0.0.5", "10.0.0.2", 53, 4000, 2.0, "SF", 900))
            .collect();
        let out = detect_v3(
            &flows,
            &services,
            &hosts,
            &mut state,
            ALL,
            &th,
            at(10),
            &HashMap::new(),
        );
        assert!(
            out.events
                .iter()
                .any(|e| e.event_type == "packet_rate_spike")
        );
    }

    #[test]
    fn attempts_are_attributed_to_source_and_success_to_unknown_service() {
        let (services, hosts) = known();
        let mut state = DetectorState::default();
        let th = V3Thresholds::default();
        let mut flows: Vec<_> = (1..=30u16)
            .map(|p| flow("203.0.113.7", "10.0.0.2", 1000 + p, 1, 0.0, "S0", 0))
            .collect();
        for _ in 0..4 {
            flows.push(flow("10.0.0.8", "10.0.0.2", 8443, 20, 1.0, "SF", 5000));
        }
        // pokusy na neznamou adresu nejsou unexpected_traffic po tocich
        flows.push(flow("10.0.0.8", "10.0.0.77", 22, 1, 0.0, "S0", 0));
        let out = detect_v3(
            &flows,
            &services,
            &hosts,
            &mut state,
            ALL,
            &th,
            at(0),
            &HashMap::new(),
        );
        let unexpected: Vec<_> = out
            .events
            .iter()
            .filter(|e| e.event_type == "unexpected_traffic")
            .collect();
        assert_eq!(unexpected.len(), 1);
        assert_eq!(unexpected[0].dst_port, Some(8443));
        let scan = out
            .events
            .iter()
            .find(|e| e.event_type == "scan_attempts")
            .expect("sken");
        assert!(scan.message.contains("203.0.113.7"));
        assert_eq!(scan.dst_ip, "10.0.0.2");
    }

    #[test]
    fn slow_scan_accumulates_distinct_targets_across_cycles() {
        let (services, hosts) = known();
        let mut state = DetectorState::default();
        let th = V3Thresholds::default();
        let mut seen = false;
        for cycle in 0..12 {
            let flows = vec![flow(
                "10.9.9.9",
                &format!("10.0.1.{}", cycle + 1),
                2000 + cycle as u16,
                1,
                0.0,
                "S0",
                0,
            )];
            let out = detect_v3(
                &flows,
                &services,
                &hosts,
                &mut state,
                ALL,
                &th,
                at(cycle),
                &HashMap::new(),
            );
            seen |= out.events.iter().any(|e| e.event_type == "scan_attempts");
        }
        assert!(seen, "pomaly sken se musi nascitat");
    }

    #[test]
    fn state_is_bounded_under_unique_key_flood_and_serializable() {
        let (services, hosts) = known();
        let mut state = DetectorState::default();
        let th = V3Thresholds {
            max_services: 500,
            max_scanners: 100,
            ..V3Thresholds::default()
        };
        for cycle in 0..5 {
            let flows: Vec<_> = (0..3000u32)
                .map(|i| {
                    flow(
                        &format!("198.51.{}.{}", i / 250, i % 250),
                        &format!("10.0.{}.{}", i / 250, i % 250),
                        (i % 60000) as u16 + 1,
                        1,
                        0.0,
                        "S0",
                        0,
                    )
                })
                .collect();
            detect_v3(
                &flows,
                &services,
                &hosts,
                &mut state,
                ALL,
                &th,
                at(cycle),
                &HashMap::new(),
            );
            assert!(state.tracked_services() <= 500);
            assert!(state.tracked_scanners() <= 100);
        }
        let json = serde_json::to_string(&state).unwrap();
        let back: DetectorState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tracked_services(), state.tracked_services());
    }

    #[test]
    fn binomial_tail_matches_reference_values() {
        // P(X >= 2 | 8, 0.06) = 1 - 0.94^8 - 8*0.06*0.94^7 ≈ 0.0791
        assert!((binomial_tail(8, 2, 0.06) - 0.0791).abs() < 1e-3);
        assert!(binomial_tail(40, 40, 0.06) < 1e-40);
        assert_eq!(binomial_tail(10, 0, 0.3), 1.0);
        assert_eq!(binomial_tail(10, 11, 0.3), 0.0);
        // velke n: normalni aproximace v rozumne mezi
        let big = binomial_tail(10_000, 700, 0.06);
        assert!(big > 0.0 && big < 1e-3, "{big}");
    }

    fn many_clients(
        dst: &str,
        port: u16,
        clients: usize,
        per: usize,
        state: &str,
    ) -> Vec<ConnectionObservation> {
        let mut out = Vec::new();
        for c in 0..clients {
            for _ in 0..per {
                let resp = if state == "SF" { 400 } else { 0 };
                out.push(flow(
                    &format!("10.0.1.{}", 10 + c),
                    dst,
                    port,
                    4,
                    0.2,
                    state,
                    resp,
                ));
            }
        }
        out
    }

    fn known_with(
        services: &[(&str, u16)],
        hosts: &[&str],
    ) -> (HashSet<ServiceKey>, HashSet<String>) {
        (
            services
                .iter()
                .map(|(ip, port)| (ip.to_string(), "tcp".to_string(), *port))
                .collect(),
            hosts.iter().map(|h| h.to_string()).collect(),
        )
    }

    fn run(
        flows: &[ConnectionObservation],
        known: &(HashSet<ServiceKey>, HashSet<String>),
        state: &mut DetectorState,
        switches: V3Switches,
        cycle: i64,
        groups: &HashMap<String, String>,
    ) -> V3Output {
        detect_v3(
            flows,
            &known.0,
            &known.1,
            state,
            switches,
            &V3Thresholds::default(),
            at(cycle),
            groups,
        )
    }

    /// A07: timeouty od mnoha klientu bez skoku objemu = sluzba nedostupna (vypadek);
    /// timeouty jednoho zdroje = tlak zdroje; nahodna 2 selhani z 8 = nic.
    #[test]
    fn timeouts_are_split_by_source_distribution_and_tested_against_base_rate() {
        let mut known = known_with(&[("10.0.0.5", 80)], &["10.0.0.5"]);
        known.1.extend((10..40).map(|i| format!("10.0.1.{i}")));
        let none = HashMap::new();
        let down = many_clients("10.0.0.5", 80, 12, 3, "S0");
        let out = run(
            &down,
            &known,
            &mut DetectorState::default(),
            RECALL,
            0,
            &none,
        );
        assert!(
            out.events
                .iter()
                .any(|e| e.event_type == "service_unreachable")
        );
        // mnoho VNEJSICH zdroju bez odpovedi (DoS) zustava timeout, ne vypadek
        let dos: Vec<_> = (0..40)
            .map(|i| flow(&format!("198.51.100.{i}"), "10.0.0.5", 80, 1, 0.0, "S0", 0))
            .collect();
        let dos_out = run(
            &dos,
            &known,
            &mut DetectorState::default(),
            RECALL,
            0,
            &none,
        );
        assert!(
            dos_out
                .events
                .iter()
                .any(|e| e.event_type == "connection_timeout_burst")
        );
        assert!(
            !dos_out
                .events
                .iter()
                .any(|e| e.event_type == "service_unreachable")
        );
        assert!(
            !out.events
                .iter()
                .any(|e| e.event_type == "connection_timeout_burst")
        );

        let mut pressure = many_clients("10.0.0.5", 80, 6, 4, "SF");
        for _ in 0..30 {
            pressure.push(flow("203.0.113.7", "10.0.0.5", 80, 2, 0.0, "S0", 0));
        }
        let out = run(
            &pressure,
            &known,
            &mut DetectorState::default(),
            RECALL,
            0,
            &none,
        );
        let burst = out
            .events
            .iter()
            .find(|e| e.event_type == "connection_timeout_burst")
            .expect("tlak zdroje");
        assert_eq!(burst.src_ip.as_deref(), Some("203.0.113.7"));

        let mut chance = many_clients("10.0.0.5", 80, 3, 2, "SF");
        chance.push(flow("10.0.1.40", "10.0.0.5", 80, 2, 0.0, "S0", 0));
        chance.push(flow("10.0.1.41", "10.0.0.5", 80, 2, 0.0, "S0", 0));
        let legacy = run(
            &chance,
            &known,
            &mut DetectorState::default(),
            ALL,
            0,
            &none,
        );
        assert!(
            legacy
                .events
                .iter()
                .any(|e| e.event_type == "connection_timeout_burst")
        );
        let out = run(
            &chance,
            &known,
            &mut DetectorState::default(),
            RECALL,
            0,
            &none,
        );
        assert!(
            !out.events.iter().any(|e| matches!(
                e.event_type.as_str(),
                "connection_timeout_burst" | "service_unreachable"
            )),
            "2 selhani z 8 jsou v mezich bezne miry"
        );
    }

    /// Lateralni pohyb: zdroj s historii jednoho cile osloví na SMB 15 hostu.
    #[test]
    fn admin_fanout_against_source_history_is_flagged() {
        let mut hosts: HashSet<String> = (2..40).map(|i| format!("10.0.0.{i}")).collect();
        hosts.insert("10.0.1.9".to_string());
        let known = (HashSet::new(), hosts);
        let none = HashMap::new();
        let mut state = DetectorState::default();
        for cycle in 0..6 {
            let flows = vec![flow("10.0.1.9", "10.0.0.2", 445, 6, 1.0, "SF", 900)];
            let out = run(&flows, &known, &mut state, RECALL, cycle, &none);
            assert!(
                !out.events
                    .iter()
                    .any(|e| e.event_type == "multi_target_pattern")
            );
        }
        let flows: Vec<_> = (2..17)
            .map(|i| flow("10.0.1.9", &format!("10.0.0.{i}"), 445, 6, 1.0, "SF", 900))
            .collect();
        let out = run(&flows, &known, &mut state, RECALL, 7, &none);
        let event = out
            .events
            .iter()
            .find(|e| e.event_type == "multi_target_pattern")
            .expect("rozptyl po hostech");
        assert_eq!(event.dst_ip, "10.0.1.9");
        assert_eq!(event.count, 15);
        // vypnuty recall = beze zmeny kroku 1
        let off = run(&flows, &known, &mut DetectorState::default(), ALL, 7, &none);
        assert!(
            !off.events
                .iter()
                .any(|e| e.event_type == "multi_target_pattern")
        );
    }

    /// DNS tunel: jeden klient ma mnohonasobek toku ostatnich klientu tehoz serveru.
    #[test]
    fn source_volume_outlier_flags_single_heavy_client() {
        let known = known_with(&[("10.0.0.2", 53)], &["10.0.0.2"]);
        let none = HashMap::new();
        let mut state = DetectorState::default();
        let mut flows = many_clients("10.0.0.2", 53, 10, 6, "SF");
        let normal = run(&flows, &known, &mut state, RECALL, 0, &none);
        assert!(
            !normal
                .events
                .iter()
                .any(|e| e.event_type == "source_volume_outlier")
        );
        for _ in 0..200 {
            flows.push(flow("10.0.1.99", "10.0.0.2", 53, 2, 0.1, "SF", 500));
        }
        let out = run(&flows, &known, &mut state, RECALL, 1, &none);
        let event = out
            .events
            .iter()
            .find(|e| e.event_type == "source_volume_outlier")
            .expect("odlehly zdroj");
        assert_eq!(event.src_ip.as_deref(), Some("10.0.1.99"));
        let key = (
            "10.0.0.2".to_string(),
            "tcp".to_string(),
            53,
            "source_volume_outlier".to_string(),
        );
        assert_eq!(out.sources[&key], vec!["10.0.1.99".to_string()]);
    }

    /// Horizontalni sken OTEVRENEHO portu: pokusy na znamou sluzbu se pricitaji zdroji.
    #[test]
    fn attempts_on_known_services_count_for_scan_attempts() {
        let open: Vec<(String, u16)> = (2..14).map(|i| (format!("10.0.0.{i}"), 22)).collect();
        let services: HashSet<ServiceKey> = open
            .iter()
            .map(|(ip, port)| (ip.clone(), "tcp".to_string(), *port))
            .collect();
        let hosts: HashSet<String> = open.iter().map(|(ip, _)| ip.clone()).collect();
        let known = (services, hosts);
        let none = HashMap::new();
        let flows: Vec<_> = open
            .iter()
            .map(|(ip, port)| flow("198.51.100.4", ip, *port, 1, 0.0, "S0", 0))
            .collect();
        let step1 = run(&flows, &known, &mut DetectorState::default(), ALL, 0, &none);
        assert!(!step1.events.iter().any(|e| e.event_type == "scan_attempts"));
        let out = run(
            &flows,
            &known,
            &mut DetectorState::default(),
            RECALL,
            0,
            &none,
        );
        assert!(out.events.iter().any(|e| e.event_type == "scan_attempts"));
    }

    /// Krok 2D: studeny start srovnava sluzbu se stejnym typem zarizeni a podsiti.
    #[test]
    fn peer_group_of_device_type_is_preferred_over_port_group() {
        let mut flows = Vec::new();
        let mut groups = HashMap::new();
        let mut services = HashSet::new();
        let mut hosts = HashSet::new();
        // 6 tiskaren (malo provozu) a 6 web serveru (hodne provozu), vse port 80
        for i in 0..6u32 {
            let printer = format!("10.0.2.{}", 10 + i);
            let web = format!("10.0.3.{}", 10 + i);
            groups.insert(printer.clone(), "printer@10.0.2".to_string());
            groups.insert(web.clone(), "web@10.0.3".to_string());
            for ip in [&printer, &web] {
                services.insert((ip.clone(), "tcp".to_string(), 80u16));
                hosts.insert(ip.clone());
            }
            for _ in 0..3 {
                flows.push(flow("10.0.1.5", &printer, 80, 4, 0.2, "SF", 300));
            }
            for _ in 0..400 {
                flows.push(flow("10.0.1.6", &web, 80, 4, 0.2, "SF", 300));
            }
        }
        // sedma tiskarna s vetsim objemem: proti tiskarnam anomalie, proti portu 80 ne
        let odd = "10.0.2.99".to_string();
        groups.insert(odd.clone(), "printer@10.0.2".to_string());
        services.insert((odd.clone(), "tcp".to_string(), 80));
        hosts.insert(odd.clone());
        for _ in 0..120 {
            flows.push(flow("10.0.1.7", &odd, 80, 4, 0.2, "SF", 300));
        }
        let known = (services, hosts);
        let flagged = |out: &V3Output| {
            out.events
                .iter()
                .any(|e| e.event_type == "inductive_volume_anomaly" && e.dst_ip == odd)
        };
        let with_groups = run(
            &flows,
            &known,
            &mut DetectorState::default(),
            RECALL,
            0,
            &groups,
        );
        assert!(flagged(&with_groups), "proti tiskarnam je to anomalie");
        let without = run(
            &flows,
            &known,
            &mut DetectorState::default(),
            RECALL,
            0,
            &HashMap::new(),
        );
        assert!(!flagged(&without), "proti vsem sluzbam portu 80 ne");
    }
}
