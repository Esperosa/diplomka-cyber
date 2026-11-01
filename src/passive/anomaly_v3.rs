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
    median_and_mad,
};

type ServiceKey = (String, String, u16);
/// (pocet, prvni cas, zdroje) uspesnych spojeni na neznamy port znameho hostu.
type SuccessTally = (u32, DateTime<Utc>, HashMap<String, u32>);
/// (pocet, prvni cas, porty) uspesnych spojeni na neznamou adresu.
type UnknownHostTally = (u32, DateTime<Utc>, HashMap<(String, u16), u32>);

/// Které části v3 jsou zapnuté (zbytek je legacy logika ablace A).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V3Switches {
    pub rate: bool,
    pub volume: bool,
    pub unexpected: bool,
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
pub(crate) fn detect_v3(
    connections: &[ConnectionObservation],
    known_services: &HashSet<ServiceKey>,
    known_hosts: &HashSet<String>,
    state: &mut DetectorState,
    switches: V3Switches,
    th: &V3Thresholds,
    now: DateTime<Utc>,
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

        if known_services.contains(&key) {
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
    // skupina podobnych sluzeb (proto/port) pro studeny start
    let mut peers: HashMap<(&str, u16), Vec<[f32; FEATURES]>> = HashMap::new();
    for (key, sample) in &samples {
        peers
            .entry((key.1.as_str(), key.2))
            .or_default()
            .push(*sample);
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
        let group = peers.get(&(key.1.as_str(), key.2))?;
        let mut values: Vec<f64> = group
            .iter()
            .filter(|other| *other != sample)
            .map(|other| f64::from(other[feature]))
            .filter(|v| *v >= 0.0)
            .collect();
        if values.len() < th.peer_min {
            return None; // bez historie a bez skupiny: jen sbirat
        }
        let (z, median) = robust(x, &mut values, th.peer_mad_floor)?;
        let ratio = (x - median).exp();
        (z >= th.z && ratio >= th.peer_ratio.max(ratio_min)).then_some(Verdict {
            z,
            ratio,
            median,
            basis: "skupina_sluzeb",
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

    // --- ohraniceni stavu ---
    if cycle.is_multiple_of(48) {
        state
            .services
            .retain(|_, h| cycle.saturating_sub(h.last_cycle) <= th.service_ttl_cycles);
        state
            .scanners
            .retain(|_, s| cycle.saturating_sub(s.last_cycle) <= th.scan_window_cycles);
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
            let out = detect_v3(&flows, &services, &hosts, &mut state, ALL, &th, at(cycle));
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
            );
        }
        let mut flows = busy_service(100, 16);
        for _ in 0..900 {
            let mut f = flow("10.0.0.99", "10.0.0.2", 53, 2, 0.002, "SF", 300);
            f.timestamp = at(16);
            flows.push(f);
        }
        let out = detect_v3(&flows, &services, &hosts, &mut state, ALL, &th, at(16));
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
            let out = detect_v3(&flows, &services, &hosts, &mut state, ALL, &th, at(cycle));
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
        let out = detect_v3(&flows, &services, &hosts, &mut state, ALL, &th, at(10));
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
        let out = detect_v3(&flows, &services, &hosts, &mut state, ALL, &th, at(0));
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
            let out = detect_v3(&flows, &services, &hosts, &mut state, ALL, &th, at(cycle));
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
            detect_v3(&flows, &services, &hosts, &mut state, ALL, &th, at(cycle));
            assert!(state.tracked_services() <= 500);
            assert!(state.tracked_scanners() <= 100);
        }
        let json = serde_json::to_string(&state).unwrap();
        let back: DetectorState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tracked_services(), state.tracked_services());
    }
}
