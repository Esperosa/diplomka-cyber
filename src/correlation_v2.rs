//! Temporal/graph korelace (Deliverable 3) — žije VEDLE `passive::anomaly`/`correlation.rs`,
//! které zůstávají nezměněné jako ablace A (`src/eval/dataset_replay.rs::AblationVariant::A`).
//!
//! `passive::anomaly::detect_connection_anomalies()` agreguje anomálie podle
//! `(dst_ip, proto, dst_port)` přes CELÝ capture, `time_window_s` se v `correlation.rs`
//! nikdy nepoužívá k filtrování. Tento modul implementuje stejné heuristiky (stejné
//! prahy), ale agregované po TUMBLING oknech `time_window_s` (ablace B), a navíc
//! jednoduché graph-linking spojující anomálie se stejným `src_ip` napříč různými cíli
//! ve stejném okně (ablace C — signalizuje sken/lateral movement: jeden zdroj, víc cílů).
//!
//! Vědomé zjednodušení oproti `passive::anomaly`: induktivní z-score outlier detektor
//! (population stats přes >=4 klíčů) je v této první verzi vynechaný — v okénkovaném
//! provozu na malých scénářích (desítky–stovky flows) mají jednotlivá okna často méně
//! než 4 aktivní klíče, takže by stejně nikdy nevystřelil; dodat, až reálná data ukážou,
//! že je potřeba.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};

use crate::model::{NormalizedEvent, Severity};
use crate::passive::ConnectionObservation;
use crate::passive::thresholds::{HIGH_BPS_THRESHOLD, HIGH_PPS_THRESHOLD};

type ServiceKey = (String, String, u16);
type WindowedKey = (String, String, u16, i64);
type TargetsByWindow = HashMap<(i64, String), HashMap<ServiceKey, DateTime<Utc>>>;

#[derive(Debug, Clone, Default)]
struct WindowedAggregate {
    first_seen: Option<DateTime<Utc>>,
    representative_src_ip: Option<String>,
    /// H2 krok 4 (produkcni-plan.md): potreba pro `community_id` na emitovanych
    /// eventech. Stejne zjednoduseni jako `representative_src_ip` - pokud by okno
    /// agregovalo vice ruznych flows (ruzne src_port), tohle je jen PRVNI pozorovany,
    /// ne presna identifikace "toho jednoho" toku; pro `count>=3` ze STEJNE src_ip na
    /// STEJNY cil (typicky pripad, kdy fuze dava smysl) je to spravna hodnota.
    representative_src_port: Option<u16>,
    count: u32,
    timeout_like: u32,
    overload_votes: u32,
    loss_votes: u32,
    max_pps: f64,
    max_bps: f64,
}

impl WindowedAggregate {
    fn observe(&mut self, connection: &ConnectionObservation) {
        self.count = self.count.saturating_add(1);
        if self
            .first_seen
            .is_none_or(|seen| connection.timestamp < seen)
        {
            self.first_seen = Some(connection.timestamp);
        }
        if self.representative_src_ip.is_none() {
            self.representative_src_ip = connection.src_ip.clone();
            self.representative_src_port = connection.src_port;
        }

        let timeout_like = is_timeout_like(connection);
        if timeout_like {
            self.timeout_like = self.timeout_like.saturating_add(1);
        }
        if connection.missed_bytes.unwrap_or_default() > 2_048 {
            self.loss_votes = self.loss_votes.saturating_add(1);
        }

        let duration_s = connection
            .duration_s
            .filter(|value| *value > 0.001)
            .unwrap_or(0.0);
        if duration_s <= 0.0 {
            if timeout_like {
                self.overload_votes = self.overload_votes.saturating_add(1);
            }
            return;
        }

        let total_pkts = connection
            .total_pkts
            .or_else(|| combine_optional(connection.orig_pkts, connection.resp_pkts))
            .unwrap_or(0);
        let total_bytes = connection
            .total_bytes
            .or_else(|| combine_optional(connection.orig_bytes, connection.resp_bytes))
            .unwrap_or(0);
        let pps = total_pkts as f64 / duration_s;
        let bps = (total_bytes as f64 * 8.0) / duration_s;
        self.max_pps = self.max_pps.max(pps);
        self.max_bps = self.max_bps.max(bps);
        if pps >= HIGH_PPS_THRESHOLD || bps >= HIGH_BPS_THRESHOLD || timeout_like {
            self.overload_votes = self.overload_votes.saturating_add(1);
        }
    }

    fn timeout_ratio(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.timeout_like as f64 / self.count as f64
        }
    }
}

fn is_timeout_like(connection: &ConnectionObservation) -> bool {
    let state = connection
        .conn_state
        .as_deref()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let history = connection
        .history
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(state.as_str(), "S0" | "REJ" | "RSTOS0" | "RSTRH" | "SH")
        || history.contains('t')
        || history.contains('r')
}

fn combine_optional(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.saturating_add(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Okno je ukotvené na čas prvního pozorování v datasetu, ne na libovolný epoch offset -
/// jinak by hranice oken závisely na tom, kdy "náhodou" začíná Unix epocha, ne na datech.
fn window_start_for(timestamp: DateTime<Utc>, anchor: DateTime<Utc>, time_window_s: i64) -> i64 {
    let offset = (timestamp - anchor).num_seconds();
    let window_index = offset.div_euclid(time_window_s.max(1));
    anchor.timestamp() + window_index * time_window_s.max(1)
}

/// Ablace B: stejné heuristiky jako `passive::anomaly`, agregované po tumbling oknech.
pub(crate) fn detect_windowed_anomalies(
    connections: Vec<ConnectionObservation>,
    known_services: &HashSet<ServiceKey>,
    time_window_s: i64,
) -> Vec<NormalizedEvent> {
    let Some(anchor) = connections.iter().map(|c| c.timestamp).min() else {
        return Vec::new();
    };

    let mut aggregates: HashMap<WindowedKey, WindowedAggregate> = HashMap::new();
    let mut unexpected: HashMap<WindowedKey, u32> = HashMap::new();

    for connection in &connections {
        let Some(port) = connection.dst_port else {
            continue;
        };
        let window_start = window_start_for(connection.timestamp, anchor, time_window_s);
        let key: WindowedKey = (
            connection.dst_ip.clone(),
            connection.proto.clone(),
            port,
            window_start,
        );

        if !known_services.contains(&(connection.dst_ip.clone(), connection.proto.clone(), port)) {
            *unexpected.entry(key.clone()).or_insert(0) += 1;
        }

        let aggregate = aggregates.entry(key).or_default();
        aggregate.observe(connection);
    }

    let mut events = windowed_events(&aggregates, &unexpected);
    events.sort_by_key(|event| event.timestamp);
    events
}

/// Ablace D: primy, zmereny dusledek potvrzene fragmentacni hypotezy v
/// `docs/diplomka/eval/cross-dataset-ctu13.md` - fixni `time_window_s` je trade-off
/// (male okno oddeli kratke intenzivni bursty, velke okno zachyti sustained nizko-
/// -objemovy C2 beaconing, ale ne obe najednou). Misto volby JEDNE konstanty se
/// detekce spusti na VICE skalach a vysledky se sjednoti - (dst_ip,proto,port) klic
/// je "predicted positive", pokud ho zachyti ALESPON JEDNA skala. Vedomy trade-off:
/// tohle muze zvysit recall za cenu precision (kazda skala pridava i sve vlastni FP) -
/// zmereno, ne predpokladano, viz `docs/diplomka/eval/ablation-d-multiscale.md`.
pub(crate) fn detect_multiscale_windowed_anomalies(
    connections: Vec<ConnectionObservation>,
    known_services: &HashSet<ServiceKey>,
    window_scales: &[i64],
) -> Vec<NormalizedEvent> {
    let mut all_events = Vec::new();
    for &scale in window_scales {
        all_events.extend(detect_windowed_anomalies(
            connections.clone(),
            known_services,
            scale,
        ));
    }
    all_events.sort_by_key(|event| event.timestamp);
    all_events
}

fn windowed_events(
    aggregates: &HashMap<WindowedKey, WindowedAggregate>,
    unexpected: &HashMap<WindowedKey, u32>,
) -> Vec<NormalizedEvent> {
    let mut events = Vec::new();
    let mut keys: Vec<_> = aggregates.keys().cloned().collect();
    keys.sort();

    for (dst_ip, proto, port, window_start) in keys {
        let key: WindowedKey = (dst_ip.clone(), proto.clone(), port, window_start);
        let Some(aggregate) = aggregates.get(&key) else {
            continue;
        };
        let Some(first_seen) = aggregate.first_seen else {
            continue;
        };

        if let Some(count) = unexpected.get(&key).copied()
            && count >= 3
        {
            events.push(NormalizedEvent {
                event_id: format!("windowed:unexpected:{dst_ip}:{proto}:{port}:{window_start}"),
                timestamp: first_seen,
                src_ip: aggregate.representative_src_ip.clone(),
                src_port: aggregate.representative_src_port,
                dst_ip: dst_ip.clone(),
                proto: proto.clone(),
                dst_port: Some(port),
                event_type: "unexpected_traffic".to_string(),
                severity: Severity::Low,
                source: "correlation_v2".to_string(),
                rule_id: Some("heuristika:unexpected_traffic:windowed".to_string()),
                message: format!(
                    "Okno {window_start}: provoz na portu {port} mimo aktivní inventář ({count}x)."
                ),
                raw_ref: Some("conn.log".to_string()),
                count,
            });
        }

        let timeout_ratio = aggregate.timeout_ratio();
        if aggregate.timeout_like >= 2 && timeout_ratio >= 0.22 {
            events.push(NormalizedEvent {
                event_id: format!("windowed:timeout:{dst_ip}:{proto}:{port}:{window_start}"),
                timestamp: first_seen,
                src_ip: aggregate.representative_src_ip.clone(),
                src_port: aggregate.representative_src_port,
                dst_ip: dst_ip.clone(),
                proto: proto.clone(),
                dst_port: Some(port),
                event_type: "connection_timeout_burst".to_string(),
                severity: if timeout_ratio >= 0.45 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                source: "correlation_v2".to_string(),
                rule_id: Some("heuristika:timeout-burst:windowed".to_string()),
                message: format!(
                    "Okno {window_start}: timeout/retry tlak (ratio {timeout_ratio:.2}, {} z {}).",
                    aggregate.timeout_like, aggregate.count
                ),
                raw_ref: Some("conn.log".to_string()),
                count: aggregate.timeout_like,
            });
        }

        if aggregate.max_pps >= 2_800.0 || aggregate.max_bps >= 40_000_000.0 {
            events.push(NormalizedEvent {
                event_id: format!("windowed:rate:{dst_ip}:{proto}:{port}:{window_start}"),
                timestamp: first_seen,
                src_ip: aggregate.representative_src_ip.clone(),
                src_port: aggregate.representative_src_port,
                dst_ip: dst_ip.clone(),
                proto: proto.clone(),
                dst_port: Some(port),
                event_type: "packet_rate_spike".to_string(),
                severity: if aggregate.max_pps >= 4_800.0 || aggregate.max_bps >= 90_000_000.0 {
                    Severity::High
                } else {
                    Severity::Medium
                },
                source: "correlation_v2".to_string(),
                rule_id: Some("heuristika:packet-rate-spike:windowed".to_string()),
                message: format!("Okno {window_start}: max_pps {:.0}.", aggregate.max_pps),
                raw_ref: Some("conn.log".to_string()),
                count: aggregate.count,
            });
        }

        if aggregate.loss_votes >= 2 {
            events.push(NormalizedEvent {
                event_id: format!("windowed:loss:{dst_ip}:{proto}:{port}:{window_start}"),
                timestamp: first_seen,
                src_ip: aggregate.representative_src_ip.clone(),
                src_port: aggregate.representative_src_port,
                dst_ip: dst_ip.clone(),
                proto: proto.clone(),
                dst_port: Some(port),
                event_type: "packet_loss_signal".to_string(),
                severity: Severity::Medium,
                source: "correlation_v2".to_string(),
                rule_id: Some("heuristika:packet-loss:windowed".to_string()),
                message: format!("Okno {window_start}: loss_votes {}.", aggregate.loss_votes),
                raw_ref: Some("conn.log".to_string()),
                count: aggregate.loss_votes,
            });
        }

        if (aggregate.overload_votes >= 3 && aggregate.count >= 4)
            || (aggregate.max_pps >= 4_500.0 && timeout_ratio >= 0.15)
        {
            events.push(NormalizedEvent {
                event_id: format!("windowed:overload:{dst_ip}:{proto}:{port}:{window_start}"),
                timestamp: first_seen,
                src_ip: aggregate.representative_src_ip.clone(),
                src_port: aggregate.representative_src_port,
                dst_ip,
                proto,
                dst_port: Some(port),
                event_type: "service_overload_risk".to_string(),
                severity: Severity::High,
                source: "correlation_v2".to_string(),
                rule_id: Some("heuristika:overload-risk:windowed".to_string()),
                message: format!(
                    "Okno {window_start}: overload_votes {}.",
                    aggregate.overload_votes
                ),
                raw_ref: Some("conn.log".to_string()),
                count: aggregate.count,
            });
        }
    }

    events
}

/// Ablace C: B + graph-linking. Uvnitř stejného okna spojí anomálie se stejným `src_ip`
/// napříč >=2 různými (dst_ip,proto,port) cíli do jednoho "multi_target_pattern" nálezu
/// (jeden zdroj, víc cílů, krátký čas = typický sken/lateral-movement signál).
///
/// POZOR: na scénářích s legitimním fan-outem (např. periodický NTP na více serverů)
/// tahle heuristika produkuje false positive - viz `docs/diplomka/eval/ablation-b-c-iot23.md`.
/// Nefiltruje se tu podle known-benign vzorů, protože to by vyžadovalo přesně ten typ
/// baseline/allowlist znalosti, kterou tahle ablace teprve má ukázat, že chybí.
pub(crate) fn detect_windowed_anomalies_linked(
    connections: Vec<ConnectionObservation>,
    known_services: &HashSet<ServiceKey>,
    time_window_s: i64,
) -> Vec<NormalizedEvent> {
    let Some(anchor) = connections.iter().map(|c| c.timestamp).min() else {
        return Vec::new();
    };

    let base_events = detect_windowed_anomalies(connections, known_services, time_window_s);

    // Skupina podle (window_start, src_ip) -> množina odlišných (dst_ip,proto,port) cílů.
    let mut by_src_window: TargetsByWindow = HashMap::new();

    for event in &base_events {
        let Some(src_ip) = event.src_ip.clone() else {
            continue;
        };
        let Some(port) = event.dst_port else {
            continue;
        };
        let window_start = window_start_for(event.timestamp, anchor, time_window_s);
        by_src_window
            .entry((window_start, src_ip))
            .or_default()
            .entry((event.dst_ip.clone(), event.proto.clone(), port))
            .or_insert(event.timestamp);
    }

    let mut linked_events = Vec::new();
    let mut keys: Vec<_> = by_src_window.keys().cloned().collect();
    keys.sort();

    for (window_start, src_ip) in keys {
        let Some(targets) = by_src_window.get(&(window_start, src_ip.clone())) else {
            continue;
        };
        if targets.len() < 2 {
            continue;
        }
        let earliest = targets.values().min().copied().unwrap_or_default();
        let mut target_list: Vec<String> = targets
            .keys()
            .map(|(dst_ip, proto, port)| format!("{dst_ip}/{proto}/{port}"))
            .collect();
        target_list.sort();

        linked_events.push(NormalizedEvent {
            event_id: format!("windowed:multi_target:{src_ip}:{window_start}"),
            timestamp: earliest,
            src_ip: Some(src_ip.clone()),
            // Nejde o jediny tok (spojuje vice cilu/portu), takze jeden src_port
            // by byl zavadejici - zadny community_id na tomhle eventu neni spravny.
            src_port: None,
            dst_ip: target_list.first().cloned().unwrap_or_default(),
            proto: "multi".to_string(),
            dst_port: None,
            event_type: "multi_target_pattern".to_string(),
            severity: Severity::Medium,
            source: "correlation_v2".to_string(),
            rule_id: Some("heuristika:multi-target:windowed".to_string()),
            message: format!(
                "Okno {window_start}: {src_ip} vykazuje anomálie proti {} různým cílům ve stejném okně: {}.",
                target_list.len(),
                target_list.join(", ")
            ),
            raw_ref: Some("conn.log".to_string()),
            count: targets.len() as u32,
        });
    }

    let mut combined = base_events;
    combined.extend(linked_events);
    combined.sort_by_key(|event| event.timestamp);
    combined
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn conn(ts: i64, dst_ip: &str, src_ip: &str, port: u16, state: &str) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: Utc.timestamp_opt(ts, 0).unwrap(),
            src_ip: Some(src_ip.to_string()),
            src_port: None,
            dst_ip: dst_ip.to_string(),
            proto: "tcp".to_string(),
            dst_port: Some(port),
            duration_s: Some(0.1),
            orig_bytes: Some(10),
            resp_bytes: Some(10),
            total_bytes: Some(20),
            orig_pkts: Some(1),
            resp_pkts: Some(1),
            total_pkts: Some(2),
            conn_state: Some(state.to_string()),
            history: None,
            missed_bytes: None,
        }
    }

    #[test]
    fn windows_are_anchored_to_first_observation_not_unix_epoch() {
        let anchor = Utc.timestamp_opt(1_000_050, 0).unwrap();
        // offset 90s < okno 100s -> stale prvni okno.
        let same_window = Utc.timestamp_opt(1_000_140, 0).unwrap();
        // offset 150s >= okno 100s -> druhe okno.
        let next_window = Utc.timestamp_opt(1_000_200, 0).unwrap();
        assert_eq!(window_start_for(anchor, anchor, 100), anchor.timestamp());
        assert_eq!(
            window_start_for(same_window, anchor, 100),
            anchor.timestamp()
        );
        assert_eq!(
            window_start_for(next_window, anchor, 100),
            anchor.timestamp() + 100
        );
    }

    #[test]
    fn unexpected_traffic_requires_three_or_more_in_the_same_window() {
        let known = HashSet::new();
        let connections = vec![
            conn(0, "10.0.0.1", "10.0.0.5", 4444, "S0"),
            conn(1, "10.0.0.1", "10.0.0.5", 4444, "S0"),
        ];
        let events = detect_windowed_anomalies(connections, &known, 300);
        assert!(
            events
                .iter()
                .all(|event| event.event_type != "unexpected_traffic"),
            "2 pozorování nemají stačit na unexpected_traffic"
        );

        let connections = vec![
            conn(0, "10.0.0.1", "10.0.0.5", 4444, "S0"),
            conn(1, "10.0.0.1", "10.0.0.5", 4444, "S0"),
            conn(2, "10.0.0.1", "10.0.0.5", 4444, "S0"),
        ];
        let events = detect_windowed_anomalies(connections, &known, 300);
        assert!(
            events
                .iter()
                .any(|event| event.event_type == "unexpected_traffic")
        );
    }

    #[test]
    fn same_signal_split_across_two_windows_does_not_trigger() {
        let known = HashSet::new();
        // 2 v prvním okně (0-299s), 2 v druhém (300-599s) - žádné okno nemá >=3.
        let connections = vec![
            conn(0, "10.0.0.1", "10.0.0.5", 4444, "S0"),
            conn(1, "10.0.0.1", "10.0.0.5", 4444, "S0"),
            conn(300, "10.0.0.1", "10.0.0.5", 4444, "S0"),
            conn(301, "10.0.0.1", "10.0.0.5", 4444, "S0"),
        ];
        let events = detect_windowed_anomalies(connections, &known, 300);
        assert!(
            events
                .iter()
                .all(|event| event.event_type != "unexpected_traffic"),
            "tumbling okno rozdělilo signál - známé omezení, test ho dokumentuje"
        );
    }

    #[test]
    fn multi_target_pattern_links_same_source_across_distinct_destinations() {
        let known = HashSet::new();
        let connections = vec![
            conn(0, "10.0.0.1", "10.0.0.5", 4444, "S0"),
            conn(1, "10.0.0.1", "10.0.0.5", 4444, "S0"),
            conn(2, "10.0.0.1", "10.0.0.5", 4444, "S0"),
            conn(3, "10.0.0.2", "10.0.0.5", 4444, "S0"),
            conn(4, "10.0.0.2", "10.0.0.5", 4444, "S0"),
            conn(5, "10.0.0.2", "10.0.0.5", 4444, "S0"),
        ];
        let events = detect_windowed_anomalies_linked(connections, &known, 300);
        let multi_target = events
            .iter()
            .find(|event| event.event_type == "multi_target_pattern")
            .expect(
                "ocekavam multi_target_pattern pri 2 cilich ze stejneho src_ip ve stejnem okne",
            );
        assert_eq!(multi_target.count, 2);
    }

    #[test]
    fn single_target_does_not_produce_multi_target_pattern() {
        let known = HashSet::new();
        let connections = vec![
            conn(0, "10.0.0.1", "10.0.0.5", 4444, "S0"),
            conn(1, "10.0.0.1", "10.0.0.5", 4444, "S0"),
            conn(2, "10.0.0.1", "10.0.0.5", 4444, "S0"),
        ];
        let events = detect_windowed_anomalies_linked(connections, &known, 300);
        assert!(
            events
                .iter()
                .all(|event| event.event_type != "multi_target_pattern")
        );
    }

    // --- Velkoobjemovy property-based fuzz test (stejny vzor jako
    // `fusion::tests::fuse_same_flow_events_holds_invariants_across_many_random_scenarios`,
    // na zadost uzivatele testovat stovky tisic az miliony nahodnych scenaru paralelne).
    // Nekontroluje presne prahy (ty uz pokryvaji rucne psane testy vyse) - kontroluje
    // STRUKTURALNI invarianty, ktere musi platit bez ohledu na konkretni konstanty:
    // (1) `unexpected_traffic` smi existovat JEN pro klice s >=3 neznamymi pozorovanimi
    //     ve stejnem okne (nezavisle pocitano ze syrovych connections, ne z detektoru),
    //     (2) `multi_target_pattern.count` musi presne odpovidat poctu distinktnich
    //     dst_ip mezi ostatnimi eventy stejneho src_ip ve vystupu, (3) determinismus,
    //     (4) zadny panic na nahodnem vstupu (NaN/overflow hranice).

    use rand::{Rng, SeedableRng, rngs::StdRng};

    const FUZZ_TARGETS: &[(&str, &str, u16, bool)] = &[
        ("10.9.0.1", "tcp", 80, true),
        ("10.9.0.1", "tcp", 443, true),
        ("10.9.0.2", "tcp", 4444, false),
        ("10.9.0.3", "tcp", 31337, false),
        ("10.9.0.4", "udp", 53, false),
    ];
    const FUZZ_SOURCES: &[&str] = &["10.1.0.1", "10.1.0.2", "10.1.0.3"];
    const FUZZ_TIME_WINDOW_S: i64 = 300;
    const FUZZ_ANCHOR: i64 = 1_700_000_000;

    fn fuzz_connection(rng: &mut StdRng) -> ConnectionObservation {
        let (dst_ip, proto, port, _known) = FUZZ_TARGETS[rng.random_range(0..FUZZ_TARGETS.len())];
        let src_ip = FUZZ_SOURCES[rng.random_range(0..FUZZ_SOURCES.len())];
        let ts = FUZZ_ANCHOR + rng.random_range(0..1_800_i64);
        let state = if rng.random_bool(0.3) { "S0" } else { "SF" };
        ConnectionObservation {
            timestamp: Utc.timestamp_opt(ts, 0).unwrap(),
            src_ip: Some(src_ip.to_string()),
            src_port: Some(rng.random_range(1024..65535)),
            dst_ip: dst_ip.to_string(),
            proto: proto.to_string(),
            dst_port: Some(port),
            duration_s: Some(rng.random_range(0.0..5.0)),
            orig_bytes: Some(rng.random_range(0..5000)),
            resp_bytes: Some(rng.random_range(0..5000)),
            total_bytes: Some(rng.random_range(0..10000)),
            orig_pkts: Some(rng.random_range(0..200)),
            resp_pkts: Some(rng.random_range(0..200)),
            total_pkts: Some(rng.random_range(0..400)),
            conn_state: Some(state.to_string()),
            history: None,
            missed_bytes: Some(rng.random_range(0..3000)),
        }
    }

    fn known_services_for_fuzz() -> HashSet<ServiceKey> {
        FUZZ_TARGETS
            .iter()
            .filter(|(_, _, _, known)| *known)
            .map(|(dst_ip, proto, port, _)| (dst_ip.to_string(), proto.to_string(), *port))
            .collect()
    }

    fn check_windowed_scenario(rng: &mut StdRng, scenario_seed: u64) -> Option<String> {
        let connection_count = rng.random_range(0..=20usize);
        let connections: Vec<ConnectionObservation> = (0..connection_count)
            .map(|_| fuzz_connection(rng))
            .collect();
        let known = known_services_for_fuzz();

        // Nezavisly pocet "neznamych" pozorovani per (dst_ip,proto,port,window) -
        // POCITANY ZE SYROVYCH CONNECTIONS, ne z vystupu detektoru.
        let anchor = match connections
            .iter()
            .map(|connection| connection.timestamp)
            .min()
        {
            Some(value) => value,
            None => Utc.timestamp_opt(FUZZ_ANCHOR, 0).unwrap(),
        };
        let mut unexpected_counts: HashMap<WindowedKey, u32> = HashMap::new();
        for connection in &connections {
            let Some(port) = connection.dst_port else {
                continue;
            };
            let service_key = (connection.dst_ip.clone(), connection.proto.clone(), port);
            if !known.contains(&service_key) {
                let window_start =
                    window_start_for(connection.timestamp, anchor, FUZZ_TIME_WINDOW_S);
                let windowed_key: WindowedKey = (
                    connection.dst_ip.clone(),
                    connection.proto.clone(),
                    port,
                    window_start,
                );
                *unexpected_counts.entry(windowed_key).or_insert(0) += 1;
            }
        }

        let events_once =
            detect_windowed_anomalies_linked(connections.clone(), &known, FUZZ_TIME_WINDOW_S);
        let events_twice =
            detect_windowed_anomalies_linked(connections, &known, FUZZ_TIME_WINDOW_S);

        let key_of = |events: &[NormalizedEvent]| -> Vec<(String, String, u32)> {
            events
                .iter()
                .map(|event| {
                    (
                        event.event_id.clone(),
                        event.event_type.clone(),
                        event.count,
                    )
                })
                .collect()
        };
        if key_of(&events_once) != key_of(&events_twice) {
            return Some(format!(
                "scenar {scenario_seed}: detect_windowed_anomalies_linked neni deterministicka na stejnem vstupu"
            ));
        }

        for event in &events_once {
            if event.event_type == "unexpected_traffic" {
                // event_id ma tvar "windowed:unexpected:{dst_ip}:{proto}:{port}:{window_start}".
                let window_start = event
                    .event_id
                    .rsplit(':')
                    .next()
                    .and_then(|value| value.parse::<i64>().ok())
                    .unwrap_or_default();
                let windowed_key: WindowedKey = (
                    event.dst_ip.clone(),
                    event.proto.clone(),
                    event.dst_port.unwrap_or(0),
                    window_start,
                );
                let independent_count = unexpected_counts.get(&windowed_key).copied().unwrap_or(0);
                if independent_count < 3 {
                    return Some(format!(
                        "scenar {scenario_seed}: unexpected_traffic existuje pro klic {windowed_key:?} s jen {independent_count} nezavisle pocitanymi neznamymi pozorovanimi (< 3)"
                    ));
                }
            }

            if event.event_type == "multi_target_pattern" {
                if event.count < 2 {
                    return Some(format!(
                        "scenar {scenario_seed}: multi_target_pattern.count {} < 2",
                        event.count
                    ));
                }
                let Some(src_ip) = &event.src_ip else {
                    return Some(format!(
                        "scenar {scenario_seed}: multi_target_pattern bez src_ip"
                    ));
                };
                let distinct_targets_in_output: HashSet<(String, String, u16)> = events_once
                    .iter()
                    .filter(|other| {
                        other.event_type != "multi_target_pattern"
                            && other.src_ip.as_ref() == Some(src_ip)
                    })
                    .filter_map(|other| {
                        other
                            .dst_port
                            .map(|port| (other.dst_ip.clone(), other.proto.clone(), port))
                    })
                    .collect();
                if (distinct_targets_in_output.len() as u32) < event.count {
                    return Some(format!(
                        "scenar {scenario_seed}: multi_target_pattern.count {} presahuje pocet distinktnich cilu {} pozorovanych pro src_ip {src_ip} ve vystupu",
                        event.count,
                        distinct_targets_in_output.len()
                    ));
                }
            }
        }

        None
    }

    fn run_windowed_fuzz_worker(base_seed: u64, scenario_count: usize) -> Option<String> {
        let mut rng = StdRng::seed_from_u64(base_seed);
        for scenario_index in 0..scenario_count {
            if let Some(violation) =
                check_windowed_scenario(&mut rng, base_seed.wrapping_add(scenario_index as u64))
            {
                return Some(violation);
            }
        }
        None
    }

    /// Stejny env-var ovladany pocet jako u `fusion.rs` fuzz testu - vychozi hodnota
    /// bezi v radu sekund, `BAKULA_FUZZ_SCENARIOS=1000000` pro zamerny stres-beh.
    #[test]
    fn detect_windowed_anomalies_linked_holds_structural_invariants_across_many_random_scenarios() {
        let total_scenarios: usize = std::env::var("BAKULA_FUZZ_SCENARIOS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(200_000);
        let worker_count = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(4);
        let base_seed: u64 = 0x9E37_u64;

        let started = std::time::Instant::now();
        let violation = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..worker_count)
                .map(|worker_index| {
                    let scenarios_for_worker = total_scenarios / worker_count
                        + usize::from(worker_index < total_scenarios % worker_count);
                    let worker_seed = base_seed.wrapping_add((worker_index as u64) * 2_147_483_647);
                    scope.spawn(move || run_windowed_fuzz_worker(worker_seed, scenarios_for_worker))
                })
                .collect();
            handles
                .into_iter()
                .find_map(|handle| handle.join().expect("fuzz worker nesmi panikarit"))
        });
        let elapsed = started.elapsed();
        println!(
            "detect_windowed_anomalies_linked fuzz: {total_scenarios} scenaru na {worker_count} OS vlaknech za {elapsed:.2?}"
        );

        if let Some(message) = violation {
            panic!("{message}");
        }
    }
}
