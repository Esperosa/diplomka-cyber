use std::{collections::HashSet, net::IpAddr, path::PathBuf};

use chrono::{DateTime, Utc};
use ipnet::IpNet;

use crate::{
    error::{BakulaError, Result},
    model::{HostReport, NormalizedEvent},
};

mod anomaly;
pub(crate) mod anomaly_v3;
mod community_id;
pub(crate) mod detector;
pub(crate) mod egress;
mod suricata;
pub(crate) mod thresholds;
mod zeek;

// Re-exporty pro src/eval (dataset replay baseline) - beze zmeny viditelnosti celych modulu.
// Faze 2: produkcni cesta (`load_and_normalize`) i `eval::dataset_replay::run_ablation` uz
// jdou pres `ConnectionDetector`/`LegacyAnomalyDetector` nize - tenhle re-export zustava
// jen kvuli `src/lab.rs`'s `#[cfg(test)]` modulu, ktery `cargo check` (bez --tests) nevidi.
#[allow(unused_imports)]
pub(crate) use anomaly::detect_connection_anomalies;
pub(crate) use anomaly::score_connection_keys;
#[allow(unused_imports)]
pub(crate) use anomaly::score_source_hosts;
pub(crate) use detector::{ConnectionDetector, LegacyAnomalyDetector, V3StatefulDetector};
pub(crate) use suricata::{parse_suricata_str, parse_suricata_str_mode};
pub(crate) use zeek::parse_zeek_log;
pub use zeek::{ZeekParseResult, parse_zeek_dir, parse_zeek_dir_mode};

#[derive(Debug, Clone)]
pub struct PassiveSources {
    pub suricata_eve: Option<PathBuf>,
    pub zeek_dir: Option<PathBuf>,
}

pub(crate) fn load_and_normalize(
    sources: &PassiveSources,
    scope: &[IpNet],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    hosts: &[HostReport],
    detector: &dyn ConnectionDetector,
) -> Result<Vec<NormalizedEvent>> {
    let mut events = Vec::new();
    if let Some(path) = &sources.suricata_eve {
        events.extend(suricata::parse_suricata(path, scope, start, end)?);
    }

    let mut connections = Vec::new();
    if let Some(path) = &sources.zeek_dir {
        let parsed = zeek::parse_zeek_dir(path, scope, start, end)?;
        events.extend(parsed.events);
        connections.extend(parsed.connections);
    }

    let known_services = hosts
        .iter()
        .flat_map(|host| {
            host.services
                .iter()
                .filter(|service| service.port_state == "open")
                .map(move |service| (host.ip.clone(), service.proto.clone(), service.port))
        })
        .collect::<HashSet<_>>();

    events.extend(detector.detect(connections, &known_services));

    // H2 krok 4 (produkcni-plan.md): eventy od ruznych senzoru (suricata/zeek) se stejnym
    // community_id jsou stejny fyzicky tok, ne dve nezavisla potvrzeni - viz `fusion.rs`.
    let mut events = crate::fusion::fuse_same_flow_events(events);

    events.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));
    Ok(events)
}

/// Toky okna pro behaviorální vrstvu (krok 3; jen v3 s viditelností ven nebo grafem).
#[derive(Debug, Default)]
pub(crate) struct BehaviorFlows {
    pub(crate) outbound: Vec<ConnectionObservation>,
    pub(crate) internal: Vec<ConnectionObservation>,
    /// IDS alerty se zdrojem uvnitř a cílem venku.
    pub(crate) outbound_alerts: Vec<NormalizedEvent>,
    pub(crate) outbound_seen: u64,
    pub(crate) outbound_dropped: u64,
    pub(crate) sample_level: u32,
}

/// Jako `load_and_normalize`; s `egress = Some(policy)` parsery drží i toky a alerty se
/// zdrojem v rozsahu (krok 3A) a vrátí je odděleně pro behaviorální vrstvu. Detektor
/// a korelace dostávají pořád jen záznamy s cílem v rozsahu, takže jejich vstup je
/// stejný jako v legacy cestě. `egress = None` = přesně `load_and_normalize`.
pub(crate) fn load_and_normalize_with_behavior(
    sources: &PassiveSources,
    scope: &[IpNet],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    hosts: &[HostReport],
    detector: &dyn ConnectionDetector,
    egress: Option<&egress::EgressPolicy>,
) -> Result<(Vec<NormalizedEvent>, Option<BehaviorFlows>)> {
    let Some(policy) = egress else {
        return load_and_normalize(sources, scope, start, end, hosts, detector).map(|e| (e, None));
    };
    let mut flows = BehaviorFlows::default();
    let mut events = Vec::new();
    if let Some(path) = &sources.suricata_eve {
        for event in
            suricata::parse_suricata_mode(path, scope, start, end, egress::ScopeMode::SrcOrDst)?
        {
            match egress::direction(scope, event.src_ip.as_deref(), &event.dst_ip) {
                egress::FlowDirection::Outbound => flows.outbound_alerts.push(event),
                egress::FlowDirection::External => {}
                _ => events.push(event),
            }
        }
    }
    let mut connections = Vec::new();
    if let Some(path) = &sources.zeek_dir {
        let parsed =
            zeek::parse_zeek_dir_mode(path, scope, start, end, egress::ScopeMode::SrcOrDst)?;
        events.extend(
            parsed
                .events
                .into_iter()
                .filter(|e| in_scope(scope, &e.dst_ip)),
        );
        let split = egress::split_flows(parsed.connections, scope, policy);
        connections = split.to_scope;
        flows.outbound = split.outbound;
        flows.internal = split.internal;
        flows.outbound_seen = split.outbound_seen;
        flows.outbound_dropped = split.outbound_dropped;
        flows.sample_level = split.sample_level;
    }
    let known_services = hosts
        .iter()
        .flat_map(|host| {
            host.services
                .iter()
                .filter(|service| service.port_state == "open")
                .map(move |service| (host.ip.clone(), service.proto.clone(), service.port))
        })
        .collect::<HashSet<_>>();
    events.extend(detector.detect(connections, &known_services));
    let mut events = crate::fusion::fuse_same_flow_events(events);
    events.sort_by_key(|event| event.timestamp);
    Ok((events, Some(flows)))
}

fn in_scope(scope: &[IpNet], value: &str) -> bool {
    value
        .parse::<IpAddr>()
        .ok()
        .map(|ip| scope.iter().any(|net| net.contains(&ip)))
        .unwrap_or(false)
}

fn event_in_window(timestamp: DateTime<Utc>, start: DateTime<Utc>, end: DateTime<Utc>) -> bool {
    timestamp >= start && timestamp <= end
}

pub(crate) fn parse_zeek_ts(value: &str) -> Result<DateTime<Utc>> {
    let seconds = value
        .trim()
        .parse::<f64>()
        .map_err(|error| BakulaError::Processing(format!("Neplatny Zeek timestamp: {error}")))?;
    let secs = seconds.floor() as i64;
    let nanos = ((seconds - secs as f64) * 1_000_000_000.0).round() as u32;
    DateTime::<Utc>::from_timestamp(secs, nanos)
        .ok_or_else(|| BakulaError::Processing("Neplatny Zeek cas.".to_string()))
}

fn parse_suricata_ts(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|error| BakulaError::Processing(format!("Neplatny Suricata timestamp: {error}")))
}

// pub(crate): naside tez pro src/eval (dataset replay baseline), beze zmeny logiky.
#[derive(Debug, Clone)]
pub(crate) struct ConnectionObservation {
    pub(crate) timestamp: DateTime<Utc>,
    pub(crate) src_ip: Option<String>,
    /// Deliverable 26 (H2 schema wiring) - dřív chybělo (audit finding), ačkoliv
    /// Zeek `conn.log`'s `id.orig_p` i Suricata eve.json `src_port` ho obě nesou.
    /// Potřebný pro `community_id()` níže. Docasne nevyuzivane v produkcnim kodu
    /// mimo testy, dokud nevznikne `src/fusion.rs` (produkcni-plan.md, Faze 1
    /// pokracuje) - proto `#[allow(dead_code)]` na metode community_id nize.
    pub(crate) src_port: Option<u16>,
    pub(crate) dst_ip: String,
    pub(crate) proto: String,
    pub(crate) dst_port: Option<u16>,
    pub(crate) duration_s: Option<f64>,
    pub(crate) orig_bytes: Option<u64>,
    pub(crate) resp_bytes: Option<u64>,
    pub(crate) total_bytes: Option<u64>,
    pub(crate) orig_pkts: Option<u64>,
    pub(crate) resp_pkts: Option<u64>,
    pub(crate) total_pkts: Option<u64>,
    pub(crate) conn_state: Option<String>,
    pub(crate) history: Option<String>,
    pub(crate) missed_bytes: Option<u64>,
}

impl ConnectionObservation {
    /// Deliverable 26 (H2 schema wiring): Community ID POCITANY Z existujicich poli,
    /// ne stored field - zabranuje zastaralosti (kdyby se src_ip/dst_port zmenily
    /// nezavisle na precomputed hodnote by stary join-key tise zustal). `None`, pokud
    /// chybi src_ip/src_port (napr. observation bez identifikovaneho zdroje), nebo
    /// proto neni tcp/udp/sctp - jediny protokoly, co `community_id_v1` umi.
    #[allow(dead_code)]
    pub(crate) fn community_id(&self) -> Option<String> {
        let src_ip: std::net::IpAddr = self.src_ip.as_deref()?.parse().ok()?;
        let dst_ip: std::net::IpAddr = self.dst_ip.parse().ok()?;
        let src_port = self.src_port?;
        let dst_port = self.dst_port?;
        let proto_num = match self.proto.as_str() {
            "tcp" => 6,
            "udp" => 17,
            "sctp" => 132,
            _ => return None,
        };
        community_id::community_id_v1(src_ip, src_port, dst_ip, dst_port, proto_num)
    }
}

/// H2 krok 4 (produkcni-plan.md): stejny vypocet jako `ConnectionObservation::community_id`
/// vyse, ale pro uz-normalizovany `NormalizedEvent` - `fusion::fuse_same_flow_events` bezi
/// PO detekci/normalizaci, ne na syrovych connections, takze potrebuje svou vlastni cestu
/// ke stejnemu join-key. `None` za stejnych podminek jako u `ConnectionObservation` (chybi
/// src_ip/src_port, nebo proto neni tcp/udp/sctp).
pub(crate) fn normalized_event_community_id(event: &NormalizedEvent) -> Option<String> {
    let src_ip: IpAddr = event.src_ip.as_deref()?.parse().ok()?;
    let dst_ip: IpAddr = event.dst_ip.parse().ok()?;
    let src_port = event.src_port?;
    let dst_port = event.dst_port?;
    let proto_num = match event.proto.as_str() {
        "tcp" => 6,
        "udp" => 17,
        "sctp" => 132,
        _ => return None,
    };
    community_id::community_id_v1(src_ip, src_port, dst_ip, dst_port, proto_num)
}

#[cfg(test)]
mod connection_observation_tests {
    use super::*;
    use chrono::TimeZone;

    fn base() -> ConnectionObservation {
        ConnectionObservation {
            timestamp: Utc.timestamp_opt(0, 0).unwrap(),
            src_ip: None,
            src_port: None,
            dst_ip: String::new(),
            proto: "tcp".to_string(),
            dst_port: None,
            duration_s: None,
            orig_bytes: None,
            resp_bytes: None,
            total_bytes: None,
            orig_pkts: None,
            resp_pkts: None,
            total_pkts: None,
            conn_state: None,
            history: None,
            missed_bytes: None,
        }
    }

    /// Deliverable 26 - stejna referencni hodnota jako
    /// `community_id::tests::matches_real_zeek_reference_value_for_captured_tcp_flow`,
    /// ted overena pres cely `ConnectionObservation::community_id()`, ne jen pres
    /// holou funkci - potvrzuje, ze schema wiring (src_ip/src_port/dst_port/proto)
    /// skutecne dava stejny vysledek jako primy volani.
    #[test]
    fn community_id_matches_real_zeek_reference_through_full_observation() {
        let observation = ConnectionObservation {
            src_ip: Some("172.17.0.1".to_string()),
            src_port: Some(49818),
            dst_ip: "172.17.0.2".to_string(),
            dst_port: Some(80),
            proto: "tcp".to_string(),
            ..base()
        };
        assert_eq!(
            observation.community_id(),
            Some("1:nTs1CSdTGlG13eI4k9WSGFAbjAw=".to_string())
        );
    }

    #[test]
    fn community_id_is_none_when_src_port_missing() {
        let observation = ConnectionObservation {
            src_ip: Some("172.17.0.1".to_string()),
            src_port: None,
            dst_ip: "172.17.0.2".to_string(),
            dst_port: Some(80),
            ..base()
        };
        assert_eq!(observation.community_id(), None);
    }

    #[test]
    fn community_id_is_none_for_unsupported_proto() {
        let observation = ConnectionObservation {
            src_ip: Some("172.17.0.1".to_string()),
            src_port: Some(1),
            dst_ip: "172.17.0.2".to_string(),
            dst_port: Some(80),
            proto: "icmp".to_string(),
            ..base()
        };
        assert_eq!(observation.community_id(), None);
    }
}
