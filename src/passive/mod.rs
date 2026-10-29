use std::{collections::HashSet, net::IpAddr, path::PathBuf};

use chrono::{DateTime, Utc};
use ipnet::IpNet;

use crate::{
    error::{BakulaError, Result},
    model::{HostReport, NormalizedEvent},
};

mod anomaly;
mod community_id;
mod suricata;
mod zeek;

// Re-exporty pro src/eval (dataset replay baseline) - beze zmeny viditelnosti celych modulu.
pub(crate) use anomaly::detect_connection_anomalies;
pub(crate) use anomaly::score_connection_keys;
#[allow(unused_imports)]
pub(crate) use anomaly::score_source_hosts;
pub(crate) use zeek::parse_zeek_log;
pub use zeek::{ZeekParseResult, parse_zeek_dir};

#[derive(Debug, Clone)]
pub struct PassiveSources {
    pub suricata_eve: Option<PathBuf>,
    pub zeek_dir: Option<PathBuf>,
}

pub fn load_and_normalize(
    sources: &PassiveSources,
    scope: &[IpNet],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    hosts: &[HostReport],
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

    events.extend(anomaly::detect_connection_anomalies(
        connections,
        &known_services,
    ));

    events.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));
    Ok(events)
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
