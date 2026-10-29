use std::{collections::HashSet, net::IpAddr, path::PathBuf};

use chrono::{DateTime, Utc};
use ipnet::IpNet;

use crate::{
    error::{BakulaError, Result},
    model::{HostReport, NormalizedEvent},
};

mod anomaly;
mod suricata;
mod zeek;

// Re-exporty pro src/eval (dataset replay baseline) - beze zmeny viditelnosti celych modulu.
pub(crate) use anomaly::detect_connection_anomalies;
pub(crate) use anomaly::score_connection_keys;
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
