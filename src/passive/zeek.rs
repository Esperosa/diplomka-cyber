use std::{collections::HashMap, fs, path::Path};

use chrono::{DateTime, Utc};
use ipnet::IpNet;

use crate::{
    error::{BakulaError, Result},
    model::{NormalizedEvent, Severity},
    passive::{ConnectionObservation, event_in_window, in_scope, parse_zeek_ts},
};

#[allow(private_interfaces)]
#[derive(Debug)]
pub struct ZeekParseResult {
    pub events: Vec<NormalizedEvent>,
    pub connections: Vec<ConnectionObservation>,
}

pub fn parse_zeek_dir(
    path: &Path,
    scope: &[IpNet],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<ZeekParseResult> {
    let mut events = Vec::new();
    let mut connections = Vec::new();

    let notice_path = path.join("notice.log");
    if notice_path.exists() {
        for row in parse_zeek_log(&notice_path)? {
            let timestamp = match parse_zeek_ts(row.get("ts").map(String::as_str).unwrap_or("0")) {
                Ok(timestamp) => timestamp,
                Err(error) => {
                    eprintln!(
                        "VAROVANI: {} radek s neplatnym 'ts' ({error}), radek se vynecha",
                        notice_path.display()
                    );
                    continue;
                }
            };
            let dst_ip = row
                .get("id.resp_h")
                .cloned()
                .or_else(|| row.get("dst_ip").cloned())
                .unwrap_or_default();
            if dst_ip.is_empty()
                || !in_scope(scope, &dst_ip)
                || !event_in_window(timestamp, start, end)
            {
                continue;
            }
            let rule = row.get("note").cloned();
            let message = row
                .get("msg")
                .cloned()
                .unwrap_or_else(|| "Zeek notice".to_string());
            let dst_port = row
                .get("id.resp_p")
                .and_then(|value| value.parse::<u16>().ok());

            events.push(NormalizedEvent {
                event_id: format!(
                    "zeek:{}:{}",
                    row.get("uid")
                        .cloned()
                        .unwrap_or_else(|| "notice".to_string()),
                    timestamp.timestamp()
                ),
                timestamp,
                src_ip: row.get("id.orig_h").cloned(),
                src_port: row
                    .get("id.orig_p")
                    .and_then(|value| value.parse::<u16>().ok()),
                dst_ip,
                proto: "tcp".to_string(),
                dst_port,
                event_type: classify_notice(&message),
                severity: Severity::Medium,
                source: "zeek".to_string(),
                rule_id: rule,
                message,
                raw_ref: Some(notice_path.to_string_lossy().to_string()),
                count: 1,
            });
        }
    }

    let http_path = path.join("http.log");
    if http_path.exists() {
        for row in parse_zeek_log(&http_path)? {
            let timestamp = match parse_zeek_ts(row.get("ts").map(String::as_str).unwrap_or("0")) {
                Ok(timestamp) => timestamp,
                Err(error) => {
                    eprintln!(
                        "VAROVANI: {} radek s neplatnym 'ts' ({error}), radek se vynecha",
                        http_path.display()
                    );
                    continue;
                }
            };
            let dst_ip = row.get("id.resp_h").cloned().unwrap_or_default();
            if dst_ip.is_empty()
                || !in_scope(scope, &dst_ip)
                || !event_in_window(timestamp, start, end)
            {
                continue;
            }
            let dst_port = row
                .get("id.resp_p")
                .and_then(|value| value.parse::<u16>().ok());
            let uri = row.get("uri").cloned().unwrap_or_default();
            let path_upper = uri.to_ascii_lowercase();
            let auth_type = row
                .get("auth_type")
                .cloned()
                .or_else(|| row.get("proxied").cloned())
                .unwrap_or_default()
                .to_ascii_lowercase();
            let mut maybe_event = None;
            if auth_type.contains("basic") {
                maybe_event = Some(("http_basic_without_tls".to_string(), Severity::High));
            } else if dst_port == Some(80)
                && (path_upper.contains("login")
                    || path_upper.contains("signin")
                    || path_upper.contains("auth"))
            {
                maybe_event = Some(("insecure_auth_possible".to_string(), Severity::Low));
            }

            if let Some((event_type, severity)) = maybe_event {
                events.push(NormalizedEvent {
                    event_id: format!(
                        "zeek:{}:http:{}",
                        row.get("uid")
                            .cloned()
                            .unwrap_or_else(|| "http".to_string()),
                        timestamp.timestamp()
                    ),
                    timestamp,
                    src_ip: row.get("id.orig_h").cloned(),
                    src_port: row
                        .get("id.orig_p")
                        .and_then(|value| value.parse::<u16>().ok()),
                    dst_ip,
                    proto: "tcp".to_string(),
                    dst_port,
                    event_type,
                    severity,
                    source: "zeek".to_string(),
                    rule_id: Some("heuristika:http".to_string()),
                    message: format!("HTTP pozorovani: {}", uri),
                    raw_ref: Some(http_path.to_string_lossy().to_string()),
                    count: 1,
                });
            }
        }
    }

    let conn_path = path.join("conn.log");
    if conn_path.exists() {
        for row in parse_zeek_log(&conn_path)? {
            let timestamp = match parse_zeek_ts(row.get("ts").map(String::as_str).unwrap_or("0")) {
                Ok(timestamp) => timestamp,
                Err(error) => {
                    eprintln!(
                        "VAROVANI: {} radek s neplatnym 'ts' ({error}), radek se vynecha",
                        conn_path.display()
                    );
                    continue;
                }
            };
            let dst_ip = row.get("id.resp_h").cloned().unwrap_or_default();
            if dst_ip.is_empty()
                || !in_scope(scope, &dst_ip)
                || !event_in_window(timestamp, start, end)
            {
                continue;
            }
            let orig_pkts = parse_u64_field(&row, &["orig_pkts"]);
            let resp_pkts = parse_u64_field(&row, &["resp_pkts"]);
            let orig_bytes = parse_u64_field(&row, &["orig_bytes"]);
            let resp_bytes = parse_u64_field(&row, &["resp_bytes"]);
            connections.push(ConnectionObservation {
                timestamp,
                dst_ip,
                src_ip: row.get("id.orig_h").cloned(),
                // Deliverable 26 (H2 schema wiring) - drive se `id.orig_p` vubec necetlo
                // (audit finding), ackoliv je v conn.log vzdy pritomne vedle id.orig_h.
                src_port: row
                    .get("id.orig_p")
                    .and_then(|value| value.parse::<u16>().ok()),
                proto: row
                    .get("proto")
                    .cloned()
                    .unwrap_or_else(|| "tcp".to_string())
                    .to_ascii_lowercase(),
                dst_port: row
                    .get("id.resp_p")
                    .and_then(|value| value.parse::<u16>().ok()),
                duration_s: row
                    .get("duration")
                    .and_then(|value| value.parse::<f64>().ok()),
                orig_bytes,
                resp_bytes,
                total_bytes: combine_optional(orig_bytes, resp_bytes),
                orig_pkts,
                resp_pkts,
                total_pkts: combine_optional(orig_pkts, resp_pkts),
                conn_state: row.get("conn_state").cloned(),
                history: row.get("history").cloned(),
                missed_bytes: parse_u64_field(&row, &["missed_bytes"]),
            });
        }
    }

    Ok(ZeekParseResult {
        events,
        connections,
    })
}

pub(crate) fn parse_zeek_log(path: &Path) -> Result<Vec<HashMap<String, String>>> {
    let content = fs::read_to_string(path)?;
    let mut fields = Vec::new();
    let mut rows = Vec::new();

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("#fields\t") {
            fields = rest.split('\t').map(ToString::to_string).collect();
            continue;
        }
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        // Audit nalez (30.10.2026, produkcni gap analyza): tenhle parser umi jen
        // Zeek TSV format (#fields hlavicka). Zeek v JSON formatu (JSON::use_json=T)
        // NEMA #fields radek - bez tyhle kontroly by `fields` zustalo prazdne,
        // kazdy radek by se naparsoval na prazdnou HashMap a cely soubor by tise
        // vratil 0 udalosti (nastroj by tvrdil "vse ciste", protoze nic nevidel).
        // Nahle selhani s jasnou chybou je bezpecnejsi nez tiche tiseni dat.
        if fields.is_empty() {
            return Err(BakulaError::Processing(format!(
                "Zeek log {} nema TSV '#fields' hlavicku - bud je poskozeny, nebo je to \
                 JSON format (JSON::use_json), ktery tento parser neumi. Pouzijte TSV \
                 vystup (vychozi Zeek format) nebo prevedte pres 'zeek -C -r <pcap> local'.",
                path.display()
            )));
        }
        let values = line.split('\t').collect::<Vec<_>>();
        let mut row = HashMap::new();
        for (index, field) in fields.iter().enumerate() {
            if let Some(value) = values.get(index) {
                row.insert(field.clone(), (*value).to_string());
            }
        }
        rows.push(row);
    }

    Ok(rows)
}

fn classify_notice(message: &str) -> String {
    let lowered = message.to_ascii_lowercase();
    if lowered.contains("telnet") || lowered.contains("ftp") {
        "plaintext_protocol".to_string()
    } else if lowered.contains("basic") {
        "http_basic_without_tls".to_string()
    } else {
        "zeek_notice".to_string()
    }
}

fn parse_u64_field(row: &HashMap<String, String>, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        row.get(*key).and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() || trimmed == "-" {
                None
            } else {
                trimmed.parse::<u64>().ok()
            }
        })
    })
}

fn combine_optional(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.saturating_add(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use tempfile::TempDir;

    use super::*;

    fn scope() -> Vec<IpNet> {
        vec!["10.0.0.0/24".parse().expect("scope")]
    }

    fn window() -> (DateTime<Utc>, DateTime<Utc>) {
        let end = Utc::now();
        (end - Duration::hours(2), end)
    }

    /// Audit nalez (30.10.2026, produkcni gap analyza): Zeek v JSON formatu
    /// (JSON::use_json=T) nema '#fields' TSV hlavicku. Drive se takovy soubor
    /// tise naparsoval na 0 udalosti/spojeni bez jakehokoliv varovani - nastroj
    /// by tvrdil "vse ciste", protoze nic nevidel. Ted to musi selhat nahle a
    /// hlasite, ne tise.
    #[test]
    fn json_format_conn_log_fails_loudly_instead_of_silently_returning_zero() {
        let dir = TempDir::new().expect("tempdir");
        let (start, end) = window();
        let ts = (start + Duration::minutes(5)).timestamp();
        let json_line = format!(
            r#"{{"ts":{ts}.0,"uid":"C1","id.orig_h":"10.0.0.9","id.orig_p":51000,"id.resp_h":"10.0.0.5","id.resp_p":443,"proto":"tcp"}}"#
        );
        fs::write(dir.path().join("conn.log"), json_line).expect("write conn.log");

        let error = parse_zeek_dir(dir.path(), &scope(), start, end)
            .expect_err("JSON format bez '#fields' hlavicky musi selhat nahlas");
        assert!(error.to_string().contains("#fields"));
    }

    /// Stejna trida chyby jako u Suricaty: jeden radek s neplatnym 'ts' nesmi
    /// shodit zpracovani zbytku souboru (a tedy celeho `monitor --continuous` behu).
    #[test]
    fn malformed_timestamp_row_in_conn_log_is_skipped_not_fatal() {
        let dir = TempDir::new().expect("tempdir");
        let (start, end) = window();
        let good_ts = (start + Duration::minutes(5)).timestamp();
        let content = format!(
            "#separator \\x09\n\
             #fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\tmissed_bytes\tconn_state\thistory\n\
             #types\ttime\tstring\taddr\tport\taddr\tport\tstring\tinterval\tcount\tcount\tcount\tcount\tcount\tstring\tstring\n\
             not-a-timestamp\tC1\t10.0.0.9\t51000\t10.0.0.5\t443\ttcp\t1.0\t100\t200\t1\t1\t0\tSF\tShadAfF\n\
             {good_ts}.0\tC2\t10.0.0.9\t51000\t10.0.0.5\t443\ttcp\t1.0\t100\t200\t1\t1\t0\tSF\tShadAfF\n"
        );
        fs::write(dir.path().join("conn.log"), content).expect("write conn.log");

        let result = parse_zeek_dir(dir.path(), &scope(), start, end)
            .expect("neplatny 'ts' radek nesmi shodit cely parse");
        assert_eq!(result.connections.len(), 1);
        assert_eq!(result.connections[0].src_port, Some(51000));
    }
}
