use std::{fs, path::Path};

use chrono::{DateTime, Utc};
use ipnet::IpNet;

use crate::{
    error::Result,
    model::{NormalizedEvent, Severity},
    passive::{
        egress::{ScopeMode, keep},
        event_in_window, parse_suricata_ts,
    },
};

pub fn parse_suricata(
    path: &Path,
    scope: &[IpNet],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Vec<NormalizedEvent>> {
    parse_suricata_mode(path, scope, start, end, ScopeMode::DstOnly)
}

/// `mode = SrcOrDst`: i alerty se zdrojem v rozsahu a cílem venku (C2, miner, krok 3A).
pub fn parse_suricata_mode(
    path: &Path,
    scope: &[IpNet],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    mode: ScopeMode,
) -> Result<Vec<NormalizedEvent>> {
    let content = fs::read_to_string(path)?;
    parse_lines(
        &content,
        &path.to_string_lossy(),
        scope,
        start,
        end,
        mode,
        true,
    )
}

/// Stejna logika nad textem (`label` nahrazuje cestu v logu/`raw_ref`) - pouziva ji
/// i soak simulator, aby generovane alerty prochazely PRESNE produkcnim parserem
/// (klasifikace signatur, scope a casove okno), ne paralelni kopii.
pub(crate) fn parse_suricata_str(
    content: &str,
    label: &str,
    scope: &[IpNet],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<Vec<NormalizedEvent>> {
    parse_suricata_str_mode(content, label, scope, start, end, ScopeMode::DstOnly)
}

/// Bez varovani na stderr: soak pocita poskozene radky sam (`corrupt_alert_lines`)
/// a synchronni zapis na stderr uvnitr cyklu zkresloval mereni casu cyklu (krok 4, G4).
pub(crate) fn parse_suricata_str_mode(
    content: &str,
    label: &str,
    scope: &[IpNet],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    mode: ScopeMode,
) -> Result<Vec<NormalizedEvent>> {
    parse_lines(content, label, scope, start, end, mode, false)
}

fn parse_lines(
    content: &str,
    label: &str,
    scope: &[IpNet],
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    mode: ScopeMode,
    warn: bool,
) -> Result<Vec<NormalizedEvent>> {
    let mut events = Vec::new();
    for (line_no, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let row: serde_json::Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(error) => {
                if warn {
                    eprintln!(
                        "VAROVANI: {} radek {}: nelze naparsovat JSON ({error}), radek se vynecha",
                        label,
                        line_no + 1
                    );
                }
                continue;
            }
        };

        // Audit nalez (30.10.2026, produkcni gap analyza): bezna konfigurace eve.json
        // loguje i zaznamy typu flow/http/dns/tls/stats, ne jen "alert" - ty nenesou
        // signaturu/severity, co tento parser cte, a bez filtru se z nich stavaly
        // falesne nalezy (napr. HTTP flow na portu 80 -> "insecure_auth_possible").
        if row["event_type"].as_str() != Some("alert") {
            continue;
        }

        let timestamp = match parse_suricata_ts(row["timestamp"].as_str().unwrap_or_default()) {
            Ok(timestamp) => timestamp,
            Err(error) => {
                if warn {
                    eprintln!(
                        "VAROVANI: {} radek {}: {error}, radek se vynecha",
                        label,
                        line_no + 1
                    );
                }
                continue;
            }
        };
        let dst_ip = row["dest_ip"].as_str().unwrap_or_default().to_string();
        if !keep(mode, scope, row["src_ip"].as_str(), &dst_ip)
            || !event_in_window(timestamp, start, end)
        {
            continue;
        }

        let src_ip = row["src_ip"].as_str().map(ToString::to_string);
        let src_port = row["src_port"].as_u64().map(|value| value as u16);
        let proto = row["proto"].as_str().unwrap_or("tcp").to_ascii_lowercase();
        let dst_port = row["dest_port"].as_u64().map(|value| value as u16);
        let signature = row["alert"]["signature"]
            .as_str()
            .unwrap_or("Suricata alert");
        let signature_id = row["alert"]["signature_id"].as_i64().unwrap_or_default();
        let severity = Severity::from_numeric(row["alert"]["severity"].as_i64().unwrap_or(3));
        let event_type = classify_signature(signature, dst_port);
        let event_id = format!(
            "suricata:{}:{}",
            row["flow_id"].as_i64().unwrap_or_default(),
            timestamp.timestamp()
        );

        events.push(NormalizedEvent {
            event_id,
            timestamp,
            src_ip,
            src_port,
            dst_ip,
            proto,
            dst_port,
            event_type,
            severity,
            source: "suricata".to_string(),
            rule_id: Some(signature_id.to_string()),
            message: signature.to_string(),
            raw_ref: Some(label.to_string()),
            count: 1,
        });
    }
    Ok(events)
}

fn classify_signature(signature: &str, dst_port: Option<u16>) -> String {
    let lowered = signature.to_ascii_lowercase();
    if lowered.contains("basic") {
        "http_basic_without_tls".to_string()
    } else if lowered.contains("telnet") {
        "plaintext_protocol".to_string()
    } else if lowered.contains("ftp") {
        "plaintext_protocol".to_string()
    } else if dst_port == Some(80) {
        "insecure_auth_possible".to_string()
    } else {
        "suricata_alert".to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use chrono::Duration;
    use tempfile::NamedTempFile;

    use super::*;

    fn scope() -> Vec<IpNet> {
        vec!["10.0.0.0/24".parse().expect("scope")]
    }

    fn window() -> (DateTime<Utc>, DateTime<Utc>) {
        let end = Utc::now();
        (end - Duration::hours(1), end)
    }

    fn write_lines(lines: &[String]) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("tempfile");
        for line in lines {
            writeln!(file, "{line}").expect("write radku do fixtury");
        }
        file
    }

    /// Audit nalez (produkcni gap analyza, 30.10.2026): bez filtru na "event_type"
    /// se kazdy ne-alert zaznam z bezneho eve.json (flow/http/dns/...) stal
    /// falesnym nalezem - konkretne HTTP flow na portu 80 davalo
    /// "insecure_auth_possible", presne tu samou klasifikaci jako skutecny alert.
    #[test]
    fn non_alert_event_types_are_ignored() {
        let (start, end) = window();
        let ts = (start + Duration::minutes(10)).to_rfc3339();
        let flow_line = format!(
            r#"{{"timestamp":"{ts}","event_type":"flow","src_ip":"10.0.0.9","src_port":51000,"dest_ip":"10.0.0.5","dest_port":80,"proto":"TCP"}}"#
        );
        let alert_line = format!(
            r#"{{"timestamp":"{ts}","flow_id":1,"event_type":"alert","src_ip":"10.0.0.9","src_port":51000,"dest_ip":"10.0.0.5","dest_port":443,"proto":"TCP","alert":{{"signature_id":100,"signature":"ET SCAN nmap","severity":2}}}}"#
        );
        let file = write_lines(&[flow_line, alert_line]);

        let events = parse_suricata(file.path(), &scope(), start, end).expect("parse");

        assert_eq!(
            events.len(),
            1,
            "non-alert zaznam (flow) nesmi vyprodukovat finding"
        );
        assert_eq!(events[0].message, "ET SCAN nmap");
    }

    /// Audit nalez: `?` na JSON parse chybe shodilo cely soubor (a tedy cely
    /// `monitor --continuous` beh) na jednom poskozenem/rozepsanem radku.
    #[test]
    fn malformed_json_line_is_skipped_not_fatal() {
        let (start, end) = window();
        let ts = (start + Duration::minutes(5)).to_rfc3339();
        let alert_line = format!(
            r#"{{"timestamp":"{ts}","flow_id":2,"event_type":"alert","src_ip":"10.0.0.9","src_port":51000,"dest_ip":"10.0.0.5","dest_port":443,"proto":"TCP","alert":{{"signature_id":200,"signature":"ET POLICY test","severity":2}}}}"#
        );
        let file = write_lines(&["{not valid json".to_string(), alert_line]);

        let events = parse_suricata(file.path(), &scope(), start, end)
            .expect("poskozeny radek nesmi shodit cely parse");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message, "ET POLICY test");
    }

    /// Stejna trida chyby jako u JSON parse - neplatny/chybejici timestamp na
    /// jednom radku nesmi shodit zpracovani zbytku souboru.
    #[test]
    fn invalid_timestamp_line_is_skipped_not_fatal() {
        let (start, end) = window();
        let ts = (start + Duration::minutes(5)).to_rfc3339();
        let bad_ts_line = r#"{"timestamp":"not-a-timestamp","event_type":"alert","dest_ip":"10.0.0.5","dest_port":443,"alert":{"signature_id":1,"signature":"bad ts","severity":1}}"#.to_string();
        let good_line = format!(
            r#"{{"timestamp":"{ts}","flow_id":3,"event_type":"alert","src_ip":"10.0.0.9","src_port":51000,"dest_ip":"10.0.0.5","dest_port":443,"proto":"TCP","alert":{{"signature_id":300,"signature":"ok","severity":2}}}}"#
        );
        let file = write_lines(&[bad_ts_line, good_line]);

        let events = parse_suricata(file.path(), &scope(), start, end)
            .expect("neplatny timestamp nesmi shodit cely parse");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].message, "ok");
    }

    /// Krok 3A: alert C2 se zdrojem uvnitr a cilem venku legacy zahodi, `SrcOrDst` drzi.
    #[test]
    fn outbound_alert_is_kept_only_in_src_or_dst_mode() {
        let (start, end) = window();
        let ts = (start + Duration::minutes(5)).to_rfc3339();
        let line = format!(
            r#"{{"timestamp":"{ts}","flow_id":4,"event_type":"alert","src_ip":"10.0.0.9","src_port":51000,"dest_ip":"203.0.113.7","dest_port":443,"proto":"TCP","alert":{{"signature_id":2027865,"signature":"ET MALWARE Known C2 beacon pattern","severity":1}}}}"#
        );
        let legacy = parse_suricata_str(&line, "t", &scope(), start, end).unwrap();
        assert!(legacy.is_empty());
        let egress =
            parse_suricata_str_mode(&line, "t", &scope(), start, end, ScopeMode::SrcOrDst).unwrap();
        assert_eq!(egress.len(), 1);
        assert_eq!(egress[0].dst_ip, "203.0.113.7");
    }
}
