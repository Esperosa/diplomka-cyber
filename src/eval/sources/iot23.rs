use std::collections::HashMap;
use std::path::Path;

use crate::error::Result;
use crate::eval::ground_truth::{GroundTruthLabel, LabeledDataset};
use crate::eval::source::{DatasetSourceInfo, ScenarioSource};
use crate::passive::{ConnectionObservation, parse_zeek_log, parse_zeek_ts};

/// Vlna 0 zdroj: IoT-23 (Stratosphere/CTU), `conn.log.labeled` Zeek format.
/// Zvlastnost formatu: `tunnel_parents`/`label`/`detailed-label` jsou v `#fields`
/// headeru odddelene mezerami, ne tabulatorem jako ostatni pole - jde tedy v
/// `parse_zeek_log` o JEDNO tab-pole s internimi mezerami, ne tri samostatne klice.
pub(crate) struct Iot23Source;

impl ScenarioSource for Iot23Source {
    fn info(&self) -> DatasetSourceInfo {
        DatasetSourceInfo {
            dataset_id: "iot23",
            wave: 0,
            license: "CC BY-NC-SA 4.0 (Stratosphere IPS / CTU, pro vyzkum)",
            url: "https://www.stratosphereips.org/datasets-iot23",
        }
    }

    fn load(&self, path: &Path) -> Result<LabeledDataset> {
        let rows = parse_zeek_log(path)?;
        let mut observations = Vec::with_capacity(rows.len());
        let mut labels = Vec::with_capacity(rows.len());

        for row in &rows {
            let dst_ip = row.get("id.resp_h").cloned().unwrap_or_default();
            if dst_ip.is_empty() {
                continue;
            }
            let timestamp = parse_zeek_ts(row.get("ts").map(String::as_str).unwrap_or("0"))?;

            let orig_bytes = parse_u64_field(row, "orig_bytes");
            let resp_bytes = parse_u64_field(row, "resp_bytes");
            let orig_pkts = parse_u64_field(row, "orig_pkts");
            let resp_pkts = parse_u64_field(row, "resp_pkts");

            observations.push(ConnectionObservation {
                timestamp,
                dst_ip,
                src_ip: row.get("id.orig_h").cloned(),
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
                missed_bytes: parse_u64_field(row, "missed_bytes"),
            });
            labels.push(extract_label(row));
        }

        Ok(LabeledDataset {
            dataset_id: "iot23".to_string(),
            observations,
            labels,
        })
    }
}

/// `tunnel_parents`/`label`/`detailed-label` jsou v IoT-23 jedno tab-pole s hodnotami
/// oddelenymi mezerami (zvlastnost puvodniho labelovaciho skriptu CTU), proto se hleda
/// podle prefixu nazvu klice, ne presnou shodou - pocet mezer v headeru neni garantovany.
fn extract_label(row: &HashMap<String, String>) -> GroundTruthLabel {
    let combined = row
        .iter()
        .find(|(key, _)| key.starts_with("tunnel_parents"))
        .map(|(_, value)| value.as_str())
        .unwrap_or("-   Benign   -");

    let mut parts = combined.split_whitespace();
    let _tunnel_parents = parts.next();
    let label = parts.next().unwrap_or("Benign").to_string();
    let detailed_label = parts.next().unwrap_or("-").to_string();

    GroundTruthLabel {
        label,
        detailed_label,
    }
}

fn parse_u64_field(row: &HashMap<String, String>, key: &str) -> Option<u64> {
    row.get(key).and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed == "-" {
            None
        } else {
            trimmed.parse::<u64>().ok()
        }
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
    use std::path::{Path, PathBuf};

    use super::*;

    fn dataset_path(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
    }

    #[test]
    fn malware_scenario_44_1_parses_and_has_expected_label_split() {
        let dataset = Iot23Source
            .load(&dataset_path(
                "labs/datasets/iot23/CTU-IoT-Malware-Capture-44-1/conn.log.labeled",
            ))
            .expect("parse iot23 scenario 44-1");

        assert_eq!(dataset.observations.len(), dataset.labels.len());
        assert_eq!(dataset.observations.len(), 237);
        let malicious = dataset
            .labels
            .iter()
            .filter(|label| label.is_malicious())
            .count();
        assert_eq!(malicious, 26);
        assert_eq!(dataset.observations.len() - malicious, 211);
    }

    #[test]
    fn honeypot_scenario_somfy_01_is_fully_benign() {
        let dataset = Iot23Source
            .load(&dataset_path(
                "labs/datasets/iot23/CTU-Honeypot-Capture-7-1-Somfy-01/conn.log.labeled",
            ))
            .expect("parse iot23 somfy-01 scenario");

        assert_eq!(dataset.observations.len(), 130);
        assert!(dataset.labels.iter().all(|label| !label.is_malicious()));
    }
}
