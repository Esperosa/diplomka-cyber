//! Krok 5 zdroj: CIC-IDS2017 v pregenerovane verzi Engelen a kol. (WTMC 2021, opravene
//! toky a stitky tehoz zaznamu UNB CIC). Vstup je redukovany vyrez CSV (sloupce
//! `KEEP` v `tools`/skriptu vyrezu, viz `docs/diplomka/dataset-registry.md`), data
//! lezi mimo repo (`SALTICUS_EXTERNAL_DATASETS`).
//!
//! **Prevod na `ConnectionObservation`:** CICFlowMeter nema Zeek `conn_state`. Stav se
//! odvozuje priblizne: bez paketu zpet = `S0`, s RST = `RSTO`, jinak `SF`. Bajty jsou
//! delky payloadu (bez hlavicek), doba v mikrosekundach. Timto prevodem se meri, co by
//! engine videl z flow exportu bez Zeeku, ne totez co nad Zeek conn.log.
//!
//! **Stitky:** `BENIGN` = Benign, cokoli jineho (vcetne `... - Attempted`) = Malicious
//! s puvodnim stitkem jako `detailed_label`. Treti stav (Unknown) dataset nema.

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, NaiveDateTime, Utc};

use crate::error::{SalticusError, Result};
use crate::eval::ground_truth::{GroundTruthLabel, LabeledDataset};
use crate::eval::source::{DatasetSourceInfo, ScenarioSource};
use crate::passive::ConnectionObservation;

pub(crate) struct CicIds2017Source;

impl ScenarioSource for CicIds2017Source {
    fn info(&self) -> DatasetSourceInfo {
        DatasetSourceInfo {
            dataset_id: "cicids2017",
            wave: 1,
            license: "bez vyslovne licence, citace Sharafaldin a kol. (ICISSP 2018) a Engelen a kol. (WTMC 2021)",
            url: "https://intrusion-detection.distrinet-research.be/WTMC2021/",
        }
    }

    fn load(&self, path: &Path) -> Result<LabeledDataset> {
        let content = std::fs::read_to_string(path)?;
        let mut lines = content.lines();
        let header = lines
            .next()
            .ok_or_else(|| SalticusError::Processing("CIC-IDS2017 vyrez je prazdny.".into()))?;
        let columns: HashMap<&str, usize> = header
            .split(',')
            .enumerate()
            .map(|(index, name)| (name.trim(), index))
            .collect();
        let column = |name: &str| -> Result<usize> {
            columns.get(name).copied().ok_or_else(|| {
                SalticusError::Processing(format!("CIC-IDS2017 vyrez postrada sloupec '{name}'."))
            })
        };
        let idx = [
            column("Src IP")?,
            column("Src Port")?,
            column("Dst IP")?,
            column("Dst Port")?,
            column("Protocol")?,
            column("Timestamp")?,
            column("Flow Duration")?,
            column("Total Fwd Packet")?,
            column("Total Bwd packets")?,
            column("Total Length of Fwd Packet")?,
            column("Total Length of Bwd Packet")?,
            column("RST Flag Count")?,
            column("Label")?,
        ];
        let mut observations = Vec::new();
        let mut labels = Vec::new();
        for line in lines {
            let cells: Vec<&str> = line.split(',').collect();
            if cells.len() < columns.len() {
                continue;
            }
            let Some(timestamp) = parse_ts(cells[idx[5]]) else {
                continue;
            };
            let num = |i: usize| cells[i].trim().parse::<f64>().ok();
            let fwd_pkts = num(idx[7]).map(|v| v.max(0.0) as u64);
            let bwd_pkts = num(idx[8]).map(|v| v.max(0.0) as u64);
            let fwd_bytes = num(idx[9]).map(|v| v.max(0.0) as u64);
            let bwd_bytes = num(idx[10]).map(|v| v.max(0.0) as u64);
            let rst = num(idx[11]).unwrap_or(0.0);
            let conn_state = if bwd_pkts.unwrap_or(0) == 0 {
                "S0"
            } else if rst > 0.0 {
                "RSTO"
            } else {
                "SF"
            };
            observations.push(ConnectionObservation {
                timestamp,
                src_ip: Some(cells[idx[0]].trim().to_string()),
                src_port: cells[idx[1]].trim().parse().ok(),
                dst_ip: cells[idx[2]].trim().to_string(),
                proto: proto_name(cells[idx[4]].trim()),
                dst_port: cells[idx[3]].trim().parse().ok(),
                duration_s: num(idx[6]).map(|us| us.max(0.0) / 1e6),
                orig_bytes: fwd_bytes,
                resp_bytes: bwd_bytes,
                total_bytes: Some(fwd_bytes.unwrap_or(0) + bwd_bytes.unwrap_or(0)),
                orig_pkts: fwd_pkts,
                resp_pkts: bwd_pkts,
                total_pkts: Some(fwd_pkts.unwrap_or(0) + bwd_pkts.unwrap_or(0)),
                conn_state: Some(conn_state.to_string()),
                history: None,
                missed_bytes: None,
            });
            labels.push(label_of(cells[idx[12]]));
        }
        Ok(LabeledDataset {
            dataset_id: "cicids2017".to_string(),
            observations,
            labels,
        })
    }
}

fn parse_ts(text: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(text.trim(), "%d/%m/%Y %I:%M:%S %p")
        .ok()
        .map(|naive| naive.and_utc())
}

fn proto_name(code: &str) -> String {
    match code {
        "6" => "tcp".to_string(),
        "17" => "udp".to_string(),
        "1" => "icmp".to_string(),
        other => other.to_ascii_lowercase(),
    }
}

fn label_of(text: &str) -> GroundTruthLabel {
    let text = text.trim();
    if text.eq_ignore_ascii_case("benign") {
        GroundTruthLabel {
            label: "Benign".into(),
            detailed_label: "-".into(),
        }
    } else if text.is_empty() {
        GroundTruthLabel {
            label: "Unknown".into(),
            detailed_label: "-".into(),
        }
    } else {
        GroundTruthLabel {
            label: "Malicious".into(),
            detailed_label: text.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduced_slice_parses_states_labels_and_units() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flows.csv");
        std::fs::write(
            &path,
            "Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,Flow Duration,Total Fwd Packet,Total Bwd packets,Total Length of Fwd Packet,Total Length of Bwd Packet,FIN Flag Count,SYN Flag Count,RST Flag Count,Label\n\
             172.16.0.1,52000,192.168.10.50,22,6,04/07/2017 02:01:05 PM,2500000,10,8,640.0,1200.0,1,1,0,SSH-Patator\n\
             192.168.10.5,49159,192.168.10.3,445,6,04/07/2017 01:53:44 PM,90030854,10,0,8.0,0.0,0,1,0,BENIGN\n\
             192.168.10.9,40000,8.8.8.8,53,17,04/07/2017 01:55:00 PM,1000,1,1,40.0,80.0,0,0,1,FTP-Patator - Attempted\n\
             broken,line\n",
        )
        .unwrap();
        let data = CicIds2017Source.load(&path).unwrap();
        assert_eq!(data.observations.len(), 3);
        let ssh = &data.observations[0];
        assert_eq!(ssh.conn_state.as_deref(), Some("SF"));
        assert_eq!(ssh.duration_s, Some(2.5));
        assert_eq!(ssh.orig_bytes, Some(640));
        assert_eq!(ssh.proto, "tcp");
        assert_eq!(ssh.timestamp.format("%H:%M:%S").to_string(), "14:01:05");
        assert!(data.labels[0].is_malicious());
        assert_eq!(data.observations[1].conn_state.as_deref(), Some("S0"));
        assert!(!data.labels[1].is_malicious() && !data.labels[1].is_unknown());
        assert_eq!(data.observations[2].conn_state.as_deref(), Some("RSTO"));
        assert_eq!(data.observations[2].proto, "udp");
        assert!(data.labels[2].is_malicious());
    }
}
