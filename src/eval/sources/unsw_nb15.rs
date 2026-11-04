//! Krok 5 zdroj: UNSW-NB15 (UNSW Canberra, Moustafa a Slay, MilCIS 2015). Vstup je
//! redukovany vyrez `UNSW-NB15_4.csv` (sloupce `stime, srcip, sport, dstip, dsport,
//! proto, state, dur, sbytes, dbytes, spkts, dpkts, attack_cat, label`), data mimo repo.
//!
//! **Stav spojeni:** Argus stavy se prevadi priblizne na Zeek slovnik: `INT` a `REQ`
//! (bez odpovedi) = `S0`, `RST` = `RSTO`, `FIN`, `CON`, `CLO`, `ACC` = `SF`, jinak `OTH`.
//! **Stitky:** `label = 1` = Malicious (`attack_cat` jako `detailed_label`), `0` = Benign.

use std::collections::HashMap;
use std::path::Path;

use chrono::DateTime;

use crate::error::{BakulaError, Result};
use crate::eval::ground_truth::{GroundTruthLabel, LabeledDataset};
use crate::eval::source::{DatasetSourceInfo, ScenarioSource};
use crate::passive::ConnectionObservation;

pub(crate) struct UnswNb15Source;

impl ScenarioSource for UnswNb15Source {
    fn info(&self) -> DatasetSourceInfo {
        DatasetSourceInfo {
            dataset_id: "unsw-nb15",
            wave: 1,
            license: "volne pro akademicky vyzkum, komercni pouziti po dohode s autory (UNSW Canberra)",
            url: "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        }
    }

    fn load(&self, path: &Path) -> Result<LabeledDataset> {
        let content = std::fs::read_to_string(path)?;
        let mut lines = content.lines();
        let header = lines
            .next()
            .ok_or_else(|| BakulaError::Processing("UNSW-NB15 vyrez je prazdny.".into()))?;
        let columns: HashMap<&str, usize> = header
            .split(',')
            .enumerate()
            .map(|(index, name)| (name.trim(), index))
            .collect();
        let column = |name: &str| -> Result<usize> {
            columns.get(name).copied().ok_or_else(|| {
                BakulaError::Processing(format!("UNSW-NB15 vyrez postrada sloupec '{name}'."))
            })
        };
        let idx: Vec<usize> = [
            "stime",
            "srcip",
            "sport",
            "dstip",
            "dsport",
            "proto",
            "state",
            "dur",
            "sbytes",
            "dbytes",
            "spkts",
            "dpkts",
            "attack_cat",
            "label",
        ]
        .iter()
        .map(|name| column(name))
        .collect::<Result<_>>()?;
        let mut observations = Vec::new();
        let mut labels = Vec::new();
        for line in lines {
            let cells: Vec<&str> = line.split(',').map(str::trim).collect();
            if cells.len() < columns.len() {
                continue;
            }
            let Some(timestamp) = cells[idx[0]]
                .parse::<i64>()
                .ok()
                .and_then(|s| DateTime::from_timestamp(s, 0))
            else {
                continue;
            };
            let int = |i: usize| cells[i].parse::<u64>().ok();
            let state = match cells[idx[6]] {
                "INT" | "REQ" => "S0",
                "RST" => "RSTO",
                "FIN" | "CON" | "CLO" | "ACC" => "SF",
                _ => "OTH",
            };
            let (ob, rb, op, rp) = (int(idx[8]), int(idx[9]), int(idx[10]), int(idx[11]));
            observations.push(ConnectionObservation {
                timestamp,
                src_ip: Some(cells[idx[1]].to_string()),
                src_port: parse_port(cells[idx[2]]),
                dst_ip: cells[idx[3]].to_string(),
                proto: cells[idx[5]].to_ascii_lowercase(),
                dst_port: parse_port(cells[idx[4]]),
                duration_s: cells[idx[7]].parse::<f64>().ok(),
                orig_bytes: ob,
                resp_bytes: rb,
                total_bytes: Some(ob.unwrap_or(0) + rb.unwrap_or(0)),
                orig_pkts: op,
                resp_pkts: rp,
                total_pkts: Some(op.unwrap_or(0) + rp.unwrap_or(0)),
                conn_state: Some(state.to_string()),
                history: None,
                missed_bytes: None,
            });
            let malicious = cells[idx[13]] == "1";
            labels.push(GroundTruthLabel {
                label: if malicious { "Malicious" } else { "Benign" }.to_string(),
                detailed_label: if malicious && !cells[idx[12]].is_empty() {
                    cells[idx[12]].to_string()
                } else {
                    "-".to_string()
                },
            });
        }
        Ok(LabeledDataset {
            dataset_id: "unsw-nb15".to_string(),
            observations,
            labels,
        })
    }
}

/// Porty jsou desitkove, u nekterych radku hexadecimalni (`0x000b`) nebo `-`.
fn parse_port(text: &str) -> Option<u16> {
    text.strip_prefix("0x").map_or_else(
        || text.parse().ok(),
        |hex| u16::from_str_radix(hex, 16).ok(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduced_slice_parses_argus_states_labels_and_hex_ports() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flows.csv");
        std::fs::write(
            &path,
            "stime,srcip,sport,dstip,dsport,proto,state,dur,sbytes,dbytes,spkts,dpkts,attack_cat,label\n\
             1424242000,175.45.176.1,1043,149.171.126.16,80,tcp,FIN,0.5,900,1200,10,8,Exploits,1\n\
             1424242001,59.166.0.4,0x000b,149.171.126.9,53,udp,INT,0.0,60,0,1,0,,0\n\
             1424242002,59.166.0.5,40000,149.171.126.2,22,tcp,RST,0.1,100,40,2,1,,0\n",
        )
        .unwrap();
        let data = UnswNb15Source.load(&path).unwrap();
        assert_eq!(data.observations.len(), 3);
        assert!(data.labels[0].is_malicious());
        assert_eq!(data.labels[0].detailed_label, "Exploits");
        assert_eq!(data.observations[0].conn_state.as_deref(), Some("SF"));
        assert_eq!(data.observations[1].src_port, Some(11));
        assert_eq!(data.observations[1].conn_state.as_deref(), Some("S0"));
        assert_eq!(data.observations[2].conn_state.as_deref(), Some("RSTO"));
        assert!(!data.labels[2].is_malicious());
    }
}
