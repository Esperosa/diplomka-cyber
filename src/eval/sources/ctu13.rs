//! Vlna 1 zdroj: CTU-13 (Stratosphere/CTU), `binetflow` CSV format - NetFlow-style
//! bidirektiovni flow zaznamy, NE Zeek conn.log jako IoT-23. Napoveda pro budouci
//! zdroje: kazdy novy format potrebuje svuj vlastni parser, zadne sdileni s
//! `passive::zeek` (jina modalita dat, viz navrh sekce 7.2 "neslevat modality do
//! jednoho plocheho CSV").
//!
//! **Tri kategorie labelu, ne dve jako u IoT-23:** CTU-13 oznacuje kazdy flow jako
//! `Botnet`/`Normal`/`Background`. `Background` je provoz, ktery autoři datasetu
//! nemohli overit jako cistě normalni ani botnet.
//!
//! **OPRAVA 29.10.2026 (puvodne mapovano chybne):** prvni verze tohoto parseru
//! mapovala `Background` na `label="Benign"` - zduvodnene jako "zjednoduseni", ale
//! nezavisla kontrola (Opus Plan agent) na realnych datech ukazala, ze z 26 212
//! (dst_ip,proto,port) klicu v CTU-13 vyrezu je 25 317 (96,6 %) "Background-only".
//! Pocitat vsechny tyhle klice jako potvrzene benigni v confusion matrix NENI
//! "zjednoduseni s dokumentovanou limitaci" - je to chyba, ktera sama o sobe
//! zpusobila hlasenou precision 0.083 na CTU-13 (vs. ~0.77 po spravnem vyrazeni
//! neznamych klicu z confusion matrix, viz `docs/diplomka/eval/cross-dataset-ctu13.md`).
//! Ted se `Background` mapuje na `label="Unknown"` (tretí hodnota, ne jen Malicious/
//! Benign) a `dataset_replay.rs` tyto klice z confusion matrix VYRAZUJE, nepocita
//! je jako TN/FP.
//!
//! **Cross-dataset limitace:** `State` pole ("FPA_FPA", "CON", "RA_PA"...) je NetFlow
//! stavova notace, ne Zeek `conn_state` slovnik ("S0", "REJ", "RSTOS0"...), na ktery
//! jsou `is_timeout_like` heuristiky v `passive::anomaly`/`correlation_v2` naladene.
//! Tyhle heuristiky tedy na CTU-13 pravdepodobne nebudou fungovat stejne jako na
//! IoT-23 - to je presne to, co se ma zmerit, ne predpokladat.

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, NaiveDateTime, Utc};

use crate::error::{BakulaError, Result};
use crate::eval::ground_truth::{GroundTruthLabel, LabeledDataset};
use crate::eval::source::{DatasetSourceInfo, ScenarioSource};
use crate::passive::ConnectionObservation;

pub(crate) struct Ctu13Source;

impl ScenarioSource for Ctu13Source {
    fn info(&self) -> DatasetSourceInfo {
        DatasetSourceInfo {
            dataset_id: "ctu13",
            wave: 1,
            license: "CC BY-NC-SA 4.0 (Stratosphere IPS / CTU, pro vyzkum)",
            url: "https://www.stratosphereips.org/datasets-ctu13",
        }
    }

    fn load(&self, path: &Path) -> Result<LabeledDataset> {
        let content = std::fs::read_to_string(path)?;
        let mut lines = content.lines();
        let header = lines
            .next()
            .ok_or_else(|| BakulaError::Processing("CTU-13 soubor je prazdny.".to_string()))?;
        let columns: HashMap<&str, usize> = header
            .split(',')
            .enumerate()
            .map(|(index, name)| (name, index))
            .collect();

        let column = |name: &str| -> Result<usize> {
            columns.get(name).copied().ok_or_else(|| {
                BakulaError::Processing(format!("CTU-13 header postrada sloupec '{name}'."))
            })
        };
        let idx_start_time = column("StartTime")?;
        let idx_dur = column("Dur")?;
        let idx_proto = column("Proto")?;
        let idx_src_addr = column("SrcAddr")?;
        let idx_dst_addr = column("DstAddr")?;
        let idx_dport = column("Dport")?;
        let idx_state = column("State")?;
        let idx_tot_pkts = column("TotPkts")?;
        let idx_tot_bytes = column("TotBytes")?;
        let idx_src_bytes = column("SrcBytes")?;
        let idx_label = column("Label")?;
        let min_fields = columns.len();

        let mut observations = Vec::new();
        let mut labels = Vec::new();

        for line in lines {
            // Label pole je posledni a muze obsahovat pomlcky, ale ne dalsi carky v
            // tomto formatu - prosty split(',') je bezpecny. Radky s mene poli nez
            // header (napr. useknuty posledni radek pri stazeni vyrezu) se tise
            // vynechaji, ne crashnou cely parser.
            let fields: Vec<&str> = line.split(',').collect();
            if fields.len() < min_fields {
                continue;
            }

            let Some(timestamp) = parse_ctu13_timestamp(fields[idx_start_time]) else {
                continue;
            };
            let dst_ip = fields[idx_dst_addr].trim().to_string();
            if dst_ip.is_empty() {
                continue;
            }
            let dst_port = fields[idx_dport].trim().parse::<u16>().ok();
            let total_bytes = fields[idx_tot_bytes].trim().parse::<u64>().ok();
            let src_bytes = fields[idx_src_bytes].trim().parse::<u64>().ok();
            let resp_bytes = match (total_bytes, src_bytes) {
                (Some(total), Some(src)) => Some(total.saturating_sub(src)),
                _ => None,
            };

            observations.push(ConnectionObservation {
                timestamp,
                src_ip: Some(fields[idx_src_addr].trim().to_string()),
                dst_ip,
                proto: fields[idx_proto].trim().to_ascii_lowercase(),
                dst_port,
                duration_s: fields[idx_dur].trim().parse::<f64>().ok(),
                orig_bytes: src_bytes,
                resp_bytes,
                total_bytes,
                // NetFlow `TotPkts` je uz souctem obou smeru - per-smerove pakety
                // CTU-13 binetflow format neposkytuje, na rozdil od Zeek conn.log.
                orig_pkts: None,
                resp_pkts: None,
                total_pkts: fields[idx_tot_pkts].trim().parse::<u64>().ok(),
                conn_state: Some(fields[idx_state].trim().to_string()),
                history: None,
                missed_bytes: None,
            });
            labels.push(extract_label(fields[idx_label]));
        }

        Ok(LabeledDataset {
            dataset_id: "ctu13".to_string(),
            observations,
            labels,
        })
    }
}

/// Format `"2011/08/15 17:13:40.449530"` - bez explicitni casove zony v datasetu;
/// osetreno jako UTC (jen label, Identity/Correlation logika pracuje s relativnimi
/// rozdily v ramci jednoho souboru, ne s absolutnim casem).
fn parse_ctu13_timestamp(value: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(value.trim(), "%Y/%m/%d %H:%M:%S%.f")
        .ok()
        .map(|naive| naive.and_utc())
}

/// `Label` pole ma tvar `flow=From-Botnet-V54-UDP-DNS` / `flow=Background` /
/// `flow=Normal-V54-HTTP...`. CTU-13 trikategorie (Botnet/Background/Normal) se
/// mapuje na `label` se TREMI hodnotami ("Malicious"/"Benign"/"Unknown" -
/// `GroundTruthLabel::is_malicious()`/`is_unknown()`), ne na binarni - viz oprava
/// v modulove dokumentaci vyse. Puvodni CTU-13-specificka kategorie zustava v
/// `detailed_label`.
fn extract_label(raw: &str) -> GroundTruthLabel {
    let detailed = raw
        .trim()
        .strip_prefix("flow=")
        .unwrap_or(raw.trim())
        .to_string();
    let lower = detailed.to_ascii_lowercase();
    let label = if lower.contains("botnet") {
        "Malicious".to_string()
    } else if lower.contains("background") {
        // Neoverenej provoz (CTU-13 metodologie) - NE potvrzene benigni. Viz
        // modulova dokumentace k opravě 29.10.2026.
        "Unknown".to_string()
    } else {
        "Benign".to_string()
    };
    GroundTruthLabel {
        label,
        detailed_label: detailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_sample(content: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("tempfile");
        file.write_all(content.as_bytes()).expect("write sample");
        file
    }

    const SAMPLE: &str = "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label\n\
2011/08/15 17:13:40.449530,504.234436,tcp,90.177.154.197,20127,  <?>,147.32.84.144,22,FPA_FPA,0,0,25518,24184088,681036,flow=Background\n\
2011/08/15 17:16:48.558133,0.000241,udp,147.32.84.165,1025,  <->,147.32.80.9,53,CON,0,0,2,203,64,flow=From-Botnet-V54-UDP-DNS\n\
2011/08/15 17:13:40.513280,75.502029,tcp,74.125.218.80,80,  <?>,147.32.86.187,54142,FPA_FA,0,0,6491,7424261,7328903,flow=Normal-V54-HTTP\n";

    #[test]
    fn normalizes_three_ctu13_categories_to_ternary_label_with_detail_preserved() {
        let file = write_sample(SAMPLE);
        let dataset = Ctu13Source.load(file.path()).expect("parse ctu13 sample");

        assert_eq!(dataset.observations.len(), 3);
        assert_eq!(dataset.labels.len(), 3);

        // Background: NEOVERENY provoz, ne potvrzene benigni - viz oprava 29.10.2026
        // v modulove dokumentaci. `is_unknown()`, ne `label=="Benign"`.
        assert_eq!(dataset.labels[0].label, "Unknown");
        assert!(!dataset.labels[0].is_malicious());
        assert!(dataset.labels[0].is_unknown());
        assert_eq!(dataset.labels[0].detailed_label, "Background");

        assert_eq!(dataset.labels[1].label, "Malicious");
        assert!(dataset.labels[1].is_malicious());
        assert_eq!(dataset.labels[1].detailed_label, "From-Botnet-V54-UDP-DNS");

        assert_eq!(dataset.labels[2].label, "Benign");
        assert!(!dataset.labels[2].is_malicious());
        assert!(!dataset.labels[2].is_unknown());
        assert_eq!(dataset.labels[2].detailed_label, "Normal-V54-HTTP");
    }

    #[test]
    fn maps_fields_to_connection_observation_correctly() {
        let file = write_sample(SAMPLE);
        let dataset = Ctu13Source.load(file.path()).expect("parse ctu13 sample");

        let botnet_flow = &dataset.observations[1];
        assert_eq!(botnet_flow.dst_ip, "147.32.80.9");
        assert_eq!(botnet_flow.src_ip, Some("147.32.84.165".to_string()));
        assert_eq!(botnet_flow.proto, "udp");
        assert_eq!(botnet_flow.dst_port, Some(53));
        assert_eq!(botnet_flow.total_bytes, Some(203));
        assert_eq!(botnet_flow.orig_bytes, Some(64));
        assert_eq!(botnet_flow.resp_bytes, Some(139));
    }

    #[test]
    fn truncated_trailing_line_is_skipped_not_crashed() {
        let sample_with_truncated_tail = format!("{SAMPLE}2011/08/15 17:20:00.0,1.0,tcp,1.2.3.4");
        let file = write_sample(&sample_with_truncated_tail);
        let dataset = Ctu13Source
            .load(file.path())
            .expect("parse ctu13 sample s useknutym radkem");
        assert_eq!(
            dataset.observations.len(),
            3,
            "useknuty posledni radek se musi tise vynechat"
        );
    }
}
