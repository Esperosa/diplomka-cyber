//! Kotva kroku 3: behaviorální detektory na OZNAČENÝCH reálných tocích (CTU-13, IoT-23)
//! a předem rozdělená vývojová a testovací část.
//!
//! Rozdělení (`ANCHOR_DEV`, `ANCHOR_TEST`) je pevné a uložené v repu
//! (`docs/diplomka/eval/anchor-split.txt`) i s SHA-256 seznamu testovací části.
//! Testovací část je ZAMČENÁ: `scenarios(Part::Test, false)` vrátí chybu, při ladění se
//! nespouští. Otevírá se jen jednou, pro závěrečné měření, s `unlock = true`.
//!
//! Rozdělení po scénářích, ne po tocích (toky jednoho scénáře jsou silně závislé). Rodiny
//! botnetů se dvěma a více scénáři (Neris, Rbot, Virut) mají scénář v obou částech,
//! jednorázové rodiny se střídají; u IoT-23 mají obě části honeypot (neškodný) záznam
//! a Mirai i Torii jsou v obou.
//!
//! Měří se na úrovni hostu uvnitř rozsahu: host je škodlivý, když je zdrojem toku
//! s označením Malicious; neškodný, když je zdrojem jen neškodných toků; ostatní
//! (CTU-13 Background) jsou neznámé a do metrik nevstupují (stejně jako
//! `dataset_replay`).

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
};

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use sha2::{Digest, Sha256};

use crate::{
    behavior::{BehaviorInput, BehaviorState, BehaviorSwitches, BehaviorThresholds, run_window},
    error::{BakulaError, Result},
    eval::{
        ground_truth::LabeledDataset,
        source::ScenarioSource,
        sources::{ctu13::Ctu13Source, iot23::Iot23Source},
    },
    passive::egress::{EgressPolicy, split_flows},
};

/// Část kotvy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    /// Vývojová část: smí se použít k ladění a odhadu rozdělení.
    Dev,
    /// Testovací část: zamčená, jen závěrečné měření.
    Test,
}

pub const ANCHOR_DEV: &[&str] = &[
    "ctu13/Botnet-42", // Neris
    "ctu13/Botnet-44", // Rbot
    "ctu13/Botnet-46", // Virut
    "ctu13/Botnet-47", // Menti
    "ctu13/Botnet-49", // Murlo
    "ctu13/Botnet-52", // Rbot
    "iot23/CTU-Honeypot-Capture-4-1",
    "iot23/CTU-IoT-Malware-Capture-3-1",  // Muhstik
    "iot23/CTU-IoT-Malware-Capture-20-1", // Torii
    "iot23/CTU-IoT-Malware-Capture-34-1", // Mirai
    "iot23/CTU-IoT-Malware-Capture-42-1", // Trojan
];

pub const ANCHOR_TEST: &[&str] = &[
    "ctu13/Botnet-43", // Neris
    "ctu13/Botnet-45", // Rbot
    "ctu13/Botnet-48", // Sogou
    "ctu13/Botnet-50", // Neris
    "ctu13/Botnet-51", // Rbot
    "ctu13/Botnet-53", // NSIS.ay
    "ctu13/Botnet-54", // Virut
    "iot23/CTU-Honeypot-Capture-5-1",
    "iot23/CTU-Honeypot-Capture-7-1-Somfy-01",
    "iot23/CTU-IoT-Malware-Capture-8-1",  // Hakai
    "iot23/CTU-IoT-Malware-Capture-21-1", // Torii
    "iot23/CTU-IoT-Malware-Capture-44-1", // Mirai
];

/// SHA-256 seznamu testovací části (řádky spojené `\n`); test hlídá shodu se souborem.
pub const ANCHOR_TEST_SHA256: &str =
    "15b0127a3745325427fb8131ae6e83703968bcf7288c4ab1fa9e47edea6d8fd7";

pub fn list_sha256(items: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(items.join("\n").as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Scénáře části. Testovací část bez `unlock` nebo s jiným otiskem seznamu = chyba.
pub fn scenarios(part: Part, unlock: bool) -> Result<&'static [&'static str]> {
    match part {
        Part::Dev => Ok(ANCHOR_DEV),
        Part::Test if !unlock => Err(BakulaError::Processing(
            "testovaci cast kotvy je zamcena (jen zaverecne mereni)".into(),
        )),
        Part::Test if list_sha256(ANCHOR_TEST) != ANCHOR_TEST_SHA256 => Err(
            BakulaError::Processing("seznam testovaci casti kotvy nesouhlasi s otiskem".into()),
        ),
        Part::Test => Ok(ANCHOR_TEST),
    }
}

/// Načte scénář `ctu13/<dir>` nebo `iot23/<dir>` z `repo_root/labs/datasets`.
pub(crate) fn load(repo_root: &Path, scenario: &str) -> Result<Option<LabeledDataset>> {
    let base = repo_root.join("labs/datasets").join(scenario);
    if !base.is_dir() {
        return Ok(None);
    }
    if scenario.starts_with("ctu13/") {
        let mut files: Vec<_> = std::fs::read_dir(&base)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "csv"))
            .collect();
        files.sort();
        match files.first() {
            Some(file) => Ok(Some(Ctu13Source.load(file)?)),
            None => Ok(None),
        }
    } else {
        let file = base.join("conn.log.labeled");
        if file.is_file() {
            Ok(Some(Iot23Source.load(&file)?))
        } else {
            Ok(None)
        }
    }
}

/// Vnitřní rozsah scénáře (CTU-13: síť univerzity 147.32.0.0/16; IoT-23: 192.168.0.0/16).
pub fn scope_for(scenario: &str) -> Vec<IpNet> {
    let net = if scenario.starts_with("ctu13/") {
        "147.32.0.0/16"
    } else {
        "192.168.0.0/16"
    };
    vec![net.parse().expect("platny CIDR")]
}

/// Výsledek behaviorálních detektorů na jednom scénáři (úroveň hostu).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BehaviorAnchorRow {
    pub scenario: String,
    pub flows: usize,
    pub windows: usize,
    pub hosts_malicious: usize,
    pub hosts_benign: usize,
    /// Typ nálezu -> (škodliví hosté s nálezem, neškodní hosté s nálezem).
    pub by_type: BTreeMap<String, (usize, usize)>,
    /// Libovolný behaviorální nález.
    pub any: (usize, usize),
}

const WINDOW_S: i64 = 1800;

/// Pustí behaviorální vrstvu (výchozí prahy, všechny detektory) po 30min oknech.
pub(crate) fn run_behavior(scenario: &str, dataset: &LabeledDataset) -> BehaviorAnchorRow {
    let scope = scope_for(scenario);
    let inside = |ip: &str| {
        ip.parse::<std::net::IpAddr>()
            .ok()
            .is_some_and(|a| scope.iter().any(|n| n.contains(&a)))
    };
    // pravda na urovni hostu (jen po behu, labely nevstupuji do detekce)
    let mut malicious: HashSet<String> = HashSet::new();
    let mut benign_seen: HashSet<String> = HashSet::new();
    for (o, label) in dataset.observations.iter().zip(&dataset.labels) {
        let Some(src) = o.src_ip.as_deref().filter(|s| inside(s)) else {
            continue;
        };
        if label.is_malicious() {
            malicious.insert(src.to_string());
        } else if !label.is_unknown() {
            benign_seen.insert(src.to_string());
        }
    }
    let benign: HashSet<String> = benign_seen.difference(&malicious).cloned().collect();

    let mut order: Vec<usize> = (0..dataset.observations.len()).collect();
    order.sort_by_key(|i| dataset.observations[*i].timestamp);
    let switches = BehaviorSwitches {
        egress: true,
        beacon: true,
        interactive: true,
        graph: true,
        profile: false,
    };
    let thresholds = BehaviorThresholds::default();
    let policy = EgressPolicy::default();
    let mut state = BehaviorState::default();
    let mut flagged: HashMap<String, HashSet<String>> = HashMap::new();
    let mut windows = 0usize;
    let mut cursor = 0usize;
    while cursor < order.len() {
        let start = dataset.observations[order[cursor]].timestamp.timestamp();
        let window_start = start - start.rem_euclid(WINDOW_S);
        let mut batch = Vec::new();
        while cursor < order.len()
            && dataset.observations[order[cursor]].timestamp.timestamp() < window_start + WINDOW_S
        {
            batch.push(dataset.observations[order[cursor]].clone());
            cursor += 1;
        }
        let split = split_flows(batch, &scope, &policy);
        let now: DateTime<Utc> = DateTime::from_timestamp(window_start, 0).unwrap_or_else(Utc::now);
        let out = run_window(
            &mut state,
            switches,
            &thresholds,
            &BehaviorInput {
                outbound: &split.outbound,
                internal: &split.internal,
                outbound_alerts: &[],
                now,
            },
        );
        windows += 1;
        for item in out.findings {
            flagged
                .entry(item.finding.finding_type.clone())
                .or_default()
                .insert(item.actor);
        }
    }
    let mut row = BehaviorAnchorRow {
        scenario: scenario.to_string(),
        flows: dataset.observations.len(),
        windows,
        hosts_malicious: malicious.len(),
        hosts_benign: benign.len(),
        ..Default::default()
    };
    let mut any: HashSet<&String> = HashSet::new();
    for (kind, hosts) in &flagged {
        let m = hosts.iter().filter(|h| malicious.contains(*h)).count();
        let b = hosts.iter().filter(|h| benign.contains(*h)).count();
        row.by_type.insert(kind.clone(), (m, b));
        any.extend(hosts.iter());
    }
    row.any = (
        any.iter().filter(|h| malicious.contains(**h)).count(),
        any.iter().filter(|h| benign.contains(**h)).count(),
    );
    row
}

/// Empirické rozdělení neškodných toků (vývojová část): kvantily délky, bajtů
/// a podíl pravidelných dvojic (CV mezer < 0,2 při ≥ 8 tocích) jako kontrola
/// generátoru neškodných vzorů (krok 3, bod 2).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EmpiricalBenign {
    pub flows: usize,
    pub duration_q: [f64; 5],
    pub orig_bytes_q: [f64; 5],
    pub resp_bytes_q: [f64; 5],
    pub pairs: usize,
    pub periodic_pairs: usize,
    /// Kvantily mediánové mezery pravidelných dvojic (s).
    pub periodic_gap_q: [f64; 5],
}

const QS: [f64; 5] = [0.1, 0.25, 0.5, 0.75, 0.9];

fn quantiles(values: &mut [f64]) -> [f64; 5] {
    if values.is_empty() {
        return [0.0; 5];
    }
    values.sort_by(|a, b| a.total_cmp(b));
    let n = values.len();
    QS.map(|q| values[((q * (n - 1) as f64).round() as usize).min(n - 1)])
}

pub(crate) fn empirical_benign(dataset: &LabeledDataset) -> EmpiricalBenign {
    let mut durations = Vec::new();
    let mut orig = Vec::new();
    let mut resp = Vec::new();
    let mut by_pair: HashMap<(String, String, u16), Vec<i64>> = HashMap::new();
    for (o, label) in dataset.observations.iter().zip(&dataset.labels) {
        if label.is_malicious() || label.is_unknown() {
            continue;
        }
        durations.push(o.duration_s.unwrap_or(0.0));
        orig.push(o.orig_bytes.unwrap_or(0) as f64);
        resp.push(o.resp_bytes.unwrap_or(0) as f64);
        by_pair
            .entry((
                o.src_ip.clone().unwrap_or_default(),
                o.dst_ip.clone(),
                o.dst_port.unwrap_or(0),
            ))
            .or_default()
            .push(o.timestamp.timestamp());
    }
    let mut out = EmpiricalBenign {
        flows: durations.len(),
        duration_q: quantiles(&mut durations),
        orig_bytes_q: quantiles(&mut orig),
        resp_bytes_q: quantiles(&mut resp),
        ..Default::default()
    };
    let mut periodic_gaps = Vec::new();
    for times in by_pair.values_mut() {
        if times.len() < 8 {
            continue;
        }
        out.pairs += 1;
        times.sort_unstable();
        let gaps: Vec<f64> = times
            .windows(2)
            .map(|w| (w[1] - w[0]) as f64)
            .filter(|g| *g > 0.0)
            .collect();
        if gaps.len() < 7 {
            continue;
        }
        let mean = gaps.iter().sum::<f64>() / gaps.len() as f64;
        let var = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f64>() / gaps.len() as f64;
        if mean > 0.0 && var.sqrt() / mean < 0.2 {
            out.periodic_pairs += 1;
            let mut g = gaps.clone();
            g.sort_by(|a, b| a.total_cmp(b));
            periodic_gaps.push(g[g.len() / 2]);
        }
    }
    out.periodic_gap_q = quantiles(&mut periodic_gaps);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_is_disjoint_locked_and_matches_committed_list() {
        let dev: HashSet<&str> = ANCHOR_DEV.iter().copied().collect();
        assert!(
            ANCHOR_TEST.iter().all(|s| !dev.contains(s)),
            "casti se prekryvaji"
        );
        assert!(
            scenarios(Part::Test, false).is_err(),
            "test musi byt zamceny"
        );
        assert_eq!(list_sha256(ANCHOR_TEST), ANCHOR_TEST_SHA256);
        assert_eq!(scenarios(Part::Test, true).unwrap(), ANCHOR_TEST);
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let file = std::fs::read_to_string(root.join("docs/diplomka/eval/anchor-split.txt"))
            .expect("seznam v repu");
        let section = |name: &str| -> Vec<String> {
            file.lines()
                .skip_while(|l| l.trim() != name)
                .skip(1)
                .take_while(|l| !l.trim().is_empty() && !l.starts_with('['))
                .filter(|l| !l.starts_with('#'))
                .map(|l| l.trim().to_string())
                .collect()
        };
        assert_eq!(section("[dev]"), ANCHOR_DEV);
        assert_eq!(section("[test]"), ANCHOR_TEST);
        assert!(file.contains(ANCHOR_TEST_SHA256));
        // kazdy scenar v labs/datasets je v prave jedne casti
        for kind in ["ctu13", "iot23"] {
            let Ok(entries) = std::fs::read_dir(root.join("labs/datasets").join(kind)) else {
                continue;
            };
            for entry in entries.filter_map(|e| e.ok()).filter(|e| e.path().is_dir()) {
                let name = format!("{kind}/{}", entry.file_name().to_string_lossy());
                assert!(
                    dev.contains(name.as_str()) || ANCHOR_TEST.contains(&name.as_str()),
                    "{name} neni v zadne casti"
                );
            }
        }
    }

    #[test]
    fn periodic_inside_host_is_flagged_and_labels_stay_out_of_detection() {
        use crate::{eval::ground_truth::GroundTruthLabel, passive::ConnectionObservation};
        let flow = |src: &str, dst: &str, at: i64| ConnectionObservation {
            timestamp: DateTime::from_timestamp(1_700_000_000 + at, 0).unwrap(),
            src_ip: Some(src.into()),
            src_port: Some(40000),
            dst_ip: dst.into(),
            proto: "tcp".into(),
            dst_port: Some(443),
            duration_s: Some(0.3),
            orig_bytes: Some(300),
            resp_bytes: Some(400),
            total_bytes: Some(700),
            orig_pkts: Some(3),
            resp_pkts: Some(3),
            total_pkts: Some(6),
            conn_state: Some("SF".into()),
            history: None,
            missed_bytes: Some(0),
        };
        let mut dataset = LabeledDataset::default();
        for i in 0..(48 * 12) {
            dataset
                .observations
                .push(flow("192.168.1.5", "198.51.100.9", i * 300 + (i % 3) * 7));
            dataset.labels.push(GroundTruthLabel {
                label: "Malicious".into(),
                detailed_label: "C&C".into(),
            });
        }
        let row = run_behavior("iot23/synth", &dataset);
        assert_eq!(row.hosts_malicious, 1);
        assert_eq!(row.any.0, 1, "{row:?}");
        // stejne toky s jinymi labely = stejna detekce (labely do detekce nevstupuji)
        let mut relabeled = dataset.clone();
        for label in &mut relabeled.labels {
            label.label = "Benign".into();
        }
        let other = run_behavior("iot23/synth", &relabeled);
        assert_eq!(other.windows, row.windows);
        assert_eq!(other.any.1, 1);
        let empirical = empirical_benign(&relabeled);
        assert_eq!(empirical.periodic_pairs, 1);
    }

    /// Ruční běh vývojové části: `cargo test --release --lib behavior_anchor_dev --
    /// --ignored --nocapture`. Testovací část se tu nespouští.
    #[test]
    #[ignore]
    fn behavior_anchor_dev() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        for scenario in scenarios(Part::Dev, false).unwrap() {
            let Some(dataset) = load(root, scenario).unwrap() else {
                println!("{scenario}: chybi data");
                continue;
            };
            let row = run_behavior(scenario, &dataset);
            let emp = empirical_benign(&dataset);
            println!("ROW {row:?}");
            println!("EMP {scenario} {emp:?}");
        }
    }
}
