//! Realna data jako kotva soak behu: dokola (a deterministicky) prehrava vsechny
//! dostupne CTU-13 a IoT-23 scenare pres produkcni detektor a meri F1 ablace A,
//! triavialni baseline a zdrojove poradi. Syntetika nikdy nenahradi realny provoz -
//! tahle vrstva hlida, aby se meritko soak behu neodtrhlo od skutecnych dat, a
//! kazdy pruchod musi dat BITOVE stejna cisla (jinak je nekde nedeterminismus).

use std::{collections::HashSet, path::Path};

use crate::{
    error::Result,
    eval::{
        dataset_replay::{AblationVariant, run_ablation},
        ground_truth::LabeledDataset,
        source::ScenarioSource,
        sources::{ctu13::Ctu13Source, iot23::Iot23Source},
        stats::pr_auc,
    },
    passive::score_source_hosts,
};

#[derive(Debug, Clone, PartialEq)]
pub struct AnchorRow {
    pub label: String,
    pub flows: usize,
    pub malicious: usize,
    pub f1: f64,
    pub trivial_f1: f64,
    /// PR-AUC / prevalence zdrojoveho skore; 0, pokud neni zadny malicious zdroj.
    pub source_lift: f64,
}

fn source_lift(dataset: &LabeledDataset) -> f64 {
    let scores = score_source_hosts(&dataset.observations);
    if scores.is_empty() {
        return 0.0;
    }
    let mut malicious_sources: HashSet<&str> = HashSet::new();
    for (observation, label) in dataset.observations.iter().zip(dataset.labels.iter()) {
        if label.is_malicious() {
            if let Some(src) = observation.src_ip.as_deref() {
                malicious_sources.insert(src);
            }
        }
    }
    if malicious_sources.is_empty() {
        return 0.0;
    }
    let pairs: Vec<(f64, bool)> = scores
        .iter()
        .map(|(src, score)| (*score, malicious_sources.contains(src.as_str())))
        .collect();
    let prevalence = pairs.iter().filter(|(_, l)| *l).count() as f64 / pairs.len() as f64;
    if prevalence == 0.0 {
        0.0
    } else {
        pr_auc(&pairs) / prevalence
    }
}

fn row(label: String, dataset: &LabeledDataset) -> AnchorRow {
    let result = run_ablation(dataset, 300, AblationVariant::A);
    let (_, _, trivial_f1) = result.confusion.trivial_always_positive_baseline();
    AnchorRow {
        label,
        flows: dataset.observations.len(),
        malicious: result.malicious_flow_count,
        f1: result.confusion.f1(),
        trivial_f1,
        source_lift: source_lift(dataset),
    }
}

/// Projde dostupne scenare VYVOJOVE casti kotvy pod `repo_root/labs/datasets`
/// (krok 3: testovaci cast je zamcena, `behavior_anchor::ANCHOR_TEST`). Chybejici
/// adresar = prazdny vysledek (data nejsou na kazdem stroji; soak to zapise, ne zamlci).
pub fn anchor_pass(repo_root: &Path) -> Result<Vec<AnchorRow>> {
    anchor_pass_with(repo_root, true)
}

/// `include_ctu13 = false` preskoci velke (30 MB) CTU-13 vyrezy - pro rychle testy.
pub fn anchor_pass_with(repo_root: &Path, include_ctu13: bool) -> Result<Vec<AnchorRow>> {
    let mut rows = Vec::new();
    let ctu = repo_root.join("labs/datasets/ctu13");
    if include_ctu13 && ctu.is_dir() {
        let mut dirs: Vec<_> = std::fs::read_dir(&ctu)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        for dir in dirs.into_iter().filter(|d| is_dev(d, "ctu13")) {
            let mut files: Vec<_> = std::fs::read_dir(&dir)?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "csv"))
                .collect();
            files.sort();
            if let Some(file) = files.first() {
                let dataset = Ctu13Source.load(file)?;
                rows.push(row(
                    format!(
                        "ctu13/{}",
                        dir.file_name().unwrap_or_default().to_string_lossy()
                    ),
                    &dataset,
                ));
            }
        }
    }
    let iot = repo_root.join("labs/datasets/iot23");
    if iot.is_dir() {
        let mut dirs: Vec<_> = std::fs::read_dir(&iot)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        for dir in dirs.into_iter().filter(|d| is_dev(d, "iot23")) {
            let file = dir.join("conn.log.labeled");
            if file.is_file() {
                let dataset = Iot23Source.load(&file)?;
                rows.push(row(
                    format!(
                        "iot23/{}",
                        dir.file_name().unwrap_or_default().to_string_lossy()
                    ),
                    &dataset,
                ));
            }
        }
    }
    Ok(rows)
}

fn is_dev(dir: &Path, kind: &str) -> bool {
    let name = format!(
        "{kind}/{}",
        dir.file_name().unwrap_or_default().to_string_lossy()
    );
    crate::eval::behavior_anchor::ANCHOR_DEV.contains(&name.as_str())
}

/// Otisk cisel (zaokrouhlenych), pro porovnani mezi pruchody.
pub fn anchor_digest(rows: &[AnchorRow]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for r in rows {
        let text = format!(
            "{}|{}|{}|{:.6}|{:.6}|{:.6}",
            r.label, r.flows, r.malicious, r.f1, r.trivial_f1, r.source_lift
        );
        for byte in text.bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_iot23_scenarios_replay_identically_twice() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let first = anchor_pass_with(root, false).unwrap();
        assert!(
            first.iter().any(|r| r.label.starts_with("iot23/")),
            "committed IoT-23 scenare musi byt k dispozici"
        );
        let second = anchor_pass_with(root, false).unwrap();
        assert_eq!(first, second);
        assert_eq!(anchor_digest(&first), anchor_digest(&second));
    }
}
