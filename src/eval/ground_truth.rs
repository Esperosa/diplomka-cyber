use crate::passive::ConnectionObservation;

/// Referencni label pro jeden flow/connection. Pouziva se VYHRADNE v `src/eval/*`
/// (vypocet metrik v `dataset_replay::run_baseline`). Nikdy se neimportuje v
/// `correlation.rs`/`decision.rs`/`report.rs`/`model.rs`.
#[derive(Debug, Clone)]
pub(crate) struct GroundTruthLabel {
    /// Napr. "Benign" / "Malicious" - presna velikost pismen se lisi dataset od datasetu
    /// (IoT-23 pouziva "Malicious" i "benign"), proto `is_malicious()` porovnava case-insensitive.
    pub(crate) label: String,
    /// Napr. "C&C", "DDoS", "PartOfAHorizontalPortScan", "-" pokud chybi.
    pub(crate) detailed_label: String,
}

impl GroundTruthLabel {
    pub(crate) fn is_malicious(&self) -> bool {
        self.label.eq_ignore_ascii_case("malicious")
    }
}

/// Labelovany dataset pro replay. `observations[i]` a `labels[i]` odpovidaji stejnemu
/// zdrojovemu radku/flow - jsou to paralelni Vec se stejnym poradim a delkou, ne spojene
/// pres klic. Tato struktura je zaruka proti label leakage: `observations` je jediny
/// vstup, ktery jde do analyticke pipeline (`correlate_events` apod.), `labels` se
/// cte az po behu pipeline v `dataset_replay::score_against_ground_truth`.
#[derive(Debug, Clone, Default)]
pub(crate) struct LabeledDataset {
    pub(crate) dataset_id: String,
    pub(crate) observations: Vec<ConnectionObservation>,
    pub(crate) labels: Vec<GroundTruthLabel>,
}
