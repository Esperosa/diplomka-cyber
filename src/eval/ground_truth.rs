use crate::passive::ConnectionObservation;

/// Referencni label pro jeden flow/connection. Pouziva se VYHRADNE v `src/eval/*`
/// (vypocet metrik v `dataset_replay::run_baseline`). Nikdy se neimportuje v
/// `correlation.rs`/`decision.rs`/`report.rs`/`model.rs`.
///
/// Tri hodnoty `label`, ne dve: "Malicious" / "Benign" / "Unknown". Puvodne (do 29.10.2026)
/// mel CTU-13 jen binarni Malicious/Benign a "Background" (neoverenej provoz, ne
/// potvrzene benigni - CTU-13 metodologie sama tak Background definuje) se mapoval na
/// "Benign". Nezavisla kontrola (Opus Plan agent) na realnych datech ukazala, ze z
/// 26 212 (dst_ip,proto,port) klicu v CTU-13 vyrezu je 25 317 (96,6 %) "Background-only",
/// a tahle chyba sama zpusobila hlasenou precision 0.083 namisto realistictejsich 0.77
/// po vyrazeni neznamych klicu. `is_unknown()` umoznuje `dataset_replay.rs` VYRADIT
/// takove klice z confusion matrix (ani FP, ani TN), ne je tise pocitat jako potvrzene
/// benigni.
#[derive(Debug, Clone)]
pub(crate) struct GroundTruthLabel {
    /// "Malicious" / "Benign" / "Unknown" - presna velikost pismen se lisi dataset od
    /// datasetu (IoT-23 pouziva "Malicious" i "benign"), proto porovnavaci metody
    /// pracuji case-insensitive.
    pub(crate) label: String,
    /// Napr. "C&C", "DDoS", "PartOfAHorizontalPortScan", "Background", "-" pokud chybi.
    pub(crate) detailed_label: String,
}

impl GroundTruthLabel {
    pub(crate) fn is_malicious(&self) -> bool {
        self.label.eq_ignore_ascii_case("malicious")
    }

    /// `true` jen pro neoverenej provoz (CTU-13 "Background") - NIKDY pro IoT-23, ktery
    /// tenhle stav nema (jen Benign/Malicious). Klice, kde VSECHNY flows jsou unknown,
    /// se v `dataset_replay.rs` vyrazuji z confusion matrix, ne pocitaji jako benigni.
    pub(crate) fn is_unknown(&self) -> bool {
        self.label.eq_ignore_ascii_case("unknown")
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
