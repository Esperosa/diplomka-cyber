//! Deliverable 23 (audit finding N6 - bounded fix, ne plný Case Memory). Návrh (sekce
//! 5.6) popisuje Case Memory jako verzovaný, s poisoning guardem chránícím UČENÍ
//! KLASIFIKACE z neověřených případů - to je investice, kterou master plán (viz
//! `docs/diplomka/dalsi-postup-master-plan.md`) vědomě nepostavil jako neúměrnou
//! jedné hypotéze. Tohle řešení je užší a nemá stejné riziko: empirická statistika
//! z OPAKOVANÝCH REÁLNÝCH měření JEDNÉ konkrétní verifikační metody (čas běhu, síťový
//! náklad, informační přínos) nahrazuje caller-supplied konstanty ve
//! `verification_planner.rs`. Poisoning guard dává smysl pro učení "je tohle
//! malicious/benign" (chybná klasifikace se šíří dál) - ne pro "jak dlouho tahle
//! konkrétní GET kontrola trvala minule", kde selhání modelu je nanejvýš špatný odhad
//! nákladu, ne tiché zfalšování bezpečnostního rozhodnutí.

use std::{collections::BTreeMap, fs, path::Path};

use serde::{Deserialize, Serialize};

use crate::{error::Result, storage::write_atomic, verification_planner::VerificationCandidate};

/// Min. pocet realnych mereni metody, od kterych nahrazuji odhady katalogu.
pub const MIN_SAMPLES_FOR_HISTORY: usize = 3;
/// Strop historie na metodu (nejnovejsi vzorky), omezuje rust souboru.
pub const MAX_SAMPLES_PER_METHOD: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ExecutionSample {
    pub runtime_ms: u64,
    pub network_cost: f64,
    pub information_gain: f64,
}

/// Prumer z REALNYCH opakovanych mereni nahrazuje konstantu od volajiciho. Panikne na
/// prazdnem vstupu - "odvodit z dat" bez jakychkoliv dat je kontradikce, ne pripad k
/// tichemu osetreni defaultni hodnotou.
pub fn derive_candidate_from_samples(
    method: &str,
    samples: &[ExecutionSample],
    disruption_risk: f64,
    requires_approval: bool,
) -> VerificationCandidate {
    assert!(
        !samples.is_empty(),
        "derive_candidate_from_samples potrebuje alespon 1 realne mereni, ne prazdnou historii"
    );
    let count = samples.len() as f64;
    let mean_runtime_ms = samples
        .iter()
        .map(|sample| sample.runtime_ms as f64)
        .sum::<f64>()
        / count;
    let mean_network_cost = samples
        .iter()
        .map(|sample| sample.network_cost)
        .sum::<f64>()
        / count;
    let mean_information_gain = samples
        .iter()
        .map(|sample| sample.information_gain)
        .sum::<f64>()
        / count;

    VerificationCandidate {
        method: method.to_string(),
        estimated_information_gain: mean_information_gain,
        estimated_network_cost: mean_network_cost,
        estimated_runtime_ms: mean_runtime_ms.round() as u64,
        disruption_risk,
        requires_approval,
    }
}

/// Perzistovana historie skutecne vykonanych kontrol (`verification-history.json`
/// ve workspace). Nahrazuje kuratorske konstanty v `verification_planner` odhady z
/// realnych mereni: `information_gain` je dobrovolne zjednoduseny proxy (1.0 =
/// vysledek kontroly rozhodl/zmenil verdikt pameti pripadu, 0.0 = nic nového
/// nepridal; viz `pipeline::run_pipeline`), `network_cost` = 0.01 * pocet
/// odeslanych pozadavku.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct VerificationHistory {
    methods: BTreeMap<String, Vec<ExecutionSample>>,
}

impl VerificationHistory {
    /// Chybejici/poskozeny soubor = prazdna historie (chovani katalogu se nemeni).
    pub fn load_or_default(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        write_atomic(path, serde_json::to_string_pretty(self)?.as_bytes())
    }

    /// Cte-uprav-uloz pod zamkem (pipeline vice procesu).
    pub fn update<T>(path: &Path, change: impl FnOnce(&mut Self) -> T) -> Result<T> {
        crate::case_memory::with_file_lock(path, || {
            let mut history = Self::load_or_default(path);
            let value = change(&mut history);
            history.save(path)?;
            Ok(value)
        })
    }

    pub fn record(&mut self, method: &str, sample: ExecutionSample) {
        let samples = self.methods.entry(method.to_string()).or_default();
        samples.push(sample);
        if samples.len() > MAX_SAMPLES_PER_METHOD {
            let excess = samples.len() - MAX_SAMPLES_PER_METHOD;
            samples.drain(..excess);
        }
    }

    pub fn samples(&self, method: &str) -> &[ExecutionSample] {
        self.methods.get(method).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_candidate_averages_real_samples_not_a_single_point() {
        let samples = [
            ExecutionSample {
                runtime_ms: 400,
                network_cost: 0.01,
                information_gain: 0.5,
            },
            ExecutionSample {
                runtime_ms: 600,
                network_cost: 0.03,
                information_gain: 0.7,
            },
        ];
        let candidate = derive_candidate_from_samples("test_method", &samples, 0.0, false);
        assert_eq!(candidate.estimated_runtime_ms, 500);
        assert!((candidate.estimated_network_cost - 0.02).abs() < 1e-9);
        assert!((candidate.estimated_information_gain - 0.6).abs() < 1e-9);
    }

    fn sample(runtime_ms: u64) -> ExecutionSample {
        ExecutionSample {
            runtime_ms,
            network_cost: 0.01,
            information_gain: 1.0,
        }
    }

    #[test]
    fn history_cap_keeps_only_the_newest_samples() {
        let mut history = VerificationHistory::default();
        for i in 0..(MAX_SAMPLES_PER_METHOD as u64 + 25) {
            history.record("m", sample(i));
        }
        let samples = history.samples("m");
        assert_eq!(samples.len(), MAX_SAMPLES_PER_METHOD);
        assert_eq!(samples[0].runtime_ms, 25);
        assert_eq!(
            samples.last().unwrap().runtime_ms,
            MAX_SAMPLES_PER_METHOD as u64 + 24
        );
    }

    #[test]
    fn history_persists_atomically_and_missing_or_corrupt_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("verification-history.json");
        assert!(VerificationHistory::load_or_default(&path).is_empty());
        VerificationHistory::update(&path, |h| h.record("m", sample(5))).unwrap();
        VerificationHistory::update(&path, |h| h.record("m", sample(7))).unwrap();
        assert_eq!(
            VerificationHistory::load_or_default(&path)
                .samples("m")
                .len(),
            2
        );
        std::fs::write(&path, "garbage").unwrap();
        assert!(VerificationHistory::load_or_default(&path).is_empty());
    }

    #[test]
    #[should_panic(expected = "alespon 1 realne mereni")]
    fn derive_candidate_refuses_empty_history() {
        derive_candidate_from_samples("test_method", &[], 0.0, false);
    }
}
