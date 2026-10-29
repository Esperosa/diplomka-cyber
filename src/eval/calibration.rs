//! Deliverable 19 (H4): minimalni kalibrace kontinualniho anomaly skore proti
//! ground truth, leave-one-scenario-out pres 3 CTU-13 scenare (Deliverable 18).
//! Izotonicka regrese (PAVA), ne plny Case Memory - ten navrh sam (sekce 5.6) rika,
//! ze vyzaduje verzovani modelu a poisoning guard, coz je vetsi investice nez tenhle
//! krok (viz `docs/diplomka/dalsi-postup-master-plan.md`, bod "H4 se nestavi").
//! Tohle je prvni skutecne zmerena cast H4 (kalibrace z overenych pripadu), ne jen
//! zdokumentovana limitace.

use std::cmp::Ordering;
use std::collections::HashSet;

use super::ground_truth::LabeledDataset;
use crate::passive::score_connection_keys;

type AggKey = (String, String, u16);

#[derive(Debug, Clone, Copy)]
pub(crate) struct ScoredPoint {
    pub(crate) score: f64,
    pub(crate) is_malicious: bool,
}

/// Z `LabeledDataset` vyrobi (score, label) body - jen pro klice se znamou evidenci
/// (Malicious/Benign, nikdy Unknown - stejne vyrazeni jako v `dataset_replay::run_ablation`)
/// a s dostatkem flows na vypocet skore (`score_connection_keys` interne vyzaduje count>=3).
pub(crate) fn scored_points(dataset: &LabeledDataset) -> Vec<ScoredPoint> {
    let scores = score_connection_keys(&dataset.observations);

    let mut ground_truth_positive: HashSet<AggKey> = HashSet::new();
    let mut key_has_known_evidence: HashSet<AggKey> = HashSet::new();
    for (observation, label) in dataset.observations.iter().zip(dataset.labels.iter()) {
        let Some(port) = observation.dst_port else {
            continue;
        };
        let key = (observation.dst_ip.clone(), observation.proto.clone(), port);
        if label.is_malicious() {
            ground_truth_positive.insert(key.clone());
            key_has_known_evidence.insert(key);
        } else if !label.is_unknown() {
            key_has_known_evidence.insert(key);
        }
    }

    scores
        .into_iter()
        .filter(|(key, _)| key_has_known_evidence.contains(key))
        .map(|(key, score)| ScoredPoint {
            score,
            is_malicious: ground_truth_positive.contains(&key),
        })
        .collect()
}

/// Izotonicka regrese (pool adjacent violators) - necalibrovane skore -> P(malicious).
/// Breakpointy jsou (prumerne skore poolu, kalibrovana pravdepodobnost poolu), serazene
/// vzestupne podle skore - neklesajici schodova funkce, standardni PAVA vystup.
pub(crate) struct IsotonicCalibrator {
    breakpoints: Vec<(f64, f64)>,
}

struct Pool {
    // Minimum skore mezi body v tomhle poolu - POUZIVA se jako prahova hodnota pro
    // `predict()`, ne prumer. Pool vznikly slouceni dvou sousednich poolu pokryva
    // souvisly rozsah skore (vstup je pred PAVA serazeny); jeho minimum je proto
    // spravna hranice, od ktere zacina platit jeho kalibrovana pravdepodobnost.
    // Pouziti prumeru by misto toho vratilo JINOU pravdepodobnost pro dva trenovaci
    // body slouceny do stejneho poolu, podle toho, zda jejich skore je nad/pod
    // prumerem poolu - zjistena a opravena chyba pri psani testu.
    min_score: f64,
    count: usize,
    sum_label: f64,
}

impl IsotonicCalibrator {
    pub(crate) fn fit(points: &[ScoredPoint]) -> Self {
        let mut sorted: Vec<&ScoredPoint> = points.iter().collect();
        sorted.sort_by(|left, right| {
            left.score
                .partial_cmp(&right.score)
                .unwrap_or(Ordering::Equal)
        });

        // Kazdy bod zacina jako vlastni pool; sousedni pooly, ktere porusuji monotonii
        // (predchozi prumer > nasledujici), se sluci, dokud je cela posloupnost
        // neklesajici - standardni PAVA (pool adjacent violators algorithm).
        let mut pools: Vec<Pool> = sorted
            .iter()
            .map(|point| Pool {
                min_score: point.score,
                count: 1,
                sum_label: if point.is_malicious { 1.0 } else { 0.0 },
            })
            .collect();

        let mut i = 0;
        while i + 1 < pools.len() {
            let mean_i = pools[i].sum_label / pools[i].count as f64;
            let mean_next = pools[i + 1].sum_label / pools[i + 1].count as f64;
            if mean_i > mean_next {
                let merged = Pool {
                    min_score: pools[i].min_score,
                    count: pools[i].count + pools[i + 1].count,
                    sum_label: pools[i].sum_label + pools[i + 1].sum_label,
                };
                pools[i] = merged;
                pools.remove(i + 1);
                i = i.saturating_sub(1);
            } else {
                i += 1;
            }
        }

        let breakpoints = pools
            .into_iter()
            .map(|pool| (pool.min_score, pool.sum_label / pool.count as f64))
            .collect();

        Self { breakpoints }
    }

    /// Predikce: posledni breakpoint se score_threshold <= query skore (nejblizsi
    /// trenovaci skore shora). Pro skore pod nejnizsim trenovacim breakpointem vrati
    /// pravdepodobnost prvniho poolu (bezpecna extrapolace, ne natvrdo 0.0).
    pub(crate) fn predict(&self, score: f64) -> f64 {
        let Some((_, first_probability)) = self.breakpoints.first() else {
            return 0.0;
        };
        let mut result = *first_probability;
        for (threshold, probability) in &self.breakpoints {
            if *threshold <= score {
                result = *probability;
            } else {
                break;
            }
        }
        result
    }
}

pub(crate) fn brier_score(predictions: &[(f64, bool)]) -> f64 {
    if predictions.is_empty() {
        return 0.0;
    }
    let sum: f64 = predictions
        .iter()
        .map(|(probability, actual)| {
            let label = if *actual { 1.0 } else { 0.0 };
            (probability - label).powi(2)
        })
        .sum();
    sum / predictions.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isotonic_regression_produces_nondecreasing_step_function() {
        // Zamerne neuspořádany vstup s jednim "porusenim monotonie" (skore 2.0 ma
        // label 1, skore 3.0 ma label 0) - PAVA je musi slit do jednoho poolu.
        let points = vec![
            ScoredPoint {
                score: 1.0,
                is_malicious: false,
            },
            ScoredPoint {
                score: 2.0,
                is_malicious: true,
            },
            ScoredPoint {
                score: 3.0,
                is_malicious: false,
            },
            ScoredPoint {
                score: 4.0,
                is_malicious: true,
            },
        ];
        let calibrator = IsotonicCalibrator::fit(&points);

        let p1 = calibrator.predict(1.0);
        let p2 = calibrator.predict(2.0);
        let p3 = calibrator.predict(3.0);
        let p4 = calibrator.predict(4.0);

        assert!(p1 <= p2, "p1={p1} p2={p2}");
        assert!(p2 <= p3, "p2={p2} p3={p3}");
        assert!(p3 <= p4, "p3={p3} p4={p4}");
        // Skore 2.0 a 3.0 musely byt slity do jednoho poolu (prumer 0.5), protoze
        // samostatne by porusily monotonii (label(2.0)=1 > label(3.0)=0).
        assert!((p2 - p3).abs() < 1e-9, "p2={p2} p3={p3} museji byt stejne");
    }

    #[test]
    fn brier_score_is_zero_for_perfect_predictions() {
        let predictions = vec![(1.0, true), (0.0, false), (1.0, true)];
        assert_eq!(brier_score(&predictions), 0.0);
    }

    #[test]
    fn brier_score_is_one_for_perfectly_wrong_predictions() {
        let predictions = vec![(0.0, true), (1.0, false)];
        assert_eq!(brier_score(&predictions), 1.0);
    }
}
