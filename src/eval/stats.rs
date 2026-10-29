//! Deliverable 20 (chybejici statisticky aparat, audit N4): bootstrap confidence
//! intervaly pro precision/recall/F1. Resampling je WITHIN jednoho scenare (known-
//! evidence klice toho scenare), ne MEZI scenari - na porovnani mezi scenari/
//! ablacemi N=3 (Deliverable 18) nestaci na jakoukoliv smysluplnou silu (Wilcoxon
//! potrebuje n>=6, viz `docs/diplomka/dalsi-postup-master-plan.md`). Tohle reportuje
//! nejistotu uvnitr jednoho mereni (kolik by se cislo zmenilo na jinem vzorku stejne
//! populace klicu), ne signifikanci rozdilu mezi dvema mereními.

use rand::{Rng, SeedableRng, rngs::StdRng};

use super::dataset_replay::ConfusionMatrix;

pub(crate) struct BootstrapCi {
    pub(crate) point_estimate: f64,
    pub(crate) lower_95: f64,
    pub(crate) upper_95: f64,
}

fn confusion_from_pairs(pairs: &[(bool, bool)]) -> ConfusionMatrix {
    let mut confusion = ConfusionMatrix::default();
    for (predicted, actual) in pairs {
        match (predicted, actual) {
            (true, true) => confusion.true_positive += 1,
            (true, false) => confusion.false_positive += 1,
            (false, true) => confusion.false_negative += 1,
            (false, false) => confusion.true_negative += 1,
        }
    }
    confusion
}

/// Percentilova metoda, `resamples` opakovani resamplovani s navracenim ze stejne
/// populace `pairs`. `seed` je explicitni (ne `rand::rng()`) - reprodukovatelnost je
/// tu vyzadovana vlastnost, stejny pozadavek jako u ostatnich eval testu v projektu.
pub(crate) fn bootstrap_metric_ci(
    pairs: &[(bool, bool)],
    resamples: usize,
    seed: u64,
    metric: impl Fn(&ConfusionMatrix) -> f64,
) -> BootstrapCi {
    let point_estimate = metric(&confusion_from_pairs(pairs));
    if pairs.is_empty() || resamples == 0 {
        return BootstrapCi {
            point_estimate,
            lower_95: point_estimate,
            upper_95: point_estimate,
        };
    }

    let mut rng = StdRng::seed_from_u64(seed);
    let mut samples: Vec<f64> = Vec::with_capacity(resamples);
    for _ in 0..resamples {
        let resampled: Vec<(bool, bool)> = (0..pairs.len())
            .map(|_| pairs[rng.random_range(0..pairs.len())])
            .collect();
        samples.push(metric(&confusion_from_pairs(&resampled)));
    }
    samples.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));

    let lower_index = ((resamples as f64) * 0.025) as usize;
    let upper_index = (((resamples as f64) * 0.975) as usize).min(resamples - 1);

    BootstrapCi {
        point_estimate,
        lower_95: samples[lower_index],
        upper_95: samples[upper_index],
    }
}

/// Plocha pod precision-recall krivkou (average precision), pocitana ze (score,
/// label) dvojic BEZ vazby na konkretni prah - Deliverable 28, reakce na pozadavek
/// "zjistit, jestli slaby vysledek je spatny signal nebo jen spatne zvoleny prah".
/// Nahodny/konstantni klasifikator ma PR-AUC = prevalence (podil pozitivnich mezi
/// known klici) - to je spravny "nahodny" baseline pro srovnani, analogicky 0.5 u
/// ROC-AUC. Pokud skore ma PR-AUC vyrazne nad prevalenci, signal NESE uzitecnou
/// informaci, i kdyz aktualne zvoleny prah (3.2) ji nevyuziva dobre.
pub(crate) fn pr_auc(pairs: &[(f64, bool)]) -> f64 {
    let total_positive = pairs.iter().filter(|(_, label)| *label).count();
    if total_positive == 0 {
        return 0.0;
    }

    let mut sorted: Vec<&(f64, bool)> = pairs.iter().collect();
    sorted.sort_by(|left, right| {
        right
            .0
            .partial_cmp(&left.0)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut true_positive = 0usize;
    let mut false_positive = 0usize;
    let mut average_precision = 0.0_f64;
    let mut previous_recall = 0.0_f64;

    for (_, label) in sorted {
        if *label {
            true_positive += 1;
        } else {
            false_positive += 1;
        }
        if *label {
            let precision = true_positive as f64 / (true_positive + false_positive) as f64;
            let recall = true_positive as f64 / total_positive as f64;
            average_precision += (recall - previous_recall) * precision;
            previous_recall = recall;
        }
    }
    average_precision
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Klasicky referencni prepocet (stejne vstupy jako scikit-learn
    /// `average_precision_score` dokumentacni priklad: y_true=[1,0,1,0],
    /// y_score=[0.9,0.8,0.7,0.6]) - ocekavana hodnota 5/6 = 0.8333... overena rucne:
    /// 1. bod (0.9,True): precision=1/1, recall=1/2 -> prispevek 0.5*1.0=0.5
    /// 2. bod (0.7,True): precision=2/3, recall=1 -> prispevek 0.5*0.6667=0.3333
    #[test]
    fn pr_auc_matches_hand_computed_reference_example() {
        let pairs = vec![(0.9, true), (0.8, false), (0.7, true), (0.6, false)];
        let auc = pr_auc(&pairs);
        assert!((auc - 5.0 / 6.0).abs() < 1e-9, "pr_auc={auc}");
    }

    #[test]
    fn pr_auc_is_one_for_perfect_separation() {
        let pairs = vec![(0.9, true), (0.8, true), (0.2, false), (0.1, false)];
        assert!((pr_auc(&pairs) - 1.0).abs() < 1e-9);
    }

    /// Skore, ktere NENESE zadnou informaci o labelu - rovnomerne interleaved
    /// pozitivni/negativni (1 pozitivni na kazdych 10 polozek) se stejnym skore (0.5)
    /// pro vsechny. Pri remíze stabilni sort zachova vstupni poradi, takze na kazdem
    /// z 10 "kontrolnich bodu" (kazdy 10. prvek) je precision presne 1/10 - rucne
    /// odvozeny presny vysledek AP=0.1=prevalence, ne jen odhad.
    #[test]
    fn pr_auc_of_uninformative_interleaved_score_equals_prevalence_exactly() {
        let mut pairs: Vec<(f64, bool)> = Vec::new();
        for block in 0..10 {
            for position in 0..10 {
                let _ = block;
                pairs.push((0.5, position == 9));
            }
        }
        let auc = pr_auc(&pairs);
        assert!(
            (auc - 0.1).abs() < 1e-9,
            "rovnomerne interleaved neinformativni skore musi dat presne prevalenci (0.1), dostal jsem {auc}"
        );
    }

    #[test]
    fn bootstrap_ci_on_perfect_classifier_is_tight_around_one() {
        let pairs: Vec<(bool, bool)> = (0..100).map(|_| (true, true)).collect();
        let ci = bootstrap_metric_ci(&pairs, 500, 42, ConfusionMatrix::precision);
        assert_eq!(ci.point_estimate, 1.0);
        assert!(ci.lower_95 >= 0.999, "lower_95={}", ci.lower_95);
        assert!(ci.upper_95 <= 1.0, "upper_95={}", ci.upper_95);
    }

    #[test]
    fn bootstrap_ci_is_reproducible_for_same_seed() {
        let pairs: Vec<(bool, bool)> = vec![
            (true, true),
            (true, false),
            (false, true),
            (false, false),
            (true, true),
            (false, false),
            (true, false),
            (false, true),
        ];
        let first = bootstrap_metric_ci(&pairs, 1000, 7, ConfusionMatrix::f1);
        let second = bootstrap_metric_ci(&pairs, 1000, 7, ConfusionMatrix::f1);
        assert_eq!(first.lower_95, second.lower_95);
        assert_eq!(first.upper_95, second.upper_95);
    }

    #[test]
    fn bootstrap_ci_widens_with_smaller_sample() {
        // Mensi, vice nejisty vzorek stejneho "typu" dat (50% TP, 50% FN) musi mit
        // sirsi interval nez velky vzorek se stejnym poměrem.
        let small: Vec<(bool, bool)> = vec![(true, true), (false, true)];
        let large: Vec<(bool, bool)> = (0..200)
            .map(|index| {
                if index % 2 == 0 {
                    (true, true)
                } else {
                    (false, true)
                }
            })
            .collect();

        let small_ci = bootstrap_metric_ci(&small, 2000, 1, ConfusionMatrix::recall);
        let large_ci = bootstrap_metric_ci(&large, 2000, 1, ConfusionMatrix::recall);

        let small_width = small_ci.upper_95 - small_ci.lower_95;
        let large_width = large_ci.upper_95 - large_ci.lower_95;
        assert!(
            small_width > large_width,
            "small_width={small_width} large_width={large_width}"
        );
    }
}
