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
/// Audit nalez (30.10.2026, rozsireni CTU-13 na N=13): puvodni verze zpracovavala
/// shodne skore JEDNOTLIVE, ne po skupinach - u vazanych skore pak vysledek zavisel
/// na RELATIVNIM PORADI vazanych vzorku ve vstupnim `pairs`, coz nema zadny
/// kanonicky vyznam (na stejnem skore nejde v realnem nasazeni rozhodnout, ktery
/// vzorek "je prvni"). Volajici (`score_source_hosts`, vraci `HashMap`) predavali
/// `pairs` v poradi HashMap iterace, ktere Rust NEGARANTUJE stabilni mezi behy
/// procesu (SipHash s nahodnym per-proces klicem) - vysledkem bylo PR-AUC, ktere se
/// litovalo az o desitky procent mezi opakovanymi behy STEJNYCH dat (zmereno primo:
/// 3 opakovane behy daly ruzne hodnoty). Oprava: vsechny vzorky se STEJNYM skore se
/// zpracuji jako JEDNA skupina (vsechny TP/FP pricteny najednou, bod na PR krivce
/// spocitany jednou za skupinu) - vysledek pak zavisi jen na multisetu (skore,
/// label) dvojic, ne na jejich poradi.
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

    let mut index = 0;
    while index < sorted.len() {
        let score = sorted[index].0;
        let mut group_end = index + 1;
        while group_end < sorted.len() && sorted[group_end].0 == score {
            group_end += 1;
        }
        for (_, label) in &sorted[index..group_end] {
            if *label {
                true_positive += 1;
            } else {
                false_positive += 1;
            }
        }
        if true_positive > 0 {
            let precision = true_positive as f64 / (true_positive + false_positive) as f64;
            let recall = true_positive as f64 / total_positive as f64;
            average_precision += (recall - previous_recall) * precision;
            previous_recall = recall;
        }
        index = group_end;
    }
    average_precision
}

/// Vysledek Wilcoxonova znamenkoveho poradoveho testu (parovy, nonparametricky
/// test shody s medianem 0) - Deliverable 31, reakce na pozadavek "median vypada
/// lepe" nestaci jako "statisticky prukazne". Potrebuje n>=6 pro jakoukoliv silu
/// (viz modulova dokumentace vyse) - CTU-13 (N=13) a IoT-23 malware scenare (N=6)
/// po rozsireni 30.10.2026 poprve tuhle hranici splnuji.
pub(crate) struct WilcoxonResult {
    pub(crate) n_effective: usize,
    pub(crate) w_statistic: f64,
    pub(crate) p_value_two_sided: f64,
}

/// Parovy test: `differences[i]` = metrika_a[i] - metrika_b[i] pro stejny scenar i.
/// Nulove rozdily se vyrazuji (standardni konvence, snizuje n_effective).
/// Exaktni p-hodnota: za H0 (median rozdilu == 0) ma kazdy poradovy soucet nezavisle
/// 50% sanci na + nebo - znamenko - vyctem vsech 2^n kombinaci znamenek pro stejnou
/// multisadu poradi se zjisti presny podil kombinaci alespon tak extremnich jako
/// namereny statistik. Presne (ne normalni aproximace) pro n<=20, coz pokryva oba
/// nase pripady (n=13, n=6) - normalni aproximace by tu byla zbytecna nepresnost.
pub(crate) fn wilcoxon_signed_rank_test(differences: &[f64]) -> WilcoxonResult {
    let nonzero: Vec<f64> = differences
        .iter()
        .copied()
        .filter(|difference| *difference != 0.0)
        .collect();
    let n = nonzero.len();
    if n == 0 {
        return WilcoxonResult {
            n_effective: 0,
            w_statistic: 0.0,
            p_value_two_sided: 1.0,
        };
    }

    let mut abs_with_sign: Vec<(f64, f64)> = nonzero
        .iter()
        .map(|difference| (difference.abs(), difference.signum()))
        .collect();
    abs_with_sign.sort_by(|left, right| left.0.partial_cmp(&right.0).unwrap());

    let mut ranks = vec![0.0_f64; n];
    let mut index = 0;
    while index < n {
        let mut group_end = index + 1;
        while group_end < n && (abs_with_sign[group_end].0 - abs_with_sign[index].0).abs() < 1e-12 {
            group_end += 1;
        }
        let average_rank = ((index + 1 + group_end) as f64) / 2.0;
        for rank in &mut ranks[index..group_end] {
            *rank = average_rank;
        }
        index = group_end;
    }

    let w_plus: f64 = (0..n)
        .filter(|&k| abs_with_sign[k].1 > 0.0)
        .map(|k| ranks[k])
        .sum();
    let w_minus: f64 = (0..n)
        .filter(|&k| abs_with_sign[k].1 < 0.0)
        .map(|k| ranks[k])
        .sum();
    let w_statistic = w_plus.min(w_minus);

    let p_value_two_sided = if n <= 20 {
        let total_combinations = 1u32 << n;
        let mut extreme_count = 0u32;
        for mask in 0..total_combinations {
            let mut sum_plus = 0.0_f64;
            for (bit, &rank) in ranks.iter().enumerate() {
                if mask & (1 << bit) != 0 {
                    sum_plus += rank;
                }
            }
            let sum_minus: f64 = ranks.iter().sum::<f64>() - sum_plus;
            if sum_plus.min(sum_minus) <= w_statistic + 1e-9 {
                extreme_count += 1;
            }
        }
        (extreme_count as f64 / total_combinations as f64).min(1.0)
    } else {
        let mean = n as f64 * (n as f64 + 1.0) / 4.0;
        let variance = n as f64 * (n as f64 + 1.0) * (2.0 * n as f64 + 1.0) / 24.0;
        let z = ((w_statistic - mean).abs() - 0.5) / variance.sqrt();
        (2.0 * (1.0 - standard_normal_cdf(z))).min(1.0)
    };

    WilcoxonResult {
        n_effective: n,
        w_statistic,
        p_value_two_sided,
    }
}

/// Abramowitz-Stegun aproximace CDF standardni normalni distribuce (pouzita jen
/// jako fallback pro n>20, kde exaktni vycet 2^n kombinaci uz neni prakticky) -
/// presnost ~1e-7, dostatecna pro p-hodnotu, kterou nikdo necte na víc des. mist.
fn standard_normal_cdf(z: f64) -> f64 {
    let b1 = 0.319_381_530;
    let b2 = -0.356_563_782;
    let b3 = 1.781_477_937;
    let b4 = -1.821_255_978;
    let b5 = 1.330_274_429;
    let p = 0.231_641_9;
    let c = 0.398_942_280_4;

    let z_abs = z.abs();
    let t = 1.0 / (1.0 + p * z_abs);
    let poly = t * (b1 + t * (b2 + t * (b3 + t * (b4 + t * b5))));
    let density = c * (-z_abs * z_abs / 2.0).exp();
    let tail = density * poly;
    if z >= 0.0 { 1.0 - tail } else { tail }
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

    /// Skore, ktere NENESE zadnou informaci o labelu - 100 polozek se STEJNYM
    /// skore (0.5), z nich 10 pozitivnich. Vsech 100 je jedna vazana skupina -
    /// zpracovana najednou (po oprave 30.10.2026, viz modulova dokumentace
    /// `pr_auc`), jeden bod na krivce: precision=10/100=0.1 pri recall=1.0 ->
    /// AP=0.1=prevalence presne. Matematicky invariant (neinformativni skore =>
    /// AP==prevalence) platí bez ohledu na to, jak se vazby reseni - dobra
    /// nezavisla kontrola, ze skupinova oprava nezmenila spravnou hodnotu.
    #[test]
    fn pr_auc_of_uninformative_tied_score_equals_prevalence_exactly() {
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
            "rovnomerne vazane neinformativni skore musi dat presne prevalenci (0.1), dostal jsem {auc}"
        );
    }

    /// Audit nalez (30.10.2026): puvodni `pr_auc` zpracovavalo vazane skore po
    /// jednotlivych vzorcich, takze vysledek zavisel na poradi vstupu - u
    /// volajicich, co skore drzi v `HashMap` (`score_source_hosts`), se tim PR-AUC
    /// litoval mezi opakovanymi behy STEJNYCH dat (zmereno primo: 3 behy CTU-13
    /// testu daly ruzne hodnoty). Tenhle test primo overuje, ze 2 permutace
    /// STEJNEHO multisetu (score, label) dvojic se shodnym skore davaji BAJTOVE
    /// stejny vysledek.
    #[test]
    fn pr_auc_is_independent_of_input_order_within_tied_scores() {
        let order_a = vec![
            (1.0, true),
            (0.5, false),
            (0.5, true),
            (0.5, false),
            (0.5, true),
            (0.0, false),
        ];
        let mut order_b = order_a.clone();
        order_b.swap(1, 4);
        order_b.swap(2, 3);

        let auc_a = pr_auc(&order_a);
        let auc_b = pr_auc(&order_b);
        assert_eq!(
            auc_a, auc_b,
            "permutace vazanych skore nesmi zmenit PR-AUC: {auc_a} vs {auc_b}"
        );
    }

    /// Rucne overeny referencni pripad: 6 rozdilu, vsechny stejneho znamenka
    /// (zadne vazby v absolutni hodnote) -> jedine 2 ze 64 kombinaci znamenek
    /// (vsechny +, vsechny -) davaji min(W+,W-)=0, presne jako namereny
    /// statistik. p = 2/64 = 0.03125 presne.
    #[test]
    fn wilcoxon_monotonic_same_sign_differences_matches_hand_computed_exact_p() {
        let differences = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let result = wilcoxon_signed_rank_test(&differences);
        assert_eq!(result.n_effective, 6);
        assert!(
            (result.w_statistic - 0.0).abs() < 1e-9,
            "w_statistic={}",
            result.w_statistic
        );
        assert!(
            (result.p_value_two_sided - 2.0 / 64.0).abs() < 1e-9,
            "p={}",
            result.p_value_two_sided
        );
    }

    /// Rucne overeny protiprikald: rozdily presne vyvazene mezi + a - tak, ze
    /// W+ == W- == polovina celkoveho souctu poradi - matematicky invariant
    /// (min(x, total-x) <= total/2 pro KAZDOU podmnozinu) zarucuje, ze VSECH
    /// 2^n kombinaci je "aspon tak extremni", tedy p=1.0 presne, bez ohledu na
    /// konkretni rozdeleni poradi.
    #[test]
    fn wilcoxon_perfectly_balanced_signed_ranks_gives_exact_p_one() {
        let differences = vec![1.0, -1.0, 2.0, -2.0, 3.0, -3.0];
        let result = wilcoxon_signed_rank_test(&differences);
        assert_eq!(result.n_effective, 6);
        assert!(
            (result.w_statistic - 10.5).abs() < 1e-9,
            "w_statistic={} (ocekavano 10.5 = polovina celkoveho souctu poradi 21)",
            result.w_statistic
        );
        assert!(
            (result.p_value_two_sided - 1.0).abs() < 1e-9,
            "p={}",
            result.p_value_two_sided
        );
    }

    /// Nulove rozdily se vyrazuji (standardni konvence) - z 5 vstupu zbyvaji 3
    /// nenulove, n_effective musi klesnout na 3, ne zustat 5.
    #[test]
    fn wilcoxon_drops_zero_differences_and_reports_reduced_n_effective() {
        let differences = vec![0.0, 0.0, 1.0, -1.0, 2.0];
        let result = wilcoxon_signed_rank_test(&differences);
        assert_eq!(result.n_effective, 3);
    }

    #[test]
    fn wilcoxon_all_zero_differences_is_trivially_non_significant() {
        let differences = vec![0.0, 0.0, 0.0];
        let result = wilcoxon_signed_rank_test(&differences);
        assert_eq!(result.n_effective, 0);
        assert_eq!(result.p_value_two_sided, 1.0);
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
