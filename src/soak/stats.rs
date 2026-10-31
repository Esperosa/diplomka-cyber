//! Slucitelne agregaty soak behu. Vsechno, co jde do checkpointu a reportu, je tady:
//! pocitadla, histogramy, statistiky po rodinach utoku, FP, zasahy, identita,
//! invarianty. `merge` je asociativni a komutativni (poradi slevani bloku ani vlaken
//! nesmi zmenit vysledek - je to podminka reprodukovatelnosti).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::soak::hist::LogHistogram;

pub const TTD_BINS: usize = 24;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct FamilyStats {
    pub truth: u64,
    pub detected_any: u64,
    pub detected_typed: u64,
    /// Latence detekce v cyklech (posledni bin = "vic nez TTD_BINS-2").
    pub ttd_cycles: Vec<u64>,
    pub flows_emitted: u64,
    pub flows_blocked: u64,
    pub contained: u64,
    pub ttc_cycles: Vec<u64>,
    pub ids_visible: u64,
    pub ids_visible_detected: u64,
}

impl FamilyStats {
    pub fn bin(cycles: u32) -> usize {
        (cycles as usize).min(TTD_BINS - 1)
    }

    pub fn record_ttd(&mut self, cycles: u32) {
        if self.ttd_cycles.len() < TTD_BINS {
            self.ttd_cycles.resize(TTD_BINS, 0);
        }
        self.ttd_cycles[Self::bin(cycles)] += 1;
    }

    pub fn record_ttc(&mut self, cycles: u32) {
        if self.ttc_cycles.len() < TTD_BINS {
            self.ttc_cycles.resize(TTD_BINS, 0);
        }
        self.ttc_cycles[Self::bin(cycles)] += 1;
    }

    fn merge(&mut self, other: &FamilyStats) {
        self.truth += other.truth;
        self.detected_any += other.detected_any;
        self.detected_typed += other.detected_typed;
        self.flows_emitted += other.flows_emitted;
        self.flows_blocked += other.flows_blocked;
        self.contained += other.contained;
        self.ids_visible += other.ids_visible;
        self.ids_visible_detected += other.ids_visible_detected;
        merge_vec(&mut self.ttd_cycles, &other.ttd_cycles);
        merge_vec(&mut self.ttc_cycles, &other.ttc_cycles);
    }
}

fn merge_vec(mine: &mut Vec<u64>, theirs: &[u64]) {
    if mine.len() < theirs.len() {
        mine.resize(theirs.len(), 0);
    }
    for (index, value) in theirs.iter().enumerate() {
        mine[index] += value;
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LookalikeStats {
    pub occurrences: u64,
    /// Behavioralni nalez pripsatelny jen tomuto benignimu jevu (tvrdy FP).
    pub fp_findings: u64,
    pub occurrences_with_fp: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EnforcementStats {
    pub proposed: u64,
    pub rejected_guard: u64,
    pub duplicates: u64,
    pub approved: u64,
    pub rejected_operator: u64,
    pub applied: u64,
    pub failed: u64,
    pub expired: u64,
    pub drift_removed: u64,
    pub drift_missing: u64,
    pub sweep_failed: u64,
    pub operator_error_attempts: u64,
    pub operator_error_blocked_by_guard: u64,
    /// Chybne zablokovane legitimni IP (kolaterala) - flows, ktere kernel zahodil.
    pub collateral_flows: u64,
    pub benign_flows_total: u64,
    pub kernel_faults: u64,
    pub kernel_cmd_failed: u64,
    pub protected_in_kernel_violations: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct VerificationStats {
    pub plans: u64,
    pub executed: u64,
    pub reused: u64,
    pub needs_approval: u64,
    pub skipped_budget: u64,
    pub skipped_scope: u64,
    pub failed: u64,
    pub budget_violations: u64,
    pub approval_violations: u64,
    pub scope_violations: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct IdentityStats {
    pub devices: u64,
    pub devices_false_split: u64,
    pub asset_ids: u64,
    pub asset_ids_false_merge: u64,
    pub ambiguous_flagged: u64,
    pub churn_events: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ExposureStats {
    pub expected: u64,
    pub found: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct LearningStats {
    /// Pocet predikci `probability` s dostupnou ground truth.
    pub predictions: u64,
    pub brier_sum: f64,
    /// Brier naivni predikce "vzdy 0,5" na stejnych vzorcich (reference).
    pub baseline_brier_sum: f64,
    pub bins_n: Vec<u64>,
    pub bins_pos: Vec<u64>,
    pub bins_psum: Vec<f64>,
    /// Brier podle poctu efektivnich pripadu v pameti (0-9, 10-29, 30-99, 100+).
    pub by_cases_n: Vec<u64>,
    pub by_cases_brier: Vec<f64>,
    pub verdicts_recorded: u64,
    pub cases_accepted: u64,
    pub cases_quarantined: u64,
    pub poison_episodes: u64,
    pub poison_submitted: u64,
    pub poison_quarantined: u64,
    pub flagged_sources: u64,
    pub honest_quarantined: u64,
}

impl LearningStats {
    pub fn case_bin(effective: f64) -> usize {
        match effective {
            e if e < 10.0 => 0,
            e if e < 30.0 => 1,
            e if e < 100.0 => 2,
            _ => 3,
        }
    }

    pub fn record_prediction(&mut self, probability: f64, label: bool, effective_cases: f64) {
        if self.bins_n.len() < 10 {
            self.bins_n.resize(10, 0);
            self.bins_pos.resize(10, 0);
            self.bins_psum.resize(10, 0.0);
        }
        if self.by_cases_n.len() < 4 {
            self.by_cases_n.resize(4, 0);
            self.by_cases_brier.resize(4, 0.0);
        }
        let outcome = if label { 1.0 } else { 0.0 };
        let error = (probability - outcome).powi(2);
        self.predictions += 1;
        self.brier_sum += error;
        self.baseline_brier_sum += (0.5 - outcome).powi(2);
        let bin = ((probability * 10.0) as usize).min(9);
        self.bins_n[bin] += 1;
        self.bins_pos[bin] += label as u64;
        self.bins_psum[bin] += probability;
        let case_bin = Self::case_bin(effective_cases);
        self.by_cases_n[case_bin] += 1;
        self.by_cases_brier[case_bin] += error;
    }

    fn merge(&mut self, other: &LearningStats) {
        self.predictions += other.predictions;
        self.brier_sum += other.brier_sum;
        self.baseline_brier_sum += other.baseline_brier_sum;
        merge_vec(&mut self.bins_n, &other.bins_n);
        merge_vec(&mut self.bins_pos, &other.bins_pos);
        merge_vec(&mut self.by_cases_n, &other.by_cases_n);
        if self.bins_psum.len() < other.bins_psum.len() {
            self.bins_psum.resize(other.bins_psum.len(), 0.0);
        }
        for (i, v) in other.bins_psum.iter().enumerate() {
            self.bins_psum[i] += v;
        }
        if self.by_cases_brier.len() < other.by_cases_brier.len() {
            self.by_cases_brier.resize(other.by_cases_brier.len(), 0.0);
        }
        for (i, v) in other.by_cases_brier.iter().enumerate() {
            self.by_cases_brier[i] += v;
        }
        self.verdicts_recorded += other.verdicts_recorded;
        self.cases_accepted += other.cases_accepted;
        self.cases_quarantined += other.cases_quarantined;
        self.poison_episodes += other.poison_episodes;
        self.poison_submitted += other.poison_submitted;
        self.poison_quarantined += other.poison_quarantined;
        self.flagged_sources += other.flagged_sources;
        self.honest_quarantined += other.honest_quarantined;
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Aggregate {
    pub networks: u64,
    pub episodes: u64,
    pub cycles: u64,
    pub observations: u64,
    pub alerts: u64,
    pub events: u64,
    pub findings: u64,
    pub hypotheses: u64,
    pub virtual_hours: f64,
    pub outage_cycles: u64,
    pub families: BTreeMap<String, FamilyStats>,
    pub lookalikes: BTreeMap<String, LookalikeStats>,
    /// Behavioralni nalezy bez pripsatelne pricinu (cisty sum) podle typu.
    pub fp_noise_by_type: BTreeMap<String, u64>,
    pub fp_noise: u64,
    /// Behavioralni nalezy pripsatelne utoku (TP na urovni nalezu).
    pub behavioral_tp: u64,
    pub quiet_network_days: f64,
    pub exposure: ExposureStats,
    pub enforcement: EnforcementStats,
    pub verification: VerificationStats,
    pub identity: IdentityStats,
    pub learning: LearningStats,
    pub perf: BTreeMap<String, LogHistogram>,
    pub invariant_violations: BTreeMap<String, u64>,
    pub violation_samples: Vec<String>,
    pub panics: u64,
    pub panic_samples: Vec<String>,
    pub archetypes: BTreeMap<String, u64>,
}

const SAMPLE_CAP: usize = 100;

impl Aggregate {
    pub fn family(&mut self, label: &str) -> &mut FamilyStats {
        self.families.entry(label.to_string()).or_default()
    }

    pub fn perf_record(&mut self, stage: &str, seconds: f64) {
        self.perf
            .entry(stage.to_string())
            .or_default()
            .record(seconds);
    }

    pub fn violation(&mut self, name: &str, detail: String) {
        *self
            .invariant_violations
            .entry(name.to_string())
            .or_default() += 1;
        if self.violation_samples.len() < SAMPLE_CAP {
            self.violation_samples.push(format!("{name}: {detail}"));
        }
    }

    pub fn merge(&mut self, other: &Aggregate) {
        self.networks += other.networks;
        self.episodes += other.episodes;
        self.cycles += other.cycles;
        self.observations += other.observations;
        self.alerts += other.alerts;
        self.events += other.events;
        self.findings += other.findings;
        self.hypotheses += other.hypotheses;
        self.virtual_hours += other.virtual_hours;
        self.outage_cycles += other.outage_cycles;
        self.fp_noise += other.fp_noise;
        self.behavioral_tp += other.behavioral_tp;
        self.quiet_network_days += other.quiet_network_days;
        self.panics += other.panics;
        for (key, value) in &other.families {
            self.families.entry(key.clone()).or_default().merge(value);
        }
        for (key, value) in &other.lookalikes {
            let mine = self.lookalikes.entry(key.clone()).or_default();
            mine.occurrences += value.occurrences;
            mine.fp_findings += value.fp_findings;
            mine.occurrences_with_fp += value.occurrences_with_fp;
        }
        for (key, value) in &other.fp_noise_by_type {
            *self.fp_noise_by_type.entry(key.clone()).or_default() += value;
        }
        for (key, value) in &other.invariant_violations {
            *self.invariant_violations.entry(key.clone()).or_default() += value;
        }
        for (key, value) in &other.archetypes {
            *self.archetypes.entry(key.clone()).or_default() += value;
        }
        for (key, value) in &other.perf {
            self.perf.entry(key.clone()).or_default().merge(value);
        }
        for sample in &other.violation_samples {
            if self.violation_samples.len() < SAMPLE_CAP {
                self.violation_samples.push(sample.clone());
            }
        }
        for sample in &other.panic_samples {
            if self.panic_samples.len() < SAMPLE_CAP {
                self.panic_samples.push(sample.clone());
            }
        }
        self.exposure.expected += other.exposure.expected;
        self.exposure.found += other.exposure.found;
        let (e, o) = (&mut self.enforcement, &other.enforcement);
        e.proposed += o.proposed;
        e.rejected_guard += o.rejected_guard;
        e.duplicates += o.duplicates;
        e.approved += o.approved;
        e.rejected_operator += o.rejected_operator;
        e.applied += o.applied;
        e.failed += o.failed;
        e.expired += o.expired;
        e.drift_removed += o.drift_removed;
        e.drift_missing += o.drift_missing;
        e.sweep_failed += o.sweep_failed;
        e.operator_error_attempts += o.operator_error_attempts;
        e.operator_error_blocked_by_guard += o.operator_error_blocked_by_guard;
        e.collateral_flows += o.collateral_flows;
        e.benign_flows_total += o.benign_flows_total;
        e.kernel_faults += o.kernel_faults;
        e.kernel_cmd_failed += o.kernel_cmd_failed;
        e.protected_in_kernel_violations += o.protected_in_kernel_violations;
        let (v, w) = (&mut self.verification, &other.verification);
        v.plans += w.plans;
        v.executed += w.executed;
        v.reused += w.reused;
        v.needs_approval += w.needs_approval;
        v.skipped_budget += w.skipped_budget;
        v.skipped_scope += w.skipped_scope;
        v.failed += w.failed;
        v.budget_violations += w.budget_violations;
        v.approval_violations += w.approval_violations;
        v.scope_violations += w.scope_violations;
        self.learning.merge(&other.learning);
        let (i, j) = (&mut self.identity, &other.identity);
        i.devices += j.devices;
        i.devices_false_split += j.devices_false_split;
        i.asset_ids += j.asset_ids;
        i.asset_ids_false_merge += j.asset_ids_false_merge;
        i.ambiguous_flagged += j.ambiguous_flagged;
        i.churn_events += j.churn_events;
    }

    /// Stabilni otisk vsech DETERMINISTICKYCH poli (bez perf/casu) - dukaz
    /// reprodukovatelnosti bloku v `soak verify`.
    pub fn deterministic_digest(&self) -> u64 {
        let mut clone = self.clone();
        clone.perf.clear();
        let json = serde_json::to_string(&clone).expect("serializace agregatu");
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in json.bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
        hash
    }
}

/// Wilsonuv 95% interval pro podil `k/n` (spolehlivy i pro male n a extremni podily).
pub fn wilson(k: u64, n: u64) -> (f64, f64, f64) {
    if n == 0 {
        return (0.0, 0.0, 0.0);
    }
    let z = 1.959_963_984_540_054_f64;
    let n_f = n as f64;
    let p = k as f64 / n_f;
    let denom = 1.0 + z * z / n_f;
    let center = (p + z * z / (2.0 * n_f)) / denom;
    let margin = z * ((p * (1.0 - p) / n_f) + z * z / (4.0 * n_f * n_f)).sqrt() / denom;
    // Presne meze pri k=0 / k=n (jinak plovouci desetinna chyba dava ~1e-17 misto 0).
    let lo = if k == 0 {
        0.0
    } else {
        (center - margin).max(0.0)
    };
    let hi = if k == n {
        1.0
    } else {
        (center + margin).min(1.0)
    };
    (p, lo, hi)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wilson_matches_known_reference_values() {
        // 8/10 -> (0.490, 0.943) podle standardni tabulky Wilsonova intervalu.
        let (p, lo, hi) = wilson(8, 10);
        assert!((p - 0.8).abs() < 1e-12);
        assert!((lo - 0.4902).abs() < 5e-4, "{lo}");
        assert!((hi - 0.9433).abs() < 5e-4, "{hi}");
        let (_, lo0, hi0) = wilson(0, 50);
        assert_eq!(lo0, 0.0);
        assert!(hi0 > 0.05 && hi0 < 0.08, "{hi0}");
        assert_eq!(wilson(0, 0), (0.0, 0.0, 0.0));
    }

    #[test]
    fn merge_is_commutative_and_associative_on_counters_and_histograms() {
        let make = |seed: u64| {
            let mut a = Aggregate::default();
            a.networks = seed;
            a.cycles = seed * 3;
            a.family("ssh").truth = seed;
            a.family("ssh").record_ttd(seed as u32);
            a.perf_record("engine", seed as f64 * 1e-3);
            a.enforcement.applied = seed;
            a.violation("x", format!("v{seed}"));
            a
        };
        let (a, b, c) = (make(1), make(2), make(3));
        let mut left = a.clone();
        left.merge(&b);
        left.merge(&c);
        let mut right = c.clone();
        right.merge(&b);
        right.merge(&a);
        assert_eq!(
            left.deterministic_digest_without_samples(),
            right.deterministic_digest_without_samples()
        );
        assert_eq!(left.networks, 6);
        assert_eq!(left.invariant_violations["x"], 3);
    }

    impl Aggregate {
        fn deterministic_digest_without_samples(&self) -> u64 {
            let mut clone = self.clone();
            clone.violation_samples.clear();
            clone.panic_samples.clear();
            clone.deterministic_digest()
        }
    }

    #[test]
    fn digest_ignores_perf_but_not_counters() {
        let mut a = Aggregate::default();
        let mut b = Aggregate::default();
        a.perf_record("engine", 0.1);
        b.perf_record("engine", 9.0);
        assert_eq!(a.deterministic_digest(), b.deterministic_digest());
        b.cycles = 1;
        assert_ne!(a.deterministic_digest(), b.deterministic_digest());
    }

    #[test]
    fn ttd_bins_saturate_into_last_bin() {
        let mut f = FamilyStats::default();
        f.record_ttd(0);
        f.record_ttd(5);
        f.record_ttd(500);
        assert_eq!(f.ttd_cycles[0], 1);
        assert_eq!(f.ttd_cycles[5], 1);
        assert_eq!(f.ttd_cycles[TTD_BINS - 1], 1);
    }
}
