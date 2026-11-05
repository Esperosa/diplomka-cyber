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
    /// Detekce jen ze ZOBRAZENYCH polozek (co skutecne uvidi clovek); legacy = vse.
    #[serde(default)]
    pub detected_displayed: u64,
    #[serde(default)]
    pub typed_displayed: u64,
    /// Placebo okna (stejne klicove IP, posunuty cas bez utoku): mira nahodne shody.
    #[serde(default)]
    pub placebo_windows: u64,
    #[serde(default)]
    pub placebo_hits_captured: u64,
    #[serde(default)]
    pub placebo_hits_displayed: u64,
    /// Detekce (zobrazene) jen u utoku, ktere maji placebo okno: stejna podmnozina
    /// jako `placebo_hits_*`, takze rozdil = detekce nad pozadim.
    #[serde(default)]
    pub placebo_detected_displayed: u64,
    #[serde(default)]
    pub placebo_detected_captured: u64,
    /// Kontrafaktualni atribuce (krok 2A): utoky s emisi a z nich detekovane nalezem,
    /// ktery ve svete bez utoku chybi (`_strict` = chybi i v sousednich cyklech).
    #[serde(default)]
    pub cf_attacks: u64,
    #[serde(default)]
    pub cf_detected: u64,
    #[serde(default)]
    pub cf_detected_strict: u64,
    #[serde(default)]
    pub cf_detected_displayed: u64,
    #[serde(default)]
    pub cf_detected_displayed_strict: u64,
    #[serde(default)]
    pub cf_typed: u64,
    #[serde(default)]
    pub cf_typed_displayed: u64,
    #[serde(default)]
    pub loo_n: u64,
    #[serde(default)]
    pub loo_detected_displayed: u64,
    #[serde(default)]
    pub loo_all_detected_displayed: u64,
    #[serde(default)]
    pub loo_agree: u64,
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
        self.detected_displayed += other.detected_displayed;
        self.typed_displayed += other.typed_displayed;
        self.placebo_windows += other.placebo_windows;
        self.placebo_hits_captured += other.placebo_hits_captured;
        self.placebo_hits_displayed += other.placebo_hits_displayed;
        self.placebo_detected_displayed += other.placebo_detected_displayed;
        self.placebo_detected_captured += other.placebo_detected_captured;
        self.cf_attacks += other.cf_attacks;
        self.cf_detected += other.cf_detected;
        self.cf_detected_strict += other.cf_detected_strict;
        self.cf_detected_displayed += other.cf_detected_displayed;
        self.cf_detected_displayed_strict += other.cf_detected_displayed_strict;
        self.cf_typed += other.cf_typed;
        self.cf_typed_displayed += other.cf_typed_displayed;
        self.loo_n += other.loo_n;
        self.loo_detected_displayed += other.loo_detected_displayed;
        self.loo_all_detected_displayed += other.loo_all_detected_displayed;
        self.loo_agree += other.loo_agree;
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

/// Zobrazene polozky a "tri skupiny vystupu" (00-zaver Dodatek A.1):
/// zachyceno / automaticky vyreseno / ceka na cloveka; plus mira "zavreno omylem".
/// Stav = odlisny nalez (stejne `finding_id`, mezera bez vyskytu <= 12 cyklu), ne nalez x cyklus.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct OutputStats {
    /// Polozky zobrazene cloveku (legacy: kazdy nalez v kazdem cyklu).
    pub displayed: u64,
    pub displayed_behavioral: u64,
    /// Zobrazene behavioralni polozky bez pripsatelne priciny (falesny poplach).
    pub displayed_fp: u64,
    /// Krok 6: z toho ve fronte podezreni (bez tridy provozni problem).
    pub displayed_fp_suspect: u64,
    /// Krok 6: zobrazene polozky zarazene do fronty provoz (`ops_class`).
    pub ops_class_displayed: u64,
    pub displayed_by_reason: BTreeMap<String, u64>,
    pub states_captured: u64,
    pub states_behavioral: u64,
    pub states_fp: u64,
    pub states_auto_resolved: u64,
    pub states_awaiting_human: u64,
    pub states_awaiting_human_fp: u64,
    pub states_collected_only: u64,
    /// Automaticka zavreni (pozorovani) a z nich zavreno omylem (pripsano utoku).
    pub auto_closures: u64,
    pub auto_closures_wrong: u64,
    pub auto_closures_by_reason: BTreeMap<String, u64>,
    pub auto_closures_wrong_by_reason: BTreeMap<String, u64>,
    /// Zavreno omylem PRICINNE: utok v tomto cyklu posilal toky na cil nalezu nebo z jeho
    /// dominantniho zdroje (sirsi `auto_closures_wrong` = nalez jen zminuje klicovou IP).
    pub auto_closures_wrong_causal: u64,
    /// Zavreno omylem KONTRAFAKTUALNE (sjednocena definice kroku 3, stejna jako
    /// `ladder_refuted_wrong_cf`): uzavreny nalez ve svete bez utoku chybi.
    pub auto_closures_wrong_cf: u64,
    pub audit_wrong_causal: u64,
    /// Zavreno omylem podle `duvod|typ nalezu|rodina utoku` (diagnostika).
    pub auto_closures_wrong_detail: BTreeMap<String, u64>,
    /// Nahodny audit vzorku automaticky zavrenych (simulovany clovek, 10 %).
    pub audit_sampled: u64,
    pub audit_wrong: u64,
    pub memory_peak_entries: u64,
    pub memory_evicted: u64,
    /// Žebřík ověřování (krok 2B): případy, kontroly, rozpočet, rozhodnutí a jejich
    /// správnost proti kontrafaktuálu (`_attack` = nález způsobil útok).
    pub ladder_cases: u64,
    pub ladder_merged: u64,
    pub ladder_checks: u64,
    pub ladder_checks_deferred: u64,
    pub ladder_cases_deferred: u64,
    pub ladder_needs_approval: u64,
    pub ladder_open_at_end: u64,
    pub ladder_liveness_runs: u64,
    pub ladder_liveness_failures: u64,
    pub ladder_confirmed: u64,
    pub ladder_refuted: u64,
    pub ladder_escalated: u64,
    pub ladder_escalated_budget: u64,
    pub ladder_refuted_wrong_cf: u64,
    pub ladder_refuted_wrong_causal: u64,
    pub ladder_confirmed_attack: u64,
    pub ladder_escalated_attack: u64,
    pub ladder_decided_attack: u64,
    pub ladder_latency_sum: u64,
    pub ladder_audit_sampled: u64,
    pub ladder_audit_wrong: u64,
    pub ladder_latency_max: u64,
    /// Výsledky kontrol rozhodnutých případů podle pravdy: "kontrola:značka|attack|benign".
    pub ladder_outcome_truth: BTreeMap<String, u64>,
    /// Kalibrační koše (20) posteriory rozhodnutých behaviorálních případů proti
    /// kontrafaktuální pravdě: surová a použitá (po kalibraci) posteriora;
    /// [n, pozitivní, součet p, součet p²] na koš.
    pub calib_raw: Vec<[f64; 4]>,
    pub calib_used: Vec<[f64; 4]>,
    /// Rozpoznání typu zařízení proti roli v modelu (krok 2D, jen při skenu).
    pub device_classified: u64,
    pub device_class_correct: u64,
    pub device_class_confident: u64,
    pub ladder_checks_by_level: BTreeMap<String, u64>,
    pub ladder_outcomes: BTreeMap<String, u64>,
    pub ladder_refuted_by_type: BTreeMap<String, u64>,
    pub ladder_refuted_wrong_detail: BTreeMap<String, u64>,
    /// Behaviorální vrstva (krok 3): odchozí toky viděné / zahozené vzorkováním,
    /// nejvyšší úroveň vzorkování a počet řetězů A→B→C.
    pub egress_seen: u64,
    pub egress_dropped: u64,
    pub egress_sample_level_max: u64,
    pub behavior_chains: u64,
    /// Nálezy behaviorální vrstvy podle typu (všechny, ne jen falešné).
    pub behavior_findings_by_type: BTreeMap<String, u64>,
    /// Neškodné pravidelné vzory (krok 3, `--noise`): toky a falešné poplachy na nich
    /// (`vzor|typ nálezu`), všechny a zobrazené.
    pub regular_flows: u64,
    pub regular_fp: BTreeMap<String, u64>,
    pub regular_fp_displayed: BTreeMap<String, u64>,
    /// Krok 7: počítadla (chráněná automatická zavření, zobrazené chráněné, anotace
    /// třídy provoz, tiché potlačení); prázdné se nezapisuje (výstup kroku 6 beze změny).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub k7: BTreeMap<String, u64>,
}

impl OutputStats {
    /// Krok 7: přičte počítadlo.
    pub fn k7_add(&mut self, name: &str, value: u64) {
        *self.k7.entry(name.to_string()).or_default() += value;
    }

    fn merge(&mut self, o: &OutputStats) {
        merge_map(&mut self.k7, &o.k7);
        self.displayed += o.displayed;
        self.displayed_behavioral += o.displayed_behavioral;
        self.displayed_fp += o.displayed_fp;
        self.displayed_fp_suspect += o.displayed_fp_suspect;
        self.ops_class_displayed += o.ops_class_displayed;
        self.egress_seen += o.egress_seen;
        self.egress_dropped += o.egress_dropped;
        self.egress_sample_level_max = self.egress_sample_level_max.max(o.egress_sample_level_max);
        self.behavior_chains += o.behavior_chains;
        merge_map(
            &mut self.behavior_findings_by_type,
            &o.behavior_findings_by_type,
        );
        self.regular_flows += o.regular_flows;
        merge_map(&mut self.regular_fp, &o.regular_fp);
        merge_map(&mut self.regular_fp_displayed, &o.regular_fp_displayed);
        merge_map(&mut self.displayed_by_reason, &o.displayed_by_reason);
        self.states_captured += o.states_captured;
        self.states_behavioral += o.states_behavioral;
        self.states_fp += o.states_fp;
        self.states_auto_resolved += o.states_auto_resolved;
        self.states_awaiting_human += o.states_awaiting_human;
        self.states_awaiting_human_fp += o.states_awaiting_human_fp;
        self.states_collected_only += o.states_collected_only;
        self.auto_closures += o.auto_closures;
        self.auto_closures_wrong += o.auto_closures_wrong;
        merge_map(
            &mut self.auto_closures_by_reason,
            &o.auto_closures_by_reason,
        );
        merge_map(
            &mut self.auto_closures_wrong_by_reason,
            &o.auto_closures_wrong_by_reason,
        );
        merge_map(
            &mut self.auto_closures_wrong_detail,
            &o.auto_closures_wrong_detail,
        );
        self.audit_sampled += o.audit_sampled;
        self.auto_closures_wrong_causal += o.auto_closures_wrong_causal;
        self.auto_closures_wrong_cf += o.auto_closures_wrong_cf;
        self.audit_wrong_causal += o.audit_wrong_causal;
        self.audit_wrong += o.audit_wrong;
        self.memory_peak_entries = self.memory_peak_entries.max(o.memory_peak_entries);
        self.memory_evicted += o.memory_evicted;
        self.ladder_cases += o.ladder_cases;
        self.ladder_merged += o.ladder_merged;
        self.ladder_checks += o.ladder_checks;
        self.ladder_checks_deferred += o.ladder_checks_deferred;
        self.ladder_cases_deferred += o.ladder_cases_deferred;
        self.ladder_needs_approval += o.ladder_needs_approval;
        self.ladder_open_at_end += o.ladder_open_at_end;
        self.ladder_liveness_runs += o.ladder_liveness_runs;
        self.ladder_liveness_failures += o.ladder_liveness_failures;
        self.ladder_confirmed += o.ladder_confirmed;
        self.ladder_refuted += o.ladder_refuted;
        self.ladder_escalated += o.ladder_escalated;
        self.ladder_escalated_budget += o.ladder_escalated_budget;
        self.ladder_refuted_wrong_cf += o.ladder_refuted_wrong_cf;
        self.ladder_refuted_wrong_causal += o.ladder_refuted_wrong_causal;
        self.ladder_confirmed_attack += o.ladder_confirmed_attack;
        self.ladder_escalated_attack += o.ladder_escalated_attack;
        self.ladder_decided_attack += o.ladder_decided_attack;
        self.ladder_latency_sum += o.ladder_latency_sum;
        self.ladder_audit_sampled += o.ladder_audit_sampled;
        self.ladder_audit_wrong += o.ladder_audit_wrong;
        self.ladder_latency_max = self.ladder_latency_max.max(o.ladder_latency_max);
        merge_map(&mut self.ladder_outcome_truth, &o.ladder_outcome_truth);
        merge_bins(&mut self.calib_raw, &o.calib_raw);
        merge_bins(&mut self.calib_used, &o.calib_used);
        self.device_classified += o.device_classified;
        self.device_class_correct += o.device_class_correct;
        self.device_class_confident += o.device_class_confident;
        merge_map(&mut self.ladder_checks_by_level, &o.ladder_checks_by_level);
        merge_map(&mut self.ladder_outcomes, &o.ladder_outcomes);
        merge_map(&mut self.ladder_refuted_by_type, &o.ladder_refuted_by_type);
        merge_map(
            &mut self.ladder_refuted_wrong_detail,
            &o.ladder_refuted_wrong_detail,
        );
    }
}

fn merge_bins(mine: &mut Vec<[f64; 4]>, theirs: &[[f64; 4]]) {
    if mine.len() < theirs.len() {
        mine.resize(theirs.len(), [0.0; 4]);
    }
    for (index, bin) in theirs.iter().enumerate() {
        for k in 0..4 {
            mine[index][k] += bin[k];
        }
    }
}

impl OutputStats {
    /// Zapíše predikci (surová a použitá posteriora) a výsledek do kalibračních košů.
    pub fn record_calibration(&mut self, raw: f64, used: f64, label: bool) {
        for (bins, p) in [(&mut self.calib_raw, raw), (&mut self.calib_used, used)] {
            if bins.len() < 20 {
                bins.resize(20, [0.0; 4]);
            }
            let p = p.clamp(0.0, 1.0);
            let bin = ((p * 20.0) as usize).min(19);
            bins[bin][0] += 1.0;
            bins[bin][1] += label as u8 as f64;
            bins[bin][2] += p;
            bins[bin][3] += p * p;
        }
    }
}

pub fn merge_map(mine: &mut BTreeMap<String, u64>, theirs: &BTreeMap<String, u64>) {
    for (key, value) in theirs {
        *mine.entry(key.clone()).or_default() += value;
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
    /// Plány odložené na další cyklus (stavová fronta, krok 2B).
    #[serde(default)]
    pub deferred: u64,
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
    /// Verdikty člověka k rozhodnutým případům žebříku (krok 2C) a z nich přijaté.
    #[serde(default)]
    pub ladder_verdicts: u64,
    #[serde(default)]
    pub ladder_verdicts_accepted: u64,
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
        self.ladder_verdicts += other.ladder_verdicts;
        self.ladder_verdicts_accepted += other.ladder_verdicts_accepted;
    }
}

/// Pokryti a kvalita po rezech (velikost site, archetyp, rodina x velikost).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SegmentStats {
    pub networks: u64,
    pub devices: u64,
    pub subnets: u64,
    pub virtual_days: f64,
    pub cycles: u64,
    pub observations: u64,
    pub findings: u64,
    pub attacks: u64,
    pub detected_any: u64,
    pub detected_typed: u64,
    pub fp_noise: u64,
    pub benign_events: u64,
    pub benign_with_fp: u64,
}

impl SegmentStats {
    fn merge(&mut self, o: &SegmentStats) {
        self.networks += o.networks;
        self.devices += o.devices;
        self.subnets += o.subnets;
        self.virtual_days += o.virtual_days;
        self.cycles += o.cycles;
        self.observations += o.observations;
        self.findings += o.findings;
        self.attacks += o.attacks;
        self.detected_any += o.detected_any;
        self.detected_typed += o.detected_typed;
        self.fp_noise += o.fp_noise;
        self.benign_events += o.benign_events;
        self.benign_with_fp += o.benign_with_fp;
    }
}

/// Provozni spolehlivost: restarty, pady zarizeni, patchovani, onboarding.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OpsStats {
    pub engine_restarts: u64,
    pub identity_lost_on_restart: u64,
    pub device_down_cycles: u64,
    pub patched_devices: u64,
    pub onboarded_devices: u64,
    pub decommissioned_devices: u64,
    pub stale_exposure_findings: u64,
    pub exposure_checks_after_patch: u64,
    pub tool_failures: u64,
    pub corrupt_alert_lines: u64,
    pub sensor_down_cycles: u64,
}

impl OpsStats {
    fn merge(&mut self, o: &OpsStats) {
        self.engine_restarts += o.engine_restarts;
        self.identity_lost_on_restart += o.identity_lost_on_restart;
        self.device_down_cycles += o.device_down_cycles;
        self.patched_devices += o.patched_devices;
        self.onboarded_devices += o.onboarded_devices;
        self.decommissioned_devices += o.decommissioned_devices;
        self.stale_exposure_findings += o.stale_exposure_findings;
        self.exposure_checks_after_patch += o.exposure_checks_after_patch;
        self.tool_failures += o.tool_failures;
        self.corrupt_alert_lines += o.corrupt_alert_lines;
        self.sensor_down_cycles += o.sensor_down_cycles;
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
    /// "size|<trida>", "arch|<archetyp>", "cell|<rodina>|<trida>", "dur|<hodiny>h".
    pub segments: BTreeMap<String, SegmentStats>,
    /// Pocet zarizeni podle role (pokryti typu zarizeni).
    pub roles: BTreeMap<String, u64>,
    /// Pocet sluzeb podle nazvu (pokryti serveru/protokolu).
    pub services: BTreeMap<String, u64>,
    pub ops: OpsStats,
    /// Rezim jadra, ktery tento agregat vyrobil (`legacy`, `v3[...]`).
    #[serde(default)]
    pub engine: String,
    #[serde(default)]
    pub output: OutputStats,
    /// Zobrazene falesne poplachy podle typu.
    #[serde(default)]
    pub displayed_fp_by_type: BTreeMap<String, u64>,
    /// Diagnostika R13: pricina FP `unexpected_traffic` / `unmapped_passive_event`.
    #[serde(default)]
    pub unexpected_causes: BTreeMap<String, u64>,
    /// Kontrafaktualne pripsane zobrazene typy nalezu: "rodina|typ" -> pocet utoku.
    #[serde(default)]
    pub cf_type_hits: BTreeMap<String, u64>,
}

const SAMPLE_CAP: usize = 100;

impl Aggregate {
    pub fn segment(&mut self, key: &str) -> &mut SegmentStats {
        self.segments.entry(key.to_string()).or_default()
    }

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
        for (key, value) in &other.segments {
            self.segments.entry(key.clone()).or_default().merge(value);
        }
        for (key, value) in &other.roles {
            *self.roles.entry(key.clone()).or_default() += value;
        }
        for (key, value) in &other.services {
            *self.services.entry(key.clone()).or_default() += value;
        }
        self.ops.merge(&other.ops);
        if self.engine.is_empty() {
            self.engine = other.engine.clone();
        } else if !other.engine.is_empty() && other.engine != self.engine {
            self.engine = format!("SMISENO({}|{})", self.engine, other.engine);
        }
        self.output.merge(&other.output);
        merge_map(&mut self.displayed_fp_by_type, &other.displayed_fp_by_type);
        merge_map(&mut self.unexpected_causes, &other.unexpected_causes);
        merge_map(&mut self.cf_type_hits, &other.cf_type_hits);
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
        v.deferred += w.deferred;
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

/// Pocty jedne rodiny v jedne siti (pro parove A/B po sitich).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct FamilyCounts {
    pub truth: u64,
    pub detected: u64,
    pub detected_displayed: u64,
    pub typed: u64,
    pub typed_displayed: u64,
    pub placebo_windows: u64,
    pub placebo_hits_displayed: u64,
    pub placebo_hits_captured: u64,
    pub placebo_detected_displayed: u64,
    pub placebo_detected_captured: u64,
    pub cf_attacks: u64,
    pub cf_detected: u64,
    pub cf_detected_strict: u64,
    pub cf_detected_displayed: u64,
    pub cf_detected_displayed_strict: u64,
    pub cf_typed: u64,
    pub cf_typed_displayed: u64,
    pub loo_n: u64,
    pub loo_detected_displayed: u64,
    pub loo_all_detected_displayed: u64,
    pub loo_agree: u64,
}

/// Souhrn jedne site (radek `networks.jsonl`): jednotka paroveho A/B a bootstrapu.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct NetworkSummary {
    pub run_seed: u64,
    pub network_id: u64,
    pub engine: String,
    pub archetype: String,
    pub size_class: String,
    pub devices: u64,
    pub virtual_days: f64,
    pub findings: u64,
    pub fp_noise: u64,
    pub output: OutputStats,
    pub fp_by_type: BTreeMap<String, u64>,
    pub displayed_fp_by_type: BTreeMap<String, u64>,
    pub families: BTreeMap<String, FamilyCounts>,
    pub cf_type_hits: BTreeMap<String, u64>,
    pub identity_devices: u64,
    pub identity_false_split: u64,
    pub identity_asset_ids: u64,
    pub identity_false_merge: u64,
    pub verification_plans: u64,
    pub verification_skipped_budget: u64,
    pub verification_executed: u64,
    pub panics: u64,
    pub violations: u64,
    pub cycle_p99_s: f64,
    /// Nedeterministicke (cas behu), mimo otisk.
    pub wall_s: f64,
    /// Svet site ve smisenem behu (krok 4, `--noise-mix`); jinak chybi.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub world: Option<NetworkWorld>,
    /// Svet pokryti (krok 5): zaznam o kazdem utoku a neskodne udalosti; jinak chybi.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attacks: Vec<crate::soak::coverage::AttackRecord>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub faults: Vec<crate::soak::coverage::FaultRecord>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct NetworkWorld {
    pub noise: f64,
    pub xxxl: bool,
    pub counterfactual: bool,
}

impl NetworkSummary {
    pub fn from_aggregate(agg: &Aggregate, run_seed: u64, network_id: u64) -> Self {
        let size = agg
            .segments
            .iter()
            .find_map(|(key, seg)| {
                key.strip_prefix("size|")
                    .map(|k| (k.to_string(), seg.devices))
            })
            .unwrap_or_default();
        let families = agg
            .families
            .iter()
            .filter(|(name, _)| !name.ends_with("__ranked"))
            .map(|(name, f)| {
                (
                    name.clone(),
                    FamilyCounts {
                        truth: f.truth,
                        detected: f.detected_any,
                        detected_displayed: f.detected_displayed,
                        typed: f.detected_typed,
                        typed_displayed: f.typed_displayed,
                        placebo_windows: f.placebo_windows,
                        placebo_hits_displayed: f.placebo_hits_displayed,
                        placebo_hits_captured: f.placebo_hits_captured,
                        placebo_detected_displayed: f.placebo_detected_displayed,
                        placebo_detected_captured: f.placebo_detected_captured,
                        cf_attacks: f.cf_attacks,
                        cf_detected: f.cf_detected,
                        cf_detected_strict: f.cf_detected_strict,
                        cf_detected_displayed: f.cf_detected_displayed,
                        cf_detected_displayed_strict: f.cf_detected_displayed_strict,
                        cf_typed: f.cf_typed,
                        cf_typed_displayed: f.cf_typed_displayed,
                        loo_n: f.loo_n,
                        loo_detected_displayed: f.loo_detected_displayed,
                        loo_all_detected_displayed: f.loo_all_detected_displayed,
                        loo_agree: f.loo_agree,
                    },
                )
            })
            .collect();
        Self {
            run_seed,
            network_id,
            engine: agg.engine.clone(),
            archetype: agg.archetypes.keys().next().cloned().unwrap_or_default(),
            size_class: size.0,
            devices: size.1,
            virtual_days: agg.virtual_hours / 24.0,
            findings: agg.findings,
            fp_noise: agg.fp_noise,
            output: agg.output.clone(),
            fp_by_type: agg.fp_noise_by_type.clone(),
            displayed_fp_by_type: agg.displayed_fp_by_type.clone(),
            families,
            cf_type_hits: agg.cf_type_hits.clone(),
            identity_devices: agg.identity.devices,
            identity_false_split: agg.identity.devices_false_split,
            identity_asset_ids: agg.identity.asset_ids,
            identity_false_merge: agg.identity.asset_ids_false_merge,
            verification_plans: agg.verification.plans,
            verification_skipped_budget: agg.verification.skipped_budget,
            verification_executed: agg.verification.executed,
            panics: agg.panics,
            violations: agg.invariant_violations.values().sum(),
            cycle_p99_s: agg
                .perf
                .get("cycle_total")
                .map(|h| h.percentile(0.99))
                .unwrap_or(0.0),
            wall_s: 0.0,
            world: None,
            attacks: Vec::new(),
            faults: Vec::new(),
        }
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

/// CPU cas aktualniho vlakna v sekundach (Windows, jinde 0). Rucni profil cyklu
/// (`BAKULA_SOAK_CYCLE_TRACE`): oddeli praci cyklu od cekani na zatizenem stroji.
pub fn thread_cpu_secs() -> f64 {
    #[cfg(windows)]
    {
        #[repr(C)]
        #[derive(Default, Clone, Copy)]
        struct FileTime {
            low: u32,
            high: u32,
        }
        unsafe extern "system" {
            fn GetCurrentThread() -> *mut core::ffi::c_void;
            fn GetThreadTimes(
                thread: *mut core::ffi::c_void,
                creation: *mut FileTime,
                exit: *mut FileTime,
                kernel: *mut FileTime,
                user: *mut FileTime,
            ) -> i32;
        }
        let (mut c, mut e, mut k, mut u) = Default::default();
        // SAFETY: pseudo-handle aktualniho vlakna, vystupni struktury jsou platne.
        let ok = unsafe { GetThreadTimes(GetCurrentThread(), &mut c, &mut e, &mut k, &mut u) };
        if ok == 0 {
            return 0.0;
        }
        let ticks = |t: FileTime| ((t.high as u64) << 32 | t.low as u64) as f64 * 1e-7;
        ticks(k) + ticks(u)
    }
    #[cfg(not(windows))]
    {
        0.0
    }
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
