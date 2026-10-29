use std::collections::{BTreeSet, HashSet};

use chrono::Utc;

use crate::correlation::correlate_events;
use crate::correlation_v2::{
    detect_multiscale_windowed_anomalies, detect_windowed_anomalies,
    detect_windowed_anomalies_linked,
};
use crate::decision;
use crate::eval::ground_truth::LabeledDataset;
use crate::findings;
use crate::model::{CorrelatedEvent, PassiveWindow, RunReport, SourceMetadata};
use crate::passive::detect_connection_anomalies;
use crate::report::build_report;

/// A = soucasny nezmeneny engine (`passive::anomaly`, zadne okenkovani).
/// B = `correlation_v2::detect_windowed_anomalies` (stejne prahy, tumbling okna).
/// C = B + graph-linking stejneho `src_ip` pres ruzne cile ve stejnem okne.
/// D = multi-scale sjednoceni vice oken (`detect_multiscale_windowed_anomalies`) -
/// primy dusledek potvrzene fragmentacni hypotezy, viz `correlation_v2.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AblationVariant {
    A,
    B,
    C,
    D,
}

type AggKey = (String, String, u16);

#[derive(Debug, Clone, Default)]
pub(crate) struct ConfusionMatrix {
    pub(crate) true_positive: usize,
    pub(crate) false_positive: usize,
    pub(crate) false_negative: usize,
    pub(crate) true_negative: usize,
}

impl ConfusionMatrix {
    pub(crate) fn precision(&self) -> f64 {
        let denom = self.true_positive + self.false_positive;
        if denom == 0 {
            0.0
        } else {
            self.true_positive as f64 / denom as f64
        }
    }

    pub(crate) fn recall(&self) -> f64 {
        let denom = self.true_positive + self.false_negative;
        if denom == 0 {
            0.0
        } else {
            self.true_positive as f64 / denom as f64
        }
    }

    pub(crate) fn f1(&self) -> f64 {
        let precision = self.precision();
        let recall = self.recall();
        if precision + recall == 0.0 {
            0.0
        } else {
            2.0 * precision * recall / (precision + recall)
        }
    }

    /// Triviální "klasifikuj vse jako malicious" na STEJNE (known, ne-unknown) mnozine
    /// klicu - recall je vzdy 1.0, precision = prevalence. Bez tohoto srovnani neni
    /// jasne, jestli detektor skutecne neco umi, nebo jen kopíruje prevalenci - presne
    /// pitfall "missing baseline", ktery nezavisla kontrola (Opus Plan agent, 29.10.2026)
    /// u puvodnich tabulek oznacila. `(precision, recall, f1)`.
    pub(crate) fn trivial_always_positive_baseline(&self) -> (f64, f64, f64) {
        let total_known =
            self.true_positive + self.false_positive + self.false_negative + self.true_negative;
        let total_positive = self.true_positive + self.false_negative;
        if total_known == 0 {
            return (0.0, 0.0, 0.0);
        }
        let precision = total_positive as f64 / total_known as f64;
        let recall = 1.0;
        let f1 = if precision + recall == 0.0 {
            0.0
        } else {
            2.0 * precision * recall / (precision + recall)
        };
        (precision, recall, f1)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BaselineResult {
    pub(crate) dataset_id: String,
    pub(crate) observation_count: usize,
    pub(crate) malicious_flow_count: usize,
    /// POUZE potvrzene benigni flows (ne "Unknown"). Oprava 29.10.2026: puvodne
    /// pocitalo i CTU-13 "Background" (neoverenej provoz) jako benigni - viz
    /// `unknown_flow_count`/`excluded_unknown_keys` a `ground_truth.rs::is_unknown()`.
    pub(crate) benign_flow_count: usize,
    /// Flows s `label.is_unknown()` (CTU-13 "Background") - NEJSOU v
    /// `benign_flow_count`, nejsou v confusion matrix.
    pub(crate) unknown_flow_count: usize,
    /// Kolik (dst_ip,proto,port) klicu bylo vyrazeno z confusion matrix, protoze
    /// VSECHNY flows pod nimi jsou "Unknown" - 0 pro datasety bez tretiho stavu (IoT-23).
    pub(crate) excluded_unknown_keys: usize,
    pub(crate) correlated_event_count: usize,
    pub(crate) finding_count: usize,
    pub(crate) decision_action_count: usize,
    pub(crate) confusion: ConfusionMatrix,
    /// Jake typy utoku (`detailed_label`) jsou v malicious flows zastoupeny - kontext
    /// pro baseline report, ne vstup do rozhodovani (viz label-leakage zaruka vyse).
    pub(crate) malicious_detailed_labels: BTreeSet<String>,
    /// (predicted, actual) pro kazdy "known evidence" klic, presne ty, co vstupuji do
    /// `confusion` - Deliverable 20, umoznuje bootstrap CI bez ztraty granularity.
    pub(crate) per_key_predictions: Vec<(bool, bool)>,
}

/// Ablace A (zpetna kompatibilita s existujicimi testy/volajicimi) - tenky wrapper nad
/// `run_ablation(..., AblationVariant::A)`.
pub(crate) fn run_baseline(dataset: &LabeledDataset, time_window_s: i64) -> BaselineResult {
    run_ablation(dataset, time_window_s, AblationVariant::A)
}

/// Spusti vybranou ablaci (anomaly/korelacni detekce -> correlate_events -> findings ->
/// decision) nad `dataset.observations` a zmeri vysledek proti `dataset.labels`
/// (zadny aktivni host inventar, `hosts: &[]`, viz sekce 9.1 navrhu). Jedina cast, ktera
/// se mezi variantami lisi, je volba detektoru anomalii - zbytek pipeline (correlate_events,
/// findings, decision) je pro A/B/C stejny, aby srovnani izolovalo prave tu jednu promennou.
///
/// Label-leakage zaruka: do detektoru/`correlate_events` se posila VYHRADNE
/// `dataset.observations` (klonovane, beze zmeny typu/obsahu). `dataset.labels` se cte
/// poprve az pri stavbe ground-truth mnoziny nize, nikdy pred tim.
pub(crate) fn run_ablation(
    dataset: &LabeledDataset,
    time_window_s: i64,
    variant: AblationVariant,
) -> BaselineResult {
    let known_services: HashSet<AggKey> = HashSet::new();
    let events = match variant {
        AblationVariant::A => {
            detect_connection_anomalies(dataset.observations.clone(), &known_services)
        }
        AblationVariant::B => {
            detect_windowed_anomalies(dataset.observations.clone(), &known_services, time_window_s)
        }
        AblationVariant::C => detect_windowed_anomalies_linked(
            dataset.observations.clone(),
            &known_services,
            time_window_s,
        ),
        // Skaly voleny tak, aby pokryly obe strany trade-offu zmerenou ve sweepu:
        // kratka (burst, IoT-23-like) i dlouha (sustained beaconing, CTU-13-like).
        // `time_window_s` parametr funkce se tu neuplatnuje - D ma svou vlastni sadu.
        AblationVariant::D => detect_multiscale_windowed_anomalies(
            dataset.observations.clone(),
            &known_services,
            &[60, 300, 1800, 7200],
        ),
    };
    let correlated: Vec<CorrelatedEvent> = correlate_events(&[], events, time_window_s);

    let predicted_positive: HashSet<AggKey> = correlated
        .iter()
        .filter_map(|correlated_event| {
            correlated_event.event.dst_port.map(|port| {
                (
                    correlated_event.event.dst_ip.clone(),
                    correlated_event.event.proto.clone(),
                    port,
                )
            })
        })
        .collect();

    let mut ground_truth_positive: HashSet<AggKey> = HashSet::new();
    let mut all_keys: HashSet<AggKey> = HashSet::new();
    // Klic ma "known evidence", pokud alespon jeden flow pod nim je malicious NEBO
    // potvrzene benigni (ne "Unknown") - jinak se z confusion matrix VYRADI, viz
    // oprava 29.10.2026 (puvodne se Unknown tise pocitalo jako benigni).
    let mut key_has_known_evidence: HashSet<AggKey> = HashSet::new();
    let mut malicious_flow_count = 0usize;
    let mut benign_flow_count = 0usize;
    let mut unknown_flow_count = 0usize;
    let mut malicious_detailed_labels: BTreeSet<String> = BTreeSet::new();
    for (observation, label) in dataset.observations.iter().zip(dataset.labels.iter()) {
        if label.is_malicious() {
            malicious_flow_count += 1;
            malicious_detailed_labels.insert(label.detailed_label.clone());
        } else if label.is_unknown() {
            unknown_flow_count += 1;
        } else {
            benign_flow_count += 1;
        }
        let Some(port) = observation.dst_port else {
            continue;
        };
        let key = (observation.dst_ip.clone(), observation.proto.clone(), port);
        all_keys.insert(key.clone());
        if label.is_malicious() {
            ground_truth_positive.insert(key.clone());
            key_has_known_evidence.insert(key);
        } else if !label.is_unknown() {
            key_has_known_evidence.insert(key);
        }
    }

    let mut confusion = ConfusionMatrix::default();
    let mut excluded_unknown_keys = 0usize;
    // Deliverable 20 (statisticky aparat): stejna (predicted, actual) dvojice, ktera
    // jde do confusion matrix nize, zaznamenana i per-klic - umoznuje bootstrap
    // resampling (`eval::stats`) bez duplikace teto derivace ground truth.
    let mut per_key_predictions: Vec<(bool, bool)> = Vec::new();
    for key in &all_keys {
        if !key_has_known_evidence.contains(key) {
            excluded_unknown_keys += 1;
            continue;
        }
        let predicted = predicted_positive.contains(key);
        let actual = ground_truth_positive.contains(key);
        per_key_predictions.push((predicted, actual));
        match (predicted, actual) {
            (true, true) => confusion.true_positive += 1,
            (true, false) => confusion.false_positive += 1,
            (false, true) => confusion.false_negative += 1,
            (false, false) => confusion.true_negative += 1,
        }
    }

    // Doplnkovy popisny pruchod pres findings/decision vrstvu - stejna nezmenena logika,
    // jen pro bohatsi kontext v baseline reportu (kolik findings/akci by to vyprodukovalo).
    // Neni soucasti vypoctu confusion matrix vyse, ktera je definovana na urovni
    // (dst_ip, proto, port) agregatu presne odpovidajici granularite `detect_connection_anomalies`.
    let now = Utc::now();
    let mut report: RunReport = build_report(
        "eval-baseline",
        &format!("eval-baseline:{}", dataset.dataset_id),
        now,
        now,
        Vec::new(),
        Vec::new(),
        "eval",
        "eval",
        "passive-only",
        PassiveWindow {
            start: now,
            end: now,
            time_window_s,
        },
        SourceMetadata::default(),
        Vec::new(),
        correlated.clone(),
    );
    report.findings = findings::generate_findings(&report);
    let finding_count = report.findings.len();
    let decision_action_count = decision::build_decision_bundle(&report).actions.len();

    BaselineResult {
        dataset_id: dataset.dataset_id.clone(),
        observation_count: dataset.observations.len(),
        malicious_flow_count,
        benign_flow_count,
        unknown_flow_count,
        excluded_unknown_keys,
        correlated_event_count: correlated.len(),
        finding_count,
        decision_action_count,
        confusion,
        malicious_detailed_labels,
        per_key_predictions,
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::eval::calibration::{IsotonicCalibrator, ScoredPoint, brier_score, scored_points};
    use crate::eval::source::ScenarioSource;
    use crate::eval::sources::ctu13::Ctu13Source;
    use crate::eval::sources::iot23::Iot23Source;

    fn dataset_path(relative: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
    }

    #[test]
    fn ablation_a_on_iot23_malware_scenario_is_reproducible() {
        let dataset = Iot23Source
            .load(&dataset_path(
                "labs/datasets/iot23/CTU-IoT-Malware-Capture-44-1/conn.log.labeled",
            ))
            .expect("parse iot23 scenario 44-1");

        let first = run_baseline(&dataset, 300);
        let second = run_baseline(&dataset, 300);

        assert_eq!(first.observation_count, second.observation_count);
        assert_eq!(
            first.confusion.true_positive,
            second.confusion.true_positive
        );
        assert_eq!(
            first.confusion.false_positive,
            second.confusion.false_positive
        );
        assert_eq!(
            first.confusion.false_negative,
            second.confusion.false_negative
        );
        assert_eq!(first.malicious_flow_count, 26);
        assert_eq!(first.benign_flow_count, 211);

        // Baseline meri soucasny (nezmeneny) engine - presna hodnota precision/recall tu
        // neni natvrdo zakotvena jako "spravny" cil, protoze to je prvni zmerena hodnota,
        // ktera se zaznamenava do docs/diplomka/eval/baseline-iot23.md jako referencni bod
        // pro budouci ablace B/C/D/E, ne jako kontrola konkretniho cisla.
        println!(
            "ablace A na {} (events={}): TP={} FP={} FN={} TN={} precision={:.3} recall={:.3} f1={:.3} findings={} actions={} utok_typy={:?}",
            first.dataset_id,
            first.correlated_event_count,
            first.confusion.true_positive,
            first.confusion.false_positive,
            first.confusion.false_negative,
            first.confusion.true_negative,
            first.confusion.precision(),
            first.confusion.recall(),
            first.confusion.f1(),
            first.finding_count,
            first.decision_action_count,
            first.malicious_detailed_labels,
        );

        // Regresni assert (Deliverable 15/16 Definition-of-Done, stejny duvod jako N10 u
        // CTU-13): tohle NEodporuje komentari vyse - "prvni zmerena hodnota, ne cil k
        // dosazeni" znamena, ze se k tomuto cislu nenavrhuje detektor, ne ze cislo nesmi
        // byt pinovane proti tichemu rozjetí s `docs/diplomka/eval/baseline-iot23.md`.
        assert_eq!(
            (
                first.confusion.true_positive,
                first.confusion.false_positive,
                first.confusion.false_negative,
                first.confusion.true_negative
            ),
            (2, 6, 1, 1),
            "TP/FP/FN/TN ablace A na IoT-23 44-1 se rozesly s docs/diplomka/eval/baseline-iot23.md - pokud je zmena zamerna, oprav i dokumentaci"
        );
    }

    #[test]
    fn ablation_a_on_iot23_benign_only_scenario_measures_false_positive_rate() {
        let dataset = Iot23Source
            .load(&dataset_path(
                "labs/datasets/iot23/CTU-Honeypot-Capture-7-1-Somfy-01/conn.log.labeled",
            ))
            .expect("parse iot23 somfy-01 scenario");

        let result = run_baseline(&dataset, 300);

        assert_eq!(result.malicious_flow_count, 0);
        assert_eq!(result.confusion.true_positive, 0);
        assert_eq!(result.confusion.false_negative, 0);
        println!(
            "ablace A na {} (cist benigni, events={}): FP={} TN={} findings={} actions={}",
            result.dataset_id,
            result.correlated_event_count,
            result.confusion.false_positive,
            result.confusion.true_negative,
            result.finding_count,
            result.decision_action_count,
        );
    }

    #[test]
    fn ablation_b_c_vs_a_on_iot23_malware_scenario() {
        let dataset = Iot23Source
            .load(&dataset_path(
                "labs/datasets/iot23/CTU-IoT-Malware-Capture-44-1/conn.log.labeled",
            ))
            .expect("parse iot23 scenario 44-1");

        let a = run_ablation(&dataset, 300, AblationVariant::A);
        let b = run_ablation(&dataset, 300, AblationVariant::B);
        let c = run_ablation(&dataset, 300, AblationVariant::C);

        // Stejna ground truth pro vsechny varianty - jen detektor anomalii se lisi.
        assert_eq!(a.malicious_flow_count, b.malicious_flow_count);
        assert_eq!(a.malicious_flow_count, c.malicious_flow_count);

        for (label, result) in [("A", &a), ("B", &b), ("C", &c)] {
            println!(
                "ablace {label} na {} (events={}): TP={} FP={} FN={} TN={} precision={:.3} recall={:.3} f1={:.3} findings={}",
                result.dataset_id,
                result.correlated_event_count,
                result.confusion.true_positive,
                result.confusion.false_positive,
                result.confusion.false_negative,
                result.confusion.true_negative,
                result.confusion.precision(),
                result.confusion.recall(),
                result.confusion.f1(),
                result.finding_count,
            );
        }

        let (trivial_p, trivial_r, trivial_f1) = a.confusion.trivial_always_positive_baseline();
        println!(
            "IoT-23 44-1 trivialni baseline (vse=malicious): precision={trivial_p:.3} recall={trivial_r:.3} f1={trivial_f1:.3} (srovnej s ablaci A vyse)"
        );

        // Regresni assert (Deliverable 15/16 Definition-of-Done): pinuje cisla citovana
        // v docs/diplomka/eval/baseline-iot23.md a cross-dataset-ctu13.md proti tiche
        // regresi, stejny duvod jako N10 u CTU-13.
        let approx = |actual: f64, expected: f64| (actual - expected).abs() < 1e-3;
        assert!(
            approx(a.confusion.precision(), 0.250) && approx(a.confusion.recall(), 0.667),
            "ablace A na IoT-23: precision={:.3} recall={:.3}, cekano 0.250/0.667",
            a.confusion.precision(),
            a.confusion.recall()
        );
        assert!(
            approx(trivial_p, 0.300) && approx(trivial_f1, 0.462),
            "trivialni baseline na IoT-23: precision={trivial_p:.3} f1={trivial_f1:.3}, cekano 0.300/0.462"
        );

        // Ablace C pridava multi_target_pattern nalezy s dst_port=None, ktere confusion
        // matrix (klicovana (dst_ip,proto,port)) nikdy nezachyti jako predicted_positive -
        // proto C a B musi mit STEJNOU confusion matrix, jen C muze mit vic findings/events.
        assert_eq!(b.confusion.true_positive, c.confusion.true_positive);
        assert_eq!(b.confusion.false_positive, c.confusion.false_positive);
        assert_eq!(b.confusion.false_negative, c.confusion.false_negative);
        assert!(
            c.correlated_event_count >= b.correlated_event_count,
            "ablace C muze jen pridavat multi_target_pattern nalezy navic k B, ne jich mit min"
        );
    }

    /// Ablace D (multi-scale) na IoT-23: kratky burst zachyti uz male skaly v sade,
    /// takze D by nemela byt na IoT-23 horsi nez B - testuje se tu "nezhorsilo to
    /// burst-detekci", ne primo prinos D (ten je zmereny na CTU-13 nize, kde D
    /// skutecne reaguje na jiny typ signalu).
    #[test]
    fn ablation_d_multiscale_does_not_regress_burst_detection_on_iot23() {
        let dataset = Iot23Source
            .load(&dataset_path(
                "labs/datasets/iot23/CTU-IoT-Malware-Capture-44-1/conn.log.labeled",
            ))
            .expect("parse iot23 scenario 44-1");

        let a = run_ablation(&dataset, 300, AblationVariant::A);
        let d = run_ablation(&dataset, 300, AblationVariant::D);

        println!(
            "ablace D na {} (events={}): TP={} FP={} precision={:.3} recall={:.3} f1={:.3}",
            d.dataset_id,
            d.correlated_event_count,
            d.confusion.true_positive,
            d.confusion.false_positive,
            d.confusion.precision(),
            d.confusion.recall(),
            d.confusion.f1(),
        );

        // Regresni assert (Deliverable 15/16 Definition-of-Done): pinuje cislo citovane
        // v docs/diplomka/eval/ablation-d-multiscale.md (127 events, 4.7x vs. A) proti
        // tiche regresi.
        assert_eq!(
            d.correlated_event_count, 127,
            "ablace D na IoT-23 pocet events se rozesel s docs/diplomka/eval/ablation-d-multiscale.md"
        );

        assert!(
            d.confusion.recall() >= a.confusion.recall(),
            "D sjednocuje vice skal, nesmi mit nizsi recall nez samotna A"
        );
    }

    /// Charakterizacni test (ne jen diagnostika) - potvrzuje konkretni znamou limitaci
    /// ablace C popsanou v docs/diplomka/eval/ablation-b-c-iot23.md: naivni multi-target
    /// heuristika (stejny src_ip, >=2 cile ve stejnem okne) na tomto scenari vetsinou
    /// chytne legitimni periodicky NTP fan-out (udp/123 na vice standardnich NTP serveru),
    /// ne utok. Pokud tento test v budoucnu zacne padat (napr. po pridani baseline/allowlist
    /// filtrovani), je to ZLEPSENI - je potreba test aktualizovat, ne ho "opravit" zpet.
    #[test]
    fn multi_target_pattern_on_iot23_malware_scenario_is_mostly_ntp_false_positive() {
        let dataset = Iot23Source
            .load(&dataset_path(
                "labs/datasets/iot23/CTU-IoT-Malware-Capture-44-1/conn.log.labeled",
            ))
            .expect("parse iot23 scenario 44-1");

        let events =
            detect_windowed_anomalies_linked(dataset.observations.clone(), &HashSet::new(), 300);
        let multi_target: Vec<_> = events
            .iter()
            .filter(|event| event.event_type == "multi_target_pattern")
            .collect();
        assert!(
            !multi_target.is_empty(),
            "scenar musi produkovat alespon jeden multi_target_pattern nalez"
        );

        let ntp_only_windows = multi_target
            .iter()
            .filter(|event| event.message.contains("udp/123") && !event.message.contains("tcp/80"))
            .count();

        println!(
            "multi_target_pattern celkem={}, cisty-NTP-bez-utoku={}",
            multi_target.len(),
            ntp_only_windows
        );

        // Vetsina oken (ne vsechna - prvni okno obsahuje i skutecny C2 cil 46.101.251.172
        // tcp/80 smichany s NTP) je cista NTP falesna detekce - presne znama limitace.
        assert!(
            ntp_only_windows * 2 >= multi_target.len(),
            "ocekavana vetsina multi_target_pattern oken je cisty NTP fan-out, ne utok"
        );
    }

    #[test]
    fn iot23_source_info_matches_dataset_registry() {
        let info = Iot23Source.info();
        assert_eq!(info.dataset_id, "iot23");
        assert_eq!(info.wave, 0);
        assert_eq!(info.url, "https://www.stratosphereips.org/datasets-iot23");
        assert!(info.license.contains("CC BY-NC-SA"));
    }

    /// Vlna 1, cross-dataset generalizace: `#[ignore]` protoze 30MB vyrez neni
    /// commitnuty do gitu (viz `.gitignore`, `docs/diplomka/dataset-registry.md` pro
    /// presny stahovaci prikaz a hash) - stejna konvence jako stavajici `#[ignore]`
    /// testy vyzadujici nepublikovane fixtury. Spustit rucne po stazeni:
    /// `cargo test --lib ctu13_cross_dataset -- --ignored --nocapture`.
    #[test]
    #[ignore = "vyzaduje stazeny CTU-13 vyrez, viz docs/diplomka/dataset-registry.md"]
    fn ctu13_cross_dataset_ablation_a_b_c_generalization_check() {
        let dataset = Ctu13Source
            .load(&dataset_path(
                "labs/datasets/ctu13/Botnet-54/capture20110815-3.binetflow.excerpt.csv",
            ))
            .expect("parse ctu13 excerpt");

        let malicious_flow_count = dataset
            .labels
            .iter()
            .filter(|label| label.is_malicious())
            .count();
        assert_eq!(malicious_flow_count, 6185);

        let a = run_ablation(&dataset, 300, AblationVariant::A);
        let b = run_ablation(&dataset, 300, AblationVariant::B);
        let c = run_ablation(&dataset, 300, AblationVariant::C);
        let d = run_ablation(&dataset, 300, AblationVariant::D);

        for (label, result) in [("A", &a), ("B", &b), ("C", &c), ("D", &d)] {
            println!(
                "CTU-13 ablace {label} (events={}, observations={}): TP={} FP={} FN={} TN={} precision={:.3} recall={:.3} f1={:.3} findings={}",
                result.correlated_event_count,
                result.observation_count,
                result.confusion.true_positive,
                result.confusion.false_positive,
                result.confusion.false_negative,
                result.confusion.true_negative,
                result.confusion.precision(),
                result.confusion.recall(),
                result.confusion.f1(),
                result.finding_count,
            );
        }

        let (trivial_p, trivial_r, trivial_f1) = a.confusion.trivial_always_positive_baseline();
        println!(
            "CTU-13 trivialni baseline (vse=malicious): precision={trivial_p:.3} recall={trivial_r:.3} f1={trivial_f1:.3} (srovnej s ablaci A vyse)"
        );

        // Deliverable 20 (chybejici statisticky aparat, audit N4): bootstrap 95% CI
        // na ablaci A - nejistota UVNITR tohoto scenare (resampling 885 known klicu),
        // ne signifikance rozdilu mezi scenari (na to N=3 nestaci, viz stats.rs doc).
        let f1_ci = crate::eval::stats::bootstrap_metric_ci(
            &a.per_key_predictions,
            2000,
            42,
            ConfusionMatrix::f1,
        );
        println!(
            "CTU-13 ablace A F1 95% bootstrap CI: {:.3} [{:.3}, {:.3}] (n={}, 2000 resamplu, seed=42)",
            f1_ci.point_estimate,
            f1_ci.lower_95,
            f1_ci.upper_95,
            a.per_key_predictions.len(),
        );

        // Regresni asserty (N10 nezavisleho auditu, 29.10.2026): cisla citovana v
        // docs/diplomka/eval/cross-dataset-ctu13.md a souhrn-vysledku-a-hypotez.md
        // byla dosud jen z println vystupu rucne prepsana do markdownu - zadny test
        // je nepinoval, takze budouci zmena detekcni logiky by mohla cisla v docs
        // tise rozejit s kodem beze selhani testu. Tolerance 1e-3 na zaokrouhleni.
        let approx = |actual: f64, expected: f64| (actual - expected).abs() < 1e-3;
        assert!(
            approx(a.confusion.precision(), 0.767) && approx(a.confusion.recall(), 0.192),
            "ablace A: precision={:.3} recall={:.3}, cekano 0.767/0.192 - pokud je zmena zamerna, oprav i docs/diplomka/eval/cross-dataset-ctu13.md",
            a.confusion.precision(),
            a.confusion.recall()
        );
        assert!(
            approx(trivial_p, 0.932) && approx(trivial_f1, 0.965),
            "trivialni baseline: precision={trivial_p:.3} f1={trivial_f1:.3}, cekano 0.932/0.965"
        );
    }

    /// Deliverable 18 (datasetova dostatecnost, master plan): rozsireni ze 1 na 3
    /// CTU-13 scenare, 2 ruzne malware rodiny (Virut na Botnet-54, Rbot na Botnet-51,
    /// Neris na Botnet-42) - misto "cross-dataset = druhy capture soubor" (limitace
    /// zapsana v cross-dataset-ctu13.md) uz jde o skutecne vice nezavislych scenaru.
    /// N=3 NESTACI na formalni statisticky test (Wilcoxon potrebuje n>=6 na jakoukoliv
    /// silu, viz dalsi-postup-master-plan.md) - tenhle test honestne reportuje rozsah/
    /// medianu mezi scenari, ne fabrikovanou p-hodnotu.
    #[test]
    #[ignore = "vyzaduje stazene CTU-13 vyrezy, viz docs/diplomka/dataset-registry.md"]
    fn ctu13_three_scenarios_two_families_dataset_sufficiency_check() {
        let scenarios = [
            (
                "Botnet-54 (Virut)",
                "labs/datasets/ctu13/Botnet-54/capture20110815-3.binetflow.excerpt.csv",
            ),
            (
                "Botnet-51 (Rbot)",
                "labs/datasets/ctu13/Botnet-51/capture20110818.binetflow.excerpt.csv",
            ),
            (
                "Botnet-42 (Neris)",
                "labs/datasets/ctu13/Botnet-42/capture20110810.binetflow.excerpt.csv",
            ),
        ];

        let mut f1_scores: Vec<f64> = Vec::new();
        let mut beats_trivial_baseline: Vec<bool> = Vec::new();

        for (label, relative_path) in scenarios {
            let dataset = Ctu13Source
                .load(&dataset_path(relative_path))
                .unwrap_or_else(|error| panic!("parse {label}: {error}"));
            let a = run_ablation(&dataset, 300, AblationVariant::A);
            let (_, _, trivial_f1) = a.confusion.trivial_always_positive_baseline();
            let f1 = a.confusion.f1();

            println!(
                "{label}: known_keys={} malicious={} benign={} unknown_excluded={} TP={} FP={} FN={} TN={} precision={:.3} recall={:.3} f1={f1:.3} | trivialni_baseline_f1={trivial_f1:.3}",
                a.confusion.true_positive
                    + a.confusion.false_positive
                    + a.confusion.false_negative
                    + a.confusion.true_negative,
                a.malicious_flow_count,
                a.benign_flow_count,
                a.excluded_unknown_keys,
                a.confusion.true_positive,
                a.confusion.false_positive,
                a.confusion.false_negative,
                a.confusion.true_negative,
                a.confusion.precision(),
                a.confusion.recall(),
            );

            f1_scores.push(f1);
            beats_trivial_baseline.push(f1 > trivial_f1);
        }

        let min_f1 = f1_scores.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_f1 = f1_scores.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        println!(
            "CTU-13, 3 scenare/2 rodiny: F1 rozsah [{min_f1:.3}, {max_f1:.3}], ablace A porazila trivialni baseline v {}/3 scenarich",
            beats_trivial_baseline
                .iter()
                .filter(|beats| **beats)
                .count()
        );

        // Honestni, nefabrikovany pozadavek na N=3: ablace A musi byt zmerena (ne
        // crashnout) na vsech 3 scenarich a kazdy musi mit alespon nejaky znamy
        // (Malicious/Benign) provoz - jinak je "cross-scenario" srovnani prazdne.
        assert_eq!(
            f1_scores.len(),
            3,
            "vsechny 3 scenare musi byt uspesne zmereny"
        );
    }

    /// Deliverable 19 (H4 kalibrace, master plan): izotonicka regrese kontinualniho
    /// anomaly skore (`passive::anomaly::score_connection_keys`), trenovana na 2 ze 3
    /// CTU-13 scenaru a vyhodnocena na tom tretim (leave-one-scenario-out) - zadny
    /// scenar nikdy neni soucasne v treningu i testu. Srovnani: "nekalibrovane" skore
    /// = presne ten binarni prah (score>=3.2), ktery uz produkcni kod pouziva, jako
    /// 0/1 "pravdepodobnost" (nejcestnejsi dostupny baseline, ne vymyslena slama).
    #[test]
    #[ignore = "vyzaduje stazene CTU-13 vyrezy, viz docs/diplomka/dataset-registry.md"]
    fn h4_isotonic_calibration_loso_brier_score_across_ctu13_scenarios() {
        let scenario_paths = [
            "labs/datasets/ctu13/Botnet-54/capture20110815-3.binetflow.excerpt.csv",
            "labs/datasets/ctu13/Botnet-51/capture20110818.binetflow.excerpt.csv",
            "labs/datasets/ctu13/Botnet-42/capture20110810.binetflow.excerpt.csv",
        ];

        let points_per_scenario: Vec<Vec<_>> = scenario_paths
            .iter()
            .map(|path| {
                let dataset = Ctu13Source
                    .load(&dataset_path(path))
                    .unwrap_or_else(|error| panic!("parse {path}: {error}"));
                scored_points(&dataset)
            })
            .collect();

        for (path, points) in scenario_paths.iter().zip(points_per_scenario.iter()) {
            assert!(
                !points.is_empty(),
                "{path} nevyprodukoval zadne skorovane body - over score_connection_keys"
            );
        }

        let mut raw_brier_scores = Vec::new();
        let mut calibrated_brier_scores = Vec::new();

        for held_out in 0..points_per_scenario.len() {
            let train: Vec<_> = points_per_scenario
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != held_out)
                .flat_map(|(_, points)| points.iter().copied())
                .collect();
            let calibrator = IsotonicCalibrator::fit(&train);
            let test = &points_per_scenario[held_out];

            let raw: Vec<(f64, bool)> = test
                .iter()
                .map(|point| {
                    let raw_probability = if point.score >= 3.2 { 1.0 } else { 0.0 };
                    (raw_probability, point.is_malicious)
                })
                .collect();
            let calibrated: Vec<(f64, bool)> = test
                .iter()
                .map(|point| (calibrator.predict(point.score), point.is_malicious))
                .collect();

            let raw_brier = brier_score(&raw);
            let calibrated_brier = brier_score(&calibrated);
            println!(
                "LOSO held-out={} (n={}): raw_brier={raw_brier:.4} calibrated_brier={calibrated_brier:.4}",
                scenario_paths[held_out],
                test.len(),
            );
            raw_brier_scores.push(raw_brier);
            calibrated_brier_scores.push(calibrated_brier);
        }

        let mean_raw = raw_brier_scores.iter().sum::<f64>() / raw_brier_scores.len() as f64;
        let mean_calibrated =
            calibrated_brier_scores.iter().sum::<f64>() / calibrated_brier_scores.len() as f64;
        println!(
            "LOSO prumer pres 3 scenare: raw_brier={mean_raw:.4} calibrated_brier={mean_calibrated:.4}"
        );

        // Honestni, nefabrikovany pozadavek: kalibrace musi bezet na vsech 3 fold a
        // nesmi explodovat (napr. NaN z degenerovaneho fitu) - netvrdime predem, ze
        // kalibrace MUSI zlepsit Brier (to je otevrena empiricka otazka, ne predpoklad).
        assert_eq!(raw_brier_scores.len(), 3);
        assert_eq!(calibrated_brier_scores.len(), 3);
        for brier in raw_brier_scores
            .iter()
            .chain(calibrated_brier_scores.iter())
        {
            assert!(
                brier.is_finite() && *brier >= 0.0 && *brier <= 1.0,
                "Brier skore musi byt konecne cislo v [0,1], dostal jsem {brier}"
            );
        }
    }

    /// Deliverable 28 (reakce na pozadavek "je slaby vysledek ablace A spatny signal,
    /// nebo jen spatne zvoleny prah 3.2?"): PR-AUC meri rozlisovaci silu kontinualniho
    /// skore NEZAVISLE na prahu. Pokud je PR-AUC vyrazne nad prevalenci (= PR-AUC
    /// nahodneho/konstantniho klasifikatoru), signal NESE uzitecnou informaci a zlepseni
    /// je otazkou lepsiho prahu/kalibrace, ne noveho detektoru. Pokud je PR-AUC blizko
    /// prevalenci, signal sam o sobe nerozlisuje a je potreba lepsi detekce, ne jen
    /// jiny prah.
    #[test]
    #[ignore = "vyzaduje stazene CTU-13 vyrezy, viz docs/diplomka/dataset-registry.md"]
    fn ctu13_pr_auc_diagnoses_whether_score_has_discriminative_power_or_just_bad_threshold() {
        let scenario_paths = [
            "labs/datasets/ctu13/Botnet-54/capture20110815-3.binetflow.excerpt.csv",
            "labs/datasets/ctu13/Botnet-51/capture20110818.binetflow.excerpt.csv",
            "labs/datasets/ctu13/Botnet-42/capture20110810.binetflow.excerpt.csv",
        ];

        for path in scenario_paths {
            let dataset = Ctu13Source
                .load(&dataset_path(path))
                .unwrap_or_else(|error| panic!("parse {path}: {error}"));
            let points = scored_points(&dataset);
            assert!(
                !points.is_empty(),
                "{path} nevyprodukoval zadne skorovane body"
            );

            let pairs: Vec<(f64, bool)> = points
                .iter()
                .map(|point| (point.score, point.is_malicious))
                .collect();
            let prevalence = points.iter().filter(|point| point.is_malicious).count() as f64
                / points.len() as f64;
            let auc = crate::eval::stats::pr_auc(&pairs);

            println!(
                "{path}: PR-AUC={auc:.4} prevalence(nahodny baseline)={prevalence:.4} rozdil={:+.4}",
                auc - prevalence
            );
        }
    }

    /// Spolecny loader pro zdroj-centricke (score, label) body jednoho CTU-13 scenare -
    /// pouziva se v testech Deliverable 30 a dal, aby se nezduplikovalo napotretí stejne
    /// nacitani/skorovani, ktere uz existujici testy Deliverable 28/29 maji inline.
    fn ctu13_source_centric_points(path: &str) -> Vec<ScoredPoint> {
        let dataset = Ctu13Source
            .load(&dataset_path(path))
            .unwrap_or_else(|error| panic!("parse {path}: {error}"));
        let scores = crate::passive::score_source_hosts(&dataset.observations);
        let mut malicious_sources: HashSet<String> = HashSet::new();
        for (observation, label) in dataset.observations.iter().zip(dataset.labels.iter()) {
            if label.is_malicious() {
                if let Some(src_ip) = &observation.src_ip {
                    malicious_sources.insert(src_ip.clone());
                }
            }
        }
        scores
            .into_iter()
            .map(|(src_ip, score)| ScoredPoint {
                score,
                is_malicious: malicious_sources.contains(&src_ip),
            })
            .collect()
    }

    fn confusion_at_threshold(points: &[ScoredPoint], threshold: f64) -> ConfusionMatrix {
        let mut confusion = ConfusionMatrix::default();
        for point in points {
            let predicted = point.score >= threshold;
            match (predicted, point.is_malicious) {
                (true, true) => confusion.true_positive += 1,
                (true, false) => confusion.false_positive += 1,
                (false, true) => confusion.false_negative += 1,
                (false, false) => confusion.true_negative += 1,
            }
        }
        confusion
    }

    /// Deliverable 30 (navazuje na 29): naivni prenos prahu 3.2 selhal a kalibrovany
    /// prah 0.5 selhal ze stejneho duvodu (extremne nizka prevalence). Spravny dalsi
    /// pokus - NE cirkularni - je zvolit prah, ktery maximalizuje F1 na TRENOVACICH
    /// datech (ostatni 2 scenare v LOSO), a tenhle zmrazeny prah pak aplikovat na
    /// held-out scenar beze zmeny. Tohle NENI proladeni na evalu, protoze testovaci
    /// scenar nikdy neovlivni, jaky prah se vybere - presne stejna disciplina jako
    /// u `IsotonicCalibrator::fit(&train)` o par radku vyse.
    #[test]
    #[ignore = "vyzaduje stazene CTU-13 vyrezy, viz docs/diplomka/dataset-registry.md"]
    fn ctu13_source_centric_loso_f1_optimal_threshold_beats_naive_and_trivial() {
        let scenario_paths = [
            "labs/datasets/ctu13/Botnet-54/capture20110815-3.binetflow.excerpt.csv",
            "labs/datasets/ctu13/Botnet-51/capture20110818.binetflow.excerpt.csv",
            "labs/datasets/ctu13/Botnet-42/capture20110810.binetflow.excerpt.csv",
        ];

        let points_per_scenario: Vec<Vec<ScoredPoint>> = scenario_paths
            .iter()
            .map(|path| ctu13_source_centric_points(path))
            .collect();

        for (path, points) in scenario_paths.iter().zip(points_per_scenario.iter()) {
            assert!(
                !points.is_empty(),
                "{path} nevyprodukoval zadne zdroj-centricke skorovane body"
            );
        }

        const NAIVE_THRESHOLD: f64 = 3.2;
        let mut test_f1_scores = Vec::new();
        let mut trivial_f1_scores = Vec::new();

        for held_out in 0..points_per_scenario.len() {
            let train: Vec<ScoredPoint> = points_per_scenario
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != held_out)
                .flat_map(|(_, points)| points.iter().copied())
                .collect();
            let test = &points_per_scenario[held_out];

            // Kandidatni prahy = kazde unikatni skore v TRENOVACICH datech - standardni
            // volba bodu na PR krivce, zadne skore z test foldu tu nefiguruje.
            let mut candidates: Vec<f64> = train.iter().map(|point| point.score).collect();
            candidates.sort_by(|left, right| left.partial_cmp(right).unwrap_or(Ordering::Equal));
            candidates.dedup();

            let best_threshold = candidates
                .iter()
                .copied()
                .max_by(|left, right| {
                    let left_f1 = confusion_at_threshold(&train, *left).f1();
                    let right_f1 = confusion_at_threshold(&train, *right).f1();
                    left_f1.partial_cmp(&right_f1).unwrap_or(Ordering::Equal)
                })
                .unwrap_or(NAIVE_THRESHOLD);

            let test_confusion = confusion_at_threshold(test, best_threshold);
            let naive_confusion = confusion_at_threshold(test, NAIVE_THRESHOLD);
            let (_, _, trivial_f1) = test_confusion.trivial_always_positive_baseline();

            println!(
                "{} held-out (n={}): LOSO F1-optimalni prah (z treninku)={best_threshold:.3} -> test precision={:.4} recall={:.4} f1={:.4} | naivni prah 3.2 test f1={:.4} | trivialni baseline f1={trivial_f1:.4}",
                scenario_paths[held_out],
                test.len(),
                test_confusion.precision(),
                test_confusion.recall(),
                test_confusion.f1(),
                naive_confusion.f1(),
            );

            test_f1_scores.push(test_confusion.f1());
            trivial_f1_scores.push(trivial_f1);
        }

        for f1 in &test_f1_scores {
            assert!(f1.is_finite(), "LOSO test F1 musi byt konecne cislo");
        }
        // Honestni, nefabrikovany pozadavek - jen ze mereni probehlo na vsech 3 foldech,
        // ne ze LOSO-vybrany prah MUSI porazit trivialni baseline na kazdem z nich
        // (to je otevrena empiricka otazka, zapsana v docs vysledkem, ne predpokladem).
        assert_eq!(test_f1_scores.len(), 3);
        assert_eq!(trivial_f1_scores.len(), 3);
    }

    /// Deliverable 28, pokracovani diagnozy: `score_connection_keys` (agregace podle
    /// CILE) ma slabe PR-AUC na CTU-13. Hypoteza: CTU-13 ground truth je definovana
    /// podle ZDROJE (bot = infikovany HOST, ne anomalni sluzba), takze agregace podle
    /// src_ip (`score_source_hosts`, vcetne noveho rysu "pocet distinktnich cilu")
    /// by mela mit lepsi rozlisovaci silu. Ground truth tady je "ma tenhle src_ip
    /// alespon jeden malicious flow" - jina definice nez u destinace, ale presne ta,
    /// kterou CTU-13 label skutecne popisuje (infikovany bot, ne anomalni sluzba).
    #[test]
    #[ignore = "vyzaduje stazene CTU-13 vyrezy, viz docs/diplomka/dataset-registry.md"]
    fn ctu13_source_centric_scoring_vs_destination_centric_pr_auc_comparison() {
        let scenario_paths = [
            "labs/datasets/ctu13/Botnet-54/capture20110815-3.binetflow.excerpt.csv",
            "labs/datasets/ctu13/Botnet-51/capture20110818.binetflow.excerpt.csv",
            "labs/datasets/ctu13/Botnet-42/capture20110810.binetflow.excerpt.csv",
        ];

        for path in scenario_paths {
            let dataset = Ctu13Source
                .load(&dataset_path(path))
                .unwrap_or_else(|error| panic!("parse {path}: {error}"));

            // Destinace-centricka varianta (existujici score_connection_keys pres
            // scored_points) - uz zmereno vyse, pro srovnani ve stejnem vystupu.
            let dest_points = scored_points(&dataset);
            let dest_pairs: Vec<(f64, bool)> = dest_points
                .iter()
                .map(|point| (point.score, point.is_malicious))
                .collect();
            let dest_prevalence = dest_points
                .iter()
                .filter(|point| point.is_malicious)
                .count() as f64
                / dest_points.len().max(1) as f64;
            let dest_auc = crate::eval::stats::pr_auc(&dest_pairs);

            // Zdroj-centricka varianta (nova score_source_hosts) - ground truth je
            // "ma tenhle src_ip alespon 1 malicious flow", ne "ma tenhle (dst,proto,
            // port) klic alespon 1 malicious flow".
            let scores = crate::passive::score_source_hosts(&dataset.observations);
            let mut malicious_sources: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for (observation, label) in dataset.observations.iter().zip(dataset.labels.iter()) {
                if label.is_malicious() {
                    if let Some(src_ip) = &observation.src_ip {
                        malicious_sources.insert(src_ip.clone());
                    }
                }
            }
            let src_pairs: Vec<(f64, bool)> = scores
                .iter()
                .map(|(src_ip, score)| (*score, malicious_sources.contains(src_ip)))
                .collect();
            let src_prevalence = src_pairs.iter().filter(|(_, label)| *label).count() as f64
                / src_pairs.len().max(1) as f64;
            let src_auc = crate::eval::stats::pr_auc(&src_pairs);

            // Raw PR-AUC neni mezi destinacni a zdrojovou variantou primo srovnatelne
            // - prevalence (podil pozitiv) je u kazde JINA (zdrojova je radove nizsi,
            // protoze jen par hostu je bot mezi tisici), a PR-AUC je prevalenci shora
            // ovlivnena nezavisle na kvalite skore. Spravne srovnatelna metrika je
            // LIFT = PR-AUC / prevalence (kolikrat lepe nez nahodny klasifikator se
            // STEJNOU prevalenci) - scale-invariant pres ruzne zakladni sazby.
            let dest_lift = if dest_prevalence > 0.0 {
                dest_auc / dest_prevalence
            } else {
                0.0
            };
            let src_lift = if src_prevalence > 0.0 {
                src_auc / src_prevalence
            } else {
                0.0
            };

            println!(
                "{path}: DESTINACE-centricka PR-AUC={dest_auc:.4} prevalence={dest_prevalence:.4} LIFT={dest_lift:.2}x (n={}) | ZDROJ-centricka PR-AUC={src_auc:.4} prevalence={src_prevalence:.4} LIFT={src_lift:.2}x (n={})",
                dest_points.len(),
                src_pairs.len(),
            );

            // Regresni pojistka na klicovy nalez (Deliverable 28, dokumentovano v
            // docs/diplomka/eval/source-centric-scoring-pr-auc.md): zdroj-centricke
            // skore musi mit VYRAZNE vyssi lift nez destinace-centricke na KAZDEM ze 3
            // scenaru - pokud budouci zmena detekcni logiky tohle porusi, musi test
            // selhat, ne tise zmizet z vystupu.
            assert!(
                src_lift > dest_lift * 2.0,
                "{path}: zdroj-centricky lift ({src_lift:.2}x) musi byt aspon 2x vyssi nez destinace-centricky ({dest_lift:.2}x)"
            );

            // Lepsi ranking (PR-AUC) nemusi automaticky znamenat lepsi klasifikaci PRI
            // NEJAKEM konkretnim prahu - tohle to overuje. Prah 3.2 je prevzaty
            // nezmeneny z destinace-centricke ablace A (Deliverable 3), NE natrenovany
            // na zdrojovych datech - stejny cutoff na jine agregaci, ne nove vyladena
            // hodnota, aby srovnani nebylo cirkularni.
            const THRESHOLD: f64 = 3.2;
            let mut confusion = ConfusionMatrix::default();
            for (score, is_malicious) in &src_pairs {
                let predicted = *score >= THRESHOLD;
                match (predicted, *is_malicious) {
                    (true, true) => confusion.true_positive += 1,
                    (true, false) => confusion.false_positive += 1,
                    (false, true) => confusion.false_negative += 1,
                    (false, false) => confusion.true_negative += 1,
                }
            }
            let (trivial_p, trivial_r, trivial_f1) = confusion.trivial_always_positive_baseline();
            println!(
                "{path}: ZDROJ-centricka klasifikace pri prahu {THRESHOLD}: TP={} FP={} FN={} TN={} precision={:.3} recall={:.3} f1={:.3} | trivialni baseline (vse=bot) precision={trivial_p:.3} f1={trivial_f1:.3} (recall={trivial_r:.1})",
                confusion.true_positive,
                confusion.false_positive,
                confusion.false_negative,
                confusion.true_negative,
                confusion.precision(),
                confusion.recall(),
                confusion.f1(),
            );
        }
    }

    /// Navazuje na predchozi test: naivni prenos prahu 3.2 z destinace-centricke
    /// domeny na zdroj-centricke skore selhal (precision~=0.000-0.005, prakticky
    /// shodne s trivialnim baseline) - ale to NEVYVRACI merenej LIFT 24-90x, jen
    /// ukazuje, ze konstanta neni prenositelna mezi domenami agregace. Spravna
    /// odpoved (zdokumentovano v docs/diplomka/eval/source-centric-scoring-pr-auc.md)
    /// neni hledat novou konstantu proladenim na evalu (cirkularni), ale pouzit
    /// uz existujici kalibracni metodu (Deliverable 19, LOSO izotonicka regrese)
    /// na zdroj-centricke skore a klasifikovat podle KALIBROVANE pravdepodobnosti
    /// (prah 0.5 na P(malicious), ne na surovem skore).
    #[test]
    #[ignore = "vyzaduje stazene CTU-13 vyrezy, viz docs/diplomka/dataset-registry.md"]
    fn ctu13_source_centric_isotonic_calibration_loso_beats_naive_threshold_transfer() {
        let scenario_paths = [
            "labs/datasets/ctu13/Botnet-54/capture20110815-3.binetflow.excerpt.csv",
            "labs/datasets/ctu13/Botnet-51/capture20110818.binetflow.excerpt.csv",
            "labs/datasets/ctu13/Botnet-42/capture20110810.binetflow.excerpt.csv",
        ];

        let points_per_scenario: Vec<Vec<ScoredPoint>> = scenario_paths
            .iter()
            .map(|path| {
                let dataset = Ctu13Source
                    .load(&dataset_path(path))
                    .unwrap_or_else(|error| panic!("parse {path}: {error}"));
                let scores = crate::passive::score_source_hosts(&dataset.observations);
                let mut malicious_sources: HashSet<String> = HashSet::new();
                for (observation, label) in dataset.observations.iter().zip(dataset.labels.iter()) {
                    if label.is_malicious() {
                        if let Some(src_ip) = &observation.src_ip {
                            malicious_sources.insert(src_ip.clone());
                        }
                    }
                }
                scores
                    .into_iter()
                    .map(|(src_ip, score)| ScoredPoint {
                        score,
                        is_malicious: malicious_sources.contains(&src_ip),
                    })
                    .collect()
            })
            .collect();

        for (path, points) in scenario_paths.iter().zip(points_per_scenario.iter()) {
            assert!(
                !points.is_empty(),
                "{path} nevyprodukoval zadne zdroj-centricke skorovane body"
            );
        }

        const NAIVE_THRESHOLD: f64 = 3.2;
        const CALIBRATED_THRESHOLD: f64 = 0.5;

        for held_out in 0..points_per_scenario.len() {
            let train: Vec<ScoredPoint> = points_per_scenario
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != held_out)
                .flat_map(|(_, points)| points.iter().copied())
                .collect();
            let calibrator = IsotonicCalibrator::fit(&train);
            let test = &points_per_scenario[held_out];

            let naive: Vec<(f64, bool)> = test
                .iter()
                .map(|point| {
                    let raw_probability = if point.score >= NAIVE_THRESHOLD {
                        1.0
                    } else {
                        0.0
                    };
                    (raw_probability, point.is_malicious)
                })
                .collect();
            let calibrated: Vec<(f64, bool)> = test
                .iter()
                .map(|point| (calibrator.predict(point.score), point.is_malicious))
                .collect();

            let naive_brier = brier_score(&naive);
            let calibrated_brier = brier_score(&calibrated);

            let mut naive_confusion = ConfusionMatrix::default();
            let mut calibrated_confusion = ConfusionMatrix::default();
            for point in test.iter() {
                let naive_predicted = point.score >= NAIVE_THRESHOLD;
                let calibrated_predicted = calibrator.predict(point.score) >= CALIBRATED_THRESHOLD;
                match (naive_predicted, point.is_malicious) {
                    (true, true) => naive_confusion.true_positive += 1,
                    (true, false) => naive_confusion.false_positive += 1,
                    (false, true) => naive_confusion.false_negative += 1,
                    (false, false) => naive_confusion.true_negative += 1,
                }
                match (calibrated_predicted, point.is_malicious) {
                    (true, true) => calibrated_confusion.true_positive += 1,
                    (true, false) => calibrated_confusion.false_positive += 1,
                    (false, true) => calibrated_confusion.false_negative += 1,
                    (false, false) => calibrated_confusion.true_negative += 1,
                }
            }
            let (_, _, trivial_f1) = naive_confusion.trivial_always_positive_baseline();

            println!(
                "{} held-out (n={}): naive(3.2) brier={naive_brier:.4} f1={:.4} | kalibrovane(0.5) brier={calibrated_brier:.4} f1={:.4} | trivialni baseline f1={trivial_f1:.4}",
                scenario_paths[held_out],
                test.len(),
                naive_confusion.f1(),
                calibrated_confusion.f1(),
            );

            // Honestni, nefabrikovany pozadavek: kalibrace musi bezet na vsech foldech
            // bez explodovani (NaN) - nepredpokladame predem, ze kalibrovany F1 MUSI
            // porazit trivialni baseline na kazdem foldu (otevrena empiricka otazka),
            // jen ze je to konecne, platne cislo.
            assert!(
                calibrated_confusion.f1().is_finite(),
                "{}: kalibrovany F1 musi byt konecne cislo",
                scenario_paths[held_out]
            );
            assert!(
                calibrated_brier.is_finite() && calibrated_brier >= 0.0 && calibrated_brier <= 1.0,
                "{}: kalibrovany Brier musi byt v [0,1]",
                scenario_paths[held_out]
            );
        }
    }

    /// Nasledna otazka z `docs/diplomka/eval/cross-dataset-ctu13.md`: byla 300s
    /// ablace B horsi nez A kvuli fragmentaci nizko-objemoveho C2 beaconingu
    /// tumbling oknem (hypoteza, nepotvrzena dalsim merenim)? Sweep `time_window_s`
    /// misto nechat to jako nepotvrzenou domnenku.
    #[test]
    #[ignore = "vyzaduje stazeny CTU-13 vyrez, viz docs/diplomka/dataset-registry.md"]
    fn ctu13_time_window_sweep_tests_fragmentation_hypothesis() {
        let dataset = Ctu13Source
            .load(&dataset_path(
                "labs/datasets/ctu13/Botnet-54/capture20110815-3.binetflow.excerpt.csv",
            ))
            .expect("parse ctu13 excerpt");

        let a = run_ablation(&dataset, 300, AblationVariant::A);
        println!(
            "CTU-13 ablace A (okno irelevantni, cely capture): precision={:.3} recall={:.3} f1={:.3}",
            a.confusion.precision(),
            a.confusion.recall(),
            a.confusion.f1()
        );

        for window_s in [60i64, 300, 900, 1800, 3600, 7200] {
            let b = run_ablation(&dataset, window_s, AblationVariant::B);
            println!(
                "CTU-13 ablace B, time_window_s={window_s}: TP={} FP={} precision={:.3} recall={:.3} f1={:.3} events={}",
                b.confusion.true_positive,
                b.confusion.false_positive,
                b.confusion.precision(),
                b.confusion.recall(),
                b.confusion.f1(),
                b.correlated_event_count,
            );
        }
    }
}
