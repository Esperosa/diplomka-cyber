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
    for key in &all_keys {
        if !key_has_known_evidence.contains(key) {
            excluded_unknown_keys += 1;
            continue;
        }
        let predicted = predicted_positive.contains(key);
        let actual = ground_truth_positive.contains(key);
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
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
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
