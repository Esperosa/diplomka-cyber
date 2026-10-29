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

use crate::verification_planner::VerificationCandidate;

#[derive(Debug, Clone, Copy)]
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

    #[test]
    #[should_panic(expected = "alespon 1 realne mereni")]
    fn derive_candidate_refuses_empty_history() {
        derive_candidate_from_samples("test_method", &[], 0.0, false);
    }
}
