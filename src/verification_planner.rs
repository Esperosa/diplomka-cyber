//! Verification Planner (Deliverable 5), navazuje na Deliverable 4 (`hypothesis.rs`).
//! Zije VEDLE `decision.rs` (ktere generuje `TriageAction`/`MonitoringLane`, ne vybira
//! dalsi overovaci kontrolu) a `verification.rs` (ktery porovnava VYSLEDEK bezu proti
//! `ScenarioManifest` ocekavanim - test-harness pojem, ne tento: "ktera dalsi kontrola
//! je nejlepsi"). Nic v zadnem z nich se nemeni.
//!
//! Navrh (sekce 5.4) chce vybirat dalsi autorizovanou, nejlepe nedestruktivni kontrolu
//! podle Expected Value of Information:
//! `utility(action) = expected_decision_loss_reduction - execution_cost - network_overhead
//! - disruption_risk - delay_penalty`. Akce by mely mit `deadline`/`budget`/`scope`/
//! `rate limit`/`max retries`/`disruption class`/`approval`/`evidence output`/
//! `idempotency key`.
//!
//! **Rozsah tohoto kroku: jen SELEKCE (ktery kandidat je nejlepsi), NE EXEKUCE.**
//! `deadline`/`budget`/`rate limit`/`max retries`/`idempotency key` jsou exekucni
//! omezeni (vyzaduji skutecne spousteni akci - Mininet/Containerlab lab, sekce 8.2
//! navrhu) - vedome vynechano, budouci prace, ne fabrikovano. Tohle NEVOLA
//! `nmap.rs`/`webscan.rs` ani zadny aktivni sken.
//!
//! `TypedUncertainty` z `hypothesis.rs` se zde VEDOME nepouziva k vaze utility -
//! zprumerovani identity/observation/state os do jednoho cisla by bylo presne to
//! "falesne presne" michani, ktere Deliverable 4 zakazuje. `estimated_information_gain`
//! je vstup od volajiciho (napr. z Deliverable 4+ navazujici logiky), ne automaticky
//! odvozene z `uncertainty`.

use crate::hypothesis::SecurityHypothesis;

/// Kandidat na dalsi overovaci kontrolu - jeste NEVYBRANA/nevykonana akce.
#[derive(Debug, Clone)]
pub struct VerificationCandidate {
    pub method: String,
    pub estimated_information_gain: f64,
    pub estimated_network_cost: f64,
    pub estimated_runtime_ms: u64,
    pub disruption_risk: f64,
    pub requires_approval: bool,
}

/// Jak moc je `estimated_runtime_ms` penalizovan v utilite - navrhovy dokument rozlisuje
/// "delay_penalty" od "execution_cost"/"network_overhead" jako samostatny term.
const DELAY_PENALTY_PER_SECOND: f64 = 0.01;

/// `utility(action) = expected_decision_loss_reduction - execution_cost - network_overhead - disruption_risk - delay_penalty`.
///
/// `expected_decision_loss_reduction` je modelovano jako `estimated_information_gain *
/// hypothesis.potential_impact` - informace o hypotéze s vysokym dopadem je cennejsi
/// snizit nez o hypotéze s nizkym dopadem.
pub fn utility(hypothesis: &SecurityHypothesis, candidate: &VerificationCandidate) -> f64 {
    let expected_decision_loss_reduction =
        candidate.estimated_information_gain * hypothesis.potential_impact;
    let delay_penalty = (candidate.estimated_runtime_ms as f64 / 1000.0) * DELAY_PENALTY_PER_SECOND;

    expected_decision_loss_reduction
        - candidate.estimated_network_cost
        - candidate.disruption_risk
        - delay_penalty
}

#[derive(Debug, Clone)]
pub struct RankedCandidate {
    pub candidate: VerificationCandidate,
    pub utility: f64,
}

#[derive(Debug, Clone)]
pub struct VerificationPlan {
    /// Nejlepsi kandidat podle utility. `None` pokud `candidates` bylo prazdne.
    pub chosen: Option<RankedCandidate>,
    /// Vsichni kandidati, serazeni sestupne podle utility.
    pub ranked: Vec<RankedCandidate>,
}

impl VerificationPlan {
    /// `true` pokud vybrany kandidat vyzaduje schvaleni - volajici NESMI tiche
    /// automaticky provest akci jen proto, ze `chosen.is_some()`.
    pub fn chosen_requires_approval(&self) -> bool {
        self.chosen
            .as_ref()
            .is_some_and(|ranked| ranked.candidate.requires_approval)
    }
}

/// Cista funkce bez stavu - zadny rozpocet na kolo/limit poctu vybranych kandidatu
/// (to je exekucni omezeni stejne tridy jako `budget`/`rate limit`, navazujici krok).
pub fn plan_verification(
    hypothesis: &SecurityHypothesis,
    candidates: Vec<VerificationCandidate>,
) -> VerificationPlan {
    let mut ranked: Vec<RankedCandidate> = candidates
        .into_iter()
        .map(|candidate| {
            let score = utility(hypothesis, &candidate);
            RankedCandidate {
                candidate,
                utility: score,
            }
        })
        .collect();

    ranked.sort_by(|left, right| right.utility.total_cmp(&left.utility));
    let chosen = ranked.first().cloned();

    VerificationPlan { chosen, ranked }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypothesis::TypedUncertainty;

    fn hypothesis(potential_impact: f64) -> SecurityHypothesis {
        SecurityHypothesis {
            affected_assets: vec!["10.0.0.1".to_string()],
            hypothesis_type: "unexpected_traffic".to_string(),
            supporting_evidence: Vec::new(),
            contradicting_evidence: Vec::new(),
            probability: None,
            uncertainty: TypedUncertainty::default(),
            potential_impact,
            model_version: "test".to_string(),
        }
    }

    fn candidate(
        method: &str,
        information_gain: f64,
        network_cost: f64,
        runtime_ms: u64,
        disruption_risk: f64,
        requires_approval: bool,
    ) -> VerificationCandidate {
        VerificationCandidate {
            method: method.to_string(),
            estimated_information_gain: information_gain,
            estimated_network_cost: network_cost,
            estimated_runtime_ms: runtime_ms,
            disruption_risk,
            requires_approval,
        }
    }

    #[test]
    fn higher_information_gain_wins_when_cost_and_risk_are_equal() {
        let h = hypothesis(0.8);
        let safe_but_weak = candidate("passive_context_lookup", 0.2, 0.01, 200, 0.0, false);
        let strong_and_cheap = candidate("cve_intel_lookup", 0.7, 0.01, 200, 0.0, false);

        let plan = plan_verification(&h, vec![safe_but_weak.clone(), strong_and_cheap.clone()]);

        assert_eq!(plan.chosen.unwrap().candidate.method, "cve_intel_lookup");
    }

    #[test]
    fn high_disruption_risk_loses_to_safer_lower_gain_alternative() {
        let h = hypothesis(0.5);
        let risky_scan = candidate("aggressive_nuclei_template", 0.9, 0.05, 5_000, 0.9, false);
        let safe_lookup = candidate("passive_context_lookup", 0.3, 0.01, 200, 0.0, false);

        let plan = plan_verification(&h, vec![risky_scan, safe_lookup]);

        assert_eq!(
            plan.chosen.unwrap().candidate.method,
            "passive_context_lookup"
        );
    }

    #[test]
    fn candidate_requiring_approval_is_flagged_not_silently_auto_selected() {
        let h = hypothesis(0.9);
        let needs_approval = candidate("nmap_followup", 0.8, 0.02, 1_000, 0.1, true);
        let safe_alternative = candidate("passive_context_lookup", 0.1, 0.0, 100, 0.0, false);

        let plan = plan_verification(&h, vec![needs_approval, safe_alternative]);

        // nmap_followup ma vyssi utility a VYHRAVA v poradi, ale volajici musi
        // explicitne zkontrolovat `chosen_requires_approval()` pred provedenim.
        assert_eq!(
            plan.chosen.as_ref().unwrap().candidate.method,
            "nmap_followup"
        );
        assert!(plan.chosen_requires_approval());
    }

    #[test]
    fn empty_candidates_produce_no_chosen_action() {
        let plan = plan_verification(&hypothesis(0.5), Vec::new());
        assert!(plan.chosen.is_none());
        assert!(plan.ranked.is_empty());
    }

    #[test]
    fn higher_impact_hypothesis_makes_the_same_candidate_more_valuable() {
        let candidate_fixed = candidate("cve_intel_lookup", 0.5, 0.1, 500, 0.0, false);
        let low_impact = utility(&hypothesis(0.1), &candidate_fixed);
        let high_impact = utility(&hypothesis(0.9), &candidate_fixed);

        assert!(
            high_impact > low_impact,
            "stejna kontrola musi mit vyssi utilitu pro hypotezu s vyssim potential_impact"
        );
    }
}
