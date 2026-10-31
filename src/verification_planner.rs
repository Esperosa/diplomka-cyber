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

use serde::{Deserialize, Serialize};

use crate::case_history::{
    MIN_SAMPLES_FOR_HISTORY, VerificationHistory, derive_candidate_from_samples,
};
use crate::hypothesis::SecurityHypothesis;

/// Kandidat na dalsi overovaci kontrolu - jeste NEVYBRANA/nevykonana akce.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedCandidate {
    pub candidate: VerificationCandidate,
    pub utility: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Vzdy dostupny kandidat (passive/read-only, nikdy nevyzaduje schvaleni) - sirsi
/// pasivni pozorovaci okno, ne nova aktivni kontrola, jen vic casu pozorovat uz
/// probihajici tok. Nejlevnejsi a nejbezpecnejsi "baseline" alternativa, pritomna
/// pro kazdou hypotezu, aby `plan_verification` mela i bez aktivnich kontrol s
/// cim porovnavat.
fn passive_extended_observation_candidate() -> VerificationCandidate {
    VerificationCandidate {
        method: "passive_extended_observation".to_string(),
        estimated_information_gain: 0.2,
        estimated_network_cost: 0.0,
        estimated_runtime_ms: 0,
        disruption_risk: 0.0,
        requires_approval: false,
    }
}

/// A9 guardrail, krok 2 (`docs/diplomka/produkcni-plan.md`, Faze B): katalog
/// REALNYCH kandidatu na dalsi overovaci kontrolu, odvozeny z `hypothesis_type`
/// (= `Finding::finding_type`, viz `hypothesis.rs`). Mapuje na metody, ktere uz
/// v produkci existuji (`nmap::run_targeted_followup_nmap`, webscan/lab obsahova
/// inspekce, `intel.rs` CVE lookup) - ne na vymyslene nazvy. Tohle je JEN katalog
/// (co by se mohlo udelat); samotna exekuce je navazujici, samostatny krok (A9
/// pozaduje i rozpoctove/rate-limit mantinely pred tim, nez se cokoliv skutecne
/// zavola).
///
/// Neznamy `hypothesis_type` dostane jen baseline kandidata - fail-safe (zadna
/// aktivni kontrola neni lepsi nez vymyslena pro typ, ktery katalog nezna), ne
/// chyba.
pub fn candidates_for_hypothesis_type(hypothesis_type: &str) -> Vec<VerificationCandidate> {
    let mut candidates = vec![passive_extended_observation_candidate()];
    match hypothesis_type {
        "identification_gap" | "correlation_uncertainty" => {
            // nmap::run_targeted_followup_nmap - aktivni skriptovany sken (-sV -sC),
            // nad uroven "read-only" - vyzaduje schvaleni.
            candidates.push(VerificationCandidate {
                method: "nmap_targeted_followup".to_string(),
                estimated_information_gain: 0.6,
                estimated_network_cost: 0.05,
                estimated_runtime_ms: 20_000,
                disruption_risk: 0.3,
                requires_approval: true,
            });
        }
        "management_surface_exposure"
        | "new_exposed_service"
        | "plaintext_management_protocol"
        | "http_basic_without_tls"
        | "insecure_auth_possible" => {
            // Obsahova inspekce stylu lab::execute_inspect_metrics_content - jeden
            // read-only HTTP GET, ne destruktivni zapis - nevyzaduje schvaleni.
            candidates.push(VerificationCandidate {
                method: "read_only_content_inspection".to_string(),
                estimated_information_gain: 0.5,
                estimated_network_cost: 0.01,
                estimated_runtime_ms: 1_500,
                disruption_risk: 0.05,
                requires_approval: false,
            });
        }
        "high_risk_cve_exposure"
        | "known_exploited_vulnerability"
        | "probable_exploitation_interest" => {
            // intel.rs re-lookup proti uz stazene CVE/KEV cache - cisty read, zadny
            // dotek cileove site.
            candidates.push(VerificationCandidate {
                method: "cve_intel_relookup".to_string(),
                estimated_information_gain: 0.4,
                estimated_network_cost: 0.0,
                estimated_runtime_ms: 500,
                disruption_risk: 0.0,
                requires_approval: false,
            });
        }
        _ => {}
    }
    candidates
}

/// Katalog s odhady z historie: pro kazdou metodu s `>= MIN_SAMPLES_FOR_HISTORY`
/// realnymi vzorky se `estimated_runtime_ms`/`network_cost`/`information_gain`
/// nahradi prumerem (`case_history::derive_candidate_from_samples`);
/// `disruption_risk` a `requires_approval` zustavaji z katalogu (bezpecnostni
/// rozhodnuti se neuci z mereni rychlosti). Metody bez dost vzorku zustavaji na
/// kuratorskych konstantach v `candidates_for_hypothesis_type` - historie pro ne
/// jeste neexistuje, takze zadne vymysleni.
pub fn candidates_with_history(
    hypothesis_type: &str,
    history: &VerificationHistory,
) -> Vec<VerificationCandidate> {
    candidates_for_hypothesis_type(hypothesis_type)
        .into_iter()
        .map(|candidate| {
            let samples = history.samples(&candidate.method);
            if samples.len() >= MIN_SAMPLES_FOR_HISTORY {
                derive_candidate_from_samples(
                    &candidate.method,
                    samples,
                    candidate.disruption_risk,
                    candidate.requires_approval,
                )
            } else {
                candidate
            }
        })
        .collect()
}

/// Vysledek planovani pro JEDNU hypotezu - stinovy/aditivni vystup (viz
/// `RunReport.verification_plans`). `excluded_out_of_scope` jsou assety z
/// `hypothesis.affected_assets`, ktere `ScopePolicy` vyradila PRED planovanim -
/// reportovano, ne tise zahozeno (stejna disciplina jako `nmap.rs`'s
/// `filter_targets_in_scope`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HypothesisVerificationPlan {
    pub hypothesis_type: String,
    pub in_scope_assets: Vec<String>,
    pub excluded_out_of_scope: Vec<String>,
    pub plan: VerificationPlan,
}

/// Spojuje katalog + `ScopePolicy` + `plan_verification` do jednoho kroku pro
/// jednu hypotezu. `None` pokud VSECHNY `affected_assets` jsou mimo `scope` -
/// takova hypoteza se vubec neplanuje (nic k overeni neni autorizovano skenovat).
pub fn plan_for_hypothesis(
    hypothesis: &SecurityHypothesis,
    scope: &crate::scope_policy::ScopePolicy,
) -> Option<HypothesisVerificationPlan> {
    plan_for_hypothesis_with_history(hypothesis, scope, &VerificationHistory::default())
}

/// Stejne jako `plan_for_hypothesis`, ale odhady nakladu/zisku vezme z historie
/// skutecnych vykonani, kde jich je dost (`candidates_with_history`). S prazdnou
/// historii je vystup bajtove shodny s `plan_for_hypothesis`.
pub fn plan_for_hypothesis_with_history(
    hypothesis: &SecurityHypothesis,
    scope: &crate::scope_policy::ScopePolicy,
    history: &VerificationHistory,
) -> Option<HypothesisVerificationPlan> {
    let (in_scope_assets, excluded_out_of_scope) = scope.partition(
        hypothesis.affected_assets.clone(),
        std::string::String::as_str,
    );
    if in_scope_assets.is_empty() {
        return None;
    }
    let candidates = candidates_with_history(&hypothesis.hypothesis_type, history);
    let plan = plan_verification(hypothesis, candidates);
    Some(HypothesisVerificationPlan {
        hypothesis_type: hypothesis.hypothesis_type.clone(),
        in_scope_assets,
        excluded_out_of_scope,
        plan,
    })
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

    fn hypothesis_with_assets(assets: &[&str]) -> SecurityHypothesis {
        let mut h = hypothesis(0.6);
        h.affected_assets = assets.iter().map(|ip| ip.to_string()).collect();
        h
    }

    fn sample(runtime_ms: u64, cost: f64, gain: f64) -> crate::case_history::ExecutionSample {
        crate::case_history::ExecutionSample {
            runtime_ms,
            network_cost: cost,
            information_gain: gain,
        }
    }

    #[test]
    fn empty_history_gives_byte_identical_catalog_for_every_known_type() {
        let empty = VerificationHistory::default();
        for kind in [
            "identification_gap",
            "correlation_uncertainty",
            "management_surface_exposure",
            "new_exposed_service",
            "plaintext_management_protocol",
            "http_basic_without_tls",
            "insecure_auth_possible",
            "high_risk_cve_exposure",
            "known_exploited_vulnerability",
            "probable_exploitation_interest",
            "unknown",
        ] {
            assert_eq!(
                serde_json::to_string(&candidates_with_history(kind, &empty)).unwrap(),
                serde_json::to_string(&candidates_for_hypothesis_type(kind)).unwrap(),
                "{kind}"
            );
        }
        let h = hypothesis(0.7);
        let scope = crate::scope_policy::ScopePolicy::new(vec!["10.0.0.0/8".parse().unwrap()]);
        assert_eq!(
            serde_json::to_string(&plan_for_hypothesis(&h, &scope)).unwrap(),
            serde_json::to_string(&plan_for_hypothesis_with_history(&h, &scope, &empty)).unwrap()
        );
    }

    #[test]
    fn history_overrides_estimates_only_after_three_samples_and_keeps_safety_fields() {
        let mut history = VerificationHistory::default();
        history.record("nmap_targeted_followup", sample(1000, 0.5, 0.2));
        history.record("nmap_targeted_followup", sample(3000, 0.5, 0.4));
        let two = candidates_with_history("identification_gap", &history);
        let nmap = two
            .iter()
            .find(|c| c.method == "nmap_targeted_followup")
            .unwrap();
        assert_eq!(nmap.estimated_runtime_ms, 20_000, "2 vzorky stale nestaci");

        history.record("nmap_targeted_followup", sample(2000, 0.5, 0.3));
        let three = candidates_with_history("identification_gap", &history);
        let nmap = three
            .iter()
            .find(|c| c.method == "nmap_targeted_followup")
            .unwrap();
        assert_eq!(nmap.estimated_runtime_ms, 2000);
        assert!((nmap.estimated_network_cost - 0.5).abs() < 1e-12);
        assert!((nmap.estimated_information_gain - 0.3).abs() < 1e-12);
        assert!(
            (nmap.disruption_risk - 0.3).abs() < 1e-12,
            "disruption z katalogu"
        );
        assert!(nmap.requires_approval, "approval gate z katalogu");
        let baseline = three
            .iter()
            .find(|c| c.method == "passive_extended_observation")
            .unwrap();
        assert_eq!(baseline.estimated_information_gain, 0.2);
    }

    #[test]
    fn history_changes_the_ranking_when_real_measurements_differ_from_guesses() {
        let mut history = VerificationHistory::default();
        for _ in 0..3 {
            history.record("nmap_targeted_followup", sample(100, 0.0, 1.0));
        }
        let mut h = hypothesis(0.9);
        h.hypothesis_type = "identification_gap".to_string();
        let scope = crate::scope_policy::ScopePolicy::new(vec!["10.0.0.0/8".parse().unwrap()]);
        let before = plan_for_hypothesis(&h, &scope).unwrap();
        let after = plan_for_hypothesis_with_history(&h, &scope, &history).unwrap();
        assert_eq!(
            before.plan.chosen.unwrap().candidate.method,
            "passive_extended_observation"
        );
        assert_eq!(
            after.plan.chosen.unwrap().candidate.method,
            "nmap_targeted_followup"
        );
    }

    #[test]
    fn candidates_for_unknown_hypothesis_type_returns_only_baseline() {
        let candidates = candidates_for_hypothesis_type("nejaky_neznamy_typ");
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].method, "passive_extended_observation");
        assert!(!candidates[0].requires_approval);
    }

    #[test]
    fn candidates_for_identification_gap_add_approval_gated_active_check() {
        let candidates = candidates_for_hypothesis_type("identification_gap");
        assert_eq!(candidates.len(), 2);
        let active = candidates
            .iter()
            .find(|c| c.method == "nmap_targeted_followup")
            .expect("aktivni kandidat musi byt v katalogu pro identification_gap");
        assert!(
            active.requires_approval,
            "aktivni skenovaci kontrola musi vyzadovat schvaleni (A9)"
        );
    }

    #[test]
    fn candidates_for_management_surface_exposure_are_read_only_no_approval() {
        let candidates = candidates_for_hypothesis_type("management_surface_exposure");
        let read_only = candidates
            .iter()
            .find(|c| c.method == "read_only_content_inspection")
            .expect("read-only kandidat musi byt v katalogu");
        assert!(
            !read_only.requires_approval,
            "read-only kontrola nesmi vyzadovat schvaleni"
        );
    }

    #[test]
    fn plan_for_hypothesis_returns_none_when_all_assets_out_of_scope() {
        let h = hypothesis_with_assets(&["203.0.113.50"]);
        let scope = crate::scope_policy::ScopePolicy::new(vec![
            "192.168.1.0/24".parse().expect("valid cidr"),
        ]);

        assert!(
            plan_for_hypothesis(&h, &scope).is_none(),
            "hypoteza bez jedineho assetu v rozsahu se nesmi planovat"
        );
    }

    #[test]
    fn plan_for_hypothesis_builds_plan_when_asset_in_scope() {
        let h = hypothesis_with_assets(&["192.168.1.10"]);
        let scope = crate::scope_policy::ScopePolicy::new(vec![
            "192.168.1.0/24".parse().expect("valid cidr"),
        ]);

        let result =
            plan_for_hypothesis(&h, &scope).expect("asset je v rozsahu, plan se musi postavit");
        assert_eq!(result.in_scope_assets, vec!["192.168.1.10".to_string()]);
        assert!(result.excluded_out_of_scope.is_empty());
        assert!(result.plan.chosen.is_some());
    }

    #[test]
    fn plan_for_hypothesis_reports_mixed_scope_assets_without_dropping_silently() {
        let h = hypothesis_with_assets(&["192.168.1.10", "203.0.113.50"]);
        let scope = crate::scope_policy::ScopePolicy::new(vec![
            "192.168.1.0/24".parse().expect("valid cidr"),
        ]);

        let result = plan_for_hypothesis(&h, &scope).expect("alespon 1 asset je v rozsahu");
        assert_eq!(result.in_scope_assets, vec!["192.168.1.10".to_string()]);
        assert_eq!(
            result.excluded_out_of_scope,
            vec!["203.0.113.50".to_string()]
        );
    }
}
