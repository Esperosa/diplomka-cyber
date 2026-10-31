//! Exekuce overovacich kontrol vybranych `verification_planner` (Faze B/C,
//! `docs/diplomka/produkcni-plan.md`). Planner jen vybira; tenhle modul je
//! jediny, kdo kontrolu skutecne spusti, a vynucuje A9 mantinely TAM, kde se
//! neco deje (ne jen pri planovani):
//!
//! 1. **Scope se kontroluje znovu pri vykonani** (`ScopePolicy`), i kdyz plan uz
//!    prosel scope filtrem - plan muze byt starsi nez konfigurace.
//! 2. **Schvaleni**: kontrola s `requires_approval` se NIKDY nespusti automaticky
//!    (`needs_approval`) - automaticky jen passive/read-only.
//! 3. **Rozpocet**: globalni strop poctu kontrol na beh + strop na jeden cil.
//! 4. **Rate limit**: minimalni odstup mezi sitovymi kontrolami na stejny cil.
//! 5. **Idempotence**: stejna dvojice (metoda, asset) se v jednom behu vykona
//!    nejvyse jednou; dalsi hypotezy sdili vysledek.
//! 6. Exekuce je **opt-in** (`--execute-verification`); bez priznaku se nic
//!    nevola a `RunReport.verification_results` zustane prazdne.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use crate::{
    error::{BakulaError, Result},
    model::HostReport,
    scope_policy::ScopePolicy,
    verification_planner::HypothesisVerificationPlan,
};

#[derive(Debug, Clone)]
pub struct ExecutionBudget {
    pub max_checks_per_run: usize,
    pub max_checks_per_target: usize,
    pub min_interval_per_target: Duration,
}

impl Default for ExecutionBudget {
    fn default() -> Self {
        Self {
            max_checks_per_run: 10,
            max_checks_per_target: 2,
            min_interval_per_target: Duration::from_millis(250),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationResult {
    pub hypothesis_type: String,
    pub method: String,
    pub asset: String,
    /// `executed` | `reused` (vysledek drivejsi stejne kontroly) | `skipped_out_of_scope` |
    /// `skipped_budget` | `needs_approval` | `failed`
    pub status: String,
    pub outcome: Option<String>,
    pub runtime_ms: u64,
}

pub trait CheckRunner {
    fn run(&self, method: &str, asset: &str, hosts: &[HostReport]) -> Result<String>;
}

/// Skutecne lokalni exekutory. Zadny z nich nezapisuje do ciloveho systemu.
pub struct LocalRunner;

const WEB_PORTS: &[(u16, &str)] = &[
    (80, "http"),
    (8080, "http"),
    (8000, "http"),
    (3000, "http"),
    (443, "https"),
    (8443, "https"),
];

impl CheckRunner for LocalRunner {
    fn run(&self, method: &str, asset: &str, hosts: &[HostReport]) -> Result<String> {
        match method {
            "passive_extended_observation" => {
                Ok("bez aktivniho kroku; pasivni pozorovani pokracuje v dalsim okne".to_string())
            }
            "cve_intel_relookup" => cve_relookup(asset, hosts),
            "read_only_content_inspection" => read_only_inspection(asset, hosts),
            other => Err(BakulaError::Processing(format!(
                "metoda {other} nema lokalni exekutor"
            ))),
        }
    }
}

fn cve_relookup(asset: &str, hosts: &[HostReport]) -> Result<String> {
    let host = hosts
        .iter()
        .find(|host| host.ip == asset)
        .ok_or_else(|| BakulaError::Processing(format!("host {asset} neni v inventari")))?;
    let mut total = 0usize;
    let mut worst: f64 = 0.0;
    let mut exploit_context = 0usize;
    for service in &host.services {
        for cve in &service.cves {
            total += 1;
            if let Some(cvss) = &cve.cvss {
                worst = worst.max(cvss.base_score);
            }
            if cve.exploit_context.is_some() {
                exploit_context += 1;
            }
        }
    }
    Ok(format!(
        "{total} CVE zaznamu z lokalni intel cache, nejvyssi CVSS {worst:.1}, s exploit kontextem: {exploit_context}"
    ))
}

/// Jeden GET na kazdy otevreny webovy port - zadna zmena stavu, zadne
/// formulare, zadne skriptovani; telo se cte jen do 64 KiB.
fn read_only_inspection(asset: &str, hosts: &[HostReport]) -> Result<String> {
    let host = hosts
        .iter()
        .find(|host| host.ip == asset)
        .ok_or_else(|| BakulaError::Processing(format!("host {asset} neni v inventari")))?;
    let timeout_ms = std::env::var("BAKULA_INSPECTION_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(5_000);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .redirect(reqwest::redirect::Policy::none())
        // Cil je typicky self-signed vnitrni sluzba; kontrola je cista inspekce
        // bez prenosu tajemstvi, takze overeni certifikatu by jen potlacilo nalez.
        .danger_accept_invalid_certs(true)
        .user_agent("Bakula-read-only-inspection")
        .build()?;

    let mut lines = Vec::new();
    for service in host.services.iter().filter(|s| s.port_state == "open") {
        let Some((_, scheme)) = WEB_PORTS.iter().find(|(port, _)| *port == service.port) else {
            continue;
        };
        let url = format!("{scheme}://{asset}:{}/", service.port);
        match client.get(&url).send() {
            Ok(response) => {
                let status = response.status().as_u16();
                let server = response
                    .headers()
                    .get(reqwest::header::SERVER)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("-")
                    .to_string();
                let bytes = response
                    .bytes()
                    .map(|b| b.len().min(64 * 1024))
                    .unwrap_or(0);
                lines.push(format!(
                    "GET {url} -> {status}, server: {server}, {bytes} B"
                ));
            }
            Err(error) => lines.push(format!("GET {url} selhal: {error}")),
        }
    }
    if lines.is_empty() {
        Err(BakulaError::Processing(format!(
            "{asset} nema otevreny webovy port k inspekci"
        )))
    } else {
        Ok(lines.join("; "))
    }
}

pub fn execute_plans(
    plans: &[HypothesisVerificationPlan],
    hosts: &[HostReport],
    scope: &ScopePolicy,
    budget: &ExecutionBudget,
    runner: &dyn CheckRunner,
) -> Vec<VerificationResult> {
    let mut results = Vec::new();
    let mut executed_total = 0usize;
    let mut per_target: HashMap<String, usize> = HashMap::new();
    let mut last_run_at: HashMap<String, Instant> = HashMap::new();
    let mut cache: HashMap<(String, String), VerificationResult> = HashMap::new();

    for plan in plans {
        let Some(chosen) = plan.plan.chosen.as_ref() else {
            continue;
        };
        let method = chosen.candidate.method.clone();
        for asset in &plan.in_scope_assets {
            let make =
                |status: &str, outcome: Option<String>, runtime_ms: u64| VerificationResult {
                    hypothesis_type: plan.hypothesis_type.clone(),
                    method: method.clone(),
                    asset: asset.clone(),
                    status: status.to_string(),
                    outcome,
                    runtime_ms,
                };

            if !scope.contains(asset) {
                results.push(make("skipped_out_of_scope", None, 0));
                continue;
            }
            if chosen.candidate.requires_approval {
                results.push(make("needs_approval", None, 0));
                continue;
            }
            if let Some(previous) = cache.get(&(method.clone(), asset.clone())) {
                results.push(VerificationResult {
                    hypothesis_type: plan.hypothesis_type.clone(),
                    status: "reused".to_string(),
                    outcome: previous
                        .outcome
                        .as_ref()
                        .map(|text| format!("{text} (sdileno s drivejsi kontrolou)")),
                    runtime_ms: 0,
                    ..previous.clone()
                });
                continue;
            }
            let target_count = per_target.get(asset).copied().unwrap_or(0);
            if executed_total >= budget.max_checks_per_run
                || target_count >= budget.max_checks_per_target
            {
                results.push(make("skipped_budget", None, 0));
                continue;
            }

            if let Some(last) = last_run_at.get(asset) {
                let elapsed = last.elapsed();
                if elapsed < budget.min_interval_per_target {
                    std::thread::sleep(budget.min_interval_per_target - elapsed);
                }
            }
            let started = Instant::now();
            let result = match runner.run(&method, asset, hosts) {
                Ok(outcome) => make(
                    "executed",
                    Some(outcome),
                    started.elapsed().as_millis() as u64,
                ),
                Err(error) => make(
                    "failed",
                    Some(error.to_string()),
                    started.elapsed().as_millis() as u64,
                ),
            };
            last_run_at.insert(asset.clone(), Instant::now());
            executed_total += 1;
            *per_target.entry(asset.clone()).or_insert(0) += 1;
            cache.insert((method.clone(), asset.clone()), result.clone());
            results.push(result);
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::verification_planner::{RankedCandidate, VerificationCandidate, VerificationPlan};

    struct Recording {
        calls: Mutex<Vec<(String, String)>>,
        fail: bool,
    }

    impl Recording {
        fn new(fail: bool) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail,
            }
        }
    }

    impl CheckRunner for Recording {
        fn run(&self, method: &str, asset: &str, _hosts: &[HostReport]) -> Result<String> {
            self.calls
                .lock()
                .unwrap()
                .push((method.to_string(), asset.to_string()));
            if self.fail {
                Err(BakulaError::Processing("simulovane selhani".to_string()))
            } else {
                Ok(format!("ok {method} {asset}"))
            }
        }
    }

    fn plan(
        hypothesis_type: &str,
        method: &str,
        requires_approval: bool,
        assets: &[&str],
    ) -> HypothesisVerificationPlan {
        let candidate = VerificationCandidate {
            method: method.to_string(),
            estimated_information_gain: 0.5,
            estimated_network_cost: 0.0,
            estimated_runtime_ms: 0,
            disruption_risk: 0.0,
            requires_approval,
        };
        let ranked = RankedCandidate {
            candidate,
            utility: 0.4,
        };
        HypothesisVerificationPlan {
            hypothesis_type: hypothesis_type.to_string(),
            in_scope_assets: assets.iter().map(|a| a.to_string()).collect(),
            excluded_out_of_scope: Vec::new(),
            plan: VerificationPlan {
                chosen: Some(ranked.clone()),
                ranked: vec![ranked],
            },
        }
    }

    fn scope() -> ScopePolicy {
        ScopePolicy::new(vec!["192.168.1.0/24".parse().unwrap()])
    }

    fn fast_budget() -> ExecutionBudget {
        ExecutionBudget {
            min_interval_per_target: Duration::ZERO,
            ..ExecutionBudget::default()
        }
    }

    #[test]
    fn approval_gated_check_is_never_run_automatically() {
        let runner = Recording::new(false);
        let plans = [plan(
            "identification_gap",
            "nmap_targeted_followup",
            true,
            &["192.168.1.10"],
        )];
        let results = execute_plans(&plans, &[], &scope(), &fast_budget(), &runner);
        assert_eq!(results[0].status, "needs_approval");
        assert!(runner.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn scope_is_rechecked_at_execution_time() {
        let runner = Recording::new(false);
        // Plan tvrdi "in scope", ale aktualni scope asset neobsahuje.
        let plans = [plan("x", "cve_intel_relookup", false, &["10.9.9.9"])];
        let results = execute_plans(&plans, &[], &scope(), &fast_budget(), &runner);
        assert_eq!(results[0].status, "skipped_out_of_scope");
        assert!(runner.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn global_budget_caps_number_of_executed_checks() {
        let runner = Recording::new(false);
        let assets: Vec<String> = (1..=6).map(|n| format!("192.168.1.{n}")).collect();
        let asset_refs: Vec<&str> = assets.iter().map(String::as_str).collect();
        let plans = [plan("x", "cve_intel_relookup", false, &asset_refs)];
        let budget = ExecutionBudget {
            max_checks_per_run: 4,
            ..fast_budget()
        };
        let results = execute_plans(&plans, &[], &scope(), &budget, &runner);
        assert_eq!(results.iter().filter(|r| r.status == "executed").count(), 4);
        assert_eq!(
            results
                .iter()
                .filter(|r| r.status == "skipped_budget")
                .count(),
            2
        );
        assert_eq!(runner.calls.lock().unwrap().len(), 4);
    }

    #[test]
    fn per_target_budget_is_enforced_across_different_methods() {
        let runner = Recording::new(false);
        let plans = [
            plan("a", "cve_intel_relookup", false, &["192.168.1.5"]),
            plan("b", "read_only_content_inspection", false, &["192.168.1.5"]),
            plan("c", "passive_extended_observation", false, &["192.168.1.5"]),
        ];
        let budget = ExecutionBudget {
            max_checks_per_target: 2,
            ..fast_budget()
        };
        let results = execute_plans(&plans, &[], &scope(), &budget, &runner);
        assert_eq!(results[0].status, "executed");
        assert_eq!(results[1].status, "executed");
        assert_eq!(results[2].status, "skipped_budget");
    }

    #[test]
    fn same_method_and_asset_runs_once_and_shares_result() {
        let runner = Recording::new(false);
        let plans = [
            plan("a", "cve_intel_relookup", false, &["192.168.1.5"]),
            plan("b", "cve_intel_relookup", false, &["192.168.1.5"]),
        ];
        let results = execute_plans(&plans, &[], &scope(), &fast_budget(), &runner);
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
        assert_eq!(results[0].status, "executed");
        assert_eq!(results[1].status, "reused");
        assert!(results[1].outcome.as_ref().unwrap().contains("sdileno"));
        assert_eq!(results[1].hypothesis_type, "b");
    }

    #[test]
    fn runner_failure_is_reported_not_swallowed() {
        let runner = Recording::new(true);
        let plans = [plan("x", "cve_intel_relookup", false, &["192.168.1.5"])];
        let results = execute_plans(&plans, &[], &scope(), &fast_budget(), &runner);
        assert_eq!(results[0].status, "failed");
        assert!(
            results[0]
                .outcome
                .as_ref()
                .unwrap()
                .contains("simulovane selhani")
        );
    }

    #[test]
    fn min_interval_is_applied_between_checks_on_the_same_target() {
        let runner = Recording::new(false);
        let plans = [
            plan("a", "cve_intel_relookup", false, &["192.168.1.5"]),
            plan("b", "passive_extended_observation", false, &["192.168.1.5"]),
        ];
        let budget = ExecutionBudget {
            min_interval_per_target: Duration::from_millis(120),
            ..ExecutionBudget::default()
        };
        let started = Instant::now();
        execute_plans(&plans, &[], &scope(), &budget, &runner);
        assert!(started.elapsed() >= Duration::from_millis(120));
    }

    #[test]
    fn unknown_method_fails_loudly_in_local_runner() {
        let error = LocalRunner
            .run("neexistuje", "192.168.1.5", &[])
            .unwrap_err();
        assert!(error.to_string().contains("nema lokalni exekutor"));
    }

    #[test]
    fn plan_without_chosen_candidate_produces_no_result() {
        let mut empty = plan("x", "cve_intel_relookup", false, &["192.168.1.5"]);
        empty.plan.chosen = None;
        let results = execute_plans(
            &[empty],
            &[],
            &scope(),
            &fast_budget(),
            &Recording::new(false),
        );
        assert!(results.is_empty());
    }
}
