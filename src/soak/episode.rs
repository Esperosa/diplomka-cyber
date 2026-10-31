//! Jeden epizod = jedna virtualni sit zivena nekolik virtualnich dni. Kazdy cyklus
//! (30 virtualnich minut) projde TEMI SAMYMI produkcnimi funkcemi jako skutecny beh:
//! detektor -> Suricata parser -> fuze -> korelace -> report -> nalezy -> rozhodnuti
//! -> identita -> hypotezy -> plany -> vykonani kontrol -> zasahy (ops.rs + simulovane
//! jadro). Vysledek se porovna s ground truth a zkontroluji se invarianty.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Instant,
};

use chrono::{DateTime, Utc};
use ipnet::IpNet;

use crate::{
    case_memory::{
        CaseMemory, CaseRecord, CaseSource, Outcome, RecordOutcome, case_from_verification_result,
    },
    correlation, decision,
    enforcement::{BlockIpRequest, ProtectedRanges},
    error::{BakulaError, Result},
    findings, fusion,
    identity::{IdentityMatch, IdentityResolver},
    model::{Finding, HostReport, NormalizedEvent, PassiveWindow, RunReport, SourceMetadata},
    ops::{EnforcementMode, NftExecutor, OpsStore, ProposeError},
    passive::{
        ConnectionDetector, ConnectionObservation, LegacyAnomalyDetector, parse_suricata_str,
        score_source_hosts,
    },
    report,
    scope_policy::ScopePolicy,
    soak::{
        kernel::SimKernel,
        netmodel::{Archetype, NetworkModel},
        rng::{Rng, derive},
        stats::{Aggregate, FamilyStats},
        traffic::{
            CYCLE_SECS, CycleContext, Kind, Lookalike, Telemetry, Truth, generate_cycle,
            plan_episode, random_telemetry, seed_for_cycle, ts,
        },
    },
    verification_exec::{self, CheckRunner, ExecutionBudget, LocalRunner},
    verification_planner,
};

/// Po kolika cyklech po konci utoku jeste povazujeme nalez za prislusny utoku.
const ATTRIBUTION_LATENCY: u32 = 2;
const RANK_TOP_K: usize = 3;

#[derive(Debug, Clone)]
pub struct EpisodeConfig {
    pub run_seed: u64,
    pub network_id: u64,
    /// 0 = delka podle seedu (24/48/72/96 virtualnich hodin).
    pub hours: u32,
    pub scratch: PathBuf,
}

/// Typy nalezu odvozene z inventare (ne z provozu): nejsou "poplachy", takze se
/// nepocitaji do FP/TP behavioralnich nalezu, meri se zvlast (exposure recall).
fn is_static_exposure(finding_type: &str) -> bool {
    matches!(
        finding_type,
        "plaintext_management_protocol"
            | "high_risk_cve_exposure"
            | "known_exploited_vulnerability"
            | "probable_exploitation_interest"
            | "identification_gap"
            | "management_surface_exposure"
            | "new_exposed_service"
            | "correlation_uncertainty"
    ) || finding_type.starts_with("intel:")
        || finding_type.starts_with("active_check:")
}

struct SimRunner<'a> {
    model: &'a NetworkModel,
    cycle: u32,
    seed: u64,
}

impl CheckRunner for SimRunner<'_> {
    fn run(&self, method: &str, asset: &str, hosts: &[HostReport]) -> Result<String> {
        // vstrikovane poruchy nastroju: ~4 % kontrol vyprsi / selze (nedostupny cil, timeout)
        let roll = crate::soak::rng::mix(
            asset
                .bytes()
                .chain(method.bytes())
                .fold(self.seed ^ self.cycle as u64, |a, b| {
                    a.wrapping_mul(131).wrapping_add(b as u64)
                }),
        ) % 100;
        if roll < 4 {
            return Err(BakulaError::Processing(format!(
                "simulovany timeout nastroje {method} proti {asset}"
            )));
        }
        if method != "read_only_content_inspection" {
            return LocalRunner.run(method, asset, hosts);
        }
        let device = self
            .model
            .device_by_ip(asset)
            .ok_or_else(|| BakulaError::Processing(format!("{asset} neni v modelu")))?;
        let lines: Vec<String> = self.model.devices[device as usize]
            .services
            .iter()
            .filter(|s| s.web)
            .map(|s| {
                format!(
                    "GET http://{asset}:{}/ -> 200, server: {}",
                    s.port, s.product
                )
            })
            .collect();
        if lines.is_empty() {
            Err(BakulaError::Processing(format!(
                "{asset} nema otevreny webovy port k inspekci"
            )))
        } else {
            Ok(lines.join("; "))
        }
    }
}

struct Ledger {
    first_detect: Option<u32>,
    typed: bool,
    ranked_prod: bool,
    ranked_egress: bool,
}

fn key_ips(truth: &Truth, ips: &[String], rogue: &Option<(String, String)>) -> Vec<String> {
    let mut keys: BTreeSet<String> = BTreeSet::new();
    for &victim in &truth.victim_devices {
        keys.insert(ips[victim as usize].clone());
    }
    if let Some(device) = truth.attacker_device {
        keys.insert(ips[device as usize].clone());
    }
    if let Some(ip) = &truth.attacker_external {
        keys.insert(ip.clone());
    }
    if let Some(ip) = &truth.target_external {
        keys.insert(ip.clone());
    }
    if matches!(
        truth.kind,
        Kind::Attack(crate::soak::traffic::Family::RogueDevice)
    ) {
        if let Some((ip, _)) = rogue {
            keys.insert(ip.clone());
        }
    }
    keys.into_iter().collect()
}

/// Presny vyskyt IPv4 adresy v textu: "10.0.0.1" nesmi sedet v "10.0.0.15" ani v "110.0.0.1".
fn mentions_ip(text: &str, ip: &str) -> bool {
    let bytes = text.as_bytes();
    let mut start = 0;
    while let Some(found) = text[start..].find(ip) {
        let at = start + found;
        let end = at + ip.len();
        let before_ok = at == 0 || {
            let prev = bytes[at - 1];
            !(prev.is_ascii_digit() || (prev == b'.' && at >= 2 && bytes[at - 2].is_ascii_digit()))
        };
        let after_ok = end >= bytes.len() || {
            let next = bytes[end];
            !(next.is_ascii_digit()
                || (next == b'.' && end + 1 < bytes.len() && bytes[end + 1].is_ascii_digit()))
        };
        if before_ok && after_ok {
            return true;
        }
        start = at + 1;
    }
    false
}

fn finding_mentions(finding: &Finding, keys: &[String]) -> bool {
    if let Some(host) = &finding.host_key {
        if keys.iter().any(|k| k == host) {
            return true;
        }
    }
    keys.iter().any(|k| {
        mentions_ip(&finding.title, k)
            || mentions_ip(&finding.rationale, k)
            || finding.evidence.iter().any(|e| mentions_ip(e, k))
    })
}

fn stage<T>(agg: &mut Aggregate, name: &str, work: impl FnOnce() -> T) -> T {
    let started = Instant::now();
    let value = work();
    agg.perf_record(name, started.elapsed().as_secs_f64());
    value
}

struct EpisodeDigest(u64);

impl EpisodeDigest {
    fn feed(&mut self, value: u64) {
        self.0 = crate::soak::rng::mix(self.0 ^ value);
    }
}

pub struct EpisodeResult {
    pub agg: Aggregate,
    pub digest: u64,
}

pub fn run_episode(cfg: &EpisodeConfig) -> EpisodeResult {
    let mut agg = Aggregate::default();
    let mut digest = EpisodeDigest(0x5EED);
    if let Err(error) = run_episode_inner(cfg, &mut agg, &mut digest) {
        agg.violation("episode_error", format!("sit {}: {error}", cfg.network_id));
    }
    agg.networks += 1;
    agg.episodes += 1;
    EpisodeResult {
        digest: digest.0 ^ agg.deterministic_digest(),
        agg,
    }
}

#[allow(clippy::too_many_lines)]
fn run_episode_inner(
    cfg: &EpisodeConfig,
    agg: &mut Aggregate,
    digest: &mut EpisodeDigest,
) -> Result<()> {
    let mut model = NetworkModel::generate(cfg.run_seed, cfg.network_id);
    *agg.archetypes
        .entry(format!("{:?}", model.archetype))
        .or_default() += 1;
    let mut rng = Rng::new(derive(model.seed, 0xE915_0D));
    let telemetry: Telemetry = random_telemetry(&mut rng, model.prefixes.len());
    let hours = if cfg.hours > 0 {
        cfg.hours
    } else {
        // dlouhodobost: male site bezi i mesic virtualniho provozu, velke max tyden
        match model.archetype {
            Archetype::Metro => [24u32, 48, 72, 168][rng.weighted(&[0.3, 0.3, 0.2, 0.2])],
            Archetype::Enterprise
            | Archetype::Hospital
            | Archetype::Industrial
            | Archetype::Campus => {
                [24u32, 48, 72, 168, 336][rng.weighted(&[0.2, 0.2, 0.2, 0.25, 0.15])]
            }
            _ => [24u32, 48, 72, 168, 336, 720, 1440]
                [rng.weighted(&[0.14, 0.14, 0.12, 0.22, 0.17, 0.15, 0.06])],
        }
    };
    let cycles = hours * 2;
    let start_offset_s = rng.range(0, 6) as i64 * 86400;
    // nove (zatim nenasazena) zarizeni pro udalosti onboarding
    let dormant = rng.poisson((hours as f64 / 24.0 * 0.5).min(20.0)) as usize;
    model.add_dormant(&mut rng, dormant);
    let initial_up: Vec<bool> = model.devices.iter().map(|d| d.up).collect();
    for device in &model.devices {
        *agg.roles
            .entry(device.role.label().to_string())
            .or_default() += 1;
        for service in &device.services {
            *agg.services.entry(service.name.to_string()).or_default() += 1;
        }
    }
    let mut truths = plan_episode(&model, &mut rng, hours, &telemetry);
    let restart_cycles: HashSet<u32> = (0..rng.poisson(hours as f64 / 24.0 * 0.25))
        .map(|_| rng.range(1, cycles.saturating_sub(1).max(1) as u64) as u32)
        .collect();
    let mut patched_ids: HashSet<u32> = HashSet::new();
    let mut hosts_devices: Vec<u32> = Vec::new();
    let mut lookalike_with_fp: HashSet<usize> = HashSet::new();

    let clock = Arc::new(AtomicI64::new(
        crate::soak::traffic::EPOCH0 + start_offset_s,
    ));
    let kernel = Arc::new(SimKernel::new(
        clock.clone(),
        0.01,
        derive(model.seed, 0xFA17),
    ));
    let clock_for_ops = clock.clone();
    let ops = OpsStore::open_in_memory()?
        .with_clock(Arc::new(move || ts(clock_for_ops.load(Ordering::SeqCst))));
    let protected_ranges: Vec<IpNet> = [model.gateway, model.dns]
        .iter()
        .map(|d| {
            format!("{}/32", model.ip_of(*d))
                .parse()
                .expect("platny CIDR")
        })
        .collect();
    let protected = ProtectedRanges::with_additional(protected_ranges.clone());

    let scope_nets = model.scope();
    let scope = ScopePolicy::new(scope_nets.clone());
    let mut resolver = IdentityResolver::new();
    let mut memory = CaseMemory::in_memory();
    let poisoned = rng.chance(0.03);
    if poisoned {
        agg.learning.poison_episodes += 1;
    }
    let mut hosts_cache: Vec<HostReport> = Vec::new();
    let mut mac_assets: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut asset_macs: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut ledgers: Vec<Ledger> = truths
        .iter()
        .map(|_| Ledger {
            first_detect: None,
            typed: false,
            ranked_prod: false,
            ranked_egress: false,
        })
        .collect();
    let mut pending: Vec<(i64, u32)> = Vec::new(); // (action id, cycle proposed)
    let mut attributed_noise_cycles = 0u64;
    let mut active_attack_cycles: HashSet<u32> = HashSet::new();
    for truth in &truths {
        if matches!(truth.kind, Kind::Attack(_)) {
            for cycle in truth.start_cycle..=(truth.end_cycle + ATTRIBUTION_LATENCY).min(cycles - 1)
            {
                active_attack_cycles.insert(cycle);
            }
        }
    }
    let rogue_info: Vec<(usize, (String, String))> = truths
        .iter()
        .enumerate()
        .filter(|(_, t)| {
            matches!(
                t.kind,
                Kind::Attack(crate::soak::traffic::Family::RogueDevice)
            )
        })
        .map(|(index, t)| {
            let subnet = model.prefixes[0];
            let octet = 251 + (t.id % 4) as u8; // mimo DHCP/staticky rozsah zarizeni
            let mut rrng = Rng::new(derive(model.seed, 0x6061 + t.id as u64));
            (
                index,
                (
                    format!("{}.{}.{}.{}", subnet[0], subnet[1], subnet[2], octet),
                    format!(
                        "02:ff:{:02x}:{:02x}:{:02x}:{:02x}",
                        rrng.range(0, 255),
                        rrng.range(0, 255),
                        rrng.range(0, 255),
                        rrng.range(0, 255)
                    ),
                ),
            )
        })
        .collect();
    let budget = ExecutionBudget {
        min_interval_per_target: std::time::Duration::ZERO,
        ..ExecutionBudget::default()
    };

    for cycle in 0..cycles {
        let cycle_started = Instant::now();
        let t0 = crate::soak::traffic::cycle_start_abs(start_offset_s, cycle);
        clock.store(t0, Ordering::SeqCst);

        // --- provozni udalosti menici stav modelu: pady, patche, onboarding, vyrazeni ---
        {
            let mut desired = initial_up.clone();
            for truth in &truths {
                let Kind::Benign(look) = truth.kind else {
                    continue;
                };
                if cycle < truth.start_cycle {
                    continue;
                }
                match look {
                    Lookalike::Onboarding => {
                        for &v in &truth.victim_devices {
                            desired[v as usize] = true;
                        }
                        if cycle == truth.start_cycle {
                            agg.ops.onboarded_devices += truth.victim_devices.len() as u64;
                        }
                    }
                    Lookalike::Decommission => {
                        for &v in &truth.victim_devices {
                            desired[v as usize] = false;
                        }
                        if cycle == truth.start_cycle {
                            agg.ops.decommissioned_devices += truth.victim_devices.len() as u64;
                        }
                    }
                    Lookalike::ServiceCrash if cycle <= truth.end_cycle => {
                        for &v in &truth.victim_devices {
                            desired[v as usize] = false;
                        }
                    }
                    Lookalike::PatchWindow if cycle <= truth.end_cycle => {
                        let span = (truth.end_cycle - truth.start_cycle + 1) as usize;
                        for (i, &v) in truth.victim_devices.iter().enumerate() {
                            if cycle as usize == truth.start_cycle as usize + (i % span) {
                                desired[v as usize] = false;
                            }
                            if cycle == truth.start_cycle && model.patch_device(v) {
                                agg.ops.patched_devices += 1;
                                patched_ids.insert(v);
                            }
                        }
                    }
                    _ => {}
                }
            }
            for (index, up) in desired.iter().enumerate() {
                model.devices[index].up = *up;
                if !*up && initial_up[index] {
                    agg.ops.device_down_cycles += 1;
                }
            }
        }
        // restart enginu: ztrata volatilniho stavu (inventar), identita se nacte z uloziste
        if restart_cycles.contains(&cycle) {
            let json = serde_json::to_string(&resolver)
                .map_err(|e| BakulaError::Processing(format!("serializace identity: {e}")))?;
            resolver = serde_json::from_str(&json)
                .map_err(|e| BakulaError::Processing(format!("obnova identity: {e}")))?;
            hosts_cache.clear();
            hosts_devices.clear();
            agg.ops.engine_restarts += 1;
        }

        let churn_share = if matches!(
            model.archetype,
            crate::soak::netmodel::Archetype::Datacenter
        ) {
            0.0
        } else {
            0.01
        };
        let changes = model.churn(&mut rng, churn_share, 0.02);
        agg.identity.churn_events += changes as u64;
        let ips: Vec<String> = (0..model.devices.len() as u32)
            .map(|d| model.ip_of(d))
            .collect();
        let rogue = rogue_info
            .iter()
            .find(|(index, _)| {
                cycle >= truths[*index].start_cycle && cycle <= truths[*index].end_cycle
            })
            .map(|(_, info)| info.clone());
        if kernel.inject_faults(&mut rng).is_some() {
            agg.enforcement.kernel_faults += 1;
        }

        // --- 1. telemetrie ---
        let mut cycle_rng = Rng::new(seed_for_cycle(model.seed, cycle));
        let output = stage(agg, "generate", || {
            let ctx = CycleContext {
                model: &model,
                ips: &ips,
                cycle,
                start_offset_s,
                telemetry: &telemetry,
                oracle: kernel.as_ref(),
                rogue: rogue.clone(),
            };
            generate_cycle(&ctx, &mut truths, &mut cycle_rng)
        });
        agg.cycles += 1;
        agg.virtual_hours += CYCLE_SECS as f64 / 3600.0;
        agg.observations += output.observations.len() as u64;
        agg.alerts += output.alerts.len() as u64;
        agg.outage_cycles += output.outage as u64;
        agg.ops.sensor_down_cycles += output.sensor_down as u64;
        agg.ops.corrupt_alert_lines += output
            .alerts
            .iter()
            .filter(|line| !(line.starts_with("{\"timestamp\":\"20") && line.ends_with("}}")))
            .count() as u64;
        agg.enforcement.benign_flows_total += output.benign_flows;
        agg.enforcement.collateral_flows += output.benign_flows_blocked;

        if let Some(inventory) = &output.inventory {
            let mut hosts = report::normalize_inventory(inventory.clone());
            for host in &mut hosts {
                if let Some(device) = model.device_by_ip(&host.ip) {
                    for service in &mut host.services {
                        if let Some(spec) = model.devices[device as usize]
                            .services
                            .iter()
                            .find(|s| s.port == service.port && s.proto == service.proto)
                        {
                            service.cves = NetworkModel::cve_records(spec);
                        }
                    }
                }
            }
            hosts_cache = hosts;
            hosts_devices = output.inventory_devices.clone();
        }
        let mut hosts = hosts_cache.clone();

        // --- 2. detekce (produkcni cesta: dst musi byt v scope, viz zeek.rs) ---
        let in_scope_obs: Vec<ConnectionObservation> = output
            .observations
            .iter()
            .filter(|o| scope.contains(&o.dst_ip))
            .cloned()
            .collect();
        let known: HashSet<(String, String, u16)> = hosts
            .iter()
            .flat_map(|h| {
                h.services
                    .iter()
                    .filter(|s| s.port_state == "open")
                    .map(move |s| (h.ip.clone(), s.proto.clone(), s.port))
            })
            .collect();
        let mut events: Vec<NormalizedEvent> = stage(agg, "detect", || {
            LegacyAnomalyDetector.detect(in_scope_obs.clone(), &known)
        });
        let window_start = ts(t0 - 3600);
        let window_end = ts(t0 + CYCLE_SECS + 3600);
        if !output.alerts.is_empty() {
            events.extend(parse_suricata_str(
                &output.alerts.join("\n"),
                "soak",
                &scope_nets,
                window_start,
                window_end,
            )?);
        }
        let events = fusion::fuse_same_flow_events(events);
        agg.events += events.len() as u64;

        // --- 3. korelace, report, nalezy ---
        let (mut run_report, identity_map) = stage(agg, "report", || {
            let correlated = correlation::correlate_events(&hosts, events.clone(), 3600);
            let unmapped = report::attach_events(&mut hosts, correlated);
            report::score_services(&mut hosts);
            let matches: Vec<IdentityMatch> = hosts.iter().map(|h| resolver.resolve(h)).collect();
            let identity_map: HashMap<String, IdentityMatch> = hosts
                .iter()
                .map(|h| h.host_key.clone())
                .zip(matches)
                .collect();
            let started: DateTime<Utc> = ts(t0);
            let finished: DateTime<Utc> = ts(t0 + CYCLE_SECS);
            let mut run_report: RunReport = report::build_report(
                &format!("soak-{}-{}", cfg.network_id, cycle),
                &format!("soak:{}:{}", cfg.network_id, cycle),
                started,
                finished,
                scope_nets.clone(),
                Vec::new(),
                "soak",
                "soak",
                "soak",
                PassiveWindow {
                    start: window_start,
                    end: window_end,
                    time_window_s: 3600,
                },
                SourceMetadata::default(),
                hosts.clone(),
                unmapped,
            );
            run_report.findings = findings::generate_findings(&run_report);
            run_report
                .findings
                .sort_by(|l, r| l.finding_id.cmp(&r.finding_id));
            run_report
                .findings
                .dedup_by(|l, r| l.finding_id == r.finding_id);
            (run_report, identity_map)
        });
        agg.findings += run_report.findings.len() as u64;
        let _ = stage(agg, "decision", || {
            decision::build_decision_bundle(&run_report).actions.len()
        });

        // identita proti ground truth
        // `hosts` ma poradi inventare (= poradi zarizeni v modelu), proto index = zarizeni;
        // `run_report.hosts` je serazene podle IP, ne podle zarizeni.
        for (index, host) in hosts.iter().enumerate() {
            let Some(device) = hosts_devices
                .get(index)
                .and_then(|id| model.devices.get(*id as usize))
            else {
                continue; // rogue host pripojeny na konec inventare
            };
            let mac = &device.mac;
            match identity_map.get(&host.host_key) {
                Some(IdentityMatch::Ambiguous { .. }) => agg.identity.ambiguous_flagged += 1,
                Some(matched) => {
                    mac_assets
                        .entry(mac.clone())
                        .or_default()
                        .insert(matched.asset_id().to_string());
                    asset_macs
                        .entry(matched.asset_id().to_string())
                        .or_default()
                        .insert(mac.clone());
                }
                None => {}
            }
        }

        // --- 4. hypotezy, plany, vykonani kontrol ---
        let (plans, results, bad_probability, hypotheses) =
            stage(agg, "hypothesis_plan_exec", || {
                let hypotheses = crate::hypothesis::build_hypotheses_for_report(
                    &run_report.findings,
                    &run_report.hosts,
                    &identity_map,
                    Some(&memory),
                );
                let bad_probability = hypotheses
                    .iter()
                    .filter_map(|h| h.probability)
                    .find(|p| !(0.0..=1.0).contains(p));
                let plans: Vec<verification_planner::HypothesisVerificationPlan> = hypotheses
                    .iter()
                    .filter_map(|h| verification_planner::plan_for_hypothesis(h, &scope))
                    .collect();
                let runner = SimRunner {
                    model: &model,
                    cycle,
                    seed: model.seed,
                };
                let results = verification_exec::execute_plans(
                    &plans,
                    &run_report.hosts,
                    &scope,
                    &budget,
                    &runner,
                );
                (plans, results, bad_probability, hypotheses)
            });
        if let Some(p) = bad_probability {
            agg.violation("probability_out_of_range", format!("{p}"));
        }
        agg.hypotheses += run_report.findings.len() as u64;
        agg.verification.plans += plans.len() as u64;
        let mut executed_fresh = 0u64;
        {
            {
                for r in &results {
                    match r.status.as_str() {
                        "executed" => {
                            agg.verification.executed += 1;
                            executed_fresh += 1;
                            if r.method == "nmap_targeted_followup" {
                                agg.verification.approval_violations += 1;
                                agg.violation(
                                    "approval_gate",
                                    format!("{} vykonano bez schvaleni", r.method),
                                );
                            }
                            if !scope.contains(&r.asset) {
                                agg.verification.scope_violations += 1;
                                agg.violation(
                                    "verification_scope",
                                    format!("{} mimo scope", r.asset),
                                );
                            }
                        }
                        "reused" => agg.verification.reused += 1,
                        "needs_approval" => agg.verification.needs_approval += 1,
                        "skipped_budget" => agg.verification.skipped_budget += 1,
                        "skipped_out_of_scope" => agg.verification.skipped_scope += 1,
                        _ => agg.verification.failed += 1,
                    }
                }
                if executed_fresh as usize > budget.max_checks_per_run {
                    agg.verification.budget_violations += 1;
                    agg.violation(
                        "verification_budget",
                        format!("{executed_fresh} > {}", budget.max_checks_per_run),
                    );
                }
            }
        }
        run_report.verification_plans = plans;

        // --- 5. skorovani proti ground truth ---
        let behavioral: Vec<&Finding> = run_report
            .findings
            .iter()
            .filter(|f| !is_static_exposure(&f.finding_type))
            .collect();
        let truth_keys: Vec<Vec<String>> =
            truths.iter().map(|t| key_ips(t, &ips, &rogue)).collect();
        let mut labels: HashMap<String, bool> = HashMap::new();
        let mut attributed_to_attack = 0usize;
        let mut attributed_to_lookalike: BTreeMap<usize, usize> = BTreeMap::new();
        let ranks_prod = rank_sources(&in_scope_obs);
        let ranks_egress = rank_sources(&output.observations);
        for finding in &behavioral {
            let mut attributed = false;
            let mut attacked = false;
            for (index, truth) in truths.iter().enumerate() {
                let window_ok = cycle + ATTRIBUTION_LATENCY >= truth.start_cycle
                    && cycle <= truth.end_cycle + ATTRIBUTION_LATENCY;
                if !window_ok || !finding_mentions(finding, &truth_keys[index]) {
                    continue;
                }
                attributed = true;
                match truth.kind {
                    Kind::Attack(family) => {
                        attributed_to_attack += 1;
                        attacked = true;
                        let ledger = &mut ledgers[index];
                        if ledger.first_detect.is_none() {
                            ledger.first_detect = Some(cycle);
                        }
                        if family
                            .expected_types()
                            .contains(&finding.finding_type.as_str())
                        {
                            ledger.typed = true;
                        }
                    }
                    Kind::Benign(_) => *attributed_to_lookalike.entry(index).or_default() += 1,
                }
            }
            if !attributed {
                // udalosti bez klicovych IP (vypadek senzoru, poskozene logy, replay)
                for (index, truth) in truths.iter().enumerate() {
                    if let Kind::Benign(look) = truth.kind {
                        if look.window_scoped()
                            && cycle >= truth.start_cycle
                            && cycle <= truth.end_cycle
                        {
                            attributed = true;
                            *attributed_to_lookalike.entry(index).or_default() += 1;
                            break;
                        }
                    }
                }
            }
            labels.insert(finding.finding_id.clone(), attacked);
            if !attributed {
                agg.fp_noise += 1;
                *agg.fp_noise_by_type
                    .entry(finding.finding_type.clone())
                    .or_default() += 1;
            }
        }
        agg.behavioral_tp += attributed_to_attack as u64;
        for (index, count) in &attributed_to_lookalike {
            lookalike_with_fp.insert(*index);
            if let Kind::Benign(look) = truths[*index].kind {
                agg.lookalikes
                    .entry(look.label().to_string())
                    .or_default()
                    .fp_findings += *count as u64;
            }
        }
        // poradi zdroju (source-centric): je utocnik v top-k?
        for (index, truth) in truths.iter().enumerate() {
            if let Kind::Attack(_) = truth.kind {
                if cycle >= truth.start_cycle && cycle <= truth.end_cycle {
                    if let Some(device) = truth.attacker_device {
                        let attacker = &ips[device as usize];
                        if ranks_prod.iter().take(RANK_TOP_K).any(|r| r == attacker) {
                            ledgers[index].ranked_prod = true;
                        }
                        if ranks_egress.iter().take(RANK_TOP_K).any(|r| r == attacker) {
                            ledgers[index].ranked_egress = true;
                        }
                    }
                }
            }
        }
        if !active_attack_cycles.contains(&cycle) {
            attributed_noise_cycles += 1;
        }

        // --- 5b. uceni: predikce vs ground truth, zpetna vazba, otravovani pameti ---
        {
            let now = ts(t0 + CYCLE_SECS);
            let label_of = |finding: &Finding| -> Option<bool> {
                if is_static_exposure(&finding.finding_type) {
                    matches!(
                        finding.finding_type.as_str(),
                        "plaintext_management_protocol"
                            | "high_risk_cve_exposure"
                            | "known_exploited_vulnerability"
                    )
                    .then_some(true)
                } else {
                    labels.get(&finding.finding_id).copied()
                }
            };
            for (finding, hypothesis) in run_report.findings.iter().zip(hypotheses.iter()) {
                if let (Some(p), Some(label)) = (hypothesis.probability, label_of(finding)) {
                    let effective = memory
                        .estimate(&finding.finding_type)
                        .map(|e| e.effective_cases)
                        .unwrap_or(0.0);
                    agg.learning.record_prediction(p, label, effective);
                }
            }
            for result in &results {
                if let Some(case) = case_from_verification_result(result, now) {
                    match memory.record(case) {
                        RecordOutcome::Accepted => agg.learning.cases_accepted += 1,
                        RecordOutcome::Quarantined(_) => agg.learning.cases_quarantined += 1,
                    }
                }
            }
            let mut sampled = 0;
            for finding in &run_report.findings {
                if sampled >= 5 {
                    break;
                }
                let Some(label) = label_of(finding) else {
                    continue;
                };
                if !rng.chance(0.10) {
                    continue;
                }
                sampled += 1;
                let verdict = if rng.chance(0.05) { !label } else { label };
                let case = CaseRecord::new(
                    &finding.finding_type,
                    finding.host_key.as_deref(),
                    if verdict {
                        Outcome::Confirmed
                    } else {
                        Outcome::Refuted
                    },
                    CaseSource::Operator {
                        actor: "op-sim".to_string(),
                    },
                    1.0,
                    now,
                );
                agg.learning.verdicts_recorded += 1;
                match memory.record(case) {
                    RecordOutcome::Accepted => agg.learning.cases_accepted += 1,
                    RecordOutcome::Quarantined(_) => agg.learning.cases_quarantined += 1,
                }
            }
            if poisoned && cycle >= 10 {
                let labelled: Vec<(&Finding, bool)> = run_report
                    .findings
                    .iter()
                    .filter_map(|f| label_of(f).map(|l| (f, l)))
                    .collect();
                if !labelled.is_empty() {
                    for _ in 0..20 {
                        let (finding, label) =
                            labelled[rng.range(0, labelled.len() as u64 - 1) as usize];
                        let case = CaseRecord::new(
                            &finding.finding_type,
                            finding.host_key.as_deref(),
                            if label {
                                Outcome::Refuted
                            } else {
                                Outcome::Confirmed
                            },
                            CaseSource::Operator {
                                actor: "mallory".to_string(),
                            },
                            1.0,
                            now,
                        );
                        agg.learning.poison_submitted += 1;
                        if let RecordOutcome::Quarantined(_) = memory.record(case) {
                            agg.learning.poison_quarantined += 1;
                        }
                    }
                }
            }
        }

        // expozice z inventare (kazdy 4. cyklus)
        if cycle % 4 == 0 {
            let found_keys: HashSet<(&str, &str)> = run_report
                .findings
                .iter()
                .filter_map(|f| {
                    f.service_key
                        .as_deref()
                        .map(|key| (f.finding_type.as_str(), key))
                })
                .collect();
            for finding in &run_report.findings {
                if !matches!(
                    finding.finding_type.as_str(),
                    "high_risk_cve_exposure" | "known_exploited_vulnerability"
                ) {
                    continue;
                }
                let Some(key) = finding.service_key.as_deref() else {
                    continue;
                };
                let mut parts = key.split('/');
                let (Some(ip), Some(proto), Some(port)) =
                    (parts.next(), parts.next(), parts.next())
                else {
                    continue;
                };
                let Some(device) = model.device_by_ip(ip) else {
                    continue;
                };
                if !patched_ids.contains(&device) {
                    continue;
                }
                agg.ops.exposure_checks_after_patch += 1;
                let still_vulnerable = model.devices[device as usize].services.iter().any(|s| {
                    s.proto == proto
                        && s.port.to_string() == port
                        && s.cves.iter().any(|c| c.1 >= 7.0)
                });
                if !still_vulnerable {
                    agg.ops.stale_exposure_findings += 1;
                }
            }
            for device in model.devices.iter().filter(|d| d.up) {
                let ip = &ips[device.id as usize];
                for svc in &device.services {
                    let mut expected: Vec<&str> = Vec::new();
                    if svc.plaintext && matches!(svc.name, "telnet" | "ftp") {
                        expected.push("plaintext_management_protocol");
                    }
                    if svc.cves.iter().any(|c| c.1 >= 7.0) {
                        expected.push("high_risk_cve_exposure");
                    }
                    for want in expected {
                        agg.exposure.expected += 1;
                        let key = format!("{ip}/{}/{}", svc.proto, svc.port);
                        if found_keys.contains(&(want, key.as_str())) {
                            agg.exposure.found += 1;
                        }
                    }
                }
            }
        }

        // --- 6. zasahy ---
        let enforcement_started = Instant::now();
        (|| -> Result<()> {
            // 6a. rozhodnuti operatora o navrzich z drivejsich cyklu
            let mut still_pending = Vec::new();
            for (id, proposed_cycle) in pending.drain(..) {
                if proposed_cycle >= cycle {
                    still_pending.push((id, proposed_cycle));
                    continue;
                }
                if rng.chance(0.85) {
                    ops.decide(id, true, "operator-bot")?;
                    agg.enforcement.approved += 1;
                    ops.apply_approved(
                        id,
                        EnforcementMode::Enforce,
                        &protected,
                        kernel.as_ref(),
                        "operator-bot",
                    )?;
                } else {
                    ops.decide(id, false, "operator-bot")?;
                    agg.enforcement.rejected_operator += 1;
                }
            }
            pending = still_pending;

            // 6b. responder: externi zdroje s dominantnim podilem toku na hostu s nalezem
            let mut proposed_now = 0;
            let flagged: BTreeSet<&str> = behavioral
                .iter()
                .filter_map(|f| f.host_key.as_deref())
                .collect();
            for victim in flagged {
                if proposed_now >= 3 {
                    break;
                }
                let mut per_source: HashMap<&str, u64> = HashMap::new();
                let mut total = 0u64;
                for o in &in_scope_obs {
                    if o.dst_ip == victim {
                        total += 1;
                        if let Some(src) = o.src_ip.as_deref() {
                            if !scope.contains(src) {
                                *per_source.entry(src).or_default() += 1;
                            }
                        }
                    }
                }
                let mut ranked: Vec<(&str, u64)> = per_source.into_iter().collect();
                ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
                for (src, count) in ranked.into_iter().take(2) {
                    if count < 25 || (count as f64) < 0.4 * total as f64 {
                        continue;
                    }
                    let request = BlockIpRequest {
                        ip: src.to_string(),
                        ttl_seconds: 7200,
                        reason: format!(
                            "auto: dominantni zdroj ({count}/{total} toku) na {victim}"
                        ),
                        finding_id: None,
                    };
                    match ops.propose(&request, &protected, "responder")? {
                        Ok(action) => {
                            agg.enforcement.proposed += 1;
                            pending.push((action.id, cycle));
                            proposed_now += 1;
                        }
                        Err(ProposeError::Rejected(_)) => agg.enforcement.rejected_guard += 1,
                        Err(ProposeError::AlreadyActive) => agg.enforcement.duplicates += 1,
                    }
                }
            }

            // 6c. chyba operatora: navrh zablokovat nahodnou VNITRNI adresu
            if rng.chance(0.004) {
                agg.enforcement.operator_error_attempts += 1;
                let victim = ips[rng.range(0, ips.len() as u64 - 1) as usize].clone();
                let request = BlockIpRequest {
                    ip: victim.clone(),
                    ttl_seconds: 3600,
                    reason: "operator-error".to_string(),
                    finding_id: None,
                };
                match ops.propose(&request, &protected, "operator-bot")? {
                    Ok(action) => {
                        agg.enforcement.proposed += 1;
                        ops.decide(action.id, true, "operator-bot")?;
                        agg.enforcement.approved += 1;
                        ops.apply_approved(
                            action.id,
                            EnforcementMode::Enforce,
                            &protected,
                            kernel.as_ref(),
                            "operator-bot",
                        )?;
                    }
                    Err(ProposeError::Rejected(_)) => {
                        agg.enforcement.rejected_guard += 1;
                        agg.enforcement.operator_error_blocked_by_guard += 1;
                    }
                    Err(ProposeError::AlreadyActive) => agg.enforcement.duplicates += 1,
                }
            }

            // 6d. nezavisly sweep
            let sweep = ops.sweep(
                EnforcementMode::Enforce,
                kernel.as_ref(),
                ts(t0 + CYCLE_SECS),
            )?;
            agg.enforcement.expired += sweep.expired as u64;
            agg.enforcement.drift_removed += sweep.drift_removed.len() as u64;
            agg.enforcement.drift_missing += sweep.drift_missing.len() as u64;
            agg.enforcement.sweep_failed += sweep.failed.len() as u64;

            // invariant: chraneny rozsah nikdy v kernelu
            for ip in kernel.blocked_now() {
                if ip
                    .parse::<std::net::IpAddr>()
                    .map(|a| protected_ranges.iter().any(|n| n.contains(&a)))
                    .unwrap_or(false)
                {
                    agg.enforcement.protected_in_kernel_violations += 1;
                    agg.violation("protected_in_kernel", ip);
                }
            }
            Ok(())
        })()?;
        agg.perf_record("enforcement", enforcement_started.elapsed().as_secs_f64());

        digest.feed(output.observations.len() as u64);
        digest.feed(events.len() as u64);
        digest.feed(run_report.findings.len() as u64);
        for finding in &run_report.findings {
            digest.feed(crate::soak::rng::mix(
                finding
                    .finding_id
                    .bytes()
                    .fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(b as u64)),
            ));
        }
        agg.perf_record("cycle_total", cycle_started.elapsed().as_secs_f64());
    }

    // --- uzaverecne skorovani epizody ---
    for (index, truth) in truths.iter().enumerate() {
        let ledger = &ledgers[index];
        match truth.kind {
            Kind::Attack(family) => {
                if truth.flows_emitted == 0 {
                    continue; // nikdy nebylo co pozorovat (vypadek/ztrata telemetrie/blok)
                }
                let stats = agg.family(family.label());
                stats.truth += 1;
                stats.flows_emitted += truth.flows_emitted;
                stats.flows_blocked += truth.flows_blocked;
                if truth.ids_visible {
                    stats.ids_visible += 1;
                }
                if let (Some(detected), Some(first)) = (ledger.first_detect, truth.first_emit_cycle)
                {
                    stats.detected_any += 1;
                    stats.record_ttd(detected.saturating_sub(first));
                    if truth.ids_visible {
                        stats.ids_visible_detected += 1;
                    }
                }
                if ledger.typed {
                    stats.detected_typed += 1;
                }
                if let (Some(blocked), Some(first)) =
                    (truth.blocked_at_cycle, truth.first_emit_cycle)
                {
                    stats.contained += 1;
                    stats.record_ttc(blocked.saturating_sub(first));
                }
                let size = model.size_class();
                let arch = format!("{:?}", model.archetype);
                let detected = ledger.first_detect.is_some() && truth.first_emit_cycle.is_some();
                for key in [
                    format!("size|{size}"),
                    format!("arch|{arch}"),
                    format!("cell|{}|{size}", family.label()),
                    format!("dur|{hours}h"),
                ] {
                    let seg = agg.segment(&key);
                    seg.attacks += 1;
                    seg.detected_any += detected as u64;
                    seg.detected_typed += ledger.typed as u64;
                }
                let (rp, re) = (ledger.ranked_prod, ledger.ranked_egress);
                if truth.attacker_device.is_some() {
                    let key = format!("{}__ranked", family.label());
                    let ranked = agg.family(&key);
                    ranked.truth += 1;
                    ranked.detected_any += rp as u64;
                    ranked.detected_typed += re as u64; // typed = "s egress tokem"
                }
            }
            Kind::Benign(look) => {
                let has_fp = lookalike_with_fp.contains(&index);
                let entry = agg.lookalikes.entry(look.label().to_string()).or_default();
                entry.occurrences += 1;
                entry.occurrences_with_fp += has_fp as u64;
                let size = model.size_class();
                let arch = format!("{:?}", model.archetype);
                for key in [
                    format!("size|{size}"),
                    format!("arch|{arch}"),
                    format!("dur|{hours}h"),
                ] {
                    let seg = agg.segment(&key);
                    seg.benign_events += 1;
                    seg.benign_with_fp += has_fp as u64;
                }
            }
        }
    }
    // occurrences_with_fp: lookalike s alespon jednim pripsanym FP nalezem
    // (prepocet z fp_findings by byl nepresny; zde pocitame per-udalost v ledgeru nize)
    let _ = attributed_noise_cycles;
    agg.quiet_network_days += (cycles as f64 / 48.0)
        * if truths.iter().any(|t| matches!(t.kind, Kind::Attack(_))) {
            0.0
        } else {
            1.0
        };

    // pokryti po rezech: velikost site, archetyp, delka behu
    {
        let (devices, subnets) = (model.devices.len() as u64, model.prefixes.len() as u64);
        let days = cycles as f64 / 48.0;
        let (obs, findings, fp) = (agg.observations, agg.findings, agg.fp_noise);
        for key in [
            format!("size|{}", model.size_class()),
            format!("arch|{:?}", model.archetype),
            format!("dur|{hours}h"),
        ] {
            let seg = agg.segment(&key);
            seg.networks += 1;
            seg.devices += devices;
            seg.subnets += subnets;
            seg.virtual_days += days;
            seg.cycles += cycles as u64;
            seg.observations += obs;
            seg.findings += findings;
            seg.fp_noise += fp;
        }
    }

    // pamet pripadu: kolik zdroju guard oznacil a kolik poctivych zaznamu zadrzel
    agg.learning.flagged_sources += memory.flagged_sources().len() as u64;
    agg.learning.honest_quarantined += memory
        .quarantine_list()
        .iter()
        .filter(|q| q.record.source.key() != "operator:mallory")
        .count() as u64;

    // identita
    agg.identity.devices += mac_assets.len() as u64;
    agg.identity.devices_false_split += mac_assets
        .values()
        .filter(|assets| assets.len() > 1)
        .count() as u64;
    agg.identity.asset_ids += asset_macs.len() as u64;
    agg.identity.asset_ids_false_merge +=
        asset_macs.values().filter(|macs| macs.len() > 1).count() as u64;

    // zasahy: finalni stavy + invarianty
    if !ops.verify_audit_chain()? {
        agg.violation("audit_chain", format!("sit {}", cfg.network_id));
    }
    for action in ops.list_actions()? {
        if action.applied_at.is_some() {
            agg.enforcement.applied += 1;
        }
        if action.status == "failed" {
            agg.enforcement.failed += 1;
        }
        if action.status == "applied" || action.applied_at.is_some() {
            if let Ok(addr) = action.ip.parse::<std::net::IpAddr>() {
                if protected_ranges.iter().any(|n| n.contains(&addr)) {
                    agg.violation("protected_applied", action.ip.clone());
                }
            }
        }
    }
    let kernel_stats = kernel.stats();
    agg.enforcement.kernel_cmd_failed += kernel_stats.commands_failed;
    drop(ops);
    Ok(())
}

/// Poradi zdroju podle `score_source_hosts` (sestupne, deterministicky pri shode).
fn rank_sources(observations: &[ConnectionObservation]) -> Vec<String> {
    let mut scored: Vec<(String, f64)> = score_source_hosts(observations).into_iter().collect();
    scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    scored.into_iter().map(|(ip, _)| ip).collect()
}

pub fn family_stats_for<'a>(agg: &'a Aggregate, label: &str) -> Option<&'a FamilyStats> {
    agg.families.get(label)
}

#[allow(dead_code)]
fn _assert_executor(_: &dyn NftExecutor) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(id: u64) -> EpisodeConfig {
        EpisodeConfig {
            run_seed: 20260131,
            network_id: id,
            hours: 24,
            scratch: std::env::temp_dir()
                .join("bakula-soak-test")
                .join(format!("n{id}")),
        }
    }

    #[test]
    fn episode_runs_end_to_end_without_invariant_violations() {
        let result = run_episode(&cfg(1));
        assert_eq!(result.agg.cycles, 48);
        assert!(result.agg.observations > 0);
        assert!(
            result.agg.findings > 0,
            "engine musi nad realnym provozem neco najit"
        );
        assert!(
            result.agg.invariant_violations.is_empty(),
            "{:?}",
            result.agg.violation_samples
        );
    }

    /// Rucni profil: `cargo test --release --lib profile_big -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn profile_big_networks_per_stage() {
        for want in [
            Archetype::Enterprise,
            Archetype::Metro,
            Archetype::Hospital,
            Archetype::Cloud,
        ] {
            let id = (0..4000)
                .find(|id| NetworkModel::generate(20260131, *id).archetype == want)
                .unwrap();
            let model = NetworkModel::generate(20260131, id);
            let started = Instant::now();
            let result = run_episode(&EpisodeConfig {
                hours: 24,
                ..cfg(id)
            });
            let secs = started.elapsed().as_secs_f64();
            println!(
                "{:?} id={id} devices={} subnets={} 24h/48 cykl: {:.1} s ({:.0} ms/cyklus)",
                want,
                model.devices.len(),
                model.prefixes.len(),
                secs,
                secs * 1000.0 / 48.0
            );
            for (stage, hist) in &result.agg.perf {
                println!(
                    "    {stage:<22} prumer {:.1} ms  p95 {:.1} ms",
                    hist.mean() * 1000.0,
                    hist.percentile(0.95) * 1000.0
                );
            }
        }
    }

    /// Regrese: site, ktere ve v2 spadly na prazdnem seznamu obet (soak seed 20261031).
    #[test]
    #[ignore]
    fn regression_empty_victim_networks_do_not_panic() {
        for id in [114u64, 264, 486] {
            let result = std::panic::catch_unwind(|| {
                run_episode(&EpisodeConfig {
                    run_seed: 20261031,
                    network_id: id,
                    hours: 0,
                    scratch: std::env::temp_dir().join(format!("bakula-soak-regr-{id}")),
                })
            });
            assert!(result.is_ok(), "sit {id} spadla");
            assert!(result.unwrap().agg.invariant_violations.is_empty());
        }
    }

    #[test]
    fn ip_matching_is_exact_not_substring() {
        assert!(mentions_ip("host 10.0.0.1 je pomaly", "10.0.0.1"));
        assert!(mentions_ip("10.0.0.1.", "10.0.0.1"));
        assert!(mentions_ip("a=10.0.0.1/tcp/22", "10.0.0.1"));
        assert!(!mentions_ip("host 10.0.0.15", "10.0.0.1"));
        assert!(!mentions_ip("host 110.0.0.1", "10.0.0.1"));
        assert!(!mentions_ip("1.10.0.0.1", "10.0.0.1"));
        assert!(!mentions_ip("10.0.0.1.5", "10.0.0.1"));
        assert!(mentions_ip("10.0.0.15 a pak 10.0.0.1", "10.0.0.1"));
    }

    #[test]
    fn same_episode_replays_bit_for_bit() {
        let a = run_episode(&cfg(7));
        let b = run_episode(&cfg(7));
        assert_eq!(a.digest, b.digest);
        assert_eq!(a.agg.findings, b.agg.findings);
        let other = run_episode(&cfg(8));
        assert_ne!(a.digest, other.digest);
    }

    #[test]
    fn many_networks_produce_attacks_and_no_violations() {
        let mut total = Aggregate::default();
        for id in 100..130 {
            let result = run_episode(&cfg(id));
            total.merge(&result.agg);
        }
        assert!(
            total.invariant_violations.is_empty(),
            "{:?}",
            total.violation_samples
        );
        assert!(total.families.values().map(|f| f.truth).sum::<u64>() > 0);
        assert_eq!(total.networks, 30);
    }
}
