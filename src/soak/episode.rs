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
    context_gate::{ContextKind, GateInput},
    correlation, decision,
    enforcement::{BlockIpRequest, ProtectedRanges},
    engine::{EngineConfig, EngineMode},
    error::{BakulaError, Result},
    finding_memory::{
        Disposition, Escalation, FindingKey, FindingState, Observation, key_for_finding,
        split_service_key,
    },
    findings, fusion,
    identity::{IdentityMatch, IdentityResolver},
    model::{Finding, HostReport, NormalizedEvent, PassiveWindow, RunReport, SourceMetadata},
    ops::{EnforcementMode, NftExecutor, OpsStore, ProposeError},
    passive::{
        ConnectionDetector, ConnectionObservation, LegacyAnomalyDetector, parse_suricata_str,
        parse_suricata_str_mode, score_source_hosts,
    },
    report,
    scope_policy::ScopePolicy,
    soak::{
        kernel::SimKernel,
        ladder_env::{
            ReputationCoverage, SimReputation, SoakEvidence, group_index, is_suspicious_type,
        },
        netmodel::{Archetype, NetworkModel},
        rng::{Rng, derive, mix},
        scoring::{InventoryView, Seen, StateTracker, placebo_window, unexpected_cause},
        stats::{Aggregate, FamilyStats, NetworkSummary},
        traffic::{
            CYCLE_SECS, CycleContext, Kind, Lookalike, Telemetry, Truth, generate_cycle,
            plan_episode, random_telemetry, seed_for_cycle, ts,
        },
        v3::{ContextCoverage, SimContext, V3Runtime, phantom_windows},
    },
    verification_exec::{self, CheckRunner, ExecutionBudget, LocalRunner},
    verification_planner,
};

/// Po kolika cyklech po konci utoku jeste povazujeme nalez za prislusny utoku.
const ATTRIBUTION_LATENCY: u32 = 2;
const RANK_TOP_K: usize = 3;

/// finding_id behavioralniho nalezu -> (sila signalu, protistrany, cile toku).
type BehaviorSignal = HashMap<String, (u32, Vec<String>, Vec<(String, u16)>)>;

#[derive(Debug, Clone)]
pub struct EpisodeConfig {
    pub run_seed: u64,
    pub network_id: u64,
    /// 0 = delka podle seedu (24/48/72/96 virtualnich hodin).
    pub hours: u32,
    pub scratch: PathBuf,
    /// Rezim jadra (legacy | v3 s volbami); vychozi legacy.
    pub engine: EngineConfig,
    /// Zasahy (blokace) zpetne ovlivnuji generator provozu. Pro parove A/B se vypina
    /// (`--no-feedback`), jinak ramena dostanou jiny provoz (K20).
    pub feedback: bool,
    /// Ktere utoky se v tomto svete neemituji (kontrafaktualni beh, krok 2A).
    pub mask: WorldMask,
    /// Kontrafaktualni svety (bez utoku) pro atribuci nalezu tohoto (faktickeho) behu.
    pub counterfactual: Option<Arc<Counterfactual>>,
    /// Kalibrace posteriory zebriku (krok 2C), fit na jinych sitich nez tato.
    pub calibration: Option<Arc<crate::calibration::IsotonicCalibrator>>,
}

/// Maska udalosti sveta. Kontrafaktual = stejny seed, stejny svet, jen bez utoku.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum WorldMask {
    #[default]
    None,
    /// Vsechny utoky (zbyde pozadi a benigni udalosti).
    AllAttacks,
    /// Jen vyjmenovane utoky (id truth), leave-one-out.
    Only(Vec<u32>),
}

/// Otisk behavioralnich nalezu jednoho sveta: cyklus -> (hash finding_id -> zobrazeno).
/// Uklada se jen to, co muze byt pripsano utoku (zminuje klicovou IP utoku v jeho okne).
#[derive(Debug, Clone, Default)]
pub struct CfWorld {
    pub cycles: HashMap<u32, HashMap<u64, bool>>,
}

impl CfWorld {
    fn displayed(&self, cycle: u32, hash: u64) -> Option<bool> {
        self.cycles.get(&cycle).and_then(|m| m.get(&hash)).copied()
    }

    /// Nalez v kontrafaktualu chybi v cyklu `cycle` (a pri `strict` i v sousednich).
    fn absent(&self, cycle: u32, hash: u64, strict: bool) -> bool {
        let range = if strict {
            cycle.saturating_sub(1)..=cycle + 1
        } else {
            cycle..=cycle
        };
        range.into_iter().all(|c| self.displayed(c, hash).is_none())
    }
}

/// Kontrafaktualy faktickeho behu: svet bez vsech utoku a volitelne leave-one-out svety.
#[derive(Debug, Clone, Default)]
pub struct Counterfactual {
    pub all: CfWorld,
    pub loo: Vec<(u32, CfWorld)>,
}

fn finding_hash(id: &str) -> u64 {
    crate::soak::rng::mix(id.bytes().fold(0xcbf2_9ce4_8422_2325u64, |a, b| {
        (a ^ b as u64).wrapping_mul(0x100_0000_01b3)
    }))
}

/// Utoky vybrane pro leave-one-out (deterministicky podle seedu site, nejvys `k`).
pub fn loo_candidates(run_seed: u64, network_id: u64, attack_ids: &[u32], k: usize) -> Vec<u32> {
    let mut ranked: Vec<(u64, u32)> = attack_ids
        .iter()
        .map(|id| (derive(mix(run_seed ^ network_id), *id as u64 ^ 0x100), *id))
        .collect();
    ranked.sort_unstable();
    ranked.into_iter().take(k).map(|(_, id)| id).collect()
}

use crate::finding_kinds::is_static_exposure;

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
    /// Detekce jen ze zobrazenych polozek (co uvidi clovek).
    displayed_detect: Option<u32>,
    typed_displayed: bool,
    placebo: Option<(u32, u32)>,
    placebo_captured: bool,
    placebo_displayed: bool,
    /// Kontrafaktualni atribuce (krok 2A): nalez chybi ve svete bez utoku.
    cf_detect: bool,
    cf_detect_strict: bool,
    cf_displayed: bool,
    cf_displayed_strict: bool,
    cf_typed: bool,
    cf_typed_displayed: bool,
    /// Typy nalezu, ktere utoku kontrafaktualne pripadly (zobrazene).
    cf_types: BTreeSet<String>,
    /// Leave-one-out (jen vybrane utoky): zobrazena detekce proti svetu bez TOHOTO utoku.
    loo_displayed: Option<bool>,
}

/// Zobrazeni nalezu v cyklu (legacy: vse, v3: podle pameti a kontextu).
struct Shown {
    displayed: bool,
    reason: &'static str,
    auto: Option<ContextKind>,
    /// Cile (ip, port) a dominantni zdroje nalezu (jen u automaticky zavrenych, mereni).
    targets: Vec<(String, u16)>,
    sources: Vec<String>,
    /// Stav nalezu vyvratil zebrik overovani (automaticky vyreseno, krok 2B).
    ladder_refuted: bool,
}

/// Vystup zebriku v cyklu (krok 2B): klice nalezu, otevrene pripady, rozhodnuti.
#[derive(Default)]
struct LadderCycle {
    keys: Vec<Option<FindingKey>>,
    sources: Vec<Vec<String>>,
    opened: HashSet<usize>,
    decisions: Vec<crate::verify_ladder::Decision>,
    late: Vec<(Finding, Shown)>,
}

/// Pravda o pripadu zebriku zjistena pri otevreni (jen mereni).
#[derive(Debug, Clone, Copy)]
struct CaseTruth {
    /// Nalez kontrafaktualne zpusobil utok (chybi ve svete bez utoku).
    cf: bool,
    /// Utok v cyklu otevreni posilal toky na cil nalezu nebo z jeho zdroje.
    causal: bool,
    family: Option<&'static str>,
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
    /// Souhrn site pro parove A/B (networks.jsonl).
    pub summary: NetworkSummary,
    /// Otisk nalezu sveta (vyplni se jen u maskovaneho, kontrafaktualniho behu).
    pub world: CfWorld,
    /// Id utoku v planu epizody (pro vyber leave-one-out).
    pub attack_ids: Vec<u32>,
}

/// Fakticky beh site s kontrafaktualem: nejdriv svet bez vsech utoku (a `loo`
/// leave-one-out svetu), pak fakticky svet, jehoz nalezy se pripisou utoku jen tehdy,
/// kdyz v kontrafaktualu chybi (krok 2A, nahrada okna a placebo oken).
pub fn run_with_counterfactual(cfg: &EpisodeConfig, loo: usize) -> EpisodeResult {
    let background = run_episode(&EpisodeConfig {
        mask: WorldMask::AllAttacks,
        counterfactual: None,
        calibration: None,
        ..cfg.clone()
    });
    let mut cf = Counterfactual {
        all: background.world,
        loo: Vec::new(),
    };
    for id in loo_candidates(cfg.run_seed, cfg.network_id, &background.attack_ids, loo) {
        let world = run_episode(&EpisodeConfig {
            mask: WorldMask::Only(vec![id]),
            counterfactual: None,
            calibration: None,
            ..cfg.clone()
        })
        .world;
        cf.loo.push((id, world));
    }
    let mut result = run_episode(&EpisodeConfig {
        mask: WorldMask::None,
        counterfactual: Some(Arc::new(cf)),
        ..cfg.clone()
    });
    result.summary.wall_s += background.summary.wall_s;
    result
}

pub fn run_episode(cfg: &EpisodeConfig) -> EpisodeResult {
    let started = Instant::now();
    let mut agg = Aggregate {
        engine: cfg.engine.label(),
        ..Aggregate::default()
    };
    let mut digest = EpisodeDigest(0x5EED);
    let mut world = CfWorld::default();
    let mut attack_ids = Vec::new();
    if let Err(error) = run_episode_inner(cfg, &mut agg, &mut digest, &mut world, &mut attack_ids) {
        agg.violation("episode_error", format!("sit {}: {error}", cfg.network_id));
    }
    agg.networks += 1;
    agg.episodes += 1;
    let mut summary = NetworkSummary::from_aggregate(&agg, cfg.run_seed, cfg.network_id);
    summary.wall_s = started.elapsed().as_secs_f64();
    EpisodeResult {
        digest: digest.0 ^ agg.deterministic_digest(),
        agg,
        summary,
        world,
        attack_ids,
    }
}

#[allow(clippy::too_many_lines)]
fn run_episode_inner(
    cfg: &EpisodeConfig,
    agg: &mut Aggregate,
    digest: &mut EpisodeDigest,
    world: &mut CfWorld,
    attack_ids: &mut Vec<u32>,
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
    *attack_ids = truths
        .iter()
        .filter(|t| matches!(t.kind, Kind::Attack(_)))
        .map(|t| t.id)
        .collect();
    let masked: HashSet<u32> = match &cfg.mask {
        WorldMask::None => HashSet::new(),
        WorldMask::AllAttacks => attack_ids.iter().copied().collect(),
        WorldMask::Only(ids) => ids.iter().copied().collect(),
    };
    let collect_world = cfg.mask != WorldMask::None;
    let cf = cfg.counterfactual.clone();
    let loo_of: HashMap<u32, usize> = cf
        .as_ref()
        .map(|c| {
            c.loo
                .iter()
                .enumerate()
                .map(|(i, (id, _))| (*id, i))
                .collect()
        })
        .unwrap_or_default();
    let restart_cycles: HashSet<u32> = (0..rng.poisson(hours as f64 / 24.0 * 0.25))
        .map(|_| rng.range(1, cycles.saturating_sub(1).max(1) as u64) as u32)
        .collect();
    let mut patched_ids: HashSet<u32> = HashSet::new();
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
    let mut v3 = match cfg.engine.mode {
        EngineMode::V3 => Some(V3Runtime::new(cfg.engine, derive(model.seed, 0x001A_DDE7))?),
        EngineMode::Legacy => None,
    };
    let coverage = ContextCoverage::default();
    let reputation = SimReputation::new(&model, &truths, ReputationCoverage::default());
    let ladder_on = cfg.engine.ladder();
    let severe_types = crate::context_gate::GatePolicy::default().most_severe;
    let mut case_truth: HashMap<FindingKey, CaseTruth> = HashMap::new();
    let mut plan_queue = verification_exec::PlanQueue::default();
    let learning_on = ladder_on && cfg.engine.learning();
    if let Some(runtime) = v3.as_mut() {
        if learning_on {
            runtime.ladder.learner = Some(Default::default());
        }
        runtime.ladder.calibrator = cfg.calibration.as_deref().cloned();
    }
    let phantoms = if cfg.engine.context_gate() {
        phantom_windows(&model, cycles, &coverage)
    } else {
        Vec::new()
    };
    let mut tracker = StateTracker::default();
    let mut scan_device_of_ip: HashMap<String, u32> = HashMap::new();
    let mut scan_devices: HashSet<u32> = HashSet::new();
    let mut restart_cold = false;
    let mut memory = CaseMemory::in_memory();
    let poisoned = rng.chance(0.03);
    // Oddeleny nahodny proud pro vyhodnoceni (verdikty operatora, otrava, chyby
    // operatora): jeho spotreba zavisi na nalezech enginu, takze nesmi posouvat
    // proud sveta (churn, pady), jinak by ramena A/B dostala jiny provoz (krok 1A).
    let mut eval_rng = Rng::new(derive(model.seed, 0xE7A1_5EED));
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
            displayed_detect: None,
            typed_displayed: false,
            placebo: None,
            placebo_captured: false,
            placebo_displayed: false,
            cf_detect: false,
            cf_detect_strict: false,
            cf_displayed: false,
            cf_displayed_strict: false,
            cf_typed: false,
            cf_typed_displayed: false,
            cf_types: BTreeSet::new(),
            loo_displayed: None,
        })
        .collect();
    for (ledger, truth) in ledgers.iter_mut().zip(&truths) {
        if loo_of.contains_key(&truth.id) {
            ledger.loo_displayed = Some(false);
        }
    }
    // placebo okna: posunuty cas, stejna klicova zarizeni, bez jineho utoku na ne
    {
        let devices_of = |t: &Truth| -> BTreeSet<u32> {
            t.victim_devices
                .iter()
                .copied()
                .chain(t.attacker_device)
                .collect()
        };
        for (index, truth) in truths.iter().enumerate() {
            if !matches!(truth.kind, Kind::Attack(_)) {
                continue;
            }
            let Some((ps, pe)) = placebo_window(truth.start_cycle, truth.end_cycle, cycles) else {
                continue;
            };
            let mine = devices_of(truth);
            let clash = truths.iter().any(|other| {
                matches!(other.kind, Kind::Attack(_))
                    && other.id != truth.id
                    && other.start_cycle <= pe + 2 * ATTRIBUTION_LATENCY
                    && other.end_cycle + 2 * ATTRIBUTION_LATENCY >= ps
                    && (!devices_of(other).is_disjoint(&mine)
                        || (other.attacker_external.is_some()
                            && other.attacker_external == truth.attacker_external))
            });
            if !clash {
                ledgers[index].placebo = Some((ps, pe));
            }
        }
    }
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
            if let Some(runtime) = v3.as_mut() {
                runtime.restart()?;
            }
            // fronta planu je v pameti procesu: pri restartu se ztrati (mimo rozpocet)
            agg.verification.skipped_budget += plan_queue.len() as u64;
            plan_queue = verification_exec::PlanQueue::default();
            // legacy: inventar zil jen v pameti procesu (A09); v3 ho ma perzistentni
            if !cfg.engine.unexpected_v3() {
                hosts_cache.clear();
            }
            restart_cold = true;
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
        let rogue_scheduled = rogue_info.iter().any(|(index, _)| {
            cycle >= truths[*index].start_cycle && cycle <= truths[*index].end_cycle
        });
        let rogue = rogue_info
            .iter()
            .find(|(index, _)| {
                cycle >= truths[*index].start_cycle
                    && cycle <= truths[*index].end_cycle
                    && !masked.contains(&truths[*index].id)
            })
            .map(|(_, info)| info.clone());
        if kernel.inject_faults(&mut eval_rng).is_some() {
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
                oracle: if cfg.feedback {
                    kernel.as_ref()
                } else {
                    &crate::soak::traffic::NoBlocks
                },
                rogue: rogue.clone(),
                scan_now: cycle % 4 == 0 || rogue_scheduled,
                masked: &masked,
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
            scan_devices = output.inventory_devices.iter().copied().collect();
            for (host, device) in hosts.iter().zip(&output.inventory_devices) {
                scan_device_of_ip.insert(host.ip.clone(), *device);
            }
            if let Some(runtime) = v3.as_mut()
                && cfg.engine.unexpected_v3()
            {
                runtime.inventory.merge_scan(&hosts);
            }
            if let Some(runtime) = v3.as_mut()
                && cfg.engine.devices()
            {
                // peer skupiny podle typu zarizeni a podsite (krok 2D)
                let tables = crate::device_class::ClassifierTables::default();
                runtime.device_classes = hosts
                    .iter()
                    .map(|host| {
                        (
                            host.ip.clone(),
                            crate::device_class::classify(host, None, &tables),
                        )
                    })
                    .collect();
                runtime.peer_groups = runtime
                    .device_classes
                    .iter()
                    .filter_map(|(ip, class)| {
                        crate::device_class::peer_group_key(ip, class).map(|g| (ip.clone(), g))
                    })
                    .collect();
                // presnost klasifikace proti roli v modelu (jen mereni)
                for host in &hosts {
                    let Some(device) = model.device_by_ip(&host.ip) else {
                        continue;
                    };
                    let role = model.devices[device as usize].role;
                    let class = &runtime.device_classes[&host.ip];
                    agg.output.device_classified += 1;
                    agg.output.device_class_correct +=
                        crate::soak::ladder_env::role_matches(role, class.kind) as u64;
                    agg.output.device_class_confident +=
                        (class.confidence >= crate::device_class::ClassConfidence::Medium) as u64;
                }
            }
            restart_cold = false;
            hosts_cache = hosts;
        }
        let mut hosts = match v3.as_ref() {
            Some(runtime) if cfg.engine.unexpected_v3() => runtime.inventory.hosts(),
            _ => hosts_cache.clone(),
        };

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
        let known_hosts: HashSet<String> = hosts.iter().map(|h| h.ip.clone()).collect();
        let mut events: Vec<NormalizedEvent> = match v3.as_mut() {
            Some(runtime) if cfg.engine.v3_detector() => {
                let started = Instant::now();
                let events = runtime.detect(&in_scope_obs, &known, &known_hosts, ts(t0));
                agg.perf_record("detect", started.elapsed().as_secs_f64());
                events
            }
            _ => stage(agg, "detect", || {
                LegacyAnomalyDetector.detect(in_scope_obs.clone(), &known)
            }),
        };
        let window_start = ts(t0 - 3600);
        let window_end = ts(t0 + CYCLE_SECS + 3600);
        // krok 3A: s viditelnosti ven parser drzi i alerty se zdrojem uvnitr a cilem venku;
        // alerty s cilem v rozsahu jdou dal beze zmeny, odchozi do behavioralni vrstvy
        let behavior_on = v3.is_some() && cfg.engine.behavior();
        let mut outbound_alerts: Vec<NormalizedEvent> = Vec::new();
        if !output.alerts.is_empty() {
            let joined = output.alerts.join("\n");
            if behavior_on && cfg.engine.egress() {
                use crate::passive::egress::{FlowDirection, ScopeMode, direction};
                for event in parse_suricata_str_mode(
                    &joined,
                    "soak",
                    &scope_nets,
                    window_start,
                    window_end,
                    ScopeMode::SrcOrDst,
                )? {
                    match direction(&scope_nets, event.src_ip.as_deref(), &event.dst_ip) {
                        FlowDirection::Outbound => outbound_alerts.push(event),
                        FlowDirection::External => {}
                        _ => events.push(event),
                    }
                }
            } else {
                events.extend(parse_suricata_str(
                    &joined,
                    "soak",
                    &scope_nets,
                    window_start,
                    window_end,
                )?);
            }
        }
        // krok 3: behavioralni vrstva nad odchozimi a vnitrnimi toky okna
        let mut behavior_signal: BehaviorSignal = HashMap::new();
        let mut behavior_findings: Vec<Finding> = Vec::new();
        let mut behavior_split: Option<crate::passive::egress::SplitFlows> = None;
        if let Some(runtime) = v3.as_mut().filter(|_| behavior_on) {
            let started = Instant::now();
            let split = crate::passive::egress::split_flows(
                output.observations.iter().cloned(),
                &scope_nets,
                &runtime.egress_policy,
            );
            agg.output.egress_seen += split.outbound_seen;
            agg.output.egress_dropped += split.outbound_dropped;
            agg.output.egress_sample_level_max = agg
                .output
                .egress_sample_level_max
                .max(split.sample_level as u64);
            let input = crate::behavior::BehaviorInput {
                outbound: &split.outbound,
                internal: &split.internal,
                outbound_alerts: &outbound_alerts,
                now: ts(t0),
            };
            let out = crate::behavior::run_window(
                &mut runtime.behavior,
                crate::behavior::BehaviorSwitches::from_engine(&cfg.engine),
                &runtime.behavior_thresholds,
                &input,
            );
            agg.output.behavior_chains += out.chains.len() as u64;
            for item in out.findings {
                *agg.output
                    .behavior_findings_by_type
                    .entry(item.finding.finding_type.clone())
                    .or_default() += 1;
                behavior_signal.insert(
                    item.finding.finding_id.clone(),
                    (item.count, item.sources, item.targets),
                );
                behavior_findings.push(item.finding);
            }
            behavior_split = Some(split);
            agg.perf_record("behavior", started.elapsed().as_secs_f64());
        }
        let events = fusion::fuse_same_flow_events(events);
        agg.events += events.len() as u64;

        // --- 3. korelace, report, nalezy ---
        let (mut run_report, identity_map) = stage(agg, "report", || {
            let correlated = correlation::correlate_events(&hosts, events.clone(), 3600);
            let unmapped = report::attach_events(&mut hosts, correlated);
            report::score_services(&mut hosts);
            let matches: Vec<IdentityMatch> = match v3.as_mut() {
                Some(runtime) if cfg.engine.identity_v3() => {
                    let inventory = &runtime.inventory;
                    runtime
                        .identity
                        .resolve_snapshot_with(&hosts, |ip| inventory.is_stale(ip))
                }
                _ => hosts.iter().map(|h| resolver.resolve(h)).collect(),
            };
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
            if cfg.engine.unexpected_v3() {
                let mut list = std::mem::take(&mut run_report.findings);
                list.extend(findings::v3_extra_findings(
                    &run_report,
                    cfg.engine.recall(),
                ));
                findings::aggregate_unmapped_findings(&mut list, &run_report);
                list.sort_by(|l, r| l.finding_id.cmp(&r.finding_id));
                list.dedup_by(|l, r| l.finding_id == r.finding_id);
                run_report.findings = list;
            }
            if !behavior_findings.is_empty() {
                run_report.findings.append(&mut behavior_findings);
                run_report
                    .findings
                    .sort_by(|l, r| l.finding_id.cmp(&r.finding_id));
                run_report
                    .findings
                    .dedup_by(|l, r| l.finding_id == r.finding_id);
            }
            (run_report, identity_map)
        });
        agg.findings += run_report.findings.len() as u64;
        let _ = stage(agg, "decision", || {
            decision::build_decision_bundle(&run_report).actions.len()
        });

        // identita proti ground truth
        // `hosts` ma poradi inventare (= poradi zarizeni v modelu), proto index = zarizeni;
        // `run_report.hosts` je serazene podle IP, ne podle zarizeni.
        for host in hosts.iter() {
            let Some(device) = scan_device_of_ip
                .get(&host.ip)
                .and_then(|id| model.devices.get(*id as usize))
            else {
                continue; // rogue host (neni v modelu)
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

        // --- 3b. pamet nalezu a kontextove vylouceni (v3) ---
        let report_services: HashMap<&str, &crate::model::ServiceReport> = run_report
            .hosts
            .iter()
            .flat_map(|h| h.services.iter())
            .map(|s| (s.service_key.as_str(), s))
            .collect();
        let memory_started = Instant::now();
        let mut lc = LadderCycle::default();
        // odhady prioru z Case Memory jednou za cyklus (odhad prochazi vsechny zaznamy)
        let mut prior_cache: HashMap<String, f64> = HashMap::new();
        let mut shown: Vec<Shown> = match v3.as_mut() {
            None => run_report
                .findings
                .iter()
                .map(|_| Shown {
                    displayed: true,
                    reason: "legacy",
                    auto: None,
                    targets: Vec::new(),
                    sources: Vec::new(),
                    ladder_refuted: false,
                })
                .collect(),
            Some(runtime) => {
                runtime.gate.begin_cycle();
                let context = cfg.engine.context_gate().then(|| {
                    SimContext::for_cycle(
                        &truths,
                        &model,
                        &ips,
                        start_offset_s,
                        cycles,
                        &coverage,
                        &phantoms,
                        cycle,
                    )
                });
                let at = ts(t0);
                let memory_on = runtime.memory.is_some();
                let mut out = Vec::with_capacity(run_report.findings.len());
                for (finding_index, finding) in run_report.findings.iter().enumerate() {
                    let service_key = finding.service_key.as_deref().unwrap_or("-");
                    let (_, key_ip) = split_service_key(service_key);
                    let host_ip = finding
                        .host_key
                        .clone()
                        .unwrap_or_else(|| key_ip.to_string());
                    let entity_host = finding
                        .host_key
                        .as_ref()
                        .and_then(|k| identity_map.get(k))
                        .map(|m| m.asset_id().to_string())
                        .unwrap_or_else(|| host_ip.clone());
                    let behavior_item = behavior_signal.get(&finding.finding_id);
                    let (count, sources) = match behavior_item {
                        // behavioralni nalez: signal a protistrana z vrstvy (krok 3)
                        Some((count, sources, _)) => (*count, sources.clone()),
                        None => findings::finding_signal(
                            finding,
                            report_services.get(service_key).copied(),
                            |dst, proto, port, kind| runtime.sources_of(dst, proto, port, kind),
                        ),
                    };
                    // pokusy (sken) jsou stav ZDROJE: jeden stav na skener, ne na kazdy cil
                    let key = key_for_finding(finding, &entity_host, &sources);
                    let key_copy = key.clone();
                    let explanation = context.as_ref().and_then(|ctx| {
                        let ids = [host_ip.clone(), entity_host.clone()];
                        runtime.gate.explain(
                            ctx,
                            &GateInput {
                                finding_type: &finding.finding_type,
                                host_ids: &ids,
                                sources: &sources,
                                severity: finding.severity,
                                at,
                            },
                        )
                    });
                    let disposition = match runtime.memory.as_mut() {
                        Some(memory) => memory.observe(
                            &Observation {
                                key,
                                severity: finding.severity,
                                count,
                                sources: &sources,
                                at,
                                volume_explained: explanation
                                    .as_ref()
                                    .is_some_and(|e| e.kind.explains_volume()),
                            },
                            explanation.as_ref().map(|e| e.reason.as_str()),
                        ),
                        None => match &explanation {
                            Some(e) => Disposition::AutoResolved(e.reason.clone()),
                            None => Disposition::First,
                        },
                    };
                    let auto_closed = matches!(disposition, Disposition::AutoResolved(_));
                    let new_state = disposition.displayed();
                    let mut shown_item = match disposition {
                        Disposition::First => Shown {
                            displayed: true,
                            reason: if memory_on { "first" } else { "no_memory" },
                            auto: None,
                            targets: Vec::new(),
                            sources: Vec::new(),
                            ladder_refuted: false,
                        },
                        Disposition::Reopened => Shown {
                            displayed: true,
                            reason: "reopened",
                            auto: None,
                            targets: Vec::new(),
                            sources: Vec::new(),
                            ladder_refuted: false,
                        },
                        Disposition::Escalated(cause) => Shown {
                            displayed: true,
                            reason: match cause {
                                Escalation::Severity => "escalated_severity",
                                Escalation::NewSource => "escalated_source",
                                Escalation::Volume => "escalated_volume",
                            },
                            auto: None,
                            targets: Vec::new(),
                            sources: Vec::new(),
                            ladder_refuted: false,
                        },
                        Disposition::Suppressed => Shown {
                            displayed: false,
                            reason: "suppressed",
                            auto: None,
                            targets: Vec::new(),
                            sources: Vec::new(),
                            ladder_refuted: false,
                        },
                        Disposition::AutoResolved(_) => Shown {
                            displayed: false,
                            reason: "auto_resolved",
                            auto: explanation.as_ref().map(|e| e.kind),
                            targets: Vec::new(),
                            sources: Vec::new(),
                            ladder_refuted: false,
                        },
                    };
                    if auto_closed && let Some((_, _, targets)) = behavior_item {
                        shown_item.targets = targets.clone();
                        shown_item.sources = sources.clone();
                    } else if auto_closed {
                        shown_item.targets = report_services
                            .get(service_key)
                            .map(|svc| {
                                svc.events
                                    .iter()
                                    .filter(|e| e.event.event_type == finding.finding_type)
                                    .filter_map(|e| {
                                        e.event.dst_port.map(|p| (e.event.dst_ip.clone(), p))
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        shown_item.sources = sources.clone();
                    }
                    // krok 2B: novy stav behavioralniho nalezu jde do zebriku; zobrazi se
                    // az po overeni (vysoky dopad hned), vyvraceny se nezobrazi
                    if ladder_on && !is_static_exposure(&finding.finding_type) && !auto_closed {
                        if new_state {
                            let high = finding.severity == crate::model::Severity::High
                                || severe_types.contains(&finding.finding_type);
                            let (service, _) = split_service_key(service_key);
                            let port = service.rsplit('/').next().and_then(|p| p.parse().ok());
                            let target = service_key.contains('/').then_some(service_key);
                            let input = crate::verify_ladder::CaseInput {
                                key: key_copy.clone(),
                                finding_id: finding.finding_id.clone(),
                                finding_type: finding.finding_type.clone(),
                                host_ip: host_ip.clone(),
                                port,
                                sources: sources.clone(),
                                volume: count as f64,
                                history_key: crate::verify_ladder::history_key_for(
                                    &finding.finding_type,
                                    target,
                                    &host_ip,
                                    &sources,
                                ),
                                high_impact: high,
                                prior: if learning_on {
                                    learned_prior(
                                        &memory,
                                        &mut prior_cache,
                                        &finding.finding_type,
                                        runtime.device_classes.get(&host_ip),
                                    )
                                } else {
                                    crate::verify_ladder::DEFAULT_PRIOR
                                },
                            };
                            if runtime.ladder.open(input, cycle as u64) {
                                lc.opened.insert(finding_index);
                                runtime
                                    .case_findings
                                    .insert(key_copy.clone(), finding.clone());
                            }
                            if !high {
                                shown_item.displayed = false;
                                shown_item.reason = "verifying";
                            }
                        } else {
                            runtime.ladder.observe(&key_copy, &sources, cycle as u64);
                            shown_item.ladder_refuted = runtime
                                .memory
                                .as_ref()
                                .and_then(|m| m.get(&key_copy))
                                .is_some_and(|e| e.state == FindingState::Refuted);
                        }
                    }
                    lc.keys.push(Some(key_copy));
                    lc.sources.push(sources.clone());
                    out.push(shown_item);
                }
                if ladder_on {
                    // index cyklu pro L2 peer srovnani a L4 pivot
                    let mut typed_hosts: HashSet<(String, String)> = HashSet::new();
                    let mut suspicious: HashMap<String, usize> = HashMap::new();
                    for (index, finding) in run_report.findings.iter().enumerate() {
                        if is_static_exposure(&finding.finding_type) {
                            continue;
                        }
                        if let Some(host) = &finding.host_key {
                            typed_hosts.insert((finding.finding_type.clone(), host.clone()));
                            if is_suspicious_type(&finding.finding_type) {
                                *suspicious.entry(host.clone()).or_default() += 1;
                            }
                        }
                        if is_suspicious_type(&finding.finding_type) {
                            for source in &lc.sources[index] {
                                *suspicious.entry(source.clone()).or_default() += 1;
                            }
                        }
                    }
                    let (group_sizes, group_hits) = group_index(&runtime.peer_groups, &typed_hosts);
                    let mut env = SoakEvidence {
                        history: &runtime.history,
                        at,
                        gate: &runtime.gate,
                        context: context.as_ref(),
                        reputation: &reputation,
                        services: &report_services,
                        devices: &runtime.device_classes,
                        groups: &runtime.peer_groups,
                        group_sizes: &group_sizes,
                        group_hits: &group_hits,
                        suspicious: &suspicious,
                        scope: &scope,
                        model: &model,
                        cycle,
                        liveness_runs: 0,
                        liveness_failures: 0,
                        profile: cfg
                            .engine
                            .profile()
                            .then_some((&runtime.behavior.profile, &runtime.profile_policy)),
                    };
                    let decisions = runtime.ladder.step(cycle as u64, &mut env);
                    agg.output.ladder_liveness_runs += env.liveness_runs;
                    agg.output.ladder_liveness_failures += env.liveness_failures;
                    for decision in &decisions {
                        use crate::verify_ladder::Status;
                        let index = lc
                            .keys
                            .iter()
                            .position(|k| k.as_ref() == Some(&decision.key));
                        if let Some(memory) = runtime.memory.as_mut() {
                            match decision.status {
                                Status::Refuted => {
                                    memory.refute(&decision.key, &decision.reason, at);
                                }
                                Status::Confirmed => {
                                    memory.confirm(&decision.key, "verify_ladder", at);
                                    memory.note(
                                        &decision.key,
                                        "verify_confirm",
                                        &decision.reason,
                                        at,
                                    );
                                }
                                Status::Escalated | Status::Open => {
                                    memory.note(
                                        &decision.key,
                                        "verify_escalate",
                                        &decision.reason,
                                        at,
                                    );
                                }
                            }
                        }
                        let finding = runtime.case_findings.remove(&decision.key);
                        let reason = match decision.status {
                            Status::Refuted => None,
                            Status::Confirmed => Some("ladder_confirmed"),
                            _ => Some("ladder_escalated"),
                        };
                        match (index, reason) {
                            (Some(i), None) => out[i].ladder_refuted = true,
                            (Some(i), Some(reason)) if !out[i].displayed => {
                                out[i].displayed = true;
                                out[i].reason = reason;
                            }
                            (None, Some(reason)) if !decision.high_impact => {
                                if let Some(finding) = finding {
                                    lc.late.push((
                                        finding,
                                        Shown {
                                            displayed: true,
                                            reason,
                                            auto: None,
                                            targets: Vec::new(),
                                            sources: Vec::new(),
                                            ladder_refuted: false,
                                        },
                                    ));
                                }
                            }
                            _ => {}
                        }
                    }
                    lc.decisions = decisions;
                }
                // krok 3E: profil hostu se uci az po rozhodnuti; dvojice s poplachem ne
                if cfg.engine.profile()
                    && let Some(split) = behavior_split.as_ref()
                {
                    let started = Instant::now();
                    let frozen = crate::behavior::profile::frozen_pairs(
                        run_report
                            .findings
                            .iter()
                            .zip(&lc.sources)
                            .filter(|(f, _)| !is_static_exposure(&f.finding_type))
                            .filter_map(|(f, s)| f.host_key.as_deref().map(|h| (h, s.as_slice()))),
                    );
                    crate::behavior::learn_profile(
                        &mut runtime.behavior,
                        &crate::behavior::BehaviorInput {
                            outbound: &split.outbound,
                            internal: &split.internal,
                            outbound_alerts: &[],
                            now: at,
                        },
                        &frozen,
                        &runtime.profile_policy,
                    );
                    agg.perf_record("profile_learn", started.elapsed().as_secs_f64());
                }
                out
            }
        };
        // pozdni zobrazeni (rozhodnuti zebriku o nalezu, ktery v tomto cyklu neni)
        for (finding, show) in std::mem::take(&mut lc.late) {
            lc.keys.push(None);
            lc.sources.push(Vec::new());
            run_report.findings.push(finding);
            shown.push(show);
        }
        agg.perf_record("memory_context", memory_started.elapsed().as_secs_f64());

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
                // v3: overuje se jen to, co se zobrazuje (novy/eskalovany stav), ne
                // tentyz otevreny nalez v kazdem cyklu znovu (audit A24)
                let plans: Vec<verification_planner::HypothesisVerificationPlan> = hypotheses
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| shown.get(*index).is_none_or(|s| s.displayed))
                    // krok 2B: behavioralni nalezy overuje zebrik (stavove, jen otevrene)
                    .filter(|(_, h)| !ladder_on || is_static_exposure(&h.hypothesis_type))
                    .filter_map(|(_, h)| verification_planner::plan_for_hypothesis(h, &scope))
                    .collect();
                let runner = SimRunner {
                    model: &model,
                    cycle,
                    seed: model.seed,
                };
                let results = if ladder_on {
                    // krok 2B: stavova fronta, plan bez rozpoctu ceka na dalsi cyklus
                    let mut accepted = Vec::new();
                    for plan in &plans {
                        if plan_queue.push(plan.clone()) {
                            accepted.push(plan.clone());
                        }
                    }
                    let results = plan_queue.run(&run_report.hosts, &scope, &budget, &runner);
                    return (accepted, results, bad_probability, hypotheses);
                } else {
                    verification_exec::execute_plans(
                        &plans,
                        &run_report.hosts,
                        &scope,
                        &budget,
                        &runner,
                    )
                };
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
        let inventory_ips: HashSet<&str> = hosts.iter().map(|h| h.ip.as_str()).collect();
        let unmapped_by_id: HashMap<&str, &NormalizedEvent> = run_report
            .unmapped_events
            .iter()
            .map(|e| (e.event.event_id.as_str(), &e.event))
            .collect();
        for (finding_index, finding) in run_report.findings.iter().enumerate() {
            let show = &shown[finding_index];
            let is_behavioral = !is_static_exposure(&finding.finding_type);
            let mut attributed = false;
            let mut attacked = false;
            let mut attack_family: Option<&'static str> = None;
            let fhash = finding_hash(&finding.finding_id);
            if is_behavioral && collect_world {
                // kontrafaktualni svet: zapamatovat nalezy, ktere by fakticky beh mohl
                // pripsat nekteremu utoku (stejne okno a klicove IP)
                let candidate = truths.iter().enumerate().any(|(index, truth)| {
                    matches!(truth.kind, Kind::Attack(_))
                        && cycle + ATTRIBUTION_LATENCY >= truth.start_cycle
                        && cycle <= truth.end_cycle + ATTRIBUTION_LATENCY
                        && finding_mentions(finding, &truth_keys[index])
                });
                if candidate {
                    let slot = world.cycles.entry(cycle).or_default();
                    let entry = slot.entry(fhash).or_insert(false);
                    *entry |= show.displayed;
                }
            }
            if is_behavioral {
                for (index, truth) in truths.iter().enumerate() {
                    if let Some((ps, pe)) = ledgers[index].placebo
                        && cycle + ATTRIBUTION_LATENCY >= ps
                        && cycle <= pe + ATTRIBUTION_LATENCY
                        && finding_mentions(finding, &truth_keys[index])
                    {
                        ledgers[index].placebo_captured = true;
                        ledgers[index].placebo_displayed |= show.displayed;
                    }
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
                            attack_family.get_or_insert(family.label());
                            let ledger = &mut ledgers[index];
                            if ledger.first_detect.is_none() {
                                ledger.first_detect = Some(cycle);
                            }
                            let typed = family
                                .expected_types()
                                .contains(&finding.finding_type.as_str());
                            ledger.typed |= typed;
                            if show.displayed {
                                ledger.displayed_detect.get_or_insert(cycle);
                                ledger.typed_displayed |= typed;
                            }
                            if let Some(cf) = cf.as_deref() {
                                // pripsat jen nalez, ktery ve svete bez utoku chybi;
                                // zobrazeni jen tehdy, kdyz ho kontrafaktual nezobrazil
                                let new = cf.all.absent(cycle, fhash, false);
                                let new_strict = cf.all.absent(cycle, fhash, true);
                                let shown_cf = cf.all.displayed(cycle, fhash).unwrap_or(false);
                                ledger.cf_detect |= new;
                                ledger.cf_detect_strict |= new_strict;
                                ledger.cf_typed |= new && typed;
                                if show.displayed && !shown_cf {
                                    ledger.cf_displayed = true;
                                    ledger.cf_typed_displayed |= typed;
                                    ledger.cf_types.insert(finding.finding_type.clone());
                                }
                                if show.displayed && new_strict {
                                    ledger.cf_displayed_strict = true;
                                }
                                if let Some(&slot) = loo_of.get(&truth.id) {
                                    let loo_world = &cf.loo[slot].1;
                                    let loo_shown =
                                        loo_world.displayed(cycle, fhash).unwrap_or(false);
                                    let hit = show.displayed && !loo_shown;
                                    let entry = ledger.loo_displayed.get_or_insert(false);
                                    *entry |= hit;
                                }
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
                    if show.displayed {
                        agg.output.displayed_fp += 1;
                        *agg.displayed_fp_by_type
                            .entry(finding.finding_type.clone())
                            .or_default() += 1;
                    }
                    if matches!(
                        finding.finding_type.as_str(),
                        "unexpected_traffic" | "unmapped_passive_event" | "scan_attempts"
                    ) {
                        let target = report_services
                            .get(finding.service_key.as_deref().unwrap_or("-"))
                            .and_then(|svc| {
                                svc.events
                                    .iter()
                                    .find(|e| e.event.event_type == finding.finding_type)
                                    .map(|e| &e.event)
                            })
                            .or_else(|| {
                                finding
                                    .finding_id
                                    .strip_prefix("finding:unmapped_passive_event:-:")
                                    .and_then(|id| unmapped_by_id.get(id).copied())
                            })
                            .map(|e| {
                                format!(
                                    "{}/{}/{}",
                                    e.dst_ip,
                                    e.proto,
                                    e.dst_port.map(|p| p.to_string()).unwrap_or_default()
                                )
                            })
                            .or_else(|| finding.service_key.clone())
                            .unwrap_or_default();
                        let view = InventoryView {
                            ips: &inventory_ips,
                            services: &known,
                            devices: &scan_devices,
                        };
                        let cause = unexpected_cause(&model, &view, &target, restart_cold);
                        *agg.unexpected_causes
                            .entry(format!("{}|{cause}", finding.finding_type))
                            .or_default() += 1;
                    }
                }
            }
            if lc.opened.contains(&finding_index)
                && let Some(Some(key)) = lc.keys.get(finding_index)
            {
                let targets: Vec<(String, u16)> = report_services
                    .get(finding.service_key.as_deref().unwrap_or("-"))
                    .map(|svc| {
                        svc.events
                            .iter()
                            .filter_map(|e| e.event.dst_port.map(|p| (e.event.dst_ip.clone(), p)))
                            .collect()
                    })
                    .unwrap_or_default();
                let sources = &lc.sources[finding_index];
                let causal = truths.iter().any(|truth| {
                    matches!(truth.kind, Kind::Attack(_))
                        && cycle + ATTRIBUTION_LATENCY >= truth.start_cycle
                        && cycle <= truth.end_cycle + ATTRIBUTION_LATENCY
                        && (targets.iter().any(|t| truth.cycle_targets.contains(t))
                            || sources.iter().any(|s| truth.cycle_sources.contains(s)))
                });
                let cf_caused = attacked
                    && cf
                        .as_deref()
                        .is_none_or(|c| c.all.absent(cycle, fhash, false));
                case_truth.insert(
                    key.clone(),
                    CaseTruth {
                        cf: cf_caused,
                        causal,
                        family: attack_family,
                    },
                );
            }
            if show.displayed {
                agg.output.displayed += 1;
                agg.output.displayed_behavioral += is_behavioral as u64;
                *agg.output
                    .displayed_by_reason
                    .entry(show.reason.to_string())
                    .or_default() += 1;
            }
            if let Some(kind) = show.auto {
                let causal = truths.iter().any(|truth| {
                    matches!(truth.kind, Kind::Attack(_))
                        && cycle + ATTRIBUTION_LATENCY >= truth.start_cycle
                        && cycle <= truth.end_cycle + ATTRIBUTION_LATENCY
                        && (show.targets.iter().any(|t| truth.cycle_targets.contains(t))
                            || show.sources.iter().any(|s| truth.cycle_sources.contains(s)))
                });
                agg.output.auto_closures_wrong_causal += causal as u64;
                let reason = kind.label().to_string();
                agg.output.auto_closures += 1;
                *agg.output
                    .auto_closures_by_reason
                    .entry(reason.clone())
                    .or_default() += 1;
                if attacked {
                    agg.output.auto_closures_wrong += 1;
                    *agg.output
                        .auto_closures_wrong_detail
                        .entry(format!(
                            "{reason}|{}|{}",
                            finding.finding_type,
                            attack_family.unwrap_or("-")
                        ))
                        .or_default() += 1;
                    *agg.output
                        .auto_closures_wrong_by_reason
                        .entry(reason)
                        .or_default() += 1;
                }
                // nahodny audit vzorku zavrenych (simulovany clovek, 10 %), H-A3
                let roll = mix(finding
                    .finding_id
                    .bytes()
                    .fold(model.seed ^ cycle as u64, |a, b| {
                        a.wrapping_mul(131).wrapping_add(b as u64)
                    }))
                    % 10;
                if roll == 0 {
                    // clovek u vzorku posoudi, zda zavreni skrylo utok (pricinne)
                    agg.output.audit_sampled += 1;
                    agg.output.audit_wrong += attacked as u64;
                    agg.output.audit_wrong_causal += causal as u64;
                    if let Some(runtime) = v3.as_mut() {
                        runtime.gate.record_audit(kind, causal);
                    }
                }
            }
            tracker.observe(
                &finding.finding_id,
                cycle,
                Seen {
                    behavioral: is_behavioral,
                    attributed,
                    displayed: show.displayed,
                    auto_resolved: show.auto.is_some() || show.ladder_refuted,
                },
                &mut agg.output,
            );
        }
        agg.behavioral_tp += attributed_to_attack as u64;
        for decision in &lc.decisions {
            use crate::verify_ladder::Status;
            let truth = case_truth.remove(&decision.key);
            let caused = truth.is_some_and(|t| t.cf);
            let out = &mut agg.output;
            out.ladder_latency_sum += decision.decided - decision.opened;
            out.ladder_latency_max = out
                .ladder_latency_max
                .max(decision.decided - decision.opened);
            out.ladder_decided_attack += caused as u64;
            for (check, tag) in &decision.steps {
                *out.ladder_outcome_truth
                    .entry(format!(
                        "{}:{tag}|{}",
                        check.label(),
                        if caused { "attack" } else { "benign" }
                    ))
                    .or_default() += 1;
            }
            *out.ladder_outcome_truth
                .entry(format!(
                    "_cases|{}",
                    if caused { "attack" } else { "benign" }
                ))
                .or_default() += 1;
            match decision.status {
                Status::Refuted => {
                    out.ladder_refuted += 1;
                    *out.ladder_refuted_by_type
                        .entry(decision.finding_type.clone())
                        .or_default() += 1;
                    out.ladder_refuted_wrong_cf += caused as u64;
                    out.ladder_refuted_wrong_causal += truth.is_some_and(|t| t.causal) as u64;
                    if caused {
                        *out.ladder_refuted_wrong_detail
                            .entry(format!(
                                "{}|{}",
                                decision.finding_type,
                                truth.and_then(|t| t.family).unwrap_or("-")
                            ))
                            .or_default() += 1;
                    }
                    // nahodny audit 10 % vyvracenych (simulovany clovek, H-A3)
                    let roll =
                        mix(finding_hash(&decision.finding_id) ^ model.seed ^ cycle as u64) % 10;
                    if roll == 0 {
                        out.ladder_audit_sampled += 1;
                        out.ladder_audit_wrong += caused as u64;
                    }
                }
                Status::Confirmed => {
                    out.ladder_confirmed += 1;
                    out.ladder_confirmed_attack += caused as u64;
                }
                Status::Escalated | Status::Open => {
                    out.ladder_escalated += 1;
                    out.ladder_escalated_attack += caused as u64;
                    out.ladder_escalated_budget += decision.budget_escalation as u64;
                }
            }
            // kalibracni kose: surova a pouzita posteriora proti pravde (kontrafaktual)
            out.record_calibration(decision.raw_posterior, decision.posterior, caused);
            // krok 2C: verdikt cloveka (eskalovano/potvrzeno: posoudi s p = 0,5;
            // vyvraceno: audit 10 %) jde pres Case Memory (ochrana proti otraveni)
            if learning_on && let Some(runtime) = v3.as_mut() {
                let audited = matches!(decision.status, Status::Refuted)
                    && mix(finding_hash(&decision.finding_id) ^ model.seed ^ cycle as u64)
                        .is_multiple_of(10);
                let reviewed = match decision.status {
                    Status::Refuted => audited,
                    _ => eval_rng.chance(0.5),
                };
                let kind = runtime
                    .device_classes
                    .get(&decision.host_ip)
                    .map(|c| c.kind.label())
                    .unwrap_or("unknown");
                let now = ts(t0 + CYCLE_SECS);
                let mut submit = |actor: &str, verdict: bool, memory: &mut CaseMemory| {
                    let outcome = if verdict {
                        Outcome::Confirmed
                    } else {
                        Outcome::Refuted
                    };
                    let source = CaseSource::Operator {
                        actor: actor.to_string(),
                    };
                    let source_key = source.key();
                    let typed = CaseRecord::new(
                        &format!("ladder:{}", decision.finding_type),
                        Some(&decision.host_ip),
                        outcome,
                        source.clone(),
                        1.0,
                        now,
                    );
                    let accepted = matches!(memory.record(typed), RecordOutcome::Accepted);
                    let context = CaseRecord::new(
                        &format!("ladder:{}@{kind}", decision.finding_type),
                        Some(&decision.host_ip),
                        outcome,
                        source,
                        1.0,
                        now,
                    );
                    let _ = memory.record(context);
                    if accepted && let Some(learner) = runtime.ladder.learner.as_mut() {
                        learner.record(&source_key, &decision.steps, verdict, 1.0);
                    }
                    accepted
                };
                if reviewed {
                    let verdict = if eval_rng.chance(0.05) {
                        !caused
                    } else {
                        caused
                    };
                    agg.learning.ladder_verdicts += 1;
                    if submit("op-sim", verdict, &mut memory) {
                        agg.learning.ladder_verdicts_accepted += 1;
                    }
                }
                if poisoned && cycle >= 10 {
                    agg.learning.poison_submitted += 1;
                    if !submit("mallory", !caused, &mut memory) {
                        agg.learning.poison_quarantined += 1;
                    }
                }
                if let Some(learner) = runtime.ladder.learner.as_mut() {
                    for source in memory.flagged_sources() {
                        learner.exclude(source);
                    }
                }
            }
        }
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
                if !eval_rng.chance(0.10) {
                    continue;
                }
                sampled += 1;
                let verdict = if eval_rng.chance(0.05) { !label } else { label };
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
                            labelled[eval_rng.range(0, labelled.len() as u64 - 1) as usize];
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
                if eval_rng.chance(0.85) {
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
            if eval_rng.chance(0.004) {
                agg.enforcement.operator_error_attempts += 1;
                let victim = ips[eval_rng.range(0, ips.len() as u64 - 1) as usize].clone();
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

        if let Some(runtime) = v3.as_mut() {
            if ladder_on {
                // L0: zapsat okno do historie; klice s alarmem v tomto cyklu se neuci
                let mut frozen: HashSet<String> = HashSet::new();
                for (index, finding) in run_report.findings.iter().enumerate() {
                    if is_static_exposure(&finding.finding_type) {
                        continue;
                    }
                    if let Some(service) = finding.service_key.as_deref() {
                        frozen.insert(service.to_string());
                    }
                    if let Some(host) = &finding.host_key {
                        frozen.insert(host.clone());
                    }
                    for source in lc.sources.get(index).into_iter().flatten() {
                        frozen.insert(source.clone());
                    }
                }
                let summary = crate::flow_history::summarize(&in_scope_obs, &known_hosts);
                runtime.history.ingest(&summary, &frozen, ts(t0));
            }
            runtime.end_cycle(ts(t0 + CYCLE_SECS))?;
        }
        if cycle % 48 == 47 {
            tracker.sweep(cycle, &mut agg.output);
        }
        digest.feed(output.observations.len() as u64);
        digest.feed(events.len() as u64);
        digest.feed(shown.iter().filter(|s| s.displayed).count() as u64);
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
                if ledger.displayed_detect.is_some() && truth.first_emit_cycle.is_some() {
                    stats.detected_displayed += 1;
                }
                if ledger.typed_displayed {
                    stats.typed_displayed += 1;
                }
                if cf.is_some() && truth.first_emit_cycle.is_some() {
                    stats.cf_attacks += 1;
                    stats.cf_detected += ledger.cf_detect as u64;
                    stats.cf_detected_strict += ledger.cf_detect_strict as u64;
                    stats.cf_detected_displayed += ledger.cf_displayed as u64;
                    stats.cf_detected_displayed_strict += ledger.cf_displayed_strict as u64;
                    stats.cf_typed += ledger.cf_typed as u64;
                    stats.cf_typed_displayed += ledger.cf_typed_displayed as u64;
                    if let Some(loo) = ledger.loo_displayed {
                        stats.loo_n += 1;
                        stats.loo_detected_displayed += loo as u64;
                        stats.loo_all_detected_displayed += ledger.cf_displayed as u64;
                        stats.loo_agree += (loo == ledger.cf_displayed) as u64;
                    }
                }
                if ledger.placebo.is_some() {
                    stats.placebo_windows += 1;
                    stats.placebo_hits_captured += ledger.placebo_captured as u64;
                    stats.placebo_hits_displayed += ledger.placebo_displayed as u64;
                    let emitted = truth.first_emit_cycle.is_some();
                    stats.placebo_detected_displayed +=
                        (emitted && ledger.displayed_detect.is_some()) as u64;
                    stats.placebo_detected_captured +=
                        (emitted && ledger.first_detect.is_some()) as u64;
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
                for kind in &ledger.cf_types {
                    *agg.cf_type_hits
                        .entry(format!("{}|{kind}", family.label()))
                        .or_default() += 1;
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
    tracker.finish(&mut agg.output);
    if let Some(memory) = v3.as_ref().and_then(|runtime| runtime.memory.as_ref()) {
        agg.output.memory_peak_entries = memory.stats.peak_entries;
        agg.output.memory_evicted = memory.stats.evicted;
    }
    agg.verification.skipped_budget += plan_queue.dropped;
    agg.verification.deferred += plan_queue.deferred;
    if let Some(runtime) = v3.as_ref().filter(|_| ladder_on) {
        let st = &runtime.ladder.stats;
        let out = &mut agg.output;
        out.ladder_cases += st.cases_opened;
        out.ladder_merged += st.cases_merged;
        out.ladder_checks += st.checks_by_level.values().sum::<u64>();
        out.ladder_checks_deferred += st.checks_deferred;
        out.ladder_cases_deferred += st.cases_deferred;
        out.ladder_needs_approval += st.needs_approval;
        out.ladder_open_at_end += runtime.ladder.open_cases() as u64;
        for (level, n) in &st.checks_by_level {
            *out.ladder_checks_by_level.entry(level.clone()).or_default() += n;
        }
        for (outcome, n) in &st.outcomes {
            *out.ladder_outcomes.entry(outcome.clone()).or_default() += n;
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

/// Apriorní pravděpodobnost případu z Case Memory (krok 2C): kontext (typ nálezu a
/// typ zařízení), jinak typ, jinak výchozí. Hierarchický ústup (R12b, A21).
fn learned_prior(
    memory: &CaseMemory,
    cache: &mut HashMap<String, f64>,
    finding_type: &str,
    class: Option<&crate::device_class::DeviceClass>,
) -> f64 {
    let kind = class.map(|c| c.kind.label()).unwrap_or("unknown");
    let key = format!("{finding_type}@{kind}");
    *cache.entry(key).or_insert_with(|| {
        memory
            .estimate(&format!("ladder:{finding_type}@{kind}"))
            .or_else(|| memory.estimate(&format!("ladder:{finding_type}")))
            .map(|e| e.probability.clamp(0.01, 0.99))
            .unwrap_or(crate::verify_ladder::DEFAULT_PRIOR)
    })
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
            engine: EngineConfig::legacy(),
            feedback: true,
            mask: WorldMask::None,
            counterfactual: None,
            calibration: None,
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
                    engine: EngineConfig::legacy(),
                    feedback: true,
                    mask: WorldMask::None,
                    counterfactual: None,
                    calibration: None,
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

#[cfg(test)]
mod engine_v3_tests {
    use super::*;

    fn run(id: u64, hours: u32, engine: EngineConfig) -> EpisodeResult {
        run_episode(&EpisodeConfig {
            run_seed: 20261102,
            network_id: id,
            hours,
            scratch: std::env::temp_dir().join("bakula-soak-v3-test"),
            engine,
            feedback: false,
            mask: WorldMask::None,
            counterfactual: None,
            calibration: None,
        })
    }

    /// Parove A/B (krok 1A): bez zpetne vazby a s oddelenym proudem vyhodnoceni
    /// dostanou obe ramena IDENTICKY svet (provoz, utoky, churn), at engine dela cokoli.
    #[test]
    fn paired_arms_see_identical_world() {
        let legacy = run(9, 48, EngineConfig::legacy());
        let v3 = run(9, 48, EngineConfig::v3());
        assert_eq!(legacy.agg.observations, v3.agg.observations);
        assert_eq!(
            legacy.agg.identity.churn_events,
            v3.agg.identity.churn_events
        );
        let truths = |r: &EpisodeResult| -> Vec<(String, u64)> {
            r.agg
                .families
                .iter()
                .map(|(k, f)| (k.clone(), f.truth))
                .collect()
        };
        assert_eq!(truths(&legacy), truths(&v3));
        assert!(
            v3.agg.invariant_violations.is_empty(),
            "{:?}",
            v3.agg.violation_samples
        );
        assert!(
            v3.agg.output.displayed < legacy.agg.output.displayed,
            "v3 zobrazuje {} vs legacy {}",
            v3.agg.output.displayed,
            legacy.agg.output.displayed
        );
        assert_eq!(
            legacy.agg.output.displayed, legacy.agg.findings,
            "legacy zobrazi vse"
        );
        assert!(v3.agg.output.memory_peak_entries > 0);
        assert_eq!(v3.summary.engine, v3.agg.engine);
    }

    /// Krok 2A: kontrafaktualni detekce je podmnozina detekce oknem (pripisuje se jen
    /// nalez, ktery ve svete bez utoku chybi), svet bez utoku nema zadny utok a
    /// leave-one-out se vyhodnoti na vybranych utocich.
    #[test]
    fn counterfactual_credit_is_subset_of_window_credit() {
        let mut attacks = 0;
        for network_id in 3..30 {
            let cfg = EpisodeConfig {
                run_seed: 20261102,
                network_id,
                hours: 48,
                scratch: std::env::temp_dir().join("bakula-soak-cf-test"),
                engine: EngineConfig::legacy(),
                feedback: false,
                mask: WorldMask::None,
                counterfactual: None,
                calibration: None,
            };
            let background = run_episode(&EpisodeConfig {
                mask: WorldMask::AllAttacks,
                ..cfg.clone()
            });
            assert!(background.agg.families.values().all(|f| f.truth == 0));
            if background.attack_ids.is_empty() {
                continue;
            }
            let result = run_with_counterfactual(&cfg, 2);
            let plain = run_episode(&cfg);
            assert_eq!(
                result.agg.findings, plain.agg.findings,
                "kontrafaktual nemeni fakticky beh"
            );
            for f in result.agg.families.values() {
                attacks += f.cf_attacks;
                assert!(f.cf_detected_displayed <= f.detected_displayed, "{f:?}");
                assert!(f.cf_detected_strict <= f.cf_detected, "{f:?}");
                assert!(f.cf_typed_displayed <= f.cf_detected_displayed);
                assert!(f.loo_agree <= f.loo_n);
            }
            assert!(result.agg.families.values().map(|f| f.loo_n).sum::<u64>() <= 2);
            if attacks > 0 {
                return;
            }
        }
        panic!("zadna sit s utokem");
    }

    /// Regrese v2b (35 % falesne rozdeleno): v3 identita (jmeno hostu, drzene hosty
    /// inventare) snizi falesne rozdeleni na velke siti s podsitemi mimo L2 dosah.
    #[test]
    #[ignore]
    fn v3_identity_reduces_false_split_on_large_network() {
        let legacy = run(5, 96, EngineConfig::legacy());
        let v3 = run(5, 96, EngineConfig::v3());
        let (l, n) = (&legacy.agg.identity, &v3.agg.identity);
        assert_eq!(l.devices, n.devices);
        assert!(
            n.devices_false_split * 3 < l.devices_false_split * 2,
            "{l:?} vs {n:?}"
        );
        assert!(
            n.asset_ids_false_merge < l.asset_ids_false_merge,
            "{l:?} vs {n:?}"
        );
    }

    /// Krok 2B: žebřík otevírá případy jen pro nové stavy, rozhoduje s auditem a nic
    /// neporuší; bez žebříku (krok 1) se nic z toho neděje.
    #[test]
    fn ladder_opens_stateful_cases_and_decides_without_violations() {
        let step1 = EngineConfig {
            mode: EngineMode::V3,
            v3: crate::engine::V3Features::step1(),
        };
        let off = run(9, 48, step1);
        let on = run(9, 48, EngineConfig::v3());
        assert_eq!(off.agg.output.ladder_cases, 0);
        let o = &on.agg.output;
        assert!(o.ladder_cases > 0, "{o:?}");
        assert!(o.ladder_confirmed + o.ladder_refuted + o.ladder_escalated <= o.ladder_cases);
        assert!(o.ladder_checks > 0);
        assert!(
            on.agg.invariant_violations.is_empty(),
            "{:?}",
            on.agg.violation_samples
        );
        assert!(
            on.agg.verification.plans < off.agg.verification.plans,
            "plany jen pro staticke expozice"
        );
        assert!(o.device_classified > 0 && o.device_class_correct <= o.device_classified);
    }

    /// Krok 3: behaviorální vrstva v epizodě vidí odchozí provoz (vzorkování ho drží),
    /// vydává nálezy svých typů bez porušení invariantů a krok 2 (bez vrstvy) je
    /// nevydává; svět je v obou ramenech stejný.
    #[test]
    fn behavior_layer_runs_in_episode_and_step2_has_none() {
        let step2 = EngineConfig {
            mode: EngineMode::V3,
            v3: crate::engine::V3Features::step2(),
        };
        let mut seen = 0u64;
        let mut by_type: BTreeMap<String, u64> = BTreeMap::new();
        for id in [3u64, 9, 14] {
            let off = run(id, 96, step2);
            let on = run(id, 96, EngineConfig::v3());
            assert_eq!(off.agg.observations, on.agg.observations, "stejny svet");
            assert!(off.agg.output.behavior_findings_by_type.is_empty());
            assert_eq!(off.agg.output.egress_seen, 0);
            assert!(
                on.agg.invariant_violations.is_empty(),
                "{:?}",
                on.agg.violation_samples
            );
            seen += on.agg.output.egress_seen;
            for (kind, n) in &on.agg.output.behavior_findings_by_type {
                assert!(crate::behavior::is_behavior_type(kind), "{kind}");
                *by_type.entry(kind.clone()).or_default() += n;
            }
        }
        assert!(seen > 0, "odchozi toky musi dojit do vrstvy");
        assert!(!by_type.is_empty(), "vrstva nic nevydala: {by_type:?}");
    }

    /// Krok 2C: verdikty k rozhodnutým případům jdou přes Case Memory a plní kalibrační
    /// koše; bez učení zůstává autorský prior.
    #[test]
    fn learning_records_verdicts_through_case_memory_and_fills_calibration_bins() {
        let on = run(9, 96, EngineConfig::v3());
        assert!(on.agg.learning.ladder_verdicts > 0);
        assert!(on.agg.learning.ladder_verdicts_accepted <= on.agg.learning.ladder_verdicts);
        let n: f64 = on.agg.output.calib_raw.iter().map(|b| b[0]).sum();
        let decided = on.agg.output.ladder_confirmed
            + on.agg.output.ladder_refuted
            + on.agg.output.ladder_escalated;
        assert_eq!(n as u64, decided);
        assert!(
            on.agg.invariant_violations.is_empty(),
            "{:?}",
            on.agg.violation_samples
        );
    }

    /// Ruční profil kroku 2 (nejpomalejší síť ladicích seedů):
    /// `cargo test --release --lib profile_step2 -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn profile_step2_slowest_network() {
        let result = run_episode(&EpisodeConfig {
            run_seed: 20261104,
            network_id: 36,
            hours: 0,
            scratch: std::env::temp_dir().join("bakula-soak-profile2"),
            engine: EngineConfig::v3(),
            feedback: false,
            mask: WorldMask::None,
            counterfactual: None,
            calibration: None,
        });
        for (stage, hist) in &result.agg.perf {
            println!(
                "{stage:<22} prumer {:.1} ms  p99 {:.1} ms",
                hist.mean() * 1000.0,
                hist.percentile(0.99) * 1000.0
            );
        }
    }
}
