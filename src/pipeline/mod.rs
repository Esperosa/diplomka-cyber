//! Fáze 1 (produkční plán, framework-style wiring): `BehArgs` a `run_pipeline`
//! přesunuty z `main.rs` sem beze změny chování (ověřeno golden-snapshot
//! testem) - cíl je, aby pipeline logika žila v knihovně, volatelná i mimo
//! CLI proces (např. ze serveru přímo, ne přes manufacturing argv stringů
//! pro podproces jako dnes `server.rs::build_restart_command`).
//!
//! Vnitřní pomocné funkce (prepare_pipeline_args, apply_production_profile,
//! auto_enable_vulners/web_tools, validate_pipeline_args,
//! has_passive_telemetry, ensure_file_exists/ensure_dir_exists,
//! can_resolve_tool, odhady latency hintů, MAS plánování) zůstávají privátní
//! tomuto modulu - volané jen zevnitř `run_pipeline`. Veřejné (`pub`, ne
//! `pub(crate)` - `main.rs` je samostatný bin crate, ne stejný crate jako
//! knihovna) je jen to, co `main.rs` opravdu volá zvenčí: `BehArgs`,
//! `run_pipeline`, `promote_monitor_args`, `promote_autopilot_args`,
//! `validate_monitor_args`, `resolve_simulation_profile`.

use std::{
    env, fs,
    path::{Path, PathBuf},
    thread,
    time::Instant,
};

mod v3;

use chrono::Utc;
use clap::Args;
use ipnet::IpNet;

use crate::{
    automation, case_history, case_memory, config, context, correlation, cpe, decision, diff,
    findings, hypothesis, identity, ingest, intel, lanes,
    model::{MonitoringLane, NormalizedEvent, RunReport, Severity, TriageAction},
    nmap, passive, paths, pentest, report, scope_policy, simulation,
    storage::{RunArtifacts, Workspace},
    triage, validation, verification_exec, verification_planner, vuln, webscan,
};

/// `Default` je jen pro testy nize (`..Default::default()` konstrukce bez
/// nutnosti vypsat vsech 55 poli) - NEPOUZIVAT v produkcnim kodu. `clap`'s
/// `default_value` atributy fungujou nezavisle (jen pri `--help`/parsovani
/// CLI), takze `BehArgs::default()` dava JINE hodnoty nez skutecne CLI
/// defaulty (`ports=[]` misto `[21,22,23,80,443,8080]`, `provider=""` misto
/// `"demo"` atd.) - overeno auditem (haiku, 30.10.2026).
#[derive(Args, Debug, Clone, Default)]
pub struct BehArgs {
    #[arg(long)]
    pub workspace: PathBuf,
    #[arg(long)]
    pub nazev: String,
    #[arg(long, value_delimiter = ',')]
    pub scope: Vec<IpNet>,
    #[arg(long, value_delimiter = ',', default_value = "21,22,23,80,443,8080")]
    pub ports: Vec<u16>,
    #[arg(long, default_value = "bezny")]
    pub profile: String,
    #[arg(long, default_value = "demo")]
    pub provider: String,
    #[arg(long, default_value_t = false)]
    pub supplement_vulners: bool,
    #[arg(long, default_value_t = false)]
    pub freeze: bool,
    #[arg(long, default_value_t = false)]
    pub production: bool,
    #[arg(long)]
    pub nmap_xml: Option<PathBuf>,
    #[arg(long)]
    pub nmap_followup_xml: Option<PathBuf>,
    #[arg(long)]
    pub suricata_eve: Option<PathBuf>,
    #[arg(long)]
    pub zeek_dir: Option<PathBuf>,
    #[arg(long)]
    pub porovnat_s: Option<String>,
    #[arg(long)]
    pub spustit_nmap: bool,
    #[arg(long, default_value_t = false)]
    pub hloubkove_overeni: bool,
    #[arg(long, default_value_t = false)]
    pub web_fingerprint: bool,
    #[arg(long, default_value_t = false)]
    pub web_checks: bool,
    /// Vykona kontroly vybrane `verification_planner` (jen passive/read-only,
    /// po scope/rozpoctu/rate-limit mantinelech); kontroly vyzadujici schvaleni
    /// se nikdy nespusti automaticky. Vychozi: vypnuto (jen plan, shadow mode).
    #[arg(long, default_value_t = false)]
    pub execute_verification: bool,
    /// Cte jen NOVE radky Suricata/Zeek logu od posledniho uspesneho behu
    /// (offsety v `ingest-cursors.json`, at-least-once). Zapina se automaticky
    /// pro `monitor --continuous`.
    #[arg(long, default_value_t = false)]
    pub incremental_ingest: bool,
    /// Strop poctu automaticky vykonanych kontrol za beh.
    #[arg(long, default_value_t = 10)]
    pub verification_max_checks: usize,
    #[arg(long, default_value_t = false)]
    pub pentest: bool,
    #[arg(long, default_value_t = false)]
    pub aggressive_pentest: bool,
    #[arg(long)]
    pub httpx_bin: Option<PathBuf>,
    #[arg(long)]
    pub nuclei_bin: Option<PathBuf>,
    #[arg(long)]
    pub nuclei_templates: Option<PathBuf>,
    #[arg(long)]
    pub snmp_snapshot: Option<PathBuf>,
    #[arg(long)]
    pub librenms_snapshot: Option<PathBuf>,
    #[arg(long)]
    pub librenms_base_url: Option<String>,
    #[arg(long, default_value = "LIBRENMS_TOKEN")]
    pub librenms_token_env: String,
    #[arg(long)]
    pub meraki_snapshot: Option<PathBuf>,
    #[arg(long)]
    pub meraki_network_id: Option<String>,
    #[arg(long, default_value = "MERAKI_DASHBOARD_API_KEY")]
    pub meraki_api_key_env: String,
    #[arg(long, default_value_t = 86400)]
    pub meraki_timespan_seconds: u32,
    #[arg(long)]
    pub unifi_snapshot: Option<PathBuf>,
    #[arg(long)]
    pub unifi_devices_url: Option<String>,
    #[arg(long)]
    pub unifi_clients_url: Option<String>,
    #[arg(long)]
    pub unifi_links_url: Option<String>,
    #[arg(long, default_value = "UNIFI_API_KEY")]
    pub unifi_api_key_env: String,
    #[arg(long)]
    pub aruba_snapshot: Option<PathBuf>,
    #[arg(long)]
    pub aruba_base_url: Option<String>,
    #[arg(long, default_value = "ARUBA_CENTRAL_TOKEN")]
    pub aruba_token_env: String,
    #[arg(long)]
    pub aruba_site_id: Option<String>,
    #[arg(long)]
    pub omada_snapshot: Option<PathBuf>,
    #[arg(long)]
    pub omada_devices_url: Option<String>,
    #[arg(long)]
    pub omada_clients_url: Option<String>,
    #[arg(long)]
    pub omada_links_url: Option<String>,
    #[arg(long, default_value = "OMADA_ACCESS_TOKEN")]
    pub omada_access_token_env: String,
    #[arg(long)]
    pub ntopng_snapshot: Option<PathBuf>,
    #[arg(long)]
    pub flow_snapshot: Option<PathBuf>,
    #[arg(long)]
    pub greenbone_report: Option<PathBuf>,
    #[arg(long)]
    pub wazuh_report: Option<PathBuf>,
    #[arg(long)]
    pub napalm_snapshot: Option<PathBuf>,
    #[arg(long)]
    pub netmiko_snapshot: Option<PathBuf>,
    #[arg(long)]
    pub scrapli_snapshot: Option<PathBuf>,
    #[arg(long, default_value = "URLHAUS_AUTH_KEY")]
    pub urlhaus_auth_env: String,
    #[arg(long, default_value = "ABUSEIPDB_API_KEY")]
    pub abuseipdb_key_env: String,
    #[arg(long, default_value_t = false)]
    pub disable_circl: bool,
}
pub fn promote_monitor_args(args: &mut BehArgs) {
    args.hloubkove_overeni = true;
    auto_enable_vulners(args);
    args.disable_circl = false;
}

pub fn promote_autopilot_args(args: &mut BehArgs) {
    args.hloubkove_overeni = true;
    auto_enable_web_tools(args);
    auto_enable_vulners(args);
    args.disable_circl = false;
}

fn prepare_pipeline_args(mut args: BehArgs) -> anyhow::Result<BehArgs> {
    if args.production {
        apply_production_profile(&mut args);
    }
    if args.aggressive_pentest {
        args.pentest = true;
    }
    validate_pipeline_args(&args)?;
    Ok(args)
}

fn apply_production_profile(args: &mut BehArgs) {
    if args.nmap_xml.is_none() {
        args.spustit_nmap = true;
    }
    if args.provider == "demo" {
        args.provider = "public".to_string();
    }
    args.hloubkove_overeni = true;
    args.pentest = true;
    auto_enable_web_tools(args);
    auto_enable_vulners(args);
    args.disable_circl = false;
}

fn auto_enable_vulners(args: &mut BehArgs) {
    if matches!(args.provider.as_str(), "nvd" | "public" | "auto") {
        args.supplement_vulners = true;
    }
}

fn auto_enable_web_tools(args: &mut BehArgs) {
    let httpx_name = paths::exe_name("httpx");
    if can_resolve_tool(
        args.httpx_bin.as_deref(),
        &httpx_name,
        &[
            args.workspace
                .join("tools")
                .join("projectdiscovery")
                .join("httpx")
                .join(&httpx_name),
            paths::project_path(&["tools", "projectdiscovery", "httpx", httpx_name.as_str()]),
        ],
    ) {
        args.web_fingerprint = true;
    }
    let nuclei_name = paths::exe_name("nuclei");
    if can_resolve_tool(
        args.nuclei_bin.as_deref(),
        &nuclei_name,
        &[
            args.workspace
                .join("tools")
                .join("projectdiscovery")
                .join("nuclei")
                .join(&nuclei_name),
            paths::project_path(&["tools", "projectdiscovery", "nuclei", nuclei_name.as_str()]),
        ],
    ) {
        args.web_checks = true;
    }
}

pub fn validate_monitor_args(args: &BehArgs) -> anyhow::Result<()> {
    if !has_passive_telemetry(args) {
        return Err(anyhow::anyhow!(
            "Monitorovací režim potřebuje pasivní zdroj: zadej --suricata-eve nebo --zeek-dir."
        ));
    }
    Ok(())
}

fn validate_pipeline_args(args: &BehArgs) -> anyhow::Result<()> {
    if args.scope.is_empty() {
        return Err(anyhow::anyhow!(
            "Musím dostat alespoň jeden --scope rozsah."
        ));
    }
    if args.nmap_xml.is_none() && !args.spustit_nmap {
        return Err(anyhow::anyhow!(
            "Je nutne zadat --nmap-xml nebo zapnout --spustit-nmap."
        ));
    }
    if args.spustit_nmap && args.ports.is_empty() {
        return Err(anyhow::anyhow!(
            "Pro aktivní Nmap běh potřebuji alespoň jeden port v --ports."
        ));
    }
    if let Some(path) = &args.nmap_xml {
        ensure_file_exists(path, "--nmap-xml")?;
    }
    if let Some(path) = &args.nmap_followup_xml {
        ensure_file_exists(path, "--nmap-followup-xml")?;
    }
    if let Some(path) = &args.suricata_eve {
        ensure_file_exists(path, "--suricata-eve")?;
    }
    if let Some(path) = &args.zeek_dir {
        ensure_dir_exists(path, "--zeek-dir")?;
    }
    if args.production && !has_passive_telemetry(args) {
        return Err(anyhow::anyhow!(
            "Produkční běh má kombinovat aktivní i pasivní analýzu, proto potřebuji --suricata-eve nebo --zeek-dir."
        ));
    }
    Ok(())
}

fn has_passive_telemetry(args: &BehArgs) -> bool {
    args.suricata_eve.is_some() || args.zeek_dir.is_some()
}

fn ensure_file_exists(path: &Path, label: &str) -> anyhow::Result<()> {
    if path.is_file() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "{} ukazuje na soubor, který neexistuje: {}",
            label,
            path.display()
        ))
    }
}

fn ensure_dir_exists(path: &Path, label: &str) -> anyhow::Result<()> {
    if path.is_dir() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "{} ukazuje na složku, která neexistuje: {}",
            label,
            path.display()
        ))
    }
}

fn can_resolve_tool(explicit: Option<&Path>, file_name: &str, defaults: &[PathBuf]) -> bool {
    if let Some(path) = explicit {
        if path.is_file() {
            return true;
        }
    }
    if defaults.iter().any(|path| path.is_file()) {
        return true;
    }
    env::var_os("PATH")
        .map(|paths| env::split_paths(&paths).any(|path| path.join(file_name).is_file()))
        .unwrap_or(false)
}

pub fn resolve_simulation_profile(
    profile_name: &str,
    extra_hosts: Option<usize>,
    max_services_per_host: Option<usize>,
    telemetry_burst_per_host: Option<usize>,
    flow_repetitions: Option<usize>,
) -> anyhow::Result<simulation::SimulationScaleProfile> {
    let profile = simulation::SimulationScaleProfile::from_name(profile_name).ok_or_else(|| {
        anyhow::anyhow!(
            "Neznámý profil simulace '{}'. Použij standard|large|enterprise.",
            profile_name
        )
    })?;
    Ok(profile.with_overrides(
        extra_hosts,
        max_services_per_host,
        telemetry_burst_per_host,
        flow_repetitions,
    ))
}

#[derive(Debug, Clone)]
struct MasAgentPlan {
    role: &'static str,
    priority: f64,
    budget_ms: u64,
    latency_hint_ms: u64,
}

#[derive(Debug, Clone)]
struct MasAgentMetric {
    role: &'static str,
    priority: f64,
    budget_ms: u64,
    latency_hint_ms: u64,
    queue_wait_ms: u64,
    runtime_ms: u64,
    sla_met: bool,
}

enum ParallelCollectorOutput {
    Context(context::ContextBundle),
    Lanes(lanes::LaneBundle),
    Passive((Vec<NormalizedEvent>, Option<passive::BehaviorFlows>)),
}

fn round_metric(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

fn adaptive_priority(base: f64, latency_hint_ms: u64, max_hint_ms: u64) -> f64 {
    let normalized = if max_hint_ms == 0 {
        0.0
    } else {
        latency_hint_ms as f64 / max_hint_ms as f64
    };
    round_metric((base + normalized * 0.35).clamp(0.15, 1.5))
}

fn adaptive_budget_ms(latency_hint_ms: u64, base_budget_ms: u64) -> u64 {
    base_budget_ms
        .saturating_add(latency_hint_ms.saturating_mul(2))
        .clamp(600, 20_000)
}

fn estimate_context_latency_hint(args: &BehArgs) -> u64 {
    let mut latency_ms = 120_u64;
    latency_ms += 70 * u64::from(args.snmp_snapshot.is_some());
    latency_ms += 120 * u64::from(args.librenms_snapshot.is_some());
    latency_ms += 260 * u64::from(args.librenms_base_url.is_some());
    latency_ms += 130 * u64::from(args.meraki_snapshot.is_some());
    latency_ms += 270 * u64::from(args.meraki_network_id.is_some());
    latency_ms += 120 * u64::from(args.unifi_snapshot.is_some());
    latency_ms += 240
        * u64::from(
            args.unifi_devices_url.is_some()
                || args.unifi_clients_url.is_some()
                || args.unifi_links_url.is_some(),
        );
    latency_ms += 120 * u64::from(args.aruba_snapshot.is_some());
    latency_ms += 220 * u64::from(args.aruba_base_url.is_some());
    latency_ms += 110 * u64::from(args.omada_snapshot.is_some());
    latency_ms += 230
        * u64::from(
            args.omada_devices_url.is_some()
                || args.omada_clients_url.is_some()
                || args.omada_links_url.is_some(),
        );
    latency_ms
}

fn estimate_live_observer_latency_hint(args: &BehArgs) -> u64 {
    let mut latency_ms = 100_u64;
    latency_ms += 180 * u64::from(args.suricata_eve.is_some());
    latency_ms += 220 * u64::from(args.zeek_dir.is_some());
    latency_ms += 150 * u64::from(args.ntopng_snapshot.is_some());
    latency_ms += 140 * u64::from(args.flow_snapshot.is_some());
    latency_ms
}

fn estimate_correlator_latency_hint(hosts_total: usize, findings_total: usize) -> u64 {
    160_u64
        .saturating_add((hosts_total as u64).saturating_mul(8))
        .saturating_add((findings_total as u64).saturating_mul(12))
}

fn estimate_followup_latency_hint(raw_inventory_hosts: usize) -> u64 {
    140_u64.saturating_add((raw_inventory_hosts as u64).saturating_mul(18))
}

fn estimate_forensic_latency_hint(open_services: usize) -> u64 {
    180_u64.saturating_add((open_services as u64).saturating_mul(9))
}

fn estimate_pentest_latency_hint(open_services: usize, aggressive: bool) -> u64 {
    let per_service = if aggressive { 140 } else { 55 };
    220_u64.saturating_add((open_services as u64).saturating_mul(per_service))
}

fn compute_parallelism_ratio(total_runtime_ms: u64, wall_ms: u64, workers: usize) -> f64 {
    if wall_ms == 0 || workers == 0 {
        return 1.0;
    }
    round_metric((total_runtime_ms as f64 / (wall_ms as f64 * workers as f64)).clamp(0.0, 1.0))
}

/// `run_pipeline` přidává nové `monitoring_lanes` na 3 různých místech (po
/// MAS scheduler lane, po validation bundle, po automation insights) a po
/// každém musí přesortovat/odduplikovat podle `lane_id` a přepočítat
/// souhrnná čísla - stejná trojice kroků, dřív 3x doslova opsaná (Fáze 1,
/// produkční plán). Sjednoceno sem beze změny chování - volá se na přesně
/// stejných 3 místech jako dřív, počítá přesně totéž.
fn resort_and_recompute_lane_summary(report: &mut RunReport) {
    report
        .monitoring_lanes
        .sort_by(|left, right| left.lane_id.cmp(&right.lane_id));
    report
        .monitoring_lanes
        .dedup_by(|left, right| left.lane_id == right.lane_id);
    report.summary.monitoring_lanes_total = report.monitoring_lanes.len();
    report.summary.live_lanes_total = report
        .monitoring_lanes
        .iter()
        .filter(|lane| lane.lane_type == "live")
        .count();
    report.summary.audit_lanes_total = report
        .monitoring_lanes
        .iter()
        .filter(|lane| lane.lane_type == "audit")
        .count();
}

/// Krok 7 (C5): čas běhu při chronologickém přehrávání veřejného datasetu celou
/// produkční cestou (`tools/replay_public.py`). Jen pro evaluaci: proměnná
/// `BAKULA_REPLAY_NOW` (RFC 3339) nastaví začátek běhu na začátek přehrávaného okna,
/// aby profil, novost a paměť nálezů běžely v čase dat. Bez proměnné nástěnné hodiny.
fn replay_clock() -> Option<chrono::DateTime<Utc>> {
    let value = std::env::var("BAKULA_REPLAY_NOW").ok()?;
    match chrono::DateTime::parse_from_rfc3339(value.trim()) {
        Ok(at) => {
            tracing::warn!(%value, "cas behu z BAKULA_REPLAY_NOW (prehravani datasetu)");
            Some(at.with_timezone(&Utc))
        }
        Err(error) => {
            tracing::warn!(%value, %error, "neplatne BAKULA_REPLAY_NOW, pouzit aktualni cas");
            None
        }
    }
}

pub fn run_pipeline(args: BehArgs) -> anyhow::Result<RunReport> {
    let args = prepare_pipeline_args(args)?;
    fs::create_dir_all(&args.workspace)?;
    let config_path = args.workspace.join("bakula.toml");
    let app_config = config::load_or_default(&config_path)?;
    let workspace = Workspace::open(&args.workspace)?;
    let run_id = report::build_run_id();
    let mut mas_agent_metrics = Vec::<MasAgentMetric>::new();

    if args.hloubkove_overeni {
        let _ = automation::update_runtime_phase(
            &args.workspace,
            "planning",
            "Plánovač skládá pořadí kroků a připravuje rozsah běhu.",
        );
    }

    let start = replay_clock().unwrap_or_else(Utc::now);
    if args.hloubkove_overeni {
        let _ = automation::update_runtime_phase(
            &args.workspace,
            "inventory",
            "Inventář sbírá základní síťové služby a identity.",
        );
    }
    let nmap_path = if let Some(path) = &args.nmap_xml {
        path.clone()
    } else if args.spustit_nmap {
        nmap::run_real_nmap(&args.workspace, &args.scope, &args.ports, &args.profile)?
    } else {
        return Err(anyhow::anyhow!(
            "Je nutne zadat --nmap-xml nebo zapnout --spustit-nmap."
        ));
    };

    let mut raw_inventory = nmap::parse_nmap_xml(&nmap_path)?;
    if args.hloubkove_overeni {
        let _ = automation::update_runtime_phase(
            &args.workspace,
            "followup",
            "Cílený follow-up zpřesňuje nejasné služby a hosty.",
        );
    }
    let followup_hint_ms = estimate_followup_latency_hint(raw_inventory.hosts.len());
    let followup_budget_ms = adaptive_budget_ms(followup_hint_ms, 900);
    let followup_priority = adaptive_priority(0.68, followup_hint_ms, 1_500);
    let followup_started_at = Instant::now();
    let followup_scan = if let Some(path) = &args.nmap_followup_xml {
        Some(nmap::FollowupExecution {
            output_path: path.clone(),
            targeted_hosts: 0,
            targeted_ports: 0,
        })
    } else if args.spustit_nmap && args.nmap_xml.is_none() {
        nmap::run_targeted_followup_nmap(
            &args.workspace,
            &raw_inventory,
            &args.profile,
            &args.scope,
        )?
    } else {
        None
    };
    let followup_scan = if let Some(followup) = followup_scan {
        let followup_inventory = nmap::parse_nmap_xml(&followup.output_path)?;
        let resolved_followup = nmap::FollowupExecution {
            output_path: followup.output_path.clone(),
            targeted_hosts: if followup.targeted_hosts == 0 {
                followup_inventory.hosts.len()
            } else {
                followup.targeted_hosts
            },
            targeted_ports: if followup.targeted_ports == 0 {
                followup_inventory
                    .hosts
                    .iter()
                    .flat_map(|host| host.services.iter().map(|service| service.port))
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            } else {
                followup.targeted_ports
            },
        };
        raw_inventory = nmap::merge_followup_inventory(raw_inventory, followup_inventory);
        Some(resolved_followup)
    } else {
        None
    };
    let followup_runtime_ms = followup_started_at.elapsed().as_millis() as u64;
    mas_agent_metrics.push(MasAgentMetric {
        role: "followup",
        priority: followup_priority,
        budget_ms: followup_budget_ms,
        latency_hint_ms: followup_hint_ms,
        queue_wait_ms: 0,
        runtime_ms: followup_runtime_ms,
        sla_met: followup_runtime_ms <= followup_budget_ms,
    });
    let provider = vuln::build_provider(
        &args.workspace,
        &args.provider,
        args.supplement_vulners,
        args.freeze,
    )
    .map_err(|error| anyhow::Error::new(error).context("Nelze inicializovat provider"))?;
    let web_config = webscan::WebScanConfig {
        enable_httpx: args.web_fingerprint || args.web_checks,
        enable_nuclei: args.web_checks,
        httpx_bin: args.httpx_bin.clone(),
        nuclei_bin: args.nuclei_bin.clone(),
        nuclei_templates_dir: args.nuclei_templates.clone(),
    };
    let mut hosts = report::normalize_inventory(raw_inventory.clone());
    cpe::enrich_services_with_cpe(&mut hosts, &args.workspace.join("data"))?;
    vuln::enrich_with_vulnerabilities(&mut hosts, provider.as_ref())
        .map_err(|error| anyhow::Error::new(error).context("Obohaceni o zranitelnosti selhalo"))?;
    let mut web_artifacts =
        webscan::enrich_http_services(&mut hosts, &args.workspace, &run_id, &web_config).map_err(
            |error| anyhow::Error::new(error).context("Web fingerprinting / web checks selhaly"),
        )?;
    report::score_services(&mut hosts);
    let open_services_total = hosts
        .iter()
        .flat_map(|host| host.services.iter())
        .filter(|service| service.port_state == "open")
        .count();
    let forensic_hint_ms = estimate_forensic_latency_hint(open_services_total);
    let forensic_budget_ms = adaptive_budget_ms(forensic_hint_ms, 1_200);
    let forensic_priority = adaptive_priority(0.74, forensic_hint_ms, 1_900);
    let forensic_started_at = Instant::now();

    let forensic_scan = if args.hloubkove_overeni && args.spustit_nmap {
        let _ = automation::update_runtime_phase(
            &args.workspace,
            "forensic",
            "Forenzní vrstva spouští hlubší ověření prioritních cílů.",
        );
        nmap::run_forensic_followup_nmap(&args.workspace, &hosts, &args.profile, &args.scope)?
    } else {
        None
    };
    let forensic_scan = if let Some(forensic) = forensic_scan {
        let forensic_inventory = nmap::parse_nmap_xml(&forensic.output_path)?;
        let resolved_forensic = nmap::FollowupExecution {
            output_path: forensic.output_path.clone(),
            targeted_hosts: if forensic.targeted_hosts == 0 {
                forensic_inventory.hosts.len()
            } else {
                forensic.targeted_hosts
            },
            targeted_ports: if forensic.targeted_ports == 0 {
                forensic_inventory
                    .hosts
                    .iter()
                    .flat_map(|host| host.services.iter().map(|service| service.port))
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            } else {
                forensic.targeted_ports
            },
        };
        raw_inventory = nmap::merge_followup_inventory(raw_inventory, forensic_inventory);
        hosts = report::normalize_inventory(raw_inventory.clone());
        cpe::enrich_services_with_cpe(&mut hosts, &args.workspace.join("data"))?;
        vuln::enrich_with_vulnerabilities(&mut hosts, provider.as_ref()).map_err(|error| {
            anyhow::Error::new(error).context("Forenzní obohacení o zranitelnosti selhalo")
        })?;
        web_artifacts =
            webscan::enrich_http_services(&mut hosts, &args.workspace, &run_id, &web_config)
                .map_err(|error| {
                    anyhow::Error::new(error)
                        .context("Forenzní web fingerprinting / web checks selhaly")
                })?;
        Some(resolved_forensic)
    } else {
        None
    };
    let forensic_runtime_ms = forensic_started_at.elapsed().as_millis() as u64;
    mas_agent_metrics.push(MasAgentMetric {
        role: "forensic",
        priority: forensic_priority,
        budget_ms: forensic_budget_ms,
        latency_hint_ms: forensic_hint_ms,
        queue_wait_ms: 0,
        runtime_ms: forensic_runtime_ms,
        sla_met: forensic_runtime_ms <= forensic_budget_ms,
    });

    let pentest_hint_ms = if args.pentest {
        estimate_pentest_latency_hint(open_services_total, args.aggressive_pentest)
    } else {
        0
    };
    let pentest_budget_ms = adaptive_budget_ms(pentest_hint_ms, 1_600);
    let pentest_priority = adaptive_priority(
        if args.aggressive_pentest { 0.96 } else { 0.82 },
        pentest_hint_ms,
        if args.aggressive_pentest {
            2_400
        } else {
            1_600
        },
    );
    let pentest_started_at = Instant::now();
    let pentest_artifacts = pentest::run_internal_pentest(
        &mut hosts,
        &pentest::PentestConfig {
            enabled: args.pentest,
            aggressive: args.aggressive_pentest,
            timeout_ms: if args.aggressive_pentest {
                1_800
            } else {
                1_200
            },
        },
    )
    .map_err(|error| anyhow::Error::new(error).context("Interní pentest vrstva selhala"))?;
    let pentest_runtime_ms = pentest_started_at.elapsed().as_millis() as u64;
    if args.pentest {
        mas_agent_metrics.push(MasAgentMetric {
            role: if args.aggressive_pentest {
                "aggressive-pentest"
            } else {
                "internal-pentest"
            },
            priority: pentest_priority,
            budget_ms: pentest_budget_ms,
            latency_hint_ms: pentest_hint_ms,
            queue_wait_ms: 0,
            runtime_ms: pentest_runtime_ms,
            sla_met: pentest_runtime_ms <= pentest_budget_ms,
        });
    }

    let end = Utc::now();
    if args.hloubkove_overeni {
        let _ = automation::update_runtime_phase(
            &args.workspace,
            "context",
            "Autorizované adaptéry skládají topologii, aktiva a sousedy.",
        );
    }
    let context_config = context::ContextConfig {
        snmp_snapshot: args.snmp_snapshot.clone(),
        librenms_snapshot: args.librenms_snapshot.clone(),
        librenms_base_url: args.librenms_base_url.clone(),
        librenms_token_env: args.librenms_token_env.clone(),
        meraki_snapshot: args.meraki_snapshot.clone(),
        meraki_api_key_env: args.meraki_api_key_env.clone(),
        meraki_network_id: args.meraki_network_id.clone(),
        meraki_timespan_seconds: args.meraki_timespan_seconds,
        unifi_snapshot: args.unifi_snapshot.clone(),
        unifi_devices_url: args.unifi_devices_url.clone(),
        unifi_clients_url: args.unifi_clients_url.clone(),
        unifi_links_url: args.unifi_links_url.clone(),
        unifi_api_key_env: args.unifi_api_key_env.clone(),
        aruba_snapshot: args.aruba_snapshot.clone(),
        aruba_base_url: args.aruba_base_url.clone(),
        aruba_token_env: args.aruba_token_env.clone(),
        aruba_site_id: args.aruba_site_id.clone(),
        omada_snapshot: args.omada_snapshot.clone(),
        omada_devices_url: args.omada_devices_url.clone(),
        omada_clients_url: args.omada_clients_url.clone(),
        omada_links_url: args.omada_links_url.clone(),
        omada_access_token_env: args.omada_access_token_env.clone(),
    };
    let lane_config = lanes::LaneConfig {
        ntopng_snapshot: args.ntopng_snapshot.clone(),
        flow_snapshot: args.flow_snapshot.clone(),
        greenbone_report: args.greenbone_report.clone(),
        wazuh_report: args.wazuh_report.clone(),
        napalm_snapshot: args.napalm_snapshot.clone(),
        netmiko_snapshot: args.netmiko_snapshot.clone(),
        scrapli_snapshot: args.scrapli_snapshot.clone(),
    };
    let passive_window = report::determine_passive_window(start, end);
    let mut pending_ingest = ingest::PendingIngest::default();
    let passive_sources = if args.incremental_ingest {
        passive::PassiveSources {
            suricata_eve: match &args.suricata_eve {
                Some(path) => Some(ingest::delta_eve(
                    &args.workspace,
                    path,
                    &mut pending_ingest,
                )?),
                None => None,
            },
            zeek_dir: match &args.zeek_dir {
                Some(path) => Some(ingest::delta_zeek_dir(
                    &args.workspace,
                    path,
                    &mut pending_ingest,
                )?),
                None => None,
            },
        }
    } else {
        passive::PassiveSources {
            suricata_eve: args.suricata_eve.clone(),
            zeek_dir: args.zeek_dir.clone(),
        }
    };
    if pending_ingest.rotations > 0 {
        tracing::warn!(
            rotations = pending_ingest.rotations,
            "detekovana rotace/vymena pasivnich logu; cteno od zacatku noveho souboru"
        );
    }
    let context_hint_ms = estimate_context_latency_hint(&args);
    let live_observer_hint_ms = estimate_live_observer_latency_hint(&args);
    let correlator_prep_hint_ms = estimate_correlator_latency_hint(
        hosts.len(),
        hosts.iter().map(|host| host.services.len()).sum(),
    );
    let max_hint_ms = context_hint_ms
        .max(live_observer_hint_ms)
        .max(correlator_prep_hint_ms)
        .max(1);
    let mut parallel_plans = vec![
        MasAgentPlan {
            role: "context-fusion",
            priority: adaptive_priority(0.84, context_hint_ms, max_hint_ms),
            budget_ms: adaptive_budget_ms(context_hint_ms, 1_000),
            latency_hint_ms: context_hint_ms,
        },
        MasAgentPlan {
            role: "correlator-prep",
            priority: adaptive_priority(0.80, correlator_prep_hint_ms, max_hint_ms),
            budget_ms: adaptive_budget_ms(correlator_prep_hint_ms, 950),
            latency_hint_ms: correlator_prep_hint_ms,
        },
        MasAgentPlan {
            role: "live-observer",
            priority: adaptive_priority(0.88, live_observer_hint_ms, max_hint_ms),
            budget_ms: adaptive_budget_ms(live_observer_hint_ms, 950),
            latency_hint_ms: live_observer_hint_ms,
        },
    ];
    parallel_plans.sort_by(|left, right| {
        right
            .priority
            .partial_cmp(&left.priority)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Engine v3 (krok 1): stavovy detektor a perzistentni stav ve workspace.
    let mut v3_session = v3::V3Session::open(
        &args.workspace,
        app_config.engine,
        &hosts,
        passive_window.start,
    )
    .map_err(|error| anyhow::Error::new(error).context("Stav jadra v3 se nenacetl"))?;
    let detector_ref: &(dyn passive::ConnectionDetector + Sync) =
        match v3_session.as_ref().and_then(|session| session.detector()) {
            Some(detector) => detector,
            None => &passive::LegacyAnomalyDetector,
        };
    let hosts_ref = &hosts;
    let context_config_ref = &context_config;
    let lane_config_ref = &lane_config;
    let passive_sources_ref = &passive_sources;
    let scope_ref = &args.scope;
    // krok 3: v3 s behavioralni vrstvou drzi i odchozi toky (zdroj nebo cil v rozsahu)
    let egress_policy = crate::passive::egress::EgressPolicy::default();
    let behavior_egress = v3_session
        .as_ref()
        .filter(|session| session.behavior_enabled())
        .map(|_| &egress_policy);
    let parallel_started_at = Instant::now();
    let (context_bundle, lane_bundle, passive_events, parallel_metrics) = thread::scope(|scope| {
        let scheduler_started_at = Instant::now();
        let mut handles = Vec::new();
        for plan in parallel_plans {
            let queue_wait_ms = scheduler_started_at.elapsed().as_millis() as u64;
            let hosts_ref = hosts_ref;
            let context_config_ref = context_config_ref;
            let lane_config_ref = lane_config_ref;
            let passive_sources_ref = passive_sources_ref;
            let scope_ref = scope_ref;
            let handle = scope.spawn(move || {
                let started_at = Instant::now();
                let output = match plan.role {
                    "context-fusion" => ParallelCollectorOutput::Context(
                        context::collect_context(hosts_ref, context_config_ref).map_err(
                            |error| {
                                anyhow::Error::new(error)
                                    .context("Načtení autorizovaných síťových zdrojů selhalo")
                            },
                        )?,
                    ),
                    "correlator-prep" => ParallelCollectorOutput::Lanes(
                        lanes::collect_lanes(hosts_ref, lane_config_ref).map_err(|error| {
                            anyhow::Error::new(error).context("Načtení live/audit lanes selhalo")
                        })?,
                    ),
                    _ => ParallelCollectorOutput::Passive(
                        passive::load_and_normalize_with_behavior(
                            passive_sources_ref,
                            scope_ref,
                            passive_window.start,
                            passive_window.end,
                            hosts_ref,
                            detector_ref,
                            behavior_egress,
                        )
                        .map_err(|error| {
                            anyhow::Error::new(error).context("Pasivni import selhal")
                        })?,
                    ),
                };
                let runtime_ms = started_at.elapsed().as_millis() as u64;
                Ok::<_, anyhow::Error>((
                    MasAgentMetric {
                        role: plan.role,
                        priority: plan.priority,
                        budget_ms: plan.budget_ms,
                        latency_hint_ms: plan.latency_hint_ms,
                        queue_wait_ms,
                        runtime_ms,
                        sla_met: runtime_ms <= plan.budget_ms,
                    },
                    output,
                ))
            });
            handles.push(handle);
        }

        let mut context_bundle = None;
        let mut lane_bundle = None;
        let mut passive_events = None;
        let mut metrics = Vec::new();
        for handle in handles {
            let (metric, output) = handle
                .join()
                .map_err(|_| anyhow::anyhow!("MAS worker skončil panicem"))??;
            metrics.push(metric);
            match output {
                ParallelCollectorOutput::Context(value) => context_bundle = Some(value),
                ParallelCollectorOutput::Lanes(value) => lane_bundle = Some(value),
                ParallelCollectorOutput::Passive(value) => passive_events = Some(value),
            }
        }

        Ok::<_, anyhow::Error>((
            context_bundle.ok_or_else(|| anyhow::anyhow!("Context worker nevrátil výstup"))?,
            lane_bundle.ok_or_else(|| anyhow::anyhow!("Lane worker nevrátil výstup"))?,
            passive_events.ok_or_else(|| anyhow::anyhow!("Passive worker nevrátil výstup"))?,
            metrics,
        ))
    })?;
    let (passive_events, behavior_flows) = passive_events;
    if let Some(session) = v3_session.as_mut() {
        session.set_behavior_flows(behavior_flows);
        session
            .finish_detection()
            .map_err(|error| anyhow::Error::new(error).context("Ulozeni stavu detektoru v3"))?;
    }
    let parallel_stage_wall_ms = parallel_started_at.elapsed().as_millis() as u64;
    let parallel_stage_workers = parallel_metrics.len();
    mas_agent_metrics.extend(parallel_metrics);

    if args.hloubkove_overeni {
        let _ = automation::update_runtime_phase(
            &args.workspace,
            "passive",
            "Pasivní vrstva dokončila sběr toků a předává data ke korelaci.",
        );
    }

    let correlator_hint_ms = estimate_correlator_latency_hint(hosts.len(), 0);
    let correlator_budget_ms = adaptive_budget_ms(correlator_hint_ms, 1_100);
    let correlator_priority = adaptive_priority(0.92, correlator_hint_ms, 1_600);
    let correlator_started_at = Instant::now();
    let correlated =
        correlation::correlate_events(&hosts, passive_events, passive_window.time_window_s);
    let unmapped_events = report::attach_events(&mut hosts, correlated);
    report::score_services(&mut hosts);
    // Produkční plán (core wiring, 30.10.2026): první skutečný produkční
    // vstupní bod pro `identity.rs` - stínově/aditivně, jen doplní
    // `asset_id`/`identity_note` na každý host, beze změny `host_key`/
    // decision/triage logiky. Musí běžet AŽ TADY (ne dřív), protože hloubkové
    // ověření výš může `hosts` znovu sestavit z `normalize_inventory`.
    let identity_matches = if app_config.engine.identity_v3() {
        identity::resolve_and_annotate_v3(
            &mut hosts,
            &args.workspace.join("identity-registry-v3.json"),
        )
    } else {
        identity::resolve_and_annotate(&mut hosts, &args.workspace.join("identity-registry.json"))
    }
    .map_err(|error| anyhow::Error::new(error).context("Identity resolver selhal"))?;
    // `hypothesis::build_hypotheses_for_report` potrebuje tuhle mapu POSTAVENOU
    // TADY, dokud `hosts`'s poradi jiste odpovida `identity_matches` - `hosts`
    // se nize predava (moved) do `report::build_report`, ktere ho znovu seradi
    // podle IP (viz komentar u `build_hypotheses_for_report`).
    let identity_by_host_key: std::collections::HashMap<String, identity::IdentityMatch> = hosts
        .iter()
        .map(|host| host.host_key.clone())
        .zip(identity_matches)
        .collect();
    let correlator_runtime_ms = correlator_started_at.elapsed().as_millis() as u64;
    mas_agent_metrics.push(MasAgentMetric {
        role: "correlator",
        priority: correlator_priority,
        budget_ms: correlator_budget_ms,
        latency_hint_ms: correlator_hint_ms,
        queue_wait_ms: 0,
        runtime_ms: correlator_runtime_ms,
        sla_met: correlator_runtime_ms <= correlator_budget_ms,
    });
    if args.hloubkove_overeni {
        let _ = automation::update_runtime_phase(
            &args.workspace,
            "correlation",
            "Korelační vrstva spojuje nálezy, změny a doporučené kroky.",
        );
    }

    let mas_total_runtime_ms = mas_agent_metrics
        .iter()
        .map(|metric| metric.runtime_ms)
        .sum::<u64>();
    let mas_queue_wait_ms_avg = if mas_agent_metrics.is_empty() {
        0.0
    } else {
        round_metric(
            mas_agent_metrics
                .iter()
                .map(|metric| metric.queue_wait_ms as f64)
                .sum::<f64>()
                / mas_agent_metrics.len() as f64,
        )
    };
    let mas_agent_sla_ratio = if mas_agent_metrics.is_empty() {
        1.0
    } else {
        round_metric(
            mas_agent_metrics
                .iter()
                .filter(|metric| metric.sla_met)
                .count() as f64
                / mas_agent_metrics.len() as f64,
        )
    };
    let parallel_runtime_ms = mas_agent_metrics
        .iter()
        .filter(|metric| {
            metric.role == "context-fusion"
                || metric.role == "correlator-prep"
                || metric.role == "live-observer"
        })
        .map(|metric| metric.runtime_ms)
        .sum::<u64>();
    let mas_parallelism_ratio = compute_parallelism_ratio(
        parallel_runtime_ms,
        parallel_stage_wall_ms,
        parallel_stage_workers,
    );

    let mut report = report::build_report(
        &run_id,
        &args.nazev,
        start,
        end,
        args.scope.clone(),
        args.ports.clone(),
        &args.profile,
        &args.provider,
        if args.freeze { "freeze" } else { "live" },
        passive_window,
        report::build_source_metadata(&report::SourceInputs {
            nmap_mode: if args.spustit_nmap { "live" } else { "replay" },
            nmap_path: &nmap_path,
            nmap_followup_path: followup_scan
                .as_ref()
                .map(|item| item.output_path.as_path()),
            nmap_forensic_path: forensic_scan
                .as_ref()
                .map(|item| item.output_path.as_path()),
            suricata_eve: args.suricata_eve.as_deref(),
            zeek_dir: args.zeek_dir.as_deref(),
            snmp_snapshot: args.snmp_snapshot.as_deref(),
            librenms_snapshot: args.librenms_snapshot.as_deref(),
            librenms_base_url: args.librenms_base_url.as_deref(),
            meraki_snapshot: args.meraki_snapshot.as_deref(),
            meraki_network_id: args.meraki_network_id.as_deref(),
            unifi_snapshot: args.unifi_snapshot.as_deref(),
            aruba_snapshot: args.aruba_snapshot.as_deref(),
            omada_snapshot: args.omada_snapshot.as_deref(),
            ntopng_snapshot: args.ntopng_snapshot.as_deref(),
            flow_snapshot: args.flow_snapshot.as_deref(),
            greenbone_report: args.greenbone_report.as_deref(),
            wazuh_report: args.wazuh_report.as_deref(),
            napalm_snapshot: args.napalm_snapshot.as_deref(),
            netmiko_snapshot: args.netmiko_snapshot.as_deref(),
            scrapli_snapshot: args.scrapli_snapshot.as_deref(),
        }),
        hosts,
        unmapped_events,
    );
    // Zaokrouhleno JEDNOU tady (2 desetinna mista, stejne jako drive pri
    // zpetnem cteni pres `automation::derive_insights`); lokalni nezaokrouhlene
    // hodnoty se dal pouzivaji jen pro popisky MAS lane nize.
    report.summary.mas_parallelism_ratio = automation::round_ratio(mas_parallelism_ratio);
    report.summary.mas_queue_wait_ms_avg = automation::round_ratio(mas_queue_wait_ms_avg);
    report.summary.mas_agent_sla_ratio = automation::round_ratio(mas_agent_sla_ratio);
    report.network_assets = context_bundle.network_assets;
    report.topology_edges = context_bundle.topology_edges;
    if report.network_assets.is_empty() {
        let (inferred_assets, inferred_edges) =
            report::infer_network_context_from_hosts(&report.hosts);
        report.network_assets = inferred_assets;
        if report.topology_edges.is_empty() {
            report.topology_edges = inferred_edges;
        }
    }
    report.summary.network_assets_total = report.network_assets.len();
    report.summary.wireless_clients_total = report
        .network_assets
        .iter()
        .filter(|asset| asset.asset_type == "wireless-client")
        .count();
    report.summary.topology_edges_total = report.topology_edges.len();
    report.monitoring_lanes = context_bundle.monitoring_lanes;
    report
        .monitoring_lanes
        .extend(lane_bundle.monitoring_lanes.into_iter());
    if let Some(followup) = &followup_scan {
        report.monitoring_lanes.push(MonitoringLane {
            lane_id: format!("lane:nmap-followup:{}", report.run.run_id),
            lane_type: "audit".to_string(),
            source: "nmap-followup".to_string(),
            title: "Cílený druhý průchod služeb".to_string(),
            status: "ok".to_string(),
            summary: format!(
                "Follow-up Nmap ověřil {} hostů a {} vybraných portů s hlubší identifikací.",
                followup.targeted_hosts, followup.targeted_ports
            ),
            evidence: vec![
                format!("xml={}", followup.output_path.display()),
                format!("hosts={}", followup.targeted_hosts),
                format!("ports={}", followup.targeted_ports),
            ],
            recommended_tools: vec![
                "nmap".to_string(),
                "httpx".to_string(),
                "nuclei".to_string(),
            ],
        });
    }
    if let Some(forensic) = &forensic_scan {
        report.monitoring_lanes.push(MonitoringLane {
            lane_id: format!("lane:nmap-forensic:{}", report.run.run_id),
            lane_type: "audit".to_string(),
            source: "nmap-forensic".to_string(),
            title: "Forenzní zpřesnění prioritních cílů".to_string(),
            status: "ok".to_string(),
            summary: format!(
                "Forenzní Nmap průchod ověřil {} hostů a {} prioritních portů se silnější sadou skriptů.",
                forensic.targeted_hosts, forensic.targeted_ports
            ),
            evidence: vec![
                format!("xml={}", forensic.output_path.display()),
                format!("hosts={}", forensic.targeted_hosts),
                format!("ports={}", forensic.targeted_ports),
            ],
            recommended_tools: vec![
                "nmap".to_string(),
                "httpx".to_string(),
                "nuclei".to_string(),
                "greenbone".to_string(),
            ],
        });
    }
    if args.web_fingerprint || args.web_checks {
        let web_target_count = report
            .hosts
            .iter()
            .flat_map(|host| host.services.iter())
            .filter(|service| {
                service.port_state == "open"
                    && matches!(service.port, 80 | 443 | 8080 | 8443 | 8843 | 8880 | 6789)
            })
            .count();
        let web_probe_lines = web_artifacts
            .httpx_output_jsonl
            .as_deref()
            .map(|output| {
                output
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .count()
            })
            .unwrap_or(0);
        report.monitoring_lanes.push(MonitoringLane {
            lane_id: format!("lane:web:httpx:{}", report.run.run_id),
            lane_type: "audit".to_string(),
            source: "httpx".to_string(),
            title: "HTTP fingerprinting".to_string(),
            status: if report.summary.web_probes_total > 0 {
                "ok"
            } else {
                "limited"
            }
            .to_string(),
            summary: if report.summary.web_probes_total > 0 {
                format!(
                    "HTTPX probe proběhl nad {web_target_count} službami a vrátil {} web probe záznamů.",
                    report.summary.web_probes_total
                )
            } else {
                format!(
                    "HTTPX byl spuštěný nad {web_target_count} HTTP službami, ale v tomto běhu žádná služba nevrátila čitelnou odpověď."
                )
            },
            evidence: vec![
                format!("targets={web_target_count}"),
                format!("web_probes={}", report.summary.web_probes_total),
                format!("raw_lines={web_probe_lines}"),
            ],
            recommended_tools: vec!["httpx".to_string()],
        });
    }
    if args.web_checks {
        let nuclei_lines = web_artifacts
            .nuclei_output_jsonl
            .as_deref()
            .map(|output| {
                output
                    .lines()
                    .filter(|line| !line.trim().is_empty())
                    .count()
            })
            .unwrap_or(0);
        report.monitoring_lanes.push(MonitoringLane {
            lane_id: format!("lane:web:nuclei:{}", report.run.run_id),
            lane_type: "audit".to_string(),
            source: "nuclei".to_string(),
            title: "Řízené web checks".to_string(),
            status: if report.summary.active_checks_total > 0
                || report.summary.web_probes_total > 0
            {
                "ok"
            } else {
                "limited"
            }
            .to_string(),
            summary: if report.summary.active_checks_total > 0 {
                format!(
                    "Nuclei kontrola potvrdila {} aktivních nálezů.",
                    report.summary.active_checks_total
                )
            } else if report.summary.web_probes_total > 0 {
                "Nuclei kontrola proběhla nad odpovídajícími web službami a nepotvrdila aktivní web nález.".to_string()
            } else {
                "Nuclei nemělo odpovídající web cíl z httpx, proto zůstává aktivní web ověření neuzavřené.".to_string()
            },
            evidence: vec![
                format!("active_checks={}", report.summary.active_checks_total),
                format!("web_probes={}", report.summary.web_probes_total),
                format!("raw_lines={nuclei_lines}"),
            ],
            recommended_tools: vec!["nuclei".to_string()],
        });
    }
    if args.pentest {
        let mode = if args.aggressive_pentest {
            "aggressive"
        } else {
            "smart"
        };
        report.monitoring_lanes.push(MonitoringLane {
            lane_id: format!("lane:pentest:internal:{}", report.run.run_id),
            lane_type: "audit".to_string(),
            source: "internal-pentest".to_string(),
            title: if args.aggressive_pentest {
                "Interní agresivnější pentest".to_string()
            } else {
                "Interní smart pentest".to_string()
            },
            status: if pentest_artifacts.active_checks_total > 0
                || pentest_artifacts.web_probes_total > 0
                || pentest_artifacts.tcp_reachable_total > 0
            {
                "ok"
            } else {
                "limited"
            }
            .to_string(),
            summary: format!(
                "Vestavěný pentest engine běžel v režimu {mode}: cíle {}, TCP dosažitelné {}, web odpovědi {}, aktivní nálezy {}.",
                pentest_artifacts.targets_total,
                pentest_artifacts.tcp_reachable_total,
                pentest_artifacts.web_probes_total,
                pentest_artifacts.active_checks_total
            ),
            evidence: vec![
                format!("mode={mode}"),
                format!("targets={}", pentest_artifacts.targets_total),
                format!("tcp_reachable={}", pentest_artifacts.tcp_reachable_total),
                format!("web_probes={}", pentest_artifacts.web_probes_total),
                format!("active_checks={}", pentest_artifacts.active_checks_total),
                format!(
                    "aggressive_checks={}",
                    pentest_artifacts.aggressive_checks_total
                ),
                "tool=bakula-internal-pentest".to_string(),
            ],
            recommended_tools: vec![
                "bakula-tcp-probe".to_string(),
                "bakula-http-prober".to_string(),
                "bakula-method-auditor".to_string(),
            ],
        });
    }
    if args.suricata_eve.is_some() {
        report.monitoring_lanes.push(MonitoringLane {
            lane_id: format!("lane:passive:suricata:{}", report.run.run_id),
            lane_type: "live".to_string(),
            source: "suricata".to_string(),
            title: "Suricata pasivní telemetry".to_string(),
            status: "ok".to_string(),
            summary: format!(
                "Suricata zdroj byl načten, korelovaných událostí v okně: {}.",
                report.summary.events_total
            ),
            evidence: vec![format!(
                "suricata={}",
                args.suricata_eve.as_ref().unwrap().display()
            )],
            recommended_tools: vec!["suricata".to_string(), "zeek".to_string()],
        });
    }
    if args.zeek_dir.is_some() {
        report.monitoring_lanes.push(MonitoringLane {
            lane_id: format!("lane:passive:zeek:{}", report.run.run_id),
            lane_type: "live".to_string(),
            source: "zeek".to_string(),
            title: "Zeek pasivní telemetry".to_string(),
            status: "ok".to_string(),
            summary: format!(
                "Zeek zdroj byl načten, korelovaných událostí v okně: {}.",
                report.summary.events_total
            ),
            evidence: vec![format!(
                "zeek={}",
                args.zeek_dir.as_ref().unwrap().display()
            )],
            recommended_tools: vec!["zeek".to_string(), "suricata".to_string()],
        });
    }
    let mut scheduler_agents = mas_agent_metrics.clone();
    scheduler_agents.sort_by(|left, right| {
        right
            .priority
            .partial_cmp(&left.priority)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut scheduler_evidence = vec![
        format!("parallelism_ratio={mas_parallelism_ratio:.2}"),
        format!("queue_wait_ms_avg={mas_queue_wait_ms_avg:.2}"),
        format!("agent_sla_ratio={mas_agent_sla_ratio:.2}"),
        format!("total_runtime_ms={mas_total_runtime_ms}"),
        format!("parallel_stage_wall_ms={parallel_stage_wall_ms}"),
    ];
    scheduler_evidence.extend(scheduler_agents.iter().take(6).map(|metric| {
        format!(
            "agent={} priority={:.2} budget_ms={} wait_ms={} runtime_ms={} latency_hint_ms={}",
            metric.role,
            metric.priority,
            metric.budget_ms,
            metric.queue_wait_ms,
            metric.runtime_ms,
            metric.latency_hint_ms
        )
    }));
    report.monitoring_lanes.push(MonitoringLane {
        lane_id: format!("lane:mas:scheduler:{}", report.run.run_id),
        lane_type: "automation".to_string(),
        source: "mas-scheduler".to_string(),
        title: "Adaptivní scheduling agentů".to_string(),
        status: if mas_agent_sla_ratio >= 0.8 {
            "ok".to_string()
        } else {
            "limited".to_string()
        },
        summary: format!(
            "Scheduler přidělil dynamické priority a budgety. SLA {:.0} %, queue wait {:.0} ms, paralelismus {:.0} %.",
            mas_agent_sla_ratio * 100.0,
            mas_queue_wait_ms_avg,
            mas_parallelism_ratio * 100.0
        ),
        evidence: scheduler_evidence,
        recommended_tools: vec![
            "runtime-metrics".to_string(),
            "nmap".to_string(),
            "suricata".to_string(),
        ],
    });
    resort_and_recompute_lane_summary(&mut report);

    if let Some(base_run_id) = args.porovnat_s.as_deref() {
        if let Ok(base_report) = workspace.load_report(base_run_id) {
            report.diff = Some(diff::build_diff(&base_report, &report));
        }
    }

    report.intel_matches = intel::collect_intel(
        &report,
        &intel::IntelConfig {
            urlhaus_auth_env: args.urlhaus_auth_env.clone(),
            abuseipdb_key_env: args.abuseipdb_key_env.clone(),
            circl_enabled: !args.disable_circl,
            osv_enabled: true,
        },
    )
    .unwrap_or_default();
    report.summary.intel_matches_total = report.intel_matches.len();
    if let Some(intel_lane) = intel::build_public_intel_lane(&report) {
        report.monitoring_lanes.push(intel_lane);
    }
    report.findings = findings::generate_findings(&report);
    report.findings.extend(lane_bundle.findings);
    report
        .findings
        .sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    report
        .findings
        .dedup_by(|left, right| left.finding_id == right.finding_id);
    if let Some(session) = v3_session.as_mut() {
        let now = report.run.started_at;
        session
            .post_findings(
                &args.workspace,
                &mut report,
                &identity_by_host_key,
                now,
                args.execute_verification,
            )
            .map_err(|error| anyhow::Error::new(error).context("Pamet nalezu v3"))?;
    }
    // Case Memory (chybejici soubor = prazdna pamet, nic se nemeni) + historie
    // vykonanych kontrol: odhady pro hypotezy a planner pochazeji z overenych dat.
    let case_memory =
        case_memory::CaseMemory::load_or_default(&args.workspace.join("case-memory.json"));
    let verification_history = case_history::VerificationHistory::load_or_default(
        &args.workspace.join("verification-history.json"),
    );
    report.hypotheses = hypothesis::build_hypotheses_for_report(
        &report.findings,
        &report.hosts,
        &identity_by_host_key,
        Some(&case_memory),
    );
    // Faze B (produkcni-plan.md, 31.10.2026): stinove planovani - zadna aktivni
    // kontrola se tady nevykonava, jen se zapisuje, co by `verification_planner`
    // doporucil. `ScopePolicy` vyradi hypotezy, kde zadny `affected_assets` neni
    // v `args.scope` (stejna A9 disciplina jako oprava nmap followup/forenzni
    // scope-kontroly vyse).
    let verification_scope = scope_policy::ScopePolicy::new(args.scope.clone());
    report.verification_plans = report
        .hypotheses
        .iter()
        .filter_map(|hypothesis| {
            verification_planner::plan_for_hypothesis_with_history(
                hypothesis,
                &verification_scope,
                &verification_history,
            )
        })
        .collect();
    if args.execute_verification {
        let budget = verification_exec::ExecutionBudget {
            max_checks_per_run: args.verification_max_checks,
            ..verification_exec::ExecutionBudget::default()
        };
        report.verification_results = verification_exec::execute_plans(
            &report.verification_plans,
            &report.hosts,
            &verification_scope,
            &budget,
            &verification_exec::LocalRunner,
        );
        // Uceni selze tise jen v logu - nesmi shodit beh, ktery uz probehl.
        if let Err(error) = verification_exec::record_learning(
            &args.workspace,
            &report.verification_results,
            &case_memory,
        ) {
            tracing::warn!(%error, "zapis Case Memory / historie overeni selhal");
        }
    }
    report.summary.findings_total = report.findings.len();
    report.summary.audit_findings_total = report
        .findings
        .iter()
        .filter(|item| {
            item.finding_type.starts_with("greenbone_")
                || item.finding_type.starts_with("wazuh_")
                || item.finding_type.contains("config_issue")
        })
        .count();
    let validation_bundle = validation::build_validation_bundle(&report);
    report.monitoring_lanes.extend(validation_bundle.lanes);
    resort_and_recompute_lane_summary(&mut report);
    let consensus_snapshot = automation::build_consensus_snapshot(&report);
    report.summary.mas_consensus_score = consensus_snapshot.weighted_score;
    report.summary.mas_consensus_state = consensus_snapshot.state.clone();
    report.monitoring_lanes.push(MonitoringLane {
        lane_id: format!("lane:mas:consensus:{}", report.run.run_id),
        lane_type: "automation".to_string(),
        source: "mas-consensus".to_string(),
        title: "Confidence-weighted consensus".to_string(),
        status: if consensus_snapshot.state == "strong" {
            "ok".to_string()
        } else if consensus_snapshot.state == "review" {
            "limited".to_string()
        } else {
            "pending".to_string()
        },
        summary: format!(
            "Konsenzus followup/forensic/correlator = {:.0} % ({})",
            consensus_snapshot.weighted_score * 100.0,
            consensus_snapshot.state
        ),
        evidence: consensus_snapshot.evidence.clone(),
        recommended_tools: vec![
            "nmap".to_string(),
            "correlation".to_string(),
            "triage".to_string(),
        ],
    });
    report.triage_actions = triage::build_triage_actions(&report);
    report.triage_actions.extend(validation_bundle.actions);
    if consensus_snapshot.weighted_score < 0.55 {
        report.triage_actions.push(TriageAction {
            action_id: format!("action:mas-consensus-review:{}", report.run.run_id),
            action_type: "mas_consensus_review".to_string(),
            title: "Spustit manuální review nízkého MAS konsenzu".to_string(),
            priority: Severity::High,
            rationale: "Konsenzus mezi followup/forensic/correlator klesl pod bezpečný práh. Nejprve ověř přesnost identity služeb a forenzních důkazů.".to_string(),
            target_asset_id: None,
            target_service_key: None,
            recommended_tools: vec![
                "nmap-followup".to_string(),
                "nmap-forensic".to_string(),
                "diff".to_string(),
            ],
            evidence: consensus_snapshot.evidence.clone(),
        });
    }
    let decision_bundle = decision::build_decision_bundle(&report);
    report.triage_actions.extend(decision_bundle.actions);
    report.monitoring_lanes.extend(decision_bundle.lanes);
    report
        .triage_actions
        .sort_by(|left, right| right.priority.cmp(&left.priority));
    report
        .triage_actions
        .dedup_by(|left, right| left.action_id == right.action_id);
    report.summary.triage_actions_total = report.triage_actions.len();
    let automation_insights = automation::derive_insights(&report);
    report
        .monitoring_lanes
        .extend(automation_insights.agent_lanes.clone());
    resort_and_recompute_lane_summary(&mut report);
    report.summary.automation_agents_total = automation_insights.automation_agents_total;
    report.summary.automation_rounds_total = automation_insights.automation_rounds_total;
    report.summary.forensic_targets_total = automation_insights.forensic_targets_total;
    report.summary.realtime_sources_total = automation_insights.realtime_sources_total;
    report.summary.service_identity_high_confidence_total =
        automation_insights.service_identity_high_confidence_total;
    report.summary.service_identity_coverage_ratio =
        automation_insights.service_identity_coverage_ratio;
    report.summary.tooling_coverage_ratio = automation_insights.tooling_coverage_ratio;
    report.summary.mas_consensus_score = automation_insights.mas_consensus_score;
    report.summary.mas_consensus_state = automation_insights.mas_consensus_state;
    if args.hloubkove_overeni {
        let _ = automation::update_runtime_phase(
            &args.workspace,
            "finalize",
            "Report se finalizuje a ukládá do workspace.",
        );
    }

    workspace.save_run(
        &report,
        &RunArtifacts {
            nmap_path: &nmap_path,
            nmap_followup_path: followup_scan
                .as_ref()
                .map(|item| item.output_path.as_path()),
            nmap_forensic_path: forensic_scan
                .as_ref()
                .map(|item| item.output_path.as_path()),
            suricata_path: args.suricata_eve.as_deref(),
            zeek_dir: args.zeek_dir.as_deref(),
            httpx_output_jsonl: web_artifacts.httpx_output_jsonl.as_deref(),
            nuclei_output_jsonl: web_artifacts.nuclei_output_jsonl.as_deref(),
            pentest_output_jsonl: pentest_artifacts.output_jsonl.as_deref(),
            snmp_snapshot_json: context_bundle.artifacts.snmp_snapshot_json.as_deref(),
            librenms_snapshot_json: context_bundle.artifacts.librenms_snapshot_json.as_deref(),
            meraki_snapshot_json: context_bundle.artifacts.meraki_snapshot_json.as_deref(),
            unifi_snapshot_json: context_bundle.artifacts.unifi_snapshot_json.as_deref(),
            aruba_snapshot_json: context_bundle.artifacts.aruba_snapshot_json.as_deref(),
            omada_snapshot_json: context_bundle.artifacts.omada_snapshot_json.as_deref(),
            ntopng_json: lane_bundle.artifacts.ntopng_json.as_deref(),
            flow_json: lane_bundle.artifacts.flow_json.as_deref(),
            greenbone_json: lane_bundle.artifacts.greenbone_json.as_deref(),
            wazuh_json: lane_bundle.artifacts.wazuh_json.as_deref(),
            napalm_json: lane_bundle.artifacts.napalm_json.as_deref(),
            netmiko_json: lane_bundle.artifacts.netmiko_json.as_deref(),
            scrapli_json: lane_bundle.artifacts.scrapli_json.as_deref(),
        },
    )?;
    workspace.enforce_retention(app_config.retention.max_runs, app_config.retention.keep_raw)?;
    // Kurzory se posouvaji AZ po uspesnem ulozeni behu (at-least-once).
    pending_ingest.commit(&args.workspace)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::*;

    /// Retrospektivni audit (2 nezavisle haiku review, 29.10.2026) spravne
    /// odhalil, ze golden-snapshot test NEPOKRYVA chybove vetve
    /// `validate_pipeline_args`/`validate_monitor_args` (fixtura je vzdy
    /// platna) - golden pouziva jen `--pentest`/`--production`/vadne cesty
    /// NIKDY. Tyhle testy to zavirajin primo, bez nutnosti spoustet cely
    /// binary pipeline.
    fn minimal_valid_args(nmap_xml: &Path) -> BehArgs {
        BehArgs {
            workspace: PathBuf::from("."),
            nazev: "test".to_string(),
            scope: vec!["192.168.1.0/24".parse().expect("scope")],
            ports: vec![80],
            profile: "bezny".to_string(),
            provider: "demo".to_string(),
            nmap_xml: Some(nmap_xml.to_path_buf()),
            ..Default::default()
        }
    }

    #[test]
    fn validate_pipeline_args_rejects_empty_scope() {
        let nmap = NamedTempFile::new().expect("tempfile");
        let mut args = minimal_valid_args(nmap.path());
        args.scope.clear();

        let error = validate_pipeline_args(&args).expect_err("prazdny scope musi selhat");
        assert!(error.to_string().contains("--scope"));
    }

    #[test]
    fn validate_pipeline_args_rejects_missing_nmap_source() {
        let mut args = minimal_valid_args(Path::new("irrelevant.xml"));
        args.nmap_xml = None;
        args.spustit_nmap = false;

        let error = validate_pipeline_args(&args).expect_err("bez --nmap-xml i --spustit-nmap");
        assert!(
            error.to_string().contains("--nmap-xml")
                || error.to_string().contains("--spustit-nmap")
        );
    }

    #[test]
    fn validate_pipeline_args_rejects_live_nmap_with_no_ports() {
        let mut args = minimal_valid_args(Path::new("irrelevant.xml"));
        args.nmap_xml = None;
        args.spustit_nmap = true;
        args.ports.clear();

        let error = validate_pipeline_args(&args).expect_err("--spustit-nmap bez portu");
        assert!(error.to_string().contains("--ports"));
    }

    #[test]
    fn validate_pipeline_args_rejects_nonexistent_nmap_xml_path() {
        let args = minimal_valid_args(Path::new("this/path/does/not/exist.xml"));

        let error = validate_pipeline_args(&args).expect_err("neexistujici --nmap-xml");
        assert!(error.to_string().contains("--nmap-xml"));
    }

    #[test]
    fn validate_pipeline_args_rejects_nonexistent_zeek_dir() {
        let nmap = NamedTempFile::new().expect("tempfile");
        let mut args = minimal_valid_args(nmap.path());
        args.zeek_dir = Some(PathBuf::from("this/dir/does/not/exist"));

        let error = validate_pipeline_args(&args).expect_err("neexistujici --zeek-dir");
        assert!(error.to_string().contains("--zeek-dir"));
    }

    #[test]
    fn validate_pipeline_args_rejects_production_without_passive_telemetry() {
        let nmap = NamedTempFile::new().expect("tempfile");
        let mut args = minimal_valid_args(nmap.path());
        args.production = true;
        // Vedome bez suricata_eve/zeek_dir.

        let error = validate_pipeline_args(&args).expect_err("--production bez pasivniho zdroje");
        assert!(error.to_string().contains("pasiv"));
    }

    #[test]
    fn validate_pipeline_args_accepts_minimal_valid_combination() {
        let nmap = NamedTempFile::new().expect("tempfile");
        let args = minimal_valid_args(nmap.path());

        validate_pipeline_args(&args).expect("minimalni platna kombinace musi projit");
    }

    #[test]
    fn validate_monitor_args_rejects_missing_passive_telemetry() {
        let nmap = NamedTempFile::new().expect("tempfile");
        let args = minimal_valid_args(nmap.path());

        let error = validate_monitor_args(&args).expect_err("monitor bez pasivniho zdroje");
        assert!(
            error.to_string().contains("--suricata-eve")
                || error.to_string().contains("--zeek-dir")
        );
    }

    #[test]
    fn validate_monitor_args_accepts_suricata_source() {
        let nmap = NamedTempFile::new().expect("tempfile");
        let suricata = NamedTempFile::new().expect("tempfile");
        let mut args = minimal_valid_args(nmap.path());
        args.suricata_eve = Some(suricata.path().to_path_buf());

        validate_monitor_args(&args).expect("suricata_eve staci na pasivni telemetrii");
    }

    #[test]
    fn has_passive_telemetry_is_false_without_any_source() {
        let args = BehArgs::default();
        assert!(!has_passive_telemetry(&args));
    }

    #[test]
    fn has_passive_telemetry_is_true_with_zeek_dir_only() {
        let mut args = BehArgs::default();
        args.zeek_dir = Some(PathBuf::from("."));
        assert!(has_passive_telemetry(&args));
    }

    /// `apply_production_profile` je jen volana skrz `prepare_pipeline_args`,
    /// nikdy neni primo testovana - ověřuje VŠECH 5 vedlejsich ucinku najednou
    /// (ne jen jeden nahodny), protoze golden-snapshot test `--production`
    /// vubec nepouziva.
    #[test]
    fn prepare_pipeline_args_production_flag_applies_all_production_defaults() {
        let nmap = NamedTempFile::new().expect("tempfile");
        let suricata = NamedTempFile::new().expect("tempfile");
        let mut args = minimal_valid_args(nmap.path());
        args.production = true;
        args.suricata_eve = Some(suricata.path().to_path_buf());
        args.nmap_xml = None;
        args.spustit_nmap = false;
        // Audit nalez (haiku, 30.10.2026): `..Default::default()` v
        // `minimal_valid_args` uz davalo `disable_circl=false`, takze puvodni
        // `assert!(!prepared.disable_circl)` by prosel i kdyby
        // `apply_production_profile`'s `args.disable_circl = false;` (radek
        // vyse v tomhle souboru) zmizel - test nic neoveroval. Nastaveno na
        // `true` predem, aby assert skutecne testoval vedlejsi ucinek.
        args.disable_circl = true;

        let prepared = prepare_pipeline_args(args).expect("platna produkcni kombinace");

        assert!(
            prepared.spustit_nmap,
            "bez --nmap-xml musi --production zapnout --spustit-nmap"
        );
        assert_eq!(
            prepared.provider, "public",
            "--production s provider=demo musi prepnout na public"
        );
        assert!(prepared.hloubkove_overeni);
        assert!(prepared.pentest);
        assert!(!prepared.disable_circl);
        assert!(
            prepared.supplement_vulners,
            "provider=public (po prepnuti) musi zapnout supplement_vulners pres auto_enable_vulners"
        );
    }

    #[test]
    fn prepare_pipeline_args_aggressive_pentest_implies_pentest() {
        let nmap = NamedTempFile::new().expect("tempfile");
        let mut args = minimal_valid_args(nmap.path());
        args.aggressive_pentest = true;
        assert!(!args.pentest, "test predpoklad: pentest zatim vypnuty");

        let prepared = prepare_pipeline_args(args).expect("platna kombinace");

        assert!(
            prepared.pentest,
            "--aggressive-pentest musi implikovat --pentest"
        );
    }

    #[test]
    fn auto_enable_vulners_sets_flag_for_intel_providers_only() {
        for provider in ["nvd", "public", "auto"] {
            let mut args = BehArgs {
                provider: provider.to_string(),
                ..Default::default()
            };
            auto_enable_vulners(&mut args);
            assert!(
                args.supplement_vulners,
                "provider {provider} musi zapnout supplement_vulners"
            );
        }

        let mut demo_args = BehArgs {
            provider: "demo".to_string(),
            ..Default::default()
        };
        auto_enable_vulners(&mut demo_args);
        assert!(
            !demo_args.supplement_vulners,
            "provider demo nesmi zapnout supplement_vulners"
        );
    }
}
