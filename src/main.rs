use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use bakula_program::{
    ai, automation, broker, config, evaluation,
    model::{AppConfig, RunReport},
    pipeline::{
        BehArgs, promote_autopilot_args, promote_monitor_args, resolve_simulation_profile,
        run_pipeline, validate_monitor_args,
    },
    platform, readiness, server, simulation, verification,
};
use clap::{Args, Parser, Subcommand};
use ipnet::IpNet;

#[derive(Parser, Debug)]
#[command(
    name = "bakula",
    version,
    about = "Bakula - korelace aktivniho a pasivniho pohledu na sit."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(subcommand)]
    Simulace(SimulaceCommand),
    #[command(subcommand)]
    Beh(BehCommand),
    #[command(subcommand)]
    Autopilot(AutopilotCommand),
    #[command(subcommand)]
    Monitor(MonitorCommand),
    #[command(subcommand)]
    Overeni(OvereniCommand),
    #[command(subcommand)]
    Evaluace(EvaluaceCommand),
    #[command(subcommand)]
    Server(ServerCommand),
    #[command(subcommand)]
    Config(ConfigCommand),
    #[command(subcommand)]
    Ai(AiCommand),
    Readiness(ReadinessArgs),
    #[command(subcommand)]
    Platform(PlatformCommand),
    #[command(subcommand)]
    Broker(BrokerCommand),
    #[command(subcommand)]
    Demo(DemoCommand),
}

#[derive(Subcommand, Debug)]
enum SimulaceCommand {
    Generuj(SimulaceArgs),
}

#[derive(Args, Debug)]
struct SimulaceArgs {
    #[arg(long)]
    vystup: PathBuf,
    #[arg(long, default_value_t = 7)]
    seed: u64,
    #[arg(long, default_value_t = 0)]
    nahodnych: usize,
    #[arg(long, default_value = "standard")]
    profil: String,
    #[arg(long)]
    extra_hostu: Option<usize>,
    #[arg(long)]
    max_sluzeb_na_host: Option<usize>,
    #[arg(long)]
    telemetrie_na_host: Option<usize>,
    #[arg(long)]
    flow_repetitions: Option<usize>,
}

#[derive(Subcommand, Debug)]
enum BehCommand {
    Spust(BehArgs),
}

#[derive(Subcommand, Debug)]
enum AutopilotCommand {
    Spust(AutopilotArgs),
}

#[derive(Args, Debug, Clone)]
struct AutopilotArgs {
    #[command(flatten)]
    run: BehArgs,
    #[arg(long, default_value_t = 2)]
    cycles: usize,
    #[arg(long, default_value_t = 0)]
    interval_s: u64,
}

#[derive(Subcommand, Debug)]
enum MonitorCommand {
    Spust(MonitorArgs),
}

#[derive(Args, Debug, Clone)]
struct MonitorArgs {
    #[command(flatten)]
    run: BehArgs,
    #[arg(long, default_value_t = 1)]
    cycles: usize,
    #[arg(long, default_value_t = 60)]
    interval_s: u64,
    #[arg(long, default_value_t = false)]
    continuous: bool,
}

#[derive(Subcommand, Debug)]
enum OvereniCommand {
    Spust(OvereniArgs),
}

#[derive(Args, Debug)]
struct OvereniArgs {
    #[arg(long)]
    workspace: PathBuf,
    #[arg(long)]
    scenare: PathBuf,
    #[arg(long, default_value = "demo")]
    provider: String,
    #[arg(long, default_value_t = false)]
    freeze: bool,
}

#[derive(Subcommand, Debug)]
enum EvaluaceCommand {
    Spust(EvaluaceArgs),
}

#[derive(Args, Debug)]
struct EvaluaceArgs {
    #[arg(long)]
    workspace: PathBuf,
    #[arg(long)]
    scenare: Option<PathBuf>,
    #[arg(long, default_value_t = 17)]
    seed: u64,
    #[arg(long, default_value_t = 120)]
    nahodnych: usize,
    #[arg(long, default_value_t = 8)]
    workers: usize,
    #[arg(long, default_value = "demo")]
    provider: String,
    #[arg(long, default_value_t = false)]
    freeze: bool,
    #[arg(long, default_value = "standard")]
    profil: String,
    #[arg(long)]
    extra_hostu: Option<usize>,
    #[arg(long)]
    max_sluzeb_na_host: Option<usize>,
    #[arg(long)]
    telemetrie_na_host: Option<usize>,
    #[arg(long)]
    flow_repetitions: Option<usize>,
}

#[derive(Subcommand, Debug)]
enum ServerCommand {
    Spust(ServerArgs),
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
    Init(ConfigArgs),
    Validate(ConfigArgs),
}

#[derive(Subcommand, Debug)]
enum AiCommand {
    Diagnostika,
    Setup(AiSetupArgs),
    Modelfile(AiModelfileArgs),
    Test(AiTestArgs),
}

#[derive(Args, Debug)]
struct AiSetupArgs {
    #[arg(long, default_value_t = false)]
    pull: bool,
    #[arg(long, default_value = "models/skoky/Modelfile")]
    modelfile: PathBuf,
}

#[derive(Args, Debug)]
struct AiModelfileArgs {
    #[arg(long, default_value = "models/skoky/Modelfile")]
    vystup: PathBuf,
}

#[derive(Args, Debug)]
struct AiTestArgs {
    #[arg(long, default_value = "Co mám řešit jako první a proč?")]
    prompt: String,
}

#[derive(Args, Debug)]
struct ReadinessArgs {
    #[arg(long)]
    workspace: PathBuf,
    #[arg(long, default_value_t = false)]
    require_api_token: bool,
}

#[derive(Args, Debug)]
struct ConfigArgs {
    #[arg(long, default_value = "bakula.toml")]
    path: PathBuf,
}

#[derive(Args, Debug)]
struct ServerArgs {
    #[arg(long)]
    workspace: PathBuf,
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 8080)]
    port: u16,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    api_token_env: Option<String>,
    #[arg(long, default_value_t = false)]
    require_api_token: bool,
}

#[derive(Subcommand, Debug)]
enum DemoCommand {
    E2e(DemoArgs),
}

#[derive(Subcommand, Debug)]
enum BrokerCommand {
    PublishDue(BrokerPublishArgs),
    WorkerRun(BrokerWorkerArgs),
}

#[derive(Subcommand, Debug)]
enum PlatformCommand {
    Init(PlatformInitArgs),
    #[command(subcommand)]
    User(PlatformUserCommand),
    #[command(subcommand)]
    Token(PlatformTokenCommand),
    #[command(subcommand)]
    Job(PlatformJobCommand),
    #[command(subcommand)]
    Worker(PlatformWorkerCommand),
    #[command(subcommand)]
    Ha(PlatformHaCommand),
    Status(PlatformStatusArgs),
}

#[derive(Args, Debug)]
struct PlatformInitArgs {
    #[arg(long)]
    db: PathBuf,
}

#[derive(Subcommand, Debug)]
enum PlatformUserCommand {
    Add(PlatformUserAddArgs),
    List(PlatformDbArgs),
}

#[derive(Args, Debug)]
struct PlatformUserAddArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    username: String,
    #[arg(long)]
    role: String,
}

#[derive(Subcommand, Debug)]
enum PlatformTokenCommand {
    Issue(PlatformTokenIssueArgs),
}

#[derive(Args, Debug)]
struct PlatformTokenIssueArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    username: String,
    #[arg(long)]
    name: String,
    /// Zivotnost tokenu ve dnech; `0` = nikdy nevyprsi (vedomy opt-out).
    #[arg(long, default_value_t = platform::DEFAULT_TOKEN_TTL_DAYS)]
    ttl_days: i64,
}

#[derive(Subcommand, Debug)]
enum PlatformJobCommand {
    EnqueueScenario(PlatformJobScenarioArgs),
    List(PlatformDbArgs),
}

#[derive(Args, Debug)]
struct PlatformJobScenarioArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    workspace: PathBuf,
    #[arg(long)]
    scenario_dir: PathBuf,
    #[arg(long)]
    nazev: String,
    #[arg(long, value_delimiter = ',')]
    scope: Vec<IpNet>,
    #[arg(long, value_delimiter = ',', default_value = "21,22,23,80,443,8080")]
    ports: Vec<u16>,
    #[arg(long, default_value = "bezny")]
    profile: String,
    #[arg(long, default_value = "demo")]
    provider: String,
    #[arg(long)]
    schedule_interval_s: Option<i64>,
    #[arg(long)]
    broker_uri: Option<String>,
}

#[derive(Subcommand, Debug)]
enum PlatformWorkerCommand {
    Run(PlatformWorkerArgs),
}

#[derive(Subcommand, Debug)]
enum PlatformHaCommand {
    SetPolicy(PlatformHaPolicyArgs),
    RegisterNode(PlatformHaRegisterNodeArgs),
    MarkReady(PlatformHaMarkReadyArgs),
    Plan(PlatformDbArgs),
    Advance(PlatformDbArgs),
}

#[derive(Args, Debug)]
struct PlatformWorkerArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    node_id: String,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(long, default_value_t = 30)]
    leader_ttl_s: i64,
    #[arg(long, default_value_t = 120)]
    job_lease_s: i64,
    #[arg(long, default_value_t = false)]
    once: bool,
    #[arg(long)]
    broker_uri: Option<String>,
}

#[derive(Args, Debug)]
struct PlatformStatusArgs {
    #[arg(long)]
    db: PathBuf,
}

#[derive(Args, Debug)]
struct PlatformDbArgs {
    #[arg(long)]
    db: PathBuf,
}

#[derive(Args, Debug)]
struct PlatformHaPolicyArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    quorum: i64,
    #[arg(long)]
    min_ready: i64,
    #[arg(long, default_value_t = 1)]
    batch_size: i64,
    #[arg(long)]
    target_version: Option<String>,
}

#[derive(Args, Debug)]
struct PlatformHaRegisterNodeArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    node_id: String,
    #[arg(long)]
    display_name: Option<String>,
    #[arg(long)]
    version: String,
    #[arg(long, default_value_t = true)]
    ready: bool,
}

#[derive(Args, Debug)]
struct PlatformHaMarkReadyArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    node_id: String,
    #[arg(long)]
    version: String,
}

#[derive(Args, Debug)]
struct BrokerPublishArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    broker_uri: String,
    /// Prepis vychozi "bakula.jobs" - umoznuje izolovane fronty (napr. testy se
    /// 2 oddelenymi OS procesy proti stejnemu Redisu, aniz by se potkaly s jinou praci).
    #[arg(long, default_value = "bakula.jobs")]
    stream_key: String,
}

#[derive(Args, Debug)]
struct BrokerWorkerArgs {
    #[arg(long)]
    db: PathBuf,
    #[arg(long)]
    broker_uri: String,
    #[arg(long)]
    node_id: String,
    #[arg(long, default_value_t = 120)]
    lease_s: i64,
    /// Viz `BrokerPublishArgs::stream_key`.
    #[arg(long, default_value = "bakula.jobs")]
    stream_key: String,
}

#[derive(Args, Debug)]
struct DemoArgs {
    #[arg(long)]
    workspace: PathBuf,
}

fn main() -> anyhow::Result<()> {
    bakula_program::logging::init();
    let cli = Cli::parse();
    match cli.command {
        Command::Simulace(SimulaceCommand::Generuj(args)) => {
            let profile = resolve_simulation_profile(
                &args.profil,
                args.extra_hostu,
                args.max_sluzeb_na_host,
                args.telemetrie_na_host,
                args.flow_repetitions,
            )?;
            simulation::generate_simulation_with_profile(
                &args.vystup,
                args.seed,
                args.nahodnych,
                &profile,
            )?;
            println!(
                "Simulacni prostredi bylo vygenerovano do: {}",
                args.vystup.display()
            );
        }
        Command::Beh(BehCommand::Spust(args)) => {
            let report = run_pipeline(args)?;
            println!(
                "Beh {} dokoncen. Report: {}",
                report.run.run_id,
                Path::new(&report.run.run_id).display()
            );
        }
        Command::Autopilot(AutopilotCommand::Spust(args)) => {
            let automation_report = run_autopilot(args)?;
            println!(
                "Autopilot dokoncen. Cykly={} coverage={:.2} identity={:.2}",
                automation_report.summary.cycles_total,
                automation_report.summary.tooling_coverage_ratio,
                automation_report.summary.service_identity_coverage_ratio
            );
        }
        Command::Monitor(MonitorCommand::Spust(args)) => {
            let continuous = args.continuous;
            let reports = run_monitor(args)?;
            if !continuous {
                println!("Monitor jsem dokoncil. Cykly={}", reports.len());
            }
        }
        Command::Overeni(OvereniCommand::Spust(args)) => {
            let verification_report = run_verification(args)?;
            println!(
                "Overeni dokonceno. Proslo {}/{} scenaru.",
                verification_report.summary.passed, verification_report.summary.total
            );
        }
        Command::Evaluace(EvaluaceCommand::Spust(args)) => {
            let evaluation_report = run_evaluation(args)?;
            println!(
                "Evaluace dokoncena. Precision {:.2}, recall {:.2}, F1 {:.2}, scenare {}/{}.",
                evaluation_report.summary.core_precision,
                evaluation_report.summary.core_recall,
                evaluation_report.summary.core_f1,
                evaluation_report.summary.scenarios_passed,
                evaluation_report.summary.scenarios_total
            );
        }
        Command::Server(ServerCommand::Spust(args)) => {
            let config_path = args
                .config
                .clone()
                .unwrap_or_else(|| args.workspace.join("bakula.toml"));
            let mut config = config::load_or_default(&config_path)?;
            config.workspace_root = args.workspace.to_string_lossy().to_string();
            config.host = args.host;
            config.port = args.port;
            if let Some(api_token_env) = args.api_token_env {
                config.security.api_token_env = Some(api_token_env);
            }
            if args.require_api_token {
                config.security.require_api_token = true;
            }
            config::validate(&config)?;
            let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(server::serve_with_config(addr, config))?;
        }
        Command::Ai(AiCommand::Diagnostika) => {
            println!("{}", serde_json::to_string_pretty(&ai::diagnose())?);
        }
        Command::Ai(AiCommand::Setup(args)) => {
            let diagnostic = ai::setup_ollama_model(&args.modelfile, args.pull)?;
            println!("{}", serde_json::to_string_pretty(&diagnostic)?);
        }
        Command::Ai(AiCommand::Modelfile(args)) => {
            let path = ai::write_modelfile(&args.vystup)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "modelfile": path,
                    "model": ai::SKOKY_MODEL,
                    "base_model": ai::SKOKY_BASE_MODEL
                }))?
            );
        }
        Command::Ai(AiCommand::Test(args)) => {
            let answer = ai::smoke_prompt(&args.prompt)?;
            println!("{answer}");
        }
        Command::Readiness(args) => {
            let report = readiness::assess_workspace(&args.workspace, args.require_api_token)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Config(ConfigCommand::Init(args)) => {
            let config = config::load_or_default(&args.path)?;
            println!(
                "Konfigurace je pripravena v {} (workspace_root={}, auth_required={}, max_runs={}).",
                args.path.display(),
                config.workspace_root,
                config.security.require_api_token,
                config.retention.max_runs
            );
        }
        Command::Config(ConfigCommand::Validate(args)) => {
            let config = config::load_or_default(&args.path)?;
            config::validate(&config)?;
            println!(
                "Konfigurace je validni: workspace_root={}, host={}, port={}, auth_required={}, max_runs={}, keep_raw={}.",
                config.workspace_root,
                config.host,
                config.port,
                config.security.require_api_token,
                config.retention.max_runs,
                config.retention.keep_raw
            );
        }
        Command::Platform(PlatformCommand::Init(args)) => {
            platform::init_database(&args.db)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "db": args.db,
                    "initialized": true
                }))?
            );
        }
        Command::Platform(PlatformCommand::User(PlatformUserCommand::Add(args))) => {
            platform::init_database(&args.db)?;
            let role = platform::Role::parse(&args.role)?;
            let user = platform::create_or_update_user(&args.db, &args.username, role)?;
            println!("{}", serde_json::to_string_pretty(&user)?);
        }
        Command::Platform(PlatformCommand::User(PlatformUserCommand::List(args))) => {
            let users = platform::list_users(&args.db)?;
            println!("{}", serde_json::to_string_pretty(&users)?);
        }
        Command::Platform(PlatformCommand::Token(PlatformTokenCommand::Issue(args))) => {
            platform::init_database(&args.db)?;
            let token = platform::issue_token_with_ttl(
                &args.db,
                &args.username,
                &args.name,
                Some(args.ttl_days),
            )?;
            println!("{}", serde_json::to_string_pretty(&token)?);
        }
        Command::Platform(PlatformCommand::Job(PlatformJobCommand::EnqueueScenario(args))) => {
            platform::init_database(&args.db)?;
            let spec = build_scenario_job_spec(&args)?;
            let job_id = platform::enqueue_job(
                &args.db,
                &args.nazev,
                &spec,
                args.schedule_interval_s,
                None,
            )?;
            if let Some(broker_uri) = &args.broker_uri {
                let broker_config = broker::RedisBrokerConfig::for_uri(broker_uri);
                broker::ensure_group(&broker_config)?;
                let _ = broker::publish_job(&broker_config, job_id)?;
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "job_id": job_id,
                    "name": args.nazev,
                    "scheduled": args.schedule_interval_s.is_some(),
                }))?
            );
        }
        Command::Platform(PlatformCommand::Job(PlatformJobCommand::List(args))) => {
            let jobs = platform::list_jobs(&args.db)?;
            println!("{}", serde_json::to_string_pretty(&jobs)?);
        }
        Command::Platform(PlatformCommand::Worker(PlatformWorkerCommand::Run(args))) => {
            platform::init_database(&args.db)?;
            let display_name = args
                .display_name
                .clone()
                .unwrap_or_else(|| args.node_id.clone());
            let capabilities = vec![
                "pipeline".to_string(),
                "scheduler".to_string(),
                "cluster-lease".to_string(),
            ];
            if let Some(broker_uri) = &args.broker_uri {
                let broker_config = broker::RedisBrokerConfig::for_uri(broker_uri);
                platform::upsert_node_heartbeat(
                    &args.db,
                    &args.node_id,
                    &display_name,
                    &capabilities,
                )?;
                // min_idle_ms pro XAUTOCLAIM navazany na job_lease_s (Deliverable 24,
                // produkcni-plan.md) - drive hardcoded 30_000 bez ohledu na
                // konfigurovany lease, takze reclaim stale zpravy mohl probehnout
                // driv/pozdeji, nez sama platform.rs lease skutecne vyprsela.
                let min_idle_ms = (args.job_lease_s.max(0) as usize).saturating_mul(1000);
                let message = broker::claim_one(&broker_config, &args.node_id, 500, min_idle_ms)?;
                let run_id = if let Some(message) = message {
                    if let Some(job) = platform::claim_job_by_id(
                        &args.db,
                        message.job_id,
                        &args.node_id,
                        args.job_lease_s,
                    )? {
                        match run_pipeline(spec_to_beh_args(job.spec)?) {
                            Ok(report) => {
                                let fenced = platform::mark_job_succeeded(
                                    &args.db,
                                    job.id,
                                    &args.node_id,
                                    &report.run.run_id,
                                    job.schedule_interval_s,
                                )?;
                                if !fenced {
                                    eprintln!(
                                        "Job {} dobehl uspesne, ale jeho lease uz drzi jiny worker - vysledek {} se nezapsal",
                                        job.id, report.run.run_id
                                    );
                                }
                                broker::ack(&broker_config, &message.stream_id)?;
                                Some(report.run.run_id)
                            }
                            Err(error) => {
                                let fenced = platform::mark_job_failed(
                                    &args.db,
                                    job.id,
                                    &args.node_id,
                                    &error.to_string(),
                                    job.schedule_interval_s,
                                )?;
                                if !fenced {
                                    eprintln!(
                                        "Job {} selhal, ale jeho lease uz drzi jiny worker - chybovy stav se nezapsal",
                                        job.id
                                    );
                                }
                                broker::ack(&broker_config, &message.stream_id)?;
                                return Err(error);
                            }
                        }
                    } else {
                        broker::ack(&broker_config, &message.stream_id)?;
                        None
                    }
                } else {
                    None
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "node_id": args.node_id,
                        "run_id": run_id,
                        "broker_mode": true,
                    }))?
                );
            } else if args.once {
                let result = platform::worker_cycle(
                    &args.db,
                    &args.node_id,
                    &display_name,
                    &capabilities,
                    args.leader_ttl_s,
                    args.job_lease_s,
                    |spec| {
                        let args = spec_to_beh_args(spec).map_err(|error| error.to_string())?;
                        run_pipeline(args)
                            .map(|report| report.run.run_id)
                            .map_err(|error| error.to_string())
                    },
                )?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "node_id": args.node_id,
                        "run_id": result,
                    }))?
                );
            } else {
                platform::worker_loop(
                    &args.db,
                    &args.node_id,
                    &display_name,
                    &capabilities,
                    args.leader_ttl_s,
                    args.job_lease_s,
                    |spec| {
                        let args = spec_to_beh_args(spec).map_err(|error| error.to_string())?;
                        run_pipeline(args)
                            .map(|report| report.run.run_id)
                            .map_err(|error| error.to_string())
                    },
                    Duration::from_secs(5),
                );
            }
        }
        Command::Platform(PlatformCommand::Ha(PlatformHaCommand::SetPolicy(args))) => {
            platform::init_database(&args.db)?;
            let policy = platform::set_ha_policy(
                &args.db,
                args.quorum,
                args.min_ready,
                args.batch_size,
                args.target_version.as_deref(),
            )?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
        }
        Command::Platform(PlatformCommand::Ha(PlatformHaCommand::RegisterNode(args))) => {
            platform::init_database(&args.db)?;
            let display_name = args
                .display_name
                .clone()
                .unwrap_or_else(|| args.node_id.clone());
            let node = platform::register_managed_node(
                &args.db,
                &args.node_id,
                &display_name,
                &["scheduler".to_string(), "worker".to_string()],
                &args.version,
                args.ready,
            )?;
            println!("{}", serde_json::to_string_pretty(&node)?);
        }
        Command::Platform(PlatformCommand::Ha(PlatformHaCommand::MarkReady(args))) => {
            let node = platform::mark_node_ready(&args.db, &args.node_id, &args.version)?;
            println!("{}", serde_json::to_string_pretty(&node)?);
        }
        Command::Platform(PlatformCommand::Ha(PlatformHaCommand::Plan(args))) => {
            let status = platform::ha_status(&args.db, None)?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        Command::Platform(PlatformCommand::Ha(PlatformHaCommand::Advance(args))) => {
            let selected = platform::advance_rollout(&args.db)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "selected": selected
                }))?
            );
        }
        Command::Platform(PlatformCommand::Status(args)) => {
            let snapshot = platform::snapshot(&args.db)?;
            println!("{}", serde_json::to_string_pretty(&snapshot)?);
        }
        Command::Broker(BrokerCommand::PublishDue(args)) => {
            let mut config = broker::RedisBrokerConfig::for_uri(&args.broker_uri);
            config.stream_key = args.stream_key.clone();
            let published = broker::publish_due_jobs(&config, &args.db)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "published_job_ids": published,
                }))?
            );
        }
        Command::Broker(BrokerCommand::WorkerRun(args)) => {
            let mut config = broker::RedisBrokerConfig::for_uri(&args.broker_uri);
            config.stream_key = args.stream_key.clone();
            // min_idle_ms navazany na --lease-s (drive hardcoded 30_000, args.lease_s
            // existoval, ale nebyl pro tohle vubec pouzit - Deliverable 24).
            let min_idle_ms = (args.lease_s.max(0) as usize).saturating_mul(1000);
            let message = broker::claim_one(&config, &args.node_id, 500, min_idle_ms)?;
            println!("{}", serde_json::to_string_pretty(&message)?);
        }
        Command::Demo(DemoCommand::E2e(args)) => {
            let sim_dir = args.workspace.join("simulace");
            simulation::generate_simulation(&sim_dir, 7, 0)?;

            let baseline = run_pipeline(BehArgs {
                workspace: args.workspace.clone(),
                nazev: "Zakladni scenar".to_string(),
                scope: vec!["192.168.56.0/24".parse()?],
                ports: vec![21, 22, 23, 80, 443, 8080],
                profile: "demo".to_string(),
                provider: "demo".to_string(),
                supplement_vulners: false,
                freeze: false,
                production: false,
                nmap_xml: Some(sim_dir.join("zakladni").join("nmap.xml")),
                nmap_followup_xml: None,
                suricata_eve: Some(sim_dir.join("zakladni").join("suricata").join("eve.json")),
                zeek_dir: Some(sim_dir.join("zakladni").join("zeek")),
                porovnat_s: None,
                spustit_nmap: false,
                hloubkove_overeni: false,
                web_fingerprint: false,
                web_checks: false,
                execute_verification: false,
                incremental_ingest: false,
                verification_max_checks: 10,
                pentest: false,
                aggressive_pentest: false,
                httpx_bin: None,
                nuclei_bin: None,
                nuclei_templates: None,
                snmp_snapshot: None,
                librenms_snapshot: None,
                librenms_base_url: None,
                librenms_token_env: "LIBRENMS_TOKEN".to_string(),
                meraki_snapshot: None,
                meraki_network_id: None,
                meraki_api_key_env: "MERAKI_DASHBOARD_API_KEY".to_string(),
                meraki_timespan_seconds: 86400,
                unifi_snapshot: None,
                unifi_devices_url: None,
                unifi_clients_url: None,
                unifi_links_url: None,
                unifi_api_key_env: "UNIFI_API_KEY".to_string(),
                aruba_snapshot: None,
                aruba_base_url: None,
                aruba_token_env: "ARUBA_CENTRAL_TOKEN".to_string(),
                aruba_site_id: None,
                omada_snapshot: None,
                omada_devices_url: None,
                omada_clients_url: None,
                omada_links_url: None,
                omada_access_token_env: "OMADA_ACCESS_TOKEN".to_string(),
                ntopng_snapshot: None,
                flow_snapshot: None,
                greenbone_report: None,
                wazuh_report: None,
                napalm_snapshot: None,
                netmiko_snapshot: None,
                scrapli_snapshot: None,
                urlhaus_auth_env: "URLHAUS_AUTH_KEY".to_string(),
                abuseipdb_key_env: "ABUSEIPDB_API_KEY".to_string(),
                disable_circl: true,
            })?;

            let changed = run_pipeline(BehArgs {
                workspace: args.workspace.clone(),
                nazev: "Zmenovy scenar".to_string(),
                scope: vec!["192.168.56.0/24".parse()?],
                ports: vec![21, 22, 23, 80, 443, 8080],
                profile: "demo".to_string(),
                provider: "demo".to_string(),
                supplement_vulners: false,
                freeze: false,
                production: false,
                nmap_xml: Some(sim_dir.join("zmena").join("nmap.xml")),
                nmap_followup_xml: None,
                suricata_eve: Some(sim_dir.join("zmena").join("suricata").join("eve.json")),
                zeek_dir: Some(sim_dir.join("zmena").join("zeek")),
                porovnat_s: Some(baseline.run.run_id.clone()),
                spustit_nmap: false,
                hloubkove_overeni: false,
                web_fingerprint: false,
                web_checks: false,
                execute_verification: false,
                incremental_ingest: false,
                verification_max_checks: 10,
                pentest: false,
                aggressive_pentest: false,
                httpx_bin: None,
                nuclei_bin: None,
                nuclei_templates: None,
                snmp_snapshot: None,
                librenms_snapshot: None,
                librenms_base_url: None,
                librenms_token_env: "LIBRENMS_TOKEN".to_string(),
                meraki_snapshot: None,
                meraki_network_id: None,
                meraki_api_key_env: "MERAKI_DASHBOARD_API_KEY".to_string(),
                meraki_timespan_seconds: 86400,
                unifi_snapshot: None,
                unifi_devices_url: None,
                unifi_clients_url: None,
                unifi_links_url: None,
                unifi_api_key_env: "UNIFI_API_KEY".to_string(),
                aruba_snapshot: None,
                aruba_base_url: None,
                aruba_token_env: "ARUBA_CENTRAL_TOKEN".to_string(),
                aruba_site_id: None,
                omada_snapshot: None,
                omada_devices_url: None,
                omada_clients_url: None,
                omada_links_url: None,
                omada_access_token_env: "OMADA_ACCESS_TOKEN".to_string(),
                ntopng_snapshot: None,
                flow_snapshot: None,
                greenbone_report: None,
                wazuh_report: None,
                napalm_snapshot: None,
                netmiko_snapshot: None,
                scrapli_snapshot: None,
                urlhaus_auth_env: "URLHAUS_AUTH_KEY".to_string(),
                abuseipdb_key_env: "ABUSEIPDB_API_KEY".to_string(),
                disable_circl: true,
            })?;

            println!("Demo E2E hotovo.");
            println!("Zakladni run_id: {}", baseline.run.run_id);
            println!("Zmenovy run_id:  {}", changed.run.run_id);
            println!(
                "Spusteni UI: {} server spust --workspace {}",
                current_exe_invocation(),
                args.workspace.display()
            );
        }
    }

    Ok(())
}

fn current_exe_invocation() -> String {
    env::current_exe()
        .map(|path| format!("\"{}\"", path.display()))
        .unwrap_or_else(|_| "bakula-program.exe".to_string())
}

fn run_autopilot(args: AutopilotArgs) -> anyhow::Result<automation::AutomationReport> {
    fs::create_dir_all(&args.run.workspace)?;
    let _ = automation::begin_runtime(&args.run.workspace, args.cycles.max(1), &args.run.nazev);
    let mut cycle_reports = Vec::new();
    let mut previous_run_id = None::<String>;

    for cycle in 1..=args.cycles.max(1) {
        let _ = automation::begin_cycle(
            &args.run.workspace,
            cycle,
            args.cycles.max(1),
            &args.run.nazev,
        );
        let mut run_args = args.run.clone();
        run_args.nazev = format!("{} / cyklus {}", run_args.nazev, cycle);
        run_args.porovnat_s = previous_run_id.clone();
        promote_autopilot_args(&mut run_args);
        let report = match run_pipeline(run_args) {
            Ok(report) => report,
            Err(error) => {
                let _ = automation::fail_runtime(
                    &args.run.workspace,
                    &format!("Autopilot selhal v cyklu {cycle}: {error}"),
                );
                return Err(error);
            }
        };
        let _ = automation::finish_cycle(&args.run.workspace, &report.run.run_id);
        previous_run_id = Some(report.run.run_id.clone());
        cycle_reports.push(report);
        if cycle < args.cycles && args.interval_s > 0 {
            thread::sleep(Duration::from_secs(args.interval_s));
        }
    }

    let automation_report = automation::build_automation_report(&cycle_reports);
    automation::save_automation_report(&args.run.workspace, &automation_report)
        .map_err(|error| anyhow::Error::new(error).context("Uložení autopilot reportu selhalo"))?;
    let _ = automation::complete_runtime(&args.run.workspace, &automation_report);
    Ok(automation_report)
}

fn run_monitor(args: MonitorArgs) -> anyhow::Result<Vec<RunReport>> {
    fs::create_dir_all(&args.run.workspace)?;
    let total_cycles = args.cycles.max(1);
    let mut reports = Vec::new();
    let mut previous_run_id = args.run.porovnat_s.clone();
    let mut cycle = 1usize;

    loop {
        if !args.continuous && cycle > total_cycles {
            break;
        }

        let mut run_args = args.run.clone();
        run_args.nazev = format!("{} / monitor {}", args.run.nazev, cycle);
        run_args.porovnat_s = if cycle == 1 {
            args.run.porovnat_s.clone()
        } else {
            previous_run_id.clone()
        };
        if args.continuous {
            run_args.incremental_ingest = true;
        }
        promote_monitor_args(&mut run_args);
        validate_monitor_args(&run_args)?;

        let report = run_pipeline(run_args)?;
        println!(
            "V monitoru jsem dokoncil cyklus {}: run_id={} udalosti={} nalezy={}",
            cycle, report.run.run_id, report.summary.events_total, report.summary.findings_total
        );
        previous_run_id = Some(report.run.run_id.clone());
        if !args.continuous {
            reports.push(report);
        }

        if !args.continuous && cycle >= total_cycles {
            break;
        }
        cycle = cycle.saturating_add(1);
        if args.interval_s > 0 {
            thread::sleep(Duration::from_secs(args.interval_s));
        }
    }

    Ok(reports)
}

fn run_verification(args: OvereniArgs) -> anyhow::Result<verification::VerificationReport> {
    fs::create_dir_all(&args.workspace)?;
    let scenarios = discover_scenario_fixtures(&args.scenare)?;
    if scenarios.is_empty() {
        return Err(anyhow::anyhow!(
            "Ve slozce {} nebyly nalezeny zadne scenare s manifest.json.",
            args.scenare.display()
        ));
    }

    let mut reports_by_scenario = BTreeMap::<String, RunReport>::new();
    let mut results = Vec::new();

    for scenario in scenarios {
        let base_report = scenario
            .manifest
            .compare_to
            .as_ref()
            .and_then(|key| reports_by_scenario.get(key))
            .cloned();
        let report = run_pipeline(build_replay_beh_args(
            args.workspace.clone(),
            &scenario,
            scenario
                .manifest
                .provider
                .clone()
                .unwrap_or_else(|| args.provider.clone()),
            args.freeze,
            base_report.as_ref().map(|report| report.run.run_id.clone()),
        ))?;

        let result = verification::validate_scenario(
            &scenario.key,
            &scenario.manifest,
            &report,
            base_report.as_ref(),
        );
        reports_by_scenario.insert(scenario.key, report);
        results.push(result);
    }

    let verification_report = verification::build_verification_report(&args.provider, results);
    let path = verification::save_verification_report(&args.workspace, &verification_report)
        .map_err(|error| anyhow::Error::new(error).context("Nelze ulozit verifikacni report"))?;
    println!("Verifikacni report: {}", path.display());
    Ok(verification_report)
}

#[derive(Debug, Clone)]
struct ScenarioFixture {
    key: String,
    dir: PathBuf,
    manifest: verification::ScenarioManifest,
}

#[derive(Debug, Clone)]
struct ScenarioGroup {
    root_key: String,
    scenarios: Vec<ScenarioFixture>,
}

#[derive(Debug)]
struct ScenarioExecution {
    verification: verification::ScenarioVerification,
    metrics: evaluation::ScenarioEvalMetrics,
}

fn run_evaluation(args: EvaluaceArgs) -> anyhow::Result<evaluation::EvaluationReport> {
    fs::create_dir_all(&args.workspace)?;
    let scenarios_root = if let Some(path) = &args.scenare {
        path.clone()
    } else {
        let generated = args.workspace.join("scenarios-generated");
        let profile = resolve_simulation_profile(
            &args.profil,
            args.extra_hostu,
            args.max_sluzeb_na_host,
            args.telemetrie_na_host,
            args.flow_repetitions,
        )?;
        simulation::generate_simulation_with_profile(
            &generated,
            args.seed,
            args.nahodnych,
            &profile,
        )?;
        generated
    };
    let scenarios = discover_scenario_fixtures(&scenarios_root)?;
    if scenarios.is_empty() {
        return Err(anyhow::anyhow!(
            "Ve slozce {} nebyly nalezeny zadne scenare s manifest.json.",
            scenarios_root.display()
        ));
    }

    let tracked_core_types = scenarios
        .iter()
        .flat_map(|scenario| {
            scenario
                .manifest
                .expectations
                .required_finding_types
                .iter()
                .cloned()
        })
        .collect::<BTreeSet<_>>();
    let groups = build_scenario_groups(&scenarios)?;
    let worker_count = args.workers.max(1).min(groups.len().max(1));
    let assignments = assign_groups_to_workers(groups, worker_count);

    let mut handles = Vec::new();
    for (index, worker_groups) in assignments.into_iter().enumerate() {
        let provider = args.provider.clone();
        let tracked_core_types = tracked_core_types.clone();
        let worker_workspace = args
            .workspace
            .join("evaluation-workers")
            .join(format!("worker-{:02}", index + 1));
        let freeze = args.freeze;
        handles.push(thread::spawn(
            move || -> anyhow::Result<Vec<ScenarioExecution>> {
                prepare_worker_workspace(&worker_workspace)?;
                let mut outputs = Vec::new();
                for group in worker_groups {
                    let mut reports_by_scenario = BTreeMap::<String, RunReport>::new();
                    for scenario in group.scenarios {
                        let base_report = scenario
                            .manifest
                            .compare_to
                            .as_ref()
                            .and_then(|key| reports_by_scenario.get(key))
                            .cloned();
                        let report = run_pipeline(build_replay_beh_args(
                            worker_workspace.clone(),
                            &scenario,
                            scenario
                                .manifest
                                .provider
                                .clone()
                                .unwrap_or_else(|| provider.clone()),
                            freeze,
                            base_report.as_ref().map(|report| report.run.run_id.clone()),
                        ))?;
                        let verification = verification::validate_scenario(
                            &scenario.key,
                            &scenario.manifest,
                            &report,
                            base_report.as_ref(),
                        );
                        let metrics = evaluation::scenario_metrics(
                            &scenario.key,
                            &scenario.manifest,
                            &report,
                            &verification,
                            &tracked_core_types,
                        );
                        reports_by_scenario.insert(scenario.key.clone(), report);
                        outputs.push(ScenarioExecution {
                            verification,
                            metrics,
                        });
                    }
                }
                Ok(outputs)
            },
        ));
    }

    let mut verifications = Vec::new();
    let mut metrics = Vec::new();
    for handle in handles {
        let worker_output = handle
            .join()
            .map_err(|_| anyhow::anyhow!("Eval worker skoncil panicem"))??;
        for item in worker_output {
            verifications.push(item.verification);
            metrics.push(item.metrics);
        }
    }
    verifications.sort_by(|left, right| left.scenario_key.cmp(&right.scenario_key));

    let verification_report =
        verification::build_verification_report(&args.provider, verifications);
    let verification_path =
        verification::save_verification_report(&args.workspace, &verification_report).map_err(
            |error| anyhow::Error::new(error).context("Nelze ulozit verifikacni report z evaluace"),
        )?;
    let evaluation_report = evaluation::build_evaluation_report(
        args.seed,
        args.nahodnych,
        worker_count,
        &args.provider,
        tracked_core_types,
        metrics,
    );
    let evaluation_path =
        evaluation::save_evaluation_report(&args.workspace, &evaluation_report)
            .map_err(|error| anyhow::Error::new(error).context("Nelze ulozit evaluacni report"))?;
    println!("Verifikacni report: {}", verification_path.display());
    println!("Evaluacni report: {}", evaluation_path.display());
    Ok(evaluation_report)
}

fn discover_scenario_fixtures(root: &Path) -> anyhow::Result<Vec<ScenarioFixture>> {
    let scenario_dirs = verification::discover_scenarios(root)
        .map_err(|error| anyhow::Error::new(error).context("Nelze nacist scenare"))?;
    let mut scenarios = Vec::new();
    for scenario_dir in scenario_dirs {
        let key = scenario_key_from_dir(&scenario_dir)?;
        let manifest = verification::load_manifest(&scenario_dir.join("manifest.json"))
            .map_err(|error| anyhow::Error::new(error).context("Manifest scenare je neplatny"))?;
        scenarios.push(ScenarioFixture {
            key,
            dir: scenario_dir,
            manifest,
        });
    }
    scenarios.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(scenarios)
}

fn scenario_key_from_dir(path: &Path) -> anyhow::Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|value| value.to_string())
        .ok_or_else(|| anyhow::anyhow!("Neplatny nazev scenare: {}", path.display()))
}

fn build_replay_beh_args(
    workspace: PathBuf,
    scenario: &ScenarioFixture,
    provider: String,
    freeze: bool,
    compare_run_id: Option<String>,
) -> BehArgs {
    BehArgs {
        workspace,
        nazev: scenario.manifest.nazev.clone(),
        scope: scenario.manifest.scope.clone(),
        ports: scenario.manifest.ports.clone(),
        profile: scenario.manifest.profile.clone(),
        provider,
        supplement_vulners: false,
        freeze,
        production: false,
        nmap_xml: Some(scenario.dir.join("nmap.xml")),
        nmap_followup_xml: None,
        suricata_eve: existing_file(scenario.dir.join("suricata").join("eve.json")),
        zeek_dir: existing_dir(scenario.dir.join("zeek")),
        porovnat_s: compare_run_id,
        spustit_nmap: false,
        hloubkove_overeni: false,
        web_fingerprint: false,
        web_checks: false,
        execute_verification: false,
        incremental_ingest: false,
        verification_max_checks: 10,
        pentest: false,
        aggressive_pentest: false,
        httpx_bin: None,
        nuclei_bin: None,
        nuclei_templates: None,
        snmp_snapshot: None,
        librenms_snapshot: None,
        librenms_base_url: None,
        librenms_token_env: "LIBRENMS_TOKEN".to_string(),
        meraki_snapshot: None,
        meraki_network_id: None,
        meraki_api_key_env: "MERAKI_DASHBOARD_API_KEY".to_string(),
        meraki_timespan_seconds: 86400,
        unifi_snapshot: None,
        unifi_devices_url: None,
        unifi_clients_url: None,
        unifi_links_url: None,
        unifi_api_key_env: "UNIFI_API_KEY".to_string(),
        aruba_snapshot: None,
        aruba_base_url: None,
        aruba_token_env: "ARUBA_CENTRAL_TOKEN".to_string(),
        aruba_site_id: None,
        omada_snapshot: None,
        omada_devices_url: None,
        omada_clients_url: None,
        omada_links_url: None,
        omada_access_token_env: "OMADA_ACCESS_TOKEN".to_string(),
        ntopng_snapshot: None,
        flow_snapshot: None,
        greenbone_report: None,
        wazuh_report: None,
        napalm_snapshot: None,
        netmiko_snapshot: None,
        scrapli_snapshot: None,
        urlhaus_auth_env: "URLHAUS_AUTH_KEY".to_string(),
        abuseipdb_key_env: "ABUSEIPDB_API_KEY".to_string(),
        disable_circl: true,
    }
}

fn build_scenario_groups(scenarios: &[ScenarioFixture]) -> anyhow::Result<Vec<ScenarioGroup>> {
    let by_key = scenarios
        .iter()
        .cloned()
        .map(|scenario| (scenario.key.clone(), scenario))
        .collect::<BTreeMap<_, _>>();
    for scenario in scenarios {
        if let Some(compare_to) = &scenario.manifest.compare_to {
            if !by_key.contains_key(compare_to) {
                return Err(anyhow::anyhow!(
                    "Scenar {} odkazuje na chybejici compare_to {}.",
                    scenario.key,
                    compare_to
                ));
            }
        }
    }

    let mut children = BTreeMap::<String, Vec<String>>::new();
    let mut roots = Vec::new();
    for scenario in scenarios {
        if let Some(compare_to) = &scenario.manifest.compare_to {
            children
                .entry(compare_to.clone())
                .or_default()
                .push(scenario.key.clone());
        } else {
            roots.push(scenario.key.clone());
        }
    }
    for items in children.values_mut() {
        items.sort();
    }
    roots.sort();

    let mut visited = BTreeSet::new();
    let mut groups = Vec::new();
    for root in roots {
        if visited.contains(&root) {
            continue;
        }
        let mut ordered = Vec::new();
        collect_scenario_group(&root, &by_key, &children, &mut visited, &mut ordered)?;
        groups.push(ScenarioGroup {
            root_key: root,
            scenarios: ordered,
        });
    }
    for key in by_key.keys() {
        if visited.contains(key) {
            continue;
        }
        let mut ordered = Vec::new();
        collect_scenario_group(key, &by_key, &children, &mut visited, &mut ordered)?;
        groups.push(ScenarioGroup {
            root_key: key.clone(),
            scenarios: ordered,
        });
    }
    groups.sort_by(|left, right| left.root_key.cmp(&right.root_key));
    Ok(groups)
}

fn collect_scenario_group(
    key: &str,
    by_key: &BTreeMap<String, ScenarioFixture>,
    children: &BTreeMap<String, Vec<String>>,
    visited: &mut BTreeSet<String>,
    ordered: &mut Vec<ScenarioFixture>,
) -> anyhow::Result<()> {
    if !visited.insert(key.to_string()) {
        return Ok(());
    }
    let scenario = by_key
        .get(key)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Scenar {} nebyl nalezen.", key))?;
    ordered.push(scenario);
    if let Some(items) = children.get(key) {
        for child in items {
            collect_scenario_group(child, by_key, children, visited, ordered)?;
        }
    }
    Ok(())
}

fn assign_groups_to_workers(
    mut groups: Vec<ScenarioGroup>,
    workers: usize,
) -> Vec<Vec<ScenarioGroup>> {
    let worker_count = workers.max(1).min(groups.len().max(1));
    groups.sort_by(|left, right| {
        right
            .scenarios
            .len()
            .cmp(&left.scenarios.len())
            .then(left.root_key.cmp(&right.root_key))
    });
    let mut assignments = vec![Vec::new(); worker_count];
    let mut loads = vec![0usize; worker_count];
    for group in groups {
        let (target_index, _) = loads
            .iter()
            .enumerate()
            .min_by_key(|(_, load)| **load)
            .expect("alespon jeden worker");
        loads[target_index] += group.scenarios.len();
        assignments[target_index].push(group);
    }
    assignments
}

fn prepare_worker_workspace(workspace: &Path) -> anyhow::Result<()> {
    if workspace.exists() {
        fs::remove_dir_all(workspace)?;
    }
    fs::create_dir_all(workspace)?;
    let config_path = workspace.join("bakula.toml");
    let mut app_config = AppConfig::default();
    app_config.workspace_root = workspace.to_string_lossy().to_string();
    app_config.retention.max_runs = 10_000;
    fs::write(&config_path, toml::to_string_pretty(&app_config)?)?;
    Ok(())
}

fn build_scenario_job_spec(
    args: &PlatformJobScenarioArgs,
) -> anyhow::Result<platform::PipelineJobSpec> {
    Ok(platform::PipelineJobSpec {
        workspace_root: args.workspace.to_string_lossy().to_string(),
        nazev: args.nazev.clone(),
        scope: args.scope.iter().map(ToString::to_string).collect(),
        ports: args.ports.clone(),
        profile: args.profile.clone(),
        provider: args.provider.clone(),
        supplement_vulners: false,
        freeze: false,
        nmap_xml: Some(
            args.scenario_dir
                .join("nmap.xml")
                .to_string_lossy()
                .to_string(),
        ),
        nmap_followup_xml: None,
        suricata_eve: existing_file(args.scenario_dir.join("suricata").join("eve.json"))
            .map(|item| item.to_string_lossy().to_string()),
        zeek_dir: existing_dir(args.scenario_dir.join("zeek"))
            .map(|item| item.to_string_lossy().to_string()),
        porovnat_s: None,
        spustit_nmap: false,
        web_fingerprint: false,
        web_checks: false,
        pentest: false,
        aggressive_pentest: false,
        httpx_bin: None,
        nuclei_bin: None,
        nuclei_templates: None,
        snmp_snapshot: None,
        librenms_snapshot: None,
        librenms_base_url: None,
        librenms_token_env: "LIBRENMS_TOKEN".to_string(),
        meraki_snapshot: None,
        meraki_network_id: None,
        meraki_api_key_env: "MERAKI_DASHBOARD_API_KEY".to_string(),
        meraki_timespan_seconds: 86400,
        unifi_snapshot: None,
        unifi_devices_url: None,
        unifi_clients_url: None,
        unifi_links_url: None,
        unifi_api_key_env: "UNIFI_API_KEY".to_string(),
        aruba_snapshot: None,
        aruba_base_url: None,
        aruba_token_env: "ARUBA_CENTRAL_TOKEN".to_string(),
        aruba_site_id: None,
        omada_snapshot: None,
        omada_devices_url: None,
        omada_clients_url: None,
        omada_links_url: None,
        omada_access_token_env: "OMADA_ACCESS_TOKEN".to_string(),
        ntopng_snapshot: None,
        flow_snapshot: None,
        greenbone_report: None,
        wazuh_report: None,
        napalm_snapshot: None,
        netmiko_snapshot: None,
        scrapli_snapshot: None,
        urlhaus_auth_env: "URLHAUS_AUTH_KEY".to_string(),
        abuseipdb_key_env: "ABUSEIPDB_API_KEY".to_string(),
        disable_circl: true,
    })
}

fn spec_to_beh_args(spec: platform::PipelineJobSpec) -> anyhow::Result<BehArgs> {
    Ok(BehArgs {
        workspace: PathBuf::from(spec.workspace_root),
        nazev: spec.nazev,
        scope: spec
            .scope
            .into_iter()
            .map(|item| item.parse::<IpNet>())
            .collect::<std::result::Result<Vec<_>, _>>()?,
        ports: spec.ports,
        profile: spec.profile,
        provider: spec.provider,
        supplement_vulners: spec.supplement_vulners,
        freeze: spec.freeze,
        production: false,
        nmap_xml: spec.nmap_xml.map(PathBuf::from),
        nmap_followup_xml: spec.nmap_followup_xml.map(PathBuf::from),
        suricata_eve: spec.suricata_eve.map(PathBuf::from),
        zeek_dir: spec.zeek_dir.map(PathBuf::from),
        porovnat_s: spec.porovnat_s,
        spustit_nmap: spec.spustit_nmap,
        hloubkove_overeni: false,
        web_fingerprint: spec.web_fingerprint,
        web_checks: spec.web_checks,
        execute_verification: false,
        incremental_ingest: false,
        verification_max_checks: 10,
        pentest: spec.pentest,
        aggressive_pentest: spec.aggressive_pentest,
        httpx_bin: spec.httpx_bin.map(PathBuf::from),
        nuclei_bin: spec.nuclei_bin.map(PathBuf::from),
        nuclei_templates: spec.nuclei_templates.map(PathBuf::from),
        snmp_snapshot: spec.snmp_snapshot.map(PathBuf::from),
        librenms_snapshot: spec.librenms_snapshot.map(PathBuf::from),
        librenms_base_url: spec.librenms_base_url,
        librenms_token_env: spec.librenms_token_env,
        meraki_snapshot: spec.meraki_snapshot.map(PathBuf::from),
        meraki_network_id: spec.meraki_network_id,
        meraki_api_key_env: spec.meraki_api_key_env,
        meraki_timespan_seconds: spec.meraki_timespan_seconds,
        unifi_snapshot: spec.unifi_snapshot.map(PathBuf::from),
        unifi_devices_url: spec.unifi_devices_url,
        unifi_clients_url: spec.unifi_clients_url,
        unifi_links_url: spec.unifi_links_url,
        unifi_api_key_env: spec.unifi_api_key_env,
        aruba_snapshot: spec.aruba_snapshot.map(PathBuf::from),
        aruba_base_url: spec.aruba_base_url,
        aruba_token_env: spec.aruba_token_env,
        aruba_site_id: spec.aruba_site_id,
        omada_snapshot: spec.omada_snapshot.map(PathBuf::from),
        omada_devices_url: spec.omada_devices_url,
        omada_clients_url: spec.omada_clients_url,
        omada_links_url: spec.omada_links_url,
        omada_access_token_env: spec.omada_access_token_env,
        ntopng_snapshot: spec.ntopng_snapshot.map(PathBuf::from),
        flow_snapshot: spec.flow_snapshot.map(PathBuf::from),
        greenbone_report: spec.greenbone_report.map(PathBuf::from),
        wazuh_report: spec.wazuh_report.map(PathBuf::from),
        napalm_snapshot: spec.napalm_snapshot.map(PathBuf::from),
        netmiko_snapshot: spec.netmiko_snapshot.map(PathBuf::from),
        scrapli_snapshot: spec.scrapli_snapshot.map(PathBuf::from),
        urlhaus_auth_env: spec.urlhaus_auth_env,
        abuseipdb_key_env: spec.abuseipdb_key_env,
        disable_circl: spec.disable_circl,
    })
}

fn existing_file(path: PathBuf) -> Option<PathBuf> {
    path.is_file().then_some(path)
}

fn existing_dir(path: PathBuf) -> Option<PathBuf> {
    path.is_dir().then_some(path)
}
