use std::{
    convert::Infallible,
    fs,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tokio::sync::Mutex;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tower_http::services::ServeDir;

use crate::{
    Result, ai, assistant, automation,
    case_memory::{self, CaseMemory, CaseRecord, CaseSource},
    config,
    enforcement::{BlockIpRequest, EnforcementRejection},
    model::{AppConfig, RunIndexEntry, RunReport},
    ops::{self, NftExecutor, OpsConfig, OpsStore, ProposeError},
    paths, platform, readiness,
    storage::Workspace,
    verification,
};

#[derive(Clone)]
struct AppState {
    workspace_root: Arc<PathBuf>,
    started_at: DateTime<Utc>,
    auth_required: bool,
    api_token: Arc<Option<String>>,
    platform_db: Arc<Option<PathBuf>>,
    automation_process: Arc<Mutex<Option<AutomationProcess>>>,
    ops: Arc<OpsRuntime>,
}

/// Konfigurace + exekutor zasahu (`enforce.block_ip`). Exekutor je `dyn`, aby
/// testy mohly pouzit falesny `nft` a handlery tak nikdy nesahly na realny firewall.
struct OpsRuntime {
    config: OpsConfig,
    executor: Arc<dyn NftExecutor>,
}

impl OpsRuntime {
    fn from_env() -> Self {
        let config = OpsConfig::from_env();
        let executor = Arc::new(ops::SystemNft {
            bin: config.nft_bin.clone(),
        });
        Self { config, executor }
    }
}

#[derive(Clone)]
struct AuthContext {
    subject: String,
}

struct AutomationProcess {
    child: Child,
    started_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct AutomationRestartOptions {
    pentest: Option<String>,
}

pub async fn serve(addr: SocketAddr, workspace_root: PathBuf) -> Result<()> {
    let mut config = AppConfig::default();
    config.workspace_root = workspace_root.to_string_lossy().to_string();
    config.host = addr.ip().to_string();
    config.port = addr.port();
    serve_with_config(addr, config).await
}

pub async fn serve_with_config(addr: SocketAddr, config: AppConfig) -> Result<()> {
    let platform_db = platform::init_platform_from_config(&config)?;
    let state = AppState {
        workspace_root: Arc::new(PathBuf::from(&config.workspace_root)),
        started_at: Utc::now(),
        auth_required: config.security.require_api_token,
        api_token: Arc::new(config::resolve_api_token(&config)?),
        platform_db: Arc::new(platform_db),
        automation_process: Arc::new(Mutex::new(None)),
        ops: Arc::new(OpsRuntime::from_env()),
    };
    spawn_ops_sweep(state.clone());
    let ui_dir = paths::project_path(&["ui"]);

    let api = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/meta", get(meta))
        .route("/metrics", get(metrics))
        .route("/ai/status", get(get_ai_status))
        .route("/readiness", get(get_readiness))
        .route("/runs", get(list_runs))
        .route("/runs/{run_id}", get(get_run))
        .route("/runs/{run_id}/export/{format}", get(get_run_export))
        .route("/runs/{run_id}/assistant", post(post_run_assistant))
        .route(
            "/runs/{run_id}/assistant/stream",
            post(post_run_assistant_stream),
        )
        .route("/automation/latest", get(get_automation_latest))
        .route("/automation/status", get(get_automation_status))
        .route("/automation/restart", post(post_automation_restart))
        .route("/automation/reset", post(post_automation_reset))
        .route("/verification/latest", get(get_latest_verification))
        .route("/enforcement/actions", get(get_enforcement_actions))
        .route("/enforcement/propose", post(post_enforcement_propose))
        .route("/enforcement/{id}/approve", post(post_enforcement_approve))
        .route("/enforcement/{id}/reject", post(post_enforcement_reject))
        .route("/audit", get(get_audit))
        .route("/audit/verify", get(get_audit_verify))
        .route(
            "/runs/{run_id}/findings/{finding_id}/verdict",
            post(post_finding_verdict),
        )
        .route("/closure-audit", get(get_closure_audit))
        .route("/closure-audit/{id}/review", post(post_closure_review))
        .route(
            "/closure-audit/kinds/{kind}/enable",
            post(post_closure_enable),
        )
        .route("/novelty/consent", post(post_novelty_consent))
        .route(
            "/endpoint/ingest",
            post(post_endpoint_ingest).layer(axum::extract::DefaultBodyLimit::max(
                crate::endpoint::correlate::Limits::default().max_batch_bytes,
            )),
        )
        .route("/platform/cluster", get(get_platform_cluster))
        .route("/platform/jobs", get(get_platform_jobs))
        .route("/platform/users", get(get_platform_users))
        .route("/platform/ha", get(get_platform_ha))
        .with_state(state.clone());

    let app = Router::new()
        .nest("/api", api)
        .fallback_service(ServeDir::new(ui_dir))
        .layer(axum::middleware::map_response(disable_cache_headers))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state);

    tracing::info!(%addr, "Salticus UI bezi");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn disable_cache_headers(mut response: axum::response::Response) -> axum::response::Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
        .headers_mut()
        .insert(header::EXPIRES, HeaderValue::from_static("0"));
    response
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "stav": "ok"
    }))
}

async fn ready(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let auth = authorize_for(&headers, &state, &["runs.read"])?;
    let workspace = Workspace::open(&state.workspace_root).map_err(to_http_error)?;
    let runs = workspace.list_runs().map_err(to_http_error)?;
    let workspace_root = state.workspace_root.display().to_string();
    Ok::<_, (StatusCode, String)>(Json(serde_json::json!({
        "stav": "ready",
        "workspace": workspace_root,
        "runs_total": runs.len(),
        "started_at": state.started_at,
        "subject": auth.subject,
    })))
}

async fn meta(State(state): State<AppState>) -> impl IntoResponse {
    let workspace_root = state.workspace_root.display().to_string();
    Json(serde_json::json!({
        "service": "salticus-program",
        "version": env!("CARGO_PKG_VERSION"),
        "started_at": state.started_at,
        "workspace_root": workspace_root,
        "auth_required": state.auth_required,
        "platform_enabled": state.platform_db.is_some(),
    }))
}

async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    authorize_for(&headers, &state, &["metrics.read"])?;
    let workspace = Workspace::open(&state.workspace_root).map_err(to_http_error)?;
    let runs = workspace.list_runs().map_err(to_http_error)?;
    let latest = runs.first();
    let mut metrics = render_metrics(&runs, latest);
    metrics.push_str(&render_ops_metrics(&state));
    Ok::<_, (StatusCode, String)>((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        metrics,
    ))
}

/// Provozni metriky zasahu: pocty akci podle stavu, aktualni mod, delka auditu.
/// Nedostupna ops DB nesmi shodit cele `/metrics` - vypise se jen `salticus_ops_up 0`.
fn render_ops_metrics(state: &AppState) -> String {
    let mode = match state.ops.config.mode {
        ops::EnforcementMode::DryRun => "dry_run",
        ops::EnforcementMode::Enforce => "enforce",
    };
    let mut text = String::new();
    text.push_str(
        "# HELP salticus_enforcement_mode Aktualni rezim zasahu (1 = aktivni).
",
    );
    text.push_str(
        "# TYPE salticus_enforcement_mode gauge
",
    );
    text.push_str(&format!(
        "salticus_enforcement_mode{{mode=\"{mode}\"}} 1
"
    ));
    match ops_store(state).and_then(|store| store.metrics_snapshot()) {
        Ok((counts, audit)) => {
            text.push_str(
                "# HELP salticus_ops_up Ops databaze je dostupna.
# TYPE salticus_ops_up gauge
salticus_ops_up 1
",
            );
            text.push_str(
                "# HELP salticus_enforcement_actions Pocet zasahu podle stavu.
",
            );
            text.push_str(
                "# TYPE salticus_enforcement_actions gauge
",
            );
            for (status, count) in counts {
                text.push_str(&format!(
                    "salticus_enforcement_actions{{status=\"{status}\"}} {count}
"
                ));
            }
            text.push_str(
                "# HELP salticus_audit_entries_total Pocet zaznamu audit logu.
",
            );
            text.push_str(
                "# TYPE salticus_audit_entries_total counter
",
            );
            text.push_str(&format!(
                "salticus_audit_entries_total {audit}
"
            ));
        }
        Err(_) => text.push_str(
            "# TYPE salticus_ops_up gauge
salticus_ops_up 0
",
        ),
    }
    text
}

async fn get_ai_status(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    Ok::<_, (StatusCode, String)>(Json(ai::diagnose()))
}

async fn get_readiness(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    let report = readiness::assess_workspace(&state.workspace_root, state.auth_required)
        .map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(report))
}

async fn list_runs(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    let workspace = Workspace::open(&state.workspace_root).map_err(to_http_error)?;
    let runs = workspace.list_runs().map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(runs))
}

async fn get_run(
    Path(run_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    let workspace = Workspace::open(&state.workspace_root).map_err(to_http_error)?;
    let report = workspace.load_report(&run_id).map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(report))
}

async fn get_run_export(
    Path((run_id, format)): Path<(String, String)>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    // Audit nalez (30.10.2026, produkcni gap analyza): `run_id` z URL cesty
    // sel primo do `Path::join` bez validace - path traversal na libovolny
    // `report.*` soubor kdekoliv na disku (napr. `..%2f..%2fetc%2fpasswd`
    // po percent-decode). `build_run_id()` generuje jen alfanumericke/'-'/'_'
    // znaky, takze tohle nic legitimniho neodmitne.
    if !crate::storage::is_valid_run_id(&run_id) {
        return Err((StatusCode::BAD_REQUEST, "Neplatny run_id.".to_string()));
    }
    let (filename, content_type) = match format.as_str() {
        "json" => ("report.json", "application/json; charset=utf-8"),
        "md" => ("report.md", "text/markdown; charset=utf-8"),
        "txt" => ("report.txt", "text/plain; charset=utf-8"),
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "Neznamy export format. Pouzij json, md nebo txt.".to_string(),
            ));
        }
    };
    let path = state
        .workspace_root
        .join("runs")
        .join(&run_id)
        .join(filename);
    let bytes = fs::read(&path).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Chyba serveru: {error}"),
        )
    })?;
    let mut response = bytes.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type).map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Chyba serveru: {error}"),
            )
        })?,
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}-{}\"", run_id, filename))
            .map_err(|error| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Chyba serveru: {error}"),
                )
            })?,
    );
    Ok::<_, (StatusCode, String)>(response)
}

async fn post_run_assistant(
    Path(run_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<assistant::AssistantRequest>,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    let response = assistant::answer_run_question(&state.workspace_root, &run_id, request)
        .await
        .map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(response))
}

async fn post_run_assistant_stream(
    Path(run_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<assistant::AssistantRequest>,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    let events = assistant::answer_run_question_events(
        state.workspace_root.as_ref().clone(),
        run_id,
        request,
    );
    let stream = ReceiverStream::new(events).map(|event| {
        let payload = serde_json::to_string(&event).unwrap_or_else(|error| {
            serde_json::json!({
                "type": "error",
                "error": error.to_string()
            })
            .to_string()
        });
        Ok::<Bytes, Infallible>(Bytes::from(format!("data: {payload}\n\n")))
    });
    let mut response = Body::from_stream(stream).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    Ok::<_, (StatusCode, String)>(response)
}

async fn get_latest_verification(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["verification.read"])?;
    Workspace::open(&state.workspace_root).map_err(to_http_error)?;
    let report = verification::load_latest_verification_report(&state.workspace_root)
        .map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(report))
}

async fn get_automation_latest(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    let path = automation::latest_report_path(&state.workspace_root);
    if !path.exists() {
        return Ok::<_, (StatusCode, String)>(Json(Option::<automation::AutomationReport>::None));
    }
    let bytes = fs::read(path).map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Chyba serveru: {error}"),
        )
    })?;
    let report =
        serde_json::from_slice::<automation::AutomationReport>(&bytes).map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Chyba serveru: {error}"),
            )
        })?;
    Ok::<_, (StatusCode, String)>(Json(Some(report)))
}

async fn get_automation_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["runs.read"])?;
    let status = resolve_runtime_status(&state)
        .await
        .map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(status))
}

async fn post_automation_restart(
    State(state): State<AppState>,
    Query(options): Query<AutomationRestartOptions>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = authorize_for(&headers, &state, &["jobs.write"])?;
    ensure_csrf_guard_header(&auth, &headers)?;
    let mut guard = state.automation_process.lock().await;
    if let Some(process) = guard.as_mut() {
        match process.child.try_wait() {
            Ok(None) => {
                return Err((
                    StatusCode::CONFLICT,
                    "Autopilot už běží. Použij reset nebo počkej na dokončení.".to_string(),
                ));
            }
            Ok(Some(_)) => {
                *guard = None;
            }
            Err(error) => {
                *guard = None;
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Chyba serveru: {error}"),
                ));
            }
        }
    }

    let workspace = Workspace::open(&state.workspace_root).map_err(to_http_error)?;
    let latest_run_id = workspace
        .list_runs()
        .map_err(to_http_error)?
        .first()
        .map(|item| item.run_id.clone())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "Ve workspace není žádný běh, ze kterého by šlo odvodit restart.".to_string(),
        ))?;
    let latest_report = workspace
        .load_report(&latest_run_id)
        .map_err(to_http_error)?;
    let mut command =
        build_restart_command(&state.workspace_root, &latest_report).map_err(to_http_error)?;
    apply_restart_pentest_options(&mut command, &options);
    automation::begin_runtime(&state.workspace_root, 1, &latest_report.run.nazev)
        .map_err(to_http_error)?;
    let exe = std::env::current_exe().map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Chyba serveru: {error}"),
        )
    })?;
    let mut child = Command::new(exe);
    child.args(&command);
    child.stdout(Stdio::null());
    child.stderr(Stdio::null());
    let child = child.spawn().map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Chyba serveru: {error}"),
        )
    })?;
    let pid = child.id();
    *guard = Some(AutomationProcess {
        child,
        started_at: Utc::now(),
    });
    Ok::<_, (StatusCode, String)>(Json(serde_json::json!({
        "state": "starting",
        "pid": pid,
        "command": command,
    })))
}

async fn post_automation_reset(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let auth = authorize_for(&headers, &state, &["jobs.write"])?;
    ensure_csrf_guard_header(&auth, &headers)?;
    let mut guard = state.automation_process.lock().await;
    if let Some(process) = guard.as_mut() {
        let _ = process.child.kill();
    }
    *guard = None;
    let status = automation::clear_runtime_status(&state.workspace_root).map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(serde_json::json!({
        "state": "reset",
        "status_path": status.display().to_string(),
    })))
}

async fn get_platform_cluster(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["cluster.read"])?;
    let db = state.platform_db.as_deref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Platform DB neni aktivni.".to_string(),
    ))?;
    let snapshot = platform::snapshot(db).map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(snapshot))
}

async fn get_platform_jobs(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    authorize_for(&headers, &state, &["jobs.read"])?;
    let db = state.platform_db.as_deref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Platform DB neni aktivni.".to_string(),
    ))?;
    let jobs = platform::list_jobs(db).map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(jobs))
}

async fn get_platform_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    authorize_for(&headers, &state, &["users.read"])?;
    let db = state.platform_db.as_deref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Platform DB neni aktivni.".to_string(),
    ))?;
    let users = platform::list_users(db).map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(users))
}

async fn get_platform_ha(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    authorize_for(&headers, &state, &["cluster.read"])?;
    let db = state.platform_db.as_deref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Platform DB neni aktivni.".to_string(),
    ))?;
    let status = platform::ha_status(db, None).map_err(to_http_error)?;
    Ok::<_, (StatusCode, String)>(Json(status))
}

/// Audit nalez (30.10.2026, produkcni gap analyza): `require_api_token=false`
/// (vychozi hodnota) dela z KAZDEHO pozadavku anonymniho admina (`authorize_for`
/// nize) - vcetne `/automation/restart`, ktery spousti aktivni sken proti
/// nakonfigurovanemu scope. Bez tehle kontroly by jakakoliv webova stranka
/// otevrena v prohlizeci operatora mohla poslat "simple" cross-site POST
/// (obycejny `<form>`, zadny JS/CORS potreba) a sken tise spustit (blind CSRF -
/// odpoved sice cross-origin precist nejde, ale pozadavek se stejne provede).
/// Vlastni hlavicka tohle blokuje: `<form>` ji nastavit neumi a cross-site
/// `fetch` s vlastni hlavickou vyvola CORS preflight, ktery bez
/// `Access-Control-Allow-Origin` (server zadny CORS vrstvu nema) selze driv,
/// nez se skutecny POST vubec posle.
///
/// Oprava po nasazeni (e2e regrese, 30.10.2026): kontrola puvodne bezela PRED
/// `authorize_for` a platila univerzalne - rozbila `server_respektuje_api_token`,
/// ktery pravem ocekava 401 (ne 403) na pozadavek bez tokenu, a 200 (bez CSRF
/// hlavicky) na pozadavek SE spravnym bearer tokenem. Spravny rozsah: CSRF je
/// hrozba jen pro `anonymous-admin` (auth_required=false, zadny secret se
/// neprokazuje) - bearer token/x-api-key jde jen přes vlastní hlavičku, kterou
/// cross-site `<form>` ani `fetch` bez CORS nemůže automaticky připojit, takže
/// token-autentizovany pozadavek uz je sam o sobe CSRF-imunni.
fn ensure_csrf_guard_header(
    auth: &AuthContext,
    headers: &HeaderMap,
) -> std::result::Result<(), (StatusCode, String)> {
    if auth.subject != "anonymous-admin" || headers.contains_key("x-salticus-csrf") {
        return Ok(());
    }
    Err((
        StatusCode::FORBIDDEN,
        "Chybi hlavicka X-Salticus-Csrf - pozadavek vypada jako cross-site a byl odmitnut."
            .to_string(),
    ))
}

fn authorize_for(
    headers: &HeaderMap,
    state: &AppState,
    required_permissions: &[&str],
) -> std::result::Result<AuthContext, (StatusCode, String)> {
    let provided = bearer_token(headers).or_else(|| api_key_header(headers));
    if let Some(db_path) = state.platform_db.as_deref() {
        let token = provided.ok_or((
            StatusCode::UNAUTHORIZED,
            "Pro pristup k API je vyzadovan platformni token.".to_string(),
        ))?;
        let identity = platform::authenticate_token(db_path, &token).map_err(to_http_error)?;
        if let Some(identity) = identity {
            ensure_permissions(&identity, required_permissions)?;
            return Ok(AuthContext {
                subject: identity.username,
            });
        }
        if let Some(expected) = state.api_token.as_deref() {
            if constant_time_eq(&token, expected) {
                return Ok(admin_context("static-admin"));
            }
        }
        return Err((
            StatusCode::UNAUTHORIZED,
            "Chybi nebo je neplatny platformni token.".to_string(),
        ));
    }

    if !state.auth_required {
        return Ok(admin_context("anonymous-admin"));
    }
    // Fail-closed: bez platform DB vyzaduje KAZDY pozadavek (cteni i zapis) platny
    // staticky api_token, kdyz je auth_required=true - zadna vyjimka pro cist-only
    // permissions, jinak je API fakticky vzdy neautentizovane pro cteni.
    let Some(expected) = state.api_token.as_deref() else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Server neni nakonfigurovan pro overeni API tokenu.".to_string(),
        ));
    };
    match provided {
        Some(token) if constant_time_eq(&token, expected) => Ok(admin_context("static-admin")),
        _ => Err((
            StatusCode::UNAUTHORIZED,
            "Chybi nebo je neplatny API token.".to_string(),
        )),
    }
}

/// Audit nalez (31.10.2026, produkcni audit se tremi nezavislymi revizemi): `token == expected`
/// pouzivalo `String::eq`, ktere konci na prvnim ruznem bajtu - timing
/// side-channel proti statickemu API tokenu (vzdalenost odezvy koreluje s
/// poctem spravne uhodnutych prefix-bajtu). Konstantni-casove porovnani bez
/// nove zavislosti (bajtova XOR akumulace, zadne branveni na obsahu).
/// Delka tokenu samotna se nepovažuje za tajnou (standardni praxe - i
/// `subtle` crate porovnava delky pred samotnym XOR).
fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn ensure_permissions(
    auth: &platform::AuthIdentity,
    required_permissions: &[&str],
) -> std::result::Result<(), (StatusCode, String)> {
    if required_permissions.is_empty() || auth.permissions.iter().any(|item| item == "*") {
        return Ok(());
    }
    let missing = required_permissions
        .iter()
        .copied()
        .filter(|permission| !auth.permissions.iter().any(|item| item == permission))
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            format!("Chybi opravneni: {}.", missing.join(", ")),
        ))
    }
}

fn admin_context(subject: &str) -> AuthContext {
    AuthContext {
        subject: subject.to_string(),
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .map(|token| token.trim().to_string())
}

fn api_key_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn render_metrics(runs: &[RunIndexEntry], latest: Option<&RunIndexEntry>) -> String {
    let hosts_total: usize = runs.iter().map(|item| item.hosts_total).sum();
    let services_total: usize = runs.iter().map(|item| item.services_total).sum();
    let cves_total: usize = runs.iter().map(|item| item.cves_total).sum();
    let events_total: usize = runs.iter().map(|item| item.events_total).sum();
    let findings_total: usize = runs.iter().map(|item| item.findings_total).sum();
    let triage_total: usize = runs.iter().map(|item| item.triage_actions_total).sum();
    let lanes_total: usize = runs.iter().map(|item| item.monitoring_lanes_total).sum();
    format!(
        concat!(
            "# HELP salticus_runs_total Pocet ulozenych behu.\n",
            "# TYPE salticus_runs_total gauge\n",
            "salticus_runs_total {}\n",
            "# HELP salticus_hosts_total_sum Soucet hostu napric ulozenymi behy.\n",
            "# TYPE salticus_hosts_total_sum gauge\n",
            "salticus_hosts_total_sum {}\n",
            "# HELP salticus_services_total_sum Soucet sluzeb napric ulozenymi behy.\n",
            "# TYPE salticus_services_total_sum gauge\n",
            "salticus_services_total_sum {}\n",
            "# HELP salticus_cves_total_sum Soucet CVE napric ulozenymi behy.\n",
            "# TYPE salticus_cves_total_sum gauge\n",
            "salticus_cves_total_sum {}\n",
            "# HELP salticus_events_total_sum Soucet udalosti napric ulozenymi behy.\n",
            "# TYPE salticus_events_total_sum gauge\n",
            "salticus_events_total_sum {}\n",
            "# HELP salticus_findings_total_sum Soucet nalezu napric ulozenymi behy.\n",
            "# TYPE salticus_findings_total_sum gauge\n",
            "salticus_findings_total_sum {}\n",
            "# HELP salticus_triage_actions_total_sum Soucet triage kroku napric ulozenymi behy.\n",
            "# TYPE salticus_triage_actions_total_sum gauge\n",
            "salticus_triage_actions_total_sum {}\n",
            "# HELP salticus_monitoring_lanes_total_sum Soucet monitoring lanes napric ulozenymi behy.\n",
            "# TYPE salticus_monitoring_lanes_total_sum gauge\n",
            "salticus_monitoring_lanes_total_sum {}\n",
            "# HELP salticus_latest_hosts_total Hoste v poslednim behu.\n",
            "# TYPE salticus_latest_hosts_total gauge\n",
            "salticus_latest_hosts_total {}\n",
            "# HELP salticus_latest_findings_total Nalezy v poslednim behu.\n",
            "# TYPE salticus_latest_findings_total gauge\n",
            "salticus_latest_findings_total {}\n",
        ),
        runs.len(),
        hosts_total,
        services_total,
        cves_total,
        events_total,
        findings_total,
        triage_total,
        lanes_total,
        latest.map(|item| item.hosts_total).unwrap_or_default(),
        latest.map(|item| item.findings_total).unwrap_or_default(),
    )
}

// --- zasahy (enforcement) a audit -----------------------------------------------

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

fn pair_to_response(error: (StatusCode, String)) -> Response {
    error_response(error.0, error.1)
}

fn ops_store(state: &AppState) -> crate::Result<OpsStore> {
    OpsStore::open(&state.workspace_root.join("ops.sqlite"))
}

/// SQLite je blokujici - mimo async runtime, aby pomale zapisy nebrzdily ostatni
/// pozadavky. `Err` je rovnou hotova HTTP odpoved (handler ji jen vrati).
#[allow(clippy::result_large_err)]
async fn run_blocking<T, F>(work: F) -> std::result::Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce() -> crate::Result<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(work).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Chyba serveru: {error}"),
        )),
        Err(error) => Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Chyba serveru: {error}"),
        )),
    }
}

/// Pravidelny nezavisly sweep: expirace po TTL + (v `enforce` modu) porovnani
/// zivych `nft` setu s databazi. Bezi i v dry-run (expirace je jen DB operace).
fn spawn_ops_sweep(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let state = state.clone();
            let outcome =
                tokio::task::spawn_blocking(move || -> crate::Result<ops::SweepReport> {
                    let store = ops_store(&state)?;
                    store.sweep(
                        state.ops.config.mode,
                        state.ops.executor.as_ref(),
                        Utc::now(),
                    )
                })
                .await;
            match outcome {
                Ok(Ok(report)) if report != ops::SweepReport::default() => {
                    tracing::info!(?report, "ops sweep zmenil stav");
                }
                Ok(Ok(_)) => {}
                Ok(Err(error)) => tracing::warn!(%error, "ops sweep selhal"),
                Err(error) => tracing::warn!(%error, "ops sweep task spadl"),
            }
        }
    });
}

async fn get_enforcement_actions(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(error) = authorize_for(&headers, &state, &["enforcement.read"]) {
        return pair_to_response(error);
    }
    let mode = state.ops.config.mode;
    let worker_state = state.clone();
    match run_blocking(move || {
        let store = ops_store(&worker_state)?;
        store.sweep(mode, worker_state.ops.executor.as_ref(), Utc::now())?;
        store.list_actions()
    })
    .await
    {
        Ok(actions) => {
            Json(serde_json::json!({ "mode": mode, "actions": actions })).into_response()
        }
        Err(response) => response,
    }
}

#[derive(Debug, Deserialize)]
struct ProposeBody {
    ip: String,
    ttl_seconds: u64,
    reason: String,
    #[serde(default)]
    finding_id: Option<String>,
}

async fn post_enforcement_propose(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ProposeBody>,
) -> Response {
    let auth = match authorize_for(&headers, &state, &["enforcement.write"]) {
        Ok(auth) => auth,
        Err(error) => return pair_to_response(error),
    };
    if let Err(error) = ensure_csrf_guard_header(&auth, &headers) {
        return pair_to_response(error);
    }
    let worker_state = state.clone();
    let actor = auth.subject.clone();
    let request = BlockIpRequest {
        ip: body.ip,
        ttl_seconds: body.ttl_seconds,
        reason: body.reason,
        finding_id: body.finding_id,
    };
    match run_blocking(move || {
        ops_store(&worker_state)?.propose(&request, &worker_state.ops.config.protected, &actor)
    })
    .await
    {
        Ok(Ok(action)) => (StatusCode::CREATED, Json(action)).into_response(),
        Ok(Err(ProposeError::Rejected(rejection))) => {
            let name = match rejection {
                EnforcementRejection::UnparseableIp => "UnparseableIp",
                EnforcementRejection::ProtectedRange => "ProtectedRange",
                EnforcementRejection::TtlExceedsMaximum => "TtlExceedsMaximum",
            };
            error_response(StatusCode::UNPROCESSABLE_ENTITY, name)
        }
        Ok(Err(ProposeError::AlreadyActive)) => {
            error_response(StatusCode::UNPROCESSABLE_ENTITY, "AlreadyActive")
        }
        Err(response) => response,
    }
}

async fn decide_enforcement(
    state: AppState,
    headers: HeaderMap,
    id: i64,
    approve: bool,
) -> Response {
    let auth = match authorize_for(&headers, &state, &["enforcement.approve"]) {
        Ok(auth) => auth,
        Err(error) => return pair_to_response(error),
    };
    if let Err(error) = ensure_csrf_guard_header(&auth, &headers) {
        return pair_to_response(error);
    }
    let actor = auth.subject.clone();
    let worker_state = state.clone();
    match run_blocking(move || {
        let store = ops_store(&worker_state)?;
        let decided = store.decide(id, approve, &actor)?;
        if let Some(finding_id) = decided.finding_id.as_deref() {
            // Rozhodnuti operatora je (slabsi) dukaz o nalezu; selhani zapisu
            // pameti nesmi zablokovat samotne rozhodnuti.
            let outcome = if approve {
                case_memory::Outcome::Confirmed
            } else {
                case_memory::Outcome::Refuted
            };
            if let Err(error) =
                record_finding_case(&worker_state, None, finding_id, outcome, 0.5, &actor)
            {
                tracing::warn!(%error, finding_id, "zapis Case Memory z rozhodnuti o zasahu selhal");
            }
        }
        if approve {
            store.apply_approved(
                id,
                worker_state.ops.config.mode,
                &worker_state.ops.config.protected,
                worker_state.ops.executor.as_ref(),
                &actor,
            )
        } else {
            Ok(decided)
        }
    })
    .await
    {
        Ok(action) => Json(action).into_response(),
        Err(response) => response,
    }
}

async fn post_enforcement_approve(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    decide_enforcement(state, headers, id, true).await
}

async fn post_enforcement_reject(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    decide_enforcement(state, headers, id, false).await
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    limit: Option<usize>,
}

async fn get_audit(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(error) = authorize_for(&headers, &state, &["audit.read"]) {
        return pair_to_response(error);
    }
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    match run_blocking(move || ops_store(&state)?.audit_list(limit)).await {
        Ok(entries) => Json(entries).into_response(),
        Err(response) => response,
    }
}

// --- Case Memory: verdikt operatora k nalezu --------------------------------------

/// Najde typ nalezu v konkretnim behu (`run_id`) nebo, kdyz neni zadan, v nejnovejsim.
fn finding_type_of(
    state: &AppState,
    run_id: Option<&str>,
    finding_id: &str,
) -> crate::Result<Option<String>> {
    let workspace = Workspace::open(&state.workspace_root)?;
    let run_id = match run_id {
        Some(run_id) => run_id.to_string(),
        None => match workspace.list_runs()?.first() {
            Some(entry) => entry.run_id.clone(),
            None => return Ok(None),
        },
    };
    let report = workspace.load_report(&run_id)?;
    Ok(report
        .findings
        .iter()
        .find(|finding| finding.finding_id == finding_id)
        .map(|finding| finding.finding_type.clone()))
}

/// Zapise operatorsky dukaz do Case Memory (pod zamkem) a audit. `None` = nalez
/// nenalezen (nic se nezapise).
fn record_finding_case(
    state: &AppState,
    run_id: Option<&str>,
    finding_id: &str,
    outcome: case_memory::Outcome,
    weight: f64,
    actor: &str,
) -> crate::Result<Option<(case_memory::RecordOutcome, Option<case_memory::Estimate>)>> {
    let Some(finding_type) = finding_type_of(state, run_id, finding_id)? else {
        return Ok(None);
    };
    let record = CaseRecord::new(
        &finding_type,
        None,
        outcome,
        CaseSource::Operator {
            actor: actor.to_string(),
        },
        weight,
        Utc::now(),
    );
    let (recorded, estimate) =
        CaseMemory::update(&state.workspace_root.join("case-memory.json"), |memory| {
            let recorded = memory.record(record);
            (recorded, memory.estimate(&finding_type))
        })?;
    ops_store(state)?.audit(
        actor,
        "finding.verdict",
        finding_id,
        &format!("{finding_type} {outcome:?} weight={weight} -> {recorded:?}"),
    )?;
    Ok(Some((recorded, estimate)))
}

#[derive(Debug, Deserialize)]
struct VerdictBody {
    verdict: String,
}

async fn post_finding_verdict(
    State(state): State<AppState>,
    Path((run_id, finding_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<VerdictBody>,
) -> Response {
    let auth = match authorize_for(&headers, &state, &["findings.write"]) {
        Ok(auth) => auth,
        Err(error) => return pair_to_response(error),
    };
    if let Err(error) = ensure_csrf_guard_header(&auth, &headers) {
        return pair_to_response(error);
    }
    if !crate::storage::is_valid_run_id(&run_id) {
        return error_response(StatusCode::BAD_REQUEST, "Neplatny run_id.");
    }
    let outcome = match body.verdict.as_str() {
        "confirmed" => case_memory::Outcome::Confirmed,
        "refuted" => case_memory::Outcome::Refuted,
        _ => {
            return error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "verdict musi byt 'confirmed' nebo 'refuted'",
            );
        }
    };
    let actor = auth.subject.clone();
    match run_blocking(move || {
        record_finding_case(&state, Some(&run_id), &finding_id, outcome, 1.0, &actor)
    })
    .await
    {
        Ok(Some((recorded, estimate))) => {
            let status = match recorded {
                case_memory::RecordOutcome::Accepted => "accepted".to_string(),
                case_memory::RecordOutcome::Quarantined(reason) => {
                    format!("quarantined:{reason:?}")
                }
            };
            Json(serde_json::json!({ "recorded": status, "estimate": estimate })).into_response()
        }
        Ok(None) => error_response(StatusCode::NOT_FOUND, "Nalez v tomto behu neexistuje."),
        Err(response) => response,
    }
}

/// Krok 7 (A3): stav provozního auditu automatických uzavření a čekající vzorky.
async fn get_closure_audit(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(error) = authorize_for(&headers, &state, &["runs.read"]) {
        return pair_to_response(error);
    }
    let root = state.workspace_root.clone();
    match run_blocking(move || {
        let store = crate::engine_state::EngineStateStore::open(&root.join("engine-state.sqlite"))?;
        let audit: crate::closure_audit::ClosureAudit =
            store.load("closure_audit")?.unwrap_or_default();
        let policy = crate::closure_audit::AuditPolicy::load(&root)?;
        let now = Utc::now();
        Ok(serde_json::json!({
            "status": audit.status(&policy, now),
            "policy": policy,
            "samples": audit.samples,
            "note": "Vypnuti druhu znamena dolni mez Wilsonova intervalu omylu nad cilem; nevypnuty druh nema prokazanou chybovost pod cilem.",
        }))
    })
    .await
    {
        Ok(value) => Json(value).into_response(),
        Err(response) => response,
    }
}

#[derive(Debug, Deserialize)]
struct ClosureReviewBody {
    wrong: bool,
    #[serde(default)]
    note: String,
}

/// Krok 7 (A3): ověřený verdikt člověka ke vzorku zavření (započte se při dalším běhu).
async fn post_closure_review(
    State(state): State<AppState>,
    Path(id): Path<u64>,
    headers: HeaderMap,
    Json(body): Json<ClosureReviewBody>,
) -> Response {
    let auth = match authorize_for(&headers, &state, &["findings.write"]) {
        Ok(auth) => auth,
        Err(error) => return pair_to_response(error),
    };
    if let Err(error) = ensure_csrf_guard_header(&auth, &headers) {
        return pair_to_response(error);
    }
    let root = state.workspace_root.clone();
    let actor = auth.subject.clone();
    match run_blocking(move || {
        let store = crate::engine_state::EngineStateStore::open(&root.join("engine-state.sqlite"))?;
        let audit: crate::closure_audit::ClosureAudit =
            store.load("closure_audit")?.unwrap_or_default();
        if !audit.samples.iter().any(|s| s.id == id) {
            return Ok(None);
        }
        crate::closure_audit::submit_review(
            store.conn(),
            id,
            body.wrong,
            &actor,
            &body.note,
            Utc::now(),
        )
        .map(Some)
    })
    .await
    {
        Ok(Some(row)) => Json(serde_json::json!({ "recorded": row })).into_response(),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "Vzorek neexistuje nebo uz byl posouzen.",
        ),
        Err(response) => response,
    }
}

#[derive(Debug, Deserialize)]
struct NoteBody {
    #[serde(default)]
    note: String,
}

/// Krok 7 (A3): člověk vrací trvale vypnutý druh automatického zavírání do provozu.
async fn post_closure_enable(
    State(state): State<AppState>,
    Path(kind): Path<String>,
    headers: HeaderMap,
    Json(body): Json<NoteBody>,
) -> Response {
    let auth = match authorize_for(&headers, &state, &["findings.write"]) {
        Ok(auth) => auth,
        Err(error) => return pair_to_response(error),
    };
    if let Err(error) = ensure_csrf_guard_header(&auth, &headers) {
        return pair_to_response(error);
    }
    if kind != crate::closure_audit::LADDER_KIND
        && crate::context_gate::ContextKind::from_label(&kind).is_none()
    {
        return error_response(StatusCode::UNPROCESSABLE_ENTITY, "Neznamy druh zavirani.");
    }
    let root = state.workspace_root.clone();
    let actor = auth.subject.clone();
    match run_blocking(move || {
        let store = crate::engine_state::EngineStateStore::open(&root.join("engine-state.sqlite"))?;
        crate::closure_audit::submit_enable(store.conn(), &kind, &actor, &body.note, Utc::now())
    })
    .await
    {
        Ok(row) => Json(serde_json::json!({ "recorded": row })).into_response(),
        Err(response) => response,
    }
}

#[derive(Debug, Deserialize)]
struct ConsentBody {
    host: String,
    peer: String,
    proto: String,
    port: u16,
    days: i64,
    #[serde(default)]
    note: String,
}

#[derive(Debug, Deserialize)]
struct EndpointIngestQuery {
    format: String,
}

/// Krok 8: příjem koncových událostí (JSONL, `?format=sysmon|wazuh|osquery`). Vstup je
/// nedůvěryhodný: limity dávky, řádku a stáří, deduplikace; identita se řeší až v enginu.
async fn post_endpoint_ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<EndpointIngestQuery>,
    body: String,
) -> Response {
    let auth = match authorize_for(&headers, &state, &["findings.write"]) {
        Ok(auth) => auth,
        Err(error) => return pair_to_response(error),
    };
    if let Err(error) = ensure_csrf_guard_header(&auth, &headers) {
        return pair_to_response(error);
    }
    let format: crate::endpoint::Format = match query.format.parse() {
        Ok(format) => format,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, message),
    };
    let root = state.workspace_root.clone();
    match run_blocking(move || {
        let mut store =
            crate::engine_state::EngineStateStore::open(&root.join("engine-state.sqlite"))?;
        crate::endpoint::persist::ingest_text(
            store.conn_mut(),
            format,
            &body,
            Utc::now(),
            &crate::endpoint::correlate::Limits::default(),
        )
    })
    .await
    {
        Ok(summary) => Json(summary).into_response(),
        Err(response) => response,
    }
}

/// Krok 7 (B5): úzký expirující souhlas s novou vazbou ven (nejvýš 30 dní).
async fn post_novelty_consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ConsentBody>,
) -> Response {
    let auth = match authorize_for(&headers, &state, &["findings.write"]) {
        Ok(auth) => auth,
        Err(error) => return pair_to_response(error),
    };
    if let Err(error) = ensure_csrf_guard_header(&auth, &headers) {
        return pair_to_response(error);
    }
    let root = state.workspace_root.clone();
    let actor = auth.subject.clone();
    match run_blocking(move || {
        let store = crate::engine_state::EngineStateStore::open(&root.join("engine-state.sqlite"))?;
        crate::novelty_consent::grant(
            store.conn(),
            &body.host,
            &body.peer,
            &body.proto,
            body.port,
            body.days,
            &actor,
            &body.note,
            Utc::now(),
        )
    })
    .await
    {
        Ok(expires) => Json(serde_json::json!({ "expires": expires })).into_response(),
        Err(response) => response,
    }
}

async fn get_audit_verify(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(error) = authorize_for(&headers, &state, &["audit.read"]) {
        return pair_to_response(error);
    }
    match run_blocking(move || ops_store(&state)?.verify_audit_chain()).await {
        Ok(ok) => Json(serde_json::json!({ "chain_ok": ok })).into_response(),
        Err(response) => response,
    }
}

fn to_http_error(error: crate::SalticusError) -> (StatusCode, String) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("Chyba serveru: {error}"),
    )
}

async fn resolve_runtime_status(
    state: &AppState,
) -> crate::Result<automation::RuntimeAutomationStatus> {
    let mut running = false;
    {
        let mut guard = state.automation_process.lock().await;
        if let Some(process) = guard.as_mut() {
            match process.child.try_wait() {
                Ok(None) => {
                    running = true;
                }
                Ok(Some(exit)) => {
                    if !exit.success() {
                        let message = format!(
                            "Autopilot ukončen s chybou. Start: {}.",
                            process.started_at.to_rfc3339()
                        );
                        let _ = automation::fail_runtime(&state.workspace_root, &message);
                    }
                    *guard = None;
                }
                Err(error) => {
                    let _ = automation::fail_runtime(
                        &state.workspace_root,
                        &format!("Nelze ověřit stav autopilota: {error}"),
                    );
                    *guard = None;
                }
            }
        }
    }
    let mut status = automation::load_runtime_status(&state.workspace_root)?;
    status.process_running = running;
    Ok(status)
}

fn build_restart_command(
    workspace_root: &FsPath,
    report: &RunReport,
) -> crate::Result<Vec<String>> {
    let mut command = vec![
        "autopilot".to_string(),
        "spust".to_string(),
        "--workspace".to_string(),
        workspace_root.display().to_string(),
        "--nazev".to_string(),
        base_run_name(&report.run.nazev),
        "--scope".to_string(),
        report
            .run
            .scope
            .iter()
            .map(|item| item.to_string())
            .collect::<Vec<_>>()
            .join(","),
        "--ports".to_string(),
        report
            .run
            .ports
            .iter()
            .map(|item| item.to_string())
            .collect::<Vec<_>>()
            .join(","),
        "--profile".to_string(),
        report.run.profile.clone(),
        "--provider".to_string(),
        report.run.provider.clone(),
        "--cycles".to_string(),
        "1".to_string(),
    ];

    if report.run.enrichment_mode == "freeze" {
        command.push("--freeze".to_string());
    }
    if report.run.sources.nmap_mode.as_deref() == Some("live") {
        command.push("--spustit-nmap".to_string());
    } else if let Some(path) = existing_string_path(report.run.sources.nmap_xml.as_deref()) {
        command.push("--nmap-xml".to_string());
        command.push(path);
    } else {
        command.push("--spustit-nmap".to_string());
    }

    push_existing_path_arg(
        &mut command,
        "--suricata-eve",
        report.run.sources.suricata_eve.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--zeek-dir",
        report.run.sources.zeek_dir.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--snmp-snapshot",
        report.run.sources.snmp_snapshot.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--librenms-snapshot",
        report.run.sources.librenms_snapshot.as_deref(),
    );
    if let Some(url) = report.run.sources.librenms_base_url.as_deref() {
        command.push("--librenms-base-url".to_string());
        command.push(url.to_string());
    }
    push_existing_path_arg(
        &mut command,
        "--meraki-snapshot",
        report.run.sources.meraki_snapshot.as_deref(),
    );
    if let Some(value) = report.run.sources.meraki_network_id.as_deref() {
        command.push("--meraki-network-id".to_string());
        command.push(value.to_string());
    }
    push_existing_path_arg(
        &mut command,
        "--unifi-snapshot",
        report.run.sources.unifi_snapshot.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--aruba-snapshot",
        report.run.sources.aruba_snapshot.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--omada-snapshot",
        report.run.sources.omada_snapshot.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--ntopng-snapshot",
        report.run.sources.ntopng_snapshot.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--flow-snapshot",
        report.run.sources.flow_snapshot.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--greenbone-report",
        report.run.sources.greenbone_report.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--wazuh-report",
        report.run.sources.wazuh_report.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--napalm-snapshot",
        report.run.sources.napalm_snapshot.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--netmiko-snapshot",
        report.run.sources.netmiko_snapshot.as_deref(),
    );
    push_existing_path_arg(
        &mut command,
        "--scrapli-snapshot",
        report.run.sources.scrapli_snapshot.as_deref(),
    );

    let web_lane_sources = report
        .monitoring_lanes
        .iter()
        .map(|lane| lane.source.as_str())
        .collect::<Vec<_>>();
    if report.summary.web_probes_total > 0 || web_lane_sources.contains(&"httpx") {
        command.push("--web-fingerprint".to_string());
    }
    if report.summary.active_checks_total > 0 || web_lane_sources.contains(&"nuclei") {
        command.push("--web-checks".to_string());
    }
    if web_lane_sources.contains(&"internal-pentest") {
        command.push("--pentest".to_string());
        if report
            .monitoring_lanes
            .iter()
            .find(|lane| lane.source == "internal-pentest")
            .is_some_and(|lane| lane.evidence.iter().any(|item| item == "mode=aggressive"))
        {
            command.push("--aggressive-pentest".to_string());
        }
    }

    let httpx = paths::project_path(&["tools", "projectdiscovery", "httpx", "httpx.exe"]);
    if httpx.exists() {
        command.push("--httpx-bin".to_string());
        command.push(httpx.display().to_string());
    }
    let nuclei = paths::project_path(&["tools", "projectdiscovery", "nuclei", "nuclei.exe"]);
    if nuclei.exists() {
        command.push("--nuclei-bin".to_string());
        command.push(nuclei.display().to_string());
    }
    let nuclei_templates = paths::project_path(&["resources", "nuclei-templates", "controlled"]);
    if nuclei_templates.exists() {
        command.push("--nuclei-templates".to_string());
        command.push(nuclei_templates.display().to_string());
    }

    Ok(command)
}

fn apply_restart_pentest_options(command: &mut Vec<String>, options: &AutomationRestartOptions) {
    let Some(mode) = options.pentest.as_deref() else {
        return;
    };
    match mode.trim().to_ascii_lowercase().as_str() {
        "smart" | "safe" | "on" | "true" => {
            push_flag_once(command, "--pentest");
        }
        "aggressive" | "hard" => {
            push_flag_once(command, "--pentest");
            push_flag_once(command, "--aggressive-pentest");
        }
        _ => {}
    }
}

fn push_flag_once(command: &mut Vec<String>, flag: &str) {
    if !command.iter().any(|item| item == flag) {
        command.push(flag.to_string());
    }
}

fn push_existing_path_arg(command: &mut Vec<String>, flag: &str, value: Option<&str>) {
    if let Some(path) = existing_string_path(value) {
        command.push(flag.to_string());
        command.push(path);
    }
}

fn existing_string_path(value: Option<&str>) -> Option<String> {
    let path = PathBuf::from(value?);
    path.exists().then(|| path.display().to_string())
}

fn base_run_name(value: &str) -> String {
    value
        .rsplit_once(" / cyklus ")
        .map(|(base, _)| base.to_string())
        .unwrap_or_else(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state(workspace_root: PathBuf) -> AppState {
        AppState {
            workspace_root: Arc::new(workspace_root),
            started_at: Utc::now(),
            auth_required: false,
            api_token: Arc::new(None),
            platform_db: Arc::new(None),
            automation_process: Arc::new(Mutex::new(None)),
            ops: Arc::new(OpsRuntime::from_env()),
        }
    }

    fn csrf_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-salticus-csrf", HeaderValue::from_static("1"));
        headers
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    fn propose_body(ip: &str) -> Json<ProposeBody> {
        Json(ProposeBody {
            ip: ip.to_string(),
            ttl_seconds: 300,
            reason: "test".to_string(),
            finding_id: None,
        })
    }

    #[tokio::test]
    async fn enforcement_propose_requires_csrf_header_for_anonymous_admin() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let state = test_state(temp.path().to_path_buf());
        let response =
            post_enforcement_propose(State(state), HeaderMap::new(), propose_body("203.0.113.5"))
                .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn enforcement_propose_of_loopback_is_422_protected_range() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let state = test_state(temp.path().to_path_buf());
        let response =
            post_enforcement_propose(State(state), csrf_headers(), propose_body("127.0.0.1")).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body_json(response).await["error"], "ProtectedRange");
    }

    #[tokio::test]
    async fn enforcement_approve_in_dry_run_never_reaches_applied() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let state = test_state(temp.path().to_path_buf());
        assert_eq!(state.ops.config.mode, ops::EnforcementMode::DryRun);

        let created = post_enforcement_propose(
            State(state.clone()),
            csrf_headers(),
            propose_body("203.0.113.5"),
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let id = body_json(created).await["id"].as_i64().expect("id");

        let approved =
            post_enforcement_approve(State(state.clone()), Path(id), csrf_headers()).await;
        assert_eq!(approved.status(), StatusCode::OK);
        assert_eq!(body_json(approved).await["status"], "approved");

        let audit = get_audit(
            State(state),
            Query(AuditQuery { limit: Some(20) }),
            HeaderMap::new(),
        )
        .await;
        let entries = body_json(audit).await;
        let actions: Vec<&str> = entries
            .as_array()
            .expect("array")
            .iter()
            .filter_map(|entry| entry["action"].as_str())
            .collect();
        assert!(actions.contains(&"enforcement.dry_run"), "{actions:?}");
        assert!(actions.contains(&"enforcement.proposed"));
    }

    #[tokio::test]
    async fn enforcement_approve_requires_csrf_header_for_anonymous_admin() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let state = test_state(temp.path().to_path_buf());
        let response = post_enforcement_approve(State(state), Path(1), HeaderMap::new()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn metrics_include_enforcement_mode_and_action_counts() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let state = test_state(temp.path().to_path_buf());
        let _ = post_enforcement_propose(
            State(state.clone()),
            csrf_headers(),
            propose_body("203.0.113.7"),
        )
        .await;
        let text = render_ops_metrics(&state);
        assert!(text.contains("salticus_enforcement_mode{mode=\"dry_run\"} 1"));
        assert!(text.contains("salticus_enforcement_actions{status=\"proposed\"} 1"));
        assert!(text.contains("salticus_ops_up 1"));
    }

    fn seed_run_with_finding(workspace: &std::path::Path) -> (String, String) {
        use crate::model::{Confidence, Finding, Severity};
        let now = Utc::now();
        let mut report = crate::report::build_report(
            "verdict-test",
            "verdict-test",
            now,
            now,
            Vec::new(),
            Vec::new(),
            "t",
            "t",
            "passive-only",
            crate::model::PassiveWindow {
                start: now,
                end: now,
                time_window_s: 300,
            },
            crate::model::SourceMetadata::default(),
            Vec::new(),
            Vec::new(),
        );
        report.findings.push(Finding {
            finding_id: "finding:verdict:1".to_string(),
            finding_type: "management_surface_exposure".to_string(),
            title: "t".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            host_key: Some("10.0.0.1".to_string()),
            service_key: None,
            rationale: "r".to_string(),
            evidence: Vec::new(),
            recommendation: "x".to_string(),
        });
        let run_id = report.run.run_id.clone();
        let dir = workspace.join("runs").join(&run_id);
        std::fs::create_dir_all(&dir).expect("run dir");
        std::fs::write(
            dir.join("report.json"),
            serde_json::to_string(&report).expect("json"),
        )
        .expect("write report");
        let index = serde_json::json!({ "runs": [{
            "run_id": run_id,
            "nazev": "verdict-test",
            "created_at": now,
            "scope": [],
            "hosts_total": 0,
            "services_total": 0,
            "cves_total": 0,
            "events_total": 0
        }]});
        std::fs::write(workspace.join("runs").join("index.json"), index.to_string())
            .expect("write index");
        (run_id, "finding:verdict:1".to_string())
    }

    #[tokio::test]
    async fn verdict_requires_csrf_header_for_anonymous_admin() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let state = test_state(temp.path().to_path_buf());
        let response = post_finding_verdict(
            State(state),
            Path(("run-x".to_string(), "finding:1".to_string())),
            HeaderMap::new(),
            Json(VerdictBody {
                verdict: "confirmed".to_string(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn verdict_rejects_unknown_value_and_unknown_finding() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let state = test_state(temp.path().to_path_buf());
        let (run_id, finding_id) = seed_run_with_finding(temp.path());

        let bad = post_finding_verdict(
            State(state.clone()),
            Path((run_id.clone(), finding_id.clone())),
            csrf_headers(),
            Json(VerdictBody {
                verdict: "maybe".to_string(),
            }),
        )
        .await;
        assert_eq!(bad.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let missing = post_finding_verdict(
            State(state),
            Path((run_id, "finding:neexistuje".to_string())),
            csrf_headers(),
            Json(VerdictBody {
                verdict: "confirmed".to_string(),
            }),
        )
        .await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn verdict_is_recorded_in_case_memory_and_audit_log() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let state = test_state(temp.path().to_path_buf());
        let (run_id, finding_id) = seed_run_with_finding(temp.path());

        let response = post_finding_verdict(
            State(state.clone()),
            Path((run_id, finding_id)),
            csrf_headers(),
            Json(VerdictBody {
                verdict: "confirmed".to_string(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["recorded"], "accepted");

        let memory = CaseMemory::load_or_default(&temp.path().join("case-memory.json"));
        assert_eq!(memory.accepted_len(), 1);
        let audit = get_audit(
            State(state),
            Query(AuditQuery { limit: Some(20) }),
            HeaderMap::new(),
        )
        .await;
        let entries = body_json(audit).await;
        assert!(
            entries
                .as_array()
                .expect("array")
                .iter()
                .any(|entry| entry["action"] == "finding.verdict")
        );
    }

    #[tokio::test]
    async fn enforcement_approve_and_reject_with_finding_record_weak_cases() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let state = test_state(temp.path().to_path_buf());
        let (_run_id, finding_id) = seed_run_with_finding(temp.path());

        for (ip, approve) in [("203.0.113.21", true), ("203.0.113.22", false)] {
            let body = Json(ProposeBody {
                ip: ip.to_string(),
                ttl_seconds: 300,
                reason: "t".to_string(),
                finding_id: Some(finding_id.clone()),
            });
            let created =
                post_enforcement_propose(State(state.clone()), csrf_headers(), body).await;
            let id = body_json(created).await["id"].as_i64().expect("id");
            let response = if approve {
                post_enforcement_approve(State(state.clone()), Path(id), csrf_headers()).await
            } else {
                post_enforcement_reject(State(state.clone()), Path(id), csrf_headers()).await
            };
            assert_eq!(response.status(), StatusCode::OK);
        }
        let memory = CaseMemory::load_or_default(&temp.path().join("case-memory.json"));
        assert_eq!(memory.accepted_len(), 2);
    }

    #[tokio::test]
    async fn enforcement_without_finding_id_leaves_case_memory_untouched() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let state = test_state(temp.path().to_path_buf());
        let created = post_enforcement_propose(
            State(state.clone()),
            csrf_headers(),
            propose_body("203.0.113.30"),
        )
        .await;
        let id = body_json(created).await["id"].as_i64().expect("id");
        let _ = post_enforcement_reject(State(state), Path(id), csrf_headers()).await;
        assert!(!temp.path().join("case-memory.json").exists());
    }

    #[tokio::test]
    async fn audit_verify_reports_intact_chain() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let state = test_state(temp.path().to_path_buf());
        let _ = post_enforcement_propose(
            State(state.clone()),
            csrf_headers(),
            propose_body("203.0.113.9"),
        )
        .await;
        let response = get_audit_verify(State(state), HeaderMap::new()).await;
        assert_eq!(body_json(response).await["chain_ok"], true);
    }

    #[test]
    fn constant_time_eq_accepts_identical_tokens() {
        assert!(constant_time_eq("tajny-token-123", "tajny-token-123"));
    }

    #[test]
    fn constant_time_eq_rejects_same_length_different_token() {
        assert!(!constant_time_eq("tajny-token-123", "tajny-token-124"));
    }

    #[test]
    fn constant_time_eq_rejects_different_length_token() {
        assert!(!constant_time_eq("kratky", "mnohem-delsi-token"));
    }

    #[test]
    fn constant_time_eq_rejects_empty_against_nonempty() {
        assert!(!constant_time_eq("", "neprazdny"));
    }

    #[test]
    fn ensure_csrf_guard_header_rejects_anonymous_requests_without_custom_header() {
        let headers = HeaderMap::new();
        let anonymous = admin_context("anonymous-admin");
        let error = ensure_csrf_guard_header(&anonymous, &headers)
            .expect_err("anonymni pozadavek bez hlavicky musi selhat");
        assert_eq!(error.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn ensure_csrf_guard_header_accepts_anonymous_requests_with_custom_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-salticus-csrf", HeaderValue::from_static("1"));
        let anonymous = admin_context("anonymous-admin");
        assert!(ensure_csrf_guard_header(&anonymous, &headers).is_ok());
    }

    /// Regrese po nasazeni (30.10.2026): token-autentizovany pozadavek nesmi
    /// vyzadovat CSRF hlavicku - bearer token sam o sobe uz je CSRF-imunni,
    /// a `server_respektuje_api_token` (tests/e2e.rs) pravem ocekava 200 bez ni.
    #[test]
    fn ensure_csrf_guard_header_accepts_token_authenticated_requests_without_custom_header() {
        let headers = HeaderMap::new();
        let token_authenticated = admin_context("static-admin");
        assert!(ensure_csrf_guard_header(&token_authenticated, &headers).is_ok());
    }

    /// Audit nalez (30.10.2026, produkcni gap analyza): `require_api_token=false`
    /// (vychozi) dela z kazdeho pozadavku anonymniho admina - bez CSRF hlidky by
    /// obycejny cross-site `<form method=POST>` tise spustil aktivni sken proti
    /// nakonfigurovanemu scope. Test overuje, ze se odmitnuti stane PRED jakymkoliv
    /// pristupem k workspace (ne ze by nahodou selhalo na "zadny beh ve workspace").
    #[tokio::test]
    async fn post_automation_restart_rejects_request_without_csrf_header() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let state = test_state(temp.path().to_path_buf());

        let response = post_automation_restart(
            State(state),
            Query(AutomationRestartOptions::default()),
            HeaderMap::new(),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_automation_reset_rejects_request_without_csrf_header() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let state = test_state(temp.path().to_path_buf());

        let response = post_automation_reset(State(state), HeaderMap::new())
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// Audit nalez (30.10.2026, produkcni gap analyza): `run_id` z URL cesty
    /// sel primo do `Path::join` bez validace - path traversal na libovolny
    /// `report.*` soubor kdekoliv na disku, dosazitelne i bez tokenu v
    /// defaultni konfiguraci (`auth_required=false`). Tenhle test vola
    /// handler primo, ne pres skutecny TCP server.
    #[tokio::test]
    async fn get_run_export_rejects_path_traversal_run_id() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let state = test_state(temp.path().to_path_buf());

        let response = get_run_export(
            Path(("../../../../etc/passwd".to_string(), "json".to_string())),
            State(state),
            HeaderMap::new(),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_run_export_rejects_unknown_format_before_touching_run_id() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let state = test_state(temp.path().to_path_buf());

        let response = get_run_export(
            Path(("run-20261030201943-1-abc123".to_string(), "exe".to_string())),
            State(state),
            HeaderMap::new(),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
