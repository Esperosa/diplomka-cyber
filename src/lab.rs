//! Prvni realny aktivni-overovaci lab cil (Deliverable 7), navazuje na Deliverable 5
//! (`verification_planner.rs` - VOI SELEKCE kandidatu, zatim bez EXEKUCE).
//!
//! Navrh (sekce 8.2) doporucuje Mininet/Containerlab pro sitovou topologii, ale plna
//! network-namespace emulace je velka infrastrukturni investice (WSL2 + Linux network
//! namespace capabilities). Tento krok je vedomy predstupen: overit, ze aktivni
//! overeni (`nmap.rs` + `webscan.rs`) vubec funguje end-to-end proti realnemu,
//! autorizovanemu cili, nez se investuje do plne topologicke emulace. Mininet/
//! Containerlab prijde az ve chvili, kdy bude potreba testovat topologii/segmentaci
//! (vice hostu, VLAN, firewall pravidla) - ne pro "sken jednoho vlastniho kontejneru
//! na localhostu".
//!
//! **Lab cil: OWASP Juice Shop** (`bkimminich/juice-shop`) - zamerne zranitelna
//! aplikace, explicitne urcena ke skenovani (navrh sekce 8.2 ji jmenuje primo).
//! Container bezi jen na `127.0.0.1`, zadna externi expozice, vlastni Docker instance -
//! zadne povoleni treti strany potrebne.
//!
//! **Deliverable 8 doplnila `build_hypotheses_from_lab_scan`**, ktera zavre smyckou:
//! lab sken -> `report::build_report`/`findings::generate_findings` (stejna nezmenena
//! produkcni logika jako vsude jinde) -> `hypothesis::build_hypothesis` pro kazdy
//! `Finding`. `verification_planner::plan_verification` se vola az v testu (ne v tomto
//! modulu) nad REALNE zmerenym nalezem (prometheus-metrics-exposed na Juice Shopu),
//! ne nad synteticky vymyslenym - poprve v cele diplomce je cely pipeline Observation
//! -> Finding -> Hypothesis -> Verification Planner demonstrovan na realnych datech.

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use chrono::Utc;

use crate::error::{BakulaError, Result};
use crate::findings::generate_findings;
use crate::hypothesis::{SecurityHypothesis, build_hypothesis};
use crate::identity::IdentityMatch;
use crate::model::{Finding, HostReport, PassiveWindow, RunReport, SourceMetadata};
use crate::nmap::{parse_nmap_xml, run_real_nmap};
use crate::report::normalize_inventory;
use crate::report::{build_report, score_services};
use crate::webscan::{WebScanArtifacts, WebScanConfig, enrich_http_services};

const JUICE_SHOP_IMAGE: &str = "bkimminich/juice-shop";
const JUICE_SHOP_PORT: u16 = 3000;

/// RAII: `docker rm -f` i kdyz test panikne. `stop_lab()` je explicitni cesta pro
/// happy-path cleanup o nic jina nez `drop(handle)` - cteni kodu je jasnejsi s
/// explicitnim nazvem na konci testu, i kdyz mechanicky dela totez co Drop.
pub struct LabHandle {
    container_name: String,
}

impl Drop for LabHandle {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container_name])
            .status();
    }
}

pub fn stop_lab(handle: LabHandle) {
    drop(handle);
}

/// Lab bezi vzdy na pevnem portu 3000 (Juice Shop uvnitr kontejneru na nem nasloucha).
/// Dusledek: testy v tomto modulu NESMI bezet paralelne (`cargo test -- --test-threads=1`
/// nebo spoustet jednotlive) - jinak si dva testy soutezi o stejny host port. To je
/// zdokumentovane omezeni, ne skryty predpoklad.
pub fn start_juice_shop_lab() -> Result<LabHandle> {
    let container_name = format!("bakula-lab-juiceshop-{}", uuid::Uuid::new_v4());
    let status = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &container_name,
            "-p",
            &format!("127.0.0.1:{JUICE_SHOP_PORT}:{JUICE_SHOP_PORT}"),
            JUICE_SHOP_IMAGE,
        ])
        .status()
        .map_err(|error| BakulaError::Processing(format!("docker run selhal: {error}")))?;
    if !status.success() {
        // `docker run` muze kontejner VYTVORIT (napr. v stavu "Created") i kdyz
        // selze start (napr. kolize portu) - bez LabHandle by nikdy neprobehl
        // cleanup a kontejner by osiral navzdy. Smazat ho tady eplicitne, driv
        // nez se vrati chyba.
        let _ = Command::new("docker")
            .args(["rm", "-f", &container_name])
            .status();
        return Err(BakulaError::Processing(
            "docker run pro juice-shop lab se nepodarilo spustit (mozna kolize portu 3000 - lab testy nesmi bezet paralelne).".to_string(),
        ));
    }

    let handle = LabHandle { container_name };
    if let Err(error) = wait_for_http_health(JUICE_SHOP_PORT, Duration::from_secs(30)) {
        drop(handle);
        return Err(error);
    }
    Ok(handle)
}

/// Cistý TCP connect NESTACI jako health-check pro HTTP aplikaci v kontejneru - port
/// muze prijimat spojeni drive, nez je aplikacni vrstva (napr. Node/Express) skutecne
/// pripravena odpovidat na pozadavky. Cekame na realnou HTTP odpoved.
fn wait_for_http_health(port: u16, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok()
            && reqwest::blocking::get(format!("http://127.0.0.1:{port}/"))
                .is_ok_and(|response| response.status().is_success())
        {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err(BakulaError::Processing(format!(
                "Lab cil 127.0.0.1:{port} nebyl HTTP-zdravy po {timeout:?}."
            )));
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

#[derive(Debug, Clone)]
pub struct LabScanResult {
    pub hosts: Vec<HostReport>,
    pub web_artifacts: WebScanArtifacts,
}

/// `httpx_bin`/`nuclei_bin` jsou explicitni cesty (ne spoleham na PATH) - prostredi
/// muze mit na PATH jiny `httpx` (napr. Python HTTP klient se stejnym nazvem), presne
/// tento mismatch byl pricinou predem zname nesouvisejici chyby v `tests/e2e.rs`.
pub fn run_active_scan_against_lab(
    workspace: &Path,
    run_id: &str,
    httpx_bin: PathBuf,
    nuclei_bin: PathBuf,
    nuclei_templates_dir: PathBuf,
) -> Result<LabScanResult> {
    let scope = vec!["127.0.0.1/32".parse().map_err(|error| {
        BakulaError::Processing(format!("neplatny scope 127.0.0.1/32: {error}"))
    })?];

    let xml_path = run_real_nmap(workspace, &scope, &[JUICE_SHOP_PORT], "opatrny")?;
    let parsed = parse_nmap_xml(&xml_path)?;
    let mut hosts = normalize_inventory(parsed);

    let web_config = WebScanConfig {
        enable_httpx: true,
        enable_nuclei: true,
        httpx_bin: Some(httpx_bin),
        nuclei_bin: Some(nuclei_bin),
        nuclei_templates_dir: Some(nuclei_templates_dir),
    };
    let web_artifacts = enrich_http_services(&mut hosts, workspace, run_id, &web_config)?;

    Ok(LabScanResult {
        hosts,
        web_artifacts,
    })
}

#[derive(Debug, Clone)]
pub struct LabPipelineResult {
    pub report: RunReport,
    /// Kazdy `Finding` z `report.findings` parovany se svou `SecurityHypothesis` -
    /// stejne poradi, stejna delka jako `report.findings`.
    pub hypotheses: Vec<(Finding, SecurityHypothesis)>,
}

/// Zavre smycku Observation -> Finding -> Hypothesis pres STEJNOU, NEZMENENOU
/// produkcni logiku (`score_services`/`build_report`/`generate_findings`) jako
/// kdekoliv jinde v projektu - lab sken se tu nijak nezvyhodnuje ani neobchazi.
/// Identita je `IdentityMatch::New` pro kazdy finding - zadna historie bezu pro
/// tenhle lab jeste neexistuje (jen jeden sken, ne sekvence jako v Deliverable 2).
pub fn build_hypotheses_from_lab_scan(
    scan: LabScanResult,
    run_id: &str,
) -> Result<LabPipelineResult> {
    let mut hosts = scan.hosts;
    score_services(&mut hosts);

    let now = Utc::now();
    let scope = vec!["127.0.0.1/32".parse().map_err(|error| {
        BakulaError::Processing(format!("neplatny scope 127.0.0.1/32: {error}"))
    })?];
    let mut report: RunReport = build_report(
        run_id,
        &format!("lab-pipeline:{run_id}"),
        now,
        now,
        scope,
        vec![JUICE_SHOP_PORT],
        "opatrny",
        "lab",
        "active-only",
        PassiveWindow {
            start: now,
            end: now,
            time_window_s: 0,
        },
        SourceMetadata::default(),
        hosts,
        Vec::new(),
    );
    report.findings = generate_findings(&report);

    let hypotheses = report
        .findings
        .iter()
        .map(|finding| {
            let asset_id = format!("asset:lab:{}", finding.host_key.clone().unwrap_or_default());
            let identity = IdentityMatch::New(asset_id);
            let hypothesis = build_hypothesis(finding, None, Some(&identity), None);
            (finding.clone(), hypothesis)
        })
        .collect();

    Ok(LabPipelineResult { report, hypotheses })
}

/// Vysledek skutecneho vykonani vybraneho `VerificationCandidate` - ne odhad, realna
/// data z realneho HTTP pozadavku.
#[derive(Debug, Clone)]
pub struct InspectionOutcome {
    pub status_code: u16,
    pub body_line_count: usize,
    /// Konkretni nazvy metrik, ktere vypadaji citlive/interni (ne jen "je endpoint
    /// dostupny" - to uz potvrdil nuclei nalez v Deliverable 7/8; tohle je DALSI
    /// informace, kterou vykonani kandidata ma prinest).
    pub sensitive_looking_metric_names: Vec<String>,
}

/// Vykona kandidata `"inspect_metrics_content"` vybraneho `plan_verification()` v
/// Deliverable 8 - prvni SKUTECNE provedena akce z planneru v cele diplomce, ne jen
/// jeho vyber. Zamerne jednoduche: GET na `/metrics`, bez dalsiho skenovani/nastroje -
/// presne odpovida odhadovanemu nizkemu `estimated_network_cost`/`estimated_runtime_ms`
/// kandidata, ktery kvuli temto odhadum vyhral v `plan_verification()`.
pub fn execute_inspect_metrics_content(base_url: &str) -> Result<InspectionOutcome> {
    let response = reqwest::blocking::get(format!("{base_url}/metrics"))
        .map_err(|error| BakulaError::Processing(format!("GET /metrics selhal: {error}")))?;
    let status_code = response.status().as_u16();
    let body = response.text().map_err(|error| {
        BakulaError::Processing(format!("cteni odpovedi /metrics selhalo: {error}"))
    })?;

    let sensitive_looking_metric_names = body
        .lines()
        .filter(|line| line.starts_with("# HELP"))
        .filter_map(|line| line.split_whitespace().nth(2))
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            lower.contains("token") || lower.contains("upload") || lower.contains("llm")
        })
        .map(ToString::to_string)
        .collect();

    Ok(InspectionOutcome {
        status_code,
        body_line_count: body.lines().count(),
        sensitive_looking_metric_names,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// `cargo test` spousti testy v ramci jednoho binary vicevlaknove by default -
    /// bez tohoto zamku by si dva lab testy soutezily o stejny host port 3000
    /// (presne tak se to stalo, nez byl tenhle zamek pridan). Zamek se drzi po celou
    /// dobu testu (`_guard` zivotnost), ne jen pri startu kontejneru.
    static LAB_PORT_LOCK: Mutex<()> = Mutex::new(());

    /// Cesty k realnym ProjectDiscovery binarkam (ne systemovy PATH - viz modulova
    /// dokumentace k mismatchi s jinym `httpx`). Prepsatelne env promennymi pro CI/jine
    /// stroje; vychozi odpovida tomu, kam byly binarky pro tuto session nainstalovany.
    fn httpx_bin() -> PathBuf {
        std::env::var("BAKULA_TEST_HTTPX_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(r"C:\Users\Creator\tools\projectdiscovery\httpx.exe"))
    }

    fn nuclei_bin() -> PathBuf {
        std::env::var("BAKULA_TEST_NUCLEI_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(r"C:\Users\Creator\tools\projectdiscovery\nuclei.exe")
            })
    }

    fn nuclei_templates_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("resources/nuclei-templates/controlled")
    }

    /// Prvni skutecny end-to-end test aktivniho overeni: nmap + httpx proti realnemu,
    /// vlastnimu, autorizovanemu cili (ne syntheticka fixtura, ne mock). Overuje
    /// KONKRETNI OBSAH vysledku (otevreny port, detekovana HTTP sluzba), ne jen "prikaz
    /// dobehl bez erroru".
    #[test]
    fn real_nmap_and_httpx_scan_finds_juice_shop_http_service() {
        let _guard = LAB_PORT_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let lab = start_juice_shop_lab().expect("start juice shop lab");

        let temp = tempfile::TempDir::new().expect("tempdir");
        let result = run_active_scan_against_lab(
            temp.path(),
            "lab-test-run",
            httpx_bin(),
            nuclei_bin(),
            nuclei_templates_dir(),
        );

        stop_lab(lab);
        let result = result.expect("aktivni sken proti lab cili");

        assert_eq!(
            result.hosts.len(),
            1,
            "nmap musi najit presne 1 host (127.0.0.1)"
        );
        let host = &result.hosts[0];
        assert_eq!(host.ip, "127.0.0.1");

        let port_3000 = host
            .services
            .iter()
            .find(|service| service.port == JUICE_SHOP_PORT)
            .expect("port 3000 musi byt v nmap vysledku nalezen jako otevreny");
        assert_eq!(port_3000.port_state, "open");

        // httpx musi skutecne probnout HTTP sluzbu - overujeme obsah JSONL vystupu,
        // ne jen ze soubor existuje.
        let httpx_output = result
            .web_artifacts
            .httpx_output_jsonl
            .as_ref()
            .expect("httpx musi vygenerovat JSONL vystup");
        assert!(
            httpx_output.to_ascii_lowercase().contains("juice"),
            "httpx vystup musi obsahovat stopu po Juice Shop titulku/obsahu, dostal jsem: {httpx_output}"
        );
    }

    /// PUVODNI PREDPOKLAD (moje i nezavisleho Plan-agent review pred implementaci) byl,
    /// ze z 8 kurátorovanych sablon (`resources/nuclei-templates/controlled/`, cilenych
    /// na exposed admin panely) nic na Juice Shopu nesedne, a 0 nalezu bude spravny
    /// nulovy vysledek. REALNE MERENI to vyvratilo: tahle verze Juice Shopu vystavuje
    /// neautentizovany Prometheus `/metrics` endpoint s realnymi aplikacnimi daty
    /// (potvrzeno rucne: `curl http://127.0.0.1:3000/metrics` vraci 200 a skutecne
    /// metriky). Test asertuje ZMERENOU realitu, ne predem predpokladany vysledek -
    /// presne to je duvod delat aktivni overeni, ne jen teoreticky odhadovat.
    #[test]
    fn nuclei_finds_real_exposed_prometheus_metrics_endpoint_on_juice_shop() {
        let _guard = LAB_PORT_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let lab = start_juice_shop_lab().expect("start juice shop lab");

        let temp = tempfile::TempDir::new().expect("tempdir");
        let result = run_active_scan_against_lab(
            temp.path(),
            "lab-test-run-nuclei",
            httpx_bin(),
            nuclei_bin(),
            nuclei_templates_dir(),
        );

        stop_lab(lab);
        let result = result.expect("aktivni sken proti lab cili");

        let nuclei_output = result
            .web_artifacts
            .nuclei_output_jsonl
            .as_deref()
            .unwrap_or("");
        assert!(
            nuclei_output.contains("prometheus-metrics-exposed"),
            "ocekavam realny nalez neautentizovaneho /metrics endpointu, dostal jsem: {nuclei_output}"
        );
    }

    /// Deliverable 8: poprve v cele diplomce cely pipeline Observation -> Finding ->
    /// Hypothesis -> Verification Planner demonstrovany spolu na REALNE zmerenem
    /// nalezu (ne synteticke fixture). `VerificationCandidate` cisla jsou poctive
    /// odhady (ne zmerena), proto se `plan_verification` nikde netvari, ze je to
    /// kalibrovane - presne stejna disciplina jako ve `verification_planner.rs` testech.
    #[test]
    fn full_pipeline_plans_next_verification_for_real_metrics_exposure_finding() {
        let _guard = LAB_PORT_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let lab = start_juice_shop_lab().expect("start juice shop lab");

        let temp = tempfile::TempDir::new().expect("tempdir");
        let scan = run_active_scan_against_lab(
            temp.path(),
            "lab-pipeline-run",
            httpx_bin(),
            nuclei_bin(),
            nuclei_templates_dir(),
        );

        stop_lab(lab);
        let scan = scan.expect("aktivni sken proti lab cili");
        let pipeline =
            build_hypotheses_from_lab_scan(scan, "lab-pipeline-run").expect("build hypotheses");

        let (finding, hypothesis) = pipeline
            .hypotheses
            .iter()
            .find(|(finding, _)| finding.finding_type.contains("prometheus-metrics-exposed"))
            .expect("pipeline musi vyprodukovat Finding pro realny nuclei nalez");

        assert_eq!(finding.severity, crate::model::Severity::Medium);
        // Nova identita (New) - zadna historie bezu pro tenhle lab jeste neexistuje.
        assert!(hypothesis.uncertainty.identity.is_some());

        let candidates = vec![
            crate::verification_planner::VerificationCandidate {
                method: "inspect_metrics_content".to_string(),
                estimated_information_gain: 0.6,
                estimated_network_cost: 0.02,
                estimated_runtime_ms: 500,
                disruption_risk: 0.0,
                requires_approval: false,
            },
            crate::verification_planner::VerificationCandidate {
                method: "broad_nuclei_rescan_full_template_set".to_string(),
                estimated_information_gain: 0.5,
                estimated_network_cost: 0.3,
                estimated_runtime_ms: 60_000,
                disruption_risk: 0.1,
                requires_approval: false,
            },
            crate::verification_planner::VerificationCandidate {
                method: "escalate_to_human_review".to_string(),
                estimated_information_gain: 0.3,
                estimated_network_cost: 0.0,
                estimated_runtime_ms: 0,
                disruption_risk: 0.0,
                requires_approval: true,
            },
        ];

        let plan = crate::verification_planner::plan_verification(hypothesis, candidates);
        let requires_approval = plan.chosen_requires_approval();
        let chosen = plan.chosen.expect("planner musi vybrat kandidata");

        // Levny, rychly, informativni krok (precist obsah uz potvrzeneho exponovaneho
        // endpointu) ma vyhrat proti pomalejsimu/drazsimu rescanu a proti eskalaci,
        // ktera ma nejnizsi odhadovany information gain ze vsech tri.
        assert_eq!(chosen.candidate.method, "inspect_metrics_content");
        assert!(!requires_approval);
    }

    /// Deliverable 11: navazujici krok explicitne odlozeny v Deliverable 8 ("vybrany
    /// kandidat se v tomto kroku nevykonava") - ted se SKUTECNE vykona. Poprve v cele
    /// diplomce je cely cyklus Observation -> Finding -> Hypothesis -> Planner ->
    /// EXEKUCE uzavren na realnych datech, ne jen navrzen.
    #[test]
    fn executing_planners_chosen_candidate_reveals_real_sensitive_metric_names() {
        let _guard = LAB_PORT_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let lab = start_juice_shop_lab().expect("start juice shop lab");

        let temp = tempfile::TempDir::new().expect("tempdir");
        let scan = run_active_scan_against_lab(
            temp.path(),
            "lab-execution-run",
            httpx_bin(),
            nuclei_bin(),
            nuclei_templates_dir(),
        );
        let scan = match scan {
            Ok(scan) => scan,
            Err(error) => {
                stop_lab(lab);
                panic!("aktivni sken proti lab cili: {error}");
            }
        };
        let pipeline =
            build_hypotheses_from_lab_scan(scan, "lab-execution-run").expect("build hypotheses");

        let (_, hypothesis) = pipeline
            .hypotheses
            .iter()
            .find(|(finding, _)| finding.finding_type.contains("prometheus-metrics-exposed"))
            .expect("pipeline musi vyprodukovat Finding pro realny nuclei nalez");

        let candidates = vec![
            crate::verification_planner::VerificationCandidate {
                method: "inspect_metrics_content".to_string(),
                estimated_information_gain: 0.6,
                estimated_network_cost: 0.02,
                estimated_runtime_ms: 500,
                disruption_risk: 0.0,
                requires_approval: false,
            },
            crate::verification_planner::VerificationCandidate {
                method: "broad_nuclei_rescan_full_template_set".to_string(),
                estimated_information_gain: 0.5,
                estimated_network_cost: 0.3,
                estimated_runtime_ms: 60_000,
                disruption_risk: 0.1,
                requires_approval: false,
            },
        ];
        let plan = crate::verification_planner::plan_verification(hypothesis, candidates);
        let chosen = plan
            .chosen
            .expect("planner musi vybrat kandidata")
            .candidate;
        assert_eq!(chosen.method, "inspect_metrics_content");

        // Skutecne vykonani vybraneho kandidata - ne dalsi odhad.
        let outcome = execute_inspect_metrics_content("http://127.0.0.1:3000");

        stop_lab(lab);
        let outcome = outcome.expect("vykonani inspect_metrics_content");

        assert_eq!(outcome.status_code, 200);
        assert!(outcome.body_line_count > 0);
        assert!(
            !outcome.sensitive_looking_metric_names.is_empty(),
            "ocekavam alespon jednu citlive vyhlizejici metriku (token/upload/llm), dostal jsem {:?}",
            outcome.sensitive_looking_metric_names
        );
        println!(
            "Deliverable 11: vykonani inspect_metrics_content nalezlo {} citlivych metrik: {:?}",
            outcome.sensitive_looking_metric_names.len(),
            outcome.sensitive_looking_metric_names
        );
    }
}
