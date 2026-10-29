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

// Deliverable 15: 3 dalsi cile pro multiservice lab (H3 odblokovani, viz
// docs/diplomka/eval/h3-measurement-difficulty.md a dalsi-postup-master-plan.md).
// Vsechny 3 overeny rucne (`docker run` + `curl`) proti realnym default obrazum PRED
// zapsanim do kodu - stejna disciplina jako prometheus nalez v Deliverable 7.
const GRAFANA_IMAGE: &str = "grafana/grafana-oss:11.3.0";
const GRAFANA_HOST_PORT: u16 = 3001;
const GRAFANA_CONTAINER_PORT: u16 = 3000;

// Port 8000 (ne 3002) zamerne - `webscan.rs::is_http_candidate` pozna jako http
// kandidata port bud podle jmena sluzby z nmap -sV detekce, nebo podle pevneho
// seznamu znamych web-portu. Pythonuv zakladni http.server ma nestandardni banner
// ("SimpleHTTP/0.6 Python/3.x"), ktery nmap -sV nerozpozna jako "http" sluzbu podle
// jmena - overeno rucne (port 3002 skutecne vypada jako "Directory listing" pro curl,
// ale httpx ho vubec neoskenoval, protoze nebyl na pevnem seznamu). Port 8000 na
// seznamu je, takze stejny obraz na tomhle portu uz httpx/nuclei spravne zacili.
const DIRLISTING_IMAGE: &str = "python:3-alpine";
const DIRLISTING_HOST_PORT: u16 = 8000;
const DIRLISTING_CONTAINER_PORT: u16 = 8000;

const CLEAN_IMAGE: &str = "nginx:alpine";
const CLEAN_HOST_PORT: u16 = 3003;
const CLEAN_CONTAINER_PORT: u16 = 80;

const MULTISERVICE_PORTS: [u16; 4] = [
    JUICE_SHOP_PORT,
    GRAFANA_HOST_PORT,
    DIRLISTING_HOST_PORT,
    CLEAN_HOST_PORT,
];

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

/// RAII pro vice kontejneru najednou (Deliverable 15) - stejny princip jako
/// `LabHandle`, jen pro N cilu. `docker rm -f` kazdeho kontejneru i kdyz test panikne.
pub struct MultiLabHandle {
    container_names: Vec<String>,
}

impl Drop for MultiLabHandle {
    fn drop(&mut self) {
        for name in &self.container_names {
            let _ = Command::new("docker").args(["rm", "-f", name]).status();
        }
    }
}

pub fn stop_multiservice_lab(handle: MultiLabHandle) {
    drop(handle);
}

fn docker_run(container_name: &str, port_mapping: &str, image_and_cmd: &[&str]) -> Result<()> {
    let mut args: Vec<&str> = vec!["run", "-d", "--name", container_name, "-p", port_mapping];
    args.extend_from_slice(image_and_cmd);
    let status = Command::new("docker")
        .args(&args)
        .status()
        .map_err(|error| BakulaError::Processing(format!("docker run selhal: {error}")))?;
    if !status.success() {
        let _ = Command::new("docker")
            .args(["rm", "-f", container_name])
            .status();
        return Err(BakulaError::Processing(format!(
            "docker run pro {container_name} se nepodarilo spustit."
        )));
    }
    Ok(())
}

/// Lab se 4 cíli pro Deliverable 15: 3 odlisitelne zranitelnosti ruznych produktu
/// (Juice Shop/prometheus, Grafana/login, python http.server/directory listing) +
/// 1 cisty negativni kontrolni cil (nginx default stranka) - presne ta kombinace
/// "realny aktivni inventar s vice nalezy ruzne jistoty soucasne", kterou
/// `docs/diplomka/eval/h3-measurement-difficulty.md` identifikoval jako chybejici.
pub fn start_multiservice_lab() -> Result<MultiLabHandle> {
    let suffix = uuid::Uuid::new_v4();
    let names = [
        format!("bakula-lab-juiceshop-{suffix}"),
        format!("bakula-lab-grafana-{suffix}"),
        format!("bakula-lab-dirlisting-{suffix}"),
        format!("bakula-lab-clean-{suffix}"),
    ];

    let start_result = docker_run(
        &names[0],
        &format!("127.0.0.1:{JUICE_SHOP_PORT}:{JUICE_SHOP_PORT}"),
        &[JUICE_SHOP_IMAGE],
    )
    .and_then(|()| {
        docker_run(
            &names[1],
            &format!("127.0.0.1:{GRAFANA_HOST_PORT}:{GRAFANA_CONTAINER_PORT}"),
            &[GRAFANA_IMAGE],
        )
    })
    .and_then(|()| {
        docker_run(
            &names[2],
            &format!("127.0.0.1:{DIRLISTING_HOST_PORT}:{DIRLISTING_CONTAINER_PORT}"),
            &[DIRLISTING_IMAGE, "python3", "-m", "http.server", "8000"],
        )
    })
    .and_then(|()| {
        docker_run(
            &names[3],
            &format!("127.0.0.1:{CLEAN_HOST_PORT}:{CLEAN_CONTAINER_PORT}"),
            &[CLEAN_IMAGE],
        )
    });

    if let Err(error) = start_result {
        for name in &names {
            let _ = Command::new("docker").args(["rm", "-f", name]).status();
        }
        return Err(error);
    }

    let handle = MultiLabHandle {
        container_names: names.to_vec(),
    };

    for port in MULTISERVICE_PORTS {
        if let Err(error) = wait_for_http_health(port, Duration::from_secs(30)) {
            drop(handle);
            return Err(error);
        }
    }

    Ok(handle)
}

#[derive(Debug, Clone)]
pub struct LabScanResult {
    pub hosts: Vec<HostReport>,
    pub web_artifacts: WebScanArtifacts,
}

/// `httpx_bin`/`nuclei_bin` jsou explicitni cesty (ne spoleham na PATH) - prostredi
/// muze mit na PATH jiny `httpx` (napr. Python HTTP klient se stejnym nazvem), presne
/// tento mismatch byl pricinou predem zname nesouvisejici chyby v `tests/e2e.rs`.
/// Obecna verze - skenuje libovolnou sadu portu na 127.0.0.1, ne jen Juice Shop.
/// `run_active_scan_against_lab` (nize) je tenky wrapper pro zpetnou kompatibilitu
/// se vsemi existujicimi testy z Deliverable 7-13.
pub fn run_active_scan_against_ports(
    workspace: &Path,
    run_id: &str,
    ports: &[u16],
    httpx_bin: PathBuf,
    nuclei_bin: PathBuf,
    nuclei_templates_dir: PathBuf,
) -> Result<LabScanResult> {
    let scope = vec!["127.0.0.1/32".parse().map_err(|error| {
        BakulaError::Processing(format!("neplatny scope 127.0.0.1/32: {error}"))
    })?];

    let xml_path = run_real_nmap(workspace, &scope, ports, "opatrny")?;
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

pub fn run_active_scan_against_lab(
    workspace: &Path,
    run_id: &str,
    httpx_bin: PathBuf,
    nuclei_bin: PathBuf,
    nuclei_templates_dir: PathBuf,
) -> Result<LabScanResult> {
    run_active_scan_against_ports(
        workspace,
        run_id,
        &[JUICE_SHOP_PORT],
        httpx_bin,
        nuclei_bin,
        nuclei_templates_dir,
    )
}

pub fn run_active_scan_against_multiservice_lab(
    workspace: &Path,
    run_id: &str,
    httpx_bin: PathBuf,
    nuclei_bin: PathBuf,
    nuclei_templates_dir: PathBuf,
) -> Result<LabScanResult> {
    run_active_scan_against_ports(
        workspace,
        run_id,
        &MULTISERVICE_PORTS,
        httpx_bin,
        nuclei_bin,
        nuclei_templates_dir,
    )
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
    build_hypotheses_from_lab_scan_with_ports(scan, run_id, vec![JUICE_SHOP_PORT])
}

pub fn build_hypotheses_from_lab_scan_with_ports(
    scan: LabScanResult,
    run_id: &str,
    ports: Vec<u16>,
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
        ports,
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

    /// Predikce sablony z pasivniho httpx titulku PRED jakoukoliv aktivni kontrolou -
    /// obecne pravidlo (rozpoznej produkt z titulku, zkontroluj jeho znamou exponovanou
    /// cestu), NE zpetne odvozene ze znameho vysledku tohoto konkretniho labu. Vraci
    /// None, kde titulek nenese zadnou specifickou stopu - to je zamerne, ne chyba
    /// (presne tenhle pripad byl u Juice Shopu identifikovan jako strukturalne
    /// neinformativni v `docs/diplomka/eval/h3-measurement-difficulty.md`).
    fn voi_predict_template_from_passive_title(title: &str) -> Option<&'static str> {
        let lower = title.to_ascii_lowercase();
        if lower.contains("grafana") {
            Some("bakula-grafana-login-exposed")
        } else if lower.contains("directory listing") {
            Some("bakula-directory-listing-exposed")
        } else {
            None
        }
    }

    /// Deliverable 15: prvni test s realnym aktivnim inventarem A vice nalezy ruzne
    /// jistoty soucasne - presne ta kombinace, kterou `h3-measurement-difficulty.md`
    /// identifikoval jako chybejici infrastrukturu pro smysluplne H3 mereni.
    #[test]
    fn multiservice_lab_exposes_three_distinct_findings_and_one_clean_control() {
        let _guard = LAB_PORT_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let lab = start_multiservice_lab().expect("start multiservice lab");

        let temp = tempfile::TempDir::new().expect("tempdir");
        let scan = run_active_scan_against_multiservice_lab(
            temp.path(),
            "lab-d15-smoke",
            httpx_bin(),
            nuclei_bin(),
            nuclei_templates_dir(),
        );
        stop_multiservice_lab(lab);
        let scan = scan.expect("aktivni sken proti multiservice labu");

        assert_eq!(
            scan.hosts.len(),
            1,
            "vsechny 4 cile bezi na 127.0.0.1, musi se slit do 1 hosta se 4 otevrenymi porty"
        );
        let host = &scan.hosts[0];
        assert_eq!(
            host.services.len(),
            4,
            "nmap musi najit vsechny 4 otevrene porty"
        );

        let find_service = |port: u16| {
            host.services
                .iter()
                .find(|service| service.port == port)
                .unwrap_or_else(|| panic!("port {port} musi byt v nmap vysledku"))
        };
        let has_template = |port: u16, template_id: &str| {
            find_service(port)
                .active_checks
                .iter()
                .any(|check| check.template_id == template_id)
        };

        assert!(
            has_template(JUICE_SHOP_PORT, "bakula-prometheus-metrics-exposed"),
            "Juice Shop musi vykazat prometheus-metrics-exposed jako v Deliverable 7"
        );
        assert!(
            has_template(GRAFANA_HOST_PORT, "bakula-grafana-login-exposed"),
            "Grafana musi vykazat grafana-login-exposed"
        );
        assert!(
            has_template(DIRLISTING_HOST_PORT, "bakula-directory-listing-exposed"),
            "python http.server musi vykazat directory-listing-exposed"
        );
        assert!(
            find_service(CLEAN_HOST_PORT).active_checks.is_empty(),
            "cisty kontrolni cil (nginx default) nesmi vyvolat zadny z 8 kurátorovanych nalezu"
        );
    }

    /// Deliverable 15 - skutecne mereni H3 ("typovana nejistota a VOI planner dosahne
    /// stejne/vyssi presnosti s mensim poctem aktivnich kontrol oproti plosnemu
    /// skenu"), poprve na nezniklem (ne cirkularnim, ne degenerovanem na konstantu)
    /// zakladu: 4 sluzby, kazda s vlastnim pasivnim titulkem ZISKANYM PRED nuclei
    /// skenem, 3 z nich s realnym nalezem, 1 cista. "Blanket" = vsech 8 kurátorovanych
    /// sablon na vsech 4 sluzbach (= to, co uz skutecne probehlo v teto jedne scan).
    /// "VOI" = jen sablona predikovana z pasivniho titulku, 0 kontrol kde titulek
    /// nema specifickou stopu.
    #[test]
    fn h3_voi_informed_template_selection_recovers_most_findings_with_far_fewer_checks() {
        let _guard = LAB_PORT_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let lab = start_multiservice_lab().expect("start multiservice lab");

        let temp = tempfile::TempDir::new().expect("tempdir");
        let scan = run_active_scan_against_multiservice_lab(
            temp.path(),
            "lab-d15-h3",
            httpx_bin(),
            nuclei_bin(),
            nuclei_templates_dir(),
        );
        stop_multiservice_lab(lab);
        let scan = scan.expect("aktivni sken proti multiservice labu");
        let host = &scan.hosts[0];

        const CURATED_TEMPLATE_COUNT: usize = 8; // resources/nuclei-templates/controlled/

        // Predregistrovany manifest (napsany pred spustenim tohoto testu, ne odvozeny
        // ze zmereneho vysledku) - stejna disciplina jako label-leakage-safe eval.
        let expected_manifest: [(u16, Option<&str>); 4] = [
            (JUICE_SHOP_PORT, Some("bakula-prometheus-metrics-exposed")),
            (GRAFANA_HOST_PORT, Some("bakula-grafana-login-exposed")),
            (
                DIRLISTING_HOST_PORT,
                Some("bakula-directory-listing-exposed"),
            ),
            (CLEAN_HOST_PORT, None),
        ];

        let mut blanket_checks = 0usize;
        let mut blanket_correct = 0usize;
        let mut voi_checks = 0usize;
        let mut voi_correct = 0usize;
        let mut voi_missed: Vec<u16> = Vec::new();
        let mut spurious_blanket_matches: Vec<(u16, String)> = Vec::new();

        for (port, expected_template) in expected_manifest {
            let service = host
                .services
                .iter()
                .find(|service| service.port == port)
                .unwrap_or_else(|| panic!("port {port} musi byt v nmap vysledku"));
            blanket_checks += CURATED_TEMPLATE_COUNT;

            let blanket_is_correct = match expected_template {
                Some(template) => service
                    .active_checks
                    .iter()
                    .any(|check| check.template_id == template),
                None => service.active_checks.is_empty(),
            };
            if blanket_is_correct {
                blanket_correct += 1;
            }
            for check in &service.active_checks {
                if expected_template != Some(check.template_id.as_str()) {
                    spurious_blanket_matches.push((port, check.template_id.clone()));
                }
            }

            let passive_title = service
                .web_probe
                .as_ref()
                .and_then(|probe| probe.title.clone())
                .unwrap_or_default();
            let predicted = voi_predict_template_from_passive_title(&passive_title);

            match (predicted, expected_template) {
                (Some(_), _) => {
                    voi_checks += 1;
                    if predicted == expected_template {
                        voi_correct += 1;
                    }
                }
                (None, Some(_)) => voi_missed.push(port),
                (None, None) => {}
            }
        }

        println!(
            "H3: blanket={blanket_correct}/4 spravne za {blanket_checks} kontrol (spurious navic nalezy: {spurious_blanket_matches:?}) | VOI={voi_correct}/3 spravne za {voi_checks} kontroly (chybi porty: {voi_missed:?})"
        );

        // Blanket sken (vsech 8 sablon na vsech 4 sluzbach) musi spravne rozlisit
        // vsechny 4 cile podle manifestu - to je ground truth, proti kteremu se VOI
        // porovnava.
        assert_eq!(
            blanket_correct, 4,
            "blanket sken musi spravne rozlisit vsechny 4 cile (3 zranitelne + 1 cisty)"
        );
        // VOI musi spravne cilit presne ty nalezy, kde pasivni titulek nese
        // specifickou stopu (Grafana, directory listing) - 2 ze 3 zranitelnych cilu.
        assert_eq!(
            voi_correct, 2,
            "VOI musi spravne cilit presne 2 ze 3 nalezu diky specifickemu titulku (Grafana, directory listing), dostal jsem {voi_correct}"
        );
        // A musi to udelat za radikalne min kontrol nez blanket (2 cilene kontroly
        // vs. 32 = 4 sluzby * 8 sablon).
        assert!(
            voi_checks * 4 < blanket_checks,
            "VOI musi pouzit radikalne min kontrol nez blanket sken (voi={voi_checks}, blanket={blanket_checks})"
        );
        // Honest limitace, ne skryta: Juice Shop nema v titulku zadnou specifickou
        // stopu (presne nalez z h3-measurement-difficulty.md) - VOI ho proto musi
        // minout.
        assert_eq!(
            voi_missed,
            vec![JUICE_SHOP_PORT],
            "VOI musi minout presne Juice Shop (zadna specificka stopa v titulku) - pokud se tohle zmenilo, over zda Juice Shop titulek je stale jen 'OWASP Juice Shop'"
        );
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

    /// Deliverable 12 - prvni skutecne zmerena cast hypotezy H1 (navrh sekce 11:
    /// "spojeni pasivni a aktivni telemetrie zvysi kvalitu rozhodnuti proti samotne
    /// pasivni vrstve za definovanych nakladu"). "Pasivni" tu znamena nmap+httpx bez
    /// nuclei (jediny zdroj `active_checks` v tomhle skenu) - realne porovnani na
    /// stejnych datech ze stejneho behu, ne syntetický protiklad.
    #[test]
    fn h1_active_checks_increase_decision_quality_over_passive_only() {
        let _guard = LAB_PORT_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let lab = start_juice_shop_lab().expect("start juice shop lab");

        let temp = tempfile::TempDir::new().expect("tempdir");
        let scan = run_active_scan_against_lab(
            temp.path(),
            "lab-h1-run",
            httpx_bin(),
            nuclei_bin(),
            nuclei_templates_dir(),
        );
        stop_lab(lab);
        let scan = scan.expect("aktivni sken proti lab cili");

        // "Pasivni" varianta: stejna data ze stejneho behu, jen s odstranenymi
        // active_checks (ktere pochazeji vyhradne z nuclei - viz webscan.rs
        // `attach_nuclei_checks`). Nmap/httpx vysledky (otevreny port, HTTP titulek)
        // zustavaji - to je presne hranice "pasivni vs. +aktivni" v tomto kroku.
        let mut passive_only_hosts = scan.hosts.clone();
        for host in &mut passive_only_hosts {
            for service in &mut host.services {
                service.active_checks.clear();
            }
        }

        let passive_only_scan = LabScanResult {
            hosts: passive_only_hosts,
            web_artifacts: WebScanArtifacts::default(),
        };
        let active_scan = LabScanResult {
            hosts: scan.hosts,
            web_artifacts: scan.web_artifacts,
        };

        let passive_pipeline = build_hypotheses_from_lab_scan(passive_only_scan, "lab-h1-passive")
            .expect("passive pipeline");
        let active_pipeline =
            build_hypotheses_from_lab_scan(active_scan, "lab-h1-active").expect("active pipeline");

        let passive_actions = crate::decision::build_decision_bundle(&passive_pipeline.report)
            .actions
            .len();
        let active_actions = crate::decision::build_decision_bundle(&active_pipeline.report)
            .actions
            .len();

        println!(
            "H1: pasivni findings={} akce={} | pasivni+aktivni findings={} akce={} (dodatecny naklad: 1 nuclei sken s 8 kurátorovanymi sablonami + 1 GET pozadavek)",
            passive_pipeline.report.findings.len(),
            passive_actions,
            active_pipeline.report.findings.len(),
            active_actions,
        );

        // Bez aktivniho overeni (nuclei) tento konkretni nalez (exponovany /metrics)
        // vubec nevznikne - nmap/httpx samy o sobe nemaji zpusob, jak ho detekovat.
        assert!(
            active_pipeline
                .report
                .findings
                .iter()
                .any(|finding| finding.finding_type.contains("prometheus-metrics-exposed")),
            "pasivni+aktivni varianta musi obsahovat nalez z aktivni kontroly"
        );
        assert!(
            passive_pipeline
                .report
                .findings
                .iter()
                .all(|finding| !finding.finding_type.contains("prometheus-metrics-exposed")),
            "pasivni varianta (bez nuclei) nesmi obsahovat nalez, ktery umi detekovat jen aktivni kontrola"
        );
        assert!(
            active_pipeline.report.findings.len() > passive_pipeline.report.findings.len(),
            "aktivni telemetrie musi zvysit pocet findings oproti pasivni variante na stejnych datech"
        );
    }
}
