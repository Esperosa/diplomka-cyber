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
//! **Co tento modul NEDELA:** nevola `verification_planner::plan_verification` -
//! zadna `SecurityHypothesis` o Juice Shopu jeste neexistuje, na kterou by se planner
//! mel vztahovat (stejna disciplina jako "vedome OUT" v Deliverable 1/5). Tento krok
//! jen namefi a zapise syrova fakta (co nmap/httpx/nuclei skutecne najdou), ktera az
//! navazujici krok muze pouzit jako vstup pro hypotezu/planner.

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::error::{BakulaError, Result};
use crate::model::HostReport;
use crate::nmap::{parse_nmap_xml, run_real_nmap};
use crate::report::normalize_inventory;
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
        return Err(BakulaError::Processing(
            "docker run pro juice-shop lab se nepodarilo spustit.".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
