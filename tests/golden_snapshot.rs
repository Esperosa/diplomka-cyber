//! Faze 0 pripravy na "framework style" refaktor (produkcni-plan): zachranna
//! sit PRED jakoukoliv zmenou v `run_pipeline`/`passive::load_and_normalize`/
//! `findings.rs`. Existujici e2e testy kontroluji jen prahove vlastnosti
//! (`.len() >= N`, `any(finding_type == ...)`) - tenhle test naopak zachyti
//! JAKOUKOLIV zmenu ve tvaru vysledneho `report.json` pro stejny vstup (stejne
//! fixtury jako `full_visibility_stack_populates_lanes_and_findings`, seed=7,
//! 0 nahodnych). Vstup NENI uplne deterministicky bit-po-bitu (`simulation.rs`
//! vnitrne pouziva `Utc::now()` pro relativni casove posuny) - vystup na
//! tenhle posun je ale invariantni (overeno opakovanymi behy), proto na
//! predvidatelnost golden snapshotu nema vliv.
//!
//! Volatilni pole (run_id, casova razitka, absolutni docasne cesty k
//! fixturam) se pred porovnanim normalizuji - jinak by test padal na kazdem
//! behu, ne jen pri skutecne zmene chovani.
//!
//! Test NENI `#[ignore]` - potrebuje jen binarku + commitnute fixtury v
//! `data/` (zadny Docker/nmap/httpx/nuclei), stejne jako existujici
//! `full_visibility_stack_populates_lanes_and_findings` v `tests/e2e.rs`,
//! takze bezi normalne v CI. Jako bezpecnostni sit pro refaktor musi bezet
//! automaticky, ne za specialni flag.
//!
//! Aktualizace zlateho souboru po VEDOME zmene chovani:
//! `SALTICUS_UPDATE_GOLDEN=1 cargo test --test golden_snapshot`

use std::{fs, path::Path, process::Command};

use serde_json::Value;
use tempfile::TempDir;

fn bin_path() -> &'static str {
    env!("CARGO_BIN_EXE_salticus-program")
}

fn golden_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("full_visibility_stack.json")
}

/// Rozpozna RFC3339 casove razitko ("2026-10-29T18:30:00Z" apod.) na zacatku
/// retezce bez pridavani zavislosti na `regex` - staci par pevnych pozic.
fn looks_like_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 19 {
        return false;
    }
    let digit = |index: usize| bytes.get(index).is_some_and(u8::is_ascii_digit);
    digit(0)
        && digit(1)
        && digit(2)
        && digit(3)
        && bytes[4] == b'-'
        && digit(5)
        && digit(6)
        && bytes[7] == b'-'
        && digit(8)
        && digit(9)
        && bytes[10] == b'T'
        && digit(11)
        && digit(12)
        && bytes[13] == b':'
        && digit(14)
        && digit(15)
        && bytes[16] == b':'
        && digit(17)
        && digit(18)
}

/// Delka tokenu "run-<14 cislic>-<citac>-<32 hex>" (`build_run_id()`,
/// src/report.rs) na zacatku `s`, pokud tam je - umoznuje maskovat run_id i
/// jako SOUCAST vetsiho retezce (napr. "lane:mas:consensus:run-...",
/// "source_action=validation:foo-agent:run-..."), ne jen pri presne shode
/// celeho retezce.
fn run_id_token_len(s: &str) -> Option<usize> {
    let rest = s.strip_prefix("run-")?;
    let date_len = rest.bytes().take_while(u8::is_ascii_digit).count();
    if date_len != 14 {
        return None;
    }
    let rest = rest[date_len..].strip_prefix('-')?;
    let counter_len = rest.bytes().take_while(u8::is_ascii_digit).count();
    if counter_len == 0 {
        return None;
    }
    let rest = rest[counter_len..].strip_prefix('-')?;
    let hex_len = rest.bytes().take_while(u8::is_ascii_hexdigit).count();
    if hex_len != 32 {
        return None;
    }
    Some(4 + date_len + 1 + counter_len + 1 + hex_len)
}

fn mask_run_ids(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut last_end = 0;
    for (start, _) in text.match_indices("run-") {
        if start < last_end {
            continue;
        }
        if let Some(token_len) = run_id_token_len(&text[start..]) {
            result.push_str(&text[last_end..start]);
            result.push_str("<RUN_ID>");
            last_end = start + token_len;
        }
    }
    result.push_str(&text[last_end..]);
    result
}

/// `event_id` (napr. "suricata:1002:1793301118", "zeek:H1:http:1793301118")
/// konci unixovym casovym razitkem v sekundach (10 cislic v soucasnem
/// rozsahu) - normalizuje kazdy takovy beh cislic bez ohledu na okolni text.
fn mask_epoch_seconds(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut result = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let run = &text[start..i];
            if run.len() == 10 {
                result.push_str("<EPOCH>");
            } else {
                result.push_str(run);
            }
        } else {
            let ch = text[i..].chars().next().expect("non-empty zbytek retezce");
            result.push(ch);
            i += ch.len_utf8();
        }
    }
    result
}

/// MAS scheduler/consensus evidence a summary texty (automation.rs) obsahuji
/// SKUTECNE namerene cas steny hodiny (thread::scope parallel kolektory) -
/// nejsou odvozene od vstupnich dat, takze se liseji kazdy beh. Masky se
/// aplikuji jen na CISLO hned za markerem, ne na cely retezec kolem nej -
/// puvodni verze nahrazovala celou hodnotu "<VOLATILE_TIMING_TEXT>", coz by
/// schovalo i zmenu neceho DETERMINISTICKEHO ve stejnem retezci (napr.
/// nazvu role agenta) - nezavisle odhaleno 2 revizemi,
/// 29.10.2026.
const VOLATILE_TIMING_MARKERS: &[&str] = &[
    "runtime_ms=",
    "parallel_stage_wall_ms=",
    "parallelism_ratio=",
    "paralelismus ",
    "wait_ms=",
    "queue_wait_ms_avg=",
    "agent_sla_ratio=",
    "queue wait ",
    "SLA ",
];

/// Pro kazdy vyskyt markeru v `text` nahradi nasledujici ciselny token
/// (cifry a desetinna tecka) placeholderem "<N>" - zbytek retezce (nazvy
/// roli, jednotky, oddelovace) zustava beze zmeny a dal se porovnava.
fn mask_numbers_after_markers(text: &str) -> String {
    let mut current = text.to_string();
    for marker in VOLATILE_TIMING_MARKERS {
        let mut result = String::with_capacity(current.len());
        let mut rest = current.as_str();
        while let Some(offset) = rest.find(marker) {
            let (before, after_marker) = rest.split_at(offset);
            result.push_str(before);
            result.push_str(marker);
            let number_part = &after_marker[marker.len()..];
            let number_len = number_part
                .bytes()
                .take_while(|byte| byte.is_ascii_digit() || *byte == b'.')
                .count();
            // Audit nalez (30.10.2026): bez teto podminky by "<N>" vznikl
            // i kdyz za markerem ZADNE cislo neni (prazdna/chybejici hodnota) -
            // takovou regresi by test tise prehledl. Nic se nemaskuje, pokud
            // zadne cislo nenasledovalo - zbytek retezce zustava nedotceny a
            // pripoji se bud pri dalsim najiti markeru (jako `before`), nebo
            // na konci cyklu (`result.push_str(rest)`).
            if number_len > 0 {
                result.push_str("<N>");
            }
            rest = &number_part[number_len..];
        }
        result.push_str(rest);
        current = result;
    }
    current
}

/// Pole v `Summary` (model.rs), jejichz hodnota je primo namerene cas steny
/// hodiny, ne odvozena od (determinstickych) vstupnich dat.
const VOLATILE_SUMMARY_KEYS: &[&str] = &[
    "mas_parallelism_ratio",
    "mas_queue_wait_ms_avg",
    "mas_agent_sla_ratio",
];

/// Nahradi volatilni hodnoty stabilnimi placeholdery - rekurzivne projde
/// cely JSON strom (vcetne vnorenych struktur z automation/context/lanes,
/// ktere tenhle test vedome nezna do detailu - prave proto je normalizace
/// podle TVARU hodnoty, ne podle enumerace klicu, s par vyjimkami pro znama
/// cas-steny-hodiny pole).
fn normalize(value: &mut Value, path_needles: &[(String, &str)]) {
    match value {
        Value::String(text) => {
            // Cesty ulozene v `run.sources.*` (puvodem z `--nmap-xml`/atd. argumentu)
            // nesou nativni oddelovac adresare - `\` na Windows, `/` na Linux (CI).
            // Sjednoceni na `/` PRED needle matchingem drzi golden soubor prenositelny
            // mezi platformami, ne jen mezi behy na stejnem stroji.
            let mut normalized = text.replace('\\', "/");
            for (needle, placeholder) in path_needles {
                if normalized.contains(needle.as_str()) {
                    normalized = normalized.replace(needle.as_str(), placeholder);
                }
            }
            if looks_like_timestamp(&normalized) {
                normalized = "<TIMESTAMP>".to_string();
            } else {
                normalized =
                    mask_numbers_after_markers(&mask_epoch_seconds(&mask_run_ids(&normalized)));
            }
            *text = normalized;
        }
        Value::Array(items) => {
            for item in items {
                normalize(item, path_needles);
            }
        }
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                if VOLATILE_SUMMARY_KEYS.contains(&key.as_str()) {
                    *item = Value::String("<VOLATILE>".to_string());
                } else {
                    normalize(item, path_needles);
                }
            }
        }
        _ => {}
    }
}

fn load_single_report(workspace: &Path) -> Value {
    let runs_dir = workspace.join("runs");
    let mut reports = Vec::new();
    for entry in fs::read_dir(&runs_dir).expect("runs dir") {
        let entry = entry.expect("entry");
        if !entry.file_type().expect("file type").is_dir() {
            continue;
        }
        let report_path = entry.path().join("report.json");
        if report_path.exists() {
            let bytes = fs::read(&report_path).expect("report bytes");
            reports.push(serde_json::from_slice::<Value>(&bytes).expect("report json"));
        }
    }
    assert_eq!(reports.len(), 1, "ocekavan presne 1 report v {runs_dir:?}");
    reports.pop().expect("report")
}

/// Stejny deterministicky vstup jako
/// `full_visibility_stack_populates_lanes_and_findings` v `tests/e2e.rs`
/// (seed=7, 0 nahodnych scenaru, vsechny snapshoty z `data/`) - zamerne
/// duplikovano misto sdileni helperu, aby zmena jednoho testu neposunula
/// tise i vstup druheho.
#[test]
fn full_visibility_stack_report_matches_golden_snapshot() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let scenarios = temp.path().join("simulace");

    let status = Command::new(bin_path())
        .args([
            "simulace",
            "generuj",
            "--vystup",
            scenarios.to_str().expect("scenarios"),
            "--seed",
            "7",
            "--nahodnych",
            "0",
        ])
        .status()
        .expect("generovani simulace");
    assert!(status.success());

    let data_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("data");

    let status = Command::new(bin_path())
        .args([
            "beh",
            "spust",
            "--workspace",
            workspace.to_str().expect("workspace"),
            "--nazev",
            "Full visibility stack",
            "--scope",
            "192.168.56.0/24",
            "--nmap-xml",
            scenarios
                .join("zakladni")
                .join("nmap.xml")
                .to_str()
                .expect("nmap xml"),
            "--suricata-eve",
            scenarios
                .join("zakladni")
                .join("suricata")
                .join("eve.json")
                .to_str()
                .expect("eve json"),
            "--zeek-dir",
            scenarios
                .join("zakladni")
                .join("zeek")
                .to_str()
                .expect("zeek"),
            "--provider",
            "demo",
            "--disable-circl",
            "--snmp-snapshot",
            data_dir
                .join("snmp_demo_snapshot.json")
                .to_str()
                .expect("snmp"),
            "--librenms-snapshot",
            data_dir
                .join("librenms_demo_snapshot.json")
                .to_str()
                .expect("librenms"),
            "--meraki-snapshot",
            data_dir
                .join("meraki_demo_snapshot.json")
                .to_str()
                .expect("meraki"),
            "--unifi-snapshot",
            data_dir
                .join("unifi_demo_snapshot.json")
                .to_str()
                .expect("unifi"),
            "--aruba-snapshot",
            data_dir
                .join("aruba_demo_snapshot.json")
                .to_str()
                .expect("aruba"),
            "--omada-snapshot",
            data_dir
                .join("omada_demo_snapshot.json")
                .to_str()
                .expect("omada"),
            "--ntopng-snapshot",
            data_dir
                .join("ntopng_demo_snapshot.json")
                .to_str()
                .expect("ntopng"),
            "--flow-snapshot",
            data_dir
                .join("flow_demo_snapshot.json")
                .to_str()
                .expect("flow"),
            "--greenbone-report",
            data_dir
                .join("greenbone_demo_report.json")
                .to_str()
                .expect("greenbone"),
            "--wazuh-report",
            data_dir
                .join("wazuh_demo_report.json")
                .to_str()
                .expect("wazuh"),
            "--napalm-snapshot",
            data_dir
                .join("napalm_demo_snapshot.json")
                .to_str()
                .expect("napalm"),
            "--netmiko-snapshot",
            data_dir
                .join("netmiko_demo_snapshot.json")
                .to_str()
                .expect("netmiko"),
            "--scrapli-snapshot",
            data_dir
                .join("scrapli_demo_snapshot.json")
                .to_str()
                .expect("scrapli"),
        ])
        .status()
        .expect("spusteni plneho behu");
    assert!(status.success(), "plny beh musi probehnout");

    let mut report = load_single_report(&workspace);

    // `data_dir` (CARGO_MANIFEST_DIR) je absolutni cesta k checkoutu repa - stejne
    // volatilni mezi stroji/CI jako `workspace`/`scenarios`, jen jina kategorie
    // (kontrolovany vstup z `data/`, ne test-scoped docasny adresar).
    let path_needles: Vec<(String, &str)> = vec![
        (workspace.to_string_lossy().replace('\\', "/"), "<TMP>"),
        (scenarios.to_string_lossy().replace('\\', "/"), "<TMP>"),
        (data_dir.to_string_lossy().replace('\\', "/"), "<REPO>/data"),
    ];
    normalize(&mut report, &path_needles);

    let actual = serde_json::to_string_pretty(&report).expect("serializace reportu");

    if std::env::var("SALTICUS_UPDATE_GOLDEN").is_ok() {
        fs::create_dir_all(golden_path().parent().expect("golden dir")).expect("mkdir golden");
        fs::write(golden_path(), &actual).expect("zapis zlateho souboru");
        return;
    }

    // `.gitattributes` vynucuje LF pro `tests/golden/*.json`, ale normalizace
    // CRLF->LF i tady je levna pojistka pro checkout, ktery vznikl pred timhle
    // pravidlem (nezavisle odhaleno 2 review agenty, 29.10.2026) - test ma
    // hlidat zmenu CHOVANI, ne zpusob konce radku na disku.
    let golden = fs::read_to_string(golden_path())
        .unwrap_or_else(|error| {
            panic!(
                "zlaty soubor {:?} chybi nebo se neda cist ({error}) - vygeneruj ho: \
                 SALTICUS_UPDATE_GOLDEN=1 cargo test --test golden_snapshot",
                golden_path()
            )
        })
        .replace('\r', "");

    if actual != golden {
        let actual_path = golden_path().with_extension("actual.json");
        fs::write(&actual_path, &actual).expect("zapis actual souboru pro diff");
        panic!(
            "report.json se zmenil oproti zlatemu snapshotu.\n\
             Skutecny vystup ulozen do {actual_path:?} - over diffem proti {:?}.\n\
             Pokud je zmena VEDOMA (napr. nova vrstva jadra zapojena do pipeline), \
             aktualizuj zlaty soubor: SALTICUS_UPDATE_GOLDEN=1 cargo test --test golden_snapshot",
            golden_path()
        );
    }
}
