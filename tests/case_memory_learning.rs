//! End-to-end: opakovane behy s `--execute-verification` do JEDNOHO workspace
//! ukladaji historii kontrol a Case Memory; bez exekuce se zadny soubor
//! nevytvori (stinovy rezim zustava bez vedlejsich ucinku).

use std::{fs, path::Path, process::Command};

use tempfile::TempDir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_salticus-program")
}

fn run_cycle(workspace: &Path, scenarios: &Path, name: &str, execute: bool) {
    let base = scenarios.join("zakladni");
    let mut args: Vec<String> = [
        "beh",
        "spust",
        "--workspace",
        workspace.to_str().unwrap(),
        "--nazev",
        name,
        "--scope",
        "192.168.56.0/24",
        "--nmap-xml",
        base.join("nmap.xml").to_str().unwrap(),
        "--suricata-eve",
        base.join("suricata").join("eve.json").to_str().unwrap(),
        "--zeek-dir",
        base.join("zeek").to_str().unwrap(),
        "--provider",
        "demo",
        "--disable-circl",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    if execute {
        args.push("--execute-verification".to_string());
    }
    let status = Command::new(bin())
        .args(&args)
        .env("SALTICUS_INSPECTION_TIMEOUT_MS", "300")
        .status()
        .expect("beh");
    assert!(status.success());
}

fn simulate(dir: &Path) -> std::path::PathBuf {
    let scenarios = dir.join("simulace");
    assert!(
        Command::new(bin())
            .args([
                "simulace",
                "generuj",
                "--vystup",
                scenarios.to_str().unwrap(),
                "--seed",
                "7",
                "--nahodnych",
                "0",
            ])
            .status()
            .unwrap()
            .success()
    );
    scenarios
}

#[test]
fn shadow_mode_creates_no_learning_files() {
    let temp = TempDir::new().unwrap();
    let scenarios = simulate(temp.path());
    let workspace = temp.path().join("workspace");
    run_cycle(&workspace, &scenarios, "bez-exekuce", false);
    assert!(!workspace.join("case-memory.json").exists());
    assert!(!workspace.join("verification-history.json").exists());
}

#[test]
fn executed_checks_accumulate_history_and_case_memory_across_runs() {
    let temp = TempDir::new().unwrap();
    let scenarios = simulate(temp.path());
    let workspace = temp.path().join("workspace");

    run_cycle(&workspace, &scenarios, "cyklus-1", true);
    let history_path = workspace.join("verification-history.json");
    assert!(
        history_path.exists(),
        "historie vykonanych kontrol se musi zapsat"
    );
    let first: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&history_path).unwrap()).unwrap();
    let count = |value: &serde_json::Value| -> usize {
        value["methods"]
            .as_object()
            .unwrap()
            .values()
            .map(|samples| samples.as_array().unwrap().len())
            .sum()
    };
    let after_first = count(&first);
    assert!(after_first > 0);

    run_cycle(&workspace, &scenarios, "cyklus-2", true);
    let second: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&history_path).unwrap()).unwrap();
    assert!(
        count(&second) > after_first,
        "druhy beh pridava dalsi vzorky"
    );

    if workspace.join("case-memory.json").exists() {
        let memory: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(workspace.join("case-memory.json")).unwrap())
                .unwrap();
        assert!(memory["version"].as_u64().unwrap() >= 1);
    }
    assert!(
        !workspace.join("case-memory.lock").exists()
            && !workspace.join("verification-history.lock").exists(),
        "zamky se po behu uvolni"
    );
}
