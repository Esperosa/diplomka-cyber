//! Engine v3 v produkční pipeline (krok 1): `[engine] mode = "v3"` v `bakula.toml`.
//! Dva po sobě jdoucí běhy nad stejnými daty: první výskyt se zobrazí, opakovaný
//! stejný stav se podruhé nezobrazí (paměť nálezů v `engine-state.sqlite` přežije
//! konec procesu), legacy režim výstup nemění (pole `findingLifecycle` chybí).

use std::{fs, path::Path, process::Command};

use serde_json::Value;
use tempfile::TempDir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_bakula-program")
}

fn generate(scenarios: &Path) {
    let status = Command::new(bin())
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
        .expect("simulace");
    assert!(status.success());
}

fn run(workspace: &Path, scenarios: &Path, name: &str) {
    let base = scenarios.join("zakladni");
    let status = Command::new(bin())
        .args([
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
        ])
        .status()
        .expect("beh");
    assert!(status.success(), "beh {name}");
}

fn reports(workspace: &Path) -> Vec<Value> {
    let mut out: Vec<(String, Value)> = Vec::new();
    for entry in fs::read_dir(workspace.join("runs")).unwrap() {
        let path = entry.unwrap().path().join("report.json");
        if path.exists() {
            let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            let started = value["run"]["started_at"]
                .as_str()
                .unwrap_or("")
                .to_string();
            out.push((started, value));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.into_iter().map(|(_, v)| v).collect()
}

fn dispositions(report: &Value) -> Vec<String> {
    report["findingLifecycle"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|i| i["disposition"].as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn v3_memory_shows_first_occurrence_and_suppresses_repeat_across_processes() {
    let temp = TempDir::new().unwrap();
    let scenarios = temp.path().join("simulace");
    generate(&scenarios);

    let workspace = temp.path().join("ws-v3");
    fs::create_dir_all(&workspace).unwrap();
    fs::write(workspace.join("bakula.toml"), "[engine]\nmode = \"v3\"\n").unwrap();
    run(&workspace, &scenarios, "prvni");
    run(&workspace, &scenarios, "druhy");
    assert!(workspace.join("engine-state.sqlite").exists());
    let runs = reports(&workspace);
    assert_eq!(runs.len(), 2);
    let first = dispositions(&runs[0]);
    let second = dispositions(&runs[1]);
    assert!(!first.is_empty(), "v3 musi zapsat zivotni cyklus nalezu");
    assert!(
        first.iter().all(|d| d == "first" || d == "auto_resolved"),
        "prvni beh: {first:?}"
    );
    let suppressed = second.iter().filter(|d| *d == "suppressed").count();
    assert!(
        suppressed * 2 >= second.len(),
        "opakovany stejny stav se podruhe nema zobrazit: {second:?}"
    );

    let legacy = temp.path().join("ws-legacy");
    run(&legacy, &scenarios, "legacy");
    let runs = reports(&legacy);
    assert!(runs[0].get("findingLifecycle").is_none());
    assert!(!legacy.join("engine-state.sqlite").exists());
}
