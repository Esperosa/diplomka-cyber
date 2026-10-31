//! End-to-end: `--incremental-ingest` cte kazdy radek logu pri uspesnych behach
//! prave jednou (offsety v `ingest-cursors.json`).

use std::{fs, process::Command};

use tempfile::TempDir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_bakula-program")
}

fn run_cycle(workspace: &std::path::Path, scenarios: &std::path::Path, name: &str) -> u64 {
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
            "--incremental-ingest",
        ])
        .status()
        .expect("beh");
    assert!(status.success());

    let latest = fs::read_dir(workspace.join("runs"))
        .unwrap()
        .filter_map(|entry| entry.ok())
        .find(|entry| {
            fs::read_to_string(entry.path().join("report.json"))
                .map(|text| text.contains(&format!("\"nazev\": \"{name}\"")))
                .unwrap_or(false)
        })
        .expect("report tohoto cyklu");
    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(latest.path().join("report.json")).unwrap())
            .unwrap();
    report["summary"]["events_total"].as_u64().unwrap()
}

#[test]
fn second_cycle_does_not_reprocess_already_consumed_log_lines() {
    let temp = TempDir::new().unwrap();
    let workspace = temp.path().join("workspace");
    let scenarios = temp.path().join("simulace");
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

    let first = run_cycle(&workspace, &scenarios, "cyklus-1");
    let second = run_cycle(&workspace, &scenarios, "cyklus-2");

    assert!(first > 0, "prvni cyklus musi videt udalosti z logu");
    assert_eq!(
        second, 0,
        "druhy cyklus bez novych radku nesmi opakovat udalosti"
    );
    assert!(workspace.join("ingest-cursors.json").exists());
}
