//! End-to-end: `--execute-verification` na realne simulacni fixture. Overuje
//! jen invarianty (ne konkretni cisla): exekuce je opt-in, kazdy vysledek ma
//! povoleny status, nic mimo scope a nic s approval-gate se nevykona.

use std::{fs, path::Path, process::Command};

use tempfile::TempDir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_bakula-program")
}

fn run(extra: &[&str]) -> serde_json::Value {
    let temp = TempDir::new().expect("tempdir");
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
                "0"
            ])
            .status()
            .expect("simulace")
            .success()
    );
    let base = scenarios.join("zakladni");
    let mut args = vec![
        "beh".to_string(),
        "spust".to_string(),
        "--workspace".to_string(),
        workspace.to_str().unwrap().to_string(),
        "--nazev".to_string(),
        "Verification exec".to_string(),
        "--scope".to_string(),
        "192.168.56.0/24".to_string(),
        "--nmap-xml".to_string(),
        base.join("nmap.xml").to_str().unwrap().to_string(),
        "--suricata-eve".to_string(),
        base.join("suricata")
            .join("eve.json")
            .to_str()
            .unwrap()
            .to_string(),
        "--zeek-dir".to_string(),
        base.join("zeek").to_str().unwrap().to_string(),
        "--provider".to_string(),
        "demo".to_string(),
        "--disable-circl".to_string(),
    ];
    args.extend(extra.iter().map(|item| item.to_string()));
    let status = Command::new(bin())
        .args(&args)
        .env("BAKULA_INSPECTION_TIMEOUT_MS", "300")
        .status()
        .expect("beh");
    assert!(status.success());

    let runs = workspace.join("runs");
    let run_dir = fs::read_dir(&runs)
        .expect("runs")
        .filter_map(|entry| entry.ok())
        .find(|entry| entry.path().join("report.json").exists())
        .expect("report.json");
    serde_json::from_str(&fs::read_to_string(run_dir.path().join("report.json")).unwrap()).unwrap()
}

#[test]
fn execution_is_off_by_default() {
    let report = run(&[]);
    assert!(
        report["verification_results"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(!report["verification_plans"].as_array().unwrap().is_empty());
}

#[test]
fn execution_respects_scope_approval_and_budget() {
    let report = run(&["--execute-verification", "--verification-max-checks", "3"]);
    let results = report["verification_results"].as_array().unwrap();
    assert!(
        !results.is_empty(),
        "exekuce zapnuta, vysledky musi existovat"
    );

    let allowed = [
        "executed",
        "reused",
        "skipped_budget",
        "needs_approval",
        "failed",
        "skipped_out_of_scope",
    ];
    for result in results {
        let status = result["status"].as_str().unwrap();
        assert!(allowed.contains(&status), "neznamy status {status}");
        let asset = result["asset"].as_str().unwrap();
        assert!(
            asset.starts_with("192.168.56."),
            "asset mimo scope: {asset}"
        );
        if result["method"] == "nmap_targeted_followup" {
            assert_eq!(status, "needs_approval", "aktivni sken nikdy automaticky");
        }
    }
    let executed = results.iter().filter(|r| r["status"] == "executed").count();
    assert!(executed <= 3, "rozpocet 3 prekrocen: {executed}");
    assert!(Path::new(env!("CARGO_MANIFEST_DIR")).exists());
}
