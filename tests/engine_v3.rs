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

    // krok 2D: typ zarizeni v modelu hostu (API vraci report.json)
    let hosts = runs[0]["hosts"].as_array().expect("hosts");
    assert!(
        hosts
            .iter()
            .all(|h| h["device_class"]["kind"].is_string()
                && h["device_class"]["reasons"].is_array()),
        "kazdy host ma typ, jistotu a duvody"
    );
    // krok 2B: stav zebriku prezije mezi procesy (otevrene pripady, rozhodnuti v reportu)
    let conn = rusqlite::Connection::open(workspace.join("engine-state.sqlite")).unwrap();
    let ladder: String = conn
        .query_row("SELECT value FROM kv WHERE name = 'ladder'", [], |r| {
            r.get(0)
        })
        .expect("stav zebriku ulozen");
    assert!(ladder.contains("\"policy\""));

    let legacy = temp.path().join("ws-legacy");
    run(&legacy, &scenarios, "legacy");
    let runs = reports(&legacy);
    assert!(runs[0].get("findingLifecycle").is_none());
    assert!(runs[0].get("verificationDecisions").is_none());
    assert!(
        runs[0]["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|h| h.get("device_class").is_none()),
        "legacy vystup beze zmeny"
    );
    assert!(!legacy.join("engine-state.sqlite").exists());
}

/// Krok 3: odchozí IDS alert (zdroj v rozsahu, cíl venku) vytvoří ve v3 nález
/// `egress_ids_alert` na vnitřním hostu a stav behaviorální vrstvy se uloží; legacy
/// takový alert zahodí jako dřív (cíl mimo rozsah).
#[test]
fn v3_behavior_layer_reports_outbound_ids_alert_and_persists_state() {
    let temp = TempDir::new().unwrap();
    let scenarios = temp.path().join("simulace");
    generate(&scenarios);
    let eve = scenarios.join("zakladni").join("suricata").join("eve.json");
    let content = fs::read_to_string(&eve).unwrap();
    let template = content
        .lines()
        .find(|l| l.contains("\"event_type\":\"alert\""))
        .expect("scenar ma alert");
    let mut row: Value = serde_json::from_str(template).unwrap();
    let inside = row["dest_ip"].as_str().unwrap().to_string();
    row["src_ip"] = Value::String(inside.clone());
    row["dest_ip"] = Value::String("203.0.113.77".into());
    row["dest_port"] = Value::from(443);
    row["alert"]["signature_id"] = Value::from(2027865);
    row["alert"]["signature"] = Value::String("ET MALWARE Known C2 beacon pattern".into());
    fs::write(&eve, format!("{content}\n{row}\n")).unwrap();

    let workspace = temp.path().join("ws-v3");
    fs::create_dir_all(&workspace).unwrap();
    fs::write(workspace.join("bakula.toml"), "[engine]\nmode = \"v3\"\n").unwrap();
    run(&workspace, &scenarios, "egress");
    let runs = reports(&workspace);
    let egress: Vec<&Value> = runs[0]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["finding_type"] == "egress_ids_alert")
        .collect();
    assert_eq!(egress.len(), 1, "jeden odchozi IDS nalez");
    assert_eq!(egress[0]["host_key"], Value::String(inside));
    let conn = rusqlite::Connection::open(workspace.join("engine-state.sqlite")).unwrap();
    let behavior: String = conn
        .query_row("SELECT value FROM kv WHERE name = 'behavior'", [], |r| {
            r.get(0)
        })
        .expect("stav behavioralni vrstvy ulozen");
    assert!(behavior.contains("\"profile\""));

    let legacy = temp.path().join("ws-legacy");
    run(&legacy, &scenarios, "legacy");
    let runs = reports(&legacy);
    assert!(
        runs[0]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["finding_type"] != "egress_ids_alert"),
        "legacy odchozi alert nevidi"
    );
}
