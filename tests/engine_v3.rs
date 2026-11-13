//! Engine v3 v produkční pipeline (krok 1): `[engine] mode = "v3"` v `salticus.toml`.
//! Dva po sobě jdoucí běhy nad stejnými daty: první výskyt se zobrazí, opakovaný
//! stejný stav se podruhé nezobrazí (paměť nálezů v `engine-state.sqlite` přežije
//! konec procesu), legacy režim výstup nemění (pole `findingLifecycle` chybí).

use std::{fs, path::Path, process::Command};

use serde_json::Value;
use tempfile::TempDir;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_salticus-program")
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
    fs::write(workspace.join("salticus.toml"), "[engine]\nmode = \"v3\"\n").unwrap();
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
    fs::write(workspace.join("salticus.toml"), "[engine]\nmode = \"v3\"\n").unwrap();
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

/// Krok 7 (A3): jedno produkční automatické zavření kontextem projde vzorkem pro
/// člověka, verdiktem „omyl“ (API zapisuje do append-only tabulky), trvalým vypnutím
/// druhu kontextu a restartem procesu (vypnutí platí dál, druh už nezavírá). Report
/// nese stav auditu a degradaci pokrytí (A4).
#[test]
fn v3_closure_audit_samples_review_disables_kind_and_survives_restart() {
    let temp = TempDir::new().unwrap();
    let scenarios = temp.path().join("simulace");
    generate(&scenarios);
    let workspace = temp.path().join("ws-v3");
    fs::create_dir_all(&workspace).unwrap();
    fs::write(workspace.join("salticus.toml"), "[engine]\nmode = \"v3\"\n").unwrap();
    fs::write(
        workspace.join("closure-audit.json"),
        r#"{"sample_rate": 1.0, "min_samples": 1}"#,
    )
    .unwrap();
    let now = chrono::Utc::now();
    let hosts: Vec<String> = (1..255).map(|i| format!("192.168.56.{i}")).collect();
    let entry = serde_json::json!([{
        "kind": "maintenance",
        "hosts": hosts,
        "sources": [],
        "start": (now - chrono::Duration::days(2)).to_rfc3339(),
        "end": (now + chrono::Duration::days(2)).to_rfc3339(),
        "covers": [
            "connection_timeout_burst", "service_unreachable", "inductive_volume_anomaly",
            "packet_rate_spike", "unexpected_traffic", "unmapped_passive_event",
            "service_overload_risk", "external_flow_observed", "multi_target_pattern"
        ],
        "approved_by": "spravce",
        "expires": (now + chrono::Duration::days(3)).to_rfc3339()
    }]);
    fs::write(workspace.join("context-calendar.json"), entry.to_string()).unwrap();
    run(&workspace, &scenarios, "prvni");
    let runs = reports(&workspace);
    let first = dispositions(&runs[0]);
    assert!(
        first.iter().any(|d| d == "auto_resolved"),
        "ocekavano automaticke zavreni kontextem: {first:?}"
    );
    assert!(
        runs[0]["coverageStatus"]["reasons"].is_array(),
        "A4 pole v reportu"
    );
    let pending = runs[0]["closureAudit"]["pending"].as_u64().unwrap();
    assert!(
        pending >= 1,
        "zavreni je ve vzorku: {}",
        runs[0]["closureAudit"]
    );

    // clovek oznaci prvni vzorek jako omyl (cesta API)
    let db = workspace.join("engine-state.sqlite");
    {
        let store = salticus_program::engine_state::EngineStateStore::open(&db).unwrap();
        let audit: salticus_program::closure_audit::ClosureAudit =
            store.load("closure_audit").unwrap().unwrap();
        let sample = &audit.samples[0];
        assert_eq!(sample.kind, "maintenance");
        salticus_program::closure_audit::submit_review(
            store.conn(),
            sample.id,
            true,
            "analytik",
            "skryty utok",
            chrono::Utc::now(),
        )
        .unwrap();
    }
    run(&workspace, &scenarios, "druhy");
    run(&workspace, &scenarios, "treti");
    let runs = reports(&workspace);
    for report in &runs[1..] {
        let disabled = report["closureAudit"]["disabled"].as_array().unwrap();
        assert!(
            disabled.iter().any(|k| k == "maintenance"),
            "vypnuti druhu prezije restart: {}",
            report["closureAudit"]
        );
        assert!(
            report["findingLifecycle"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["disposition"] != "auto_resolved"),
            "vypnuty druh uz nezavira"
        );
    }
    let conn = rusqlite::Connection::open(&db).unwrap();
    let actions: Vec<String> = conn
        .prepare("SELECT action FROM finding_audit")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    for needed in ["audit_sample", "audit_review", "audit_disable"] {
        assert!(
            actions.iter().any(|a| a == needed),
            "{needed} v auditu: {actions:?}"
        );
    }
}
