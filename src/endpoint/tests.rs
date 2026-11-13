//! Testy parserů a odolnosti vstupu (krok 8, E12): vzorové záznamy, limity a fuzz.

use super::{Format, correlate::Limits, model::EventKind, parse_batch, parse_time};

const SYSMON_NESTED: &str = r#"{"Event":{"System":{"EventID":3,"Computer":"WS5.corp","TimeCreated":{"SystemTime":"2026-11-11T10:00:00.123Z"}},"EventData":{"Image":"C:\\Program Files\\Veeam\\a.exe","Protocol":"tcp","Initiated":"true","SourceIp":"10.0.0.5","SourcePort":"50000","DestinationIp":"203.0.113.9","DestinationPort":"443"}}}"#;
const SYSMON_FLAT: &str = r#"{"EventID":1,"Hostname":"ws5","@timestamp":"2026-11-11T10:00:00Z","Image":"C:\\Windows\\System32\\cmd.exe","ParentImage":"C:\\inetpub\\w3wp.exe","CommandLine":"cmd /c whoami","Company":"Microsoft Corporation"}"#;
const SYSMON_WINLOGBEAT: &str = r#"{"@timestamp":"2026-11-11T10:00:00Z","winlog":{"event_id":"4624","computer_name":"srv1","event_data":{"TargetUserName":"admin","LogonType":"3","IpAddress":"10.0.0.9"}}}"#;
const WAZUH_SSH: &str = r#"{"timestamp":"2026-11-11T10:00:00.000+0000","rule":{"id":"5710","level":5,"description":"sshd: attempt to login using a non-existent user","groups":["syslog","sshd","authentication_failed"]},"agent":{"id":"001","name":"web1","ip":"10.0.0.7"},"data":{"srcip":"203.0.113.50","dstuser":"admin"}}"#;
const WAZUH_FIM: &str = r#"{"timestamp":"2026-11-11T10:00:00.000+0000","rule":{"id":"550","level":7,"description":"Integrity checksum changed.","groups":["ossec","syscheck"]},"agent":{"id":"002","name":"db1"},"syscheck":{"path":"/etc/passwd","event":"modified"}}"#;
const OSQUERY_SOCKET: &str = r#"{"name":"pack/x/process_open_sockets","hostIdentifier":"WS5","unixTime":1794391200,"action":"added","columns":{"path":"/tmp/x","remote_address":"203.0.113.9","remote_port":"443","local_address":"10.0.0.5","local_port":"50000"}}"#;

#[test]
fn sample_records_parse_into_typed_events() {
    let e = Format::Sysmon.parse_line(SYSMON_NESTED).unwrap().unwrap();
    assert_eq!(e.host.hostname.as_deref(), Some("ws5.corp"));
    assert_eq!(e.ts, 1_794_391_200);
    assert!(
        matches!(e.kind, EventKind::NetConnect(ref c) if c.dst_port == 443 && c.dst_ip == "203.0.113.9")
    );
    let e = Format::Sysmon.parse_line(SYSMON_FLAT).unwrap().unwrap();
    assert!(
        matches!(e.kind, EventKind::ProcessCreate(ref p) if p.vendor.as_deref() == Some("Microsoft Corporation"))
    );
    let e = Format::Sysmon
        .parse_line(SYSMON_WINLOGBEAT)
        .unwrap()
        .unwrap();
    assert!(matches!(e.kind, EventKind::Logon(ref l) if l.success && l.logon_type == 3));
    let e = Format::Wazuh.parse_line(WAZUH_SSH).unwrap().unwrap();
    assert!(matches!(e.kind, EventKind::Logon(ref l) if !l.success));
    assert_eq!(e.host.ips, vec!["10.0.0.7".to_string()]);
    let e = Format::Wazuh.parse_line(WAZUH_FIM).unwrap().unwrap();
    assert!(matches!(e.kind, EventKind::Integrity { ref path, .. } if path == "/etc/passwd"));
    let e = Format::Osquery.parse_line(OSQUERY_SOCKET).unwrap().unwrap();
    assert!(matches!(e.kind, EventKind::NetConnect(_)));
}

#[test]
fn uninteresting_and_invalid_records_are_not_events() {
    // Sysmon ID 22 (DNS) se nepouziva, `removed` v osquery je bez noveho faktu
    let dns =
        r#"{"EventID":22,"Hostname":"a","@timestamp":"2026-11-11T10:00:00Z","QueryName":"x"}"#;
    assert_eq!(Format::Sysmon.parse_line(dns), Ok(None));
    let removed = OSQUERY_SOCKET.replace("added", "removed");
    assert_eq!(Format::Osquery.parse_line(&removed), Ok(None));
    // chybi cas, hostitel, EventID, neplatna IP
    assert!(
        Format::Sysmon
            .parse_line(r#"{"EventID":1,"Hostname":"a"}"#)
            .is_err()
    );
    assert!(
        Format::Sysmon
            .parse_line(r#"{"EventID":1,"@timestamp":"2026-11-11T10:00:00Z"}"#)
            .is_err()
    );
    assert!(Format::Sysmon.parse_line("[1,2]").is_err());
    let bad_ip = SYSMON_NESTED.replace("203.0.113.9", "999.1.1.1");
    assert_eq!(Format::Sysmon.parse_line(&bad_ip), Ok(None));
    assert_eq!(parse_time("0"), None);
    assert_eq!(parse_time("-5"), None);
    assert_eq!(parse_time("2026-11-11 10:00:00.5"), Some(1_794_391_200));
}

#[test]
fn batch_limits_hold() {
    let limits = Limits {
        max_batch_events: 3,
        max_line_bytes: 400,
        ..Limits::default()
    };
    let big = format!(
        r#"{{"EventID":1,"Hostname":"a","@timestamp":"2026-11-11T10:00:00Z","Image":"{}"}}"#,
        "x".repeat(1000)
    );
    let text = format!("{big}\n{SYSMON_FLAT}\n{SYSMON_FLAT}\n{SYSMON_NESTED}\n{SYSMON_NESTED}\n");
    let batch = parse_batch(Format::Sysmon, &text, &limits);
    assert_eq!(batch.errors, 1, "radek nad limit se odmitne");
    assert_eq!(batch.events.len(), 3);
    assert!(batch.truncated);
    // pole se orezava
    let long_image = format!(
        r#"{{"EventID":1,"Hostname":"a","@timestamp":"2026-11-11T10:00:00Z","Image":"{}"}}"#,
        "y".repeat(600)
    );
    let e = Format::Sysmon.parse_line(&long_image).unwrap().unwrap();
    if let EventKind::ProcessCreate(p) = e.kind {
        assert_eq!(p.image.chars().count(), super::model::MAX_FIELD);
    } else {
        panic!("proces");
    }
    // davka nad limit bajtu se zkrati na hranici znaku (bez paniky na UTF-8)
    let utf = "á".repeat(100);
    let small = Limits {
        max_batch_bytes: 51,
        ..Limits::default()
    };
    assert!(parse_batch(Format::Sysmon, &utf, &small).truncated);
}

/// Deterministicky generator (bez nove zavislosti).
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

/// E12: fuzz parseru. Nahodne mutace vzorovych zaznamu (zmena, vlozeni, smazani bajtu,
/// useknuti), nahodne bajty a hluboke zanorovani nesmi nikdy zpusobit paniku.
/// Pocet pruchodu: `SALTICUS_FUZZ_N` (vychozi 20 000 na format, v mereni 100 000).
#[test]
fn fuzz_parsers_never_panic() {
    let n: u64 = std::env::var("SALTICUS_FUZZ_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    let seeds: [(Format, &[&str]); 3] = [
        (
            Format::Sysmon,
            &[SYSMON_NESTED, SYSMON_FLAT, SYSMON_WINLOGBEAT],
        ),
        (Format::Wazuh, &[WAZUH_SSH, WAZUH_FIM]),
        (Format::Osquery, &[OSQUERY_SOCKET]),
    ];
    let mut rng = Lcg(0x5EED_8888);
    let mut parsed = 0u64;
    for (format, samples) in seeds {
        for i in 0..n {
            let sample = samples[(rng.next() as usize) % samples.len()];
            let mut bytes = sample.as_bytes().to_vec();
            match i % 6 {
                0 => {
                    for _ in 0..1 + rng.next() % 4 {
                        let at = (rng.next() as usize) % bytes.len();
                        bytes[at] = rng.next() as u8;
                    }
                }
                1 => {
                    let at = (rng.next() as usize) % bytes.len();
                    bytes.truncate(at);
                }
                2 => {
                    let at = (rng.next() as usize) % bytes.len();
                    bytes.remove(at);
                }
                3 => {
                    bytes = (0..(rng.next() % 300)).map(|_| rng.next() as u8).collect();
                }
                4 => {
                    // hluboke zanoreni a obrovska cisla
                    let depth = 1 + rng.next() % 100;
                    bytes = format!(
                        "{}1e999{}",
                        "[".repeat(depth as usize),
                        "]".repeat(depth as usize)
                    )
                    .into_bytes();
                }
                _ => {
                    let at = (rng.next() as usize) % bytes.len();
                    bytes.insert(at, b'"');
                }
            }
            let text = String::from_utf8_lossy(&bytes);
            if format.parse_line(&text).is_ok() {
                parsed += 1;
            }
        }
    }
    // kontrola, ze fuzz neni prazdny: nektere mutace se stale parsuji
    assert!(parsed > 0);
}
