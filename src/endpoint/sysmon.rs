//! Parser Sysmon a Windows Security událostí v JSON (EVTX exporty, winlogbeat, ploché
//! záznamy OTRF Security-Datasets). Studie 08, bod 1.
//!
//! Podporované: Sysmon 1, 3, 10, 11, 13 a Windows 4624, 4625, 4688, 7045. Ostatní ID
//! vrací `Ok(None)`. Sysmon ID 1 podpis neuvádí, proto `signed = None` a výrobce z
//! pole `Company`.

use serde_json::{Map, Value};

use super::{
    EndpointEvent, EndpointSource, ParseError, ParseResult, child, field, ips_of,
    model::{Conn, EventKind, HostRef, Logon, Process, clip},
    parse_time, port, truthy,
};

struct Layout {
    id: Option<String>,
    host: Option<String>,
    time: Option<String>,
    data: Map<String, Value>,
}

fn layout(map: &Map<String, Value>) -> Layout {
    if let Some(event) = child(map, "Event") {
        let system = child(event, "System");
        let id = system.and_then(|s| {
            field(s, &["EventID"])
                .or_else(|| child(s, "EventID").and_then(|e| field(e, &["#text", "text"])))
        });
        return Layout {
            id,
            host: system.and_then(|s| field(s, &["Computer"])),
            time: system
                .and_then(|s| child(s, "TimeCreated"))
                .and_then(|t| field(t, &["SystemTime"])),
            data: child(event, "EventData").cloned().unwrap_or_default(),
        };
    }
    if let Some(winlog) = child(map, "winlog") {
        return Layout {
            id: field(winlog, &["event_id"]),
            host: field(winlog, &["computer_name"]),
            time: field(map, &["@timestamp"]),
            data: child(winlog, "event_data").cloned().unwrap_or_default(),
        };
    }
    let data = child(map, "EventData")
        .cloned()
        .unwrap_or_else(|| map.clone());
    Layout {
        id: field(map, &["EventID", "event_id"]),
        host: field(map, &["Hostname", "Computer", "host_name", "computer_name"]),
        time: field(map, &["@timestamp", "EventTime", "TimeCreated"]),
        data,
    }
}

pub fn parse(map: &Map<String, Value>) -> ParseResult {
    let lay = layout(map);
    let id: u32 = lay
        .id
        .and_then(|t| t.trim().parse().ok())
        .ok_or_else(|| ParseError("chybi EventID".into()))?;
    let ts = lay
        .time
        .and_then(|t| parse_time(&t))
        .or_else(|| field(&lay.data, &["UtcTime"]).and_then(|t| parse_time(&t)))
        .ok_or_else(|| ParseError("chybi cas udalosti".into()))?;
    let hostname = lay
        .host
        .ok_or_else(|| ParseError("chybi hostitel".into()))?;
    let host = HostRef {
        hostname: Some(hostname.to_ascii_lowercase()),
        ..Default::default()
    };
    Ok(from_event(id, &lay.data, host, ts, EndpointSource::Sysmon))
}

/// Překlad události podle ID a polí (sdílí Wazuh pro vnořené Windows události).
pub fn from_event(
    id: u32,
    data: &Map<String, Value>,
    mut host: HostRef,
    ts: i64,
    source: EndpointSource,
) -> Option<EndpointEvent> {
    let kind = match id {
        1 | 4688 => EventKind::ProcessCreate(Process {
            image: field(data, &["Image", "NewProcessName"])?,
            parent_image: field(data, &["ParentImage", "ParentProcessName"]),
            cmdline: field(data, &["CommandLine"]).unwrap_or_default(),
            user: field(data, &["User", "SubjectUserName"]),
            signed: field(data, &["Signed"]).map(|s| truthy(&s)),
            vendor: field(data, &["Company"]),
        }),
        3 => {
            // jen odchozí spojení (pokud je pole uvedeno)
            if let Some(initiated) = field(data, &["Initiated"])
                && !truthy(&initiated)
            {
                return None;
            }
            let dst = super::valid_ip(&field(data, &["DestinationIp"])?)?;
            let src = field(data, &["SourceIp"]).and_then(|s| super::valid_ip(&s));
            if host.ips.is_empty() {
                host.ips = ips_of(std::slice::from_ref(&src));
            }
            EventKind::NetConnect(Conn {
                image: field(data, &["Image"]),
                proto: field(data, &["Protocol"])
                    .map(|p| p.to_ascii_lowercase())
                    .unwrap_or_else(|| "tcp".into()),
                src_ip: src,
                src_port: port(field(data, &["SourcePort"])),
                dst_ip: dst,
                dst_port: port(field(data, &["DestinationPort"]))?,
                vendor: None,
                signed: None,
            })
        }
        10 => EventKind::ProcessAccess {
            source: field(data, &["SourceImage"])?,
            target: field(data, &["TargetImage"])?,
            access: field(data, &["GrantedAccess"]).unwrap_or_default(),
        },
        11 => EventKind::FileCreate {
            image: field(data, &["Image"]),
            path: field(data, &["TargetFilename"])?,
        },
        13 => {
            let target = field(data, &["TargetObject"])?;
            let lower = target.to_ascii_lowercase();
            let mechanism = if lower.contains("\\currentversion\\run") {
                "registry_run"
            } else if lower.contains("\\services\\") && lower.ends_with("\\imagepath") {
                "service_registry"
            } else {
                return None;
            };
            EventKind::Persistence {
                mechanism: mechanism.into(),
                target: clip(&format!(
                    "{target} = {}",
                    field(data, &["Details"]).unwrap_or_default()
                )),
                image: field(data, &["Image"]),
                signed: None,
            }
        }
        4624 | 4625 => EventKind::Logon(Logon {
            user: field(data, &["TargetUserName"])?,
            logon_type: field(data, &["LogonType"])
                .and_then(|t| t.trim().parse().ok())
                .unwrap_or(0),
            src_ip: field(data, &["IpAddress", "SourceNetworkAddress"])
                .and_then(|s| super::valid_ip(&s)),
            success: id == 4624,
        }),
        7045 => EventKind::ServiceInstall {
            name: field(data, &["ServiceName"])?,
            image: field(data, &["ImagePath", "ImageFile"])?,
            signed: None,
        },
        _ => return None,
    };
    Some(EndpointEvent {
        source,
        host,
        ts,
        kind,
    })
}
