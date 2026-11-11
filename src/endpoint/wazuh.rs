//! Parser Wazuh alerts (`alerts.json`, jeden JSON objekt na řádek). Studie 08, bod 1.
//!
//! Alert nese `rule.{id,level,groups,description}`, `agent.{id,name,ip}`, `data.*` a
//! volitelně `syscheck.*` (integrita souborů). Windows události vnořené v
//! `data.win.{system,eventdata}` se překládají stejně jako Sysmon. Ostatní alerty jsou
//! druh `Alert` (úroveň pravidla určuje váhu); neúspěšná přihlášení SSH (skupina
//! `authentication_failed`) se přeloží na `Logon` s `success = false`.

use serde_json::{Map, Value};

use super::{
    EndpointEvent, EndpointSource, ParseError, ParseResult, child, field, ips_of,
    model::{EventKind, HostRef, Logon, clip},
    parse_time, sysmon, valid_ip,
};

pub fn parse(map: &Map<String, Value>) -> ParseResult {
    let ts = field(map, &["timestamp", "@timestamp"])
        .and_then(|t| parse_time(&t))
        .ok_or_else(|| ParseError("chybi cas alertu".into()))?;
    let agent = child(map, "agent").ok_or_else(|| ParseError("chybi agent".into()))?;
    let name = field(agent, &["name"]).map(|n| n.to_ascii_lowercase());
    let id = field(agent, &["id"]);
    if name.is_none() && id.is_none() {
        return Err(ParseError("agent bez nazvu a id".into()));
    }
    let host = HostRef {
        hostname: name,
        ips: ips_of(&[field(agent, &["ip"])]),
        macs: Vec::new(),
        agent: id,
    };
    let rule = child(map, "rule");
    let data = child(map, "data");
    // vnořená Windows událost
    if let Some(win) = data.and_then(|d| child(d, "win"))
        && let (Some(system), Some(eventdata)) = (child(win, "system"), child(win, "eventdata"))
        && let Some(event_id) = field(system, &["eventID"]).and_then(|t| t.trim().parse().ok())
        && let Some(event) =
            sysmon::from_event(event_id, eventdata, host.clone(), ts, EndpointSource::Wazuh)
    {
        return Ok(Some(event));
    }
    let level = rule
        .and_then(|r| field(r, &["level"]))
        .and_then(|l| l.parse::<u8>().ok())
        .unwrap_or(0);
    let groups: Vec<String> = rule
        .and_then(|r| r.get("groups"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .take(16)
                .map(clip)
                .collect()
        })
        .unwrap_or_default();
    let kind = if let Some(sys) = child(map, "syscheck") {
        EventKind::Integrity {
            path: field(sys, &["path"]).ok_or_else(|| ParseError("syscheck bez cesty".into()))?,
            change: field(sys, &["event"]).unwrap_or_else(|| "modified".into()),
        }
    } else if groups
        .iter()
        .any(|g| g == "authentication_failed" || g == "authentication_failures")
        && let Some(src) = data
            .and_then(|d| field(d, &["srcip"]))
            .and_then(|s| valid_ip(&s))
    {
        EventKind::Logon(Logon {
            user: data
                .and_then(|d| field(d, &["dstuser"]))
                .unwrap_or_else(|| "?".into()),
            logon_type: 0,
            src_ip: Some(src),
            success: false,
        })
    } else {
        EventKind::Alert {
            rule_id: rule.and_then(|r| field(r, &["id"])).unwrap_or_default(),
            level,
            groups,
            description: rule
                .and_then(|r| field(r, &["description"]))
                .unwrap_or_default(),
        }
    };
    Ok(Some(EndpointEvent {
        source: EndpointSource::Wazuh,
        host,
        ts,
        kind,
    }))
}
