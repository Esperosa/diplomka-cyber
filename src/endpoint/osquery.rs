//! Parser osquery results (log výsledků plánovaných dotazů). Studie 08, bod 1.
//!
//! Řádek: `{"name": "...", "hostIdentifier": "...", "unixTime": N, "action": "added",
//! "columns": {...}}`. Obsah určuje dotaz, rozpoznává se podle názvu: `process`
//! (cesta, cmdline, rodič), `socket` (vzdálená adresa a port), `startup`, `scheduled`,
//! `service` (perzistence), `logged_in`, `logon` (přihlášení), `file_events`
//! (integrita). Rozpoznává se jen `action` = `added` (a snapshot bez akce);
//! `removed` se zahazuje (nic nového se nestalo).

use serde_json::{Map, Value};

use super::{
    EndpointEvent, EndpointSource, ParseError, ParseResult, child, field,
    model::{Conn, EventKind, HostRef, Logon, Process},
    parse_time, port, truthy, valid_ip,
};

pub fn parse(map: &Map<String, Value>) -> ParseResult {
    let name = field(map, &["name"])
        .ok_or_else(|| ParseError("chybi nazev dotazu".into()))?
        .to_ascii_lowercase();
    let host = field(map, &["hostIdentifier", "host_identifier"])
        .ok_or_else(|| ParseError("chybi hostIdentifier".into()))?
        .to_ascii_lowercase();
    let ts = field(map, &["unixTime", "unix_time", "calendarTime"])
        .and_then(|t| parse_time(&t))
        .ok_or_else(|| ParseError("chybi cas".into()))?;
    if field(map, &["action"]).is_some_and(|a| a == "removed") {
        return Ok(None);
    }
    let cols = child(map, "columns").ok_or_else(|| ParseError("chybi columns".into()))?;
    let hostref = HostRef {
        hostname: Some(host),
        ..Default::default()
    };
    let kind = if name.contains("open_sockets") || name.contains("socket") {
        let dst = valid_ip(&field(cols, &["remote_address"]).unwrap_or_default());
        let (Some(dst), Some(dport)) = (dst, port(field(cols, &["remote_port"]))) else {
            return Ok(None);
        };
        if dport == 0 {
            return Ok(None);
        }
        EventKind::NetConnect(Conn {
            image: field(cols, &["path", "name"]),
            proto: "tcp".into(),
            src_ip: field(cols, &["local_address"]).and_then(|s| valid_ip(&s)),
            src_port: port(field(cols, &["local_port"])),
            dst_ip: dst,
            dst_port: dport,
            vendor: None,
            signed: field(cols, &["signed"]).map(|s| truthy(&s)),
        })
    } else if name.contains("process") {
        EventKind::ProcessCreate(Process {
            image: field(cols, &["path", "name"])
                .ok_or_else(|| ParseError("proces bez cesty".into()))?,
            parent_image: field(cols, &["parent_path", "parent"]),
            cmdline: field(cols, &["cmdline"]).unwrap_or_default(),
            user: field(cols, &["username", "uid"]),
            signed: field(cols, &["signed"]).map(|s| truthy(&s)),
            vendor: field(cols, &["authority", "signer"]),
        })
    } else if name.contains("startup") || name.contains("scheduled") || name.contains("service") {
        EventKind::Persistence {
            mechanism: if name.contains("scheduled") {
                "scheduled_task"
            } else if name.contains("service") {
                "service"
            } else {
                "startup_item"
            }
            .into(),
            target: field(cols, &["name", "path"]).unwrap_or_default(),
            image: field(cols, &["path", "module_path"]),
            signed: field(cols, &["signed"]).map(|s| truthy(&s)),
        }
    } else if name.contains("logged_in") || name.contains("logon") {
        EventKind::Logon(Logon {
            user: field(cols, &["user", "username"]).unwrap_or_else(|| "?".into()),
            logon_type: field(cols, &["type", "logon_type"])
                .and_then(|t| t.parse().ok())
                .unwrap_or(0),
            src_ip: field(cols, &["host", "remote_address"]).and_then(|s| valid_ip(&s)),
            success: true,
        })
    } else if name.contains("file_events") {
        EventKind::Integrity {
            path: field(cols, &["target_path"])
                .ok_or_else(|| ParseError("file_events bez cesty".into()))?,
            change: field(cols, &["action"]).unwrap_or_else(|| "modified".into()),
        }
    } else {
        return Ok(None);
    };
    Ok(Some(EndpointEvent {
        source: EndpointSource::Osquery,
        host: hostref,
        ts,
        kind,
    }))
}
