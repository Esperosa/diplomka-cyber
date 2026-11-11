//! Koncová telemetrie (EDR-like) jako nezávislý druh důkazu (krok 8,
//! docs/diplomka/eval/impl-krok8.md, studie 08).
//!
//! Skákavka čte VÝSTUPY hotových nástrojů (Sysmon a Windows log v JSON, Wazuh alerts,
//! osquery results), žádný vlastní agent. Vrstva:
//! - `model`: typovaná událost,
//! - `sysmon`, `wazuh`, `osquery`: odolné parsery nedůvěryhodného vstupu,
//! - `correlate`: identita hosta, sklad s limity a deduplikací, verdikt hosta,
//!   spojení s toky, pokrytí.
//!
//! Pravidla (A2 předregistrace): neškodný koncový signál sám nezavře nic, chybějící
//! telemetrie je vidět (pokrytí), vstup je omezený, podezřelé zvyšuje jistotu.

pub mod correlate;
pub mod model;
pub mod osquery;
pub mod persist;
pub mod sysmon;
pub mod wazuh;

#[cfg(test)]
mod tests;

use chrono::{DateTime, NaiveDateTime};
use serde_json::{Map, Value};

pub use model::{EndpointEvent, EndpointSource, EventKind, HostRef};

/// Chyba parsování jednoho záznamu (nikdy panika).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub type ParseResult = Result<Option<EndpointEvent>, ParseError>;

/// Formát vstupu (`--format`, `?format=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Sysmon,
    Wazuh,
    Osquery,
}

impl std::str::FromStr for Format {
    type Err = String;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.trim().to_ascii_lowercase().as_str() {
            "sysmon" => Ok(Format::Sysmon),
            "wazuh" => Ok(Format::Wazuh),
            "osquery" => Ok(Format::Osquery),
            other => Err(format!("neznamy format {other} (sysmon | wazuh | osquery)")),
        }
    }
}

impl Format {
    /// Jeden řádek (JSON objekt) na událost; `Ok(None)` = ID události, které nás nezajímá.
    pub fn parse_line(self, line: &str) -> ParseResult {
        let value: Value =
            serde_json::from_str(line).map_err(|e| ParseError(format!("json: {e}")))?;
        let Value::Object(map) = value else {
            return Err(ParseError("radek neni objekt".into()));
        };
        match self {
            Format::Sysmon => sysmon::parse(&map),
            Format::Wazuh => wazuh::parse(&map),
            Format::Osquery => osquery::parse(&map),
        }
    }
}

/// Výsledek zpracování dávky textu (JSONL).
#[derive(Debug, Default)]
pub struct ParsedBatch {
    pub events: Vec<EndpointEvent>,
    pub skipped: usize,
    pub errors: usize,
    pub truncated: bool,
}

/// Rozdělí dávku na řádky s limity velikosti řádku, dávky a počtu událostí.
pub fn parse_batch(format: Format, text: &str, limits: &correlate::Limits) -> ParsedBatch {
    let mut out = ParsedBatch::default();
    let text = if text.len() > limits.max_batch_bytes {
        out.truncated = true;
        let mut cut = limits.max_batch_bytes;
        while cut > 0 && !text.is_char_boundary(cut) {
            cut -= 1;
        }
        &text[..cut]
    } else {
        text
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if out.events.len() >= limits.max_batch_events {
            out.truncated = true;
            break;
        }
        if line.len() > limits.max_line_bytes {
            out.errors += 1;
            continue;
        }
        match format.parse_line(line) {
            Ok(Some(event)) => out.events.push(event),
            Ok(None) => out.skipped += 1,
            Err(_) => out.errors += 1,
        }
    }
    out
}

// ---- společné pomocné funkce parserů ----

fn lookup<'a>(map: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    map.get(name).or_else(|| {
        map.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    })
}

/// Hodnota pole bez ohledu na velikost písmen v názvu; čísla a logické hodnoty jako text.
pub(crate) fn field(map: &Map<String, Value>, names: &[&str]) -> Option<String> {
    for name in names {
        match lookup(map, name) {
            Some(Value::String(s)) if !s.is_empty() => return Some(model::clip(s)),
            Some(Value::Number(n)) => return Some(n.to_string()),
            Some(Value::Bool(b)) => return Some(b.to_string()),
            _ => {}
        }
    }
    None
}

pub(crate) fn child<'a>(map: &'a Map<String, Value>, name: &str) -> Option<&'a Map<String, Value>> {
    lookup(map, name).and_then(Value::as_object)
}

/// Čas z textu: RFC 3339, `YYYY-MM-DD HH:MM:SS(.fff)` (UTC) nebo epocha (s, ms).
pub(crate) fn parse_time(text: &str) -> Option<i64> {
    let text = text.trim();
    if let Ok(n) = text.parse::<f64>() {
        if !n.is_finite() || n <= 0.0 {
            return None;
        }
        return Some(if n > 1.0e11 {
            (n / 1000.0) as i64
        } else {
            n as i64
        });
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(text) {
        return Some(dt.timestamp());
    }
    // Wazuh: 2024-01-01T10:00:00.000+0000
    if let Ok(dt) = DateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S%.f%z") {
        return Some(dt.timestamp());
    }
    for pattern in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(text.trim_end_matches('Z'), pattern) {
            return Some(dt.and_utc().timestamp());
        }
    }
    None
}

pub(crate) fn port(text: Option<String>) -> Option<u16> {
    text.and_then(|t| t.trim().parse::<u16>().ok())
}

pub(crate) fn truthy(text: &str) -> bool {
    matches!(
        text.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes"
    )
}

/// Platná IP adresa (jiné řetězce se zahodí, nikdy se neukládají jako IP).
pub(crate) fn valid_ip(text: &str) -> Option<String> {
    text.trim()
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| ip.to_string())
}

pub(crate) fn ips_of(values: &[Option<String>]) -> Vec<String> {
    let mut ips: Vec<String> = values
        .iter()
        .flatten()
        .filter_map(|v| valid_ip(v))
        .collect();
    ips.sort();
    ips.dedup();
    ips
}
