//! Typovaný model koncové události (krok 8, A1; studie 08, bod 1).
//!
//! Model je nezávislý na zdroji: parsery (`sysmon`, `wazuh`, `osquery`) přeloží výstup
//! hotového nástroje na `EndpointEvent`, korelace (`correlate`) čte jen tento model.

use serde::{Deserialize, Serialize};

/// Nejvyšší délka textového pole události (delší se ořízne na hranici znaku).
pub const MAX_FIELD: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointSource {
    Sysmon,
    Wazuh,
    Osquery,
    /// Simulace soak harnessu.
    Sim,
}

impl EndpointSource {
    pub fn label(self) -> &'static str {
        match self {
            EndpointSource::Sysmon => "sysmon",
            EndpointSource::Wazuh => "wazuh",
            EndpointSource::Osquery => "osquery",
            EndpointSource::Sim => "sim",
        }
    }
}

/// Identifikátory hosta z události (slabé a měnitelné, proto se nikdy nesměšují).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRef {
    pub hostname: Option<String>,
    pub ips: Vec<String>,
    pub macs: Vec<String>,
    pub agent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    pub image: String,
    pub parent_image: Option<String>,
    pub cmdline: String,
    pub user: Option<String>,
    /// `Some(true)` jen ze zdroje, který podpis uvádí (Sysmon ID 7, osquery).
    pub signed: Option<bool>,
    /// Výrobce (`Company`) nebo podepisující.
    pub vendor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conn {
    pub image: Option<String>,
    pub proto: String,
    pub src_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_ip: String,
    pub dst_port: u16,
    pub vendor: Option<String>,
    pub signed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Logon {
    pub user: String,
    /// Windows typ přihlášení (3 síť, 10 vzdálená plocha); 0 = neznámý (SSH a jiné).
    pub logon_type: u8,
    pub src_ip: Option<String>,
    pub success: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventKind {
    ProcessCreate(Process),
    NetConnect(Conn),
    Logon(Logon),
    FileCreate {
        image: Option<String>,
        path: String,
    },
    ServiceInstall {
        name: String,
        image: String,
        signed: Option<bool>,
    },
    Persistence {
        mechanism: String,
        target: String,
        image: Option<String>,
        signed: Option<bool>,
    },
    Integrity {
        path: String,
        change: String,
    },
    ProcessAccess {
        source: String,
        target: String,
        access: String,
    },
    Alert {
        rule_id: String,
        level: u8,
        groups: Vec<String>,
        description: String,
    },
}

impl EventKind {
    pub fn label(&self) -> &'static str {
        match self {
            EventKind::ProcessCreate(_) => "process_create",
            EventKind::NetConnect(_) => "net_connect",
            EventKind::Logon(_) => "logon",
            EventKind::FileCreate { .. } => "file_create",
            EventKind::ServiceInstall { .. } => "service_install",
            EventKind::Persistence { .. } => "persistence",
            EventKind::Integrity { .. } => "integrity",
            EventKind::ProcessAccess { .. } => "process_access",
            EventKind::Alert { .. } => "alert",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointEvent {
    pub source: EndpointSource,
    pub host: HostRef,
    /// Čas události podle hodin agenta (epocha, sekundy).
    pub ts: i64,
    pub kind: EventKind,
}

/// Ořízne text na `MAX_FIELD` znaků (ne bajtů, aby nevznikl neplatný UTF-8).
pub fn clip(text: &str) -> String {
    text.chars().take(MAX_FIELD).collect()
}

fn fnv(state: u64, bytes: &[u8]) -> u64 {
    bytes.iter().fold(state, |a, b| {
        (a ^ u64::from(*b)).wrapping_mul(0x100_0000_01b3)
    })
}

impl EndpointEvent {
    /// Otisk obsahu pro deduplikaci (at-least-once doručení). Zdroj, host, čas a obsah.
    pub fn fingerprint(&self) -> u64 {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        h = fnv(h, self.source.label().as_bytes());
        h = fnv(h, &self.ts.to_le_bytes());
        let host = serde_json::to_vec(&self.host).unwrap_or_default();
        h = fnv(h, &host);
        let kind = serde_json::to_vec(&self.kind).unwrap_or_default();
        fnv(h, &kind)
    }
}
