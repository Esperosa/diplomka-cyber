//! Rozpoznání typu zařízení v jádru (krok 2D).
//!
//! Dřív existovala jen heuristika v UI (`ui-src/devices.ts`, `classifyHost`). Tady je
//! ekvivalent v Rustu, aby typ zařízení mohlo použít jádro:
//! - peer-group baseline: zařízení stejného typu a podsítě se porovnávají mezi sebou
//!   (RQ2 §3b a H8: peer-group prior pro zařízení bez historie; měření pro zařízení
//!   v literatuře chybí, jistota velmi nízká, proto se přínos měří A/B),
//! - kontext pro ověřování: služba, která k typu nepatří (tiskárna s portem 22), je
//!   neobvyklá (`unusual_service`).
//!
//! Hlasování: každý znak (aktivum z CMDB, port, produkt, jméno, výrobce z OUI) přidá
//! váhu typu a důvod. Výsledek nese typ, jistotu a lidsky čitelné důvody. Tabulky jsou
//! data (`ClassifierTables`), dají se rozšířit JSONem bez změny kódu.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::model::{HostReport, NetworkAsset};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    Router,
    Switch,
    Ap,
    Server,
    Database,
    Web,
    Mail,
    Files,
    Dns,
    Workstation,
    Mobile,
    Printer,
    Camera,
    Iot,
    Plc,
    Hmi,
    Medical,
    Voip,
    Vpn,
    Container,
    Unknown,
}

impl DeviceKind {
    pub fn label(self) -> &'static str {
        match self {
            DeviceKind::Router => "router",
            DeviceKind::Switch => "switch",
            DeviceKind::Ap => "ap",
            DeviceKind::Server => "server",
            DeviceKind::Database => "database",
            DeviceKind::Web => "web",
            DeviceKind::Mail => "mail",
            DeviceKind::Files => "files",
            DeviceKind::Dns => "dns",
            DeviceKind::Workstation => "workstation",
            DeviceKind::Mobile => "mobile",
            DeviceKind::Printer => "printer",
            DeviceKind::Camera => "camera",
            DeviceKind::Iot => "iot",
            DeviceKind::Plc => "plc",
            DeviceKind::Hmi => "hmi",
            DeviceKind::Medical => "medical",
            DeviceKind::Voip => "voip",
            DeviceKind::Vpn => "vpn",
            DeviceKind::Container => "container",
            DeviceKind::Unknown => "unknown",
        }
    }

    /// Křehké zařízení (OT, IoT, zdravotnictví): aktivní kontrola jen se schválením
    /// (RQ3 Z10: pád PLC po sondě, passive-first).
    pub fn is_fragile(self) -> bool {
        matches!(
            self,
            DeviceKind::Plc
                | DeviceKind::Hmi
                | DeviceKind::Medical
                | DeviceKind::Iot
                | DeviceKind::Camera
                | DeviceKind::Printer
        )
    }

    /// Porty (TCP/UDP), které jsou pro typ běžné. Mimo ně je služba neobvyklá.
    /// `None` = typ bez omezení (obecný server, neznámé).
    pub fn usual_ports(self) -> Option<&'static [u16]> {
        Some(match self {
            DeviceKind::Printer => &[80, 443, 515, 631, 9100, 161],
            DeviceKind::Camera => &[80, 443, 554, 8554, 8000, 8080],
            DeviceKind::Iot => &[80, 443, 1883, 8883, 5683, 8080],
            DeviceKind::Plc => &[102, 502, 44818, 20000, 80, 443, 161],
            DeviceKind::Hmi => &[80, 443, 5900, 102, 502],
            DeviceKind::Medical => &[104, 2575, 80, 443],
            DeviceKind::Voip => &[5060, 5061, 80, 443],
            DeviceKind::Mobile => &[],
            DeviceKind::Workstation => &[3389, 5900, 445, 139, 135],
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceClass {
    pub kind: DeviceKind,
    pub confidence: ClassConfidence,
    /// Proč si to myslíme (lidsky čitelné, pro UI a audit).
    pub reasons: Vec<String>,
}

impl DeviceClass {
    pub fn unknown(reason: &str) -> Self {
        Self {
            kind: DeviceKind::Unknown,
            confidence: ClassConfidence::Low,
            reasons: vec![reason.to_string()],
        }
    }

    /// Je služba `port` pro tento typ neobvyklá? Jen při střední a vyšší jistotě typu,
    /// jinak by nejistá klasifikace vyráběla falešný kontext.
    pub fn unusual_service(&self, port: u16) -> bool {
        self.confidence >= ClassConfidence::Medium
            && self
                .kind
                .usual_ports()
                .is_some_and(|usual| !usual.contains(&port))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortRule {
    pub ports: Vec<u16>,
    pub kind: DeviceKind,
    pub label: String,
    /// Silný znak (jednoznačný protokol) má váhu 3, slabý 1,2.
    pub strong: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TextRule {
    /// Podřetězce (malá písmena) v produktu nebo názvu služby.
    pub needles: Vec<String>,
    pub kind: DeviceKind,
    pub why: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NameRule {
    /// Tokeny jména hostu (po odstranění koncových číslic), přesná shoda.
    #[serde(default)]
    pub tokens: Vec<String>,
    /// Podřetězce jména (malá písmena).
    #[serde(default)]
    pub contains: Vec<String>,
    pub kind: DeviceKind,
    pub why: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VendorRule {
    /// Podřetězce výrobce (malá písmena).
    pub needles: Vec<String>,
    pub kind: DeviceKind,
    pub weight: f64,
}

/// Rozšiřitelné tabulky klasifikátoru (výchozí odpovídají `ui-src/devices.ts`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClassifierTables {
    pub ports: Vec<PortRule>,
    pub products: Vec<TextRule>,
    pub names: Vec<NameRule>,
    pub vendors: Vec<VendorRule>,
    /// OUI (první tři bajty MAC, `aa:bb:cc`, malá písmena) → výrobce.
    pub oui: HashMap<String, String>,
    /// `asset_type` z CMDB/síťového zdroje → typ.
    pub asset_types: HashMap<String, DeviceKind>,
}

fn strs(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

impl Default for ClassifierTables {
    fn default() -> Self {
        use DeviceKind as K;
        let port = |ports: &[u16], kind, label: &str, strong| PortRule {
            ports: ports.to_vec(),
            kind,
            label: label.to_string(),
            strong,
        };
        let text = |needles: &[&str], kind, why: &str| TextRule {
            needles: strs(needles),
            kind,
            why: why.to_string(),
        };
        let name = |tokens: &[&str], contains: &[&str], kind, why: &str| NameRule {
            tokens: strs(tokens),
            contains: strs(contains),
            kind,
            why: why.to_string(),
        };
        let vendor = |needles: &[&str], kind, weight| VendorRule {
            needles: strs(needles),
            kind,
            weight,
        };
        Self {
            ports: vec![
                port(&[9100, 515, 631], K::Printer, "tiskový protokol", true),
                port(&[554, 8554], K::Camera, "RTSP (video)", true),
                port(
                    &[502, 102, 44818, 20000],
                    K::Plc,
                    "průmyslový protokol",
                    true,
                ),
                port(&[104, 2575], K::Medical, "DICOM / HL7", true),
                port(&[5060, 5061], K::Voip, "SIP", true),
                port(&[1194, 500, 4500, 1701], K::Vpn, "VPN protokol", true),
                port(
                    &[6443, 2375, 2376, 10250],
                    K::Container,
                    "orchestrace kontejnerů",
                    true,
                ),
                port(
                    &[3306, 5432, 1433, 27017, 1521, 6379],
                    K::Database,
                    "databázový port",
                    true,
                ),
                port(
                    &[25, 465, 587, 143, 993, 110, 995],
                    K::Mail,
                    "poštovní protokol",
                    true,
                ),
                port(&[445, 139, 2049, 21], K::Files, "sdílení souborů", false),
                port(&[53], K::Dns, "DNS", true),
                port(
                    &[1883, 8883, 5683],
                    K::Iot,
                    "IoT protokol (MQTT/CoAP)",
                    true,
                ),
                port(&[80, 443, 8080, 8443], K::Web, "webový port", false),
                port(&[3389, 5900], K::Workstation, "vzdálená plocha", false),
            ],
            products: vec![
                text(
                    &["jetdirect", "cups", "hp embedded"],
                    K::Printer,
                    "produkt tiskárny",
                ),
                text(
                    &["live555", "hikvision", "dahua", "goahead"],
                    K::Camera,
                    "produkt kamery",
                ),
                text(
                    &["modicon", "siemens s7", "rockwell", "s7-300"],
                    K::Plc,
                    "produkt průmyslového řízení",
                ),
                text(&["wincc"], K::Hmi, "produkt operátorského panelu"),
                text(&["mosquitto", "boa"], K::Iot, "produkt IoT zařízení"),
                text(&["asterisk", "freepbx"], K::Voip, "produkt telefonie"),
                text(&["openvpn", "strongswan"], K::Vpn, "produkt VPN"),
                text(&["dropbear"], K::Ap, "produkt síťového prvku (Dropbear)"),
                text(
                    &["mysql", "postgres", "mariadb", "mongo", "mssql"],
                    K::Database,
                    "produkt databáze",
                ),
                text(&["postfix", "dovecot", "exim"], K::Mail, "produkt pošty"),
                text(&["samba", "vsftpd"], K::Files, "produkt sdílení souborů"),
                text(&["dnsmasq", "bind", "unbound"], K::Dns, "produkt DNS"),
                text(&["orthanc", "hl7"], K::Medical, "produkt zdravotnictví"),
                text(
                    &["kube-apiserver", "docker"],
                    K::Container,
                    "produkt kontejnerů",
                ),
            ],
            names: vec![
                name(
                    &["gw", "gateway", "router", "brana"],
                    &[],
                    K::Router,
                    "název odpovídá bráně",
                ),
                name(&["sw", "switch"], &[], K::Switch, "název odpovídá switchi"),
                name(
                    &["ap", "wifi", "wlan", "aruba", "unifi"],
                    &[],
                    K::Ap,
                    "název odpovídá Wi-Fi AP",
                ),
                name(
                    &[],
                    &["print", "tisk", "mfp", "jetdirect"],
                    K::Printer,
                    "název obsahuje tiskárnu",
                ),
                name(
                    &["cam", "camera", "kamera", "nvr", "dvr"],
                    &[],
                    K::Camera,
                    "název obsahuje kameru",
                ),
                name(&["plc", "scada"], &[], K::Plc, "název obsahuje PLC"),
                name(&["hmi"], &[], K::Hmi, "název obsahuje HMI"),
                name(
                    &["db", "sql", "mysql", "postgres", "mongo"],
                    &[],
                    K::Database,
                    "název obsahuje databázi",
                ),
                name(
                    &["mail", "smtp", "imap", "mx"],
                    &[],
                    K::Mail,
                    "název obsahuje poštu",
                ),
                name(
                    &["files", "nas", "smb", "bak", "backup"],
                    &[],
                    K::Files,
                    "název obsahuje úložiště",
                ),
                name(
                    &["dns", "ldap", "ad"],
                    &[],
                    K::Dns,
                    "název obsahuje adresářovou službu",
                ),
                name(&["vpn"], &[], K::Vpn, "název obsahuje VPN"),
                name(
                    &["web", "www", "proxy", "git", "ci", "wiki"],
                    &[],
                    K::Web,
                    "název obsahuje webovou službu",
                ),
                name(
                    &["voip", "phone", "sip"],
                    &[],
                    K::Voip,
                    "název obsahuje telefon",
                ),
                name(
                    &["ws", "nb", "pc", "laptop", "desktop"],
                    &[],
                    K::Workstation,
                    "název obsahuje pracovní stanici",
                ),
                name(
                    &["iot", "sensor", "hvac"],
                    &[],
                    K::Iot,
                    "název obsahuje IoT zařízení",
                ),
                name(
                    &["iphone", "android", "ipad", "mobile"],
                    &[],
                    K::Mobile,
                    "název mobilního zařízení",
                ),
            ],
            vendors: vec![
                vendor(
                    &[
                        "hp", "brother", "canon", "epson", "xerox", "ricoh", "kyocera",
                    ],
                    K::Printer,
                    1.2,
                ),
                vendor(
                    &["aruba", "ubiquiti", "ruckus", "cisco meraki", "tp-link"],
                    K::Ap,
                    1.0,
                ),
                vendor(&["hikvision", "axis", "dahua", "reolink"], K::Camera, 2.0),
                vendor(&["apple", "samsung", "xiaomi", "huawei"], K::Mobile, 0.8),
                vendor(&["siemens", "schneider", "rockwell"], K::Plc, 1.2),
            ],
            oui: [
                ("00:80:77", "Brother"),
                ("3c:d9:2b", "HP"),
                ("00:40:8c", "Axis"),
                ("44:19:b6", "Hikvision"),
                ("00:1b:1b", "Siemens"),
                ("00:80:f4", "Schneider"),
                ("24:a4:3c", "Ubiquiti"),
                ("f0:18:98", "Apple"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            asset_types: [
                ("router", K::Router),
                ("gateway", K::Router),
                ("firewall", K::Router),
                ("switch", K::Switch),
                ("access-point", K::Ap),
                ("wireless-client", K::Mobile),
                ("printer", K::Printer),
                ("camera", K::Camera),
                ("phone", K::Voip),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        }
    }
}

impl ClassifierTables {
    /// Výchozí tabulky rozšířené o JSON (pole se PŘIDÁVAJÍ před výchozí, takže
    /// vlastní pravidlo vyhraje při stejné váze; mapy se přepisují).
    pub fn extended_with_json(text: &str) -> crate::error::Result<Self> {
        /// Rozšíření: chybějící pole = prázdné (ne výchozí tabulky).
        #[derive(Default, Deserialize)]
        #[serde(default)]
        struct Patch {
            ports: Vec<PortRule>,
            products: Vec<TextRule>,
            names: Vec<NameRule>,
            vendors: Vec<VendorRule>,
            oui: HashMap<String, String>,
            asset_types: HashMap<String, DeviceKind>,
        }
        fn prepend<T>(mine: &mut Vec<T>, theirs: Vec<T>) {
            let mut merged = theirs;
            merged.append(mine);
            *mine = merged;
        }
        let extra: Patch = serde_json::from_str(text)?;
        let mut out = Self::default();
        prepend(&mut out.ports, extra.ports);
        prepend(&mut out.products, extra.products);
        prepend(&mut out.names, extra.names);
        prepend(&mut out.vendors, extra.vendors);
        out.oui.extend(extra.oui);
        out.asset_types.extend(extra.asset_types);
        Ok(out)
    }
}

/// Tokeny jména hostu: dělené `-_.`, bez koncových číslic, malými písmeny.
fn name_tokens(name: &str) -> Vec<String> {
    name.to_ascii_lowercase()
        .split(['-', '_', '.'])
        .map(|token| {
            token
                .trim_end_matches(|c: char| c.is_ascii_digit())
                .to_string()
        })
        .filter(|token| !token.is_empty())
        .collect()
}

fn oui_of(mac: &str) -> Option<String> {
    let normalized = mac.to_ascii_lowercase().replace('-', ":");
    let prefix: Vec<&str> = normalized.split(':').take(3).collect();
    (prefix.len() == 3 && prefix.iter().all(|p| p.len() == 2)).then(|| prefix.join(":"))
}

/// Lokálně spravovaná MAC (druhý nejnižší bit prvního bajtu): náhodná MAC mobilů.
fn locally_administered(mac: &str) -> bool {
    mac.get(0..2)
        .and_then(|b| u8::from_str_radix(b, 16).ok())
        .is_some_and(|b| b & 0x02 != 0)
}

#[derive(Default)]
struct Votes {
    by_kind: HashMap<DeviceKind, (f64, Vec<String>)>,
}

impl Votes {
    fn add(&mut self, kind: DeviceKind, score: f64, why: String) {
        let entry = self.by_kind.entry(kind).or_default();
        entry.0 += score;
        if entry.1.len() < 6 {
            entry.1.push(why);
        }
    }
}

/// Klasifikace hostu. `asset` = záznam z CMDB/síťového zdroje (nejsilnější znak).
pub fn classify(
    host: &HostReport,
    asset: Option<&NetworkAsset>,
    tables: &ClassifierTables,
) -> DeviceClass {
    use DeviceKind as K;
    if let Some(asset) = asset
        && let Some(kind) = tables
            .asset_types
            .get(&asset.asset_type.to_ascii_lowercase())
    {
        let model = asset
            .model
            .as_deref()
            .map(|m| format!(" ({m})"))
            .unwrap_or_default();
        return DeviceClass {
            kind: *kind,
            confidence: ClassConfidence::High,
            reasons: vec![format!(
                "zdroj {} ho vede jako „{}“{model}",
                asset.source, asset.asset_type
            )],
        };
    }
    let mut votes = Votes::default();
    if asset.is_some_and(|a| a.asset_type == "endpoint") {
        votes.add(
            K::Workstation,
            0.8,
            "zdroj ho vede jen jako koncový bod".to_string(),
        );
    }
    let open: Vec<u16> = host
        .services
        .iter()
        .filter(|s| s.port_state == "open" || s.port_state.is_empty())
        .map(|s| s.port)
        .collect();
    for rule in &tables.ports {
        let hit: Vec<String> = rule
            .ports
            .iter()
            .filter(|p| open.contains(p))
            .map(|p| p.to_string())
            .collect();
        if !hit.is_empty() {
            votes.add(
                rule.kind,
                if rule.strong { 3.0 } else { 1.2 },
                format!("{} (port {})", rule.label, hit.join(", ")),
            );
        }
    }
    for service in &host.services {
        let text = format!(
            "{} {}",
            service.inventory.product.as_deref().unwrap_or(""),
            service.inventory.service_name
        )
        .to_ascii_lowercase();
        for rule in &tables.products {
            if rule.needles.iter().any(|n| text.contains(n.as_str())) {
                let what = service
                    .inventory
                    .product
                    .clone()
                    .unwrap_or_else(|| service.inventory.service_name.clone());
                votes.add(rule.kind, 2.2, format!("{} ({what})", rule.why));
            }
        }
    }
    if let Some(name) = host.hostname.as_deref().filter(|n| !n.is_empty()) {
        let tokens = name_tokens(name);
        let lowered = name.to_ascii_lowercase();
        for rule in &tables.names {
            let by_token = rule.tokens.iter().any(|t| tokens.contains(t));
            let by_text = rule.contains.iter().any(|c| lowered.contains(c.as_str()));
            if by_token || by_text {
                votes.add(rule.kind, 2.0, format!("{} („{name}“)", rule.why));
            }
        }
    }
    if host.ip.ends_with(".1") {
        votes.add(
            K::Router,
            1.0,
            "adresa končí na .1 (typicky brána)".to_string(),
        );
    }
    let vendor = host.vendor.clone().or_else(|| {
        host.mac
            .as_deref()
            .and_then(oui_of)
            .and_then(|oui| tables.oui.get(&oui).cloned())
    });
    if let Some(vendor) = vendor {
        let lowered = vendor.to_ascii_lowercase();
        for rule in &tables.vendors {
            if rule.needles.iter().any(|n| {
                lowered == *n
                    || lowered.starts_with(&format!("{n} "))
                    || (n.len() > 3 && lowered.contains(n.as_str()))
            }) {
                votes.add(rule.kind, rule.weight, format!("výrobce {vendor}"));
            }
        }
    } else if host.mac.as_deref().is_some_and(locally_administered) && open.is_empty() {
        votes.add(
            K::Mobile,
            0.8,
            "náhodná (lokálně spravovaná) MAC bez služeb".to_string(),
        );
    }
    if votes.by_kind.is_empty() {
        if host.services.is_empty() {
            return DeviceClass::unknown("žádná otevřená služba ani jméno, nelze určit");
        }
        if open.contains(&22) {
            return DeviceClass {
                kind: K::Server,
                confidence: ClassConfidence::Low,
                reasons: vec!["jen SSH, nejspíš server".to_string()],
            };
        }
        return DeviceClass::unknown("služby nic jednoznačného neříkají");
    }
    let mut ranked: Vec<(DeviceKind, f64, Vec<String>)> = votes
        .by_kind
        .into_iter()
        .map(|(kind, (score, why))| (kind, score, why))
        .collect();
    // deterministicky: skóre sestupně, při shodě pořadí výčtu
    ranked.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    let (kind, best, why) = ranked[0].clone();
    if best < 1.1 && ranked.len() == 1 {
        return DeviceClass::unknown(&format!("jediný náznak je slabý ({})", why[0]));
    }
    let second = ranked.get(1).map(|r| r.1).unwrap_or(0.0);
    // web + databáze/pošta/soubory na jednom hostu = obecnější role, ne čistý web
    let final_kind = if kind == K::Web {
        ranked
            .iter()
            .find(|r| matches!(r.0, K::Database | K::Mail | K::Files))
            .map(|r| r.0)
            .unwrap_or(kind)
    } else {
        kind
    };
    let confidence = if best >= 3.0 && best - second >= 1.5 {
        ClassConfidence::High
    } else if best >= 2.0 {
        ClassConfidence::Medium
    } else {
        ClassConfidence::Low
    };
    DeviceClass {
        kind: final_kind,
        confidence,
        reasons: why,
    }
}

/// Klasifikace všech hostů reportu (aktiva se párují přes `linked_host_key` nebo IP).
pub fn classify_hosts(
    hosts: &mut [HostReport],
    assets: &[NetworkAsset],
    tables: &ClassifierTables,
) {
    for host in hosts.iter_mut() {
        let asset = assets.iter().find(|a| {
            a.linked_host_key.as_deref() == Some(host.host_key.as_str())
                || a.ip.as_deref() == Some(host.ip.as_str())
        });
        host.device_class = Some(classify(host, asset, tables));
    }
}

/// Klíč peer skupiny: typ zařízení (při aspoň střední jistotě) a podsíť /24.
/// `None` = zařízení bez spolehlivého typu do skupiny nepatří.
pub fn peer_group_key(ip: &str, class: &DeviceClass) -> Option<String> {
    if class.kind == DeviceKind::Unknown || class.confidence < ClassConfidence::Medium {
        return None;
    }
    let subnet = ip.rsplit_once('.').map(|(net, _)| net).unwrap_or(ip);
    Some(format!("{}@{subnet}", class.kind.label()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Confidence, InventoryRecord, ServiceReport};

    fn service(port: u16, name: &str, product: Option<&str>) -> ServiceReport {
        ServiceReport {
            service_id: format!("s{port}"),
            service_key: format!("10.0.0.5/tcp/{port}"),
            proto: "tcp".to_string(),
            port,
            port_state: "open".to_string(),
            state_reason: None,
            inventory: InventoryRecord {
                service_name: name.to_string(),
                product: product.map(ToString::to_string),
                version: None,
                extrainfo: None,
                detection_source: "nmap".to_string(),
                confidence: Confidence::High,
            },
            cpe: Vec::new(),
            cves: Vec::new(),
            events: Vec::new(),
            web_probe: None,
            active_checks: Vec::new(),
            score: 0.0,
            priorita: "nizka".to_string(),
        }
    }

    fn host(ip: &str, name: Option<&str>, services: Vec<ServiceReport>) -> HostReport {
        HostReport {
            host_id: ip.to_string(),
            host_key: ip.to_string(),
            ip: ip.to_string(),
            hostname: name.map(ToString::to_string),
            mac: None,
            vendor: None,
            asset_id: None,
            identity_note: None,
            device_class: None,
            services,
        }
    }

    #[test]
    fn printer_by_ports_and_product_with_reasons() {
        let tables = ClassifierTables::default();
        let class = classify(
            &host(
                "10.0.0.20",
                None,
                vec![
                    service(9100, "jetdirect", Some("HP JetDirect")),
                    service(80, "http", Some("HP embedded")),
                ],
            ),
            None,
            &tables,
        );
        assert_eq!(class.kind, DeviceKind::Printer);
        assert_eq!(class.confidence, ClassConfidence::High);
        assert!(class.reasons.iter().any(|r| r.contains("9100")));
        assert!(class.unusual_service(22), "tiskárna s SSH je neobvyklá");
        assert!(!class.unusual_service(631));
    }

    #[test]
    fn asset_record_wins_and_web_with_database_is_database() {
        let tables = ClassifierTables::default();
        let asset = NetworkAsset {
            asset_id: "a1".to_string(),
            asset_type: "switch".to_string(),
            name: "core".to_string(),
            source: "snmp".to_string(),
            confidence: Confidence::High,
            ip: Some("10.0.0.2".to_string()),
            mac: None,
            vendor: None,
            model: Some("C9300".to_string()),
            serial: None,
            status: None,
            location: None,
            linked_host_key: None,
            observations: Vec::new(),
        };
        let class = classify(&host("10.0.0.2", None, vec![]), Some(&asset), &tables);
        assert_eq!(class.kind, DeviceKind::Switch);
        let class = classify(
            &host(
                "10.0.0.7",
                None,
                vec![
                    service(80, "http", Some("nginx")),
                    service(3306, "mysql", Some("MySQL")),
                ],
            ),
            None,
            &tables,
        );
        assert_eq!(class.kind, DeviceKind::Database);
    }

    #[test]
    fn name_tokens_strip_digits_and_need_boundaries() {
        assert_eq!(name_tokens("cam-12.lan"), vec!["cam", "lan"]);
        let tables = ClassifierTables::default();
        let camera = classify(&host("10.0.0.9", Some("cam-12"), vec![]), None, &tables);
        assert_eq!(camera.kind, DeviceKind::Camera);
        // "camping" není kamera (token musí sedět celý)
        let other = classify(&host("10.0.0.9", Some("camping"), vec![]), None, &tables);
        assert_eq!(other.kind, DeviceKind::Unknown);
    }

    #[test]
    fn weak_single_hint_is_unknown_and_ssh_only_is_low_server() {
        let tables = ClassifierTables::default();
        // jediný slabý znak (adresa .1) nestačí
        let weak = classify(&host("10.0.0.1", None, vec![]), None, &tables);
        assert_eq!(weak.kind, DeviceKind::Unknown);
        let web = classify(
            &host("10.0.0.30", None, vec![service(8080, "http-alt", None)]),
            None,
            &tables,
        );
        assert_eq!(web.kind, DeviceKind::Web);
        assert_eq!(web.confidence, ClassConfidence::Low);
        let ssh = classify(
            &host("10.0.0.31", None, vec![service(22, "ssh", Some("OpenSSH"))]),
            None,
            &tables,
        );
        assert_eq!(ssh.kind, DeviceKind::Server);
        assert_eq!(ssh.confidence, ClassConfidence::Low);
        assert!(!ssh.unusual_service(23), "nízká jistota nevyrábí kontext");
        assert!(peer_group_key("10.0.0.31", &ssh).is_none());
    }

    #[test]
    fn tables_extend_from_json_and_oui_resolves_vendor() {
        let tables = ClassifierTables::extended_with_json(
            r#"{"ports":[{"ports":[47808],"kind":"iot","label":"BACnet","strong":true}],
                "oui":{"aa:bb:cc":"Hikvision"}}"#,
        )
        .unwrap();
        let bacnet = classify(
            &host("10.0.1.4", None, vec![service(47808, "bacnet", None)]),
            None,
            &tables,
        );
        assert_eq!(bacnet.kind, DeviceKind::Iot);
        let mut cam = host("10.0.1.5", None, vec![service(554, "rtsp", None)]);
        cam.mac = Some("AA:BB:CC:01:02:03".to_string());
        let class = classify(&cam, None, &tables);
        assert_eq!(class.kind, DeviceKind::Camera);
        assert!(class.reasons.iter().any(|r| r.contains("Hikvision")));
        assert_eq!(
            peer_group_key("10.0.1.5", &class).as_deref(),
            Some("camera@10.0.1")
        );
        assert!(ClassifierTables::extended_with_json("{neplatne").is_err());
    }

    #[test]
    fn classification_is_deterministic_under_ties() {
        let tables = ClassifierTables::default();
        let h = host(
            "10.0.0.40",
            None,
            vec![service(53, "domain", None), service(25, "smtp", None)],
        );
        let first = classify(&h, None, &tables);
        for _ in 0..20 {
            assert_eq!(classify(&h, None, &tables), first);
        }
    }
}
