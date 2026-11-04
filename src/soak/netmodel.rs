//! Virtualni sit: deterministicky odvozena ze (seed behu, id site). Zadna sit se
//! neuklada - kdykoli se znovu postavi z dvojice cisel, takze "miliony siti" jsou
//! jen citac, ne pamet. Model drzi pravdu (identita zarizeni pres zmeny IP,
//! sluzby, zranitelnosti), kterou engine nikdy nevidi a scoring s ni porovnava.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::{
    model::Confidence,
    model::{CveRecord, CvssRecord, ExploitContext, KevRecord},
    nmap::{ParsedHost, ParsedInventory, ParsedService},
    soak::rng::{Rng, derive},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    Gateway,
    Dns,
    Web,
    Database,
    Mail,
    FileServer,
    Workstation,
    Printer,
    IotSensor,
    Camera,
    Jump,
    /// Prumyslovy automat (Modbus/S7/EtherNet-IP).
    Plc,
    /// Operatorsky panel/SCADA stanice, mluvi s PLC.
    Hmi,
    Medical,
    VoipPhone,
    WifiAp,
    Vpn,
    Container,
    /// Mobilni zarizeni (roaming, castá zmena adresy).
    Mobile,
}

impl Role {
    pub const ALL: [Role; 19] = [
        Role::Gateway,
        Role::Dns,
        Role::Web,
        Role::Database,
        Role::Mail,
        Role::FileServer,
        Role::Workstation,
        Role::Printer,
        Role::IotSensor,
        Role::Camera,
        Role::Jump,
        Role::Plc,
        Role::Hmi,
        Role::Medical,
        Role::VoipPhone,
        Role::WifiAp,
        Role::Vpn,
        Role::Container,
        Role::Mobile,
    ];

    pub fn is_server(self) -> bool {
        matches!(
            self,
            Role::Gateway
                | Role::Dns
                | Role::Web
                | Role::Database
                | Role::Mail
                | Role::FileServer
                | Role::Jump
                | Role::Plc
                | Role::WifiAp
                | Role::Vpn
                | Role::Container
        )
    }

    pub fn label(self) -> &'static str {
        match self {
            Role::Gateway => "gateway",
            Role::Dns => "dns",
            Role::Web => "web",
            Role::Database => "db",
            Role::Mail => "mail",
            Role::FileServer => "files",
            Role::Workstation => "ws",
            Role::Printer => "printer",
            Role::IotSensor => "iot",
            Role::Camera => "cam",
            Role::Jump => "jump",
            Role::Plc => "plc",
            Role::Hmi => "hmi",
            Role::Medical => "medical",
            Role::VoipPhone => "voip",
            Role::WifiAp => "wifi-ap",
            Role::Vpn => "vpn",
            Role::Container => "container",
            Role::Mobile => "mobile",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Archetype {
    Soho,
    Smb,
    Datacenter,
    IotHeavy,
    Campus,
    /// Stovky az tisice zarizeni, desitky podsiti (VLAN), segmentace.
    Enterprise,
    /// Velka organizace: tisice zarizeni, desitky az stovky podsiti.
    Metro,
    /// OT/ICS: PLC, HMI, historian, oddelene vyrobni podsite.
    Industrial,
    Hospital,
    /// Cloud VPC: kontejnery, kratce zijici adresy, VPN.
    Cloud,
}

impl Archetype {
    pub const ALL: [Archetype; 10] = [
        Archetype::Soho,
        Archetype::Smb,
        Archetype::Datacenter,
        Archetype::IotHeavy,
        Archetype::Campus,
        Archetype::Enterprise,
        Archetype::Metro,
        Archetype::Industrial,
        Archetype::Hospital,
        Archetype::Cloud,
    ];
}

/// Velikostni trida sit podle poctu zarizeni (klic pro agregace v reportu).
pub fn size_class(devices: usize) -> &'static str {
    match devices {
        0..=25 => "S (<=25)",
        26..=100 => "M (26-100)",
        101..=400 => "L (101-400)",
        401..=1500 => "XL (401-1500)",
        1501..=6000 => "XXL (1501-6000)",
        _ => "XXXL (>6000)",
    }
}

/// Třída XXXL (krok 3) vzniká jen vynucením (`--size xxxl`), ne v běžném mixu.
pub const SIZE_CLASSES: [&str; 6] = [
    "S (<=25)",
    "M (26-100)",
    "L (101-400)",
    "XL (401-1500)",
    "XXL (1501-6000)",
    "XXXL (>6000)",
];

#[derive(Debug, Clone)]
pub struct Svc {
    pub port: u16,
    pub proto: &'static str,
    pub name: &'static str,
    pub product: &'static str,
    pub version: &'static str,
    pub plaintext: bool,
    pub web: bool,
    /// (cve_id, cvss, kev)
    pub cves: Vec<(&'static str, f64, bool)>,
}

#[derive(Debug, Clone)]
pub struct Device {
    pub id: u32,
    pub mac: String,
    pub role: Role,
    pub subnet: usize,
    pub host_octet: u8,
    pub services: Vec<Svc>,
    pub criticality: f64,
    pub dhcp: bool,
    /// Zakladni pocet toku za hodinu u klientskych roli.
    pub rate: f64,
    pub peers: Vec<u32>,
    /// Zarizeni je pritomne a bezi (false = pad, odstaveni, jeste nenasazene).
    pub up: bool,
}

#[derive(Debug, Clone)]
pub struct NetworkModel {
    pub id: u64,
    pub seed: u64,
    pub archetype: Archetype,
    pub prefixes: Vec<[u8; 3]>,
    pub devices: Vec<Device>,
    pub gateway: u32,
    pub dns: u32,
    pub externals: Vec<String>,
    pub tz_hours: i64,
    ip_index: std::collections::HashMap<String, u32>,
    prefix_index: std::collections::HashMap<[u8; 3], usize>,
}

// Ilustrativni prirazeni zranitelnosti (kombinace produkt/verze -> CVE s realistickym
// CVSS); cilem je rozlozeni zavaznosti pro engine, ne pravdivost konkretni verze.
fn svc(
    port: u16,
    proto: &'static str,
    name: &'static str,
    product: &'static str,
    version: &'static str,
) -> Svc {
    let cves: Vec<(&'static str, f64, bool)> = match (product, version) {
        ("OpenSSH", "7.4") => vec![
            ("CVE-2018-15473", 5.3, false),
            ("CVE-2016-10009", 7.3, false),
        ],
        ("OpenSSH", "8.2") => vec![("CVE-2020-15778", 7.8, false)],
        ("nginx", "1.14") => vec![
            ("CVE-2019-9511", 7.5, false),
            ("CVE-2021-23017", 7.7, false),
        ],
        ("Apache httpd", "2.4.49") => {
            vec![("CVE-2021-41773", 7.5, true), ("CVE-2021-42013", 9.8, true)]
        }
        ("MySQL", "5.7") => vec![
            ("CVE-2020-14812", 4.9, false),
            ("CVE-2021-2307", 7.2, false),
        ],
        ("GoAhead", "3.6") => vec![("CVE-2017-17562", 8.1, true)],
        ("BusyBox telnetd", "1.30") => vec![("CVE-2021-42386", 7.2, false)],
        ("Samba", "4.9") => vec![("CVE-2020-1472", 10.0, true), ("CVE-2017-7494", 9.8, true)],
        ("Postfix", "3.3") => vec![("CVE-2020-12063", 5.9, false)],
        ("vsftpd", "2.3.4") => vec![("CVE-2011-2523", 9.8, true)],
        ("Boa", "0.94") => vec![("CVE-2017-9833", 8.8, false)],
        ("Modicon M340", "3.0") => vec![("CVE-2021-22779", 9.8, true)],
        ("Siemens S7-300", "3.2") => vec![("CVE-2019-13945", 7.5, false)],
        ("Dropbear", "2017.75") => vec![("CVE-2018-15599", 5.3, false)],
        ("OpenVPN", "2.4") => vec![("CVE-2020-11810", 5.9, false)],
        ("kube-apiserver", "1.18") => vec![("CVE-2020-8558", 8.8, true)],
        ("Asterisk", "13.0") => vec![("CVE-2019-18610", 7.5, false)],
        ("Orthanc DICOM", "1.5") => vec![("CVE-2020-12640", 9.8, false)],
        _ => Vec::new(),
    };
    Svc {
        port,
        proto,
        name,
        product,
        version,
        plaintext: matches!(name, "telnet" | "ftp" | "http"),
        web: matches!(name, "http" | "https" | "http-alt"),
        cves,
    }
}

fn services_for(role: Role, rng: &mut Rng) -> Vec<Svc> {
    // Cast zarizeni ma starsi (zranitelnou) verzi - realisticka heterogenita.
    let old = rng.chance(0.35);
    match role {
        Role::Gateway => vec![
            svc(22, "tcp", "ssh", "OpenSSH", if old { "7.4" } else { "9.0" }),
            svc(
                443,
                "tcp",
                "https",
                "nginx",
                if old { "1.14" } else { "1.24" },
            ),
        ],
        Role::Dns => vec![
            svc(53, "udp", "domain", "dnsmasq", "2.89"),
            svc(53, "tcp", "domain", "dnsmasq", "2.89"),
        ],
        Role::Web => {
            let mut v = vec![
                svc(
                    80,
                    "tcp",
                    "http",
                    if old { "Apache httpd" } else { "nginx" },
                    if old { "2.4.49" } else { "1.24" },
                ),
                svc(
                    443,
                    "tcp",
                    "https",
                    "nginx",
                    if old { "1.14" } else { "1.24" },
                ),
            ];
            if rng.chance(0.3) {
                v.push(svc(8080, "tcp", "http-alt", "nginx", "1.24"));
            }
            v
        }
        Role::Database => vec![svc(
            3306,
            "tcp",
            "mysql",
            "MySQL",
            if old { "5.7" } else { "8.0" },
        )],
        Role::Mail => vec![
            svc(
                25,
                "tcp",
                "smtp",
                "Postfix",
                if old { "3.3" } else { "3.8" },
            ),
            svc(993, "tcp", "imaps", "Dovecot", "2.3"),
        ],
        Role::FileServer => {
            let mut v = vec![svc(
                445,
                "tcp",
                "microsoft-ds",
                "Samba",
                if old { "4.9" } else { "4.18" },
            )];
            if rng.chance(0.25) {
                v.push(svc(
                    21,
                    "tcp",
                    "ftp",
                    "vsftpd",
                    if old { "2.3.4" } else { "3.0.5" },
                ));
            }
            v
        }
        Role::Workstation => {
            if rng.chance(0.2) {
                vec![svc(3389, "tcp", "ms-wbt-server", "Microsoft RDP", "10.0")]
            } else {
                Vec::new()
            }
        }
        Role::Printer => vec![
            svc(9100, "tcp", "jetdirect", "HP JetDirect", "1.0"),
            svc(80, "tcp", "http", "HP embedded", "1.0"),
        ],
        Role::IotSensor => {
            let mut v = vec![
                svc(80, "tcp", "http", "Boa", "0.94"),
                svc(1883, "tcp", "mqtt", "Mosquitto", "1.6"),
            ];
            if rng.chance(0.4) {
                v.push(svc(23, "tcp", "telnet", "BusyBox telnetd", "1.30"));
            }
            v
        }
        Role::Camera => {
            let mut v = vec![
                svc(554, "tcp", "rtsp", "Live555", "2020"),
                svc(80, "tcp", "http", "GoAhead", "3.6"),
            ];
            if rng.chance(0.5) {
                v.push(svc(23, "tcp", "telnet", "BusyBox telnetd", "1.30"));
            }
            v
        }
        Role::Jump => vec![
            svc(22, "tcp", "ssh", "OpenSSH", if old { "8.2" } else { "9.0" }),
            svc(3389, "tcp", "ms-wbt-server", "Microsoft RDP", "10.0"),
        ],
        Role::Plc => {
            let mut v = if rng.chance(0.6) {
                vec![svc(
                    502,
                    "tcp",
                    "modbus",
                    "Modicon M340",
                    if old { "3.0" } else { "3.4" },
                )]
            } else {
                vec![svc(
                    102,
                    "tcp",
                    "iso-tsap",
                    "Siemens S7-300",
                    if old { "3.2" } else { "3.3" },
                )]
            };
            if rng.chance(0.3) {
                v.push(svc(44818, "tcp", "EtherNet-IP", "Rockwell CIP", "20.0"));
            }
            v
        }
        Role::Hmi => vec![
            svc(5900, "tcp", "vnc", "TightVNC", "2.8"),
            svc(80, "tcp", "http", "Siemens WinCC", "7.5"),
        ],
        Role::Medical => vec![
            svc(
                104,
                "tcp",
                "dicom",
                "Orthanc DICOM",
                if old { "1.5" } else { "1.12" },
            ),
            svc(2575, "tcp", "hl7", "HL7 listener", "2.5"),
        ],
        Role::VoipPhone => vec![svc(
            5060,
            "udp",
            "sip",
            "Asterisk",
            if old { "13.0" } else { "20.0" },
        )],
        Role::WifiAp => vec![
            svc(
                22,
                "tcp",
                "ssh",
                "Dropbear",
                if old { "2017.75" } else { "2022.83" },
            ),
            svc(443, "tcp", "https", "nginx", "1.24"),
        ],
        Role::Vpn => vec![
            svc(
                1194,
                "udp",
                "openvpn",
                "OpenVPN",
                if old { "2.4" } else { "2.6" },
            ),
            svc(443, "tcp", "https", "nginx", "1.24"),
        ],
        Role::Container => {
            let mut v = vec![svc(8080, "tcp", "http-alt", "nginx", "1.24")];
            if rng.chance(0.05) {
                v.push(svc(
                    6443,
                    "tcp",
                    "kube-apiserver",
                    "kube-apiserver",
                    if old { "1.18" } else { "1.29" },
                ));
            }
            v
        }
        Role::Mobile => Vec::new(),
    }
}

fn random_mac(rng: &mut Rng) -> String {
    format!(
        "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        rng.range(0, 255),
        rng.range(0, 255),
        rng.range(0, 255),
        rng.range(0, 255),
        rng.range(0, 255)
    )
}

struct Profile {
    weight: f64,
    devices: (u64, u64),
    subnets: (u64, u64),
    dhcp_share: f64,
    server_share: f64,
    /// (role, vaha) pro servery / klienty.
    servers: &'static [(Role, f64)],
    clients: &'static [(Role, f64)],
}

const GENERIC_SERVERS: &[(Role, f64)] = &[
    (Role::Web, 2.0),
    (Role::Database, 1.0),
    (Role::Mail, 1.0),
    (Role::FileServer, 1.0),
    (Role::Jump, 1.0),
];

fn profile(archetype: Archetype) -> Profile {
    match archetype {
        Archetype::Soho => Profile {
            weight: 0.20,
            devices: (5, 14),
            subnets: (1, 1),
            dhcp_share: 0.8,
            server_share: 0.1,
            servers: GENERIC_SERVERS,
            clients: &[
                (Role::Workstation, 2.0),
                (Role::Printer, 1.0),
                (Role::IotSensor, 1.0),
                (Role::Camera, 1.0),
                (Role::Mobile, 1.5),
            ],
        },
        Archetype::Smb => Profile {
            weight: 0.18,
            devices: (15, 55),
            subnets: (1, 2),
            dhcp_share: 0.6,
            server_share: 0.2,
            servers: GENERIC_SERVERS,
            clients: &[
                (Role::Workstation, 3.0),
                (Role::Printer, 1.0),
                (Role::IotSensor, 1.0),
                (Role::Camera, 1.0),
                (Role::VoipPhone, 1.5),
                (Role::Mobile, 1.5),
            ],
        },
        Archetype::Datacenter => Profile {
            weight: 0.09,
            devices: (30, 120),
            subnets: (2, 3),
            dhcp_share: 0.0,
            server_share: 0.75,
            servers: &[
                (Role::Web, 3.0),
                (Role::Database, 2.0),
                (Role::Mail, 1.0),
                (Role::FileServer, 1.0),
                (Role::Jump, 1.0),
                (Role::Container, 2.0),
                (Role::Vpn, 0.3),
            ],
            clients: &[(Role::Workstation, 1.0), (Role::IotSensor, 1.0)],
        },
        Archetype::IotHeavy => Profile {
            weight: 0.08,
            devices: (20, 70),
            subnets: (1, 2),
            dhcp_share: 0.7,
            server_share: 0.2,
            servers: GENERIC_SERVERS,
            clients: &[
                (Role::IotSensor, 2.0),
                (Role::Camera, 1.0),
                (Role::Workstation, 1.0),
                (Role::Printer, 1.0),
            ],
        },
        Archetype::Campus => Profile {
            weight: 0.08,
            devices: (80, 220),
            subnets: (2, 4),
            dhcp_share: 0.7,
            server_share: 0.2,
            servers: GENERIC_SERVERS,
            clients: &[
                (Role::Workstation, 3.0),
                (Role::Printer, 1.0),
                (Role::IotSensor, 1.0),
                (Role::Camera, 1.0),
                (Role::WifiAp, 0.5),
                (Role::Mobile, 3.0),
            ],
        },
        Archetype::Enterprise => Profile {
            weight: 0.15,
            devices: (300, 1500),
            subnets: (8, 32),
            dhcp_share: 0.75,
            server_share: 0.12,
            servers: &[
                (Role::Web, 2.0),
                (Role::Database, 2.0),
                (Role::Mail, 1.0),
                (Role::FileServer, 2.0),
                (Role::Jump, 1.0),
                (Role::Vpn, 0.5),
                (Role::WifiAp, 2.0),
                (Role::Container, 0.5),
            ],
            clients: &[
                (Role::Workstation, 10.0),
                (Role::VoipPhone, 4.0),
                (Role::Mobile, 4.0),
                (Role::Printer, 1.5),
                (Role::IotSensor, 1.0),
                (Role::Camera, 1.0),
            ],
        },
        Archetype::Metro => Profile {
            weight: 0.04,
            devices: (1500, 4000),
            subnets: (30, 80),
            dhcp_share: 0.8,
            server_share: 0.1,
            servers: &[
                (Role::Web, 2.0),
                (Role::Database, 2.0),
                (Role::Mail, 1.0),
                (Role::FileServer, 2.0),
                (Role::Jump, 1.0),
                (Role::Vpn, 1.0),
                (Role::WifiAp, 3.0),
                (Role::Container, 1.0),
            ],
            clients: &[
                (Role::Workstation, 10.0),
                (Role::VoipPhone, 5.0),
                (Role::Mobile, 7.0),
                (Role::Printer, 1.5),
                (Role::IotSensor, 2.0),
                (Role::Camera, 2.0),
            ],
        },
        Archetype::Industrial => Profile {
            weight: 0.06,
            devices: (60, 400),
            subnets: (3, 10),
            dhcp_share: 0.15,
            server_share: 0.55,
            servers: &[
                (Role::Plc, 10.0),
                (Role::Database, 1.0),
                (Role::Web, 1.0),
                (Role::Jump, 0.6),
                (Role::FileServer, 0.5),
            ],
            clients: &[
                (Role::Hmi, 3.0),
                (Role::Workstation, 2.0),
                (Role::IotSensor, 6.0),
                (Role::Camera, 1.0),
                (Role::Printer, 0.3),
            ],
        },
        Archetype::Hospital => Profile {
            weight: 0.05,
            devices: (150, 900),
            subnets: (6, 20),
            dhcp_share: 0.5,
            server_share: 0.1,
            servers: &[
                (Role::Database, 2.0),
                (Role::Web, 1.0),
                (Role::FileServer, 1.5),
                (Role::Mail, 0.6),
                (Role::Jump, 0.6),
                (Role::WifiAp, 1.5),
            ],
            clients: &[
                (Role::Medical, 8.0),
                (Role::Workstation, 5.0),
                (Role::VoipPhone, 3.0),
                (Role::Mobile, 3.0),
                (Role::IotSensor, 2.0),
                (Role::Printer, 1.0),
                (Role::Camera, 1.0),
            ],
        },
        Archetype::Cloud => Profile {
            weight: 0.07,
            devices: (100, 800),
            subnets: (4, 16),
            dhcp_share: 0.0,
            server_share: 0.9,
            servers: &[
                (Role::Container, 8.0),
                (Role::Web, 3.0),
                (Role::Database, 2.0),
                (Role::Vpn, 0.3),
                (Role::Jump, 0.3),
            ],
            clients: &[(Role::Workstation, 1.0), (Role::Mobile, 1.0)],
        },
    }
}

/// Minimalni pocet /24 podsiti pro `total` zarizeni: z celku (~110 na /24) i ze
/// statickych adres (horni odhad podilu statickych + 15 % rezerva, ~90 na /24,
/// staticky rozsah 2..=99 bez brany a DNS). Regrese: panika "kapacita podsiti"
/// v soak v2b (sit 808) u huste serverovych archetypu.
fn subnets_needed(total: usize, server_share: f64, dhcp_share: f64) -> u64 {
    let static_share = (server_share + (1.0 - server_share) * (1.0 - dhcp_share)).clamp(0.0, 1.0);
    let statics = (total as f64 * static_share * 1.15).ceil() as u64;
    (total as u64)
        .div_ceil(110)
        .max(statics.div_ceil(90))
        .max(1)
}

fn pick_weighted(rng: &mut Rng, table: &[(Role, f64)]) -> Role {
    let weights: Vec<f64> = table.iter().map(|(_, w)| *w).collect();
    table[rng.weighted(&weights)].0
}

impl NetworkModel {
    pub fn generate(run_seed: u64, id: u64) -> Self {
        Self::generate_with(run_seed, id, false)
    }

    /// `xxxl` = vynucená třída XXXL (krok 3): velká organizace s 8 000 až 10 000
    /// zařízeními a 150 až 240 podsítěmi (/24). Jinak stejné jako `generate`.
    pub fn generate_with(run_seed: u64, id: u64, xxxl: bool) -> Self {
        let seed = derive(run_seed, id);
        let mut rng = Rng::new(derive(seed, 0xA11CE));
        let weights: Vec<f64> = Archetype::ALL.iter().map(|a| profile(*a).weight).collect();
        let mut archetype = Archetype::ALL[rng.weighted(&weights)];
        if xxxl {
            archetype = if rng.chance(0.5) {
                Archetype::Metro
            } else {
                Archetype::Enterprise
            };
        }
        let prof = profile(archetype);
        let total = if xxxl {
            rng.range(8_000, 10_000) as usize
        } else {
            rng.range(prof.devices.0, prof.devices.1) as usize
        };
        // kapacita jedne /24: ~98 statickych (2..=99) + ~150 DHCP adres (100..=250).
        // Hustě serverové archetypy (Cloud, Datacenter, Industrial) mají skoro jen
        // statické adresy, proto se počet podsítí odvozuje i ze statických adres
        // (horní odhad podílu + 15 % rezerva, ~90 na /24), ne jen z celku / 110.
        let needed = subnets_needed(total, prof.server_share, prof.dhcp_share);
        let subnets = if xxxl {
            rng.range(150, 240).max(needed).min(240) as usize
        } else {
            rng.range(prof.subnets.0, prof.subnets.1)
                .max(needed)
                .min(200) as usize
        };
        let base_a = if rng.chance(0.5) { 192 } else { 10 };
        let base_b = if base_a == 192 {
            168
        } else {
            rng.range(0, 250) as u8
        };
        // XXXL: az 240 podsiti, aby se treti oktet nepretocil (base_c + index <= 255)
        let base_c = rng.range(0, if xxxl { 15 } else { 40 }) as u8;
        let prefixes: Vec<[u8; 3]> = (0..subnets)
            .map(|index| [base_a, base_b, base_c.wrapping_add(index as u8)])
            .collect();

        let mut devices: Vec<Device> = Vec::with_capacity(total + 2);
        let mut octets_used: Vec<Vec<bool>> = vec![vec![false; 256]; subnets];
        // "serverova zona": servery se shlukuji v prvnich podsitich, klienti jsou rozprostreni
        let server_zone = (subnets / 6).max(1);

        let mut add = |devices: &mut Vec<Device>,
                       rng: &mut Rng,
                       role: Role,
                       preferred_subnet: usize,
                       fixed_octet: Option<u8>,
                       dhcp: bool| {
            let (lo, hi) = if dhcp {
                (100u64, 250u64)
            } else {
                (2u64, 99u64)
            };
            let mut chosen: Option<(usize, u8)> = fixed_octet.map(|o| (preferred_subnet, o));
            if chosen.is_none() {
                'outer: for shift in 0..subnets {
                    let subnet = (preferred_subnet + shift) % subnets;
                    for _ in 0..24 {
                        let candidate = rng.range(lo, hi) as u8;
                        if !octets_used[subnet][candidate as usize] {
                            chosen = Some((subnet, candidate));
                            break 'outer;
                        }
                    }
                    if let Some(free) = (lo as usize..=hi as usize)
                        .find(|candidate| !octets_used[subnet][*candidate])
                    {
                        chosen = Some((subnet, free as u8));
                        break 'outer;
                    }
                }
            }
            // Pojistka: preferovany rozsah je vsude plny -> libovolna volna adresa
            // 2..=250 (zadna panika); kdyz neni ani ta, zarizeni se neprida.
            if chosen.is_none() {
                chosen = (0..subnets).find_map(|subnet| {
                    (2usize..=250)
                        .find(|candidate| !octets_used[subnet][*candidate])
                        .map(|free| (subnet, free as u8))
                });
            }
            let Some((subnet, octet)) = chosen else {
                return false;
            };
            octets_used[subnet][octet as usize] = true;
            let id = devices.len() as u32;
            let services = services_for(role, rng);
            let criticality = match role {
                Role::Gateway | Role::Dns | Role::Plc => 1.0,
                Role::Database
                | Role::FileServer
                | Role::Mail
                | Role::Web
                | Role::Medical
                | Role::Vpn => 0.85,
                Role::Jump | Role::Hmi | Role::Container => 0.7,
                _ => 0.3,
            };
            let rate = match role {
                r if r.is_server() => 0.0,
                Role::Hmi => rng.lognormal(140.0, 0.3),
                Role::Medical => rng.lognormal(40.0, 0.5),
                Role::VoipPhone => rng.lognormal(30.0, 0.4),
                Role::Mobile => rng.lognormal(12.0, 0.8),
                _ => rng.lognormal(18.0, 0.6),
            };
            devices.push(Device {
                id,
                mac: random_mac(rng),
                role,
                subnet,
                host_octet: octet,
                services,
                criticality,
                dhcp,
                rate,
                peers: Vec::new(),
                up: true,
            });
            true
        };

        add(&mut devices, &mut rng, Role::Gateway, 0, Some(1), false);
        add(&mut devices, &mut rng, Role::Dns, 0, Some(53), false);
        while devices.len() < total {
            let is_server = rng.chance(prof.server_share);
            let role = if is_server {
                pick_weighted(&mut rng, prof.servers)
            } else {
                pick_weighted(&mut rng, prof.clients)
            };
            let preferred = if role == Role::WifiAp {
                rng.range(0, subnets as u64 - 1) as usize
            } else if role == Role::Plc {
                // vyrobni podsite mimo serverovou zonu
                (server_zone + rng.range(0, subnets as u64 - 1) as usize) % subnets
            } else if role.is_server() {
                rng.range(0, server_zone as u64 - 1) as usize
            } else {
                rng.range(0, subnets as u64 - 1) as usize
            };
            let dhcp = (!role.is_server() && role != Role::Hmi && rng.chance(prof.dhcp_share))
                || role == Role::Mobile
                || (archetype == Archetype::Cloud && role == Role::Container);
            if !add(&mut devices, &mut rng, role, preferred, None, dhcp) {
                break; // vsechny podsite plne (nenastava pri spravnem `subnets_needed`)
            }
        }

        let server_ids: Vec<u32> = devices
            .iter()
            .filter(|d| d.role.is_server() && d.role != Role::Plc)
            .map(|d| d.id)
            .collect();
        let plc_ids: Vec<u32> = devices
            .iter()
            .filter(|d| d.role == Role::Plc)
            .map(|d| d.id)
            .collect();
        for index in 0..devices.len() {
            if devices[index].role.is_server() {
                continue;
            }
            if devices[index].role == Role::Hmi && !plc_ids.is_empty() {
                let count = rng.range(1, 4.min(plc_ids.len() as u64));
                let picks = rng.sample_distinct(plc_ids.len(), count as usize);
                devices[index].peers = picks.into_iter().map(|p| plc_ids[p]).collect();
                continue;
            }
            let count = rng.range(1, 3.min(server_ids.len() as u64));
            let picks = rng.sample_distinct(server_ids.len(), count as usize);
            devices[index].peers = picks.into_iter().map(|p| server_ids[p]).collect();
        }

        let externals: Vec<String> = (0..12)
            .map(|_| {
                format!(
                    "{}.{}.{}.{}",
                    *rng.pick(&[34u64, 52, 104, 142, 185, 203, 13]),
                    rng.range(1, 254),
                    rng.range(1, 254),
                    rng.range(1, 254)
                )
            })
            .collect();

        let mut model = Self {
            id,
            seed,
            archetype,
            prefixes,
            devices,
            gateway: 0,
            dns: 1,
            externals,
            tz_hours: rng.range(0, 23) as i64 - 12,
            ip_index: Default::default(),
            prefix_index: Default::default(),
        };
        model.rebuild_indexes();
        model
    }

    pub fn rebuild_indexes(&mut self) {
        self.prefix_index = self
            .prefixes
            .iter()
            .enumerate()
            .map(|(index, prefix)| (*prefix, index))
            .collect();
        self.ip_index = (0..self.devices.len() as u32)
            .map(|id| (self.ip_of(id), id))
            .collect();
    }

    /// Podsit (index) pro IP z modelu; `None` pro externi / neznamou adresu.
    pub fn subnet_of(&self, ip: &str) -> Option<usize> {
        let mut parts = ip.split('.');
        let prefix = [
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
        ];
        self.prefix_index.get(&prefix).copied()
    }

    /// Vzorkovani toku u velkych siti (NetFlow 1:N): velke site nikdy nedodavaji
    /// plny provoz; utoky se nevzorkuji (zkresleni je v reportu uvedeno).
    pub fn flow_sampling(&self) -> f64 {
        (300.0 / self.devices.len().max(1) as f64).clamp(0.08, 1.0)
    }

    pub fn size_class(&self) -> &'static str {
        size_class(self.devices.len())
    }

    /// Prida zarizeni, ktera jeste nejsou v siti (`up = false`); udalost Onboarding je
    /// pozdeji "zapne". Id jsou stabilni od zacatku, takze ground truth nemusi nic prepisovat.
    pub fn add_dormant(&mut self, rng: &mut Rng, count: usize) {
        let server_ids: Vec<u32> = self
            .devices
            .iter()
            .filter(|d| d.role.is_server() && d.role != Role::Plc)
            .map(|d| d.id)
            .collect();
        let mut used: Vec<std::collections::HashSet<u8>> =
            vec![Default::default(); self.prefixes.len()];
        for device in &self.devices {
            used[device.subnet].insert(device.host_octet);
        }
        for _ in 0..count {
            let role = *rng.pick(&[
                Role::Workstation,
                Role::Workstation,
                Role::Workstation,
                Role::Mobile,
                Role::Printer,
                Role::IotSensor,
                Role::Camera,
            ]);
            let mut placed = None;
            for _ in 0..40 {
                let subnet = rng.range(0, self.prefixes.len() as u64 - 1) as usize;
                let octet = rng.range(100, 250) as u8;
                if !used[subnet].contains(&octet) {
                    placed = Some((subnet, octet));
                    break;
                }
            }
            let Some((subnet, octet)) = placed else {
                continue;
            };
            used[subnet].insert(octet);
            let id = self.devices.len() as u32;
            let services = services_for(role, rng);
            let peers = if server_ids.is_empty() {
                Vec::new()
            } else {
                let n = rng.range(1, 2.min(server_ids.len() as u64)) as usize;
                rng.sample_distinct(server_ids.len(), n)
                    .into_iter()
                    .map(|p| server_ids[p])
                    .collect()
            };
            self.devices.push(Device {
                id,
                mac: random_mac(rng),
                role,
                subnet,
                host_octet: octet,
                services,
                criticality: 0.3,
                dhcp: true,
                rate: rng.lognormal(18.0, 0.6),
                peers,
                up: false,
            });
        }
        self.rebuild_indexes();
    }

    /// Patch: sluzby ztrati zname zranitelnosti a dostanou novejsi verzi.
    pub fn patch_device(&mut self, id: u32) -> bool {
        let mut changed = false;
        for service in &mut self.devices[id as usize].services {
            if !service.cves.is_empty() {
                service.cves.clear();
                service.version = "patched";
                changed = true;
            }
        }
        changed
    }

    pub fn ip_of(&self, device: u32) -> String {
        let d = &self.devices[device as usize];
        let p = self.prefixes[d.subnet];
        format!("{}.{}.{}.{}", p[0], p[1], p[2], d.host_octet)
    }

    pub fn scope(&self) -> Vec<IpNet> {
        self.prefixes
            .iter()
            .map(|p| {
                format!("{}.{}.{}.0/24", p[0], p[1], p[2])
                    .parse()
                    .expect("platny CIDR")
            })
            .collect()
    }

    pub fn device_by_ip(&self, ip: &str) -> Option<u32> {
        self.ip_index.get(ip).copied()
    }

    /// DHCP "renewal": cast dynamickych zarizeni dostane novou adresu (stejny MAC =
    /// stejne zarizeni - to je pravda identity, kterou engine musi dohledat).
    /// Mobilni zarizeni roamuji 4x casteji. Vzacne dve zarizeni prohodi adresy
    /// (NAT/swap). Vraci pocet zmen.
    pub fn churn(&mut self, rng: &mut Rng, change_share: f64, swap_probability: f64) -> usize {
        let dynamic: Vec<usize> = (0..self.devices.len())
            .filter(|i| self.devices[*i].dhcp)
            .collect();
        if dynamic.is_empty() {
            return 0;
        }
        let mut used: Vec<std::collections::HashSet<u8>> =
            vec![Default::default(); self.prefixes.len()];
        for device in &self.devices {
            used[device.subnet].insert(device.host_octet);
        }
        let mut changes = 0;
        for &index in &dynamic {
            let share = if self.devices[index].role == Role::Mobile {
                (change_share * 4.0).min(0.5)
            } else {
                change_share
            };
            if !rng.chance(share) {
                continue;
            }
            let subnet = self.devices[index].subnet;
            for _ in 0..20 {
                let candidate = rng.range(100, 250) as u8;
                if !used[subnet].contains(&candidate) {
                    used[subnet].remove(&self.devices[index].host_octet);
                    used[subnet].insert(candidate);
                    self.devices[index].host_octet = candidate;
                    changes += 1;
                    break;
                }
            }
        }
        if dynamic.len() >= 2 && rng.chance(swap_probability) {
            let a = dynamic[rng.range(0, dynamic.len() as u64 - 1) as usize];
            let b = dynamic[rng.range(0, dynamic.len() as u64 - 1) as usize];
            if a != b && self.devices[a].subnet == self.devices[b].subnet {
                let octet = self.devices[a].host_octet;
                self.devices[a].host_octet = self.devices[b].host_octet;
                self.devices[b].host_octet = octet;
                changes += 1;
            }
        }
        if changes > 0 {
            self.rebuild_indexes();
        }
        changes
    }

    /// Krok 5, porucha `dhcp_renumber`: 30 az 80 % dynamickych zarizeni podsite dostane
    /// novou adresu najednou (zmena rozsahu, obnova DHCP serveru) a vybrany server novou
    /// statickou adresu. MAC zustava. Vraci (pocet zmen, stara adresa serveru).
    pub fn renumber(
        &mut self,
        subnet: usize,
        server: Option<u32>,
        rng: &mut Rng,
    ) -> (usize, Option<String>) {
        if subnet >= self.prefixes.len() {
            return (0, None);
        }
        let mut used: std::collections::HashSet<u8> = self
            .devices
            .iter()
            .filter(|d| d.subnet == subnet)
            .map(|d| d.host_octet)
            .collect();
        let share = rng.range_f(0.3, 0.8);
        let mut changes = 0;
        for index in 0..self.devices.len() {
            if self.devices[index].subnet != subnet
                || !self.devices[index].dhcp
                || !rng.chance(share)
            {
                continue;
            }
            for _ in 0..20 {
                let candidate = rng.range(100, 250) as u8;
                if used.insert(candidate) {
                    used.remove(&self.devices[index].host_octet);
                    self.devices[index].host_octet = candidate;
                    changes += 1;
                    break;
                }
            }
        }
        let mut old = None;
        if let Some(server) = server.filter(|s| (*s as usize) < self.devices.len()) {
            let device = server as usize;
            let mut used: std::collections::HashSet<u8> = self
                .devices
                .iter()
                .filter(|d| d.subnet == self.devices[device].subnet)
                .map(|d| d.host_octet)
                .collect();
            for _ in 0..40 {
                let candidate = rng.range(2, 99) as u8;
                if used.insert(candidate) {
                    old = Some(self.ip_of(server));
                    self.devices[device].host_octet = candidate;
                    changes += 1;
                    break;
                }
            }
        }
        if changes > 0 {
            self.rebuild_indexes();
        }
        (changes, old)
    }

    /// Aktivni inventar (jako vystup nmapu): sluzby, produkty, verze. Vynecha zarizeni,
    /// ktera neběží (pad, odstaveni, jeste nenasazena); druhy vystup = jejich id.
    pub fn inventory(&self) -> (ParsedInventory, Vec<u32>) {
        // nmap vidi MAC jen na stejne L2 siti jako scanner; ve velkych sitich je
        // scanneru vic (kazda ~6. podsit), zbytek je dohledatelny jen pres IP.
        let scanned_l2 = 1 + self.prefixes.len() / 6;
        let mut ids = Vec::with_capacity(self.devices.len());
        let hosts = self
            .devices
            .iter()
            .filter(|d| d.up)
            .map(|d| {
                ids.push(d.id);
                ParsedHost {
                    ip: self.ip_of(d.id),
                    hostname: self.hostname_of(d),
                    mac: (d.subnet < scanned_l2).then(|| d.mac.clone()),
                    vendor: None,
                    services: d
                        .services
                        .iter()
                        .map(|s| ParsedService {
                            proto: s.proto.to_string(),
                            port: s.port,
                            port_state: "open".to_string(),
                            state_reason: Some("syn-ack".to_string()),
                            service_name: Some(s.name.to_string()),
                            product: Some(s.product.to_string()),
                            version: Some(s.version.to_string()),
                            extrainfo: None,
                            detection_source: "nmap".to_string(),
                            confidence: Confidence::High,
                            cpes: Vec::new(),
                        })
                        .collect(),
                }
            })
            .collect();
        (ParsedInventory { hosts }, ids)
    }

    /// Jmeno hostu, jak by ho videl sken (rDNS/DHCP): realisticky NEUPLNE. Servery a
    /// spravovane stanice maji vetsinou jedinecne jmeno, telefony casto genericke
    /// ("iPhone") nebo zadne, IoT jen cast. Deterministicke ze (seed site, id zarizeni).
    pub fn hostname_of(&self, device: &Device) -> Option<String> {
        let roll = crate::soak::rng::mix(self.seed ^ 0x4057_0000 ^ device.id as u64) % 100;
        let unique = || Some(format!("{}-{}", device.role.label(), device.id));
        match device.role {
            r if r.is_server() => (roll < 95).then(unique).flatten(),
            Role::Workstation => (roll < 90).then(unique).flatten(),
            Role::Mobile => match roll {
                0..=29 => unique(),
                30..=59 => Some(
                    if roll.is_multiple_of(2) {
                        "iPhone"
                    } else {
                        "android"
                    }
                    .to_string(),
                ),
                _ => None,
            },
            Role::VoipPhone => (roll < 60).then(unique).flatten(),
            _ => (roll < 50).then(unique).flatten(),
        }
    }

    /// CVE zaznamy pro sluzbu (to, co by do reportu doplnil intel provider).
    pub fn cve_records(svc: &Svc) -> Vec<CveRecord> {
        svc.cves
            .iter()
            .map(|(id, score, kev)| CveRecord {
                cve_id: id.to_string(),
                summary: Some(format!("Ilustrativni zranitelnost {id} ({})", svc.product)),
                cvss: Some(CvssRecord {
                    version: "3.1".to_string(),
                    base_score: *score,
                    severity: Some(
                        if *score >= 9.0 {
                            "CRITICAL"
                        } else if *score >= 7.0 {
                            "HIGH"
                        } else {
                            "MEDIUM"
                        }
                        .to_string(),
                    ),
                }),
                source: "soak-sim".to_string(),
                retrieved_at: chrono::DateTime::<chrono::Utc>::from_timestamp(1_767_000_000, 0)
                    .expect("cas"),
                references: Vec::new(),
                exploit_context: if *kev {
                    Some(ExploitContext {
                        epss: None,
                        cisa_kev: Some(KevRecord {
                            known_exploited: true,
                            vendor_project: None,
                            product: Some(svc.product.to_string()),
                            vulnerability_name: None,
                            short_description: None,
                            date_added: None,
                            due_date: None,
                            required_action: None,
                            known_ransomware_campaign_use: None,
                            source: "soak-sim".to_string(),
                        }),
                    })
                } else {
                    None
                },
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_and_id_give_identical_network_and_ids_differ() {
        let a = NetworkModel::generate(1, 5);
        let b = NetworkModel::generate(1, 5);
        assert_eq!(a.devices.len(), b.devices.len());
        for id in 0..a.devices.len() as u32 {
            assert_eq!(a.ip_of(id), b.ip_of(id));
            assert_eq!(a.devices[id as usize].mac, b.devices[id as usize].mac);
        }
        let other = NetworkModel::generate(1, 6);
        assert!(
            a.devices.len() != other.devices.len()
                || a.ip_of(2) != other.ip_of(2)
                || a.prefixes != other.prefixes
        );
    }

    #[test]
    fn ips_are_unique_within_a_network_across_many_networks() {
        for id in 0..300 {
            let net = NetworkModel::generate(99, id);
            let mut seen = std::collections::HashSet::new();
            for d in 0..net.devices.len() as u32 {
                assert!(seen.insert(net.ip_of(d)), "duplicitni IP v siti {id}");
            }
            assert_eq!(net.devices[0].role, Role::Gateway);
            assert!(
                net.devices
                    .iter()
                    .all(|d| d.role.is_server() || !d.peers.is_empty())
            );
        }
    }

    #[test]
    fn churn_keeps_ips_unique_and_macs_stable() {
        let mut net = NetworkModel::generate(7, 11);
        let macs: Vec<String> = net.devices.iter().map(|d| d.mac.clone()).collect();
        let mut rng = Rng::new(1);
        for _ in 0..50 {
            net.churn(&mut rng, 0.4, 0.3);
            let mut seen = std::collections::HashSet::new();
            for d in 0..net.devices.len() as u32 {
                assert!(seen.insert(net.ip_of(d)));
            }
        }
        for (device, mac) in net.devices.iter().zip(macs) {
            assert_eq!(device.mac, mac);
        }
    }

    #[test]
    fn scope_contains_every_device_and_inventory_matches_devices() {
        let net = NetworkModel::generate(3, 21);
        let scope = net.scope();
        for d in 0..net.devices.len() as u32 {
            let ip: std::net::IpAddr = net.ip_of(d).parse().unwrap();
            assert!(scope.iter().any(|n| n.contains(&ip)));
        }
        assert_eq!(net.inventory().0.hosts.len(), net.devices.len());
    }

    #[test]
    fn archetype_mix_covers_all_kinds_sizes_and_roles() {
        let mut kinds = std::collections::HashSet::new();
        let mut classes = std::collections::HashSet::new();
        let mut roles = std::collections::HashSet::new();
        let mut max_devices = 0;
        let mut max_subnets = 0;
        for id in 0..1200 {
            let net = NetworkModel::generate(5, id);
            kinds.insert(format!("{:?}", net.archetype));
            classes.insert(net.size_class());
            max_devices = max_devices.max(net.devices.len());
            max_subnets = max_subnets.max(net.prefixes.len());
            for d in &net.devices {
                roles.insert(d.role);
            }
        }
        assert_eq!(kinds.len(), Archetype::ALL.len());
        // XXXL vznika jen vynucenim (krok 3)
        assert_eq!(classes.len(), SIZE_CLASSES.len() - 1, "{classes:?}");
        let big = NetworkModel::generate_with(5, 1, true);
        assert_eq!(big.size_class(), "XXXL (>6000)");
        assert!(big.prefixes.len() >= 150, "{}", big.prefixes.len());
        let scope = big.scope();
        for d in (0..big.devices.len() as u32).step_by(97) {
            let ip: std::net::IpAddr = big.ip_of(d).parse().unwrap();
            assert!(scope.iter().any(|n| n.contains(&ip)));
        }
        let unique: std::collections::HashSet<_> = big.prefixes.iter().collect();
        assert_eq!(
            unique.len(),
            big.prefixes.len(),
            "podsite se nesmi opakovat"
        );
        assert_eq!(roles.len(), Role::ALL.len(), "{roles:?}");
        assert!(max_devices > 2500, "nejvetsi sit {max_devices}");
        assert!(max_subnets >= 30, "nejvic podsiti {max_subnets}");
    }

    /// Regrese soak v2b: sit 808 (seed 20261101) padala na "kapacita podsiti".
    #[test]
    fn dense_server_networks_never_run_out_of_static_addresses() {
        let net = NetworkModel::generate(20261101, 808);
        assert!(!net.devices.is_empty());
        for seed in [20261101u64, 20261102, 20261103, 20261104] {
            for id in 0..1500 {
                let net = NetworkModel::generate(seed, id);
                let prof = profile(net.archetype);
                assert!(
                    net.devices.len() as u64 >= prof.devices.0,
                    "sit {seed}/{id}: {} zarizeni",
                    net.devices.len()
                );
                let statics = net.devices.iter().filter(|d| !d.dhcp).count();
                assert!(statics <= net.prefixes.len() * 98, "sit {seed}/{id}");
            }
        }
    }

    #[test]
    fn subnets_needed_counts_static_addresses() {
        // Cloud-like: 800 zarizeni, 90 % serveru, zadne DHCP -> skoro vse staticke
        assert!(subnets_needed(800, 0.9, 0.0) >= 10);
        // Kancelar: 800 zarizeni, vetsina DHCP -> rozhoduje celkovy pocet
        assert_eq!(subnets_needed(800, 0.1, 0.8), 800u64.div_ceil(110));
        assert_eq!(subnets_needed(1, 0.0, 1.0), 1);
    }
}
