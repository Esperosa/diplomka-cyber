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
}

impl Role {
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
}

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

impl NetworkModel {
    pub fn generate(run_seed: u64, id: u64) -> Self {
        let seed = derive(run_seed, id);
        let mut rng = Rng::new(derive(seed, 0xA11CE));
        let archetype = match rng.weighted(&[0.35, 0.30, 0.15, 0.12, 0.08]) {
            0 => Archetype::Soho,
            1 => Archetype::Smb,
            2 => Archetype::Datacenter,
            3 => Archetype::IotHeavy,
            _ => Archetype::Campus,
        };
        let (device_range, subnet_range, dhcp_share) = match archetype {
            Archetype::Soho => ((5, 14), (1, 1), 0.8),
            Archetype::Smb => ((15, 55), (1, 2), 0.6),
            Archetype::Datacenter => ((30, 120), (2, 3), 0.0),
            Archetype::IotHeavy => ((20, 70), (1, 2), 0.7),
            Archetype::Campus => ((80, 220), (2, 4), 0.7),
        };
        let subnets = rng.range(subnet_range.0, subnet_range.1) as usize;
        let base_a = if rng.chance(0.5) { 192 } else { 10 };
        let base_b = if base_a == 192 {
            168
        } else {
            rng.range(0, 250) as u8
        };
        let base_c = rng.range(0, 200) as u8;
        let prefixes: Vec<[u8; 3]> = (0..subnets)
            .map(|index| [base_a, base_b, base_c.wrapping_add(index as u8)])
            .collect();

        let total = rng.range(device_range.0, device_range.1) as usize;
        let mut devices: Vec<Device> = Vec::with_capacity(total + 2);
        let mut octets_used: Vec<std::collections::HashSet<u8>> = vec![Default::default(); subnets];

        let mut add = |devices: &mut Vec<Device>,
                       rng: &mut Rng,
                       role: Role,
                       subnet: usize,
                       fixed_octet: Option<u8>,
                       dhcp: bool| {
            let octet = fixed_octet.unwrap_or_else(|| {
                loop {
                    let candidate = if dhcp {
                        rng.range(100, 250)
                    } else {
                        rng.range(2, 99)
                    } as u8;
                    if !octets_used[subnet].contains(&candidate) {
                        break candidate;
                    }
                }
            });
            octets_used[subnet].insert(octet);
            let id = devices.len() as u32;
            let services = services_for(role, rng);
            let criticality = match role {
                Role::Gateway | Role::Dns => 1.0,
                Role::Database | Role::FileServer | Role::Mail | Role::Web => 0.8,
                Role::Jump => 0.7,
                _ => 0.3,
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
                rate: if role.is_server() {
                    0.0
                } else {
                    rng.lognormal(18.0, 0.6)
                },
                peers: Vec::new(),
            });
        };

        add(&mut devices, &mut rng, Role::Gateway, 0, Some(1), false);
        add(&mut devices, &mut rng, Role::Dns, 0, Some(53), false);
        let server_share = match archetype {
            Archetype::Datacenter => 0.75,
            Archetype::Soho => 0.1,
            _ => 0.2,
        };
        while devices.len() < total {
            let subnet = rng.range(0, subnets as u64 - 1) as usize;
            let is_server = rng.chance(server_share);
            let role = if is_server {
                *rng.pick(&[
                    Role::Web,
                    Role::Web,
                    Role::Database,
                    Role::Mail,
                    Role::FileServer,
                    Role::Jump,
                ])
            } else {
                match archetype {
                    Archetype::IotHeavy => *rng.pick(&[
                        Role::IotSensor,
                        Role::IotSensor,
                        Role::Camera,
                        Role::Workstation,
                        Role::Printer,
                    ]),
                    Archetype::Soho => *rng.pick(&[
                        Role::Workstation,
                        Role::Workstation,
                        Role::Printer,
                        Role::IotSensor,
                        Role::Camera,
                    ]),
                    _ => *rng.pick(&[
                        Role::Workstation,
                        Role::Workstation,
                        Role::Workstation,
                        Role::Printer,
                        Role::IotSensor,
                        Role::Camera,
                    ]),
                }
            };
            let dhcp = !role.is_server() && rng.chance(dhcp_share);
            add(&mut devices, &mut rng, role, subnet, None, dhcp);
        }

        let server_ids: Vec<u32> = devices
            .iter()
            .filter(|d| d.role.is_server())
            .map(|d| d.id)
            .collect();
        for index in 0..devices.len() {
            if !devices[index].role.is_server() {
                let count = rng.range(1, 3.min(server_ids.len() as u64));
                let picks = rng.sample_distinct(server_ids.len(), count as usize);
                devices[index].peers = picks.into_iter().map(|p| server_ids[p]).collect();
            }
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

        Self {
            id,
            seed,
            archetype,
            prefixes,
            devices,
            gateway: 0,
            dns: 1,
            externals,
            tz_hours: rng.range(0, 23) as i64 - 12,
        }
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
        (0..self.devices.len() as u32).find(|id| self.ip_of(*id) == ip)
    }

    /// DHCP "renewal": cast dynamickych zarizeni dostane novou adresu (stejny MAC =
    /// stejne zarizeni - to je pravda identity, kterou engine musi dohledat).
    /// Vzacne dve zarizeni prohodi adresy (NAT/swap). Vraci pocet zmen.
    pub fn churn(&mut self, rng: &mut Rng, change_share: f64, swap_probability: f64) -> usize {
        let dynamic: Vec<usize> = (0..self.devices.len())
            .filter(|i| self.devices[*i].dhcp)
            .collect();
        if dynamic.is_empty() {
            return 0;
        }
        let mut changes = 0;
        for &index in &dynamic {
            if !rng.chance(change_share) {
                continue;
            }
            let subnet = self.devices[index].subnet;
            let used: std::collections::HashSet<u8> = self
                .devices
                .iter()
                .filter(|d| d.subnet == subnet)
                .map(|d| d.host_octet)
                .collect();
            for _ in 0..20 {
                let candidate = rng.range(100, 250) as u8;
                if !used.contains(&candidate) {
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
        changes
    }

    /// Aktivni inventar (jako vystup nmapu): sluzby, produkty, verze.
    pub fn inventory(&self) -> ParsedInventory {
        ParsedInventory {
            hosts: self
                .devices
                .iter()
                .map(|d| ParsedHost {
                    ip: self.ip_of(d.id),
                    hostname: Some(format!("{}-{}", d.role.label(), d.id)),
                    // nmap vidi MAC jen na stejne L2 siti jako scanner (podsit 0);
                    // zbytek je identifikovatelny jen pres IP (realisticke omezeni).
                    mac: (d.subnet == 0).then(|| d.mac.clone()),
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
                })
                .collect(),
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
        assert_eq!(net.inventory().hosts.len(), net.devices.len());
    }

    #[test]
    fn archetype_mix_covers_all_five_kinds() {
        let mut kinds = std::collections::HashSet::new();
        for id in 0..400 {
            kinds.insert(format!("{:?}", NetworkModel::generate(5, id).archetype));
        }
        assert_eq!(kinds.len(), 5);
    }
}
