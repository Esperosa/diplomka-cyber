//! Generator provozu: zakladni (denni/tydenni) zatizeni, utoky s ground truth,
//! benigni "lookalike" udalosti (zalohy, autorizovany scanner, flash crowd, ...) a
//! degradace telemetrie (ztrata, duplicity, posun hodin, vypadky sensoru).
//! Vystup jsou presne ty typy, ktere cte produkcni engine (`ConnectionObservation`
//! a Suricata eve.json radky), ne primo "nalezy".

use std::collections::BTreeSet;

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    nmap::{ParsedHost, ParsedInventory, ParsedService},
    passive::ConnectionObservation,
    soak::{
        netmodel::{Archetype, NetworkModel, Role},
        rng::{Rng, derive},
    },
};

pub const CYCLE_SECS: i64 = 1800;
/// 2026-01-05 00:00:00 UTC (pondeli) - zaklad virtualniho kalendare.
pub const EPOCH0: i64 = 1_767_571_200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Family {
    PortScanVertical,
    PortScanHorizontal,
    SshBrute,
    C2Beacon,
    Ddos,
    Exfil,
    Lateral,
    RogueDevice,
    Exploit,
    DnsTunnel,
    SlowScan,
    /// Hadani hesel z botnetu proti webu/VPN.
    CredentialStuffing,
    /// Interni hostitel sifruje sdilene disky pres SMB a vola domu.
    Ransomware,
    /// Dlouhodobe spojeni na mining pool (stratum).
    Cryptomining,
    /// Zamestnanec hromadi data z file serveru, pak je posila ven.
    InsiderHoarding,
    /// Webovy exploit (SQLi/RCE) proti vystavenemu serveru.
    WebExploit,
    /// Zapis na PLC (Modbus/S7) od nepovoleneho zdroje.
    IcsAttack,
    /// Kompromitovany distribuovany update: mnoho stanic volá na jednu cizi adresu.
    FleetBeacon,
    /// Vicefazova kampan (recon -> exploit -> pohyb -> exfiltrace) rozlozena na dny.
    ApChain,
}

impl Family {
    pub const ALL: [Family; 19] = [
        Family::PortScanVertical,
        Family::PortScanHorizontal,
        Family::SshBrute,
        Family::C2Beacon,
        Family::Ddos,
        Family::Exfil,
        Family::Lateral,
        Family::RogueDevice,
        Family::Exploit,
        Family::DnsTunnel,
        Family::SlowScan,
        Family::CredentialStuffing,
        Family::Ransomware,
        Family::Cryptomining,
        Family::InsiderHoarding,
        Family::WebExploit,
        Family::IcsAttack,
        Family::FleetBeacon,
        Family::ApChain,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Family::PortScanVertical => "port_scan_vertical",
            Family::PortScanHorizontal => "port_scan_horizontal",
            Family::SshBrute => "ssh_bruteforce",
            Family::C2Beacon => "c2_beacon",
            Family::Ddos => "ddos_volume",
            Family::Exfil => "exfiltration",
            Family::Lateral => "lateral_movement",
            Family::RogueDevice => "rogue_device",
            Family::Exploit => "exploit_attempt",
            Family::DnsTunnel => "dns_tunnel",
            Family::SlowScan => "slow_scan",
            Family::CredentialStuffing => "credential_stuffing",
            Family::Ransomware => "ransomware",
            Family::Cryptomining => "cryptomining",
            Family::InsiderHoarding => "insider_hoarding",
            Family::WebExploit => "web_exploit",
            Family::IcsAttack => "ics_attack",
            Family::FleetBeacon => "fleet_beacon",
            Family::ApChain => "apt_chain",
        }
    }

    /// Typy nalezu, ktere engine skutecne umi pro dany utok vyprodukovat; "typed"
    /// detekce = nalez jednoho z nich. (Ne vsechny rodiny maji specificky typ.)
    pub fn expected_types(self) -> &'static [&'static str] {
        match self {
            Family::PortScanVertical | Family::PortScanHorizontal | Family::SlowScan => &[
                "unexpected_traffic",
                "connection_timeout_burst",
                "external_flow_observed",
                "packet_rate_spike",
            ],
            Family::SshBrute => &[
                "connection_timeout_burst",
                "packet_rate_spike",
                "unexpected_traffic",
                "suricata_alert",
            ],
            Family::C2Beacon => &[
                "external_flow_observed",
                "unexpected_traffic",
                "unmapped_passive_event",
            ],
            Family::Ddos => &[
                "packet_rate_spike",
                "service_overload_risk",
                "connection_timeout_burst",
                "inductive_volume_anomaly",
            ],
            Family::Exfil => &[
                "external_flow_observed",
                "inductive_volume_anomaly",
                "unexpected_traffic",
                "packet_rate_spike",
            ],
            Family::Lateral => &[
                "unexpected_traffic",
                "multi_target_pattern",
                "connection_timeout_burst",
            ],
            Family::RogueDevice => &[
                "new_exposed_service",
                "unexpected_traffic",
                "unmapped_passive_event",
                "identification_gap",
            ],
            Family::Exploit => &[
                "suricata_alert",
                "high_risk_cve_exposure",
                "known_exploited_vulnerability",
                "probable_exploitation_interest",
            ],
            Family::DnsTunnel => &[
                "packet_rate_spike",
                "unexpected_traffic",
                "inductive_volume_anomaly",
            ],
            Family::CredentialStuffing => &[
                "connection_timeout_burst",
                "packet_rate_spike",
                "unexpected_traffic",
                "suricata_alert",
            ],
            Family::Ransomware => &[
                "multi_target_pattern",
                "unexpected_traffic",
                "inductive_volume_anomaly",
                "external_flow_observed",
            ],
            Family::Cryptomining => &[
                "external_flow_observed",
                "unexpected_traffic",
                "inductive_volume_anomaly",
            ],
            Family::InsiderHoarding => &[
                "inductive_volume_anomaly",
                "unexpected_traffic",
                "external_flow_observed",
            ],
            Family::WebExploit => &[
                "suricata_alert",
                "packet_rate_spike",
                "unexpected_traffic",
                "service_overload_risk",
            ],
            Family::IcsAttack => &["unexpected_traffic", "suricata_alert", "packet_rate_spike"],
            Family::FleetBeacon => &[
                "external_flow_observed",
                "unexpected_traffic",
                "multi_target_pattern",
            ],
            Family::ApChain => &[
                "unexpected_traffic",
                "multi_target_pattern",
                "suricata_alert",
                "external_flow_observed",
                "inductive_volume_anomaly",
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Lookalike {
    Backup,
    AuthorizedScanner,
    FlashCrowd,
    SoftwareUpdate,
    NtpFanout,
    // --- provozni udalosti a poruchy (nikdy nejsou utok) ---
    /// Server spadl/restartuje: klienti dostavaji timeouty.
    ServiceCrash,
    /// Vypadek linky/ISP: retry bourka na externi spojeni.
    RetryStorm,
    /// Nove legitimni zarizeni v siti.
    Onboarding,
    /// Zarizeni definitivne zmizi.
    Decommission,
    /// Patchovaci okno: davkove restarty a velke stahovani.
    PatchWindow,
    /// Mesicni/tydenni davka mezi databazi a file serverem.
    BatchJob,
    /// Sber dohnal zpozdena data (stare casy, davka).
    CollectorReplay,
    /// Senzor/sber nefunguje po nekolik cyklu.
    SensorCrash,
    /// Poskozene logy: useknute/binarni radky a neuplne zaznamy.
    LogCorruption,
}

impl Lookalike {
    /// Udalosti bez klicovych IP: nalezy v jejich okne se pripisuji jim.
    pub fn window_scoped(self) -> bool {
        matches!(
            self,
            Lookalike::CollectorReplay | Lookalike::SensorCrash | Lookalike::LogCorruption
        )
    }

    pub fn is_ops(self) -> bool {
        !matches!(
            self,
            Lookalike::Backup
                | Lookalike::AuthorizedScanner
                | Lookalike::FlashCrowd
                | Lookalike::SoftwareUpdate
                | Lookalike::NtpFanout
        )
    }

    pub fn label(self) -> &'static str {
        match self {
            Lookalike::Backup => "backup_burst",
            Lookalike::AuthorizedScanner => "authorized_scanner",
            Lookalike::FlashCrowd => "flash_crowd",
            Lookalike::SoftwareUpdate => "software_update",
            Lookalike::NtpFanout => "ntp_fanout",
            Lookalike::ServiceCrash => "service_crash",
            Lookalike::RetryStorm => "retry_storm",
            Lookalike::Onboarding => "device_onboarding",
            Lookalike::Decommission => "device_decommission",
            Lookalike::PatchWindow => "patch_window",
            Lookalike::BatchJob => "batch_job",
            Lookalike::CollectorReplay => "collector_replay",
            Lookalike::SensorCrash => "sensor_crash",
            Lookalike::LogCorruption => "log_corruption",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Attack(Family),
    Benign(Lookalike),
}

#[derive(Debug, Clone)]
pub struct Truth {
    pub id: u32,
    pub kind: Kind,
    pub start_cycle: u32,
    pub end_cycle: u32,
    /// 0.15 (nenapadny) .. 1.0 (hlucny).
    pub intensity: f64,
    pub attacker_device: Option<u32>,
    pub attacker_external: Option<String>,
    pub victim_devices: Vec<u32>,
    /// Cil mimo sit (C2/exfil).
    pub target_external: Option<String>,
    pub ids_visible: bool,
    // --- behem emise ---
    pub touched_ips: BTreeSet<String>,
    pub flows_emitted: u64,
    pub flows_blocked: u64,
    pub first_emit_cycle: Option<u32>,
    pub blocked_at_cycle: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Telemetry {
    pub drop_p: f64,
    pub dup_p: f64,
    pub skew_s: i64,
    pub outage_p: f64,
    pub ids_coverage: f64,
    /// Podsite, ktere senzor nevidi (jen velke segmentovane site): tok je neviditelny,
    /// pokud jsou VSECHNY jeho vnitrni konce ve slepych podsitich.
    pub blind_subnets: Vec<bool>,
}

/// Co je v danem okamziku zablokovano (kernel simulator nebo "nic").
pub trait BlockOracle {
    fn is_blocked(&self, ip: &str, at: DateTime<Utc>) -> bool;
}

pub struct NoBlocks;
impl BlockOracle for NoBlocks {
    fn is_blocked(&self, _: &str, _: DateTime<Utc>) -> bool {
        false
    }
}

#[derive(Default)]
pub struct CycleOutput {
    pub observations: Vec<ConnectionObservation>,
    pub alerts: Vec<String>,
    pub inventory: Option<ParsedInventory>,
    pub benign_flows: u64,
    pub benign_flows_blocked: u64,
    pub outage: bool,
    /// Senzor/sber v tomto cyklu nefunguje (udalost SensorCrash).
    pub sensor_down: bool,
    /// Id zarizeni, ktera jsou v `inventory` (v tomto poradi).
    pub inventory_devices: Vec<u32>,
}

pub fn ts(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(secs, 0).single().expect("platny cas")
}

fn local_hour(abs: i64, tz: i64) -> i64 {
    (((abs + tz * 3600) % 86400) + 86400) % 86400 / 3600
}

fn weekday(abs: i64, tz: i64) -> i64 {
    // 0 = pondeli (EPOCH0 je pondeli)
    ((((abs + tz * 3600 - EPOCH0) / 86400) % 7) + 7) % 7
}

/// Denni/tydenni profil zatizeni: kancelar (pracovni doba), servery/IoT plocha.
pub fn diurnal(role: Role, archetype: Archetype, abs: i64, tz: i64) -> f64 {
    let flat = matches!(
        archetype,
        Archetype::Datacenter | Archetype::Industrial | Archetype::Cloud
    ) || matches!(
        role,
        Role::IotSensor
            | Role::Camera
            | Role::Printer
            | Role::Plc
            | Role::Hmi
            | Role::WifiAp
            | Role::Container
    );
    if flat {
        return 0.8;
    }
    let hour = local_hour(abs, tz);
    let day = (abs + tz * 3600 - EPOCH0).div_euclid(86400);
    // sviatky: ~3 % dni se chova jako vikend (stejne pro vsechny site = kalendar)
    let holiday = crate::soak::rng::mix(day as u64 ^ 0xCA1E_DA2) % 33 == 0;
    let weekend = weekday(abs, tz) >= 5 || holiday;
    let mut base: f64 = match hour {
        8..=17 => 1.0,
        6..=7 | 18..=21 => 0.35,
        _ => 0.06,
    };
    if archetype == Archetype::Hospital || role == Role::Medical {
        base = base.max(0.55);
    }
    if weekend {
        if archetype == Archetype::Hospital || role == Role::Medical {
            base * 0.7
        } else {
            base * 0.15
        }
    } else {
        base
    }
}

fn public_ip(rng: &mut Rng) -> String {
    format!(
        "{}.{}.{}.{}",
        rng.pick(&[45u64, 61, 77, 91, 103, 154, 178, 193, 198]),
        rng.range(1, 254),
        rng.range(1, 254),
        rng.range(1, 254)
    )
}

#[allow(clippy::too_many_arguments)]
fn obs(
    at: i64,
    src: &str,
    sport: u16,
    dst: &str,
    proto: &str,
    dport: u16,
    dur: f64,
    ob: u64,
    rb: u64,
    state: &str,
) -> ConnectionObservation {
    let op = ob / 900 + 1;
    let rp = if rb == 0 { 0 } else { rb / 900 + 1 };
    ConnectionObservation {
        timestamp: ts(at),
        src_ip: Some(src.to_string()),
        src_port: Some(sport),
        dst_ip: dst.to_string(),
        proto: proto.to_string(),
        dst_port: Some(dport),
        duration_s: Some(dur),
        orig_bytes: Some(ob),
        resp_bytes: Some(rb),
        total_bytes: Some(ob + rb),
        orig_pkts: Some(op),
        resp_pkts: Some(rp),
        total_pkts: Some(op + rp),
        conn_state: Some(state.to_string()),
        history: None,
        missed_bytes: Some(0),
    }
}

fn eve_line(
    at: i64,
    flow: u64,
    src: &str,
    sport: u16,
    dst: &str,
    dport: u16,
    sig_id: u32,
    sig: &str,
    severity: u8,
) -> String {
    format!(
        "{{\"timestamp\":\"{}\",\"flow_id\":{flow},\"event_type\":\"alert\",\"src_ip\":\"{src}\",\"src_port\":{sport},\"dest_ip\":\"{dst}\",\"dest_port\":{dport},\"proto\":\"TCP\",\"alert\":{{\"signature_id\":{sig_id},\"signature\":\"{sig}\",\"severity\":{severity}}}}}",
        ts(at).to_rfc3339_opts(chrono::SecondsFormat::Micros, false)
    )
}

pub fn random_telemetry(rng: &mut Rng, subnets: usize) -> Telemetry {
    // velke segmentovane site maji cast podsiti mimo dosah senzoru
    let blind_subnets = if subnets >= 6 && rng.chance(0.5) {
        let share = rng.range_f(0.1, 0.45);
        (0..subnets).map(|_| rng.chance(share)).collect()
    } else {
        Vec::new()
    };
    Telemetry {
        blind_subnets,
        drop_p: if rng.chance(0.3) {
            rng.range_f(0.01, 0.15)
        } else {
            0.0
        },
        dup_p: if rng.chance(0.2) {
            rng.range_f(0.01, 0.1)
        } else {
            0.0
        },
        skew_s: if rng.chance(0.4) {
            rng.range(0, 240) as i64 - 120
        } else {
            0
        },
        outage_p: if rng.chance(0.25) { 0.02 } else { 0.0 },
        ids_coverage: if rng.chance(0.25) {
            0.0
        } else {
            rng.range_f(0.5, 1.0)
        },
    }
}

/// Naplanuje utoky, benigni udalosti a provozni poruchy na cely epizod.
pub fn plan_episode(
    model: &NetworkModel,
    rng: &mut Rng,
    hours: u32,
    telemetry: &Telemetry,
) -> Vec<Truth> {
    let cycles = hours * 2;
    let size_scale = (model.devices.len() as f64 / 60.0)
        .max(1.0)
        .powf(0.45)
        .min(4.0);
    let attack_rate_per_day = size_scale
        * match model.archetype {
            Archetype::Soho => 0.8,
            Archetype::Smb => 1.2,
            Archetype::Datacenter => 2.0,
            Archetype::IotHeavy => 1.5,
            Archetype::Campus => 2.5,
            Archetype::Enterprise => 2.2,
            Archetype::Metro => 2.6,
            Archetype::Industrial => 1.5,
            Archetype::Hospital => 2.2,
            Archetype::Cloud => 2.6,
        };
    let days = hours as f64 / 24.0;
    let attacks = rng.poisson(attack_rate_per_day * days);
    let lookalikes = rng.poisson(1.6 * days * size_scale.sqrt());
    let ops_events = rng.poisson(1.1 * days * size_scale.sqrt());
    let mut truths: Vec<Truth> = Vec::new();
    let devices = model.devices.len();
    let live = |d: &&crate::soak::netmodel::Device| d.up;
    let internal: Vec<u32> = model
        .devices
        .iter()
        .filter(live)
        .filter(|d| !matches!(d.role, Role::Gateway | Role::Dns))
        .map(|d| d.id)
        .collect();
    let servers: Vec<u32> = model
        .devices
        .iter()
        .filter(live)
        .filter(|d| d.role.is_server())
        .map(|d| d.id)
        .collect();
    let clients: Vec<u32> = model
        .devices
        .iter()
        .filter(live)
        .filter(|d| !d.role.is_server())
        .map(|d| d.id)
        .collect();
    let by_role = |roles: &[Role]| -> Vec<u32> {
        model
            .devices
            .iter()
            .filter(live)
            .filter(|d| roles.contains(&d.role))
            .map(|d| d.id)
            .collect()
    };
    let webs = by_role(&[Role::Web, Role::Vpn, Role::Container]);
    let files = by_role(&[Role::FileServer, Role::Database]);
    let plcs = by_role(&[Role::Plc]);
    let dormant: Vec<u32> = model
        .devices
        .iter()
        .filter(|d| !d.up)
        .map(|d| d.id)
        .collect();
    let mut dormant_cursor = 0usize;

    let mut weights = [
        12.0, 8.0, 14.0, 8.0, 4.0, 5.0, 7.0, 3.0, 10.0, 4.0, 6.0, 8.0, 3.0, 4.0, 3.0, 7.0, 3.0,
        2.0, 3.0,
    ];
    if !plcs.is_empty() && model.archetype == Archetype::Industrial {
        weights[Family::IcsAttack as usize] *= 5.0;
    }
    let eligible = |family: Family| -> bool {
        match family {
            Family::IcsAttack => !plcs.is_empty(),
            Family::CredentialStuffing | Family::WebExploit => !webs.is_empty(),
            Family::Ransomware => !clients.is_empty() && !files.is_empty(),
            Family::InsiderHoarding => !clients.is_empty() && !files.is_empty(),
            Family::FleetBeacon => clients.len() >= 5,
            Family::ApChain => !servers.is_empty() && internal.len() >= 4,
            Family::Cryptomining | Family::C2Beacon | Family::Lateral | Family::DnsTunnel => {
                !clients.is_empty()
            }
            Family::Exfil => !servers.is_empty() || !internal.is_empty(),
            _ => true,
        }
    };

    for _ in 0..attacks {
        let mut family = Family::ALL[rng.weighted(&weights)];
        for _ in 0..8 {
            if eligible(family) {
                break;
            }
            family = Family::ALL[rng.weighted(&weights)];
        }
        if !eligible(family) {
            family = Family::PortScanVertical;
        }
        let intensity = match rng.weighted(&[0.4, 0.4, 0.2]) {
            0 => rng.range_f(0.8, 1.0),
            1 => rng.range_f(0.4, 0.7),
            _ => rng.range_f(0.15, 0.35),
        };
        let (min_len, max_len) = match family {
            Family::PortScanVertical | Family::PortScanHorizontal => (1, 3),
            Family::SshBrute => (2, 12),
            Family::C2Beacon => (6, 40),
            Family::Ddos => (1, 4),
            Family::Exfil => (1, 2),
            Family::Lateral => (2, 8),
            Family::RogueDevice => (6, 48),
            Family::Exploit => (1, 2),
            Family::DnsTunnel => (4, 20),
            Family::SlowScan => (8, 40),
            Family::CredentialStuffing => (2, 24),
            Family::Ransomware => (2, 6),
            Family::Cryptomining => (12, 200),
            Family::InsiderHoarding => (2, 10),
            Family::WebExploit => (1, 6),
            Family::IcsAttack => (1, 6),
            Family::FleetBeacon => (24, 400),
            Family::ApChain => (96, 720),
        };
        let mut len = rng.range(min_len, max_len) as u32;
        // dlouhodobe kampane: 1 z 4 pomalych utoku trva ~6x delsi (dny az tydny)
        if matches!(
            family,
            Family::C2Beacon | Family::SlowScan | Family::RogueDevice | Family::DnsTunnel
        ) && rng.chance(0.25)
        {
            len = len.saturating_mul(6);
        }
        let len = len.min(cycles.max(1));
        let start = rng.range(0, cycles.saturating_sub(1) as u64) as u32;
        let end = (start + len - 1).min(cycles - 1);
        let internal_attacker = matches!(
            family,
            Family::C2Beacon
                | Family::Exfil
                | Family::Lateral
                | Family::DnsTunnel
                | Family::Ransomware
                | Family::Cryptomining
                | Family::InsiderHoarding
        ) || (family == Family::IcsAttack && rng.chance(0.7));
        let attacker_device = if internal_attacker && !internal.is_empty() {
            Some(match family {
                Family::Exfil => *rng.pick(if servers.is_empty() {
                    &internal
                } else {
                    &servers
                }),
                _ => *rng.pick(if clients.is_empty() {
                    &internal
                } else {
                    &clients
                }),
            })
        } else {
            None
        };
        let attacker_external = if attacker_device.is_none()
            && !matches!(family, Family::RogueDevice | Family::FleetBeacon)
        {
            Some(public_ip(rng))
        } else {
            None
        };
        let victim_devices: Vec<u32> = match family {
            Family::PortScanVertical | Family::SshBrute | Family::Ddos | Family::Exploit => {
                let pool = if servers.is_empty() {
                    &internal
                } else {
                    &servers
                };
                vec![*rng.pick(pool)]
            }
            Family::PortScanHorizontal | Family::SlowScan | Family::Lateral => {
                let n = ((devices as f64 * intensity * 0.5).ceil() as usize)
                    .clamp(2, devices.clamp(2, 1500));
                rng.sample_distinct(devices, n)
                    .into_iter()
                    .map(|d| d as u32)
                    .filter(|d| model.devices[*d as usize].up)
                    .collect::<Vec<u32>>()
            }
            Family::DnsTunnel => vec![model.dns],
            Family::CredentialStuffing | Family::WebExploit => vec![*rng.pick(&webs)],
            Family::Ransomware => {
                let mut v = vec![*rng.pick(&files)];
                let extra = ((internal.len() as f64 * intensity * 0.15) as usize).clamp(5, 60);
                for pick in rng.sample_distinct(internal.len(), extra.min(internal.len())) {
                    v.push(internal[pick]);
                }
                v.sort_unstable();
                v.dedup();
                v
            }
            Family::InsiderHoarding => vec![*rng.pick(&files)],
            Family::IcsAttack => {
                let n = rng.range(1, 3.min(plcs.len() as u64)) as usize;
                rng.sample_distinct(plcs.len(), n)
                    .into_iter()
                    .map(|p| plcs[p])
                    .collect()
            }
            Family::FleetBeacon => {
                let n = ((clients.len() as f64 * (0.05 + 0.25 * intensity)) as usize)
                    .clamp(3, 400)
                    .min(clients.len());
                rng.sample_distinct(clients.len(), n)
                    .into_iter()
                    .map(|p| clients[p])
                    .collect()
            }
            Family::ApChain => {
                let entry = if webs.is_empty() {
                    *rng.pick(&servers)
                } else {
                    *rng.pick(&webs)
                };
                let mut v = vec![entry];
                let extra = (rng.range(2, 6) as usize).min(internal.len());
                for pick in rng.sample_distinct(internal.len(), extra) {
                    if internal[pick] != entry {
                        v.push(internal[pick]);
                    }
                }
                v
            }
            _ => Vec::new(),
        };
        // vsechny vybrane cile mohly byt vypnute: radsi jeden bezici nez prazdny seznam
        let victim_devices = if victim_devices.is_empty()
            && matches!(
                family,
                Family::PortScanHorizontal | Family::SlowScan | Family::Lateral
            )
            && !internal.is_empty()
        {
            vec![*rng.pick(&internal)]
        } else {
            victim_devices
        };
        let target_external = matches!(
            family,
            Family::C2Beacon
                | Family::Exfil
                | Family::DnsTunnel
                | Family::Cryptomining
                | Family::InsiderHoarding
                | Family::FleetBeacon
                | Family::ApChain
                | Family::Ransomware
        )
        .then(|| public_ip(rng));
        let ids_visible = rng.chance(telemetry.ids_coverage)
            && rng.chance(match family {
                Family::SshBrute | Family::Exploit => 0.8,
                Family::PortScanVertical | Family::PortScanHorizontal => 0.5,
                Family::C2Beacon | Family::Lateral => 0.3,
                Family::Ddos
                | Family::Exfil
                | Family::DnsTunnel
                | Family::SlowScan
                | Family::RogueDevice => 0.2,
                Family::CredentialStuffing => 0.7,
                Family::Ransomware | Family::Cryptomining => 0.5,
                Family::InsiderHoarding => 0.1,
                Family::WebExploit => 0.8,
                Family::IcsAttack | Family::ApChain => 0.4,
                Family::FleetBeacon => 0.15,
            });
        truths.push(Truth {
            id: truths.len() as u32,
            kind: Kind::Attack(family),
            start_cycle: start,
            end_cycle: end,
            intensity,
            attacker_device,
            attacker_external,
            victim_devices,
            target_external,
            ids_visible,
            touched_ips: BTreeSet::new(),
            flows_emitted: 0,
            flows_blocked: 0,
            first_emit_cycle: None,
            blocked_at_cycle: None,
        });
    }

    // --- benigni lookalike a provozni udalosti ---
    let build_benign = |truths: &mut Vec<Truth>,
                        rng: &mut Rng,
                        which: Lookalike,
                        forced_start: Option<u32>,
                        dormant_cursor: &mut usize| {
        let night_cycle = |rng: &mut Rng| -> u32 {
            let day = rng.range(0, (hours as u64 / 24).max(1) - 1) as u32;
            let target_local_hour = match which {
                Lookalike::Backup => 2,
                Lookalike::AuthorizedScanner => 3,
                _ => 4,
            };
            let local_midnight_utc = -(model.tz_hours * 3600);
            let secs = local_midnight_utc + day as i64 * 86400 + target_local_hour * 3600;
            let base_secs = secs.rem_euclid(86400 * (hours as i64 / 24).max(1));
            ((base_secs / CYCLE_SECS) as u32).min(cycles - 1)
        };
        let start = forced_start.unwrap_or_else(|| match which {
            Lookalike::Backup
            | Lookalike::AuthorizedScanner
            | Lookalike::SoftwareUpdate
            | Lookalike::PatchWindow
            | Lookalike::BatchJob => night_cycle(rng),
            _ => rng.range(0, cycles.saturating_sub(1) as u64) as u32,
        });
        let len = match which {
            Lookalike::Backup => rng.range(1, 3),
            Lookalike::AuthorizedScanner => rng.range(1, 2),
            Lookalike::FlashCrowd => rng.range(1, 3),
            Lookalike::SoftwareUpdate => rng.range(1, 2),
            Lookalike::NtpFanout => 1,
            Lookalike::ServiceCrash => rng.range(1, 8),
            Lookalike::RetryStorm => rng.range(1, 4),
            Lookalike::Onboarding | Lookalike::Decommission => 1,
            Lookalike::PatchWindow => rng.range(2, 5),
            Lookalike::BatchJob => rng.range(1, 6),
            Lookalike::CollectorReplay => rng.range(1, 3),
            Lookalike::SensorCrash => rng.range(1, 12),
            Lookalike::LogCorruption => rng.range(1, 4),
        } as u32;
        let attacker_device = match which {
            Lookalike::AuthorizedScanner | Lookalike::NtpFanout | Lookalike::Backup
                if !internal.is_empty() =>
            {
                Some(*rng.pick(&internal))
            }
            _ => None,
        };
        let victim_devices: Vec<u32> = match which {
            Lookalike::Backup => servers
                .iter()
                .copied()
                .filter(|s| matches!(model.devices[*s as usize].role, Role::FileServer))
                .take(1)
                .collect(),
            Lookalike::FlashCrowd => servers
                .iter()
                .copied()
                .filter(|s| matches!(model.devices[*s as usize].role, Role::Web))
                .take(1)
                .collect(),
            Lookalike::ServiceCrash => {
                let pool: Vec<u32> = servers
                    .iter()
                    .copied()
                    .filter(|s| *s != model.gateway)
                    .collect();
                if pool.is_empty() {
                    Vec::new()
                } else {
                    vec![*rng.pick(&pool)]
                }
            }
            Lookalike::Onboarding => {
                if *dormant_cursor < dormant.len() {
                    let id = dormant[*dormant_cursor];
                    *dormant_cursor += 1;
                    vec![id]
                } else {
                    return;
                }
            }
            Lookalike::Decommission => {
                if internal.is_empty() {
                    return;
                }
                vec![*rng.pick(&internal)]
            }
            Lookalike::PatchWindow => {
                if servers.len() < 2 {
                    return;
                }
                let n = ((servers.len() as f64 / 3.0).ceil() as usize).clamp(2, 40);
                rng.sample_distinct(servers.len(), n.min(servers.len()))
                    .into_iter()
                    .map(|p| servers[p])
                    .filter(|d| *d != model.gateway)
                    .collect()
            }
            Lookalike::BatchJob => files.iter().copied().take(2).collect(),
            _ => Vec::new(),
        };
        let end = (start + len - 1).min(cycles - 1);
        truths.push(Truth {
            id: truths.len() as u32,
            kind: Kind::Benign(which),
            start_cycle: start,
            end_cycle: end,
            intensity: rng.range_f(0.4, 1.0),
            attacker_device,
            attacker_external: None,
            victim_devices,
            target_external: Some(public_ip(rng)),
            ids_visible: false,
            touched_ips: BTreeSet::new(),
            flows_emitted: 0,
            flows_blocked: 0,
            first_emit_cycle: None,
            blocked_at_cycle: None,
        });
    };

    for _ in 0..lookalikes {
        let which = *rng.pick(&[
            Lookalike::Backup,
            Lookalike::AuthorizedScanner,
            Lookalike::FlashCrowd,
            Lookalike::SoftwareUpdate,
            Lookalike::NtpFanout,
        ]);
        build_benign(&mut truths, rng, which, None, &mut dormant_cursor);
    }
    let ops_weights = [6.0, 3.0, 3.0, 2.0, 3.0, 3.0, 3.0, 3.0, 2.0];
    let ops_kinds = [
        Lookalike::ServiceCrash,
        Lookalike::RetryStorm,
        Lookalike::Onboarding,
        Lookalike::Decommission,
        Lookalike::PatchWindow,
        Lookalike::BatchJob,
        Lookalike::CollectorReplay,
        Lookalike::SensorCrash,
        Lookalike::LogCorruption,
    ];
    for _ in 0..ops_events {
        let which = ops_kinds[rng.weighted(&ops_weights)];
        build_benign(&mut truths, rng, which, None, &mut dormant_cursor);
    }
    // slozene scenare: cast utoku se potka s benigni udalosti ve stejnem okne (sum + utok)
    let attack_starts: Vec<u32> = truths
        .iter()
        .filter(|t| matches!(t.kind, Kind::Attack(_)))
        .map(|t| t.start_cycle)
        .collect();
    for start in attack_starts {
        if rng.chance(0.12) {
            let which = *rng.pick(&[
                Lookalike::Backup,
                Lookalike::FlashCrowd,
                Lookalike::SoftwareUpdate,
                Lookalike::BatchJob,
                Lookalike::ServiceCrash,
                Lookalike::RetryStorm,
            ]);
            build_benign(&mut truths, rng, which, Some(start), &mut dormant_cursor);
        }
    }
    truths
}

pub struct CycleContext<'a> {
    pub model: &'a NetworkModel,
    pub ips: &'a [String],
    pub cycle: u32,
    pub start_offset_s: i64,
    pub telemetry: &'a Telemetry,
    pub oracle: &'a dyn BlockOracle,
    /// Neprirazene (rogue) zarizeni: ip, mac.
    pub rogue: Option<(String, String)>,
}

pub fn cycle_start_abs(start_offset_s: i64, cycle: u32) -> i64 {
    EPOCH0 + start_offset_s + cycle as i64 * CYCLE_SECS
}

/// Vygeneruje telemetrii jednoho cyklu (zakladni provoz + aktivni utoky/lookalikes).
pub fn generate_cycle(ctx: &CycleContext<'_>, truths: &mut [Truth], rng: &mut Rng) -> CycleOutput {
    let model = ctx.model;
    let t0 = cycle_start_abs(ctx.start_offset_s, ctx.cycle);
    let mut out = CycleOutput::default();
    let mut flow_id: u64 = (ctx.cycle as u64) << 32;
    let cycle_h = CYCLE_SECS as f64 / 3600.0;

    // --- zakladni provoz ---
    let sampling = model.flow_sampling();
    for device in &model.devices {
        if device.role.is_server() || !device.up {
            continue;
        }
        let factor = diurnal(device.role, model.archetype, t0, model.tz_hours);
        let n = rng.poisson(device.rate * cycle_h * factor * sampling);
        let src = &ctx.ips[device.id as usize];
        for _ in 0..n {
            let at = t0 + rng.range(0, CYCLE_SECS as u64 - 1) as i64;
            let mut peer_down = false;
            let (dst, proto, port) = if rng.chance(0.18) {
                (
                    model.externals[rng.range(0, model.externals.len() as u64 - 1) as usize]
                        .clone(),
                    "tcp",
                    443,
                )
            } else if let Some(peer) = device
                .peers
                .first()
                .and_then(|_| Some(*rng.pick(&device.peers)))
            {
                let server = &model.devices[peer as usize];
                if server.services.is_empty() {
                    continue;
                }
                peer_down = !server.up;
                let s = rng.pick(&server.services);
                (ctx.ips[peer as usize].clone(), s.proto, s.port)
            } else {
                continue;
            };
            let state = if peer_down {
                "S0" // server nebezi: klient jen opakuje SYN do prazdna
            } else {
                match rng.weighted(&[0.965, 0.02, 0.015]) {
                    0 => "SF",
                    1 => "RSTO",
                    _ => "S0",
                }
            };
            let (ob, rb) = if state == "S0" {
                (0, 0)
            } else {
                (
                    rng.lognormal(700.0, 1.0) as u64,
                    rng.lognormal(9000.0, 1.4) as u64,
                )
            };
            push(
                &mut out,
                ctx,
                obs(
                    at,
                    src,
                    rng.range(32768, 60999) as u16,
                    &dst,
                    proto,
                    port,
                    rng.lognormal(0.5, 1.2),
                    ob,
                    rb,
                    state,
                ),
                None,
                truths,
            );
        }
        // DNS
        let dns_n = rng.poisson(device.rate * cycle_h * factor * 1.2 * sampling);
        let dns_ip = &ctx.ips[model.dns as usize];
        let dns_state = if model.devices[model.dns as usize].up {
            "SF"
        } else {
            "S0"
        };
        for _ in 0..dns_n {
            let at = t0 + rng.range(0, CYCLE_SECS as u64 - 1) as i64;
            push(
                &mut out,
                ctx,
                obs(
                    at,
                    src,
                    rng.range(32768, 60999) as u16,
                    dns_ip,
                    "udp",
                    53,
                    0.05,
                    rng.range(40, 90),
                    rng.range(80, 400),
                    dns_state,
                ),
                None,
                truths,
            );
        }
    }
    // Externi klienti na webove servery.
    for device in model
        .devices
        .iter()
        .filter(|d| matches!(d.role, Role::Web | Role::Container) && d.up)
    {
        let factor = diurnal(Role::Web, model.archetype, t0, model.tz_hours).max(0.3);
        let n = rng.poisson(45.0 * factor * sampling);
        let dst = &ctx.ips[device.id as usize];
        for _ in 0..n {
            let at = t0 + rng.range(0, CYCLE_SECS as u64 - 1) as i64;
            let port = if rng.chance(0.6) { 443 } else { 80 };
            let client = public_ip(rng);
            push(
                &mut out,
                ctx,
                obs(
                    at,
                    &client,
                    rng.range(32768, 60999) as u16,
                    dst,
                    "tcp",
                    port,
                    rng.lognormal(0.4, 1.0),
                    rng.lognormal(500.0, 0.8) as u64,
                    rng.lognormal(12000.0, 1.3) as u64,
                    "SF",
                ),
                None,
                truths,
            );
        }
    }
    // NTP z brany (zname benigni "fan-out" na externi adresy).
    for _ in 0..rng.range(1, 3) {
        let at = t0 + rng.range(0, CYCLE_SECS as u64 - 1) as i64;
        let dst = model.externals[rng.range(0, model.externals.len() as u64 - 1) as usize].clone();
        push(
            &mut out,
            ctx,
            obs(
                at,
                &ctx.ips[model.gateway as usize],
                123,
                &dst,
                "udp",
                123,
                0.05,
                76,
                76,
                "SF",
            ),
            None,
            truths,
        );
    }

    // --- aktivni truth polozky ---
    for index in 0..truths.len() {
        if ctx.cycle < truths[index].start_cycle || ctx.cycle > truths[index].end_cycle {
            continue;
        }
        let snapshot = truths[index].clone();
        emit_truth(
            &snapshot,
            ctx,
            t0,
            &mut flow_id,
            rng,
            &mut out,
            truths,
            index,
        );
    }

    // --- aktivni inventar nmapu (kazdy 4. cyklus, nebo kdyz je tu rogue) ---
    if ctx.cycle % 4 == 0 || ctx.rogue.is_some() {
        let (mut inventory, inventory_devices) = model.inventory();
        for (device_id, host) in inventory_devices.iter().zip(inventory.hosts.iter_mut()) {
            host.ip = ctx.ips[*device_id as usize].clone();
        }
        out.inventory_devices = inventory_devices;
        if let Some((ip, mac)) = &ctx.rogue {
            inventory.hosts.push(ParsedHost {
                ip: ip.clone(),
                hostname: None,
                mac: Some(mac.clone()),
                vendor: None,
                services: vec![ParsedService {
                    proto: "tcp".to_string(),
                    port: 8080,
                    port_state: "open".to_string(),
                    state_reason: Some("syn-ack".to_string()),
                    service_name: Some("http-proxy".to_string()),
                    product: None,
                    version: None,
                    extrainfo: None,
                    detection_source: "nmap".to_string(),
                    confidence: crate::model::Confidence::Low,
                    cpes: Vec::new(),
                }],
            });
        }
        out.inventory = Some(inventory);
    }

    degrade(&mut out, ctx, rng);
    out
}

/// Pridani toku s kontrolou kernelu: zablokovany zdroj tok "nikdy nedorazi".
fn push(
    out: &mut CycleOutput,
    ctx: &CycleContext<'_>,
    observation: ConnectionObservation,
    truth: Option<usize>,
    truths: &mut [Truth],
) {
    let src = observation.src_ip.clone().unwrap_or_default();
    let blocked = ctx.oracle.is_blocked(&src, observation.timestamp);
    match truth {
        Some(index) => {
            let item = &mut truths[index];
            item.flows_emitted += 1;
            item.touched_ips.insert(src.clone());
            item.touched_ips.insert(observation.dst_ip.clone());
            if item.first_emit_cycle.is_none() {
                item.first_emit_cycle = Some(ctx.cycle);
            }
            if blocked {
                item.flows_blocked += 1;
                if item.blocked_at_cycle.is_none() {
                    item.blocked_at_cycle = Some(ctx.cycle);
                }
            }
        }
        None => {
            out.benign_flows += 1;
            if blocked {
                out.benign_flows_blocked += 1;
            }
        }
    }
    if !blocked {
        out.observations.push(observation);
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_truth(
    truth: &Truth,
    ctx: &CycleContext<'_>,
    t0: i64,
    flow_id: &mut u64,
    rng: &mut Rng,
    out: &mut CycleOutput,
    truths: &mut [Truth],
    index: usize,
) {
    let model = ctx.model;
    let ips = ctx.ips;
    let at = |rng: &mut Rng| t0 + rng.range(0, CYCLE_SECS as u64 - 1) as i64;
    let attacker_ip: Option<String> = truth
        .attacker_device
        .map(|d| ips[d as usize].clone())
        .or_else(|| truth.attacker_external.clone());
    let alert = |out: &mut CycleOutput,
                 when: i64,
                 src: &str,
                 sport: u16,
                 dst: &str,
                 dport: u16,
                 sig_id: u32,
                 sig: &str,
                 sev: u8,
                 flow_id: &mut u64| {
        *flow_id += 1;
        out.alerts.push(eve_line(
            when, *flow_id, src, sport, dst, dport, sig_id, sig, sev,
        ));
    };
    macro_rules! flow {
        ($when:expr, $src:expr, $dst:expr, $proto:expr, $port:expr, $dur:expr, $ob:expr, $rb:expr, $state:expr) => {
            push(
                out,
                ctx,
                obs(
                    $when,
                    $src,
                    rng.range(32768, 60999) as u16,
                    $dst,
                    $proto,
                    $port,
                    $dur,
                    $ob,
                    $rb,
                    $state,
                ),
                Some(index),
                truths,
            )
        };
    }
    let benign_marker = matches!(truth.kind, Kind::Benign(_));
    let family = match truth.kind {
        Kind::Attack(f) => Some(f),
        Kind::Benign(_) => None,
    };

    match truth.kind {
        Kind::Attack(Family::PortScanVertical) => {
            let (Some(src), Some(&victim)) = (&attacker_ip, truth.victim_devices.first()) else {
                return;
            };
            let dst = &ips[victim as usize];
            let k = ((truth.intensity * 400.0).ceil() as usize).max(8);
            let open: Vec<u16> = model.devices[victim as usize]
                .services
                .iter()
                .map(|s| s.port)
                .collect();
            for port in rng
                .sample_distinct(65535, k)
                .into_iter()
                .map(|p| p as u16 + 1)
            {
                let is_open = open.contains(&port);
                push(
                    out,
                    ctx,
                    obs(
                        at(rng),
                        src,
                        rng.range(32768, 60999) as u16,
                        dst,
                        "tcp",
                        port,
                        0.0,
                        0,
                        0,
                        if is_open { "S1" } else { "S0" },
                    ),
                    Some(index),
                    truths,
                );
            }
            if truth.ids_visible {
                let when = at(rng);
                alert(
                    out,
                    when,
                    src,
                    40000,
                    dst,
                    22,
                    2010935,
                    "ET SCAN Suspicious inbound to SSH port scan",
                    2,
                    flow_id,
                );
            }
        }
        Kind::Attack(Family::PortScanHorizontal) => {
            let Some(src) = &attacker_ip else { return };
            if truth.victim_devices.is_empty() {
                return;
            }
            let port = *rng.pick(&[22u16, 445, 3389, 23, 80, 443]);
            for &victim in &truth.victim_devices {
                if rng.chance(0.3 + truth.intensity * 0.7) {
                    push(
                        out,
                        ctx,
                        obs(
                            at(rng),
                            src,
                            rng.range(32768, 60999) as u16,
                            &ips[victim as usize],
                            "tcp",
                            port,
                            0.0,
                            0,
                            0,
                            "S0",
                        ),
                        Some(index),
                        truths,
                    );
                }
            }
            if truth.ids_visible {
                let when = at(rng);
                alert(
                    out,
                    when,
                    src,
                    40001,
                    &ips[truth.victim_devices[0] as usize],
                    port,
                    2002910,
                    "ET SCAN Potential horizontal scan",
                    2,
                    flow_id,
                );
            }
        }
        Kind::Attack(Family::SlowScan) => {
            let Some(src) = &attacker_ip else { return };
            if truth.victim_devices.is_empty() {
                return;
            }
            let victim =
                truth.victim_devices[rng.range(0, truth.victim_devices.len() as u64 - 1) as usize];
            for _ in 0..rng.range(1, 3) {
                push(
                    out,
                    ctx,
                    obs(
                        at(rng),
                        src,
                        rng.range(32768, 60999) as u16,
                        &ips[victim as usize],
                        "tcp",
                        rng.range(1, 10000) as u16,
                        0.0,
                        0,
                        0,
                        "S0",
                    ),
                    Some(index),
                    truths,
                );
            }
        }
        Kind::Attack(Family::SshBrute) => {
            let (Some(src), Some(&victim)) = (&attacker_ip, truth.victim_devices.first()) else {
                return;
            };
            let device = &model.devices[victim as usize];
            let port = device
                .services
                .iter()
                .map(|s| s.port)
                .find(|p| matches!(p, 22 | 23 | 3389 | 3306))
                .unwrap_or(22);
            let n = ((truth.intensity * 1500.0) as usize).max(20);
            for _ in 0..n {
                let state = match rng.weighted(&[0.5, 0.3, 0.2]) {
                    0 => "RSTO",
                    1 => "S1",
                    _ => "SF",
                };
                push(
                    out,
                    ctx,
                    obs(
                        at(rng),
                        src,
                        rng.range(32768, 60999) as u16,
                        &ips[victim as usize],
                        "tcp",
                        port,
                        rng.range_f(0.2, 2.0),
                        rng.range(100, 500),
                        rng.range(80, 400),
                        state,
                    ),
                    Some(index),
                    truths,
                );
            }
            if truth.ids_visible {
                for _ in 0..rng.range(1, 4) {
                    let when = at(rng);
                    alert(
                        out,
                        when,
                        src,
                        40002,
                        &ips[victim as usize],
                        port,
                        2001219,
                        "ET SCAN Potential SSH Scan",
                        2,
                        flow_id,
                    );
                }
            }
        }
        Kind::Attack(Family::C2Beacon) => {
            let (Some(src), Some(target)) = (&attacker_ip, &truth.target_external) else {
                return;
            };
            let interval = 60.0 * (1.0 + (1.0 - truth.intensity) * 10.0);
            let n = (CYCLE_SECS as f64 / interval).ceil() as usize;
            for i in 0..n {
                let jitter = rng.range_f(-0.2, 0.2) * interval;
                let when =
                    t0 + ((i as f64 * interval + jitter).max(0.0) as i64).min(CYCLE_SECS - 1);
                push(
                    out,
                    ctx,
                    obs(
                        when,
                        src,
                        rng.range(32768, 60999) as u16,
                        target,
                        "tcp",
                        443,
                        rng.range_f(0.1, 1.0),
                        rng.range(200, 400),
                        rng.range(100, 1000),
                        "SF",
                    ),
                    Some(index),
                    truths,
                );
            }
            if truth.ids_visible && rng.chance(0.3) {
                let when = at(rng);
                alert(
                    out,
                    when,
                    src,
                    40003,
                    target,
                    443,
                    2027865,
                    "ET MALWARE Known C2 beacon pattern",
                    1,
                    flow_id,
                );
            }
        }
        Kind::Attack(Family::Ddos) => {
            let (Some(&victim), true) = (truth.victim_devices.first(), true) else {
                return;
            };
            let n = ((truth.intensity * 8000.0) as usize).max(500);
            let sources = ((truth.intensity * 500.0) as usize).max(20);
            let pool: Vec<String> = (0..sources).map(|_| public_ip(rng)).collect();
            let port = if rng.chance(0.6) { 80 } else { 443 };
            for i in 0..n {
                push(
                    out,
                    ctx,
                    obs(
                        at(rng),
                        &pool[i % sources],
                        rng.range(1024, 65000) as u16,
                        &ips[victim as usize],
                        "tcp",
                        port,
                        0.0,
                        rng.range(40, 120),
                        0,
                        if rng.chance(0.7) { "S0" } else { "S1" },
                    ),
                    Some(index),
                    truths,
                );
            }
            if truth.ids_visible {
                let when = at(rng);
                alert(
                    out,
                    when,
                    &pool[0],
                    40004,
                    &ips[victim as usize],
                    port,
                    2008578,
                    "ET DOS Possible SYN flood",
                    2,
                    flow_id,
                );
            }
        }
        Kind::Attack(Family::Exfil) => {
            let (Some(src), Some(target)) = (&attacker_ip, &truth.target_external) else {
                return;
            };
            for _ in 0..rng.range(1, 3) {
                let bytes = rng.lognormal(truth.intensity * 3.0e9, 0.5) as u64;
                push(
                    out,
                    ctx,
                    obs(
                        at(rng),
                        src,
                        rng.range(32768, 60999) as u16,
                        target,
                        "tcp",
                        443,
                        rng.range_f(300.0, 1800.0),
                        bytes,
                        rng.range(2000, 50000),
                        "SF",
                    ),
                    Some(index),
                    truths,
                );
            }
        }
        Kind::Attack(Family::Lateral) => {
            let Some(src) = &attacker_ip else { return };
            for &victim in &truth.victim_devices {
                let ip = &ips[victim as usize];
                if ip == src {
                    continue;
                }
                let port = *rng.pick(&[445u16, 3389, 22, 135]);
                push(
                    out,
                    ctx,
                    obs(
                        at(rng),
                        src,
                        rng.range(32768, 60999) as u16,
                        ip,
                        "tcp",
                        port,
                        rng.range_f(0.5, 20.0),
                        rng.range(500, 20000),
                        rng.range(500, 20000),
                        "SF",
                    ),
                    Some(index),
                    truths,
                );
            }
        }
        Kind::Attack(Family::RogueDevice) => {
            let Some((rogue_ip, _)) = &ctx.rogue else {
                return;
            };
            for _ in 0..rng.range(3, 20) {
                let victim = rng.range(0, ips.len() as u64 - 1) as usize;
                push(
                    out,
                    ctx,
                    obs(
                        at(rng),
                        rogue_ip,
                        rng.range(32768, 60999) as u16,
                        &ips[victim],
                        "tcp",
                        rng.range(1, 1024) as u16,
                        0.0,
                        0,
                        0,
                        "S0",
                    ),
                    Some(index),
                    truths,
                );
            }
        }
        Kind::Attack(Family::Exploit) => {
            let (Some(src), Some(&victim)) = (&attacker_ip, truth.victim_devices.first()) else {
                return;
            };
            let device = &model.devices[victim as usize];
            let Some(service) = device
                .services
                .iter()
                .find(|s| !s.cves.is_empty())
                .or_else(|| device.services.first())
            else {
                return;
            };
            for _ in 0..rng.range(1, 5) {
                push(
                    out,
                    ctx,
                    obs(
                        at(rng),
                        src,
                        rng.range(32768, 60999) as u16,
                        &ips[victim as usize],
                        service.proto,
                        service.port,
                        rng.range_f(0.1, 3.0),
                        rng.range(400, 5000),
                        rng.range(200, 4000),
                        "SF",
                    ),
                    Some(index),
                    truths,
                );
            }
            if truth.ids_visible {
                let when = at(rng);
                let sig = format!(
                    "ET EXPLOIT {} remote code execution attempt",
                    service.product
                );
                alert(
                    out,
                    when,
                    src,
                    40005,
                    &ips[victim as usize],
                    service.port,
                    2024897,
                    &sig,
                    1,
                    flow_id,
                );
            }
        }
        Kind::Attack(Family::DnsTunnel) => {
            let (Some(src), Some(target)) = (&attacker_ip, &truth.target_external) else {
                return;
            };
            let n = ((truth.intensity * 600.0) as usize).max(30);
            for i in 0..n {
                let dst = if i % 3 == 0 {
                    target.clone()
                } else {
                    ips[model.dns as usize].clone()
                };
                push(
                    out,
                    ctx,
                    obs(
                        at(rng),
                        src,
                        rng.range(32768, 60999) as u16,
                        &dst,
                        "udp",
                        53,
                        0.1,
                        rng.range(180, 500),
                        rng.range(400, 1200),
                        "SF",
                    ),
                    Some(index),
                    truths,
                );
            }
        }
        Kind::Benign(Lookalike::Backup) => {
            let (Some(src_dev), Some(&server)) =
                (truth.attacker_device, truth.victim_devices.first())
            else {
                return;
            };
            if src_dev == server {
                return;
            }
            for _ in 0..rng.range(2, 6) {
                let bytes = rng.lognormal(3.0e9 * truth.intensity, 0.4) as u64;
                push(
                    out,
                    ctx,
                    obs(
                        at(rng),
                        &ips[src_dev as usize],
                        rng.range(32768, 60999) as u16,
                        &ips[server as usize],
                        "tcp",
                        445,
                        rng.range_f(600.0, 1800.0),
                        bytes,
                        rng.range(1000, 9000),
                        "SF",
                    ),
                    Some(index),
                    truths,
                );
            }
        }
        Kind::Benign(Lookalike::AuthorizedScanner) => {
            let Some(scanner) = truth.attacker_device else {
                return;
            };
            for target in 0..ips.len() {
                if target as u32 == scanner {
                    continue;
                }
                for port in [22u16, 80, 443, 445, 3389] {
                    if rng.chance(0.5 * truth.intensity + 0.2) {
                        push(
                            out,
                            ctx,
                            obs(
                                at(rng),
                                &ips[scanner as usize],
                                rng.range(32768, 60999) as u16,
                                &ips[target],
                                "tcp",
                                port,
                                0.0,
                                0,
                                0,
                                "S0",
                            ),
                            Some(index),
                            truths,
                        );
                    }
                }
            }
        }
        Kind::Benign(Lookalike::FlashCrowd) => {
            let Some(&server) = truth.victim_devices.first() else {
                return;
            };
            let n = (truth.intensity * 3000.0) as usize + 400;
            for _ in 0..n {
                let client = public_ip(rng);
                push(
                    out,
                    ctx,
                    obs(
                        at(rng),
                        &client,
                        rng.range(32768, 60999) as u16,
                        &ips[server as usize],
                        "tcp",
                        443,
                        rng.lognormal(0.6, 0.8),
                        rng.lognormal(600.0, 0.6) as u64,
                        rng.lognormal(30000.0, 1.0) as u64,
                        "SF",
                    ),
                    Some(index),
                    truths,
                );
            }
        }
        Kind::Benign(Lookalike::SoftwareUpdate) => {
            let target = truth
                .target_external
                .clone()
                .unwrap_or_else(|| public_ip(rng));
            for device in model.devices.iter().filter(|d| d.role == Role::Workstation) {
                push(
                    out,
                    ctx,
                    obs(
                        at(rng),
                        &ips[device.id as usize],
                        rng.range(32768, 60999) as u16,
                        &target,
                        "tcp",
                        443,
                        rng.range_f(30.0, 300.0),
                        rng.range(2000, 9000),
                        rng.lognormal(1.2e8, 0.5) as u64,
                        "SF",
                    ),
                    Some(index),
                    truths,
                );
            }
        }
        Kind::Benign(Lookalike::NtpFanout) => {
            let Some(src_dev) = truth.attacker_device else {
                return;
            };
            for _ in 0..rng.range(20, 50) {
                let dst = public_ip(rng);
                push(
                    out,
                    ctx,
                    obs(
                        at(rng),
                        &ips[src_dev as usize],
                        123,
                        &dst,
                        "udp",
                        123,
                        0.05,
                        76,
                        76,
                        "SF",
                    ),
                    Some(index),
                    truths,
                );
            }
        }
        Kind::Attack(Family::CredentialStuffing) => {
            let (Some(&victim), Some(src0)) = (truth.victim_devices.first(), &attacker_ip) else {
                return;
            };
            let device = &model.devices[victim as usize];
            let port = device
                .services
                .iter()
                .map(|s| s.port)
                .find(|p| matches!(p, 443 | 1194 | 80 | 8080))
                .unwrap_or(443);
            let sources = ((truth.intensity * 300.0) as usize).max(10);
            let pool: Vec<String> = std::iter::once(src0.clone())
                .chain((1..sources).map(|_| public_ip(rng)))
                .collect();
            let n = ((truth.intensity * 1200.0) as usize).max(60);
            for i in 0..n {
                let state = if rng.chance(0.25) { "RSTO" } else { "SF" };
                flow!(
                    at(rng),
                    &pool[i % sources],
                    &ips[victim as usize],
                    "tcp",
                    port,
                    rng.range_f(0.1, 1.5),
                    rng.range(300, 900),
                    rng.range(200, 600),
                    state
                );
            }
            if truth.ids_visible {
                let when = at(rng);
                alert(
                    out,
                    when,
                    &pool[0],
                    40010,
                    &ips[victim as usize],
                    port,
                    2024219,
                    "ET WEB_SERVER Possible credential stuffing",
                    2,
                    flow_id,
                );
            }
        }
        Kind::Attack(Family::Ransomware) => {
            let Some(src) = &attacker_ip else { return };
            for &victim in &truth.victim_devices {
                if &ips[victim as usize] == src || !model.devices[victim as usize].up {
                    continue;
                }
                for _ in 0..rng.range(1, 3) {
                    flow!(
                        at(rng),
                        src,
                        &ips[victim as usize],
                        "tcp",
                        445,
                        rng.range_f(20.0, 600.0),
                        rng.range(1_000_000, 80_000_000),
                        rng.range(500_000, 40_000_000),
                        "SF"
                    );
                }
            }
            if let Some(target) = &truth.target_external {
                for _ in 0..rng.range(2, 6) {
                    flow!(at(rng), src, target, "tcp", 443, 0.5, 300, 600, "SF");
                }
            }
            if truth.ids_visible && rng.chance(0.5) {
                if let Some(&first) = truth.victim_devices.first() {
                    let when = at(rng);
                    alert(
                        out,
                        when,
                        src,
                        40011,
                        &ips[first as usize],
                        445,
                        2027000,
                        "ET MALWARE Ransomware SMB encryption activity",
                        1,
                        flow_id,
                    );
                }
            }
        }
        Kind::Attack(Family::Cryptomining) => {
            let (Some(src), Some(target)) = (&attacker_ip, &truth.target_external) else {
                return;
            };
            for _ in 0..rng.range(1, 3) {
                flow!(
                    t0 + rng.range(0, 200) as i64,
                    src,
                    target,
                    "tcp",
                    3333,
                    1700.0,
                    rng.range(40_000, 200_000),
                    rng.range(40_000, 200_000),
                    "SF"
                );
            }
            if truth.ids_visible && rng.chance(0.1) {
                let when = at(rng);
                alert(
                    out,
                    when,
                    src,
                    40012,
                    target,
                    3333,
                    2024792,
                    "ET POLICY Cryptocurrency Miner Checkin",
                    2,
                    flow_id,
                );
            }
        }
        Kind::Attack(Family::InsiderHoarding) => {
            let (Some(src), Some(&server)) = (&attacker_ip, truth.victim_devices.first()) else {
                return;
            };
            for _ in 0..rng.range(3, 10) {
                flow!(
                    at(rng),
                    src,
                    &ips[server as usize],
                    "tcp",
                    445,
                    rng.range_f(60.0, 900.0),
                    4000,
                    rng.lognormal(6.0e8 * truth.intensity + 1.0e8, 0.5) as u64,
                    "SF"
                );
            }
            if ctx.cycle == truth.end_cycle {
                if let Some(target) = &truth.target_external {
                    flow!(
                        at(rng),
                        src,
                        target,
                        "tcp",
                        443,
                        600.0,
                        rng.lognormal(3.0e8 * truth.intensity + 5.0e7, 0.4) as u64,
                        20_000,
                        "SF"
                    );
                }
            }
        }
        Kind::Attack(Family::WebExploit) => {
            let (Some(src), Some(&victim)) = (&attacker_ip, truth.victim_devices.first()) else {
                return;
            };
            let port = model.devices[victim as usize]
                .services
                .iter()
                .find(|s| s.web)
                .map(|s| s.port)
                .unwrap_or(443);
            let n = 40 + (truth.intensity * 400.0) as usize;
            for _ in 0..n {
                let state = if rng.chance(0.1) { "RSTO" } else { "SF" };
                flow!(
                    at(rng),
                    src,
                    &ips[victim as usize],
                    "tcp",
                    port,
                    rng.range_f(0.05, 1.5),
                    rng.range(800, 6000),
                    rng.range(200, 3000),
                    state
                );
            }
            if truth.ids_visible {
                for _ in 0..rng.range(1, 3) {
                    let when = at(rng);
                    alert(
                        out,
                        when,
                        src,
                        40013,
                        &ips[victim as usize],
                        port,
                        2006446,
                        "ET WEB_SERVER SQL Injection Attempt",
                        1,
                        flow_id,
                    );
                }
            }
        }
        Kind::Attack(Family::IcsAttack) => {
            let Some(src) = &attacker_ip else { return };
            for &plc in &truth.victim_devices {
                let port = model.devices[plc as usize]
                    .services
                    .first()
                    .map(|s| s.port)
                    .unwrap_or(502);
                let n = 30 + (truth.intensity * 300.0) as usize;
                for _ in 0..n {
                    flow!(
                        at(rng),
                        src,
                        &ips[plc as usize],
                        "tcp",
                        port,
                        0.05,
                        40,
                        40,
                        "SF"
                    );
                }
                if truth.ids_visible {
                    let when = at(rng);
                    alert(
                        out,
                        when,
                        src,
                        40014,
                        &ips[plc as usize],
                        port,
                        2026001,
                        "ET SCADA Modbus Write from non-HMI source",
                        1,
                        flow_id,
                    );
                }
            }
        }
        Kind::Attack(Family::FleetBeacon) => {
            let Some(target) = &truth.target_external else {
                return;
            };
            for &victim in &truth.victim_devices {
                if !model.devices[victim as usize].up {
                    continue;
                }
                for _ in 0..rng.range(1, 3) {
                    flow!(
                        at(rng),
                        &ips[victim as usize],
                        target,
                        "tcp",
                        443,
                        rng.range_f(0.1, 0.8),
                        rng.range(200, 450),
                        rng.range(100, 900),
                        "SF"
                    );
                }
            }
            if truth.ids_visible && rng.chance(0.05) {
                if let Some(&first) = truth.victim_devices.first() {
                    let when = at(rng);
                    alert(
                        out,
                        when,
                        &ips[first as usize],
                        40015,
                        target,
                        443,
                        2027865,
                        "ET MALWARE Known C2 beacon pattern",
                        1,
                        flow_id,
                    );
                }
            }
        }
        Kind::Attack(Family::ApChain) => {
            let (Some(ext), Some(&entry), Some(target)) = (
                &attacker_ip,
                truth.victim_devices.first(),
                &truth.target_external,
            ) else {
                return;
            };
            let span = (truth.end_cycle - truth.start_cycle).max(1) as f64;
            let progress = (ctx.cycle - truth.start_cycle) as f64 / span;
            let entry_ip = &ips[entry as usize];
            if progress < 0.12 {
                for port in rng
                    .sample_distinct(65535, 40)
                    .into_iter()
                    .map(|p| p as u16 + 1)
                {
                    flow!(at(rng), ext, entry_ip, "tcp", port, 0.0, 0, 0, "S0");
                }
            } else if progress < 0.25 {
                let device = &model.devices[entry as usize];
                if let Some(service) = device
                    .services
                    .iter()
                    .find(|s| !s.cves.is_empty())
                    .or_else(|| device.services.first())
                {
                    for _ in 0..rng.range(2, 4) {
                        flow!(
                            at(rng),
                            ext,
                            entry_ip,
                            service.proto,
                            service.port,
                            rng.range_f(0.1, 3.0),
                            rng.range(400, 5000),
                            rng.range(200, 4000),
                            "SF"
                        );
                    }
                    if truth.ids_visible && rng.chance(0.4) {
                        let when = at(rng);
                        alert(
                            out,
                            when,
                            ext,
                            40016,
                            entry_ip,
                            service.port,
                            2024897,
                            "ET EXPLOIT remote code execution attempt",
                            1,
                            flow_id,
                        );
                    }
                }
            } else if progress < 0.85 {
                for &victim in truth.victim_devices.iter().skip(1) {
                    if rng.chance(0.12) && ips[victim as usize] != *entry_ip {
                        let port = *rng.pick(&[445u16, 3389, 22, 135]);
                        flow!(
                            at(rng),
                            entry_ip,
                            &ips[victim as usize],
                            "tcp",
                            port,
                            rng.range_f(0.5, 20.0),
                            rng.range(500, 20000),
                            rng.range(500, 20000),
                            "SF"
                        );
                    }
                }
                for _ in 0..rng.range(1, 3) {
                    flow!(at(rng), entry_ip, target, "tcp", 443, 0.4, 300, 500, "SF");
                }
            } else if rng.chance(0.5) {
                let source = truth.victim_devices.last().copied().unwrap_or(entry);
                flow!(
                    at(rng),
                    &ips[source as usize],
                    target,
                    "tcp",
                    443,
                    rng.range_f(300.0, 1800.0),
                    rng.lognormal(2.0e8 * truth.intensity + 3.0e7, 0.5) as u64,
                    rng.range(2000, 50000),
                    "SF"
                );
            }
        }
        // --- provozni udalosti: tvari se jako utok, ale jsou to jen provoz a poruchy ---
        Kind::Benign(Lookalike::ServiceCrash) | Kind::Benign(Lookalike::Decommission) => {
            // symptomy vznikaji v zakladnim provozu (klienti dostavaji timeouty)
        }
        Kind::Benign(Lookalike::RetryStorm) => {
            let clients: Vec<u32> = model
                .devices
                .iter()
                .filter(|d| !d.role.is_server() && d.up)
                .map(|d| d.id)
                .collect();
            if clients.is_empty() {
                return;
            }
            let n = clients.len().min(200);
            for pick in rng.sample_distinct(clients.len(), n) {
                let client = clients[pick];
                for _ in 0..rng.range(6, 24) {
                    let dst = model.externals
                        [rng.range(0, model.externals.len() as u64 - 1) as usize]
                        .clone();
                    flow!(
                        at(rng),
                        &ips[client as usize],
                        &dst,
                        "tcp",
                        443,
                        0.0,
                        0,
                        0,
                        "S0"
                    );
                }
            }
        }
        Kind::Benign(Lookalike::Onboarding) => {
            let Some(&device) = truth.victim_devices.first() else {
                return;
            };
            let servers: Vec<u32> = model
                .devices
                .iter()
                .filter(|d| d.role.is_server() && d.up)
                .map(|d| d.id)
                .collect();
            if servers.is_empty() {
                return;
            }
            for _ in 0..rng.range(10, 40) {
                let server = *rng.pick(&servers);
                let Some(service) = model.devices[server as usize].services.first() else {
                    continue;
                };
                flow!(
                    at(rng),
                    &ips[device as usize],
                    &ips[server as usize],
                    service.proto,
                    service.port,
                    rng.range_f(0.1, 2.0),
                    rng.range(200, 4000),
                    rng.range(500, 30000),
                    "SF"
                );
            }
        }
        Kind::Benign(Lookalike::PatchWindow) => {
            let Some(target) = &truth.target_external else {
                return;
            };
            for &victim in &truth.victim_devices {
                flow!(
                    at(rng),
                    &ips[victim as usize],
                    target,
                    "tcp",
                    443,
                    rng.range_f(60.0, 600.0),
                    4000,
                    rng.lognormal(1.5e8, 0.5) as u64,
                    "SF"
                );
            }
        }
        Kind::Benign(Lookalike::BatchJob) => {
            let partners: Vec<u32> = model
                .devices
                .iter()
                .filter(|d| d.role.is_server() && d.up && d.role != Role::Gateway)
                .map(|d| d.id)
                .collect();
            for &server in &truth.victim_devices {
                if partners.is_empty() {
                    return;
                }
                let port = model.devices[server as usize]
                    .services
                    .first()
                    .map(|s| s.port)
                    .unwrap_or(445);
                for _ in 0..rng.range(3, 10) {
                    let partner = *rng.pick(&partners);
                    if partner == server {
                        continue;
                    }
                    flow!(
                        at(rng),
                        &ips[partner as usize],
                        &ips[server as usize],
                        "tcp",
                        port,
                        rng.range_f(300.0, 1800.0),
                        rng.lognormal(2.0e9, 0.5) as u64,
                        5000,
                        "SF"
                    );
                }
            }
        }
        Kind::Benign(Lookalike::CollectorReplay) => {
            let up: Vec<u32> = model
                .devices
                .iter()
                .filter(|d| d.up)
                .map(|d| d.id)
                .collect();
            if up.len() < 2 {
                return;
            }
            for _ in 0..rng.range(200, 3000) {
                let src = *rng.pick(&up);
                let dst = *rng.pick(&up);
                if src == dst {
                    continue;
                }
                let Some(service) = model.devices[dst as usize].services.first() else {
                    continue;
                };
                let when = t0 - rng.range(1, 6) as i64 * CYCLE_SECS
                    + rng.range(0, CYCLE_SECS as u64 - 1) as i64;
                flow!(
                    when,
                    &ips[src as usize],
                    &ips[dst as usize],
                    service.proto,
                    service.port,
                    rng.range_f(0.1, 2.0),
                    rng.range(200, 4000),
                    rng.range(500, 30000),
                    "SF"
                );
            }
        }
        Kind::Benign(Lookalike::SensorCrash) => {
            out.sensor_down = true;
        }
        Kind::Benign(Lookalike::LogCorruption) => {
            for _ in 0..rng.range(10, 40) {
                let junk = match rng.range(0, 3) {
                    0 => "{\"timestamp\":\"2026-01-05T10:00:00.000000+0000\",\"flow_id\":12,\"event_t".to_string(),
                    1 => "\u{0}\u{1}\u{2}binary-garbage\u{7f}".to_string(),
                    2 => "{\"event_type\":\"alert\",\"src_ip\":null,\"dest_ip\":12345}".to_string(),
                    _ => "}{ not json at all ]".to_string(),
                };
                out.alerts.push(junk);
            }
            let up: Vec<u32> = model
                .devices
                .iter()
                .filter(|d| d.up)
                .map(|d| d.id)
                .collect();
            for _ in 0..rng.range(50, 300) {
                if up.len() < 2 {
                    break;
                }
                let (a, b) = (*rng.pick(&up), *rng.pick(&up));
                let mut broken = obs(
                    at(rng),
                    &ips[a as usize],
                    rng.range(32768, 60999) as u16,
                    &ips[b as usize],
                    "tcp",
                    rng.range(1, 65000) as u16,
                    0.1,
                    100,
                    100,
                    "SF",
                );
                match rng.range(0, 3) {
                    0 => {
                        broken.orig_bytes = None;
                        broken.resp_bytes = None;
                        broken.total_bytes = None;
                    }
                    1 => {
                        broken.dst_port = None;
                        broken.conn_state = None;
                    }
                    2 => broken.duration_s = None,
                    _ => {
                        broken.proto = "unknown".to_string();
                        broken.total_pkts = None;
                    }
                }
                push(out, ctx, broken, Some(index), truths);
            }
        }
    }
    let _ = (benign_marker, family);
}

/// Degradace telemetrie podle parametru site: ztrata, duplicity, posun hodin,
/// vypadek celeho sensoru (zadna data tento cyklus).
fn degrade(out: &mut CycleOutput, ctx: &CycleContext<'_>, rng: &mut Rng) {
    let t = ctx.telemetry;
    if out.sensor_down {
        out.observations.clear();
        out.alerts.clear();
        out.outage = true;
        return;
    }
    if !t.blind_subnets.is_empty() {
        out.observations.retain(|o| {
            let ends = [o.src_ip.as_deref().unwrap_or(""), o.dst_ip.as_str()];
            let subnets: Vec<usize> = ends
                .iter()
                .filter_map(|ip| ctx.model.subnet_of(ip))
                .collect();
            subnets.is_empty()
                || !subnets
                    .iter()
                    .all(|s| t.blind_subnets.get(*s).copied().unwrap_or(false))
        });
    }
    if t.outage_p > 0.0 && rng.chance(t.outage_p) {
        out.observations.clear();
        out.alerts.clear();
        out.outage = true;
        return;
    }
    if t.drop_p > 0.0 || t.dup_p > 0.0 || t.skew_s != 0 {
        let mut kept = Vec::with_capacity(out.observations.len());
        for mut observation in out.observations.drain(..) {
            if t.drop_p > 0.0 && rng.chance(t.drop_p) {
                continue;
            }
            if t.skew_s != 0 {
                observation.timestamp += chrono::Duration::seconds(t.skew_s);
            }
            if t.dup_p > 0.0 && rng.chance(t.dup_p) {
                kept.push(observation.clone());
            }
            kept.push(observation);
        }
        out.observations = kept;
    }
}

pub fn seed_for_cycle(network_seed: u64, cycle: u32) -> u64 {
    derive(network_seed, 0xC1C1_E000 + cycle as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(model: &NetworkModel) -> Vec<String> {
        (0..model.devices.len() as u32)
            .map(|d| model.ip_of(d))
            .collect()
    }

    #[test]
    fn calendar_starts_on_monday_and_diurnal_profile_has_office_peak_and_weekend_dip() {
        assert_eq!(weekday(EPOCH0, 0), 0);
        assert_eq!(weekday(EPOCH0 + 5 * 86400, 0), 5);
        let monday_noon = EPOCH0 + 12 * 3600;
        let monday_3am = EPOCH0 + 3 * 3600;
        let saturday_noon = EPOCH0 + 5 * 86400 + 12 * 3600;
        let a = Archetype::Smb;
        assert!(
            diurnal(Role::Workstation, a, monday_noon, 0)
                > diurnal(Role::Workstation, a, monday_3am, 0) * 10.0
        );
        assert!(
            diurnal(Role::Workstation, a, monday_noon, 0)
                > diurnal(Role::Workstation, a, saturday_noon, 0) * 5.0
        );
        assert!(
            (diurnal(Role::Workstation, Archetype::Datacenter, monday_3am, 0) - 0.8).abs() < 1e-9
        );
    }

    #[test]
    fn cycle_generation_is_deterministic_for_same_seed() {
        let model = NetworkModel::generate(1, 3);
        let ip = ips(&model);
        let telemetry = Telemetry {
            drop_p: 0.05,
            dup_p: 0.05,
            skew_s: 30,
            outage_p: 0.0,
            ids_coverage: 1.0,
            blind_subnets: Vec::new(),
        };
        let run = || {
            let mut rng = Rng::new(77);
            let mut truths = plan_episode(&model, &mut rng, 48, &telemetry);
            let ctx = CycleContext {
                model: &model,
                ips: &ip,
                cycle: 12,
                start_offset_s: 0,
                telemetry: &telemetry,
                oracle: &NoBlocks,
                rogue: None,
            };
            let out = generate_cycle(&ctx, &mut truths, &mut rng);
            (out.observations.len(), out.alerts.len(), truths.len())
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn blocked_attacker_flows_are_dropped_and_counted_but_benign_are_not_affected() {
        struct BlockAll;
        impl BlockOracle for BlockAll {
            fn is_blocked(&self, ip: &str, _: DateTime<Utc>) -> bool {
                ip == "203.0.113.9"
            }
        }
        let model = NetworkModel::generate(2, 5);
        let ip = ips(&model);
        let telemetry = Telemetry {
            drop_p: 0.0,
            dup_p: 0.0,
            skew_s: 0,
            outage_p: 0.0,
            ids_coverage: 1.0,
            blind_subnets: Vec::new(),
        };
        let victim = model
            .devices
            .iter()
            .find(|d| d.role.is_server() && !d.services.is_empty())
            .unwrap()
            .id;
        let mut truths = vec![Truth {
            id: 0,
            kind: Kind::Attack(Family::SshBrute),
            start_cycle: 0,
            end_cycle: 5,
            intensity: 0.5,
            attacker_device: None,
            attacker_external: Some("203.0.113.9".to_string()),
            victim_devices: vec![victim],
            target_external: None,
            ids_visible: false,
            touched_ips: BTreeSet::new(),
            flows_emitted: 0,
            flows_blocked: 0,
            first_emit_cycle: None,
            blocked_at_cycle: None,
        }];
        let mut rng = Rng::new(5);
        let ctx = CycleContext {
            model: &model,
            ips: &ip,
            cycle: 1,
            start_offset_s: 0,
            telemetry: &telemetry,
            oracle: &BlockAll,
            rogue: None,
        };
        let out = generate_cycle(&ctx, &mut truths, &mut rng);
        assert!(truths[0].flows_emitted > 0);
        assert_eq!(
            truths[0].flows_emitted, truths[0].flows_blocked,
            "vsechny utocnikovy toky maji byt zablokovany"
        );
        assert!(
            out.observations
                .iter()
                .all(|o| o.src_ip.as_deref() != Some("203.0.113.9"))
        );
        assert_eq!(out.benign_flows_blocked, 0);
        assert_eq!(truths[0].blocked_at_cycle, Some(1));
    }

    #[test]
    fn planned_episode_has_valid_cycle_ranges_and_all_families_appear_over_many_networks() {
        let telemetry = Telemetry {
            drop_p: 0.0,
            dup_p: 0.0,
            skew_s: 0,
            outage_p: 0.0,
            ids_coverage: 1.0,
            blind_subnets: Vec::new(),
        };
        let mut families = std::collections::HashSet::new();
        let mut lookalikes = std::collections::HashSet::new();
        for id in 0..600 {
            let mut model = NetworkModel::generate(11, id);
            let mut rng = Rng::new(id);
            model.add_dormant(&mut rng, 3);
            for truth in plan_episode(&model, &mut rng, 72, &telemetry) {
                assert!(truth.start_cycle <= truth.end_cycle && truth.end_cycle < 144);
                match truth.kind {
                    Kind::Attack(f) => {
                        families.insert(f);
                    }
                    Kind::Benign(l) => {
                        lookalikes.insert(l);
                    }
                }
            }
        }
        assert_eq!(families.len(), Family::ALL.len());
        assert_eq!(lookalikes.len(), 14);
    }

    #[test]
    fn eve_lines_are_accepted_by_the_production_suricata_parser() {
        let line = eve_line(
            EPOCH0 + 60,
            7,
            "198.51.100.4",
            4444,
            "10.0.0.5",
            22,
            2001219,
            "ET SCAN Potential SSH Scan",
            2,
        );
        let scope = vec!["10.0.0.0/24".parse().unwrap()];
        let events = crate::passive::parse_suricata_str(
            &line,
            "soak",
            &scope,
            ts(EPOCH0),
            ts(EPOCH0 + 3600),
        )
        .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].dst_port, Some(22));
        assert_eq!(events[0].source, "suricata");
    }

    #[test]
    fn outage_clears_all_telemetry_for_the_cycle() {
        let model = NetworkModel::generate(4, 4);
        let ip = ips(&model);
        let telemetry = Telemetry {
            drop_p: 0.0,
            dup_p: 0.0,
            skew_s: 0,
            outage_p: 1.0,
            ids_coverage: 1.0,
            blind_subnets: Vec::new(),
        };
        let mut rng = Rng::new(1);
        let mut truths = Vec::new();
        let ctx = CycleContext {
            model: &model,
            ips: &ip,
            cycle: 10,
            start_offset_s: 0,
            telemetry: &telemetry,
            oracle: &NoBlocks,
            rogue: None,
        };
        let out = generate_cycle(&ctx, &mut truths, &mut rng);
        assert!(out.outage && out.observations.is_empty() && out.alerts.is_empty());
    }
}
