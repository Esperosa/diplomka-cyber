//! Simulace koncové telemetrie pro soak (krok 8, D; impl-krok8.md A4).
//!
//! Události se odvozují z EXISTUJÍCÍCH rodin útoků a benigního provozu světa; žádná
//! nová útočná technika. Generátor píše autor (tvrdí „co by koncový nástroj
//! zaznamenal, kdyby techniku viděl“), takže měření ověřuje zapojení do jádra a
//! invarianty, ne zisk na reálném provozu (studie 08, bod 4).
//!
//! Nezávislost proudů: benigní události závisí jen na (zařízení, cyklus), útočné na
//! (id útoku, cyklus), takže kontrafaktuální svět bez útoků má benigní události beze
//! změny a atribuce nálezů útoku funguje stejně jako u síťových nálezů.
//!
//! Imperfekce: pokrytí hostů agentem, výpadky agenta, posun hodin, duplicity,
//! zašuměné benigní události, správcovské nástroje jako falešné podezření a
//! kompromitovaný agent (`silent`: nic neposílá; `ok`: místo útoku hlásí pravidelné
//! spojení podepsaného procesu na protistranu útoku od prvního cyklu).

use std::collections::{HashMap, HashSet};

use crate::{
    endpoint::model::{Conn, EndpointEvent, EndpointSource, EventKind, HostRef, Logon, Process},
    soak::{
        benign_regular::{Peer, RegularInstance},
        netmodel::NetworkModel,
        rng::{Rng, derive},
        traffic::{CYCLE_SECS, Family, Kind, Lookalike, Truth},
    },
};

/// Chování agentů na kompromitovaných hostech.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum AgentMode {
    #[default]
    Honest,
    /// Kompromitovaný agent nic neposílá.
    Silent,
    /// Kompromitovaný agent hlásí jen „vše v pořádku“ (podepsaný pravidelný vzor).
    Ok,
}

impl std::str::FromStr for AgentMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "honest" => Ok(AgentMode::Honest),
            "silent" => Ok(AgentMode::Silent),
            "ok" => Ok(AgentMode::Ok),
            other => Err(format!(
                "neznamy rezim agenta {other} (honest | silent | ok)"
            )),
        }
    }
}

/// Volby světa koncové telemetrie (`--endpoint`, `--endpoint-coverage`, `--endpoint-agent`).
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct EndpointWorld {
    pub on: bool,
    /// Podíl hostů s agentem v procentech.
    pub coverage_pct: u32,
    pub agent: AgentMode,
}

impl Default for EndpointWorld {
    fn default() -> Self {
        Self {
            on: false,
            coverage_pct: 100,
            agent: AgentMode::Honest,
        }
    }
}

/// Parametry šumu (volba autora; zapsané v impl-krok8.md).
const SPOOF_P: f64 = 0.01;
const DUP_P: f64 = 0.02;
const ADMIN_TOOL_P: f64 = 0.0006;
const ENC_SCRIPT_P: f64 = 0.0004;
const OUTAGE_HOST_P: f64 = 0.15;

fn visible_share(family: Family) -> f64 {
    match family {
        Family::Exploit | Family::WebExploit => 0.75,
        Family::Lateral => 0.7,
        Family::ApChain => 0.5,
        Family::C2Beacon | Family::DnsTunnel | Family::Cryptomining => 0.7,
        Family::FleetBeacon => 0.5,
        Family::SshBrute => 0.9,
        Family::CredentialStuffing => 0.6,
        Family::Ransomware => 0.8,
        Family::Exfil | Family::InsiderHoarding => 0.6,
        _ => 0.0,
    }
}

const WRITABLE: &str = "C:\\Users\\svc\\AppData\\Local\\Temp\\";

pub struct EndpointSim {
    pub world: EndpointWorld,
    seed: u64,
    covered: Vec<bool>,
    compromised: Vec<bool>,
    skew: Vec<i64>,
    outages: Vec<Vec<(u32, u32)>>,
    visible: HashMap<u32, bool>,
    /// Zařízení -> (protistrana, benigní vzor) pro celý běh (i pro pozadí).
    regular: Vec<(u32, String, bool)>,
}

fn name_of(device: u32) -> String {
    format!("host{device}")
}

impl EndpointSim {
    pub fn new(
        world: EndpointWorld,
        model: &NetworkModel,
        truths: &[Truth],
        regular: &[RegularInstance],
        ips: &[String],
    ) -> Self {
        let seed = derive(model.seed, 0xE9D0_1757);
        let n = model.devices.len();
        let mut rng = Rng::new(derive(seed, 1));
        let covered: Vec<bool> = (0..n)
            .map(|_| rng.range(0, 99) < world.coverage_pct as u64)
            .collect();
        let skew: Vec<i64> = (0..n)
            .map(|_| {
                if rng.chance(0.4) {
                    0
                } else {
                    rng.range(0, 300) as i64 * if rng.chance(0.5) { 1 } else { -1 }
                }
            })
            .collect();
        let outages: Vec<Vec<(u32, u32)>> = (0..n)
            .map(|_| {
                if rng.chance(OUTAGE_HOST_P) {
                    let start = rng.range(0, 400) as u32;
                    vec![(start, start + rng.range(4, 40) as u32)]
                } else {
                    Vec::new()
                }
            })
            .collect();
        // kompromitovany agent: hosty utoku (aktualni i maskovane utoky, stejne ve svetech)
        let mut compromised = vec![false; n];
        if world.agent != AgentMode::Honest {
            for t in truths.iter().filter(|t| matches!(t.kind, Kind::Attack(_))) {
                for d in t.victim_devices.iter().chain(t.attacker_device.iter()) {
                    compromised[*d as usize] = true;
                }
            }
        }
        let mut visible = HashMap::new();
        for t in truths {
            if let Kind::Attack(family) = t.kind {
                let mut r = Rng::new(derive(seed, 0x7157 + t.id as u64));
                visible.insert(t.id, r.chance(visible_share(family)));
            }
        }
        // benigni pravidelne vzory: pravidelne instance a lookalike (zdroj, protistrana)
        let mut pairs: Vec<(u32, String, bool)> = Vec::new();
        for inst in regular {
            for peer in inst.peers.iter().take(3) {
                let ip = match peer {
                    Peer::Device(d) => ips[*d as usize].clone(),
                    Peer::External(ip) => ip.clone(),
                };
                pairs.push((inst.src, ip, true));
            }
        }
        for t in truths {
            let Kind::Benign(look) = t.kind else { continue };
            if !matches!(
                look,
                Lookalike::Backup
                    | Lookalike::SoftwareUpdate
                    | Lookalike::NtpFanout
                    | Lookalike::BatchJob
                    | Lookalike::AuthorizedScanner
                    | Lookalike::FlashCrowd
            ) {
                continue;
            }
            let mut r = Rng::new(derive(seed, 0xBE15 + t.id as u64));
            let devices: Vec<u32> = t
                .victim_devices
                .iter()
                .copied()
                .chain(t.attacker_device)
                .collect();
            let mut peers: Vec<String> = devices.iter().map(|d| ips[*d as usize].clone()).collect();
            peers.extend(t.target_external.clone());
            peers.extend(t.attacker_external.clone());
            // 20 % lookalike nemá podepsaný proces (vlastní nástroj): zůstane NoSignal
            let signed = !r.chance(0.2);
            let mut count = 0;
            for d in &devices {
                for p in &peers {
                    if *p != ips[*d as usize] && count < 6 {
                        pairs.push((*d, p.clone(), signed));
                        count += 1;
                    }
                }
            }
        }
        pairs.sort();
        pairs.dedup();
        Self {
            world,
            seed,
            covered,
            compromised,
            skew,
            outages,
            visible,
            regular: pairs,
        }
    }

    pub fn covered(&self, device: u32) -> bool {
        self.covered.get(device as usize).copied().unwrap_or(false)
    }

    fn host(&self, device: u32, ips: &[String], r: &mut Rng, model: &NetworkModel) -> HostRef {
        let ip = ips[device as usize].clone();
        let mut host = HostRef {
            hostname: Some(name_of(device)),
            ips: vec![ip],
            macs: vec![model.devices[device as usize].mac.clone()],
            agent: Some(format!("agent-{device}")),
        };
        // špatná identita agenta: jméno jednoho hosta a IP jiného (spor, nikdy sloučení)
        if r.chance(SPOOF_P) && ips.len() > 1 {
            let other = r.range(0, ips.len() as u64 - 1) as usize;
            if other != device as usize {
                host.ips = vec![ips[other].clone()];
                host.macs.clear();
            }
        }
        host
    }

    fn alive(&self, device: u32, cycle: u32) -> bool {
        self.covered(device)
            && !self.outages[device as usize]
                .iter()
                .any(|(a, b)| cycle >= *a && cycle <= *b)
    }

    /// Události cyklu (čas události podle hodin agenta, tedy s posunem). `masked` =
    /// utoky, které se v tomto světě neemitují.
    #[allow(clippy::too_many_arguments)]
    pub fn cycle(
        &self,
        cycle: u32,
        t0: i64,
        truths: &[Truth],
        masked: &HashSet<u32>,
        model: &NetworkModel,
        ips: &[String],
    ) -> Vec<EndpointEvent> {
        let mut out: Vec<EndpointEvent> = Vec::new();
        let at = |r: &mut Rng, device: u32| -> i64 {
            t0 + r.range(0, CYCLE_SECS as u64 - 1) as i64 + self.skew[device as usize]
        };
        let mk = |host: HostRef, ts: i64, kind: EventKind| EndpointEvent {
            source: EndpointSource::Sim,
            host,
            ts,
            kind,
        };
        // --- benigni pozadi: podepsane pravidelne vzory a sum ---
        for (device, peer, signed) in &self.regular {
            if !self.alive(*device, cycle)
                || self.compromised[*device as usize] && self.world.agent == AgentMode::Silent
            {
                continue;
            }
            let mut r = Rng::new(derive(
                self.seed ^ *device as u64,
                cycle as u64 * 7919 + hash(peer),
            ));
            let host = self.host(*device, ips, &mut r, model);
            // pravidelne: pevny odstup cyklu s malym jitterem (agent agreguje)
            let ts = t0 + 600 + r.range(0, 30) as i64 + self.skew[*device as usize];
            let (image, vendor, sig) = if *signed {
                (
                    "C:\\Program Files\\Veeam\\Agent\\veeamagent.exe",
                    Some("Veeam Software"),
                    Some(true),
                )
            } else {
                ("D:\\apps\\inhouse\\sync.exe", None, None)
            };
            out.push(mk(
                host,
                ts,
                EventKind::NetConnect(Conn {
                    image: Some(image.into()),
                    proto: "tcp".into(),
                    src_ip: Some(ips[*device as usize].clone()),
                    src_port: None,
                    dst_ip: peer.clone(),
                    dst_port: 443,
                    vendor: vendor.map(str::to_string),
                    signed: sig,
                }),
            ));
        }
        for device in 0..model.devices.len() as u32 {
            if !self.alive(device, cycle) || !model.devices[device as usize].up {
                continue;
            }
            if self.compromised[device as usize] && self.world.agent == AgentMode::Silent {
                continue;
            }
            let mut r = Rng::new(derive(self.seed ^ 0x5A5A ^ device as u64, cycle as u64));
            // beznyi sum: nekolik podepsanych procesu
            for _ in 0..r.range(1, 3) {
                let host = self.host(device, ips, &mut r, model);
                let ts = at(&mut r, device);
                out.push(mk(
                    host,
                    ts,
                    EventKind::ProcessCreate(Process {
                        image: format!("C:\\Windows\\System32\\svc{}.exe", r.range(0, 9)),
                        parent_image: Some("C:\\Windows\\System32\\services.exe".into()),
                        cmdline: String::new(),
                        user: Some("SYSTEM".into()),
                        signed: None,
                        vendor: Some("Microsoft Corporation".into()),
                    }),
                ));
            }
            // spravcovsky nastroj (falesne podezreni): PsExec po vzdalenem prihlaseni
            if r.chance(ADMIN_TOOL_P) {
                let host = self.host(device, ips, &mut r, model);
                let ts = at(&mut r, device);
                out.push(mk(
                    host.clone(),
                    ts,
                    EventKind::Logon(Logon {
                        user: "admin".into(),
                        logon_type: 3,
                        src_ip: Some(ips[model.gateway as usize].clone()),
                        success: true,
                    }),
                ));
                out.push(mk(
                    host,
                    ts + 20,
                    EventKind::ProcessCreate(Process {
                        image: "C:\\Windows\\PSEXESVC.exe".into(),
                        parent_image: Some("C:\\Windows\\System32\\services.exe".into()),
                        cmdline: "PSEXESVC.exe".into(),
                        user: Some("admin".into()),
                        signed: None,
                        vendor: None,
                    }),
                ));
            }
            // spravcovsky skript s kodovanym prikazem
            if r.chance(ENC_SCRIPT_P) {
                let host = self.host(device, ips, &mut r, model);
                let ts = at(&mut r, device);
                out.push(mk(
                    host,
                    ts,
                    EventKind::ProcessCreate(Process {
                        image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                            .into(),
                        parent_image: Some("C:\\Windows\\System32\\svchost.exe".into()),
                        cmdline: "powershell.exe -NoProfile -enc SQBFAFgA".into(),
                        user: Some("admin".into()),
                        signed: None,
                        vendor: Some("Microsoft Corporation".into()),
                    }),
                ));
            }
        }
        // --- utoky (jen aktivni cyklus a nemaskovane) ---
        for t in truths {
            let Kind::Attack(family) = t.kind else {
                continue;
            };
            if masked.contains(&t.id) || cycle < t.start_cycle || cycle > t.end_cycle {
                continue;
            }
            if !self.visible.get(&t.id).copied().unwrap_or(false) {
                continue;
            }
            let mut r = Rng::new(derive(self.seed ^ 0xA77A ^ t.id as u64, cycle as u64));
            let first = cycle == t.start_cycle;
            let victims: Vec<u32> = t.victim_devices.clone();
            let ext_peer = t
                .target_external
                .clone()
                .or_else(|| t.attacker_external.clone());
            let attacker_ip = t
                .attacker_device
                .map(|d| ips[d as usize].clone())
                .or_else(|| t.attacker_external.clone());
            let emit = |device: u32,
                        kind: EventKind,
                        delay: i64,
                        r: &mut Rng,
                        out: &mut Vec<EndpointEvent>| {
                if !self.alive(device, cycle) {
                    return;
                }
                let comp = self.compromised[device as usize];
                if comp {
                    // silent: nic; ok: utocne udalosti se neposilaji (kryci vzor nize)
                    return;
                }
                let host = self.host(device, ips, r, model);
                let ts = at(r, device) + delay;
                out.push(mk(host, ts, kind));
            };
            match family {
                Family::Exploit | Family::WebExploit if first => {
                    for v in victims.iter().take(2) {
                        emit(
                            *v,
                            EventKind::ProcessCreate(Process {
                                image: "C:\\Windows\\System32\\cmd.exe".into(),
                                parent_image: Some("C:\\inetpub\\w3wp.exe".into()),
                                cmdline: "cmd.exe /c whoami".into(),
                                user: Some("iis".into()),
                                signed: None,
                                vendor: Some("Microsoft Corporation".into()),
                            }),
                            0,
                            &mut r,
                            &mut out,
                        );
                    }
                }
                Family::Lateral | Family::ApChain if first || r.chance(0.3) => {
                    for v in victims.iter().take(3) {
                        emit(
                            *v,
                            EventKind::Logon(Logon {
                                user: "svc_backup".into(),
                                logon_type: 3,
                                src_ip: attacker_ip.clone(),
                                success: true,
                            }),
                            0,
                            &mut r,
                            &mut out,
                        );
                        emit(
                            *v,
                            EventKind::ServiceInstall {
                                name: "updsvc".into(),
                                image: format!("{WRITABLE}u.exe"),
                                signed: None,
                            },
                            30,
                            &mut r,
                            &mut out,
                        );
                    }
                }
                Family::C2Beacon
                | Family::DnsTunnel
                | Family::Cryptomining
                | Family::FleetBeacon => {
                    if let Some(peer) = &ext_peer {
                        let sources: Vec<u32> = t
                            .attacker_device
                            .into_iter()
                            .chain(victims.iter().copied())
                            .take(if family == Family::FleetBeacon { 6 } else { 1 })
                            .collect();
                        for s in sources {
                            // jeden vzorek za cyklus (pravidelny odstup, agent agreguje)
                            let mut r2 = Rng::new(derive(
                                self.seed ^ 0xC2C2 ^ t.id as u64 ^ s as u64,
                                cycle as u64,
                            ));
                            if !self.alive(s, cycle) || self.compromised[s as usize] {
                                continue;
                            }
                            let host = self.host(s, ips, &mut r2, model);
                            let ts = t0 + 900 + r2.range(0, 20) as i64 + self.skew[s as usize];
                            out.push(mk(
                                host,
                                ts,
                                EventKind::NetConnect(Conn {
                                    image: Some(format!("{WRITABLE}svchosts.exe")),
                                    proto: "tcp".into(),
                                    src_ip: Some(ips[s as usize].clone()),
                                    src_port: None,
                                    dst_ip: peer.clone(),
                                    dst_port: 443,
                                    vendor: None,
                                    signed: None,
                                }),
                            ));
                        }
                    }
                }
                Family::SshBrute | Family::CredentialStuffing => {
                    for v in victims.iter().take(2) {
                        for k in 0..12 {
                            emit(
                                *v,
                                EventKind::Logon(Logon {
                                    user: format!("user{}", k % 4),
                                    logon_type: 0,
                                    src_ip: attacker_ip.clone(),
                                    success: false,
                                }),
                                k,
                                &mut r,
                                &mut out,
                            );
                        }
                    }
                }
                Family::Ransomware if first => {
                    for v in victims.iter().take(1) {
                        emit(
                            *v,
                            EventKind::ProcessCreate(Process {
                                image: format!("{WRITABLE}locker.exe"),
                                parent_image: Some("C:\\Windows\\explorer.exe".into()),
                                cmdline: "locker.exe".into(),
                                user: None,
                                signed: None,
                                vendor: None,
                            }),
                            0,
                            &mut r,
                            &mut out,
                        );
                        emit(
                            *v,
                            EventKind::Persistence {
                                mechanism: "registry_run".into(),
                                target: format!("HKCU\\Run\\x = {WRITABLE}locker.exe"),
                                image: Some(format!("{WRITABLE}locker.exe")),
                                signed: None,
                            },
                            5,
                            &mut r,
                            &mut out,
                        );
                    }
                }
                Family::Exfil | Family::InsiderHoarding if first => {
                    for v in victims.iter().take(1) {
                        emit(
                            *v,
                            EventKind::ProcessCreate(Process {
                                image: format!("{WRITABLE}7z.exe"),
                                parent_image: None,
                                cmdline: "7z.exe a data.7z".into(),
                                user: None,
                                signed: None,
                                vendor: None,
                            }),
                            0,
                            &mut r,
                            &mut out,
                        );
                    }
                }
                _ => {}
            }
        }
        // `ok`: kryci vzor ve VSECH cyklech (i pred utokem a bez ohledu na masku sveta)
        if self.world.agent == AgentMode::Ok {
            for t in truths.iter().filter(|t| matches!(t.kind, Kind::Attack(_))) {
                let ext = t
                    .target_external
                    .clone()
                    .or_else(|| t.attacker_external.clone());
                let attacker_ip = t.attacker_device.map(|d| ips[d as usize].clone());
                let peers: Vec<String> = ext.into_iter().chain(attacker_ip).collect();
                for d in t.victim_devices.iter().copied().chain(t.attacker_device) {
                    if !self.compromised[d as usize] || !self.alive(d, cycle) {
                        continue;
                    }
                    for p in &peers {
                        let mut r3 = Rng::new(derive(
                            self.seed ^ 0xC0DE ^ d as u64,
                            cycle as u64 + hash(p),
                        ));
                        let host = self.host(d, ips, &mut r3, model);
                        let ts = t0 + 700 + r3.range(0, 20) as i64 + self.skew[d as usize];
                        out.push(mk(
                            host,
                            ts,
                            EventKind::NetConnect(Conn {
                                image: Some(
                                    "C:\\Program Files\\Microsoft\\Edge\\msedge.exe".into(),
                                ),
                                proto: "tcp".into(),
                                src_ip: Some(ips[d as usize].clone()),
                                src_port: None,
                                dst_ip: p.clone(),
                                dst_port: 443,
                                vendor: Some("Microsoft Corporation".into()),
                                signed: Some(true),
                            }),
                        ));
                    }
                }
            }
        }
        // duplicity (at-least-once) a promichani poradi prijmu
        let mut dups = Vec::new();
        let mut r = Rng::new(derive(self.seed ^ 0xD0D0, cycle as u64));
        for e in &out {
            if r.chance(DUP_P) {
                dups.push(e.clone());
            }
        }
        out.extend(dups);
        let n = out.len();
        for i in (1..n).rev() {
            let j = r.range(0, i as u64) as usize;
            out.swap(i, j);
        }
        out
    }
}

fn hash(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325u64, |a, b| {
        (a ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    })
}
