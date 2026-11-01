//! Neškodné pravidelné a dlouhé provozy (krok 3, bod 2): protějšky, které musí snést
//! detektory periodicity (`beacon_periodic`), dlouhých a interaktivních spojení
//! (`long_lived_tunnel`, `interactive_session`), odchozího objemu
//! (`egress_volume_anomaly`) a nových hran (`pivot_chain`).
//!
//! Cirkularita (RQ5): parametry vzorů NESMÍ pocházet z prahů detektorů. Hodnoty jsou
//! výchozí hodnoty protokolů a běžných nástrojů z jejich dokumentace (tabulka
//! `SOURCES` a docs/diplomka/eval/impl-krok3.md, bod 2), ne z prahů behaviorální vrstvy.
//! Test `parameters_do_not_reference_detector_thresholds` hlídá, že tento modul na
//! prahy detektorů neodkazuje. Generátor je tedy nezávislý na tom, co detektor hledá:
//! vzor, který prahy náhodou nesplní, se tím nestane „snadným“.
//!
//! Každý vzor má vlastní náhodný proud (`derive(seed, id)`), takže zapnutí šumu nemění
//! existující provoz ani útoky (kontrafaktuál, krok 2A); `noise = 0` = beze změny světa.

use crate::soak::{
    netmodel::{NetworkModel, Role},
    rng::{Rng, derive},
};

/// Druh neškodného pravidelného provozu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RegularKind {
    /// Monitoring služeb: dotazy na služby serverů v pevném intervalu (vnitřní).
    MonitoringPoll,
    /// Agent SaaS monitoringu: odesílá metriky ven v pevném intervalu (flotila).
    MonitoringAgent,
    /// NTP: brána k veřejnému poolu (ven) a klienti k bráně (uvnitř).
    NtpSync,
    /// Rekurze DNS serveru ven (cache miss) k autoritativním serverům.
    DnsRecursion,
    /// Kontrola aktualizací (flotila) a občasné velké stažení.
    UpdateCheck,
    /// VPN keepalive (IKE NAT-T nebo WireGuard) k pevnému protějšku.
    VpnKeepalive,
    /// Správa přes bastion: admin -> jump (SSH), jump -> servery (řetěz A->B->C).
    BastionAdmin,
    /// Vzdálená podpora: interaktivní relace ven na relay.
    RemoteSupport,
    /// CI/CD: dotazování gitu venku a nasazení na servery (vějíř hran).
    CiCd,
    /// CDN a streaming: dlouhé toky s velkým stahováním, videohovor přes TURN.
    CdnStreaming,
    /// Noční záloha do cloudu (velký odchozí objem ve stejný čas).
    ScheduledBackup,
    /// Pravidelný skript (cron) volající API venku.
    ScriptPolling,
}

impl RegularKind {
    pub const ALL: [RegularKind; 12] = [
        RegularKind::MonitoringPoll,
        RegularKind::MonitoringAgent,
        RegularKind::NtpSync,
        RegularKind::DnsRecursion,
        RegularKind::UpdateCheck,
        RegularKind::VpnKeepalive,
        RegularKind::BastionAdmin,
        RegularKind::RemoteSupport,
        RegularKind::CiCd,
        RegularKind::CdnStreaming,
        RegularKind::ScheduledBackup,
        RegularKind::ScriptPolling,
    ];

    pub fn label(self) -> &'static str {
        match self {
            RegularKind::MonitoringPoll => "monitoring_poll",
            RegularKind::MonitoringAgent => "monitoring_agent",
            RegularKind::NtpSync => "ntp_sync",
            RegularKind::DnsRecursion => "dns_recursion",
            RegularKind::UpdateCheck => "update_check",
            RegularKind::VpnKeepalive => "vpn_keepalive",
            RegularKind::BastionAdmin => "bastion_admin",
            RegularKind::RemoteSupport => "remote_support",
            RegularKind::CiCd => "ci_cd",
            RegularKind::CdnStreaming => "cdn_streaming",
            RegularKind::ScheduledBackup => "scheduled_backup",
            RegularKind::ScriptPolling => "script_polling",
        }
    }
}

/// Zdroje hodnot parametrů (výchozí hodnoty z dokumentace protokolů a nástrojů).
pub const SOURCES: &[(&str, &str)] = &[
    (
        "monitoring_poll",
        "Kubernetes probe periodSeconds výchozí 10 s; Prometheus scrape_interval výchozí 1 min; \
         Nagios check_interval 5 × interval_length 60 s = 5 min",
    ),
    (
        "monitoring_agent",
        "Telegraf interval a flush_interval výchozí 10 s; Datadog Agent odesílá metriky každých 15 s",
    ),
    (
        "ntp_sync",
        "RFC 5905: minpoll 6 a maxpoll 10, tj. 64 až 1024 s; v ustáleném stavu maxpoll",
    ),
    (
        "dns_recursion",
        "Jung et al. 2002 (DNS performance and effectiveness of caching): úspěšnost cache 80 až 87 %",
    ),
    (
        "update_check",
        "Windows Update: frekvence detekce výchozí 22 h s náhodným posunem až 20 %; \
         apt-daily.timer 2× denně s RandomizedDelaySec 12 h",
    ),
    (
        "vpn_keepalive",
        "RFC 3948 §4: NAT-keepalive výchozí 20 s; wg(8): PersistentKeepalive doporučeno 25 s",
    ),
    (
        "bastion_admin",
        "Pracovní doba 8 až 17 h (kalendář generátoru); relace 10 až 90 min (volba autora, \
         nezávislá na prazích)",
    ),
    (
        "remote_support",
        "TeamViewer port TCP 5938, AnyDesk TCP 7070 (dokumentace výrobců); relace 15 až 60 min",
    ),
    (
        "ci_cd",
        "Argo CD timeout.reconciliation výchozí 180 s; Jenkins SCM polling `H/5 * * * *` = 5 min",
    ),
    (
        "cdn_streaming",
        "RFC 8489: STUN/TURN port 3478; video 3 až 8 Mbit/s (doporučení streamovacích služeb)",
    ),
    (
        "scheduled_backup",
        "Noční okno záloh 1 až 3 h místního času, objem 1 až 50 GB (volba autora)",
    ),
    (
        "script_polling",
        "cron: granularita minut, typické `*/5`, `*/15`, hodinově; start na celou minutu",
    ),
];

/// Cíl instance.
#[derive(Debug, Clone)]
pub enum Peer {
    Device(u32),
    External(String),
}

/// Jedna instance neškodného vzoru v síti.
#[derive(Debug, Clone)]
pub struct RegularInstance {
    pub id: u32,
    pub kind: RegularKind,
    pub src: u32,
    /// Cíle (u monitoringu a nasazení víc cílů, jinak jeden).
    pub peers: Vec<Peer>,
    pub proto: &'static str,
    pub port: u16,
    /// Perioda (s); 0 = událostní vzor (relace, stream, záloha).
    pub period_s: i64,
    /// Fáze periody (s).
    pub phase_s: i64,
    /// Relativní jitter periody (podíl).
    pub jitter: f64,
}

fn ext_ip(rng: &mut Rng, first: &[u64]) -> String {
    format!(
        "{}.{}.{}.{}",
        rng.pick(first),
        rng.range(1, 254),
        rng.range(1, 254),
        rng.range(1, 254)
    )
}

/// Počet instancí při šumu `noise` (stochastické zaokrouhlení, aspoň 0).
fn scaled(rng: &mut Rng, base: f64, noise: f64) -> usize {
    let x = (base * noise).max(0.0);
    let whole = x.floor();
    whole as usize + rng.chance(x - whole) as usize
}

/// Naplánuje instance pro síť. `noise` = násobek objemu (1, 10, 50); 0 = vypnuto.
pub fn plan(model: &NetworkModel, noise: f64) -> Vec<RegularInstance> {
    if noise <= 0.0 {
        return Vec::new();
    }
    let mut rng = Rng::new(derive(model.seed, 0xBE91_0A2E));
    let devices = &model.devices;
    let servers: Vec<u32> = devices
        .iter()
        .filter(|d| d.role.is_server() && d.id != model.gateway && !d.services.is_empty())
        .map(|d| d.id)
        .collect();
    let clients: Vec<u32> = devices
        .iter()
        .filter(|d| {
            matches!(
                d.role,
                Role::Workstation | Role::Mobile | Role::Medical | Role::Hmi
            )
        })
        .map(|d| d.id)
        .collect();
    let by_role = |role: Role| -> Option<u32> {
        devices
            .iter()
            .find(|d| d.role == role && d.id != model.gateway)
            .map(|d| d.id)
    };
    let mut out: Vec<RegularInstance> = Vec::new();
    let push = |out: &mut Vec<RegularInstance>,
                kind: RegularKind,
                src: u32,
                peers: Vec<Peer>,
                proto: &'static str,
                port: u16,
                period_s: i64,
                phase_s: i64,
                jitter: f64| {
        let id = out.len() as u32;
        out.push(RegularInstance {
            id,
            kind,
            src,
            peers,
            proto,
            port,
            period_s,
            phase_s,
            jitter,
        });
    };
    let pick_server =
        |rng: &mut Rng| -> Option<u32> { (!servers.is_empty()).then(|| *rng.pick(&servers)) };
    let pick_client =
        |rng: &mut Rng| -> Option<u32> { (!clients.is_empty()).then(|| *rng.pick(&clients)) };

    // monitoring sluzeb: poller kontroluje sluzby az 40 serveru
    for _ in 0..scaled(&mut rng, 1.0, noise) {
        let Some(poller) = pick_server(&mut rng) else {
            break;
        };
        let mut targets: Vec<u32> = servers.iter().copied().filter(|s| *s != poller).collect();
        targets.truncate(40);
        if targets.is_empty() {
            continue;
        }
        let period = *rng.pick(&[10i64, 60, 300]);
        let phase = rng.range(0, period as u64 - 1) as i64;
        push(
            &mut out,
            RegularKind::MonitoringPoll,
            poller,
            targets.into_iter().map(Peer::Device).collect(),
            "tcp",
            0, // port = prvni sluzba cile
            period,
            phase,
            0.01,
        );
    }
    // agent SaaS monitoringu: ~20 % serveru na jeden spolecny endpoint
    let agent_endpoint = ext_ip(&mut rng, &[3, 18, 35, 54]);
    for _ in 0..scaled(&mut rng, servers.len() as f64 * 0.2, noise).min(servers.len() * 3) {
        let Some(server) = pick_server(&mut rng) else {
            break;
        };
        let period = *rng.pick(&[10i64, 15, 60]);
        push(
            &mut out,
            RegularKind::MonitoringAgent,
            server,
            vec![Peer::External(agent_endpoint.clone())],
            "tcp",
            443,
            period,
            rng.range(0, period as u64 - 1) as i64,
            0.02,
        );
    }
    // NTP: brana k poolu (ven), klienti k brane
    for _ in 0..scaled(&mut rng, 2.0, noise) {
        let pool = ext_ip(&mut rng, &[129, 162, 192, 216]);
        push(
            &mut out,
            RegularKind::NtpSync,
            model.gateway,
            vec![Peer::External(pool)],
            "udp",
            123,
            1024,
            rng.range(0, 1023) as i64,
            0.05,
        );
    }
    for _ in 0..scaled(&mut rng, clients.len() as f64 * 0.3, noise).min(clients.len() * 3) {
        let Some(client) = pick_client(&mut rng) else {
            break;
        };
        let poll = 1i64 << rng.range(6, 10);
        push(
            &mut out,
            RegularKind::NtpSync,
            client,
            vec![Peer::Device(model.gateway)],
            "udp",
            123,
            poll,
            rng.range(0, poll as u64 - 1) as i64,
            0.05,
        );
    }
    // rekurze DNS: jedna instance (intenzita = noise), cile = koreny a autoritativni
    {
        let mut roots: Vec<Peer> = Vec::with_capacity(53);
        for i in 0..53 {
            let first: &[u64] = if i < 13 {
                &[192, 198, 199, 202]
            } else {
                &[8, 13, 23, 104, 151]
            };
            roots.push(Peer::External(ext_ip(&mut rng, first)));
        }
        push(
            &mut out,
            RegularKind::DnsRecursion,
            model.dns,
            roots,
            "udp",
            53,
            0,
            0,
            noise,
        );
    }
    // kontrola aktualizaci: ~50 % klientu a serveru, perioda 22 h nebo 12 h
    let update_cdn = ext_ip(&mut rng, &[13, 20, 23, 40, 104]);
    let fleet: Vec<u32> = clients.iter().chain(servers.iter()).copied().collect();
    for _ in 0..scaled(&mut rng, fleet.len() as f64 * 0.5, noise).min(fleet.len() * 3) {
        let host = *rng.pick(&fleet);
        let period = if rng.chance(0.6) {
            22 * 3600
        } else {
            12 * 3600
        };
        push(
            &mut out,
            RegularKind::UpdateCheck,
            host,
            vec![Peer::External(update_cdn.clone())],
            "tcp",
            443,
            period,
            rng.range(0, period as u64 - 1) as i64,
            0.2,
        );
    }
    // VPN keepalive
    for _ in 0..scaled(&mut rng, 1.0, noise) {
        let src = by_role(Role::Vpn).unwrap_or(model.gateway);
        let (port, period) = if rng.chance(0.5) {
            (4500u16, 20i64)
        } else {
            (51820, 25)
        };
        push(
            &mut out,
            RegularKind::VpnKeepalive,
            src,
            vec![Peer::External(ext_ip(&mut rng, &[31, 62, 80, 85, 94]))],
            "udp",
            port,
            period,
            rng.range(0, period as u64 - 1) as i64,
            0.01,
        );
    }
    // sprava pres bastion: admin -> jump -> pevna sada serveru
    for _ in 0..scaled(&mut rng, 1.0, noise) {
        let (Some(admin), Some(jump)) = (
            pick_client(&mut rng),
            by_role(Role::Jump).or_else(|| pick_server(&mut rng)),
        ) else {
            break;
        };
        let mut managed: Vec<Peer> = Vec::new();
        for _ in 0..rng.range(2, 6) {
            if let Some(s) = pick_server(&mut rng).filter(|s| *s != jump) {
                managed.push(Peer::Device(s));
            }
        }
        let mut peers = vec![Peer::Device(jump)];
        peers.extend(managed);
        push(
            &mut out,
            RegularKind::BastionAdmin,
            admin,
            peers,
            "tcp",
            22,
            0,
            0,
            0.0,
        );
    }
    // vzdalena podpora: relay venku
    for _ in 0..scaled(&mut rng, 1.0, noise) {
        let Some(client) = pick_client(&mut rng) else {
            break;
        };
        let port = if rng.chance(0.5) { 5938 } else { 7070 };
        push(
            &mut out,
            RegularKind::RemoteSupport,
            client,
            vec![Peer::External(ext_ip(&mut rng, &[37, 46, 92, 188]))],
            "tcp",
            port,
            0,
            0,
            0.0,
        );
    }
    // CI/CD: build server se pta gitu venku a nasazuje na servery
    for _ in 0..scaled(&mut rng, 1.0, noise) {
        let Some(build) = by_role(Role::Container).or_else(|| pick_server(&mut rng)) else {
            break;
        };
        let git = ext_ip(&mut rng, &[140, 52, 34]);
        let period = *rng.pick(&[180i64, 300]);
        let mut peers = vec![Peer::External(git)];
        let mut targets: Vec<u32> = servers.iter().copied().filter(|s| *s != build).collect();
        targets.truncate(rng.range(3, 12) as usize);
        peers.extend(targets.into_iter().map(Peer::Device));
        push(
            &mut out,
            RegularKind::CiCd,
            build,
            peers,
            "tcp",
            443,
            period,
            rng.range(0, period as u64 - 1) as i64,
            0.01,
        );
    }
    // CDN a streaming: klienti, udalostni
    let cdn = ext_ip(&mut rng, &[23, 104, 151, 199]);
    for _ in
        0..scaled(&mut rng, (clients.len() as f64 * 0.05).max(1.0), noise).min(clients.len() * 3)
    {
        let Some(client) = pick_client(&mut rng) else {
            break;
        };
        let (proto, port, peer) = if rng.chance(0.7) {
            ("tcp", 443, cdn.clone())
        } else {
            ("udp", 3478, ext_ip(&mut rng, &[52, 13, 20]))
        };
        push(
            &mut out,
            RegularKind::CdnStreaming,
            client,
            vec![Peer::External(peer)],
            proto,
            port,
            0,
            0,
            0.0,
        );
    }
    // nocni zaloha do cloudu
    for _ in 0..scaled(&mut rng, 1.0, noise) {
        let Some(server) = by_role(Role::FileServer).or_else(|| pick_server(&mut rng)) else {
            break;
        };
        push(
            &mut out,
            RegularKind::ScheduledBackup,
            server,
            vec![Peer::External(ext_ip(&mut rng, &[3, 52, 54]))],
            "tcp",
            443,
            86_400,
            (1 + rng.range(0, 2) as i64) * 3600 - model.tz_hours * 3600,
            0.0,
        );
    }
    // pravidelny skript (cron) na API venku
    for _ in 0..scaled(&mut rng, 2.0, noise) {
        let Some(server) = pick_server(&mut rng) else {
            break;
        };
        let period = *rng.pick(&[300i64, 900, 3600]);
        push(
            &mut out,
            RegularKind::ScriptPolling,
            server,
            vec![Peer::External(ext_ip(&mut rng, &[34, 35, 104, 172]))],
            "tcp",
            443,
            period,
            (rng.range(0, (period / 60) as u64 - 1) * 60) as i64,
            0.0,
        );
    }
    out
}

/// Jeden tok neškodného vzoru (bez vazby na generátor provozu).
#[derive(Debug, Clone)]
pub struct RegularFlow {
    pub at: i64,
    pub src: u32,
    pub dst: Peer,
    pub proto: &'static str,
    pub port: u16,
    pub duration_s: f64,
    pub orig_bytes: u64,
    pub resp_bytes: u64,
}

/// Toky instance v cyklu `[t0, t0 + cycle_secs)`. `hour_of` = místní hodina,
/// `workday` = pracovní den; `stream_seed` = vlastní proud cyklu.
#[allow(clippy::too_many_arguments)]
pub fn emit(
    inst: &RegularInstance,
    model: &NetworkModel,
    t0: i64,
    cycle_secs: i64,
    hour_of: impl Fn(i64) -> i64,
    workday: bool,
    stream_seed: u64,
    out: &mut Vec<RegularFlow>,
) {
    let mut rng = Rng::new(derive(stream_seed, inst.id as u64));
    let t1 = t0 + cycle_secs;
    let flow = |out: &mut Vec<RegularFlow>,
                at: i64,
                dst: &Peer,
                port: u16,
                duration_s: f64,
                orig_bytes: u64,
                resp_bytes: u64| {
        out.push(RegularFlow {
            at: at.clamp(t0, t1 - 1),
            src: inst.src,
            dst: dst.clone(),
            proto: inst.proto,
            port,
            duration_s,
            orig_bytes,
            resp_bytes,
        });
    };
    // casy periodickych vyskytu v cyklu (s jitterem)
    let ticks = |rng: &mut Rng, period: i64, phase: i64, jitter: f64| -> Vec<i64> {
        let first = t0 + (phase - t0).rem_euclid(period);
        let mut at = first;
        let mut v = Vec::new();
        while at < t1 {
            let j = if jitter > 0.0 {
                (rng.range_f(-jitter, jitter) * period as f64) as i64
            } else {
                rng.range(0, 2) as i64 // start skriptu: 0 az 2 s
            };
            v.push(at + j);
            at += period;
        }
        v
    };
    let first_port = |peer: &Peer| -> Option<(u16, &'static str)> {
        match peer {
            Peer::Device(d) => model.devices[*d as usize]
                .services
                .first()
                .map(|s| (s.port, s.proto)),
            Peer::External(_) => None,
        }
    };
    let working = workday && (8..=17).contains(&hour_of(t0));
    match inst.kind {
        RegularKind::MonitoringPoll => {
            for at in ticks(&mut rng, inst.period_s, inst.phase_s, inst.jitter) {
                for peer in &inst.peers {
                    if let Some((port, _)) = first_port(peer) {
                        let rb = rng.lognormal(2_000.0, 0.6) as u64;
                        flow(out, at, peer, port, 0.02, 180, rb);
                    }
                }
            }
        }
        RegularKind::MonitoringAgent
        | RegularKind::VpnKeepalive
        | RegularKind::ScriptPolling
        | RegularKind::UpdateCheck => {
            let peer = &inst.peers[0];
            for at in ticks(&mut rng, inst.period_s, inst.phase_s, inst.jitter) {
                let (dur, ob, rb) = match inst.kind {
                    RegularKind::MonitoringAgent => (
                        rng.range_f(0.05, 0.4),
                        rng.lognormal(3_000.0, 0.5) as u64,
                        rng.range(200, 600),
                    ),
                    RegularKind::VpnKeepalive => (0.0, 1, 0),
                    RegularKind::ScriptPolling => (
                        rng.range_f(0.2, 2.0),
                        rng.range(300, 1200),
                        rng.lognormal(8_000.0, 1.0) as u64,
                    ),
                    _ => {
                        // kontrola; obcas (1 z 7) stazeni aktualizace
                        if rng.chance(1.0 / 7.0) {
                            (
                                rng.range_f(30.0, 900.0),
                                rng.range(20_000, 200_000),
                                rng.lognormal(2.0e8, 1.0) as u64,
                            )
                        } else {
                            (
                                rng.range_f(0.3, 3.0),
                                rng.range(800, 3000),
                                rng.range(2000, 30000),
                            )
                        }
                    }
                };
                flow(out, at, peer, inst.port, dur, ob, rb);
            }
        }
        RegularKind::NtpSync => {
            for at in ticks(&mut rng, inst.period_s, inst.phase_s, inst.jitter) {
                flow(out, at, &inst.peers[0], 123, 0.02, 48, 48);
            }
        }
        RegularKind::DnsRecursion => {
            // cache miss ~15 % dotazu klientu (Jung et al. 2002); intenzita = noise
            let clients_rate: f64 = model
                .devices
                .iter()
                .filter(|d| !d.role.is_server() && d.up)
                .map(|d| d.rate * 1.2)
                .sum::<f64>()
                * cycle_secs as f64
                / 3600.0
                * model.flow_sampling();
            let n = rng.poisson(clients_rate * 0.15 * inst.jitter.min(50.0));
            for _ in 0..n.min(20_000) {
                let peer = rng.pick(&inst.peers).clone();
                let at = t0 + rng.range(0, cycle_secs as u64 - 1) as i64;
                flow(
                    out,
                    at,
                    &peer,
                    53,
                    0.03,
                    rng.range(40, 90),
                    rng.range(80, 600),
                );
            }
        }
        RegularKind::BastionAdmin => {
            if !working || !rng.chance(0.25) {
                return;
            }
            let jump = &inst.peers[0];
            let start = t0 + rng.range(0, cycle_secs as u64 / 2) as i64;
            let dur = rng.range_f(600.0, 5400.0);
            flow(
                out,
                start,
                jump,
                22,
                dur,
                rng.lognormal(60_000.0, 0.8) as u64,
                rng.lognormal(400_000.0, 0.8) as u64,
            );
            let managed = &inst.peers[1..];
            if managed.is_empty() {
                return;
            }
            for _ in 0..rng.range(1, 3.min(managed.len() as u64)) {
                let target = rng.pick(managed).clone();
                let at = start + rng.range(30, 600) as i64;
                // druhy hop vychazi z jumpu (retez admin -> jump -> server)
                let Peer::Device(jump_id) = jump else {
                    continue;
                };
                out.push(RegularFlow {
                    at: at.clamp(t0, t1 - 1),
                    src: *jump_id,
                    dst: target,
                    proto: "tcp",
                    port: 22,
                    duration_s: dur * rng.range_f(0.2, 0.8),
                    orig_bytes: rng.lognormal(40_000.0, 0.8) as u64,
                    resp_bytes: rng.lognormal(250_000.0, 0.8) as u64,
                });
            }
        }
        RegularKind::RemoteSupport => {
            // ~2 relace tydne v pracovni dobe (odhad volby autora)
            if !working || !rng.chance(2.0 / (5.0 * 20.0)) {
                return;
            }
            let at = t0 + rng.range(0, cycle_secs as u64 - 1) as i64;
            flow(
                out,
                at,
                &inst.peers[0],
                inst.port,
                rng.range_f(900.0, 3600.0),
                rng.lognormal(3.0e6, 0.7) as u64,
                rng.lognormal(4.0e7, 0.7) as u64,
            );
        }
        RegularKind::CiCd => {
            let git = &inst.peers[0];
            for at in ticks(&mut rng, inst.period_s, inst.phase_s, inst.jitter) {
                flow(
                    out,
                    at,
                    git,
                    443,
                    rng.range_f(0.2, 1.5),
                    rng.range(800, 2500),
                    rng.range(1500, 9000),
                );
            }
            // nasazeni ~3x denne v pracovni dobe na celou sadu serveru
            if working && rng.chance(3.0 / 20.0) {
                let at = t0 + rng.range(0, cycle_secs as u64 - 1) as i64;
                for peer in &inst.peers[1..] {
                    flow(
                        out,
                        at + rng.range(0, 60) as i64,
                        peer,
                        22,
                        rng.range_f(5.0, 120.0),
                        rng.lognormal(5.0e6, 1.0) as u64,
                        rng.range(5_000, 50_000),
                    );
                }
            }
        }
        RegularKind::CdnStreaming => {
            let hour = hour_of(t0);
            let active = if (18..=23).contains(&hour) || working {
                0.3
            } else {
                0.03
            };
            if !rng.chance(active) {
                return;
            }
            let at = t0 + rng.range(0, cycle_secs as u64 - 1) as i64;
            let dur = rng.range_f(1200.0, 7200.0);
            let (ob, rb) = if inst.proto == "udp" {
                let b = (dur * rng.range_f(1.0e5, 2.5e5)) as u64; // 0,8 az 2 Mbit/s oba smery
                (b, b)
            } else {
                (
                    (dur * 2.0e3) as u64,
                    (dur * rng.range_f(3.75e5, 1.0e6)) as u64,
                )
            };
            flow(out, at, &inst.peers[0], inst.port, dur, ob, rb);
        }
        RegularKind::ScheduledBackup => {
            for at in ticks(&mut rng, inst.period_s, inst.phase_s, 0.0) {
                let gb = rng.lognormal(8.0, 0.8).clamp(1.0, 50.0);
                flow(
                    out,
                    at + rng.range(0, 120) as i64,
                    &inst.peers[0],
                    443,
                    rng.range_f(1800.0, 7200.0),
                    (gb * 1.0e9) as u64,
                    rng.range(100_000, 2_000_000),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noise_zero_plans_nothing_and_counts_scale_with_noise() {
        let model = NetworkModel::generate(20261102, 7);
        assert!(plan(&model, 0.0).is_empty());
        let one = plan(&model, 1.0).len();
        let ten = plan(&model, 10.0).len();
        let fifty = plan(&model, 50.0).len();
        assert!(one > 0 && ten > one && fifty > ten, "{one} {ten} {fifty}");
    }

    #[test]
    fn periodic_patterns_keep_phase_across_cycles() {
        let model = NetworkModel::generate(20261102, 11);
        let instances = plan(&model, 1.0);
        let ntp = instances
            .iter()
            .find(|i| i.kind == RegularKind::NtpSync && i.src == model.gateway)
            .expect("NTP brany");
        let mut times = Vec::new();
        for cycle in 0..8i64 {
            let mut out = Vec::new();
            emit(
                ntp,
                &model,
                cycle * 1800,
                1800,
                |_| 12,
                true,
                cycle as u64,
                &mut out,
            );
            times.extend(out.iter().map(|f| f.at));
        }
        let gaps: Vec<i64> = times.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(!gaps.is_empty());
        // perioda 1024 s s jitterem 5 %: kazda mezera je v 1024 ± 2 × 52 s
        assert!(gaps.iter().all(|g| (g - 1024).abs() <= 104), "{gaps:?}");
    }

    #[test]
    fn every_kind_has_a_documented_source() {
        for kind in RegularKind::ALL {
            assert!(
                SOURCES.iter().any(|(label, _)| *label == kind.label()),
                "{} bez zdroje hodnot",
                kind.label()
            );
        }
    }

    /// RQ5 cirkularita: modul vzoru nesmí číst prahy detektorů.
    #[test]
    fn parameters_do_not_reference_detector_thresholds() {
        let source = include_str!("benign_regular.rs");
        let code = source.split("#[cfg(test)]").next().expect("kod pred testy");
        for forbidden in ["behavior::", "Thresholds", "anomaly_v3", "thresholds::"] {
            assert!(!code.contains(forbidden), "odkaz na prahy: {forbidden}");
        }
    }
}
