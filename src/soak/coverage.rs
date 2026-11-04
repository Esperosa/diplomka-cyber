//! Krok 5: svet pokryti (`--coverage tuning|full`, predregistrace
//! `docs/diplomka/eval/impl-krok5.md`, sekce A2).
//!
//! Nic noveho se nevymysli: existujici rodiny utoku se parametricky meni (intenzita,
//! tempo, rozptyl casu, pocet zdroju, doba, objem, denni doba, michani s provozem),
//! skladaji se do kampani ze stavajicich emitoru a pribyvaji provozni poruchy slozene
//! ze stavajicich vzoru toku. Vse ma vlastni nahodny proud odvozeny ze seedu site, takze
//! vychozi svet (`--coverage off`) zustava bit po bitu stejny.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    passive::ConnectionObservation,
    soak::{
        netmodel::{NetworkModel, Role},
        rng::{Rng, derive, mix},
        traffic::{
            CYCLE_SECS, Family, Kind, Lookalike, OPS_KINDS, Pools, Telemetry, Truth, build_benign,
            ids_share, len_range, public_ip, ts,
        },
    },
};

/// Rezim sveta pokryti.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageMode {
    /// Vychozi svet beze zmeny.
    #[default]
    Off,
    /// Ladici svet: bez drzenych urovni os, poruch a kampani.
    Tuning,
    /// Drzeny svet: vse vcetne drzenych urovni, poruch a kampani.
    Full,
}

impl CoverageMode {
    pub fn on(self) -> bool {
        self != CoverageMode::Off
    }
}

impl std::str::FromStr for CoverageMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "off" => Ok(CoverageMode::Off),
            "tuning" => Ok(CoverageMode::Tuning),
            "full" => Ok(CoverageMode::Full),
            other => Err(format!(
                "neznamy svet pokryti {other} (off | tuning | full)"
            )),
        }
    }
}

/// Parametricka variace jednoho utoku (osy skrytosti z A2).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Variation {
    /// Nasobek poctu toku za cas (delka utoku x 1/tempo).
    pub tempo: f64,
    /// Posun casu toku o +- jitter x 600 s.
    pub jitter: f64,
    /// Pocet adres, mezi ktere se toky utocnika rozdeli.
    pub sources: u8,
    /// Nasobek delky utoku.
    pub duration: f64,
    /// Nasobek bajtu toku.
    pub volume: f64,
    pub off_hours: bool,
    pub blend: bool,
}

impl Default for Variation {
    fn default() -> Self {
        Self {
            tempo: 1.0,
            jitter: 0.0,
            sources: 1,
            duration: 1.0,
            volume: 1.0,
            off_hours: false,
            blend: false,
        }
    }
}

impl Variation {
    /// Index skrytosti S v [0, 1] (A2): prumer sesti slozek, vychozi i hlucnejsi = 0.
    pub fn stealth(&self, intensity: f64) -> f64 {
        let log2_down = |x: f64| (-x.max(1e-9).log2() / 2.0).clamp(0.0, 1.0);
        let parts = [
            (1.0 - intensity).clamp(0.0, 1.0),
            log2_down(self.tempo),
            (self.jitter / 0.5).clamp(0.0, 1.0),
            (self.sources.max(1) as f64).log10().clamp(0.0, 1.0),
            log2_down(self.volume),
            if self.blend { 1.0 } else { 0.0 },
        ];
        parts.iter().sum::<f64>() / parts.len() as f64
    }
}

/// Kampan: id, poradi faze a sablona (index do `TEMPLATES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignTag {
    pub id: u32,
    pub stage: u8,
    pub template: u8,
}

/// Dalsi stav pravdy ve svete pokryti (vychozi = prazdne, nic nemeni).
#[derive(Debug, Clone, Default)]
pub struct TruthCoverage {
    pub variation: Option<Variation>,
    pub campaign: Option<CampaignTag>,
    /// Dalsi vnitrni zdroje utoku (rozlozeni na vice adres).
    pub extra_devices: Vec<u32>,
    /// Dalsi vnejsi adresy (zdroje utoku, blok cloudu, stara adresa serveru).
    pub extra_external: Vec<String>,
    /// Parametr poruchy (perioda kolisani, podsit vypadku).
    pub param: u32,
    /// Akumulator tempa (deterministicke rideni poctu kopii toku).
    pub acc: f64,
}

/// Sablony kampani (A2): rodiny v poradi, drzena = obsahuje drzenou rodinu.
pub const TEMPLATES: [(&str, &[Family]); 6] = [
    (
        "K-T1",
        &[
            Family::PortScanHorizontal,
            Family::SshBrute,
            Family::Lateral,
            Family::Exfil,
        ],
    ),
    (
        "K-T2",
        &[Family::CredentialStuffing, Family::C2Beacon, Family::Exfil],
    ),
    (
        "K-T3",
        &[
            Family::Exploit,
            Family::C2Beacon,
            Family::Lateral,
            Family::DnsTunnel,
        ],
    ),
    (
        "K-H1",
        &[Family::WebExploit, Family::C2Beacon, Family::Ransomware],
    ),
    (
        "K-H2",
        &[Family::SlowScan, Family::Exploit, Family::Cryptomining],
    ),
    (
        "K-H3",
        &[
            Family::SlowScan,
            Family::WebExploit,
            Family::Lateral,
            Family::Exfil,
        ],
    ),
];

pub fn template_held(template: usize) -> bool {
    TEMPLATES[template].1.iter().any(|f| f.held_out())
}

/// Transformace toku utoku podle variace (volano z `traffic::push`). Vraci 0 az N kopii.
/// Tempo ridi akumulator (kazdy k-ty tok pri zpomaleni, k kopii pri zrychleni s
/// casovou osou cyklu stlacenou k-krat), takze periodicita zustane zachovana.
pub(crate) fn vary(
    truth: &mut Truth,
    observation: ConnectionObservation,
    t0: i64,
    ips: &[String],
) -> Vec<ConnectionObservation> {
    let Some(v) = truth.cov.variation else {
        return vec![observation];
    };
    truth.cov.acc += v.tempo;
    let copies = truth.cov.acc.floor().max(0.0) as i64;
    truth.cov.acc -= copies as f64;
    if copies == 0 {
        return Vec::new();
    }
    let attacker: Option<String> = truth
        .attacker_device
        .map(|d| ips[d as usize].clone())
        .or_else(|| truth.attacker_external.clone());
    let at = observation.timestamp.timestamp();
    let offset = (at - t0).clamp(0, CYCLE_SECS - 1);
    let print = mix(at as u64
        ^ ((observation.src_port.unwrap_or(0) as u64) << 16)
        ^ ((observation.dst_port.unwrap_or(0) as u64) << 40)
        ^ ((truth.id as u64) << 48));
    let extra: Vec<String> = truth
        .cov
        .extra_devices
        .iter()
        .map(|d| ips[*d as usize].clone())
        .chain(truth.cov.extra_external.iter().cloned())
        .collect();
    let mut result = Vec::with_capacity(copies as usize);
    for j in 0..copies {
        let h = derive(print, j as u64);
        let mut copy = observation.clone();
        let mut when = if copies > 1 {
            t0 + offset / copies + j * CYCLE_SECS / copies
        } else {
            at
        };
        if v.jitter > 0.0 {
            let unit = (h >> 11) as f64 / (1u64 << 53) as f64;
            when += ((unit * 2.0 - 1.0) * v.jitter * 600.0) as i64;
            when = when.clamp(t0, t0 + CYCLE_SECS - 1);
        }
        if when != at {
            copy.timestamp = ts(when);
        }
        if v.volume != 1.0 {
            let scale = |b: Option<u64>| b.map(|x| ((x as f64) * v.volume).round() as u64);
            copy.orig_bytes = scale(copy.orig_bytes);
            copy.resp_bytes = scale(copy.resp_bytes);
            copy.total_bytes = match (copy.orig_bytes, copy.resp_bytes) {
                (Some(a), Some(b)) => Some(a + b),
                (a, b) => a.or(b),
            };
        }
        if !extra.is_empty() && attacker.is_some() && copy.src_ip.as_deref() == attacker.as_deref()
        {
            let k = (mix(h ^ 0x5_0C) % (extra.len() as u64 + 1)) as usize;
            if k > 0 {
                copy.src_ip = Some(extra[k - 1].clone());
            }
        }
        result.push(copy);
    }
    result
}

fn pick_level<T: Copy>(rng: &mut Rng, default: T, others: &[T]) -> T {
    if others.is_empty() || rng.chance(0.4) {
        default
    } else {
        *rng.pick(others)
    }
}

fn base_truth(id: u32, kind: Kind, start: u32, end: u32, intensity: f64) -> Truth {
    Truth {
        id,
        kind,
        start_cycle: start,
        end_cycle: end,
        intensity,
        attacker_device: None,
        attacker_external: None,
        victim_devices: Vec::new(),
        target_external: None,
        ids_visible: false,
        touched_ips: BTreeSet::new(),
        cycle_targets: Default::default(),
        cycle_sources: Default::default(),
        flows_emitted: 0,
        flows_blocked: 0,
        first_emit_cycle: None,
        blocked_at_cycle: None,
        cov: Default::default(),
    }
}

/// Doplni plan epizody o svet pokryti: kampane, variace utoku, nove poruchy a souběhy.
/// Pri `Off` nedela nic. Vlastni proud, vychozi plan se nemeni.
pub fn plan_coverage(
    model: &NetworkModel,
    truths: &mut Vec<Truth>,
    hours: u32,
    telemetry: &Telemetry,
    mode: CoverageMode,
) {
    if !mode.on() {
        return;
    }
    let full = mode == CoverageMode::Full;
    let mut rng = Rng::new(derive(model.seed, 0xC0E5_5005));
    let cycles = hours * 2;
    let days = hours as f64 / 24.0;
    let size_scale = (model.devices.len() as f64 / 60.0)
        .max(1.0)
        .powf(0.45)
        .min(4.0);
    let pools = Pools::new(model);
    let mut dormant_cursor = truths
        .iter()
        .filter(|t| matches!(t.kind, Kind::Benign(Lookalike::Onboarding)))
        .count();

    // --- kampane ze stavajicich rodin se sdilenym utocnikem ---
    let templates: Vec<usize> = (0..TEMPLATES.len())
        .filter(|t| full || !template_held(*t))
        .collect();
    let campaigns = rng.poisson(0.3 * days);
    for cid in 0..campaigns as u32 {
        let template = *rng.pick(&templates);
        plan_campaign(
            model, &pools, truths, &mut rng, telemetry, cycles, cid, template,
        );
    }

    // --- variace vsech utoku (vcetne fazi kampani) ---
    let busy: Vec<u32> = {
        let mut clients: Vec<(f64, u32)> = pools
            .clients
            .iter()
            .map(|d| (model.devices[*d as usize].rate, *d))
            .collect();
        clients.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
        let top = (clients.len() / 5).max(1).min(clients.len());
        clients.into_iter().take(top).map(|(_, d)| d).collect()
    };
    let tempos: &[f64] = if full {
        &[0.25, 0.5, 2.0, 4.0, 8.0]
    } else {
        &[0.5, 2.0, 4.0]
    };
    let jitters: &[f64] = if full {
        &[0.15, 0.3, 0.5]
    } else {
        &[0.15, 0.3]
    };
    let sources: &[u8] = if full { &[3, 10] } else { &[3] };
    let mut blended_starts: Vec<u32> = Vec::new();
    for truth in truths.iter_mut() {
        let Kind::Attack(family) = truth.kind else {
            continue;
        };
        let stage = truth.cov.campaign.is_some();
        let v = Variation {
            tempo: pick_level(&mut rng, 1.0, tempos),
            jitter: pick_level(&mut rng, 0.0, jitters),
            sources: pick_level(&mut rng, 1, sources),
            duration: pick_level(&mut rng, 1.0, &[0.5, 2.0, 4.0]),
            volume: pick_level(&mut rng, 1.0, &[0.25, 0.5, 2.0]),
            off_hours: rng.chance(0.3) && !stage,
            blend: rng.chance(0.3),
        };
        let intensity = if full {
            rng.range_f(0.05, 1.0)
        } else {
            rng.range_f(0.10, 1.0)
        };
        truth.intensity = intensity;
        let len = truth.end_cycle - truth.start_cycle + 1;
        let len = ((len as f64 * v.duration / v.tempo).round() as u32).clamp(1, cycles.max(1));
        if v.off_hours {
            let day = rng.range(0, (hours as u64 / 24).max(1) - 1) as i64;
            let hour = rng.range(0, 5) as i64;
            let secs = -(model.tz_hours * 3600) + day * 86400 + hour * 3600;
            let secs = secs.rem_euclid(86400 * (hours as i64 / 24).max(1));
            truth.start_cycle = ((secs / CYCLE_SECS) as u32).min(cycles - 1);
        }
        truth.end_cycle = (truth.start_cycle + len - 1).min(cycles - 1);
        if v.sources > 1 {
            let extra = v.sources as usize - 1;
            if truth.attacker_device.is_some() {
                let attacker = truth.attacker_device;
                let pool: Vec<u32> = pools
                    .clients
                    .iter()
                    .copied()
                    .filter(|d| Some(*d) != attacker)
                    .collect();
                for pick in rng.sample_distinct(pool.len(), extra.min(pool.len())) {
                    truth.cov.extra_devices.push(pool[pick]);
                }
            } else if truth.attacker_external.is_some() {
                for _ in 0..extra {
                    truth.cov.extra_external.push(public_ip(&mut rng));
                }
            }
        }
        if v.blend {
            if truth.attacker_device.is_some() && !stage && family != Family::Exfil {
                truth.attacker_device = Some(*rng.pick(&busy));
            }
            blended_starts.push(truth.start_cycle);
        }
        truth.cov.variation = Some(v);
    }
    for start in blended_starts {
        let which = *rng.pick(&[
            Lookalike::Backup,
            Lookalike::SoftwareUpdate,
            Lookalike::FlashCrowd,
        ]);
        build_benign(
            model,
            &pools,
            hours,
            truths,
            &mut rng,
            which,
            Some(start),
            &mut dormant_cursor,
        );
    }

    // --- nove provozni poruchy ---
    let kinds: Vec<Lookalike> = Lookalike::COVERAGE
        .iter()
        .copied()
        .filter(|k| full || !k.held_out())
        .collect();
    let faults = rng.poisson(0.9 * days * size_scale.sqrt());
    for _ in 0..faults {
        let which = *rng.pick(&kinds);
        build_fault(model, &pools, truths, &mut rng, cycles, which, None);
    }

    // --- soubehy utoku s provozni poruchou (vcetne slepoty senzoru) ---
    let sensor: Vec<Lookalike> = OPS_KINDS
        .iter()
        .copied()
        .filter(|k| k.is_sensor())
        .collect();
    let other: Vec<Lookalike> = OPS_KINDS
        .iter()
        .copied()
        .filter(|k| !k.is_sensor())
        .chain(kinds.iter().copied())
        .collect();
    let starts: Vec<u32> = truths
        .iter()
        .filter(|t| matches!(t.kind, Kind::Attack(_)))
        .map(|t| t.start_cycle)
        .collect();
    for start in starts {
        if !rng.chance(0.25) {
            continue;
        }
        let which = if rng.chance(1.0 / 3.0) {
            *rng.pick(&sensor)
        } else {
            *rng.pick(&other)
        };
        if Lookalike::COVERAGE.contains(&which) {
            build_fault(model, &pools, truths, &mut rng, cycles, which, Some(start));
        } else {
            build_benign(
                model,
                &pools,
                hours,
                truths,
                &mut rng,
                which,
                Some(start),
                &mut dormant_cursor,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn plan_campaign(
    model: &NetworkModel,
    pools: &Pools,
    truths: &mut Vec<Truth>,
    rng: &mut Rng,
    telemetry: &Telemetry,
    cycles: u32,
    cid: u32,
    template: usize,
) {
    let stages = TEMPLATES[template].1;
    let needs_web = stages
        .iter()
        .any(|f| matches!(f, Family::CredentialStuffing | Family::WebExploit));
    let needs_files = stages.contains(&Family::Ransomware);
    if pools.internal.len() < 4
        || pools.clients.is_empty()
        || pools.servers.is_empty()
        || (needs_web && pools.webs.is_empty())
        || (needs_files && pools.files.is_empty())
    {
        return;
    }
    let attacker = public_ip(rng);
    let c2 = public_ip(rng);
    let mut start = rng.range(0, cycles.saturating_sub(1) as u64) as u32;
    // kompromitovany host = obet vstupni faze, utocnik dalsich fazi
    let mut foothold: Option<u32> = None;
    for (stage, &family) in stages.iter().enumerate() {
        if start >= cycles {
            break;
        }
        let (lo, hi) = len_range(family);
        let len = (rng.range(lo, hi.min(48)) as u32).max(1);
        let end = (start + len - 1).min(cycles - 1);
        let mut truth = base_truth(truths.len() as u32, Kind::Attack(family), start, end, 1.0);
        let external_entry = matches!(
            family,
            Family::PortScanHorizontal
                | Family::SlowScan
                | Family::SshBrute
                | Family::CredentialStuffing
                | Family::Exploit
                | Family::WebExploit
        );
        if external_entry {
            truth.attacker_external = Some(attacker.clone());
        } else {
            truth.attacker_device = Some(foothold.unwrap_or_else(|| *rng.pick(&pools.clients)));
        }
        match family {
            Family::PortScanHorizontal | Family::SlowScan | Family::Lateral => {
                let n = rng.range(2, 8).min(pools.internal.len() as u64) as usize;
                truth.victim_devices = rng
                    .sample_distinct(pools.internal.len(), n)
                    .into_iter()
                    .map(|p| pools.internal[p])
                    .filter(|d| Some(*d) != truth.attacker_device)
                    .collect();
            }
            Family::SshBrute | Family::Exploit => {
                truth.victim_devices = vec![*rng.pick(&pools.servers)];
            }
            Family::CredentialStuffing | Family::WebExploit => {
                truth.victim_devices = vec![*rng.pick(&pools.webs)];
            }
            Family::DnsTunnel => truth.victim_devices = vec![model.dns],
            Family::Ransomware => {
                let mut v = vec![*rng.pick(&pools.files)];
                let extra = rng.range(5, 20).min(pools.internal.len() as u64) as usize;
                for pick in rng.sample_distinct(pools.internal.len(), extra) {
                    v.push(pools.internal[pick]);
                }
                v.sort_unstable();
                v.dedup();
                truth.victim_devices = v;
            }
            _ => {}
        }
        if matches!(
            family,
            Family::C2Beacon
                | Family::Exfil
                | Family::DnsTunnel
                | Family::Cryptomining
                | Family::Ransomware
        ) {
            truth.target_external = Some(if family == Family::C2Beacon {
                c2.clone()
            } else {
                public_ip(rng)
            });
        }
        truth.ids_visible = rng.chance(telemetry.ids_coverage) && rng.chance(ids_share(family));
        truth.cov.campaign = Some(CampaignTag {
            id: cid,
            stage: stage as u8,
            template: template as u8,
        });
        // dalsi faze pokracuje z hostu, ktery tato faze zasahla (server pred klientem)
        if foothold.is_none() || family == Family::Lateral {
            let candidates: Vec<u32> = truth
                .victim_devices
                .iter()
                .copied()
                .filter(|d| !matches!(model.devices[*d as usize].role, Role::Gateway | Role::Dns))
                .collect();
            if let Some(&next) = candidates.first() {
                foothold = Some(next);
            }
        }
        truths.push(truth);
        start = end + 1 + rng.range(0, 24) as u32;
    }
}

/// Naplanuje jednu novou provozni poruchu kroku 5.
fn build_fault(
    model: &NetworkModel,
    pools: &Pools,
    truths: &mut Vec<Truth>,
    rng: &mut Rng,
    cycles: u32,
    which: Lookalike,
    forced_start: Option<u32>,
) {
    let start =
        forced_start.unwrap_or_else(|| rng.range(0, cycles.saturating_sub(1) as u64) as u32);
    let len = match which {
        Lookalike::DnsOutage => rng.range(1, 6),
        Lookalike::DhcpRenumber => rng.range(2, 6),
        Lookalike::LinkFlapping => rng.range(6, 20),
        Lookalike::Misconfig => rng.range(1, 8),
        Lookalike::BackupFailed => rng.range(2, 8),
        Lookalike::CertExpired => rng.range(2, 24),
        Lookalike::SegmentPowerLoss => rng.range(2, 4),
        Lookalike::VpnReconnectStorm => rng.range(1, 3),
        Lookalike::CloudMigration => rng.range(24, 200),
        _ => 1,
    } as u32;
    let end = (start + len - 1).min(cycles - 1);
    let mut truth = base_truth(
        truths.len() as u32,
        Kind::Benign(which),
        start,
        end,
        rng.range_f(0.4, 1.0),
    );
    let non_core = |d: &u32| !matches!(model.devices[*d as usize].role, Role::Gateway | Role::Dns);
    match which {
        Lookalike::DnsOutage => {
            truth.victim_devices = vec![model.dns];
            truth.target_external = Some(public_ip(rng));
        }
        Lookalike::DhcpRenumber => {
            let dynamic: Vec<usize> = (0..model.prefixes.len())
                .filter(|s| model.devices.iter().any(|d| d.subnet == *s && d.dhcp))
                .collect();
            if dynamic.is_empty() {
                return;
            }
            truth.cov.param = *rng.pick(&dynamic) as u32;
            let servers: Vec<u32> = pools.servers.iter().copied().filter(non_core).collect();
            if !servers.is_empty() {
                truth.victim_devices = vec![*rng.pick(&servers)];
            }
        }
        Lookalike::LinkFlapping => truth.cov.param = rng.range(2, 4) as u32,
        Lookalike::Misconfig => {
            if pools.clients.is_empty() {
                return;
            }
            truth.attacker_device = Some(*rng.pick(&pools.clients));
        }
        Lookalike::BackupFailed => {
            let target: Vec<u32> = if pools.files.is_empty() {
                pools.servers.iter().copied().filter(non_core).collect()
            } else {
                pools.files.clone()
            };
            if target.is_empty() || pools.internal.is_empty() {
                return;
            }
            truth.victim_devices = vec![*rng.pick(&target)];
            truth.attacker_device = Some(*rng.pick(&pools.internal));
        }
        Lookalike::CertExpired => {
            let pool = if pools.webs.is_empty() {
                pools.servers.iter().copied().filter(non_core).collect()
            } else {
                pools.webs.clone()
            };
            if pool.is_empty() {
                return;
            }
            truth.victim_devices = vec![*rng.pick(&pool)];
        }
        Lookalike::SegmentPowerLoss => {
            let subnet = rng.range(0, model.prefixes.len() as u64 - 1) as usize;
            truth.cov.param = subnet as u32;
            truth.victim_devices = model
                .devices
                .iter()
                .filter(|d| d.up && d.subnet == subnet)
                .map(|d| d.id)
                .filter(non_core)
                .collect();
            if truth.victim_devices.is_empty() {
                return;
            }
        }
        Lookalike::VpnReconnectStorm => {
            let vpn: Vec<u32> = pools
                .webs
                .iter()
                .copied()
                .filter(|d| model.devices[*d as usize].role == Role::Vpn)
                .collect();
            let pool = if vpn.is_empty() { &pools.webs } else { &vpn };
            if pool.is_empty() {
                return;
            }
            truth.victim_devices = vec![*rng.pick(pool)];
        }
        Lookalike::CloudMigration => {
            let first = public_ip(rng);
            let prefix = first
                .rsplit_once('.')
                .map(|(p, _)| p.to_string())
                .unwrap_or(first);
            truth.cov.extra_external = (0..8)
                .map(|_| format!("{prefix}.{}", rng.range(1, 254)))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let n = (pools.servers.len() / 3)
                .clamp(1, 40)
                .min(pools.servers.len());
            let mut victims: Vec<u32> = rng
                .sample_distinct(pools.servers.len(), n)
                .into_iter()
                .map(|p| pools.servers[p])
                .filter(non_core)
                .collect();
            let m = (pools.clients.len() / 4).min(100);
            for pick in rng.sample_distinct(pools.clients.len(), m) {
                victims.push(pools.clients[pick]);
            }
            victims.sort_unstable();
            victims.dedup();
            if victims.is_empty() {
                return;
            }
            truth.victim_devices = victims;
        }
        _ => return,
    }
    truths.push(truth);
}

/// Zaznam o jednom utoku ve svete pokryti (networks.jsonl, jen pri `--coverage`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AttackRecord {
    pub id: u32,
    pub family: String,
    pub held: bool,
    pub campaign: Option<CampaignTag>,
    pub intensity: f64,
    pub variation: Option<Variation>,
    pub stealth: f64,
    pub ids_visible: bool,
    /// Prvni utok rodiny v siti (uceni z verdiktu na ni jeste nema verdikt).
    pub first_of_family: bool,
    /// Provozni poruchy a lookalike s prekryvajicim se oknem.
    pub overlaps: Vec<String>,
    pub cycles: u32,
    pub emitted: bool,
    pub detected: bool,
    pub displayed: bool,
    pub cf: Option<bool>,
    pub cf_types: Vec<String>,
    /// Nektery pripsany nalez utoku byl automaticky zavren nebo vyvracen.
    pub auto_closed: bool,
    /// ... a slo o prvni vyskyt (typ, entita) v siti (pravidlo A7).
    pub auto_closed_first: bool,
}

/// Zaznam o jedne neskodne udalosti ve svete pokryti.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FaultRecord {
    pub id: u32,
    pub label: String,
    pub held: bool,
    pub ops: bool,
    pub new: bool,
    pub cycles: u32,
    pub fp_captured: bool,
    pub fp_displayed: bool,
}

/// Prekryvaji se okna dvou pravd (vcetne latence atribuce).
pub fn overlaps(a: &Truth, b: &Truth, latency: u32) -> bool {
    a.start_cycle <= b.end_cycle + latency && b.start_cycle <= a.end_cycle + latency
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soak::traffic::{
        CycleContext, NoBlocks, generate_cycle, no_mask, plan_episode, seed_for_cycle,
    };

    fn telemetry() -> Telemetry {
        Telemetry {
            drop_p: 0.0,
            dup_p: 0.0,
            skew_s: 0,
            outage_p: 0.0,
            ids_coverage: 1.0,
            blind_subnets: Vec::new(),
        }
    }

    fn flow(at: i64, src: &str) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: ts(at),
            src_ip: Some(src.to_string()),
            src_port: Some(40000 + (at % 1000) as u16),
            dst_ip: "198.51.100.7".to_string(),
            proto: "tcp".to_string(),
            dst_port: Some(443),
            duration_s: Some(0.5),
            orig_bytes: Some(1000),
            resp_bytes: Some(400),
            total_bytes: Some(1400),
            orig_pkts: Some(2),
            resp_pkts: Some(1),
            total_pkts: Some(3),
            conn_state: Some("SF".to_string()),
            history: None,
            missed_bytes: Some(0),
        }
    }

    fn attack(v: Variation) -> Truth {
        let mut t = base_truth(7, Kind::Attack(Family::C2Beacon), 0, 3, 0.5);
        t.attacker_external = Some("203.0.113.5".to_string());
        t.cov.extra_external = vec!["203.0.113.6".to_string(), "203.0.113.7".to_string()];
        t.cov.variation = Some(v);
        t
    }

    #[test]
    fn tempo_keeps_every_kth_flow_or_compresses_cycle_into_k_copies() {
        let t0 = 1_767_571_200;
        let slow = Variation {
            tempo: 0.5,
            ..Default::default()
        };
        let mut truth = attack(slow);
        let kept: usize = (0..10)
            .map(|i| vary(&mut truth, flow(t0 + i * 180, "203.0.113.5"), t0, &[]).len())
            .sum();
        assert_eq!(kept, 5, "kazdy druhy tok");

        let fast = Variation {
            tempo: 4.0,
            ..Default::default()
        };
        let mut truth = attack(fast);
        let copies = vary(&mut truth, flow(t0 + 1200, "203.0.113.5"), t0, &[]);
        assert_eq!(copies.len(), 4);
        // casova osa cyklu stlacena 4x a dlazdicovana: rozestup presne CYCLE/4
        let times: Vec<i64> = copies.iter().map(|c| c.timestamp.timestamp()).collect();
        assert_eq!(times[0], t0 + 300);
        for w in times.windows(2) {
            assert_eq!(w[1] - w[0], CYCLE_SECS / 4);
        }
        assert!(times.iter().all(|t| (t0..t0 + CYCLE_SECS).contains(t)));
    }

    #[test]
    fn volume_sources_and_jitter_change_only_attack_side() {
        let t0 = 1_767_571_200;
        let v = Variation {
            volume: 0.25,
            sources: 3,
            jitter: 0.5,
            ..Default::default()
        };
        let mut truth = attack(v);
        let mut sources = BTreeSet::new();
        for i in 0..200 {
            for c in vary(&mut truth, flow(t0 + i * 9, "203.0.113.5"), t0, &[]) {
                assert_eq!(c.orig_bytes, Some(250));
                assert_eq!(c.total_bytes, Some(350));
                let shift = (c.timestamp.timestamp() - (t0 + i * 9)).abs();
                assert!(shift <= 300, "rozptyl nejvys 0,5 x 600 s");
                sources.insert(c.src_ip.unwrap());
            }
            // tok z jine adresy (napr. odpoved obeti) se nepreadresuje
            let other = vary(&mut truth, flow(t0 + i * 9, "10.0.0.9"), t0, &[]);
            assert!(
                other
                    .iter()
                    .all(|c| c.src_ip.as_deref() == Some("10.0.0.9"))
            );
        }
        assert_eq!(sources.len(), 3, "{sources:?}");
    }

    #[test]
    fn stealth_index_is_zero_for_default_loud_attack_and_one_for_stealthiest() {
        let loud = Variation {
            tempo: 8.0,
            volume: 2.0,
            ..Default::default()
        };
        assert_eq!(loud.stealth(1.0), 0.0);
        assert_eq!(Variation::default().stealth(1.0), 0.0);
        let quiet = Variation {
            tempo: 0.25,
            jitter: 0.5,
            sources: 10,
            volume: 0.25,
            blend: true,
            ..Default::default()
        };
        assert!((quiet.stealth(0.0) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn coverage_off_leaves_plan_untouched_and_tuning_hides_held_parts() {
        let mut held_faults = 0usize;
        let mut held_templates = 0usize;
        let mut tuning_faults = BTreeSet::new();
        for id in 0..30u64 {
            let model = NetworkModel::generate(20261411, id);
            let mut rng = Rng::new(id);
            let base = plan_episode(&model, &mut rng, 336, &telemetry());
            let mut off = base.clone();
            plan_coverage(&model, &mut off, 336, &telemetry(), CoverageMode::Off);
            assert_eq!(off.len(), base.len());
            for mode in [CoverageMode::Tuning, CoverageMode::Full] {
                let mut truths = base.clone();
                plan_coverage(&model, &mut truths, 336, &telemetry(), mode);
                assert!(truths.len() >= base.len());
                for (i, t) in truths.iter().enumerate() {
                    assert_eq!(t.id as usize, i, "id = poradi");
                    assert!(t.start_cycle <= t.end_cycle && t.end_cycle < 672);
                    match t.kind {
                        Kind::Benign(look) if Lookalike::COVERAGE.contains(&look) => {
                            if mode == CoverageMode::Tuning {
                                assert!(!look.held_out(), "{look:?}");
                                tuning_faults.insert(look);
                            } else {
                                held_faults += look.held_out() as usize;
                            }
                        }
                        Kind::Attack(_) => {
                            let tag = t.cov.campaign;
                            if let Some(tag) = tag {
                                let held = template_held(tag.template as usize);
                                assert!(mode == CoverageMode::Full || !held);
                                held_templates += held as usize;
                            }
                            assert!(t.cov.variation.is_some());
                        }
                        _ => {}
                    }
                }
            }
        }
        assert!(held_faults > 0 && held_templates > 0);
        assert_eq!(tuning_faults.len(), 5, "{tuning_faults:?}");
    }

    #[test]
    fn every_new_fault_emits_flows_or_changes_state() {
        let mut emitted: BTreeSet<&'static str> = BTreeSet::new();
        for id in 0..12u64 {
            let model = NetworkModel::generate(20261412, id);
            let ip: Vec<String> = (0..model.devices.len() as u32)
                .map(|d| model.ip_of(d))
                .collect();
            let pools = Pools::new(&model);
            for which in Lookalike::COVERAGE {
                let mut truths = Vec::new();
                let mut rng = Rng::new(derive(id, which as u64));
                build_fault(&model, &pools, &mut truths, &mut rng, 96, which, Some(10));
                let Some(truth) = truths.first_mut() else {
                    continue;
                };
                if which == Lookalike::DhcpRenumber {
                    truth.cov.extra_external = vec!["10.99.0.1".to_string()];
                }
                let mut total = 0;
                // prvni tri cykly a posledni (hromadny start po vypadku napajeni)
                let (start, end) = (truth.start_cycle, truth.end_cycle);
                let cycles: BTreeSet<u32> = (start..=end.min(start + 2)).chain([end]).collect();
                for cycle in cycles {
                    let ctx = CycleContext {
                        model: &model,
                        ips: &ip,
                        cycle,
                        start_offset_s: 0,
                        telemetry: &telemetry(),
                        oracle: &NoBlocks,
                        rogue: None,
                        scan_now: false,
                        masked: no_mask(),
                        regular: &[],
                    };
                    let mut rng = Rng::new(seed_for_cycle(model.seed, cycle));
                    generate_cycle(&ctx, &mut truths, &mut rng);
                    total = truths[0].flows_emitted;
                }
                if total > 0 {
                    emitted.insert(which.label());
                }
            }
        }
        assert_eq!(emitted.len(), Lookalike::COVERAGE.len(), "{emitted:?}");
    }
}
