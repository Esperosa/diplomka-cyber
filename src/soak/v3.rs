//! Jádro v3 v soak epizodě: stav, který by produkční engine držel v
//! `engine-state.sqlite` (paměť nálezů, historie detektoru, perzistentní inventář,
//! registrace identity), a simulovaný NEÚPLNÝ poskytovatel kontextu.
//!
//! Restart enginu v soaku = zápis všeho do SQLite a nové načtení (emulace pádu
//! a startu procesu); co se nezapsalo, se ztratí stejně jako v produkci.

use std::collections::HashSet;

use chrono::{DateTime, Utc};

use crate::{
    context_gate::{ContextEntry, ContextGate, ContextKind, ContextProvider, GatePolicy},
    engine::EngineConfig,
    engine_state::{EngineStateStore, PersistentInventory},
    error::Result,
    finding_memory::FindingMemory,
    identity::IdentityResolverV3,
    model::{HostReport, NormalizedEvent},
    passive::{
        ConnectionObservation,
        anomaly_v3::{DetectorState, SourceMap, V3Switches, V3Thresholds, detect_v3},
    },
    soak::{
        netmodel::NetworkModel,
        rng::mix,
        traffic::{CYCLE_SECS, Kind, Lookalike, Truth, cycle_start_abs, ts},
    },
};

pub struct V3Runtime {
    pub engine: EngineConfig,
    store: EngineStateStore,
    pub memory: Option<FindingMemory>,
    detector: DetectorState,
    thresholds: V3Thresholds,
    pub inventory: PersistentInventory,
    pub gate: ContextGate,
    pub identity: IdentityResolverV3,
    sources: SourceMap,
    /// IP -> peer skupina (typ zarizeni + podsit), obnovuje se po kazdem skenu (krok 2D).
    pub peer_groups: std::collections::HashMap<String, String>,
    no_groups: std::collections::HashMap<String, String>,
    /// IP -> typ zarizeni z posledniho skenu (krok 2D).
    pub device_classes: std::collections::HashMap<String, crate::device_class::DeviceClass>,
    /// Ulozena historie toku (L0, krok 2B).
    pub history: crate::flow_history::FlowHistory,
    /// Zebrik overovani (krok 2B).
    pub ladder: crate::verify_ladder::Ladder,
    /// Nalez otevreneho pripadu (jen mereni: pozdni zobrazeni po rozhodnuti).
    pub case_findings:
        std::collections::HashMap<crate::finding_memory::FindingKey, crate::model::Finding>,
    /// Behavioralni vrstva kroku 3 (odchozi provoz, beacon, relace, graf, profil).
    pub behavior: crate::behavior::BehaviorState,
    pub behavior_thresholds: crate::behavior::BehaviorThresholds,
    pub profile_policy: crate::behavior::profile::ProfilePolicy,
    /// Meze objemu odchozich toku okna (vzorkovani po dvojici, krok 3A).
    pub egress_policy: crate::passive::egress::EgressPolicy,
    /// Krok 6: klientela sluzeb pro tridu provozni problem.
    pub clientele: crate::ops_evidence::Clientele,
    pub ops_policy: crate::ops_evidence::OpsPolicy,
    pub ops_marks: crate::ops_evidence::OpsMarks,
}

impl V3Runtime {
    /// `secret` = tajny klic zebriku (nahodne poradi kontrol, RQ3 Z11).
    pub fn new(engine: EngineConfig, secret: u64) -> Result<Self> {
        Ok(Self {
            engine,
            store: EngineStateStore::open_in_memory()?,
            memory: engine
                .memory()
                .then(|| FindingMemory::new(engine.memory_config())),
            detector: DetectorState::default(),
            thresholds: V3Thresholds::default(),
            inventory: PersistentInventory::default(),
            gate: ContextGate::new(GatePolicy::for_engine(&engine)),
            identity: IdentityResolverV3::new(),
            sources: SourceMap::new(),
            peer_groups: Default::default(),
            no_groups: Default::default(),
            device_classes: Default::default(),
            history: Default::default(),
            ladder: crate::verify_ladder::Ladder::new(
                crate::verify_ladder::LadderPolicy {
                    profile: engine.profile(),
                    ..Default::default()
                },
                secret,
            ),
            case_findings: Default::default(),
            behavior: Default::default(),
            behavior_thresholds: Default::default(),
            profile_policy: Default::default(),
            egress_policy: Default::default(),
            clientele: Default::default(),
            ops_policy: Default::default(),
            ops_marks: Default::default(),
        })
    }

    /// Restart procesu: zapsat stav, zahodit paměť procesu, načíst ze SQLite.
    pub fn restart(&mut self) -> Result<()> {
        if let Some(memory) = self.memory.as_mut() {
            memory.flush(self.store.conn_mut())?;
        }
        self.store.save("detector", &self.detector)?;
        self.store.save("inventory", &self.inventory)?;
        self.store.save("identity", &self.identity)?;
        self.store.save("ladder", &self.ladder)?;
        self.store.save("behavior", &self.behavior)?;
        if self.engine.ops_class() {
            self.store.save("clientele", &self.clientele)?;
            self.store.save("ops_marks", &self.ops_marks)?;
        }
        let calibrator = self.ladder.calibrator.take();
        self.history.flush(self.store.conn_mut())?;
        if self.memory.is_some() {
            let stats = self
                .memory
                .as_ref()
                .map(|m| m.stats.clone())
                .unwrap_or_default();
            let mut reloaded = FindingMemory::load(self.store.conn(), self.engine.memory_config())?;
            reloaded.stats = stats;
            self.memory = Some(reloaded);
        }
        self.detector = self.store.load("detector")?.unwrap_or_default();
        self.inventory = self.store.load("inventory")?.unwrap_or_default();
        self.identity = self.store.load("identity")?.unwrap_or_default();
        if let Some(ladder) = self.store.load("ladder")? {
            self.ladder = ladder;
        }
        // kalibrace je konfigurace (soubor), ne stav: po restartu se znovu nacte
        self.ladder.calibrator = calibrator;
        self.history = crate::flow_history::FlowHistory::load(self.store.conn())?;
        self.behavior = self.store.load("behavior")?.unwrap_or_default();
        if self.engine.ops_class() {
            self.clientele = self.store.load("clientele")?.unwrap_or_default();
            self.ops_marks = self.store.load("ops_marks")?.unwrap_or_default();
        }
        self.sources.clear();
        Ok(())
    }

    pub(crate) fn detect(
        &mut self,
        observations: &[ConnectionObservation],
        known_services: &HashSet<(String, String, u16)>,
        known_hosts: &HashSet<String>,
        now: DateTime<Utc>,
    ) -> Vec<NormalizedEvent> {
        let switches = V3Switches {
            rate: self.engine.robust_rate(),
            volume: self.engine.volume_baseline(),
            unexpected: self.engine.unexpected_v3(),
            recall: self.engine.recall(),
        };
        let out = detect_v3(
            observations,
            known_services,
            known_hosts,
            &mut self.detector,
            switches,
            &self.thresholds,
            now,
            if self.engine.peer_baseline() {
                &self.peer_groups
            } else {
                &self.no_groups
            },
        );
        self.sources = out.sources;
        out.events
    }

    /// Dominantní zdroje události posledního cyklu (pro paměť a kontext).
    pub fn sources_of(&self, dst: &str, proto: &str, port: u16, event_type: &str) -> &[String] {
        self.sources
            .get(&(
                dst.to_string(),
                proto.to_string(),
                port,
                event_type.to_string(),
            ))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn end_cycle(&mut self, now: DateTime<Utc>) -> Result<()> {
        if let Some(memory) = self.memory.as_mut() {
            memory.sweep(now);
            memory.flush(self.store.conn_mut())?;
        }
        Ok(())
    }

    pub fn tracked_services(&self) -> usize {
        self.detector.tracked_services()
    }
}

/// Pokrytí simulovaného kontextu (podíl událostí, o kterých kontext ví).
#[derive(Debug, Clone, Copy)]
pub struct ContextCoverage {
    /// Plánované práce v kalendáři: záloha, dávka, patch okno.
    pub calendar: f64,
    /// Registr autorizovaných skenerů.
    pub scanners: f64,
    /// Monitoring výpadků služeb.
    pub monitoring: f64,
    /// CMDB: nasazení a vyřazení zařízení.
    pub cmdb: f64,
    /// Stav senzoru (výpadek sběru).
    pub sensor: f64,
    /// Fantomová okna údržby (v kalendáři, ale nekonala se) na síť a den.
    pub phantom_per_day: f64,
}

impl Default for ContextCoverage {
    fn default() -> Self {
        Self {
            calendar: 0.6,
            scanners: 0.7,
            monitoring: 0.5,
            cmdb: 0.5,
            sensor: 0.8,
            phantom_per_day: 0.3,
        }
    }
}

/// Neúplný, nepřesný kontext pro simulaci (ne ground truth ve 100 %).
pub struct SimContext {
    entries: Vec<ContextEntry>,
}

impl ContextProvider for SimContext {
    fn entries(&self) -> &[ContextEntry] {
        &self.entries
    }
}

fn known(seed: u64, id: u64, salt: u64, share: f64) -> bool {
    (mix(seed ^ id.wrapping_mul(0x9E37_79B9) ^ salt) % 10_000) as f64 / 10_000.0 < share
}

/// Fantomové okno: (zařízení, první cyklus, poslední cyklus).
pub fn phantom_windows(
    model: &NetworkModel,
    cycles: u32,
    coverage: &ContextCoverage,
) -> Vec<(u32, u32, u32)> {
    let servers: Vec<u32> = model
        .devices
        .iter()
        .filter(|d| d.role.is_server() && d.id != model.gateway)
        .map(|d| d.id)
        .collect();
    if servers.is_empty() {
        return Vec::new();
    }
    (0..cycles.div_ceil(48))
        .filter(|day| known(model.seed, *day as u64, 0xF4A7, coverage.phantom_per_day))
        .map(|day| {
            let roll = mix(model.seed ^ 0xF4A8 ^ day as u64);
            let device = servers[(roll % servers.len() as u64) as usize];
            let start = (day * 48 + ((roll >> 20) % 44) as u32).min(cycles.saturating_sub(1));
            (device, start, (start + 3).min(cycles.saturating_sub(1)))
        })
        .collect()
}

impl SimContext {
    #[allow(clippy::too_many_arguments)]
    pub fn for_cycle(
        truths: &[Truth],
        model: &NetworkModel,
        ips: &[String],
        start_offset_s: i64,
        cycles: u32,
        coverage: &ContextCoverage,
        phantoms: &[(u32, u32, u32)],
        cycle: u32,
    ) -> Self {
        let at = |c: u32| ts(cycle_start_abs(start_offset_s, c));
        let window = |start: u32, end: u32, extra_end: u32| {
            // deklarovana okna jsou o cyklus sirsi nez skutecna prace (realisticky)
            let s = start.saturating_sub(1);
            let e = (end + 1 + extra_end).min(cycles);
            (
                at(s),
                ts(cycle_start_abs(start_offset_s, e) + CYCLE_SECS - 1),
            )
        };
        let mut entries = Vec::new();
        let mut push = |kind: ContextKind,
                        hosts: Vec<String>,
                        sources: Vec<String>,
                        (start, end): (DateTime<Utc>, DateTime<Utc>)| {
            entries.push(ContextEntry {
                kind,
                hosts,
                sources,
                start,
                end,
                covers: kind
                    .default_covers()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                approved_by: "sim-spravce".to_string(),
                expires: end + chrono::Duration::days(1),
            });
        };
        let ip = |device: u32| ips[device as usize].clone();
        for truth in truths {
            let Kind::Benign(look) = truth.kind else {
                continue;
            };
            let lead = match look {
                Lookalike::Onboarding | Lookalike::Decommission => 48,
                _ => 2,
            };
            if cycle + 2 < truth.start_cycle || cycle > truth.end_cycle + lead {
                continue;
            }
            let id = truth.id as u64;
            let seed = model.seed;
            match look {
                Lookalike::Backup if known(seed, id, 0xB0, coverage.calendar) => {
                    let mut hosts: Vec<String> =
                        truth.victim_devices.iter().map(|d| ip(*d)).collect();
                    if let Some(source) = truth.attacker_device {
                        hosts.push(ip(source));
                    }
                    push(
                        ContextKind::Backup,
                        hosts,
                        Vec::new(),
                        window(truth.start_cycle, truth.end_cycle, 0),
                    );
                }
                Lookalike::BatchJob if known(seed, id, 0xB1, coverage.calendar) => push(
                    ContextKind::BatchJob,
                    truth.victim_devices.iter().map(|d| ip(*d)).collect(),
                    Vec::new(),
                    window(truth.start_cycle, truth.end_cycle, 0),
                ),
                Lookalike::PatchWindow if known(seed, id, 0xB2, coverage.calendar) => push(
                    ContextKind::PatchWindow,
                    truth.victim_devices.iter().map(|d| ip(*d)).collect(),
                    Vec::new(),
                    window(truth.start_cycle, truth.end_cycle, 0),
                ),
                Lookalike::AuthorizedScanner if known(seed, id, 0xB3, coverage.scanners) => {
                    if let Some(scanner) = truth.attacker_device {
                        push(
                            ContextKind::AuthorizedScanner,
                            Vec::new(),
                            vec![ip(scanner)],
                            window(truth.start_cycle, truth.end_cycle, 0),
                        );
                    }
                }
                Lookalike::ServiceCrash if known(seed, id, 0xB4, coverage.monitoring) => push(
                    ContextKind::ServiceOutage,
                    truth.victim_devices.iter().map(|d| ip(*d)).collect(),
                    Vec::new(),
                    window(truth.start_cycle, truth.end_cycle, 0),
                ),
                Lookalike::Onboarding if known(seed, id, 0xB5, coverage.cmdb) => push(
                    ContextKind::DeviceOnboarding,
                    truth.victim_devices.iter().map(|d| ip(*d)).collect(),
                    Vec::new(),
                    window(truth.start_cycle, truth.start_cycle, 47),
                ),
                Lookalike::Decommission if known(seed, id, 0xB6, coverage.cmdb) => push(
                    ContextKind::DeviceDecommission,
                    truth.victim_devices.iter().map(|d| ip(*d)).collect(),
                    Vec::new(),
                    window(truth.start_cycle, truth.start_cycle, 47),
                ),
                Lookalike::SensorCrash if known(seed, id, 0xB7, coverage.sensor) => push(
                    ContextKind::SensorOutage,
                    Vec::new(),
                    Vec::new(),
                    window(truth.start_cycle, truth.end_cycle, 1),
                ),
                _ => {}
            }
        }
        for &(device, start, end) in phantoms {
            if cycle + 1 >= start && cycle <= end + 1 {
                push(
                    ContextKind::Maintenance,
                    vec![ip(device)],
                    Vec::new(),
                    window(start, end, 0),
                );
            }
        }
        Self { entries }
    }
}

/// Pomocník: IP adresy hostů reportu jako množina (pro `known_hosts`).
pub fn host_ips(hosts: &[HostReport]) -> HashSet<String> {
    hosts.iter().map(|h| h.ip.clone()).collect()
}
