//! Žebřík ověřování v soak epizodě (krok 2B): simulované, REALISTICKY NEÚPLNÉ zdroje
//! dat pro `verify_ladder::LadderEvidence`.
//!
//! - L0: `FlowHistory` plněná z toků epizody (stejná produkční struktura).
//! - L1 kontext: `SimContext` (neúplný kalendář z kroku 1) přes `supporting_context`.
//! - L1 reputace: veřejná adresa útočníka je ve feedu jen s pravděpodobností
//!   `bad_coverage` (deterministický hod podle adresy), známé legitimní cíle
//!   (aktualizace, CDN) s `good_coverage`, a feed omylem hlásí `false_bad` náhodných
//!   veřejných adres. Vnitřní adresy reputaci nemají.
//! - L1 intel: CVE a KEV z inventáře (to, co dodá intel modul v produkci).
//! - L3: dostupnost služby podle modelu (zařízení běží, port existuje), 4 % selhání
//!   nástroje jako u ostatních kontrol.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};

use crate::{
    context_gate::{ContextGate, GateInput},
    device_class::DeviceClass,
    flow_history::{FlowHistory, Recurrence},
    model::{ServiceReport, Severity},
    scope_policy::ScopePolicy,
    soak::{
        netmodel::NetworkModel,
        rng::mix,
        traffic::{Kind, Truth},
        v3::SimContext,
    },
    verify_ladder::{CaseInput, IntelSignal, LadderEvidence, Liveness, Reputation},
};

/// Pokrytí simulované reputace.
#[derive(Debug, Clone, Copy)]
pub struct ReputationCoverage {
    pub bad_coverage: f64,
    pub good_coverage: f64,
    pub false_bad: f64,
}

impl Default for ReputationCoverage {
    fn default() -> Self {
        Self {
            bad_coverage: 0.35,
            good_coverage: 0.6,
            false_bad: 0.005,
        }
    }
}

fn roll(seed: u64, text: &str, salt: u64) -> f64 {
    let h = text.bytes().fold(seed ^ salt, |a, b| {
        mix(a ^ b as u64).wrapping_mul(0x100_0000_01b3)
    });
    (mix(h) % 1_000_000) as f64 / 1_000_000.0
}

/// Neúplný reputační feed simulace.
pub struct SimReputation {
    bad: HashSet<String>,
    good: HashSet<String>,
    seed: u64,
    coverage: ReputationCoverage,
}

impl SimReputation {
    pub fn new(model: &NetworkModel, truths: &[Truth], coverage: ReputationCoverage) -> Self {
        let seed = model.seed;
        let bad = truths
            .iter()
            .filter(|t| matches!(t.kind, Kind::Attack(_)))
            .flat_map(|t| [&t.attacker_external, &t.target_external])
            .flatten()
            .filter(|ip| roll(seed, ip, 0xBAD) < coverage.bad_coverage)
            .cloned()
            .collect();
        let good = model
            .externals
            .iter()
            .filter(|ip| roll(seed, ip, 0x600D) < coverage.good_coverage)
            .cloned()
            .collect();
        Self {
            bad,
            good,
            seed,
            coverage,
        }
    }

    pub fn lookup(&self, ip: &str, scope: &ScopePolicy) -> Reputation {
        if scope.contains(ip) {
            return Reputation::Unknown;
        }
        if self.bad.contains(ip) {
            return Reputation::Bad("sim-feed".into());
        }
        if self.good.contains(ip) {
            return Reputation::Good("sim-allowlist".into());
        }
        if roll(self.seed, ip, 0xF00) < self.coverage.false_bad {
            return Reputation::Bad("sim-feed (omyl)".into());
        }
        Reputation::Unknown
    }
}

/// Data jednoho cyklu pro žebřík v soaku.
pub struct SoakEvidence<'a> {
    pub history: &'a FlowHistory,
    pub at: DateTime<Utc>,
    pub gate: &'a ContextGate,
    pub context: Option<&'a SimContext>,
    pub reputation: &'a SimReputation,
    pub services: &'a HashMap<&'a str, &'a ServiceReport>,
    pub devices: &'a HashMap<String, DeviceClass>,
    pub groups: &'a HashMap<String, String>,
    pub group_sizes: &'a HashMap<String, usize>,
    /// (typ nálezu, peer skupina) -> počet členů s tímto typem v cyklu.
    pub group_hits: &'a HashMap<(String, String), usize>,
    pub suspicious: &'a HashMap<String, usize>,
    pub scope: &'a ScopePolicy,
    pub model: &'a NetworkModel,
    pub cycle: u32,
    pub liveness_runs: u64,
    pub liveness_failures: u64,
    /// Profil hostu (krok 3E); `None` = vypnuto.
    pub profile: Option<(
        &'a crate::behavior::profile::HostProfiles,
        &'a crate::behavior::profile::ProfilePolicy,
    )>,
    /// Koncová telemetrie cyklu (krok 8); `None` = vypnuto.
    pub endpoint: Option<&'a crate::endpoint::correlate::EndpointView>,
}

impl LadderEvidence for SoakEvidence<'_> {
    fn recurrence(&self, history_key: &str, value: f64) -> Recurrence {
        self.history.recurrence(history_key, self.at, value)
    }

    fn context(&self, case: &CaseInput) -> Option<String> {
        let provider = self.context?;
        let ids = [case.host_ip.clone(), case.key.entity.clone()];
        self.gate
            .supporting_context(
                provider,
                &GateInput {
                    finding_type: &case.finding_type,
                    host_ids: &ids,
                    sources: &case.sources,
                    severity: Severity::Medium,
                    at: self.at,
                    protected: case.protected,
                },
            )
            .map(|(_, reason)| reason)
    }

    fn reputation(&self, ip: &str) -> Reputation {
        self.reputation.lookup(ip, self.scope)
    }

    fn intel(&self, case: &CaseInput) -> IntelSignal {
        let Some(port) = case.port else {
            return IntelSignal::NothingKnown;
        };
        let service = case.key.service.split('#').next().unwrap_or("");
        let key = if service.contains('/') {
            format!("{}/{service}", case.host_ip)
        } else {
            format!("{}/tcp/{port}", case.host_ip)
        };
        let Some(service) = self.services.get(key.as_str()) else {
            return IntelSignal::NothingKnown;
        };
        let mut best_epss = 0.0f64;
        for cve in &service.cves {
            if let Some(context) = &cve.exploit_context {
                if context.cisa_kev.is_some() {
                    return IntelSignal::KnownExploited(cve.cve_id.clone());
                }
                if let Some(epss) = &context.epss {
                    best_epss = best_epss.max(epss.score);
                }
            }
        }
        if best_epss >= 0.5 {
            IntelSignal::HighEpss(best_epss)
        } else {
            IntelSignal::NothingKnown
        }
    }

    fn device(&self, ip: &str) -> Option<DeviceClass> {
        self.devices.get(ip).cloned()
    }

    fn peers(&self, case: &CaseInput) -> Option<(usize, usize)> {
        let group = self.groups.get(&case.host_ip)?;
        let size = *self.group_sizes.get(group)?;
        let hits = self
            .group_hits
            .get(&(case.finding_type.clone(), group.clone()))
            .copied()
            .unwrap_or(0);
        Some((hits, size))
    }

    fn liveness(&mut self, case: &CaseInput) -> Liveness {
        if !self.scope.contains(&case.host_ip) {
            return Liveness::OutOfScope;
        }
        self.liveness_runs += 1;
        let fault = roll(
            self.model.seed ^ self.cycle as u64,
            &format!("{}#{}", case.host_ip, case.port.unwrap_or(0)),
            0x11FE,
        );
        if fault < 0.04 {
            self.liveness_failures += 1;
            return Liveness::Failed("simulovany timeout nastroje".into());
        }
        let Some(device) = self.model.device_by_ip(&case.host_ip) else {
            return Liveness::Down;
        };
        let device = &self.model.devices[device as usize];
        let listening = case
            .port
            .is_none_or(|port| device.services.iter().any(|s| s.port == port));
        if device.up && listening {
            Liveness::Up
        } else {
            Liveness::Down
        }
    }

    fn neighbors(&self, ip: &str) -> Vec<String> {
        self.history.neighbors(ip, self.at)
    }

    fn in_scope(&self, ip: &str) -> bool {
        self.scope.contains(ip)
    }

    fn suspicious_on(&self, ip: &str) -> usize {
        self.suspicious.get(ip).copied().unwrap_or(0)
    }

    fn profile(&self, case: &CaseInput) -> crate::behavior::profile::ProfileVerdict {
        use crate::behavior::profile::{ProfileVerdict, case_pair, case_verdict};
        let Some((profiles, policy)) = self.profile else {
            return ProfileVerdict::Unknown("profil vypnut".into());
        };
        let group = case_pair(case).and_then(|(actor, ..)| {
            self.groups
                .get(&actor)
                .and_then(|g| self.group_sizes.get(g))
                .copied()
        });
        case_verdict(profiles, policy, case, group, self.at.timestamp())
    }

    fn endpoint(&self, case: &CaseInput) -> crate::endpoint::correlate::EndpointSignal {
        match self.endpoint {
            Some(view) => view.signal(&case.host_ip, &case.sources),
            None => crate::endpoint::correlate::EndpointSignal::NoCoverage(
                "koncova telemetrie vypnuta".into(),
            ),
        }
    }
}

/// Odpovídá rozpoznaný typ roli zařízení v modelu? (Měření přesnosti, krok 2D.)
pub fn role_matches(
    role: crate::soak::netmodel::Role,
    kind: crate::device_class::DeviceKind,
) -> bool {
    use crate::device_class::DeviceKind as K;
    use crate::soak::netmodel::Role as R;
    matches!(
        (role, kind),
        (R::Gateway, K::Router)
            | (R::Dns, K::Dns)
            | (R::Web, K::Web)
            | (R::Database, K::Database)
            | (R::Mail, K::Mail)
            | (R::FileServer, K::Files)
            | (R::Workstation, K::Workstation)
            | (R::Printer, K::Printer)
            | (R::IotSensor, K::Iot)
            | (R::Camera, K::Camera)
            | (R::Jump, K::Server | K::Workstation)
            | (R::Plc, K::Plc)
            | (R::Hmi, K::Hmi)
            | (R::Medical, K::Medical)
            | (R::VoipPhone, K::Voip)
            | (R::WifiAp, K::Ap)
            | (R::Vpn, K::Vpn)
            | (R::Container, K::Container | K::Web)
            | (R::Mobile, K::Mobile)
    )
}

/// Typy nálezů, které na pivotu znamenají podezření na souvisejícím zařízení.
pub fn is_suspicious_type(kind: &str) -> bool {
    matches!(
        kind,
        "scan_attempts"
            | "multi_target_pattern"
            | "suricata_alert"
            | "source_volume_outlier"
            | "connection_timeout_burst"
            | "beacon_periodic"
            | "interactive_session"
            | "long_lived_tunnel"
            | "pivot_chain"
            | "egress_ids_alert"
            | "egress_volume_anomaly"
            | "novel_persistent_peer"
            | "novel_fanout"
    )
}

/// Index peer skupin cyklu: velikost skupin a zasažení členové po typech.
pub fn group_index(
    groups: &HashMap<String, String>,
    typed_hosts: &HashSet<(String, String)>,
) -> (HashMap<String, usize>, HashMap<(String, String), usize>) {
    let mut sizes: HashMap<String, usize> = HashMap::new();
    for group in groups.values() {
        *sizes.entry(group.clone()).or_default() += 1;
    }
    let mut hits: HashMap<(String, String), usize> = HashMap::new();
    for (kind, ip) in typed_hosts {
        if let Some(group) = groups.get(ip) {
            *hits.entry((kind.clone(), group.clone())).or_default() += 1;
        }
    }
    (sizes, hits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reputation_is_incomplete_and_internal_addresses_have_none() {
        let model = NetworkModel::generate(20261102, 7);
        let scope = ScopePolicy::new(model.scope());
        let truths: Vec<Truth> = (0..400)
            .map(|i| Truth {
                id: i,
                kind: Kind::Attack(crate::soak::traffic::Family::SshBrute),
                start_cycle: 0,
                end_cycle: 1,
                intensity: 0.5,
                attacker_device: None,
                attacker_external: Some(format!("45.1.{}.{}", i / 200, i % 200 + 1)),
                victim_devices: vec![],
                target_external: None,
                ids_visible: false,
                touched_ips: Default::default(),
                cycle_targets: Default::default(),
                cycle_sources: Default::default(),
                flows_emitted: 0,
                flows_blocked: 0,
                first_emit_cycle: None,
                blocked_at_cycle: None,
                cov: Default::default(),
            })
            .collect();
        let feed = SimReputation::new(&model, &truths, ReputationCoverage::default());
        let listed = truths
            .iter()
            .filter(|t| {
                matches!(
                    feed.lookup(t.attacker_external.as_deref().unwrap(), &scope),
                    Reputation::Bad(_)
                )
            })
            .count();
        assert!((100..180).contains(&listed), "pokryti ~35 %: {listed}");
        assert_eq!(feed.lookup(&model.ip_of(0), &scope), Reputation::Unknown);
    }
}
