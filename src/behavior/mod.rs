//! Behaviorální vrstva jádra v3 (krok 3, docs/diplomka/eval/impl-krok3.md).
//!
//! Vstupem jsou toky jednoho okna rozdělené podle směru (`passive::egress`): odchozí
//! (zdroj uvnitř, cíl venku), čistě vnitřní a odchozí IDS alerty. Výstupem jsou nálezy
//! navázané na VNITŘNÍ hostitel (aktéra), ne na cílovou službu z inventáře:
//! - `egress_volume_anomaly`, `egress_ids_alert` (A, viditelnost ven),
//! - `beacon_periodic` (B, periodicita dvojice zdroj-cíl, hypotéza RQ4 Z1/Z2),
//! - `interactive_session`, `long_lived_tunnel` (C, hypotéza bez recenzované reference, RQ4 Z13),
//! - `pivot_chain` (D, řetěz nových hran A→B→C, RQ4 Z10/Z11: nová hrana je rys, ne poplach).
//!
//! Profil hostu (E, `profile`) je naučená množina obvyklých cílů a portů s hysterezí;
//! slouží žebříku jako POZITIVNÍ důkaz neškodnosti (RQ5-053: deterministický allowlist
//! porazil učené modely na všech čtyřech datasetech DARPA TC, jiná úloha), nikdy jako
//! tiché potlačení.
//!
//! Stav je serializovatelný (v produkci kv `behavior` v `engine-state.sqlite`, v soaku
//! přežije restart) a každá struktura má strop velikosti a stáří.
#![allow(private_interfaces)]

pub mod beacon;
pub mod egress_volume;
pub mod graph;
pub mod interactive;
pub mod profile;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    model::{Confidence, Finding, NormalizedEvent, Severity},
    passive::ConnectionObservation,
};

/// Které části behaviorální vrstvy běží (z `EngineConfig`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BehaviorSwitches {
    pub egress: bool,
    pub beacon: bool,
    pub interactive: bool,
    pub graph: bool,
    pub profile: bool,
}

impl BehaviorSwitches {
    pub fn from_engine(engine: &crate::engine::EngineConfig) -> Self {
        Self {
            egress: engine.egress(),
            beacon: engine.beacon(),
            interactive: engine.interactive(),
            graph: engine.graph(),
            profile: engine.profile(),
        }
    }

    pub fn any(&self) -> bool {
        self.egress || self.graph || self.profile
    }
}

/// Typy nálezů behaviorální vrstvy (pro `expected_types`, žebřík a kontext).
pub const BEHAVIOR_TYPES: &[&str] = &[
    "egress_volume_anomaly",
    "egress_ids_alert",
    "beacon_periodic",
    "interactive_session",
    "long_lived_tunnel",
    "pivot_chain",
];

pub fn is_behavior_type(kind: &str) -> bool {
    BEHAVIOR_TYPES.contains(&kind)
}

/// Stav vrstvy mezi okny.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BehaviorState {
    pub egress: egress_volume::EgressVolumeState,
    pub prevalence: beacon::Prevalence,
    pub beacon: beacon::BeaconState,
    pub interactive: interactive::InteractiveState,
    pub graph: graph::GraphState,
    pub profile: profile::HostProfiles,
    /// Začátek prvního okna (stáří senzoru, zahřívání).
    pub first_window: Option<i64>,
}

/// Vstup jednoho okna.
pub struct BehaviorInput<'a> {
    pub outbound: &'a [ConnectionObservation],
    pub internal: &'a [ConnectionObservation],
    /// IDS alerty se zdrojem uvnitř a cílem venku.
    pub outbound_alerts: &'a [NormalizedEvent],
    /// Začátek okna.
    pub now: DateTime<Utc>,
}

/// Nález vrstvy s údaji pro paměť nálezů, kontext a měření.
#[derive(Debug, Clone)]
pub struct BehaviorFinding {
    pub finding: Finding,
    /// Protistrana (vnější cíl u odchozích nálezů, předchozí hop u řetězu): u odchozího
    /// provozu je reputace a kontext vázaný na ni, ne na vnitřního aktéra.
    pub sources: Vec<String>,
    /// Cíle toků (ip, port), ze kterých nález vznikl (příčinná atribuce v soaku).
    pub targets: Vec<(String, u16)>,
    pub count: u32,
    /// Vnitřní aktér (zdroj odchozího toku, pivot řetězu).
    pub actor: String,
}

/// Řetěz nových hran (krok 3D) pro skórování kvality řetězu.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedChain {
    /// Hrany v pořadí (zdroj, cíl, čas začátku).
    pub edges: Vec<(String, String, i64)>,
    pub score: f64,
}

#[derive(Debug, Default)]
pub struct BehaviorOutput {
    pub findings: Vec<BehaviorFinding>,
    pub chains: Vec<DetectedChain>,
}

/// Prahy vrstvy (verze se píše do `rule_id`). Volba autora z hypotéz studie 03 a RQ4;
/// laděné jen na ladicích seedech, nikdy na držených rodinách (krok 3F).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BehaviorThresholds {
    pub egress: egress_volume::EgressThresholds,
    pub beacon: beacon::BeaconThresholds,
    pub interactive: interactive::InteractiveThresholds,
    pub graph: graph::GraphThresholds,
}

impl BehaviorThresholds {
    /// 2 = krok 4 (novost periodicity, nahraný objem bez symetrických relací).
    pub const VERSION: u32 = 2;
}

/// Jedno okno vrstvy. `frozen` = hosté a dvojice s otevřeným poplachem (neučí se do
/// profilu ani do historie, RQ2 Z3 gating).
pub fn run_window(
    state: &mut BehaviorState,
    switches: BehaviorSwitches,
    thresholds: &BehaviorThresholds,
    input: &BehaviorInput<'_>,
) -> BehaviorOutput {
    let mut out = BehaviorOutput::default();
    let now = input.now.timestamp();
    state.first_window.get_or_insert(now);
    if switches.egress {
        out.findings.extend(egress_volume::detect(
            &mut state.egress,
            &thresholds.egress,
            input.outbound,
            now,
        ));
        out.findings
            .extend(egress_volume::ids_findings(input.outbound_alerts));
        state.prevalence.observe(input.outbound, now);
    }
    if switches.beacon {
        // krok 4: prvni vyskyt hostu v provozu (novost periodicity)
        let seen = input
            .outbound
            .iter()
            .filter_map(|f| f.src_ip.as_deref().map(|s| (s, f.timestamp.timestamp())))
            .chain(input.internal.iter().flat_map(|f| {
                let at = f.timestamp.timestamp();
                f.src_ip
                    .as_deref()
                    .map(|s| (s, at))
                    .into_iter()
                    .chain(std::iter::once((f.dst_ip.as_str(), at)))
            }));
        state
            .beacon
            .observe_hosts(seen, thresholds.beacon.max_hosts);
        let profile = &state.profile;
        let habit = |host: &str, peer: &str, proto: &str, port: u16| {
            profile.is_habit(host, peer, proto, port)
        };
        out.findings.extend(beacon::detect(
            &mut state.beacon,
            &state.prevalence,
            &thresholds.beacon,
            input.outbound,
            now,
            state.first_window.unwrap_or(now),
            &habit,
        ));
    }
    if switches.interactive {
        out.findings.extend(interactive::detect(
            &mut state.interactive,
            &state.prevalence,
            &thresholds.interactive,
            input.outbound,
            now,
        ));
    }
    if switches.graph {
        let roots: Vec<String> = out
            .findings
            .iter()
            .filter(|f| {
                matches!(
                    f.finding.finding_type.as_str(),
                    "interactive_session" | "long_lived_tunnel" | "beacon_periodic"
                )
            })
            .map(|f| f.actor.clone())
            .collect();
        let (findings, chains) = graph::detect(
            &mut state.graph,
            &thresholds.graph,
            input.internal,
            &roots,
            now,
        );
        out.findings.extend(findings);
        out.chains = chains;
    }
    out.findings
        .sort_by(|a, b| a.finding.finding_id.cmp(&b.finding.finding_id));
    out.findings
        .dedup_by(|a, b| a.finding.finding_id == b.finding.finding_id);
    out
}

/// Po rozhodnutí o nálezech okna: naučit profil hostů z toků, které nejsou v poplachu.
pub fn learn_profile(
    state: &mut BehaviorState,
    input: &BehaviorInput<'_>,
    frozen: &std::collections::HashSet<String>,
    policy: &profile::ProfilePolicy,
) {
    state.profile.learn(
        input.outbound.iter().chain(input.internal.iter()),
        frozen,
        input.now.timestamp(),
        policy,
    );
}

/// Pomocník: nález vrstvy.
#[allow(clippy::too_many_arguments)]
pub(crate) fn finding(
    kind: &str,
    actor: &str,
    service: &str,
    severity: Severity,
    confidence: Confidence,
    title: String,
    rationale: String,
    evidence: Vec<String>,
    recommendation: &str,
) -> Finding {
    let service_key = format!("{actor}/{service}");
    Finding {
        finding_id: format!("finding:{kind}:{actor}:{service_key}"),
        finding_type: kind.to_string(),
        title,
        severity,
        confidence,
        host_key: Some(actor.to_string()),
        service_key: Some(service_key),
        rationale,
        evidence,
        recommendation: recommendation.to_string(),
    }
}

/// Robustní statistika: medián a MAD (bez alokace navíc, řadí vstup).
pub(crate) fn median_mad(values: &mut [f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    values.sort_by(|a, b| a.total_cmp(b));
    let median = median_sorted(values);
    let mut dev: Vec<f64> = values.iter().map(|v| (v - median).abs()).collect();
    dev.sort_by(|a, b| a.total_cmp(b));
    (median, median_sorted(&dev))
}

fn median_sorted(values: &[f64]) -> f64 {
    let n = values.len();
    if n == 0 {
        0.0
    } else if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    }
}

/// Odstraní nejstarší položky mapy nad stropem (podle klíče `last`).
pub(crate) fn evict_oldest<K: Clone + Eq + Ord + std::hash::Hash, V>(
    map: &mut std::collections::HashMap<K, V>,
    cap: usize,
    last: impl Fn(&V) -> i64,
) -> usize {
    if map.len() <= cap {
        return 0;
    }
    // davkove 10 %, aby se nevyrazovalo v kazdem okne
    let target = cap - cap / 10;
    let mut ages: Vec<(i64, K)> = map.iter().map(|(k, v)| (last(v), k.clone())).collect();
    // krok 4: shoda casu se rozhoduje klicem; drive poradi HashMap (nahodne v kazdem
    // procesu) a beh nebyl bit po bitu reprodukovatelny
    ages.sort();
    let remove = map.len() - target;
    for (_, key) in ages.into_iter().take(remove) {
        map.remove(&key);
    }
    remove
}
