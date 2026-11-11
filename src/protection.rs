//! Chráněné nálezy (krok 7, A1; docs/diplomka/eval/impl-krok7.md).
//!
//! Chráněný nález se nikdy automaticky nezavře: kontext ho nevysvětlí ani nepodpoří,
//! paměť ho nepřevede do `AutoResolved` ani `Refuted`, žebřík ho nevyvrátí (rozhodnutí
//! jde člověku), zobrazí se hned a třída provoz ho z fronty podezření neodkloní.
//! Opora: Dodatek A.2 (c) a (d) studie 00 (nejzávažnější a nové bez doloženého
//! vysvětlení se nezavírá, „nic nenalezeno“ není vysvětlení), RQ6 Z3 (prázdný výsledek
//! není důkaz neškodnosti), A7 kroku 5.
//!
//! Třídy (P1 až P5 předregistrace):
//! - P1 novost vztahu, P2 graf, P3 signatura IDS (exploit), P5b agregace přes zdroje:
//!   podle typu, platí i pro uložený stav (typ je v klíči nálezu);
//! - P4 degradované pozorování (mezera v telemetrii, nezralý profil aktéra) a P5
//!   nejednoznačný kontext: podle pozorování v cyklu, nese je případ žebříku.

use serde::{Deserialize, Serialize};

/// Typy chráněné samy o sobě (P1, P2, P3 a agregace přes zdroje).
pub const PROTECTED_TYPES: &[&str] = &[
    "novel_persistent_peer",
    "novel_fanout",
    "novel_burst_peer",
    "pivot_chain",
    "suricata_alert",
    "egress_ids_alert",
    "ids_alert",
    "distributed_sources",
    "endpoint_alert",
];

/// Profil aktéra je pro chráněné pozorování zralý po 48 h (předregistrace A1, P4).
pub const PROFILE_MATURE_S: i64 = 48 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protection {
    Novelty,
    Graph,
    Signature,
    Aggregate,
    Endpoint,
    Degraded,
    Ambiguous,
}

impl Protection {
    pub fn label(self) -> &'static str {
        match self {
            Protection::Novelty => "novelty",
            Protection::Graph => "graph",
            Protection::Signature => "signature",
            Protection::Aggregate => "aggregate",
            Protection::Endpoint => "endpoint",
            Protection::Degraded => "degraded",
            Protection::Ambiguous => "ambiguous",
        }
    }
}

/// Ochrana podle typu (platí i pro uložený stav).
pub fn type_protection(kind: &str) -> Option<Protection> {
    match kind {
        "novel_persistent_peer" | "novel_fanout" | "novel_burst_peer" => Some(Protection::Novelty),
        "pivot_chain" => Some(Protection::Graph),
        "suricata_alert" | "egress_ids_alert" | "ids_alert" => Some(Protection::Signature),
        "distributed_sources" => Some(Protection::Aggregate),
        // krok 8: podezrely koncovy signal se nikdy automaticky nezavre
        "endpoint_alert" => Some(Protection::Endpoint),
        _ => None,
    }
}

pub fn is_protected_type(kind: &str) -> bool {
    type_protection(kind).is_some()
}

/// Signály pozorování v cyklu (P4, P5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Signals {
    /// Mezera v telemetrii nebo nezralý profil aktéra (P4).
    pub degraded: bool,
    /// Nejednoznačná identita nebo kontext (P5).
    pub ambiguous: bool,
}

/// Ochrana nálezu: typ, pak degradace, pak nejednoznačnost.
pub fn protection(kind: &str, signals: Signals) -> Option<Protection> {
    type_protection(kind)
        .or(signals.degraded.then_some(Protection::Degraded))
        .or(signals.ambiguous.then_some(Protection::Ambiguous))
}

/// P4: behaviorální nález vnitřního aktéra s profilem mladším než 48 h (nebo bez
/// profilu). Ostatní typy profil nehodnotí, tam nezralost není degradace.
pub fn immature_actor(
    profiles: &crate::behavior::profile::HostProfiles,
    kind: &str,
    actor: &str,
    now: i64,
) -> bool {
    crate::behavior::is_behavior_type(kind)
        && profiles
            .host_first(actor)
            .is_none_or(|first| now - first < PROFILE_MATURE_S)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_classes_and_signal_order() {
        assert_eq!(
            type_protection("novel_burst_peer"),
            Some(Protection::Novelty)
        );
        assert_eq!(type_protection("pivot_chain"), Some(Protection::Graph));
        assert_eq!(
            type_protection("suricata_alert"),
            Some(Protection::Signature)
        );
        assert!(type_protection("unexpected_traffic").is_none());
        for kind in crate::behavior::novelty::NOVELTY_TYPES {
            assert!(is_protected_type(kind), "{kind}");
        }
        assert_eq!(
            protection(
                "unexpected_traffic",
                Signals {
                    degraded: true,
                    ambiguous: true
                }
            ),
            Some(Protection::Degraded)
        );
        assert_eq!(
            protection(
                "unexpected_traffic",
                Signals {
                    degraded: false,
                    ambiguous: true
                }
            ),
            Some(Protection::Ambiguous)
        );
        assert!(protection("unexpected_traffic", Signals::default()).is_none());
    }

    /// Deterministický generátor pro property testy (bez nové závislosti).
    struct Gen(u64);

    impl Gen {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
        fn chance(&mut self, percent: u64) -> bool {
            self.below(100) < percent
        }
    }

    use crate::finding_memory::{
        Disposition, FindingKey, FindingMemory, FindingState, MemoryConfig, Observation,
    };
    use crate::flow_history::Recurrence;
    use crate::verify_ladder::{
        CaseInput, IntelSignal, Ladder, LadderEvidence, LadderPolicy, Liveness, Reputation, Status,
    };
    use chrono::{DateTime, Utc};

    const TYPES: [&str; 6] = [
        "novel_persistent_peer",
        "pivot_chain",
        "suricata_alert",
        "connection_timeout_burst",
        "inductive_volume_anomaly",
        "unexpected_traffic",
    ];

    fn at(cycle: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_767_571_200 + cycle * 1800, 0).unwrap()
    }

    fn forbidden(state: FindingState) -> bool {
        matches!(state, FindingState::AutoResolved | FindingState::Refuted)
    }

    /// Paměť: náhodné pozorování, vysvětlení, vyvrácení, ruční zásahy a restarty.
    /// Chráněný klíč nikdy není `AutoResolved` ani `Refuted` a chráněné pozorování
    /// nikdy nedostane `AutoResolved`.
    #[test]
    fn property_memory_never_auto_closes_protected() {
        let cfg = MemoryConfig {
            protect: true,
            ..MemoryConfig::default()
        };
        for seed in 1..=60u64 {
            let mut g = Gen(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            crate::finding_memory::migrate(&conn).unwrap();
            let mut memory = FindingMemory::load(&conn, cfg).unwrap();
            for cycle in 0..300i64 {
                let kind = TYPES[g.below(TYPES.len() as u64) as usize];
                let host = format!("10.0.0.{}", g.below(4));
                let key = FindingKey::new(&host, kind, "tcp/443");
                let sources: Vec<String> = (0..g.below(3))
                    .map(|i| format!("203.0.113.{}", i + g.below(3)))
                    .collect();
                let signal = g.chance(20);
                let explanation = g.chance(50).then_some("backup (test)");
                let disposition = memory.observe(
                    &Observation {
                        key: key.clone(),
                        severity: crate::model::Severity::Medium,
                        count: g.below(200) as u32,
                        sources: &sources,
                        at: at(cycle),
                        volume_explained: g.chance(50),
                        protected: signal,
                    },
                    explanation,
                );
                if is_protected_type(kind) || signal {
                    assert!(
                        !matches!(disposition, Disposition::AutoResolved(_)),
                        "seed {seed} cyklus {cycle}: {kind}"
                    );
                }
                match g.below(10) {
                    0 => {
                        memory.refute(&key, "test", at(cycle));
                    }
                    1 => {
                        memory.close(&key, "clovek", at(cycle));
                    }
                    2 => {
                        memory.flush(&mut conn).unwrap();
                        memory = FindingMemory::load(&conn, cfg).unwrap();
                    }
                    3 => memory.sweep(at(cycle)),
                    _ => {}
                }
                for kind in TYPES.iter().filter(|k| is_protected_type(k)) {
                    for h in 0..4 {
                        let key = FindingKey::new(&format!("10.0.0.{h}"), kind, "tcp/443");
                        if let Some(entry) = memory.get(&key) {
                            assert!(!forbidden(entry.state), "seed {seed}: {key:?}");
                        }
                    }
                }
            }
        }
    }

    /// Prostředí žebříku s náhodnými, převážně neškodnými důkazy (i kontext a zvyk
    /// profilu, které skutečná brána chráněným případům nedá: nejhorší případ).
    struct BenignEnv(u64);

    impl LadderEvidence for BenignEnv {
        fn recurrence(&self, _: &str, _: f64) -> Recurrence {
            Recurrence::Seen { days: 5 }
        }
        fn context(&self, _: &CaseInput) -> Option<String> {
            self.0.is_multiple_of(2).then_some("backup".to_string())
        }
        fn reputation(&self, _: &str) -> Reputation {
            Reputation::Good("feed".into())
        }
        fn intel(&self, _: &CaseInput) -> IntelSignal {
            IntelSignal::NothingKnown
        }
        fn device(&self, _: &str) -> Option<crate::device_class::DeviceClass> {
            None
        }
        fn peers(&self, _: &CaseInput) -> Option<(usize, usize)> {
            Some((9, 10))
        }
        fn liveness(&mut self, _: &CaseInput) -> Liveness {
            Liveness::Down
        }
        fn neighbors(&self, _: &str) -> Vec<String> {
            Vec::new()
        }
        fn in_scope(&self, ip: &str) -> bool {
            ip.starts_with("10.")
        }
        fn suspicious_on(&self, _: &str) -> usize {
            0
        }
        fn profile(&self, _: &CaseInput) -> crate::behavior::profile::ProfileVerdict {
            crate::behavior::profile::ProfileVerdict::Established { since: 0, days: 9 }
        }
    }

    fn case(kind: &str, host: &str, protected: bool, sources: &[&str]) -> CaseInput {
        CaseInput {
            key: FindingKey::new(host, kind, "tcp/443"),
            finding_id: format!("finding:{kind}:{host}"),
            finding_type: kind.to_string(),
            host_ip: host.to_string(),
            port: Some(443),
            sources: sources.iter().map(|s| s.to_string()).collect(),
            volume: 10.0,
            history_key: Some(format!("{host}/tcp/443#flows")),
            high_impact: false,
            prior: 0.15,
            protected,
        }
    }

    /// Žebřík: s `protect` žádný chráněný případ (typ nebo signál) nedostane `Refuted`,
    /// ani při samých neškodných důkazech; nechráněný se vyvrátit dál smí.
    #[test]
    fn property_ladder_never_refutes_protected() {
        let mut refuted_plain = 0;
        for seed in 1..=40u64 {
            let mut g = Gen(seed.wrapping_mul(0xD1B5_4A32_D192_ED03));
            let mut ladder = Ladder::new(
                LadderPolicy {
                    protect: true,
                    profile: true,
                    ..LadderPolicy::default()
                },
                seed,
            );
            let mut env = BenignEnv(seed);
            for cycle in 0..40u64 {
                for _ in 0..g.below(4) {
                    let kind = TYPES[g.below(TYPES.len() as u64) as usize];
                    let host = format!("10.0.1.{}", g.below(20));
                    let input = case(kind, &host, g.chance(25), &["198.51.100.7"]);
                    ladder.open(input, cycle);
                }
                if g.chance(10) {
                    let json = serde_json::to_string(&ladder).unwrap();
                    ladder = serde_json::from_str(&json).unwrap();
                }
                for decision in ladder.step(cycle, &mut env) {
                    if decision.protected {
                        assert_ne!(decision.status, Status::Refuted, "seed {seed}");
                    }
                    if is_protected_type(&decision.finding_type) {
                        assert_ne!(decision.status, Status::Refuted, "seed {seed}");
                    }
                    refuted_plain += (decision.status == Status::Refuted) as u32;
                }
            }
        }
        assert!(refuted_plain > 0, "kontrola: nechranene pripady se vyvraci");
    }

    /// Přehrání uložených uzavřených případů: stav paměti a žebříku vzniklý bez
    /// ochrany (chráněné typy `AutoResolved` a `Refuted`, případy s neškodným
    /// kontextem) projde načtením, pozorováním, krokem žebříku a obnovením.
    #[test]
    fn replayed_closed_protected_cases_never_auto_close() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::finding_memory::migrate(&conn).unwrap();
        let loose = MemoryConfig::default();
        let mut memory = FindingMemory::load(&conn, loose).unwrap();
        let mut keys = Vec::new();
        for (i, kind) in TYPES.iter().enumerate() {
            let key = FindingKey::new("10.0.2.1", kind, "tcp/443");
            let explanation = (i % 2 == 0).then_some("patch_window (stary stav)");
            memory.observe(
                &Observation {
                    key: key.clone(),
                    severity: crate::model::Severity::Medium,
                    count: 5,
                    sources: &[],
                    at: at(0),
                    volume_explained: false,
                    protected: false,
                },
                explanation,
            );
            if i % 2 == 1 {
                assert!(memory.refute(&key, "stary zebrik", at(1)));
            }
            keys.push(key);
        }
        assert!(
            keys.iter()
                .filter(|k| is_protected_type(&k.finding_type))
                .all(|k| forbidden(memory.get(k).unwrap().state)),
            "vychozi stav: chranene typy jsou zakazane"
        );
        memory.flush(&mut conn).unwrap();
        let mut ladder = Ladder::new(LadderPolicy::default(), 7);
        for kind in TYPES {
            ladder.open(case(kind, "10.0.2.1", false, &["198.51.100.9"]), 0);
        }
        let mut env = BenignEnv(0);
        for cycle in 0..3 {
            ladder.step(cycle, &mut env);
        }
        let stored = serde_json::to_string(&ladder).unwrap();

        // obnoveni s ochranou
        let strict = MemoryConfig {
            protect: true,
            ..MemoryConfig::default()
        };
        let mut memory = FindingMemory::load(&conn, strict).unwrap();
        for key in keys.iter().filter(|k| is_protected_type(&k.finding_type)) {
            assert_eq!(memory.get(key).unwrap().state, FindingState::Closed);
            let disposition = memory.observe(
                &Observation {
                    key: key.clone(),
                    severity: crate::model::Severity::Medium,
                    count: 5,
                    sources: &[],
                    at: at(10),
                    volume_explained: false,
                    protected: false,
                },
                Some("patch_window"),
            );
            assert_eq!(disposition, Disposition::Reopened, "{key:?}");
            assert!(!memory.refute(key, "zebrik", at(10)));
        }
        let mut ladder: Ladder = serde_json::from_str(&stored).unwrap();
        ladder.policy.protect = true;
        ladder.reset_forbidden_novelty_evidence();
        for kind in TYPES {
            ladder.open(case(kind, "10.0.2.2", false, &["198.51.100.9"]), 10);
        }
        for cycle in 10..30 {
            for decision in ladder.step(cycle, &mut env) {
                if is_protected_type(&decision.finding_type) {
                    assert_ne!(decision.status, Status::Refuted, "{decision:?}");
                }
            }
        }
        memory.flush(&mut conn).unwrap();
        let audit = crate::finding_memory::read_audit(&conn).unwrap();
        assert!(
            audit
                .iter()
                .any(|(_, action, ..)| action == "protect_reset")
        );
        assert!(
            audit
                .iter()
                .any(|(_, action, ..)| action == "protect_refuse")
        );
    }

    #[test]
    fn immature_profile_counts_only_for_behavior_types() {
        let profiles = crate::behavior::profile::HostProfiles::default();
        assert!(immature_actor(&profiles, "beacon_periodic", "10.0.0.5", 0));
        assert!(!immature_actor(
            &profiles,
            "packet_rate_spike",
            "10.0.0.5",
            0
        ));
    }
}
