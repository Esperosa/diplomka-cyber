//! Viditelnost odchozího provozu (krok 3A; audit 01 A10 a R2, studie 03 §1 bod 7).
//!
//! Parsery dřív zahazovaly toky a alerty s cílem mimo rozsah (`dst ∈ scope`). Exfiltrace,
//! C2, tunely i mining mají cíl vždy venku, takže byly slepé (zdrojové pořadí
//! exfiltrace 0,2 %, soak v2b). Režim `SrcOrDst` drží tok, když je v rozsahu zdroj NEBO
//! cíl, a směr toku (`FlowDirection`) říká, která strana je uvnitř. Pravidla závislá na
//! inventáři (neznámá služba, timeouty služby) dál dostávají jen toky s vnitřním cílem;
//! odchozí toky jdou do behaviorální vrstvy (`crate::behavior`).
//!
//! Objem: odchozí toky můžou být většina provozu (prohlížení webu). Nad stropem okna se
//! vzorkuje KONZISTENTNĚ PO DVOJICI (zdroj, cíl, port): dvojice je buď celá, nebo vůbec,
//! a úrovně vzorkování jsou vnořené (dvojice držená při 1/4 je držená i při 1/2), takže
//! časová řada dvojice pro beaconing zůstane souvislá. Strop na dvojici brání tomu, aby
//! jedna hlučná dvojice spolkla celý rozpočet. Legacy režim (`DstOnly`) je beze změny.

use std::{collections::HashMap, net::IpAddr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::passive::ConnectionObservation;

/// Které toky parser drží.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeMode {
    /// Legacy: jen cíl v rozsahu (výchozí, beze změny výstupu).
    #[default]
    DstOnly,
    /// Krok 3A: zdroj nebo cíl v rozsahu, se směrem.
    SrcOrDst,
}

/// Směr toku vůči rozsahu (zdroj, cíl).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowDirection {
    /// Zvenku dovnitř (cíl v rozsahu, zdroj venku nebo neznámý).
    Inbound,
    /// Zevnitř ven (zdroj v rozsahu, cíl venku): C2, exfiltrace, tunely.
    Outbound,
    /// Obě strany v rozsahu (laterální pohyb, správa).
    Internal,
    /// Ani jedna strana v rozsahu (tranzit, mimo zájem).
    External,
}

fn contains(scope: &[IpNet], ip: &str) -> bool {
    ip.parse::<IpAddr>()
        .ok()
        .is_some_and(|addr| scope.iter().any(|net| net.contains(&addr)))
}

pub fn direction(scope: &[IpNet], src: Option<&str>, dst: &str) -> FlowDirection {
    let src_in = src.is_some_and(|s| contains(scope, s));
    match (src_in, contains(scope, dst)) {
        (true, true) => FlowDirection::Internal,
        (false, true) => FlowDirection::Inbound,
        (true, false) => FlowDirection::Outbound,
        (false, false) => FlowDirection::External,
    }
}

/// Drží parser záznam s tímto zdrojem a cílem?
pub fn keep(mode: ScopeMode, scope: &[IpNet], src: Option<&str>, dst: &str) -> bool {
    if dst.is_empty() {
        return false;
    }
    match mode {
        ScopeMode::DstOnly => contains(scope, dst),
        ScopeMode::SrcOrDst => direction(scope, src, dst) != FlowDirection::External,
    }
}

/// Meze objemu odchozích toků v jednom okně (paměť a CPU behaviorální vrstvy).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct EgressPolicy {
    /// Nejvýš tolik odchozích toků za okno; nad stropem vnořené vzorkování po dvojici.
    pub max_outbound_per_window: usize,
    /// Nejvýš tolik toků jedné dvojice za okno (zbytek se jen započítá).
    pub max_per_pair: usize,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            max_outbound_per_window: 200_000,
            max_per_pair: 2_000,
        }
    }
}

/// Výsledek vzorkování odchozích toků okna.
#[derive(Debug, Default)]
pub struct EgressSample {
    pub kept: Vec<ConnectionObservation>,
    pub seen: u64,
    pub dropped: u64,
    /// 2^-level = podíl držených dvojic (0 = bez vzorkování).
    pub level: u32,
}

fn pair_hash(o: &ConnectionObservation) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    let mut feed = |bytes: &[u8]| {
        for b in bytes {
            h = (h ^ *b as u64).wrapping_mul(0x100_0000_01b3);
        }
    };
    feed(o.src_ip.as_deref().unwrap_or("").as_bytes());
    feed(o.dst_ip.as_bytes());
    feed(o.proto.as_bytes());
    feed(&o.dst_port.unwrap_or(0).to_le_bytes());
    // finalizace (splitmix), aby nizke bity nebyly korelovane s adresou
    h = (h ^ (h >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    h = (h ^ (h >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    h ^ (h >> 31)
}

/// Vzorkuje odchozí toky okna podle `policy` (deterministicky, bez náhody).
pub fn sample_outbound(flows: Vec<ConnectionObservation>, policy: &EgressPolicy) -> EgressSample {
    let seen = flows.len() as u64;
    let mut per_pair: HashMap<u64, usize> = HashMap::new();
    let mut capped = Vec::with_capacity(flows.len().min(policy.max_outbound_per_window));
    let mut dropped = 0u64;
    let mut hashes = Vec::with_capacity(flows.len());
    for flow in flows {
        let h = pair_hash(&flow);
        let n = per_pair.entry(h).or_default();
        if *n >= policy.max_per_pair {
            dropped += 1;
            continue;
        }
        *n += 1;
        hashes.push(h);
        capped.push(flow);
    }
    let mut level = 0u32;
    let cap = policy.max_outbound_per_window.max(1);
    // vnorene urovne: pri urovni L zustava dvojice, jejiz hash ma L nejnizsich bitu nulovych
    while level < 32 {
        let mask = (1u64 << level) - 1;
        let kept = hashes.iter().filter(|h| *h & mask == 0).count();
        if kept <= cap {
            break;
        }
        level += 1;
    }
    let mask = if level == 0 { 0 } else { (1u64 << level) - 1 };
    let kept: Vec<ConnectionObservation> = capped
        .into_iter()
        .zip(hashes)
        .filter_map(|(flow, h)| (h & mask == 0).then_some(flow))
        .collect();
    dropped += seen - dropped - kept.len() as u64;
    EgressSample {
        kept,
        seen,
        dropped,
        level,
    }
}

/// Rozdělení toků okna podle směru (krok 3A): vnitřní cíl (stávající detektory),
/// odchozí a čistě vnitřní (graf). Tranzit se zahodí.
#[derive(Debug, Default)]
pub struct SplitFlows {
    /// Cíl v rozsahu (dovnitř i uvnitř): vstup stávajících detektorů beze změny.
    pub to_scope: Vec<ConnectionObservation>,
    /// Zdroj uvnitř, cíl venku (po vzorkování).
    pub outbound: Vec<ConnectionObservation>,
    /// Obě strany v rozsahu (podmnožina `to_scope`, pro graf spojení).
    pub internal: Vec<ConnectionObservation>,
    pub outbound_seen: u64,
    pub outbound_dropped: u64,
    pub sample_level: u32,
}

pub fn split_flows(
    flows: impl IntoIterator<Item = ConnectionObservation>,
    scope: &[IpNet],
    policy: &EgressPolicy,
) -> SplitFlows {
    let mut out = SplitFlows::default();
    let mut outbound = Vec::new();
    for flow in flows {
        match direction(scope, flow.src_ip.as_deref(), &flow.dst_ip) {
            FlowDirection::Internal => {
                out.internal.push(flow.clone());
                out.to_scope.push(flow);
            }
            FlowDirection::Inbound => out.to_scope.push(flow),
            FlowDirection::Outbound => outbound.push(flow),
            FlowDirection::External => {}
        }
    }
    let sample = sample_outbound(outbound, policy);
    out.outbound = sample.kept;
    out.outbound_seen = sample.seen;
    out.outbound_dropped = sample.dropped;
    out.sample_level = sample.level;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn scope() -> Vec<IpNet> {
        vec!["10.0.0.0/24".parse().unwrap()]
    }

    fn flow(src: &str, dst: &str, port: u16) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            src_ip: Some(src.to_string()),
            src_port: Some(40000),
            dst_ip: dst.to_string(),
            proto: "tcp".to_string(),
            dst_port: Some(port),
            duration_s: Some(1.0),
            orig_bytes: Some(100),
            resp_bytes: Some(100),
            total_bytes: Some(200),
            orig_pkts: Some(1),
            resp_pkts: Some(1),
            total_pkts: Some(2),
            conn_state: Some("SF".to_string()),
            history: None,
            missed_bytes: Some(0),
        }
    }

    #[test]
    fn direction_and_keep_distinguish_inside_source() {
        let s = scope();
        assert_eq!(
            direction(&s, Some("10.0.0.5"), "8.8.8.8"),
            FlowDirection::Outbound
        );
        assert_eq!(
            direction(&s, Some("8.8.8.8"), "10.0.0.5"),
            FlowDirection::Inbound
        );
        assert_eq!(direction(&s, None, "10.0.0.5"), FlowDirection::Inbound);
        assert_eq!(
            direction(&s, Some("10.0.0.4"), "10.0.0.5"),
            FlowDirection::Internal
        );
        // legacy drzi jen cil v rozsahu (beze zmeny), novy rezim i odchozi
        assert!(!keep(ScopeMode::DstOnly, &s, Some("10.0.0.5"), "8.8.8.8"));
        assert!(keep(ScopeMode::SrcOrDst, &s, Some("10.0.0.5"), "8.8.8.8"));
        assert!(!keep(ScopeMode::SrcOrDst, &s, Some("1.1.1.1"), "8.8.8.8"));
        assert!(!keep(ScopeMode::SrcOrDst, &s, Some("10.0.0.5"), ""));
    }

    #[test]
    fn sampling_is_pair_consistent_nested_and_capped() {
        let mut flows = Vec::new();
        for host in 0..50u32 {
            for dst in 0..40u32 {
                for _ in 0..5 {
                    flows.push(flow(
                        &format!("10.0.0.{}", host + 1),
                        &format!("93.184.{}.{}", dst, host),
                        443,
                    ));
                }
            }
        }
        let policy = EgressPolicy {
            max_outbound_per_window: 2_500,
            max_per_pair: 2_000,
        };
        let sample = sample_outbound(flows.clone(), &policy);
        assert!(sample.kept.len() <= 2_500 && sample.level >= 2);
        assert_eq!(sample.seen, 10_000);
        assert_eq!(sample.dropped + sample.kept.len() as u64, 10_000);
        // kazda drzena dvojice je cela (5 toku)
        let mut counts: HashMap<(String, String), usize> = HashMap::new();
        for f in &sample.kept {
            *counts
                .entry((f.src_ip.clone().unwrap(), f.dst_ip.clone()))
                .or_default() += 1;
        }
        assert!(counts.values().all(|n| *n == 5));
        // vnorenost: dvojice drzene pri prisnejsim stropu jsou podmnozinou
        let tighter = sample_outbound(
            flows,
            &EgressPolicy {
                max_outbound_per_window: 1_000,
                max_per_pair: 2_000,
            },
        );
        for f in &tighter.kept {
            assert!(counts.contains_key(&(f.src_ip.clone().unwrap(), f.dst_ip.clone())));
        }
    }

    #[test]
    fn per_pair_cap_limits_one_noisy_pair() {
        let flows: Vec<_> = (0..5_000)
            .map(|_| flow("10.0.0.9", "93.184.0.1", 443))
            .collect();
        let sample = sample_outbound(flows, &EgressPolicy::default());
        assert_eq!(sample.kept.len(), 2_000);
        assert_eq!(sample.dropped, 3_000);
    }

    #[test]
    fn split_routes_by_direction() {
        let flows = vec![
            flow("10.0.0.2", "10.0.0.3", 445),
            flow("8.8.4.4", "10.0.0.3", 443),
            flow("10.0.0.2", "8.8.4.4", 443),
            flow("8.8.4.4", "1.1.1.1", 443),
        ];
        let split = split_flows(flows, &scope(), &EgressPolicy::default());
        assert_eq!(split.to_scope.len(), 2);
        assert_eq!(split.internal.len(), 1);
        assert_eq!(split.outbound.len(), 1);
        assert_eq!(split.outbound_seen, 1);
    }
}
