//! Obecná novost vztahů hostu (krok 6, kandidáti 4 a 5; docs/diplomka/eval/impl-krok6.md).
//!
//! Detektory nezávislé na rodině útoku: neptají se, JAK provoz vypadá (perioda, objem,
//! port), jen jestli zralý host začal dělat něco, co o něm profil nikdy neviděl.
//!
//! - `novel_persistent_peer`: zralý vnitřní host opakovaně a úspěšně komunikuje s
//!   vnějším cílem, který profil hostu nezná (ani jako kandidáta) a který nezná flotila
//!   (nejvýš `fleet_max` vnitřních hostů za 7 dní). Poplach po `persist_windows`
//!   různých oknech během `persist_span_s`. Opora: vzácný cíl a automatizovaná
//!   komunikace jako znak časné infekce (Oprea a kol., DSN 2015); RQ4 Z10 (nová hrana
//!   je rys); časování se nezkoumá, takže rychlý i nepravidelný maják projde stejně.
//! - `novel_fanout`: zralý host má během `fanout_span_s` aspoň `fanout_min` nových
//!   úspěšných vnitřních vazeb (cíl, protokol, port), které profil nezná. Součet
//!   drobných odchylek přes okna místo jednoho okna (pomalé tempo; Hopper RQ4-047:
//!   nová hrana je rys, poplach až kumulace).
//!
//! Pojistky: host bez zralého profilu (`mature_s`) se nehodnotí (výchozí chování nového
//! hostu se teprve učí); dvojice s poplachem se v profilu poznamená a nikdy se nestane
//! zvykem (gating RQ2 Z3), takže se poplach sám neumlčí naučením; kontext ani profil
//! nový vztah nezavřou (A7 kroku 5: neznámé a nové se nezavírá bez doloženého
//! vysvětlení). Riziko: legitimní nová služba jednoho hostu (`saas_adoption` v
//! drženém světě), legitimní nový monitorovací server; měří se.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::{
    behavior::{
        BehaviorFinding, beacon::Prevalence, beacon::target_key, evict_oldest, finding,
        profile::HostProfiles,
    },
    model::{Confidence, Severity},
    passive::ConnectionObservation,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NoveltyThresholds {
    /// Profil hostu je zralý po tolika sekundách (dřív se novost nehodnotí).
    pub mature_s: i64,
    pub persist_windows: usize,
    pub persist_span_s: i64,
    /// Cíl zná nejvýš tolik vnitřních hostů (víc = flotila, software).
    pub fleet_max: usize,
    /// Mez nových vnitřních vazeb; 0 = `novel_fanout` vypnuto.
    pub fanout_min: usize,
    pub fanout_span_s: i64,
    /// Strop nových vnitřních vazeb držených na hostitele (nejméně `fanout_min`, aby
    /// překročení prahu zůstalo vidět); další vazby v okně se nepřidají.
    pub fanout_cap: usize,
    pub idle_s: i64,
    pub max_pairs: usize,
    pub max_hosts: usize,
}

impl Default for NoveltyThresholds {
    /// Volba autora před prvním měřením (impl-krok6.md, B5). Jediná povolená úprava na
    /// ladicích seedech (impl-krok6.md, C): `novel_fanout` vypnuto (`fanout_min` 8 → 0),
    /// protože přidal 9,3 zobrazených FP na síť-den (+44 %) při zisku jen u lateral.
    fn default() -> Self {
        Self {
            mature_s: 48 * 3600,
            persist_windows: 6,
            persist_span_s: 24 * 3600,
            fleet_max: 2,
            fanout_min: 0,
            fanout_span_s: 6 * 3600,
            fanout_cap: 256,
            idle_s: 3 * 86_400,
            max_pairs: 200_000,
            max_hosts: 50_000,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct NewPair {
    last: i64,
    /// Začátky oken s úspěšným spojením (vzestupně, nejvýš `2 × persist_windows`).
    windows: Vec<i64>,
    alarmed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Fanout {
    last: i64,
    /// (první výskyt, vztah `cíl|proto/port`) nových vnitřních vazeb.
    recent: Vec<(i64, String)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct NoveltyState {
    pairs: HashMap<String, NewPair>,
    fanout: HashMap<String, Fanout>,
    pub evicted: u64,
    pub alarms: u64,
}

/// Typy novosti vztahů. Pojistka A7: kontext je nevysvětlí ani nepodpoří a zvyk
/// profilu (hostu ani flotily) není neškodný důkaz žebříku (review kola 1, S2 a S3).
pub const NOVELTY_TYPES: &[&str] = &["novel_persistent_peer", "novel_fanout"];

pub fn is_novelty_type(kind: &str) -> bool {
    NOVELTY_TYPES.contains(&kind)
}

fn succeeded(flow: &ConnectionObservation) -> bool {
    let state = flow.conn_state.as_deref().unwrap_or("");
    !matches!(state, "S0" | "REJ" | "RSTOS0" | "SH" | "RSTRH") && flow.resp_bytes.unwrap_or(0) > 0
}

type Rel = (String, String, String, u16);

fn successful_pairs(flows: &[ConnectionObservation]) -> BTreeSet<Rel> {
    flows
        .iter()
        .filter(|f| succeeded(f))
        .filter_map(|f| {
            Some((
                f.src_ip.clone()?,
                f.dst_ip.clone(),
                f.proto.clone(),
                f.dst_port?,
            ))
        })
        .collect()
}

fn mature(profile: &HostProfiles, host: &str, now: i64, t: &NoveltyThresholds) -> bool {
    profile
        .host_first(host)
        .is_some_and(|first| now - first >= t.mature_s)
}

/// Jedno okno. Volá se před učením profilu z tohoto okna (profil zná jen minulost).
pub fn detect(
    state: &mut NoveltyState,
    profile: &HostProfiles,
    prevalence: &Prevalence,
    t: &NoveltyThresholds,
    outbound: &[ConnectionObservation],
    internal: &[ConnectionObservation],
    now: i64,
) -> Vec<BehaviorFinding> {
    let mut out = Vec::new();
    // --- nova trvala vazba ven ---
    for (src, dst, proto, port) in successful_pairs(outbound) {
        let key = format!("{src}|{dst}|{proto}/{port}");
        let pair = match state.pairs.get_mut(&key) {
            Some(pair) => pair,
            None => {
                if profile.knows(&src, &dst, &proto, port) || !mature(profile, &src, now, t) {
                    continue;
                }
                state.pairs.entry(key).or_default()
            }
        };
        pair.last = now;
        if pair.windows.last() != Some(&now) {
            pair.windows.push(now);
        }
        let cap = 2 * t.persist_windows.max(1);
        if pair.windows.len() > cap {
            let drop = pair.windows.len() - cap;
            pair.windows.drain(..drop);
        }
        let active = pair
            .windows
            .iter()
            .filter(|w| now - **w < t.persist_span_s)
            .count();
        if !pair.alarmed {
            let (fleet, _) = prevalence.of(&target_key(&dst, &proto, port), now);
            if active < t.persist_windows || fleet > t.fleet_max {
                continue;
            }
            pair.alarmed = true;
            state.alarms += 1;
        }
        out.push(BehaviorFinding {
            finding: finding(
                "novel_persistent_peer",
                &src,
                &format!("out/{dst}/{proto}/{port}"),
                Severity::Medium,
                Confidence::Low,
                format!("Host {src} opakovane komunikuje s novym vnejsim cilem {dst}:{port}"),
                format!(
                    "Vazba neni v profilu hostu (ani jako kandidat), cil nezna flotila; uspesna spojeni v {active} oknech za {} h. Pravidlo heuristika-behavior:novelty-peer@v1 (obecny priznak, Oprea a kol. 2015, RQ4 Z10).",
                    t.persist_span_s / 3600
                ),
                vec![format!("{src} -> {dst}:{port}/{proto}: {active} oken")],
                "Overit, jakou sluzbu host nove pouziva (proces, uzivatel, zmena); nezname a nove se automaticky nezavira.",
            ),
            sources: vec![dst.clone()],
            targets: vec![(dst, port)],
            count: active as u32,
            actor: src,
        });
    }
    // --- nove vnitrni vazby hostu ---
    let mut fresh: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let internal = if t.fanout_min == 0 { &[][..] } else { internal };
    for (src, dst, proto, port) in successful_pairs(internal) {
        if src == dst || profile.knows(&src, &dst, &proto, port) || !mature(profile, &src, now, t) {
            continue;
        }
        fresh
            .entry(src)
            .or_default()
            .push(format!("{dst}|{proto}/{port}"));
    }
    for (src, relations) in fresh {
        let host = state.fanout.entry(src.clone()).or_default();
        host.last = now;
        host.recent.retain(|(at, _)| now - at < t.fanout_span_s);
        // deterministicky strop (vztahy jdou serazene z BTreeSet), prah zustava dosazitelny
        let cap = t.fanout_cap.max(t.fanout_min);
        for relation in relations {
            if host.recent.len() >= cap {
                break;
            }
            if !host.recent.iter().any(|(_, r)| *r == relation) {
                host.recent.push((now, relation));
            }
        }
        if host.recent.len() < t.fanout_min {
            continue;
        }
        state.alarms += 1;
        let targets: Vec<(String, u16)> = host
            .recent
            .iter()
            .filter_map(|(_, r)| {
                let (ip, rest) = r.split_once('|')?;
                let port = rest.rsplit('/').next()?.parse().ok()?;
                Some((ip.to_string(), port))
            })
            .collect();
        let mut peers: Vec<String> = targets.iter().map(|(ip, _)| ip.clone()).collect();
        peers.dedup();
        out.push(BehaviorFinding {
            finding: finding(
                "novel_fanout",
                &src,
                "new/internal/0",
                Severity::Medium,
                Confidence::Low,
                format!(
                    "Host {src} ma {} novych vnitrnich vazeb za {} h",
                    host.recent.len(),
                    t.fanout_span_s / 3600
                ),
                "Vazby nejsou v profilu hostu (ani jako kandidati); soucet drobnych odchylek pres okna. Pravidlo heuristika-behavior:novelty-fanout@v1 (obecny priznak, RQ4-047).".to_string(),
                host.recent
                    .iter()
                    .take(5)
                    .map(|(_, r)| format!("{src} -> {r}"))
                    .collect(),
                "Overit, proc host nove kontaktuje vnitrni sluzby (nasazeni, sprava, pohyb v siti); nezname a nove se automaticky nezavira.",
            ),
            sources: peers.into_iter().take(5).collect(),
            targets,
            count: host.recent.len() as u32,
            actor: src,
        });
    }
    state.pairs.retain(|_, p| now - p.last <= t.idle_s);
    state
        .fanout
        .retain(|_, h| now - h.last <= t.fanout_span_s.max(t.idle_s));
    state.evicted += evict_oldest(&mut state.pairs, t.max_pairs, |p| p.last) as u64;
    state.evicted += evict_oldest(&mut state.fanout, t.max_hosts, |h| h.last) as u64;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behavior::profile::ProfilePolicy;
    use chrono::{TimeZone, Utc};
    use std::collections::HashSet;

    const T0: i64 = 1_700_006_400;

    fn conn(src: &str, dst: &str, port: u16, at: i64) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: Utc.timestamp_opt(at, 0).unwrap(),
            src_ip: Some(src.to_string()),
            src_port: Some(40000),
            dst_ip: dst.to_string(),
            proto: "tcp".to_string(),
            dst_port: Some(port),
            duration_s: Some(1.0),
            orig_bytes: Some(300),
            resp_bytes: Some(300),
            total_bytes: Some(600),
            orig_pkts: Some(2),
            resp_pkts: Some(2),
            total_pkts: Some(4),
            conn_state: Some("SF".to_string()),
            history: None,
            missed_bytes: Some(0),
        }
    }

    /// Zralý profil hostu: 3 dny běžného provozu na známý cíl.
    fn mature_profile(host: &str) -> HostProfiles {
        let mut p = HostProfiles::default();
        let policy = ProfilePolicy::default();
        for w in 0..(3 * 48) {
            let at = T0 + w * 1800;
            p.learn(
                [conn(host, "198.51.100.1", 443, at)].iter(),
                &HashSet::new(),
                at,
                &policy,
            );
        }
        p
    }

    #[test]
    fn new_external_peer_alarms_after_persistence_not_before() {
        let profile = mature_profile("10.0.0.5");
        let prevalence = Prevalence::default();
        let t = NoveltyThresholds::default();
        let mut state = NoveltyState::default();
        let start = T0 + 3 * 86_400;
        let mut first_alarm = None;
        for w in 0..8 {
            let now = start + w * 1800;
            // nepravidelne casy uvnitr okna: perioda se nezkouma
            let flows = [conn("10.0.0.5", "203.0.113.9", 8443, now + (w * 37) % 1700)];
            let found = detect(&mut state, &profile, &prevalence, &t, &flows, &[], now);
            if !found.is_empty() && first_alarm.is_none() {
                first_alarm = Some(w);
                assert_eq!(found[0].finding.finding_type, "novel_persistent_peer");
                assert_eq!(found[0].actor, "10.0.0.5");
            }
        }
        assert_eq!(first_alarm, Some(5), "poplach v 6. okne");
        // znamy cil profilu: nikdy
        let mut state = NoveltyState::default();
        for w in 0..10 {
            let now = start + w * 1800;
            let flows = [conn("10.0.0.5", "198.51.100.1", 443, now)];
            assert!(detect(&mut state, &profile, &prevalence, &t, &flows, &[], now).is_empty());
        }
    }

    #[test]
    fn immature_host_and_fleet_target_do_not_alarm() {
        let t = NoveltyThresholds::default();
        let prevalence = Prevalence::default();
        // host bez zraleho profilu
        let young = HostProfiles::default();
        let mut state = NoveltyState::default();
        for w in 0..10 {
            let now = T0 + w * 1800;
            let flows = [conn("10.0.0.7", "203.0.113.9", 443, now)];
            assert!(detect(&mut state, &young, &prevalence, &t, &flows, &[], now).is_empty());
        }
        // cil, na ktery mluvi flotila (5 hostu): software, ne novost hostu
        let profile = mature_profile("10.0.0.5");
        let mut fleet = Prevalence::default();
        let start = T0 + 3 * 86_400;
        let shared: Vec<ConnectionObservation> = (1..=5)
            .map(|i| conn(&format!("10.0.0.{i}"), "203.0.113.50", 443, start))
            .collect();
        fleet.observe(&shared, start);
        let mut state = NoveltyState::default();
        for w in 0..10 {
            let now = start + w * 1800;
            let flows = [conn("10.0.0.5", "203.0.113.50", 443, now)];
            assert!(detect(&mut state, &profile, &fleet, &t, &flows, &[], now).is_empty());
        }
    }

    #[test]
    fn slow_internal_fanout_accumulates_across_windows() {
        let profile = mature_profile("10.0.0.5");
        let prevalence = Prevalence::default();
        // vychozi stav po kroku 6 C: novel_fanout vypnuto
        let off = NoveltyThresholds::default();
        assert_eq!(off.fanout_min, 0);
        let mut quiet = NoveltyState::default();
        let burst: Vec<ConnectionObservation> = (0..20)
            .map(|k| {
                conn(
                    "10.0.0.5",
                    &format!("10.0.9.{}", k + 1),
                    445,
                    T0 + 3 * 86_400,
                )
            })
            .collect();
        assert!(
            detect(
                &mut quiet,
                &profile,
                &prevalence,
                &off,
                &[],
                &burst,
                T0 + 3 * 86_400
            )
            .is_empty()
        );
        let t = NoveltyThresholds {
            fanout_min: 8,
            ..Default::default()
        };
        let mut state = NoveltyState::default();
        let start = T0 + 3 * 86_400;
        let mut alarmed_at = None;
        // dve nove vnitrni vazby za okno: zadne okno samo nestaci, za 4 okna ano
        for w in 0..6 {
            let now = start + w * 1800;
            let flows: Vec<ConnectionObservation> = (0..2)
                .map(|k| conn("10.0.0.5", &format!("10.0.1.{}", w * 2 + k + 1), 445, now))
                .collect();
            let found = detect(&mut state, &profile, &prevalence, &t, &[], &flows, now);
            if alarmed_at.is_none() && !found.is_empty() {
                alarmed_at = Some(w);
                assert_eq!(found[0].finding.finding_type, "novel_fanout");
                assert_eq!(found[0].targets.len(), 8);
            }
        }
        assert_eq!(alarmed_at, Some(3));
        // stare vazby po 6 h vypadnou ze souctu
        let later = start + 20 * 3600;
        let flows = [conn("10.0.0.5", "10.0.2.1", 445, later)];
        assert!(detect(&mut state, &profile, &prevalence, &t, &[], &flows, later).is_empty());
    }

    /// Review kola 1 (S5): vektor novych vazeb na hostitele ma strop, poplach zustava.
    #[test]
    fn fanout_relations_per_host_are_capped_deterministically() {
        let profile = mature_profile("10.0.0.5");
        let prevalence = Prevalence::default();
        let t = NoveltyThresholds {
            fanout_min: 8,
            ..Default::default()
        };
        let now = T0 + 3 * 86_400;
        let flood: Vec<ConnectionObservation> = (0..5000u32)
            .map(|k| {
                conn(
                    "10.0.0.5",
                    &format!("10.1.{}.{}", k / 250, k % 250 + 1),
                    445,
                    now,
                )
            })
            .collect();
        let run = || {
            let mut state = NoveltyState::default();
            let found = detect(&mut state, &profile, &prevalence, &t, &[], &flood, now);
            (state, found)
        };
        let (state, found) = run();
        let held = state.fanout["10.0.0.5"].recent.len();
        assert_eq!(held, t.fanout_cap);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].finding.finding_type, "novel_fanout");
        let (again, _) = run();
        assert_eq!(
            state.fanout["10.0.0.5"].recent,
            again.fanout["10.0.0.5"].recent
        );
        // strop nikdy pod prahem
        let low = NoveltyThresholds {
            fanout_min: 8,
            fanout_cap: 3,
            ..Default::default()
        };
        let mut state = NoveltyState::default();
        let found = detect(&mut state, &profile, &prevalence, &low, &[], &flood, now);
        assert_eq!(found.len(), 1);
        assert_eq!(state.fanout["10.0.0.5"].recent.len(), 8);
    }

    #[test]
    fn state_is_capped_and_serializable() {
        let profile = mature_profile("10.0.0.5");
        let prevalence = Prevalence::default();
        let t = NoveltyThresholds {
            max_pairs: 10,
            ..Default::default()
        };
        let mut state = NoveltyState::default();
        let now = T0 + 3 * 86_400;
        let flows: Vec<ConnectionObservation> = (0..50)
            .map(|i| conn("10.0.0.5", &format!("203.0.113.{i}"), 443, now))
            .collect();
        detect(&mut state, &profile, &prevalence, &t, &flows, &[], now);
        assert!(state.pairs.len() <= 10);
        let text = serde_json::to_string(&state).unwrap();
        let back: NoveltyState = serde_json::from_str(&text).unwrap();
        assert_eq!(back.pairs.len(), state.pairs.len());
    }
}
