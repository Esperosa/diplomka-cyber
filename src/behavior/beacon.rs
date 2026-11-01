//! Beaconing na dvojici zdroj-cíl (krok 3B). HYPOTÉZA, ne doložená metoda:
//! RQ4 Z1 (nízká jistota) ukazuje, že vysoké AUC periodických detektorů neříká nic
//! o provozním bodu (při FPR 1 % dvě ze tří metod nenajdou nic), Z2, že na reálném
//! provozu je ověřitelně škodlivých jen 19 až 62 % detekcí, a RQ4 §6 bod 2, že pod
//! ~12 spojeními na dvojici je skóre prázdné (RQ4-014) a filtr legitimního beaconingu
//! je nutná součást (RQ4-015). Proto se měří FPR proti neškodným pravidelným provozům
//! (monitoring, NTP, aktualizace, polling, VPN keepalive, CDN) v simulaci, ne AUC.
//!
//! Streamovací skica na dvojici (zdroj, cíl, protokol, port):
//! - mezičasy (IAT) mezi spojeními napříč okny, duplicity (< 1 s) a pozdní záznamy se
//!   přeskočí; mezery delší než `gap_factor` × medián (noc, výpadek) se z rozptylu
//!   vyřadí, aby pracovní doba nebo ztráta toků nerozbila periodicitu;
//! - robustní variační koeficient IAT = 1,4826 · MAD / medián. Odolnost vůči jitteru:
//!   při rovnoměrném jitteru ±j·P je to ≈ 0,87·j (rozdíl dvou rovnoměrných rozdělení),
//!   u Poissonova procesu ≈ 1,03; mez 0,45 tedy unese jitter do ~50 % (studie 03 §3.2
//!   bod 4 uvádí jitter 33 % jako známý únik detektorů s pevným intervalem);
//! - pravidelná velikost (MAD log bajtů) jen zpřesňuje popis, poplach nepodmiňuje;
//! - hystereze: poplach po `on_hits` periodických vyhodnoceních po sobě, konec po
//!   `off_misses` neperiodických; stav přežije restart (serde).
//! - Flotila: cíl, na který mluví mnoho vnitřních hostů (`fleet_min`), je typicky
//!   software (aktualizace, telemetrie, NTP). Jednotlivé dvojice flotily se nehlásí;
//!   hlásí se jen NOVÝ cíl flotily, který se objevil po zahřátí senzoru (kompromitovaný
//!   update, studie 03 N28). Riziko: útok přítomný od začátku se naučí (RQ2 Z3, 01-analyza
//!   §8 riziko 4); měří se zvlášť.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::{
    behavior::{BehaviorFinding, evict_oldest, finding, median_mad},
    model::{Confidence, Severity},
    passive::ConnectionObservation,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BeaconThresholds {
    /// Minimum spojení dvojice (RQ4-014: pod ~12 je skóre prázdné).
    pub min_obs: u32,
    /// Minimální rozpětí pozorování dvojice (s).
    pub min_span_s: i64,
    pub min_period_s: f64,
    pub max_period_s: f64,
    /// Mez robustního variačního koeficientu IAT.
    pub max_rcv: f64,
    pub gap_factor: f64,
    pub on_hits: u8,
    pub off_misses: u8,
    /// Kolik vnitřních hostů dělá z cíle flotilu.
    pub fleet_min: usize,
    /// Zahřátí senzoru: cíle flotily viděné dřív jsou výchozí stav (s).
    pub warmup_s: i64,
    pub history: usize,
    pub max_pairs: usize,
    /// Dvojice bez spojení déle než toto se zapomene (s).
    pub idle_s: i64,
}

impl Default for BeaconThresholds {
    fn default() -> Self {
        Self {
            min_obs: 12,
            min_span_s: 3600,
            min_period_s: 10.0,
            max_period_s: 6.0 * 3600.0,
            max_rcv: 0.45,
            gap_factor: 4.0,
            on_hits: 2,
            off_misses: 3,
            fleet_min: 5,
            warmup_s: 24 * 3600,
            history: 64,
            max_pairs: 200_000,
            idle_s: 3 * 86_400,
        }
    }
}

/// Kolik vnitřních hostů mluví na cíl (ip, port) za posledních 7 dní.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Prevalence {
    targets: HashMap<String, Target>,
    pub evicted: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Target {
    first: i64,
    last: i64,
    /// (zdroj, naposledy), nejvýš `SOURCES_CAP`.
    sources: Vec<(String, i64)>,
}

const SOURCES_CAP: usize = 64;
const PREVALENCE_WINDOW_S: i64 = 7 * 86_400;
const MAX_TARGETS: usize = 200_000;

pub fn target_key(ip: &str, proto: &str, port: u16) -> String {
    format!("{ip}|{proto}/{port}")
}

impl Prevalence {
    pub fn observe(&mut self, outbound: &[ConnectionObservation], now: i64) {
        for flow in outbound {
            let (Some(src), Some(port)) = (flow.src_ip.as_deref(), flow.dst_port) else {
                continue;
            };
            let target = self
                .targets
                .entry(target_key(&flow.dst_ip, &flow.proto, port))
                .or_insert_with(|| Target {
                    first: now,
                    ..Default::default()
                });
            target.last = now;
            if let Some(entry) = target.sources.iter_mut().find(|(s, _)| s == src) {
                entry.1 = now;
            } else if target.sources.len() < SOURCES_CAP {
                target.sources.push((src.to_string(), now));
            } else if let Some(oldest) = target.sources.iter_mut().min_by_key(|(_, t)| *t) {
                *oldest = (src.to_string(), now);
            }
        }
        self.evicted += evict_oldest(&mut self.targets, MAX_TARGETS, |t| t.last) as u64;
    }

    /// (počet vnitřních zdrojů za 7 dní, první výskyt cíle).
    pub fn of(&self, key: &str, now: i64) -> (usize, Option<i64>) {
        match self.targets.get(key) {
            Some(t) => (
                t.sources
                    .iter()
                    .filter(|(_, last)| now - last <= PREVALENCE_WINDOW_S)
                    .count(),
                Some(t.first),
            ),
            None => (0, None),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Pair {
    first: i64,
    last_ts: i64,
    n: u32,
    iats: Vec<f32>,
    sizes: Vec<f32>,
    hits: u8,
    misses: u8,
    alarmed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BeaconState {
    pairs: HashMap<String, Pair>,
    pub evicted: u64,
    pub evaluations: u64,
}

/// Vyhodnocení periodicity dvojice (veřejné kvůli testům a měření).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Periodicity {
    pub period_s: f64,
    pub rcv: f64,
    pub size_cv: f64,
    pub n: usize,
}

pub fn periodicity(iats: &[f32], sizes: &[f32], gap_factor: f64) -> Option<Periodicity> {
    if iats.len() < 3 {
        return None;
    }
    let mut all: Vec<f64> = iats.iter().map(|v| *v as f64).collect();
    let (m0, _) = median_mad(&mut all);
    let mut kept: Vec<f64> = all
        .into_iter()
        .filter(|v| *v <= gap_factor * m0.max(1.0))
        .collect();
    let n = kept.len();
    if n < 3 {
        return None;
    }
    let (m, mad) = median_mad(&mut kept);
    if m <= 0.0 {
        return None;
    }
    let mut s: Vec<f64> = sizes.iter().map(|v| *v as f64).collect();
    let (_, smad) = median_mad(&mut s);
    Some(Periodicity {
        period_s: m,
        rcv: 1.4826 * mad / m,
        size_cv: 1.4826 * smad,
        n,
    })
}

pub fn detect(
    state: &mut BeaconState,
    prevalence: &Prevalence,
    t: &BeaconThresholds,
    outbound: &[ConnectionObservation],
    now: i64,
    first_window: i64,
) -> Vec<BehaviorFinding> {
    // toky okna po dvojicich (zdroj, cil, protokol, port), serazene podle casu
    type PairKey = (String, String, String, u16);
    let mut by_pair: BTreeMap<PairKey, Vec<(i64, f64)>> = BTreeMap::new();
    for flow in outbound {
        let (Some(src), Some(port)) = (flow.src_ip.as_deref(), flow.dst_port) else {
            continue;
        };
        let bytes = (flow.orig_bytes.unwrap_or(0) + flow.resp_bytes.unwrap_or(0)) as f64;
        by_pair
            .entry((
                src.to_string(),
                flow.dst_ip.clone(),
                flow.proto.clone(),
                port,
            ))
            .or_default()
            .push((flow.timestamp.timestamp(), bytes));
    }
    let mut out = Vec::new();
    let mut fleet_alarmed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for ((src, dst, proto, port), mut times) in by_pair {
        times.sort_by_key(|(ts, _)| *ts);
        let key = format!("{src}|{dst}|{proto}/{port}");
        let pair = state.pairs.entry(key).or_insert_with(|| Pair {
            first: times[0].0,
            ..Default::default()
        });
        let mut fresh = 0;
        for (ts, bytes) in times {
            if pair.n > 0 && ts < pair.last_ts + 1 {
                continue; // duplicita nebo pozdni zaznam (replay)
            }
            if pair.n > 0 {
                pair.iats.push((ts - pair.last_ts) as f32);
            }
            pair.sizes.push(bytes.ln_1p() as f32);
            pair.last_ts = ts;
            pair.n = pair.n.saturating_add(1);
            fresh += 1;
        }
        for ring in [&mut pair.iats, &mut pair.sizes] {
            if ring.len() > t.history {
                let drop = ring.len() - t.history;
                ring.drain(..drop);
            }
        }
        if fresh == 0 || pair.n < t.min_obs || pair.last_ts - pair.first < t.min_span_s {
            continue;
        }
        state.evaluations += 1;
        let verdict = periodicity(&pair.iats, &pair.sizes, t.gap_factor);
        let periodic = verdict.is_some_and(|p| {
            p.rcv <= t.max_rcv
                && p.period_s >= t.min_period_s
                && p.period_s <= t.max_period_s
                && p.n + 1 >= t.min_obs as usize
        });
        if periodic {
            pair.hits = pair.hits.saturating_add(1);
            pair.misses = 0;
            if pair.hits >= t.on_hits {
                pair.alarmed = true;
            }
        } else {
            pair.misses = pair.misses.saturating_add(1);
            pair.hits = 0;
            if pair.misses >= t.off_misses {
                pair.alarmed = false;
            }
        }
        if !pair.alarmed {
            continue;
        }
        let Some(p) = verdict else { continue };
        let target = target_key(&dst, &proto, port);
        let (sources, first_seen) = prevalence.of(&target, now);
        if sources >= t.fleet_min {
            // flotila: hlasi se jen novy cil po zahrati senzoru (nize, jednou na cil)
            if first_seen.is_some_and(|f| f >= first_window + t.warmup_s) {
                fleet_alarmed.entry(target).or_default().push(src.clone());
            }
            continue;
        }
        let regular = if p.size_cv <= 0.35 {
            ", stejna velikost spojeni"
        } else {
            ""
        };
        out.push(BehaviorFinding {
            finding: finding(
                "beacon_periodic",
                &src,
                &format!("out/{dst}/{proto}/{port}"),
                Severity::Medium,
                Confidence::Low,
                format!(
                    "Host {src} pravidelne vola {dst}:{port} (perioda {:.0} s)",
                    p.period_s
                ),
                format!(
                    "Periodicita dvojice: robustni CV mezicasu {:.2} z {} mezicasu{regular}; cil zna {sources} vnitrnich hostu. Pravidlo heuristika-behavior:beacon@v1 (hypoteza, RQ4 Z1).",
                    p.rcv, p.n
                ),
                vec![format!(
                    "{src} -> {dst}:{port}/{proto}: {} spojeni, perioda {:.0} s, CV {:.2}, CV velikosti {:.2}",
                    pair.n, p.period_s, p.rcv, p.size_cv
                )],
                "Overit proces na hostu a reputaci cile; pravidelny provoz monitoringu, aktualizaci nebo synchronizace doplnit do profilu/kontextu.",
            ),
            sources: vec![dst.clone()],
            targets: vec![(dst, port)],
            count: pair.n,
            actor: src,
        });
    }
    for (target, members) in fleet_alarmed {
        if members.len() < t.fleet_min {
            continue;
        }
        let (dst, rest) = target.split_once('|').unwrap_or((&target, "tcp/0"));
        let port: u16 = rest
            .rsplit('/')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(0);
        out.push(BehaviorFinding {
            finding: finding(
                "beacon_periodic",
                dst,
                &format!("out/fleet/{rest}"),
                Severity::Medium,
                Confidence::Low,
                format!(
                    "{} vnitrnich hostu pravidelne vola novy cil {dst}:{port}",
                    members.len()
                ),
                format!(
                    "Cil se objevil po zahrati senzoru a pravidelne na nej mluvi flotila ({}); kompromitovana aktualizace nebo nova legitimni sluzba. Pravidlo heuristika-behavior:beacon-fleet@v1.",
                    members.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                ),
                members
                    .iter()
                    .take(5)
                    .map(|m| format!("{m} -> {dst}:{port}"))
                    .collect(),
                "Overit, zda jde o schvalenou novou sluzbu (zmena, dodavatel); jinak blokovat cil a proverit hosty.",
            ),
            sources: vec![dst.to_string()],
            targets: vec![(dst.to_string(), port)],
            count: members.len() as u32,
            actor: dst.to_string(),
        });
    }
    state.pairs.retain(|_, p| now - p.last_ts <= t.idle_s);
    state.evicted += evict_oldest(&mut state.pairs, t.max_pairs, |p| p.last_ts) as u64;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn conn(src: &str, dst: &str, at: i64, bytes: u64) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: Utc.timestamp_opt(at, 0).unwrap(),
            src_ip: Some(src.to_string()),
            src_port: Some(40000),
            dst_ip: dst.to_string(),
            proto: "tcp".to_string(),
            dst_port: Some(443),
            duration_s: Some(0.5),
            orig_bytes: Some(bytes),
            resp_bytes: Some(bytes),
            total_bytes: Some(2 * bytes),
            orig_pkts: Some(3),
            resp_pkts: Some(3),
            total_pkts: Some(6),
            conn_state: Some("SF".to_string()),
            history: None,
            missed_bytes: Some(0),
        }
    }

    fn lcg(seed: &mut u64) -> f64 {
        *seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (*seed >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Okna po 30 min; vrati prvni okno s poplachem.
    fn run(times: &[i64], src: &str, dst: &str) -> (Option<usize>, BeaconState) {
        let mut state = BeaconState::default();
        let prevalence = Prevalence::default();
        let t = BeaconThresholds::default();
        let mut first = None;
        let end = *times.last().unwrap();
        let mut w = 0usize;
        let mut start = times[0] - times[0].rem_euclid(1800);
        while start <= end {
            let flows: Vec<_> = times
                .iter()
                .filter(|ts| **ts >= start && **ts < start + 1800)
                .map(|ts| conn(src, dst, *ts, 300))
                .collect();
            let found = detect(&mut state, &prevalence, &t, &flows, start, 0);
            if !found.is_empty() && first.is_none() {
                first = Some(w);
            }
            start += 1800;
            w += 1;
        }
        (first, state)
    }

    fn jittered(period: f64, jitter: f64, n: usize, seed: u64) -> Vec<i64> {
        let mut s = seed;
        (0..n)
            .map(|i| {
                let j = (lcg(&mut s) * 2.0 - 1.0) * jitter * period;
                1_700_000_000 + (i as f64 * period + j) as i64
            })
            .collect()
    }

    #[test]
    fn periodic_beacon_with_jitter_up_to_forty_percent_alarms() {
        for jitter in [0.0, 0.1, 0.25, 0.4] {
            let (first, _) = run(&jittered(300.0, jitter, 200, 7), "10.0.0.5", "203.0.113.9");
            assert!(first.is_some(), "jitter {jitter} nedetekovan");
        }
    }

    #[test]
    fn poisson_and_lognormal_traffic_does_not_alarm() {
        let mut s = 11u64;
        let mut at = 1_700_000_000f64;
        let poisson: Vec<i64> = (0..300)
            .map(|_| {
                at += -300.0 * (1.0 - lcg(&mut s)).ln();
                at as i64
            })
            .collect();
        assert!(run(&poisson, "10.0.0.5", "203.0.113.9").0.is_none());
        let mut at = 1_700_000_000f64;
        let lognormal: Vec<i64> = (0..300)
            .map(|_| {
                // Box-Muller, sigma 1.0, median 600 s (studie 03 N20: limit detektoru)
                let (u1, u2) = (lcg(&mut s).max(1e-12), lcg(&mut s));
                let z = (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos();
                at += 600.0 * z.exp();
                at as i64
            })
            .collect();
        assert!(run(&lognormal, "10.0.0.5", "203.0.113.9").0.is_none());
    }

    #[test]
    fn slow_c2_in_working_hours_survives_night_gaps() {
        // 20 min +-30 %, jen 8-17 h, 3 dny: nocni mezery se z rozptylu vyradi
        let mut s = 5u64;
        let mut times = Vec::new();
        for day in 0..3i64 {
            let mut at = 1_700_000_000 + day * 86_400 + 8 * 3600;
            while at < 1_700_000_000 + day * 86_400 + 17 * 3600 {
                times.push(at);
                at += (1200.0 * (1.0 + (lcg(&mut s) * 2.0 - 1.0) * 0.3)) as i64;
            }
        }
        assert!(run(&times, "10.0.0.5", "203.0.113.9").0.is_some());
    }

    #[test]
    fn too_few_connections_never_alarm_and_duplicates_are_ignored() {
        let mut times = jittered(600.0, 0.0, 10, 1);
        let dup = times.clone();
        times.extend(dup); // duplicity (stejny cas) se preskoci
        times.sort();
        assert!(run(&times, "10.0.0.5", "203.0.113.9").0.is_none());
    }

    #[test]
    fn fleet_target_is_quiet_unless_new_after_warmup() {
        let t = BeaconThresholds::default();
        let hosts: Vec<String> = (1..=8).map(|i| format!("10.0.0.{i}")).collect();
        let schedule = |offset: i64| -> Vec<ConnectionObservation> {
            let mut flows = Vec::new();
            for (i, h) in hosts.iter().enumerate() {
                for k in 0..400 {
                    flows.push(conn(
                        h,
                        "198.51.100.10",
                        offset + i as i64 * 7 + k * 300,
                        300,
                    ));
                }
            }
            flows
        };
        for (offset, expect_alarm) in [(0i64, false), (2 * 86_400, true)] {
            let mut state = BeaconState::default();
            let mut prevalence = Prevalence::default();
            let flows = schedule(1_700_000_000 + offset);
            let mut alarms = Vec::new();
            for w in 0..60 {
                let start = 1_700_000_000 + offset + w * 1800;
                let window: Vec<_> = flows
                    .iter()
                    .filter(|f| {
                        let ts = f.timestamp.timestamp();
                        ts >= start && ts < start + 1800
                    })
                    .cloned()
                    .collect();
                prevalence.observe(&window, start);
                alarms.extend(detect(
                    &mut state,
                    &prevalence,
                    &t,
                    &window,
                    start,
                    1_700_000_000,
                ));
            }
            // zadna dvojice flotily se nehlasi jednotlive
            assert!(alarms.iter().all(|a| {
                a.finding
                    .service_key
                    .as_deref()
                    .is_some_and(|s| s.contains("fleet"))
            }));
            assert_eq!(!alarms.is_empty(), expect_alarm, "offset {offset}");
        }
    }

    #[test]
    fn state_is_capped_and_roundtrips() {
        let mut state = BeaconState::default();
        let t = BeaconThresholds {
            max_pairs: 50,
            ..Default::default()
        };
        let flows: Vec<_> = (0..200)
            .map(|i| {
                conn(
                    "10.0.0.1",
                    &format!("203.0.113.{}", i % 250),
                    1_700_000_000 + i,
                    100,
                )
            })
            .collect();
        detect(
            &mut state,
            &Prevalence::default(),
            &t,
            &flows,
            1_700_000_000,
            0,
        );
        assert!(state.pairs.len() <= 50);
        let json = serde_json::to_string(&state).unwrap();
        let back: BeaconState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pairs.len(), state.pairs.len());
    }
}
