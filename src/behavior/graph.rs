//! Graf spojení uvnitř sítě: nové hrany a řetěz A→B→C (krok 3D).
//!
//! RQ4 Z10 (střední jistota): samotná nová hrana (first-seen pair) má na LANL FPR
//! 4,4 % (530 082 FP), je to RYS, ne poplach. Z11: kauzální cesty (Hopper) daly
//! 94,5 % TPR při 9 FP/den, ale z autentizačních logů, ne z toků; použití na
//! `conn.log` bez identity je extrapolace. Z12a/b: korelace časování stepping-stone
//! selhává při zpoždění 1 s a chaffu, takže zrcadlení objemu je jen bonus skóre.
//!
//! Model: pro každý vnitřní host naučená množina cílů (profil hran). Nová hrana =
//! úspěšné spojení na cíl, který host dosud neoslovil, a jen u hostu, který senzor zná
//! déle než `host_warmup_s` (nový host má všechny hrany nové). Řetěz: nová hrana B→C,
//! která začala do `slow_window_s` po nové hraně X→B (X ≠ C), nebo po kompromitaci B
//! (interaktivní relace, beacon, tunel ven = kořen). Skóre řetězu sčítá váhy hopů:
//! správcovský port, rychlost navázání (do 15 min), zrcadlení objemu (±30 %); hop
//! z rozbočovače (bastion, CI/CD, Ansible: host s mnoha novými hranami denně) má váhu
//! sníženou. Poplach `pivot_chain` na pivotu (zdroj posledního hopu) při hloubce ≥ 2.
//! Okno s nárazem nových hran napříč sítí (replay sběru, poškozené logy) řetězy
//! nevyhlašuje; útočník se tak může schovat do šumu (měří se zvlášť).

use std::collections::{BTreeMap, HashMap, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{
    behavior::{BehaviorFinding, DetectedChain, evict_oldest, finding},
    model::{Confidence, Severity},
    passive::ConnectionObservation,
};

pub const ADMIN_PORTS: &[u16] = &[22, 23, 135, 139, 445, 1080, 3389, 5900, 5985, 5986];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GraphThresholds {
    pub fast_s: i64,
    pub chain_window_s: i64,
    pub slow_window_s: i64,
    pub min_depth: u8,
    pub min_score: f64,
    pub mirror_tol: f64,
    pub host_warmup_s: i64,
    /// Rozbočovač: průměrně víc nových hran za den.
    pub hub_new_per_day: f64,
    pub hub_factor: f64,
    pub root_ttl_s: i64,
    /// Náraz: nových hran v okně víc než max(min, podíl × aktivní hosté).
    pub burst_min: usize,
    pub burst_share: f64,
    pub max_edges_per_host: usize,
    pub max_hosts: usize,
    pub max_recent: usize,
}

impl Default for GraphThresholds {
    fn default() -> Self {
        Self {
            fast_s: 900,
            chain_window_s: 1800,
            slow_window_s: 36 * 3600,
            min_depth: 2,
            min_score: 2.0,
            mirror_tol: 0.3,
            host_warmup_s: 12 * 3600,
            hub_new_per_day: 5.0,
            hub_factor: 0.3,
            root_ttl_s: 24 * 3600,
            burst_min: 50,
            burst_share: 0.2,
            max_edges_per_host: 512,
            max_hosts: 50_000,
            max_recent: 20_000,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct HostEdges {
    first: i64,
    last: i64,
    edges: HashMap<String, i64>,
    /// Nové hrany: počet a počet dní pozorování (průměr za den).
    new_edges: u32,
}

impl HostEdges {
    fn new_per_day(&self, now: i64) -> f64 {
        let days = ((now - self.first) as f64 / 86_400.0).max(1.0);
        self.new_edges as f64 / days
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NewEdge {
    src: String,
    dst: String,
    port: u16,
    start: i64,
    bytes: u64,
    depth: u8,
    score: f64,
    /// Cesta od kořene (zdroj, cíl, čas).
    path: Vec<(String, String, i64)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GraphState {
    hosts: HashMap<String, HostEdges>,
    recent: VecDeque<NewEdge>,
    /// Kompromitovaní hosté (kořeny řetězu) -> čas.
    roots: HashMap<String, i64>,
    pub new_edges_total: u64,
    pub bursts: u64,
    pub evicted: u64,
}

impl GraphState {
    /// Nová hrana z hostu do `dst` by byla neobvyklá (pro žebřík, L1 profil hran)?
    pub fn knows_edge(&self, src: &str, dst: &str) -> Option<bool> {
        self.hosts.get(src).map(|h| h.edges.contains_key(dst))
    }

    /// Hosté v posledních řetězech (pro L4 pivot žebříku).
    pub fn chain_hosts(&self, since: i64) -> Vec<String> {
        let mut out: Vec<String> = self
            .recent
            .iter()
            .filter(|e| e.depth >= 2 && e.start >= since)
            .flat_map(|e| e.path.iter().flat_map(|(a, b, _)| [a.clone(), b.clone()]))
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

fn is_success(flow: &ConnectionObservation) -> bool {
    let state = flow.conn_state.as_deref().unwrap_or("");
    !matches!(state, "S0" | "REJ" | "RSTOS0" | "SH" | "RSTRH" | "OTH")
        && flow.resp_bytes.unwrap_or(0) > 0
}

pub fn detect(
    state: &mut GraphState,
    t: &GraphThresholds,
    internal: &[ConnectionObservation],
    roots: &[String],
    now: i64,
) -> (Vec<BehaviorFinding>, Vec<DetectedChain>) {
    for root in roots {
        state.roots.insert(root.clone(), now);
    }
    state.roots.retain(|_, at| now - *at <= t.root_ttl_s);
    // uspesna spojeni okna po dvojicich: nejdrivejsi cas, port, bajty od klienta
    let mut pairs: BTreeMap<(String, String), (i64, u16, u64)> = BTreeMap::new();
    let mut active: std::collections::HashSet<&str> = Default::default();
    for flow in internal {
        let Some(src) = flow.src_ip.as_deref() else {
            continue;
        };
        if src == flow.dst_ip || !is_success(flow) {
            continue;
        }
        active.insert(src);
        let at = flow.timestamp.timestamp();
        let entry = pairs
            .entry((src.to_string(), flow.dst_ip.clone()))
            .or_insert((at, flow.dst_port.unwrap_or(0), 0));
        if at < entry.0 {
            entry.0 = at;
            entry.1 = flow.dst_port.unwrap_or(0);
        }
        entry.2 += flow.orig_bytes.unwrap_or(0);
    }
    let mut fresh: Vec<NewEdge> = Vec::new();
    for ((src, dst), (start, port, bytes)) in pairs {
        // zralost hostu se pocita od prvniho vyskytu v provozu (i jako cil): server,
        // ktery sam spojeni nenavazuje, je jinak pri prvni vlastni hrane vzdy "novy"
        state
            .hosts
            .entry(dst.clone())
            .or_insert_with(|| HostEdges {
                first: now,
                ..Default::default()
            })
            .last = now;
        let host = state.hosts.entry(src.clone()).or_insert_with(|| HostEdges {
            first: now,
            ..Default::default()
        });
        host.last = now;
        if host.edges.contains_key(&dst) {
            host.edges.insert(dst, now);
            continue;
        }
        let mature = now - host.first >= t.host_warmup_s;
        host.edges.insert(dst.clone(), now);
        if host.edges.len() > t.max_edges_per_host {
            // nejstarsi hrana pryc (profil hostu ma strop)
            if let Some(oldest) = host
                .edges
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(k, _)| k.clone())
            {
                host.edges.remove(&oldest);
            }
        }
        if !mature {
            continue;
        }
        host.new_edges += 1;
        state.new_edges_total += 1;
        fresh.push(NewEdge {
            src,
            dst,
            port,
            start,
            bytes,
            depth: 1,
            score: 0.0,
            path: Vec::new(),
        });
    }
    let burst = fresh.len()
        > t.burst_min
            .max((t.burst_share * active.len() as f64) as usize);
    if burst {
        state.bursts += 1;
    }
    fresh.sort_by(|a, b| a.start.cmp(&b.start).then(a.src.cmp(&b.src)));
    let mut findings = Vec::new();
    let mut chains = Vec::new();
    for mut edge in fresh {
        let base = if ADMIN_PORTS.contains(&edge.port) {
            1.0
        } else {
            0.5
        };
        let hub = state
            .hosts
            .get(&edge.src)
            .is_some_and(|h| h.new_per_day(now) >= t.hub_new_per_day);
        let factor = if hub { t.hub_factor } else { 1.0 };
        // nejlepsi predchudce: nova hrana X -> src (X != dst) v okne, nebo koren
        let mut best: Option<(f64, u8, Vec<(String, String, i64)>)> = None;
        for prev in state.recent.iter() {
            if prev.dst != edge.src || prev.src == edge.dst {
                continue;
            }
            let dt = edge.start - prev.start;
            if dt < 0 || dt > t.slow_window_s {
                continue;
            }
            let mut weight = base;
            if dt <= t.fast_s {
                weight += 0.5;
            } else if dt <= t.chain_window_s {
                weight += 0.25;
            }
            let (a, b) = (prev.bytes as f64, edge.bytes as f64);
            if a > 0.0 && (a - b).abs() / a.max(b) <= t.mirror_tol {
                weight += 0.5;
            }
            let score = prev.score + weight * factor;
            if best.as_ref().is_none_or(|(s, ..)| score > *s) {
                let mut path = prev.path.clone();
                if path.is_empty() {
                    path.push((prev.src.clone(), prev.dst.clone(), prev.start));
                }
                best = Some((score, prev.depth + 1, path));
            }
        }
        if best.is_none() && state.roots.contains_key(&edge.src) {
            // kompromitovany host (spojeni ven): koren s hloubkou 1
            best = Some((
                1.0 + base * factor,
                2,
                vec![("ven".to_string(), edge.src.clone(), edge.start)],
            ));
        }
        match best {
            Some((score, depth, mut path)) => {
                path.push((edge.src.clone(), edge.dst.clone(), edge.start));
                edge.score = score;
                edge.depth = depth;
                edge.path = path;
            }
            None => {
                edge.score = base * factor;
                edge.path = vec![(edge.src.clone(), edge.dst.clone(), edge.start)];
            }
        }
        if !burst && edge.depth >= t.min_depth && edge.score >= t.min_score {
            let hops: Vec<String> = edge
                .path
                .iter()
                .map(|(a, b, at)| format!("{a} -> {b} @{at}"))
                .collect();
            let root = edge.path.first().map(|p| p.0.clone()).unwrap_or_default();
            findings.push(BehaviorFinding {
                finding: finding(
                    "pivot_chain",
                    &edge.src,
                    &format!("chain/{}/tcp/{}", edge.dst, edge.port),
                    if edge.depth >= 3 {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    Confidence::Low,
                    format!(
                        "Retez novych spojeni hloubky {} pres {} na {}:{}",
                        edge.depth, edge.src, edge.dst, edge.port
                    ),
                    format!(
                        "Host {} navazal nove spojeni na {} brzy po tom, co se sam stal cilem noveho spojeni nebo komunikoval ven; skore {:.2}. Pravidlo heuristika-behavior:chain@v1 (RQ4 Z10/Z11: nova hrana je rys, poplach az retez).",
                        edge.src, edge.dst, edge.score
                    ),
                    hops,
                    "Proverit prihlaseni a procesy na pivotu, overit, zda nejde o spravu pres bastion; pri potvrzeni izolovat cely retez.",
                ),
                sources: vec![root],
                targets: vec![(edge.dst.clone(), edge.port)],
                count: edge.depth as u32,
                actor: edge.src.clone(),
            });
            chains.push(DetectedChain {
                edges: edge.path.clone(),
                score: edge.score,
            });
        }
        state.recent.push_back(edge);
    }
    while state
        .recent
        .front()
        .is_some_and(|e| now - e.start > t.slow_window_s)
        || state.recent.len() > t.max_recent
    {
        state.recent.pop_front();
    }
    state.evicted += evict_oldest(&mut state.hosts, t.max_hosts, |h| h.last) as u64;
    (findings, chains)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn conn(src: &str, dst: &str, port: u16, at: i64, bytes: u64) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: Utc.timestamp_opt(at, 0).unwrap(),
            src_ip: Some(src.to_string()),
            src_port: Some(40000),
            dst_ip: dst.to_string(),
            proto: "tcp".to_string(),
            dst_port: Some(port),
            duration_s: Some(10.0),
            orig_bytes: Some(bytes),
            resp_bytes: Some(bytes),
            total_bytes: Some(2 * bytes),
            orig_pkts: Some(10),
            resp_pkts: Some(10),
            total_pkts: Some(20),
            conn_state: Some("SF".to_string()),
            history: None,
            missed_bytes: Some(0),
        }
    }

    /// Zahrati: kazdy host komunikuje se svym serverem 13 h.
    fn warm(state: &mut GraphState, t: &GraphThresholds, hosts: &[&str]) -> i64 {
        let mut now = 0;
        for w in 0..27 {
            now = w * 1800;
            let flows: Vec<_> = hosts
                .iter()
                .map(|h| conn(h, "10.0.0.250", 443, now + 5, 1000))
                .collect();
            detect(state, t, &flows, &[], now);
        }
        now + 1800
    }

    #[test]
    fn depth_three_chain_is_found_in_order_with_mirror() {
        let t = GraphThresholds::default();
        let mut state = GraphState::default();
        let now = warm(
            &mut state,
            &t,
            &["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
        );
        let flows = vec![
            conn("10.0.0.1", "10.0.0.2", 22, now + 10, 50_000),
            conn("10.0.0.2", "10.0.0.3", 3389, now + 200, 48_000),
            conn("10.0.0.3", "10.0.0.4", 445, now + 500, 47_000),
        ];
        let (findings, chains) = detect(&mut state, &t, &flows, &[], now);
        assert_eq!(findings.len(), 2, "pivoty 10.0.0.2 a 10.0.0.3");
        let deepest = chains.iter().max_by_key(|c| c.edges.len()).unwrap();
        let order: Vec<&str> = deepest.edges.iter().map(|e| e.0.as_str()).collect();
        assert_eq!(order, vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
        assert!(
            findings
                .iter()
                .any(|f| f.finding.severity == Severity::High)
        );
    }

    #[test]
    fn known_edges_new_hosts_and_hubs_do_not_chain() {
        let t = GraphThresholds::default();
        let mut state = GraphState::default();
        let now = warm(&mut state, &t, &["10.0.0.1", "10.0.0.2"]);
        // znama hrana (server) a pak nova: hloubka 1
        let (f, _) = detect(
            &mut state,
            &t,
            &[
                conn("10.0.0.1", "10.0.0.250", 443, now + 1, 100),
                conn("10.0.0.250", "10.0.0.2", 22, now + 60, 100),
            ],
            &[],
            now,
        );
        assert!(
            f.is_empty(),
            "predchozi hrana 10.0.0.1 -> 10.0.0.250 neni nova"
        );
        // novy host (nezahraty) na pivot: jeho hrany nejsou nove
        let (f, _) = detect(
            &mut state,
            &t,
            &[
                conn("10.0.0.77", "10.0.0.1", 22, now + 1900, 100),
                conn("10.0.0.1", "10.0.0.2", 22, now + 1990, 100),
            ],
            &[],
            now + 1800,
        );
        assert!(f.is_empty());
    }

    #[test]
    fn compromised_root_makes_one_new_hop_a_chain_and_bursts_are_ignored() {
        let t = GraphThresholds::default();
        let mut state = GraphState::default();
        let now = warm(&mut state, &t, &["10.0.0.1", "10.0.0.2"]);
        let (f, chains) = detect(
            &mut state,
            &t,
            &[conn("10.0.0.1", "10.0.0.2", 445, now + 30, 100)],
            &["10.0.0.1".to_string()],
            now,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(chains[0].edges[0].0, "ven");
        // naraz: 80 novych hran v okne (replay sberu) -> zadny retez
        let mut state = GraphState::default();
        let hosts: Vec<String> = (1..=60).map(|i| format!("10.0.1.{i}")).collect();
        let refs: Vec<&str> = hosts.iter().map(String::as_str).collect();
        let now = warm(&mut state, &t, &refs);
        let mut flows = Vec::new();
        for i in 0..60usize {
            flows.push(conn(
                &hosts[i],
                &hosts[(i + 1) % 60],
                445,
                now + i as i64,
                100,
            ));
            flows.push(conn(
                &hosts[i],
                &hosts[(i + 7) % 60],
                22,
                now + 100 + i as i64,
                100,
            ));
        }
        let (f, _) = detect(&mut state, &t, &flows, &[], now);
        assert!(f.is_empty());
        assert_eq!(state.bursts, 1);
    }

    #[test]
    fn state_caps_hold() {
        let t = GraphThresholds {
            max_edges_per_host: 10,
            max_recent: 5,
            host_warmup_s: 0,
            ..Default::default()
        };
        let mut state = GraphState::default();
        let flows: Vec<_> = (0..40)
            .map(|i| conn("10.0.0.1", &format!("10.0.2.{i}"), 80, i, 10))
            .collect();
        detect(&mut state, &t, &flows, &[], 0);
        assert!(state.hosts["10.0.0.1"].edges.len() <= 10);
        assert!(state.recent.len() <= 5);
    }
}
