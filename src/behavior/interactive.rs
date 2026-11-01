//! Interaktivní relace (reverse shell) a dlouhé tunely ven (krok 3C). HYPOTÉZA:
//! pro reverse shell a interaktivní relace z toků RQ4 (Z13, velmi nízká jistota)
//! nenašla recenzovanou práci s TPR/FPR, jediné číslo je z endpointu (RQ4-056). Cíle
//! a meze jsou proto vlastní a měří se poctivě proti podobným neškodným provozům
//! (SSH administrace, vzdálená podpora, VPN, streaming, DevOps).
//!
//! Co z `conn.log` jde a co ne (studie 03 §1 bod 5): délka, bajty a pakety po směrech
//! ano, mezipaketové časy a obsah ne. „Nepravidelné pauzy“ (D3FEND D3-RTSD) se tak
//! dají jen nahradit nízkou propustností při dlouhé relaci a malými pakety v obou
//! směrech. SSH správa ven má na úrovni toku stejný obraz jako reverse shell; rozliší
//! ji jen kontext (správcovský zdroj), profil hostu nebo reputace, ne tok.
//!
//! - `interactive_session`: TCP ven, délka ≥ 5 min, ≥ 40 paketů, střední paket ≤ 160 B
//!   od klienta a ≤ 220 B od serveru, poměr paketů 1 : 4 až 4 : 1, propustnost ≤ 2 kB/s.
//! - `long_lived_tunnel`: spojení dvojice souvisle déle než 2 h (Zeek zapisuje dlouhé
//!   spojení po částech nebo až na konci, studie 03 §2 poznámky) s obousměrnými daty,
//!   mimo VPN porty a mimo cíle flotily (VPN koncentrátor, CDN).

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::{
    behavior::{BehaviorFinding, beacon::Prevalence, beacon::target_key, evict_oldest, finding},
    model::{Confidence, Severity},
    passive::ConnectionObservation,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InteractiveThresholds {
    pub min_duration_s: f64,
    pub min_pkts: u64,
    pub max_orig_pkt: f64,
    pub max_resp_pkt: f64,
    pub ratio_lo: f64,
    pub ratio_hi: f64,
    pub max_rate: f64,
    /// Část dlouhého spojení: tok delší než toto (s).
    pub chunk_min_s: f64,
    /// Souvislost částí: mezera mezi koncem a dalším začátkem nejvýš (s).
    pub chunk_gap_s: i64,
    pub tunnel_min_s: i64,
    pub tunnel_min_bytes: u64,
    /// Obě strany posílají aspoň tento podíl (streaming a stahování ne).
    pub tunnel_min_share: f64,
    pub vpn_ports: Vec<u16>,
    pub fleet_min: usize,
    pub max_pairs: usize,
}

impl Default for InteractiveThresholds {
    fn default() -> Self {
        Self {
            min_duration_s: 300.0,
            min_pkts: 40,
            max_orig_pkt: 160.0,
            max_resp_pkt: 220.0,
            ratio_lo: 0.25,
            ratio_hi: 4.0,
            max_rate: 2000.0,
            chunk_min_s: 600.0,
            chunk_gap_s: 2700,
            tunnel_min_s: 7200,
            tunnel_min_bytes: 1_000_000,
            tunnel_min_share: 0.05,
            vpn_ports: vec![500, 1194, 1701, 4500, 51820],
            fleet_min: 5,
            max_pairs: 100_000,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Run {
    start: i64,
    end: i64,
    orig: u64,
    resp: u64,
    chunks: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct InteractiveState {
    runs: HashMap<String, Run>,
    pub evicted: u64,
}

/// Je tok interaktivní relací (malé pakety obousměrně, dlouhá, pomalá)?
pub fn is_interactive(flow: &ConnectionObservation, t: &InteractiveThresholds) -> bool {
    if flow.proto != "tcp" {
        return false;
    }
    let duration = flow.duration_s.unwrap_or(0.0);
    let (op, rp) = (flow.orig_pkts.unwrap_or(0), flow.resp_pkts.unwrap_or(0));
    let (ob, rb) = (flow.orig_bytes.unwrap_or(0), flow.resp_bytes.unwrap_or(0));
    if duration < t.min_duration_s || op + rp < t.min_pkts || op == 0 || rp == 0 {
        return false;
    }
    let ratio = op as f64 / rp as f64;
    ob as f64 / op as f64 <= t.max_orig_pkt
        && rb as f64 / rp as f64 <= t.max_resp_pkt
        && (t.ratio_lo..=t.ratio_hi).contains(&ratio)
        && (ob + rb) as f64 / duration <= t.max_rate
}

pub fn detect(
    state: &mut InteractiveState,
    prevalence: &Prevalence,
    t: &InteractiveThresholds,
    outbound: &[ConnectionObservation],
    now: i64,
) -> Vec<BehaviorFinding> {
    let mut sessions: BTreeMap<(String, String, u16), (u32, f64, u64)> = BTreeMap::new();
    let mut chunks: BTreeMap<(String, String, u16), Vec<&ConnectionObservation>> = BTreeMap::new();
    for flow in outbound {
        let (Some(src), Some(port)) = (flow.src_ip.as_deref(), flow.dst_port) else {
            continue;
        };
        let (fleet, _) = prevalence.of(&target_key(&flow.dst_ip, &flow.proto, port), now);
        if fleet >= t.fleet_min {
            continue; // infrastruktura flotily (VPN koncentrator, CDN, relay)
        }
        let key = (src.to_string(), flow.dst_ip.clone(), port);
        if is_interactive(flow, t) {
            let entry = sessions.entry(key.clone()).or_default();
            entry.0 += 1;
            entry.1 += flow.duration_s.unwrap_or(0.0);
            entry.2 += flow.total_pkts.unwrap_or(0);
        }
        if flow.proto == "tcp" && flow.duration_s.unwrap_or(0.0) >= t.chunk_min_s {
            chunks.entry(key).or_default().push(flow);
        }
    }
    let mut out = Vec::new();
    for ((src, dst, port), (n, duration, pkts)) in sessions {
        let severity = if port == 22 {
            Severity::Low // SSH ven: casto sprava, rozlisi az kontext/profil
        } else {
            Severity::Medium
        };
        out.push(BehaviorFinding {
            finding: finding(
                "interactive_session",
                &src,
                &format!("out/{dst}/tcp/{port}"),
                severity,
                Confidence::Low,
                format!("Interaktivni relace z {src} na {dst}:{port}"),
                format!(
                    "Dlouhe obousmerne spojeni s malymi pakety a nizkou propustnosti ({n}x, {:.0} s, {pkts} paketu), navazane zevnitr ven. Obraz odpovida reverse shellu i sprave; pravidlo heuristika-behavior:interactive@v1 (hypoteza, RQ4 Z13).",
                    duration
                ),
                vec![format!("{src} -> {dst}:{port}/tcp: {n} relaci, {duration:.0} s")],
                "Overit, zda jde o schvalenou spravu (spravce, bastion, vzdalena podpora); jinak ukoncit relaci a proverit proces na hostu.",
            ),
            sources: vec![dst.clone()],
            targets: vec![(dst, port)],
            count: n,
            actor: src,
        });
    }
    for ((src, dst, port), mut flows) in chunks {
        flows.sort_by_key(|f| f.timestamp);
        let key = format!("{src}|{dst}|{port}");
        let run = state.runs.entry(key).or_default();
        for flow in flows {
            let start = flow.timestamp.timestamp();
            let end = start + flow.duration_s.unwrap_or(0.0) as i64;
            if run.chunks == 0 || start > run.end + t.chunk_gap_s {
                *run = Run {
                    start,
                    end,
                    ..Default::default()
                };
            }
            run.end = run.end.max(end);
            run.orig += flow.orig_bytes.unwrap_or(0);
            run.resp += flow.resp_bytes.unwrap_or(0);
            run.chunks += 1;
        }
        let total = run.orig + run.resp;
        let share = run.orig.min(run.resp) as f64 / total.max(1) as f64;
        if run.end - run.start < t.tunnel_min_s
            || total < t.tunnel_min_bytes
            || share < t.tunnel_min_share
            || t.vpn_ports.contains(&port)
        {
            continue;
        }
        out.push(BehaviorFinding {
            finding: finding(
                "long_lived_tunnel",
                &src,
                &format!("out/{dst}/tcp/{port}"),
                if port == 22 {
                    Severity::Low
                } else {
                    Severity::Medium
                },
                Confidence::Low,
                format!(
                    "Dlouhe spojeni z {src} na {dst}:{port} ({:.1} h)",
                    (run.end - run.start) as f64 / 3600.0
                ),
                format!(
                    "Spojeni trva souvisle {:.1} h ({} casti), obousmerne {:.1} MB ven a {:.1} MB dovnitr; tunel, tezba kryptomen nebo dlouha relace. Pravidlo heuristika-behavior:tunnel@v1 (hypoteza).",
                    (run.end - run.start) as f64 / 3600.0,
                    run.chunks,
                    run.orig as f64 / 1e6,
                    run.resp as f64 / 1e6
                ),
                vec![format!(
                    "{src} -> {dst}:{port}: od {} do {}",
                    run.start, run.end
                )],
                "Overit ucel spojeni (VPN, vzdalena podpora, streaming); jinak spojeni ukoncit a proverit host.",
            ),
            sources: vec![dst.clone()],
            targets: vec![(dst, port)],
            count: run.chunks,
            actor: src,
        });
    }
    state.runs.retain(|_, r| now - r.end <= 86_400);
    state.evicted += evict_oldest(&mut state.runs, t.max_pairs, |r| r.end) as u64;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[allow(clippy::too_many_arguments)]
    fn flow(
        dst: &str,
        port: u16,
        at: i64,
        dur: f64,
        ob: u64,
        rb: u64,
        op: u64,
        rp: u64,
    ) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: Utc.timestamp_opt(at, 0).unwrap(),
            src_ip: Some("10.0.0.5".to_string()),
            src_port: Some(40000),
            dst_ip: dst.to_string(),
            proto: "tcp".to_string(),
            dst_port: Some(port),
            duration_s: Some(dur),
            orig_bytes: Some(ob),
            resp_bytes: Some(rb),
            total_bytes: Some(ob + rb),
            orig_pkts: Some(op),
            resp_pkts: Some(rp),
            total_pkts: Some(op + rp),
            conn_state: Some("SF".to_string()),
            history: None,
            missed_bytes: Some(0),
        }
    }

    #[test]
    fn reverse_shell_like_flow_is_interactive_but_bulk_and_web_are_not() {
        let t = InteractiveThresholds::default();
        // shell: 30 min, 600 paketu ~70 B obema smery
        assert!(is_interactive(
            &flow("203.0.113.5", 443, 0, 1800.0, 40_000, 45_000, 600, 620),
            &t
        ));
        // streaming: velke pakety od serveru
        assert!(!is_interactive(
            &flow(
                "203.0.113.5",
                443,
                0,
                1800.0,
                50_000,
                90_000_000,
                700,
                62_000
            ),
            &t
        ));
        // kratke webove spojeni
        assert!(!is_interactive(
            &flow("203.0.113.5", 443, 0, 2.0, 700, 9000, 5, 8),
            &t
        ));
        // udrzovaci spojeni bez dat: malo paketu
        assert!(!is_interactive(
            &flow("203.0.113.5", 443, 0, 1800.0, 600, 600, 10, 10),
            &t
        ));
    }

    #[test]
    fn ssh_out_is_low_severity_and_fleet_targets_are_skipped() {
        let mut state = InteractiveState::default();
        let t = InteractiveThresholds::default();
        let mut prevalence = Prevalence::default();
        let found = detect(
            &mut state,
            &prevalence,
            &t,
            &[
                flow("203.0.113.5", 22, 0, 1800.0, 40_000, 45_000, 600, 620),
                flow("203.0.113.6", 4444, 0, 1800.0, 40_000, 45_000, 600, 620),
            ],
            0,
        );
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].finding.severity, Severity::Low);
        assert_eq!(found[1].finding.severity, Severity::Medium);
        // relay vzdalene podpory, na ktery mluvi mnoho hostu
        let crowd: Vec<_> = (1..=6)
            .map(|i| {
                let mut f = flow("198.51.100.20", 5938, 0, 10.0, 100, 100, 1, 1);
                f.src_ip = Some(format!("10.0.0.{i}"));
                f
            })
            .collect();
        prevalence.observe(&crowd, 0);
        let found = detect(
            &mut state,
            &prevalence,
            &t,
            &[flow(
                "198.51.100.20",
                5938,
                0,
                1800.0,
                40_000,
                45_000,
                600,
                620,
            )],
            0,
        );
        assert!(found.is_empty());
    }

    #[test]
    fn long_lived_tunnel_needs_contiguous_hours_two_way_data_and_non_vpn_port() {
        let t = InteractiveThresholds::default();
        let run = |port: u16, rb: u64, gap: i64| {
            let mut state = InteractiveState::default();
            let mut alarms = 0;
            for w in 0..8i64 {
                let at = w * (1800 + gap);
                alarms += detect(
                    &mut state,
                    &Prevalence::default(),
                    &t,
                    &[flow(
                        "203.0.113.9",
                        port,
                        at,
                        1700.0,
                        150_000,
                        rb,
                        2000,
                        2000,
                    )],
                    at,
                )
                .iter()
                .filter(|f| f.finding.finding_type == "long_lived_tunnel")
                .count();
            }
            alarms
        };
        assert!(run(3333, 150_000, 0) > 0, "mining");
        assert_eq!(run(1194, 150_000, 0), 0, "VPN port");
        assert_eq!(run(3333, 0, 0), 0, "jednosmerne");
        assert_eq!(run(3333, 150_000, 4000), 0, "nesouvisle casti");
    }
}
