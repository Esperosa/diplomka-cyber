//! Třída „provozní problém“ (krok 6, kandidát 2; docs/diplomka/eval/impl-krok6.md).
//!
//! Zobrazený nález s POZITIVNÍM důkazem provozní příčiny jde do fronty „provoz“,
//! ne mezi podezření na útok. Nikdy se nezavírá: správce ho vidí, jen ve správné
//! frontě (krok 5: správce o výpadku DNS nebo selhané záloze vědět chce, ale ne jako
//! o útoku). Prázdný výsledek není důkaz (Dodatek A.2 d), proto se třídí jen podle
//! vzoru, který útok dělá jen výjimečně:
//!
//! - **E1 selhání služby u jejích klientů**: aspoň `min_failing_sources` zdrojů v okně
//!   na jednu službu jen selhává, medián pokusů na zdroj je malý a služba měla
//!   předtím aspoň `min_prior_clients` úspěšných klientů. Když selhávají mnozí klienti
//!   téže služby současně, příčina je ve společné závislosti (lokalizace poruch podle
//!   závislostí: Sherlock, Bahl a kol., SIGCOMM 2007; studie 00 R6a).
//! - **E2 broadcast a multicast**: cíl není hostitel (RFC 919, RFC 1112), bouře na
//!   broadcast je chyba konfigurace, ne útok na hosta.
//! - **E3 nárůst zátěže od dosavadních klientů**: nárůst objemu nesou hlavně dosavadní
//!   klienti služby a žádný zdroj nedominuje (flash crowd, hromadný start po výpadku;
//!   studie 00 R6 riziko „flash_crowd a backup_burst R6a neřeší“).
//!
//! Riziko: rozložený útok mnoha zdroji (DDoS, rozložené hádání hesel). Proto nález
//! s jediným dominantním zdrojem do třídy nikdy nejde a v soaku se měří, kolik útoků
//! skončí jen ve frontě provoz. Klientela se neučí ze zdrojů s nálezem v okně (gating
//! jako RQ2 Z3) a má strop velikosti a stáří.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{behavior::evict_oldest, passive::ConnectionObservation};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OpsPolicy {
    pub min_failing_sources: usize,
    pub max_median_attempts: f64,
    pub min_prior_clients: usize,
    pub surge_min_sources: usize,
    pub surge_clientele_share: f64,
    pub surge_max_top_share: f64,
    /// Klient služby platí tolik sekund od posledního úspěšného spojení.
    pub clientele_window_s: i64,
    pub clientele_cap: usize,
    pub max_services: usize,
}

impl Default for OpsPolicy {
    /// Volba autora před prvním měřením (impl-krok6.md, B5).
    fn default() -> Self {
        Self {
            min_failing_sources: 10,
            max_median_attempts: 6.0,
            min_prior_clients: 10,
            surge_min_sources: 10,
            surge_clientele_share: 0.7,
            surge_max_top_share: 0.2,
            clientele_window_s: 7 * 86_400,
            clientele_cap: 64,
            max_services: 100_000,
        }
    }
}

/// Typy, které smí jít do fronty provoz. Signatury, behaviorální typy, pokusy
/// zdroje (sken), více cílů a statické expozice nikdy.
const E1_TYPES: &[&str] = &[
    "connection_timeout_burst",
    "service_unreachable",
    "service_overload_risk",
    "unexpected_traffic",
    "unmapped_passive_event",
    "packet_rate_spike",
    "inductive_volume_anomaly",
];
const E3_TYPES: &[&str] = &[
    "packet_rate_spike",
    "inductive_volume_anomaly",
    "service_overload_risk",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Service {
    last: i64,
    /// (zdroj, poslední úspěšné spojení), nejvýš `clientele_cap`.
    clients: Vec<(String, i64)>,
}

/// Úspěšní klienti služeb (`ip/proto/port`) za posledních `clientele_window_s`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Clientele {
    services: HashMap<String, Service>,
    pub evicted: u64,
}

/// Důkazy provozní příčiny jednoho okna.
#[derive(Debug, Clone, Default)]
pub struct OpsWindow {
    by_service: HashMap<String, String>,
    surge: HashMap<String, String>,
    by_host: HashMap<String, String>,
}

pub fn service_key(ip: &str, proto: &str, port: u16) -> String {
    format!("{ip}/{proto}/{port}")
}

fn failed(flow: &ConnectionObservation) -> bool {
    match flow.conn_state.as_deref() {
        Some("S0" | "REJ" | "RSTOS0" | "RSTRH" | "SH" | "SHR" | "OTH") => true,
        Some("RSTO" | "RSTR") => flow.resp_bytes.unwrap_or(0) < 1000,
        _ => false,
    }
}

fn succeeded(flow: &ConnectionObservation) -> bool {
    flow.conn_state.is_some() && !failed(flow) && flow.resp_bytes.unwrap_or(0) > 0
}

/// Cíl není hostitel: broadcast posledního oktetu, omezený broadcast, multicast.
pub fn is_broadcast_or_multicast(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    addr.is_broadcast() || addr.is_multicast() || addr.octets()[3] == 255
}

#[derive(Default)]
struct Tally {
    fail: u32,
    ok: u32,
    flows: u32,
}

impl Clientele {
    fn prior_clients(&self, key: &str, now: i64, policy: &OpsPolicy) -> HashSet<&str> {
        self.services
            .get(key)
            .map(|s| {
                s.clients
                    .iter()
                    .filter(|(_, last)| now - last <= policy.clientele_window_s)
                    .map(|(c, _)| c.as_str())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Důkazy okna z toků s cílem v rozsahu (před učením tohoto okna).
    pub(crate) fn evidence(
        &self,
        flows: &[ConnectionObservation],
        now: i64,
        policy: &OpsPolicy,
    ) -> OpsWindow {
        let mut per: HashMap<String, HashMap<&str, Tally>> = HashMap::new();
        for flow in flows {
            let (Some(src), Some(port)) = (flow.src_ip.as_deref(), flow.dst_port) else {
                continue;
            };
            let tally = per
                .entry(service_key(&flow.dst_ip, &flow.proto, port))
                .or_default()
                .entry(src)
                .or_default();
            tally.flows += 1;
            if failed(flow) {
                tally.fail += 1;
            } else if succeeded(flow) {
                tally.ok += 1;
            }
        }
        let mut out = OpsWindow::default();
        let mut keys: Vec<&String> = per.keys().collect();
        keys.sort();
        for key in keys {
            let sources = &per[key];
            let prior = self.prior_clients(key, now, policy);
            let mut attempts: Vec<f64> = sources
                .values()
                .filter(|t| t.fail > 0 && t.ok == 0)
                .map(|t| t.fail as f64)
                .collect();
            let failing = attempts.len();
            if failing >= policy.min_failing_sources && prior.len() >= policy.min_prior_clients {
                let (median, _) = crate::behavior::median_mad(&mut attempts);
                if median <= policy.max_median_attempts {
                    out.by_service.insert(
                        key.clone(),
                        format!(
                            "provoz E1: {failing} zdroju na sluzbe jen selhava (median {median:.0} pokusu), sluzba mela {} uspesnych klientu",
                            prior.len()
                        ),
                    );
                }
            }
            let total: u32 = sources.values().map(|t| t.flows).sum();
            let top = sources.values().map(|t| t.flows).max().unwrap_or(0);
            let known = sources.keys().filter(|s| prior.contains(*s)).count();
            if sources.len() >= policy.surge_min_sources
                && total > 0
                && (known as f64) >= policy.surge_clientele_share * sources.len() as f64
                && (top as f64) <= policy.surge_max_top_share * total as f64
            {
                out.surge.insert(
                    key.clone(),
                    format!(
                        "provoz E3: narust nesou dosavadni klienti ({known} z {}), nejvetsi zdroj {:.0} % toku",
                        sources.len(),
                        100.0 * top as f64 / total as f64
                    ),
                );
            }
        }
        for (key, reason) in &out.by_service {
            let host = key.split('/').next().unwrap_or("");
            out.by_host
                .entry(host.to_string())
                .or_insert_with(|| reason.clone());
        }
        out
    }

    /// Naučí úspěšné klienty okna; zdroje s nálezem v okně (`frozen`) ne.
    pub(crate) fn learn(
        &mut self,
        flows: &[ConnectionObservation],
        frozen: &HashSet<String>,
        now: i64,
        policy: &OpsPolicy,
    ) {
        for flow in flows {
            let (Some(src), Some(port)) = (flow.src_ip.as_deref(), flow.dst_port) else {
                continue;
            };
            if !succeeded(flow) || frozen.contains(src) {
                continue;
            }
            let service = self
                .services
                .entry(service_key(&flow.dst_ip, &flow.proto, port))
                .or_default();
            service.last = now;
            if let Some(entry) = service.clients.iter_mut().find(|(c, _)| c == src) {
                entry.1 = now;
            } else if service.clients.len() < policy.clientele_cap {
                service.clients.push((src.to_string(), now));
            } else if let Some(oldest) = service.clients.iter_mut().min_by_key(|(_, t)| *t) {
                *oldest = (src.to_string(), now);
            }
        }
        let window = policy.clientele_window_s;
        self.services.retain(|_, s| now - s.last <= window);
        self.evicted += evict_oldest(&mut self.services, policy.max_services, |s| s.last) as u64;
    }

    pub fn services(&self) -> usize {
        self.services.len()
    }
}

/// Krok 6 C (jediná úprava kandidáta 2 na ladicích seedech): důkaz platí pro nález i
/// tehdy, když se zobrazí později (žebřík ho zobrazí až po ověření, kdy porucha už
/// skončila). Značka = `finding_id` → (čas důkazu, důvod), s TTL a stropem.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OpsMarks {
    marks: HashMap<String, (i64, String)>,
}

/// Jak dlouho platí důkaz provozní příčiny pro pozdější zobrazení (s).
pub const OPS_MARK_TTL_S: i64 = 24 * 3600;
const OPS_MARKS_CAP: usize = 200_000;

impl OpsMarks {
    pub fn note(&mut self, finding_id: &str, at: i64, reason: &str) {
        self.marks
            .insert(finding_id.to_string(), (at, reason.to_string()));
    }

    pub fn get(&self, finding_id: &str, at: i64) -> Option<&str> {
        self.marks
            .get(finding_id)
            .filter(|(when, _)| at - when <= OPS_MARK_TTL_S)
            .map(|(_, reason)| reason.as_str())
    }

    pub fn sweep(&mut self, at: i64) {
        self.marks
            .retain(|_, (when, _)| at - *when <= OPS_MARK_TTL_S);
        evict_oldest(&mut self.marks, OPS_MARKS_CAP, |(when, _)| *when);
    }

    pub fn len(&self) -> usize {
        self.marks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.marks.is_empty()
    }
}

/// Důvod zařazení nálezu do fronty provoz, nebo `None` (zůstává podezřením).
/// `service_key` je klíč služby nálezu (`ip/proto/port`), `sources` dominantní zdroje.
pub fn classify(
    window: &OpsWindow,
    finding_type: &str,
    service_key: Option<&str>,
    host_ip: &str,
    sources: &[String],
) -> Option<String> {
    if !E1_TYPES.contains(&finding_type) {
        return None;
    }
    if is_broadcast_or_multicast(host_ip) {
        return Some(format!(
            "provoz E2: cil {host_ip} je broadcast nebo multicast"
        ));
    }
    // jediny dominantni zdroj = utok jednoho aktera, ne porucha sluzby
    if sources.len() == 1 {
        return None;
    }
    let exact = service_key.filter(|k| k.matches('/').count() == 2);
    if let Some(key) = exact {
        if let Some(reason) = window.by_service.get(key) {
            return Some(reason.clone());
        }
        if E3_TYPES.contains(&finding_type)
            && let Some(reason) = window.surge.get(key)
        {
            return Some(reason.clone());
        }
        return None;
    }
    window.by_host.get(host_ip).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn flow(src: &str, dst: &str, port: u16, state: &str, rb: u64) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            src_ip: Some(src.to_string()),
            src_port: Some(40000),
            dst_ip: dst.to_string(),
            proto: "tcp".to_string(),
            dst_port: Some(port),
            duration_s: Some(0.1),
            orig_bytes: Some(300),
            resp_bytes: Some(rb),
            total_bytes: Some(300 + rb),
            orig_pkts: Some(2),
            resp_pkts: Some(2),
            total_pkts: Some(4),
            conn_state: Some(state.to_string()),
            history: None,
            missed_bytes: Some(0),
        }
    }

    fn clients(
        n: usize,
        dst: &str,
        state: &str,
        rb: u64,
        each: usize,
    ) -> Vec<ConnectionObservation> {
        (0..n)
            .flat_map(|i| (0..each).map(move |_| (i, ())))
            .map(|(i, _)| flow(&format!("10.0.1.{}", i + 1), dst, 443, state, rb))
            .collect()
    }

    #[test]
    fn many_known_clients_failing_on_one_service_is_ops() {
        let policy = OpsPolicy::default();
        let mut c = Clientele::default();
        c.learn(
            &clients(20, "10.0.0.9", "SF", 5000, 1),
            &HashSet::new(),
            0,
            &policy,
        );
        let window = c.evidence(&clients(15, "10.0.0.9", "RSTO", 0, 2), 1800, &policy);
        let key = service_key("10.0.0.9", "tcp", 443);
        let reason = classify(
            &window,
            "connection_timeout_burst",
            Some(&key),
            "10.0.0.9",
            &[],
        );
        assert!(reason.is_some_and(|r| r.contains("E1")));
        // jediny dominantni zdroj: zustava podezrenim
        let one = vec!["203.0.113.7".to_string()];
        assert!(
            classify(
                &window,
                "connection_timeout_burst",
                Some(&key),
                "10.0.0.9",
                &one
            )
            .is_none()
        );
        // signatury a behavioralni typy nikdy
        assert!(classify(&window, "suricata_alert", Some(&key), "10.0.0.9", &[]).is_none());
        assert!(classify(&window, "scan_attempts", Some(&key), "10.0.0.9", &[]).is_none());
    }

    #[test]
    fn failures_on_service_without_clientele_or_with_many_attempts_stay_suspect() {
        let policy = OpsPolicy::default();
        let c = Clientele::default();
        let key = service_key("10.0.0.9", "tcp", 443);
        // bez predchozich klientu (novy cil, sken nebo DDoS na neznamou sluzbu)
        let window = c.evidence(&clients(30, "10.0.0.9", "S0", 0, 2), 1800, &policy);
        assert!(
            classify(
                &window,
                "connection_timeout_burst",
                Some(&key),
                "10.0.0.9",
                &[]
            )
            .is_none()
        );
        // znama sluzba, ale kazdy zdroj buseni (median pokusu 20): utok, ne porucha
        let mut known = Clientele::default();
        known.learn(
            &clients(20, "10.0.0.9", "SF", 5000, 1),
            &HashSet::new(),
            0,
            &policy,
        );
        let window = known.evidence(&clients(15, "10.0.0.9", "S0", 0, 20), 1800, &policy);
        assert!(
            classify(
                &window,
                "connection_timeout_burst",
                Some(&key),
                "10.0.0.9",
                &[]
            )
            .is_none()
        );
    }

    #[test]
    fn broadcast_target_and_surge_of_known_clients() {
        let policy = OpsPolicy::default();
        let window = OpsWindow::default();
        assert!(is_broadcast_or_multicast("10.0.3.255") && is_broadcast_or_multicast("239.1.2.3"));
        assert!(!is_broadcast_or_multicast("10.0.3.7") && !is_broadcast_or_multicast("x"));
        assert!(
            classify(&window, "unexpected_traffic", None, "10.0.3.255", &[])
                .is_some_and(|r| r.contains("E2"))
        );
        let mut c = Clientele::default();
        c.learn(
            &clients(20, "10.0.0.53", "SF", 300, 1),
            &HashSet::new(),
            0,
            &policy,
        );
        let window = c.evidence(&clients(18, "10.0.0.53", "SF", 300, 5), 1800, &policy);
        let key = service_key("10.0.0.53", "tcp", 443);
        assert!(
            classify(&window, "packet_rate_spike", Some(&key), "10.0.0.53", &[])
                .is_some_and(|r| r.contains("E3"))
        );
        // E3 neplati pro timeouty
        assert!(
            classify(
                &window,
                "connection_timeout_burst",
                Some(&key),
                "10.0.0.53",
                &[]
            )
            .is_none()
        );
    }

    #[test]
    fn marks_survive_late_display_within_ttl() {
        let mut marks = OpsMarks::default();
        marks.note("finding:x", 1000, "provoz E1");
        assert_eq!(marks.get("finding:x", 1000 + 3600), Some("provoz E1"));
        assert!(marks.get("finding:x", 1000 + OPS_MARK_TTL_S + 1).is_none());
        assert!(marks.get("finding:y", 1000).is_none());
        marks.sweep(1000 + OPS_MARK_TTL_S + 1);
        assert!(marks.is_empty());
    }

    #[test]
    fn frozen_sources_are_not_learned_and_state_is_capped() {
        let policy = OpsPolicy {
            clientele_cap: 4,
            max_services: 10,
            ..OpsPolicy::default()
        };
        let mut c = Clientele::default();
        let frozen: HashSet<String> = ["10.0.1.1".to_string()].into();
        c.learn(&clients(8, "10.0.0.9", "SF", 500, 1), &frozen, 0, &policy);
        let key = service_key("10.0.0.9", "tcp", 443);
        let prior = c.prior_clients(&key, 10, &policy);
        assert_eq!(prior.len(), 4);
        assert!(!prior.contains("10.0.1.1"));
        for i in 0..30 {
            c.learn(
                &clients(1, &format!("10.0.2.{i}"), "SF", 500, 1),
                &HashSet::new(),
                i,
                &policy,
            );
        }
        assert!(c.services() <= 10);
        // stare sluzby zmizi
        c.learn(&[], &HashSet::new(), 30 + 8 * 86_400, &policy);
        assert_eq!(c.services(), 0);
    }
}
