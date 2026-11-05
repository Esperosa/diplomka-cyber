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

/// Cíl není hostitel: omezený broadcast, multicast, nebo směrovaný broadcast podle
/// skutečného prefixu podsítě (nejdelší shoda v `subnets`; review kola 1 S4:
/// 10.0.3.255 je v /16 běžná unicast adresa). Bez známé podsítě se směrovaný
/// broadcast neuznává (fail closed: nález zůstává podezřením).
pub fn is_broadcast_or_multicast(ip: &str, subnets: &[ipnet::IpNet]) -> bool {
    let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    if addr.is_broadcast() || addr.is_multicast() {
        return true;
    }
    subnets
        .iter()
        .filter_map(|net| match net {
            ipnet::IpNet::V4(net) if net.contains(&addr) => Some(net),
            _ => None,
        })
        .max_by_key(|net| net.prefix_len())
        .is_some_and(|net| net.prefix_len() <= 30 && net.broadcast() == addr)
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
        // serazene klice: stejny vstup = stejny duvod hostu (review kola 1 S6)
        let mut services: Vec<(&String, &String)> = out.by_service.iter().collect();
        services.sort();
        for (key, reason) in services {
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
/// skončila). Značka = `finding_id` → otisk důkazu, s TTL a stropem.
///
/// Review kola 1 (S1): značka je vázaná na epizodu důkazu (klíč služby a množina
/// zdrojů v době důkazu). Protichůdný důkaz ji zneplatní: jediný dominantní zdroj,
/// zdroj mimo otisk, jiná služba nebo eskalace v paměti nálezu. Jinak by nový
/// jednozdrojový útok se stejným `finding_id` dostal 24 h starý neškodný důvod.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OpsMarks {
    #[serde(deserialize_with = "marks_compat")]
    marks: HashMap<String, OpsMark>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct OpsMark {
    at: i64,
    reason: String,
    service: Option<String>,
    /// Seřazené dominantní zdroje nálezu v době důkazu.
    sources: Vec<String>,
}

/// Starý stav (`finding_id` → `[čas, důvod]`, před review kola 1) se načte, ale
/// značky bez otisku se zahodí: nejde ověřit, ke které epizodě patří (fail closed).
fn marks_compat<'de, D>(de: D) -> std::result::Result<HashMap<String, OpsMark>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Stored {
        Mark(OpsMark),
        Legacy(#[allow(dead_code)] (i64, String)),
    }
    let raw: HashMap<String, Stored> = HashMap::deserialize(de)?;
    Ok(raw
        .into_iter()
        .filter_map(|(id, stored)| match stored {
            Stored::Mark(mark) => Some((id, mark)),
            Stored::Legacy(_) => None,
        })
        .collect())
}

/// Jak dlouho platí důkaz provozní příčiny pro pozdější zobrazení (s).
pub const OPS_MARK_TTL_S: i64 = 24 * 3600;
const OPS_MARKS_CAP: usize = 200_000;

impl OpsMarks {
    pub fn note(
        &mut self,
        finding_id: &str,
        at: i64,
        reason: &str,
        service: Option<&str>,
        sources: &[String],
    ) {
        let mut sources = sources.to_vec();
        sources.sort();
        sources.dedup();
        self.marks.insert(
            finding_id.to_string(),
            OpsMark {
                at,
                reason: reason.to_string(),
                service: service.map(str::to_string),
                sources,
            },
        );
    }

    /// Jeden cyklus nálezu: čerstvý důkaz (`fresh`) značku obnoví, protichůdný důkaz
    /// ji zneplatní. Vrací platný důvod fronty provoz.
    pub fn update(
        &mut self,
        finding_id: &str,
        at: i64,
        fresh: Option<String>,
        service: Option<&str>,
        sources: &[String],
        escalated: bool,
    ) -> Option<&str> {
        match fresh {
            Some(reason) => self.note(finding_id, at, &reason, service, sources),
            None => {
                let contradicted = self.marks.get(finding_id).is_some_and(|mark| {
                    escalated
                        || mark.service.as_deref() != service
                        || sources.len() == 1
                        || sources
                            .iter()
                            .any(|s| mark.sources.binary_search(s).is_err())
                });
                if contradicted {
                    self.marks.remove(finding_id);
                }
            }
        }
        self.get(finding_id, at)
    }

    pub fn get(&self, finding_id: &str, at: i64) -> Option<&str> {
        self.marks
            .get(finding_id)
            .filter(|mark| at - mark.at <= OPS_MARK_TTL_S)
            .map(|mark| mark.reason.as_str())
    }

    pub fn sweep(&mut self, at: i64) {
        self.marks.retain(|_, mark| at - mark.at <= OPS_MARK_TTL_S);
        evict_oldest(&mut self.marks, OPS_MARKS_CAP, |mark| mark.at);
    }

    pub fn len(&self) -> usize {
        self.marks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.marks.is_empty()
    }
}

/// Důvod zařazení nálezu do fronty provoz, nebo `None` (zůstává podezřením).
/// `service_key` je klíč služby nálezu (`ip/proto/port`), `sources` dominantní zdroje,
/// `subnets` skutečné podsítě (rozsah) pro směrovaný broadcast.
pub fn classify(
    window: &OpsWindow,
    finding_type: &str,
    service_key: Option<&str>,
    host_ip: &str,
    sources: &[String],
    subnets: &[ipnet::IpNet],
) -> Option<String> {
    if !E1_TYPES.contains(&finding_type) {
        return None;
    }
    if is_broadcast_or_multicast(host_ip, subnets) {
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

    /// Podsítě rozsahu v testech (/24 jako v soaku).
    fn scope() -> Vec<ipnet::IpNet> {
        vec![
            "10.0.0.0/24".parse().unwrap(),
            "10.0.3.0/24".parse().unwrap(),
        ]
    }

    fn classify(
        window: &OpsWindow,
        finding_type: &str,
        service_key: Option<&str>,
        host_ip: &str,
        sources: &[String],
    ) -> Option<String> {
        super::classify(
            window,
            finding_type,
            service_key,
            host_ip,
            sources,
            &scope(),
        )
    }

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
        let nets = scope();
        assert!(is_broadcast_or_multicast("10.0.3.255", &nets));
        assert!(is_broadcast_or_multicast("239.1.2.3", &[]));
        assert!(is_broadcast_or_multicast("255.255.255.255", &[]));
        assert!(
            !is_broadcast_or_multicast("10.0.3.7", &nets) && !is_broadcast_or_multicast("x", &nets)
        );
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

    /// Review kola 1 (S4): smerovany broadcast podle skutecneho prefixu, ne podle .255.
    #[test]
    fn directed_broadcast_follows_real_subnet_prefix() {
        let wide: Vec<ipnet::IpNet> = vec!["10.0.0.0/16".parse().unwrap()];
        // v /16 je 10.0.3.255 bezny unicast host
        assert!(!is_broadcast_or_multicast("10.0.3.255", &wide));
        assert!(is_broadcast_or_multicast("10.0.255.255", &wide));
        // nejdelsi shoda rozhoduje
        let nested: Vec<ipnet::IpNet> = vec![
            "10.0.0.0/16".parse().unwrap(),
            "10.0.3.0/24".parse().unwrap(),
        ];
        assert!(is_broadcast_or_multicast("10.0.3.255", &nested));
        assert!(!is_broadcast_or_multicast("10.0.255.255", &nested[1..]));
        // bez znalosti podsite se smerovany broadcast neuznava
        assert!(!is_broadcast_or_multicast("10.0.3.255", &[]));
        // /31 a /32 nemaji broadcast
        let p2p: Vec<ipnet::IpNet> = vec!["10.9.9.0/31".parse().unwrap()];
        assert!(!is_broadcast_or_multicast("10.9.9.1", &p2p));
        let window = OpsWindow::default();
        assert!(
            super::classify(
                &window,
                "unexpected_traffic",
                None,
                "10.0.3.255",
                &[],
                &wide
            )
            .is_none()
        );
    }

    /// Review kola 1 (S6): duvod hostu nezavisi na poradi HashMap.
    #[test]
    fn host_level_reason_is_deterministic() {
        let policy = OpsPolicy::default();
        let mut c = Clientele::default();
        let mut learn = Vec::new();
        let mut fail = Vec::new();
        for port in [443u16, 8443, 22, 993, 25, 80] {
            for i in 0..20 {
                let src = format!("10.0.1.{}", i + 1);
                learn.push(flow(&src, "10.0.0.9", port, "SF", 5000));
                if i < 10 + port as usize % 5 {
                    fail.push(flow(&src, "10.0.0.9", port, "S0", 0));
                }
            }
        }
        c.learn(&learn, &HashSet::new(), 0, &policy);
        let reasons: HashSet<String> = (0..20)
            .map(|_| {
                let window = c.clone().evidence(&fail, 1800, &policy);
                classify(
                    &window,
                    "service_unreachable",
                    Some("10.0.0.9"),
                    "10.0.0.9",
                    &[],
                )
                .expect("E1 na hostu")
            })
            .collect();
        assert_eq!(reasons.len(), 1, "{reasons:?}");
        // vyhrava nejmensi klic sluzby (10.0.0.9/tcp/22: 12 selhavajicich zdroju)
        assert!(reasons.iter().next().unwrap().contains("12 zdroju"));
    }

    #[test]
    fn marks_survive_late_display_within_ttl() {
        let mut marks = OpsMarks::default();
        let svc = Some("10.0.0.9/tcp/443");
        marks.note("finding:x", 1000, "provoz E1", svc, &[]);
        assert_eq!(marks.get("finding:x", 1000 + 3600), Some("provoz E1"));
        // pozdni zobrazeni bez zdroju a bez eskalace: znacka plati
        assert_eq!(
            marks.update("finding:x", 1000 + 3600, None, svc, &[], false),
            Some("provoz E1")
        );
        assert!(marks.get("finding:x", 1000 + OPS_MARK_TTL_S + 1).is_none());
        assert!(marks.get("finding:y", 1000).is_none());
        marks.sweep(1000 + OPS_MARK_TTL_S + 1);
        assert!(marks.is_empty());
    }

    /// Review kola 1 (S1): novy jednozdrojovy utok se stejnym `finding_id` nedostane
    /// stary duvod provozu; znacku zneplatni i zdroj mimo otisk, jina sluzba a eskalace.
    #[test]
    fn mark_is_invalidated_by_contradicting_evidence() {
        let svc = Some("10.0.0.9/tcp/443");
        let pair = vec!["10.0.1.1".to_string(), "10.0.1.2".to_string()];
        let attacker = vec!["203.0.113.7".to_string()];
        let fresh = |marks: &mut OpsMarks| marks.note("f", 1000, "provoz E1", svc, &pair);
        let cases: [(&str, Option<&str>, &[String], bool); 4] = [
            ("jediny zdroj", svc, &attacker, false),
            (
                "zdroj mimo otisk",
                svc,
                &[pair[0].clone(), attacker[0].clone()],
                false,
            ),
            ("jina sluzba", Some("10.0.0.9/tcp/22"), &[], false),
            ("eskalace v pameti", svc, &[], true),
        ];
        for (label, service, sources, escalated) in cases {
            let mut marks = OpsMarks::default();
            fresh(&mut marks);
            assert!(
                marks
                    .update("f", 1000 + 1800, None, service, sources, escalated)
                    .is_none(),
                "{label}"
            );
            // zneplatnena znacka se nevrati ani v dalsim cyklu
            assert!(
                marks
                    .update("f", 1000 + 3600, None, svc, &[], false)
                    .is_none(),
                "{label}"
            );
        }
        // podmnozina zdroju otisku: plati
        let mut marks = OpsMarks::default();
        fresh(&mut marks);
        assert!(marks.update("f", 2800, None, svc, &pair, false).is_some());
        // cerstvy dukaz pri eskalaci znacku obnovi (dukaz z tohoto okna)
        assert!(
            marks
                .update("f", 2800, Some("provoz E1".into()), svc, &pair, true)
                .is_some()
        );
    }

    /// Stary stav `ops_marks` (pred review kola 1) se nacte; znacky bez otisku se zahodi.
    #[test]
    fn legacy_ops_marks_state_loads_and_fails_closed() {
        let old = r#"{"marks":{"finding:x":[1000,"provoz E1"]}}"#;
        let marks: OpsMarks = serde_json::from_str(old).expect("stary stav se nacte");
        assert!(marks.get("finding:x", 1000).is_none());
        let mut new = OpsMarks::default();
        new.note("finding:y", 1000, "provoz E2", None, &[]);
        let text = serde_json::to_string(&new).unwrap();
        let back: OpsMarks = serde_json::from_str(&text).unwrap();
        assert_eq!(back.get("finding:y", 1000), Some("provoz E2"));
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
