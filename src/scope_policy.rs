//! A9 guardrail, krok 1 (`docs/diplomka/produkcni-plan.md`, Faze A/B): spolecna
//! kontrola autorizovaneho rozsahu, volana PRI VYKONANI aktivni kontroly - presne
//! tam, kde byla mezera objevena 31.10.2026 (`run_forensic_followup_nmap`/
//! `run_targeted_followup_nmap` nikdy nekontrolovaly cile proti `--scope`, opraveno
//! primo v `nmap.rs`). `ScopePolicy` je ten spolecny, testovatelny kus, co
//! `nmap.rs` uz pouziva a ktery `verification_planner`/budouci `webscan.rs`/
//! `pentest.rs` zapojeni muze pouzit beze duplikace stejne fail-closed logiky.

use std::net::IpAddr;

use ipnet::IpNet;

/// Fail-closed: neparsovatelna IP neni nikdy v rozsahu (stejna disciplina jako
/// chybejici label -> "Unknown" v `eval/`, ne tiche "proste to zkus").
#[derive(Debug, Clone)]
pub struct ScopePolicy {
    allowed: Vec<IpNet>,
}

impl ScopePolicy {
    pub fn new(allowed: Vec<IpNet>) -> Self {
        Self { allowed }
    }

    /// `true` jen pokud se `ip` parsuje A patri do alespon jedne povolene siti.
    pub fn contains(&self, ip: &str) -> bool {
        ip.parse::<IpAddr>()
            .map(|addr| self.allowed.iter().any(|net| net.contains(&addr)))
            .unwrap_or(false)
    }

    /// Rozdeli `items` na (v rozsahu, mimo rozsah) podle `ip_of`. Mimo-rozsah
    /// polozky se vraceji jako IP retezce k reportovani, ne tise zahazuji.
    pub fn partition<T>(&self, items: Vec<T>, ip_of: impl Fn(&T) -> &str) -> (Vec<T>, Vec<String>) {
        let mut kept = Vec::with_capacity(items.len());
        let mut excluded = Vec::new();
        for item in items {
            if self.contains(ip_of(&item)) {
                kept.push(item);
            } else {
                excluded.push(ip_of(&item).to_string());
            }
        }
        (kept, excluded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ScopePolicy {
        ScopePolicy::new(vec!["192.168.1.0/24".parse().expect("valid cidr")])
    }

    #[test]
    fn contains_accepts_ip_inside_configured_subnet() {
        assert!(policy().contains("192.168.1.42"));
    }

    #[test]
    fn contains_rejects_ip_outside_configured_subnet() {
        assert!(!policy().contains("10.0.0.5"));
    }

    #[test]
    fn contains_rejects_unparseable_ip_fail_closed() {
        assert!(!policy().contains("not-an-ip"));
    }

    #[test]
    fn partition_splits_mixed_items_and_reports_excluded() {
        let items = vec!["192.168.1.1", "10.0.0.1", "192.168.1.2"];
        let (kept, excluded) = policy().partition(items, |item| item);
        assert_eq!(kept, vec!["192.168.1.1", "192.168.1.2"]);
        assert_eq!(excluded, vec!["10.0.0.1".to_string()]);
    }
}
