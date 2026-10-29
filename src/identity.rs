//! Multi-signálová identita zařízení napříč běhy (Deliverable 2, navazuje na `src/eval/`).
//!
//! `report.rs::normalize_inventory()` dnes dává hostu identitu podle `host.ip` - to je
//! stabilní jen uvnitř jednoho běhu, ne mezi běhy (DHCP renewal vytvoří "nový" host,
//! NAT/výměna zařízení za stejnou IP se naopak tiše slučuje). Žádná funkce v
//! `correlation.rs`/`findings.rs`/`decision.rs` nezávisí na tom, že `host_key` je
//! konkrétně IP - jen na tom, že je to stabilní klíč v rámci běhu (ověřeno). Tento modul
//! je proto samostatná vrstva NAD `normalize_inventory()`, ne jeho náhrada - `host_key`/
//! `host_id` se tu nemění, přidává se jen `asset_id` jako doplňkový, cross-run identifikátor.
//!
//! Omezení: ověřeno na autorsky vytvořených (ne reálně zachycených) sekvencích běhů -
//! reálná vícedenní síťová data s potvrzenou fyzickou identitou zařízení (longitudinal
//! capture) nejsou k dispozici; validace na takových datech je budoucí práce (vlna 3,
//! Mininet/Containerlab simulace DHCP/NAT churn).

use std::collections::HashMap;

use crate::model::HostReport;

pub type AssetId = String;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityMatch {
    /// MAC (nebo IP bez MAC) už byla viděna - stejný asset jako dřív.
    Same(AssetId),
    /// Nový asset - MAC (nebo IP bez MAC) dosud neznámá, bez konfliktu s historií.
    New(AssetId),
    /// IP, která dřív patřila jiné MAC, se teď objevuje s novou MAC. Nejde o automatické
    /// sloučení ani automatické rozdělení - vracíme obě strany sporu a necháváme rozhodnutí
    /// výš (NAT, výměna HW, nebo chyba): tichá chyba (sloučení dvou různých zařízení) je
    /// nebezpečnější než viditelně nerozhodnutý případ.
    Ambiguous { candidate: AssetId, reason: String },
}

impl IdentityMatch {
    pub fn asset_id(&self) -> &str {
        match self {
            IdentityMatch::Same(id) | IdentityMatch::New(id) => id,
            IdentityMatch::Ambiguous { candidate, .. } => candidate,
        }
    }
}

/// Udržuje stav mezi běhy (MAC/IP mapování), proto je to `struct` s `&mut self`, ne čistá
/// funkce - `storage.rs` dnes ukládá běhy jednotlivě bez cross-run asset registru, tohle
/// je první místo, které tu kontinuitu zavádí.
#[derive(Debug, Default)]
pub struct IdentityResolver {
    asset_by_mac: HashMap<String, AssetId>,
    asset_by_ip_only: HashMap<String, AssetId>,
    last_mac_at_ip: HashMap<String, String>,
    next_id: u64,
}

impl IdentityResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Vyřeší identitu jednoho pozorování hosta (typicky `HostReport` z jednoho běhu).
    /// Pořadí volání musí odpovídat časovému pořadí běhů - resolver je stavový.
    pub fn resolve(&mut self, host: &HostReport) -> IdentityMatch {
        match host.mac.as_deref().filter(|mac| !mac.is_empty()) {
            Some(mac) => self.resolve_with_mac(&host.ip, mac),
            None => self.resolve_without_mac(&host.ip),
        }
    }

    fn resolve_with_mac(&mut self, ip: &str, mac: &str) -> IdentityMatch {
        if let Some(existing) = self.asset_by_mac.get(mac).cloned() {
            self.last_mac_at_ip.insert(ip.to_string(), mac.to_string());
            return IdentityMatch::Same(existing);
        }

        // MAC dosud neznámá. Patřila tahle IP v minulosti jiné MAC? -> NAT/výměna HW.
        if let Some(previous_mac) = self.last_mac_at_ip.get(ip).cloned()
            && previous_mac != mac
        {
            let candidate = self
                .asset_by_mac
                .get(&previous_mac)
                .cloned()
                .unwrap_or_else(|| format!("asset:unknown-mac:{previous_mac}"));
            let new_id = self.new_id();
            self.asset_by_mac.insert(mac.to_string(), new_id.clone());
            self.last_mac_at_ip.insert(ip.to_string(), mac.to_string());
            return IdentityMatch::Ambiguous {
                candidate,
                reason: format!(
                    "IP {ip} dříve patřilo MAC {previous_mac}, nyní MAC {mac} - možná výměna zařízení nebo NAT, neslučuji automaticky"
                ),
            };
        }

        let new_id = self.new_id();
        self.asset_by_mac.insert(mac.to_string(), new_id.clone());
        self.last_mac_at_ip.insert(ip.to_string(), mac.to_string());
        IdentityMatch::New(new_id)
    }

    fn resolve_without_mac(&mut self, ip: &str) -> IdentityMatch {
        // Fallback pro zařízení mimo L2 dosah (typicky firewall/router za hranicí ARP) -
        // identita je tu nutně jen tak stabilní jako IP samotná, zdokumentované omezení.
        if let Some(existing) = self.asset_by_ip_only.get(ip).cloned() {
            return IdentityMatch::Same(existing);
        }
        let new_id = self.new_id();
        self.asset_by_ip_only.insert(ip.to_string(), new_id.clone());
        IdentityMatch::New(new_id)
    }

    fn new_id(&mut self) -> AssetId {
        self.next_id += 1;
        format!("asset:{}", self.next_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::HostReport;

    fn host(ip: &str, mac: Option<&str>) -> HostReport {
        HostReport {
            host_id: format!("host:{ip}"),
            host_key: ip.to_string(),
            ip: ip.to_string(),
            hostname: None,
            mac: mac.map(ToString::to_string),
            vendor: None,
            services: Vec::new(),
        }
    }

    /// Stará logika (`host_key = ip`) pro srovnání fragmentace - ne produkční kód,
    /// jen reprodukce dnešního chování `report.rs::normalize_inventory()` pro měření.
    fn old_host_key_fragmentation(sequence: &[HostReport]) -> usize {
        sequence
            .iter()
            .map(|host| host.ip.clone())
            .collect::<std::collections::HashSet<_>>()
            .len()
    }

    #[test]
    fn dhcp_renewal_same_mac_resolves_to_one_asset_but_two_host_keys() {
        // Stejné zařízení (MAC aa:bb:cc:dd:ee:01), tři DHCP pronájmy v čase.
        let sequence = vec![
            host("192.168.1.50", Some("aa:bb:cc:dd:ee:01")),
            host("192.168.1.77", Some("aa:bb:cc:dd:ee:01")),
            host("192.168.1.102", Some("aa:bb:cc:dd:ee:01")),
        ];

        // Baseline (host_key=ip) vidí 3 "různé" hosty - fragmentace.
        assert_eq!(old_host_key_fragmentation(&sequence), 3);

        let mut resolver = IdentityResolver::new();
        let matches: Vec<_> = sequence.iter().map(|host| resolver.resolve(host)).collect();

        assert!(matches!(matches[0], IdentityMatch::New(_)));
        assert!(matches!(matches[1], IdentityMatch::Same(_)));
        assert!(matches!(matches[2], IdentityMatch::Same(_)));
        let asset_ids: std::collections::HashSet<_> =
            matches.iter().map(IdentityMatch::asset_id).collect();
        assert_eq!(
            asset_ids.len(),
            1,
            "nová logika musí vidět jeden asset, ne tři"
        );
    }

    #[test]
    fn nat_or_device_swap_same_ip_different_mac_is_flagged_not_merged() {
        let sequence = [
            host("10.0.0.5", Some("aa:11:11:11:11:11")),
            // jiné zařízení se objeví na stejné IP (NAT lease / výměna HW)
            host("10.0.0.5", Some("bb:22:22:22:22:22")),
        ];

        let mut resolver = IdentityResolver::new();
        let first = resolver.resolve(&sequence[0]);
        let second = resolver.resolve(&sequence[1]);

        assert!(matches!(first, IdentityMatch::New(_)));
        match second {
            IdentityMatch::Ambiguous { candidate, reason } => {
                assert_eq!(candidate, first.asset_id());
                assert!(reason.contains("10.0.0.5"));
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn host_without_mac_falls_back_to_ip_with_documented_limitation() {
        // Router/firewall mimo ARP dosah - žádná MAC v Nmap XML (viz nmap.rs).
        let sequence = [host("172.16.0.1", None), host("172.16.0.1", None)];

        let mut resolver = IdentityResolver::new();
        let first = resolver.resolve(&sequence[0]);
        let second = resolver.resolve(&sequence[1]);

        assert!(matches!(first, IdentityMatch::New(_)));
        assert!(matches!(second, IdentityMatch::Same(_)));
        assert_eq!(first.asset_id(), second.asset_id());
    }

    #[test]
    fn mixed_fleet_mac_resolution_reduces_fragmentation_vs_ip_only_baseline() {
        // 2 reálná zařízení, každé 2x DHCP renew = 4 pozorování, stará logika vidí 4 hosty.
        let sequence = vec![
            host("192.168.1.10", Some("aa:00:00:00:00:01")),
            host("192.168.1.20", Some("aa:00:00:00:00:02")),
            host("192.168.1.30", Some("aa:00:00:00:00:01")), // renew zařízení 1
            host("192.168.1.40", Some("aa:00:00:00:00:02")), // renew zařízení 2
        ];

        assert_eq!(old_host_key_fragmentation(&sequence), 4);

        let mut resolver = IdentityResolver::new();
        let asset_ids: std::collections::HashSet<_> = sequence
            .iter()
            .map(|host| resolver.resolve(host).asset_id().to_string())
            .collect();

        assert_eq!(
            asset_ids.len(),
            2,
            "nová logika musí vidět 2 zařízení, ne 4"
        );
    }
}
