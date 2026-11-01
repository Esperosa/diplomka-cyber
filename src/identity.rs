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
//! Omezení: tyto testy (níže) ověřují logiku na autorsky vytvořených (ne reálně
//! zachycených) sekvencích běhů. Deliverable 22 (`src/identity_lab.rs`) tuhle logiku
//! navíc ověřil na REÁLNÉ síti (Docker bridge se skutečným ARP objevováním) - DHCP
//! renewal i NAT/swap správně rozlišeny, viz
//! `docs/diplomka/eval/identity-layer-real-network.md`. Skutečná vícedenní síťová data
//! s potvrzenou fyzickou identitou zařízení (longitudinal capture, víc VLAN segmentů)
//! stále nejsou k dispozici - zobecnění nad jednu plochou podsíť a krátký časový úsek
//! zůstává budoucí práce.

use std::{collections::HashMap, fs, path::Path};

use serde::{Deserialize, Serialize};

use crate::{error::Result, model::HostReport, storage};

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
#[derive(Debug, Default, Serialize, Deserialize)]
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

/// Generická jména zařízení, která identitu nenesou (stejná u mnoha zařízení).
const GENERIC_HOSTNAMES: &[&str] = &[
    "localhost",
    "iphone",
    "ipad",
    "android",
    "galaxy",
    "unknown",
    "espressif",
    "raspberrypi",
    "desktop",
    "laptop",
    "printer",
    "camera",
];

fn normalize_hostname(name: &str) -> Option<String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let short = name.split('.').next().unwrap_or("").to_string();
    if short.len() < 3 || GENERIC_HOSTNAMES.contains(&short.as_str()) {
        return None;
    }
    Some(short)
}

/// Vícesignálová identita (engine v3, krok 1E; audit A26, R8): MAC > jméno hostu
/// (nenese-li identitu = generické, nebo se v témže snímku opakuje, ignoruje se) >
/// IP. Příčina 35 % falešného rozdělení / 26 % sloučení ve v2b je v enginu: bez MAC
/// (podsítě mimo L2 dosah skeneru) byla identita jen IP, takže každá změna DHCP adresy
/// vyrobila nový asset a přidělení adresy jinému zařízení assety slilo. Stav je
/// serializovatelný (uložená registrace přežije restart). Zdokumentované omezení:
/// jméno hostu může být podvržené (DHCP option 12), proto MAC vždy vyhrává a konflikt
/// MAC proti jménu se neslučuje.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct IdentityResolverV3 {
    asset_by_mac: HashMap<String, AssetId>,
    asset_by_hostname: HashMap<String, AssetId>,
    asset_by_ip_only: HashMap<String, AssetId>,
    last_mac_at_ip: HashMap<String, String>,
    /// Kterému jménu IP-only asset patřil (aby se přidělení IP jinému zařízení nesloučilo).
    hostname_at_ip: HashMap<String, String>,
    /// Poslední asset na IP (pro dočasně chybějící hosty perzistentního inventáře).
    #[serde(default)]
    last_asset_at_ip: HashMap<String, AssetId>,
    next_id: u64,
}

impl IdentityResolverV3 {
    pub fn new() -> Self {
        Self::default()
    }

    fn new_id(&mut self) -> AssetId {
        self.next_id += 1;
        format!("asset:{}", self.next_id)
    }

    /// Vyřeší identitu všech hostů jednoho snímku (pořadí výsledků = pořadí `hosts`).
    /// Jméno se použije jen tehdy, je-li ve snímku jedinečné.
    pub fn resolve_snapshot(&mut self, hosts: &[HostReport]) -> Vec<IdentityMatch> {
        self.resolve_snapshot_with(hosts, |_| false)
    }

    /// Jako `resolve_snapshot`; hosty, které jsou jen dočasně držené v inventáři
    /// (`stale(ip)`, v posledním skenu chyběly), nejsou čerstvé pozorování: nepočítají
    /// se do jedinečnosti jmen a dostanou poslední asset své IP. Jinak by se jméno
    /// zařízení, které změnilo adresu, objevilo dvakrát a identita by se rozpadla.
    pub fn resolve_snapshot_with(
        &mut self,
        hosts: &[HostReport],
        stale: impl Fn(&str) -> bool,
    ) -> Vec<IdentityMatch> {
        let mut name_count: HashMap<String, usize> = HashMap::new();
        for host in hosts.iter().filter(|h| !stale(&h.ip)) {
            if let Some(name) = host.hostname.as_deref().and_then(normalize_hostname) {
                *name_count.entry(name).or_default() += 1;
            }
        }
        hosts
            .iter()
            .map(|host| {
                if stale(&host.ip)
                    && let Some(asset) = self.last_asset_at_ip.get(&host.ip)
                {
                    return IdentityMatch::Same(asset.clone());
                }
                let name = host
                    .hostname
                    .as_deref()
                    .and_then(normalize_hostname)
                    .filter(|n| name_count.get(n).copied() == Some(1));
                let matched = self.resolve_one(host, name);
                self.last_asset_at_ip
                    .insert(host.ip.clone(), matched.asset_id().to_string());
                matched
            })
            .collect()
    }

    fn resolve_one(&mut self, host: &HostReport, name: Option<String>) -> IdentityMatch {
        let ip = host.ip.clone();
        if let Some(mac) = host.mac.as_deref().filter(|m| !m.is_empty()) {
            if let Some(existing) = self.asset_by_mac.get(mac).cloned() {
                self.last_mac_at_ip.insert(ip, mac.to_string());
                if let Some(name) = name {
                    self.asset_by_hostname
                        .entry(name)
                        .or_insert(existing.clone());
                }
                return IdentityMatch::Same(existing);
            }
            // MAC neznámá: jméno může navázat na asset viděný dřív bez MAC (jiná podsíť)
            let by_name = name
                .as_ref()
                .and_then(|n| self.asset_by_hostname.get(n).cloned());
            if let Some(existing) = by_name {
                self.asset_by_mac.insert(mac.to_string(), existing.clone());
                self.last_mac_at_ip.insert(ip, mac.to_string());
                return IdentityMatch::Same(existing);
            }
            let previous = self.last_mac_at_ip.get(&ip).cloned();
            let id = self.new_id();
            self.asset_by_mac.insert(mac.to_string(), id.clone());
            self.last_mac_at_ip.insert(ip.clone(), mac.to_string());
            if let Some(name) = name {
                self.asset_by_hostname.insert(name, id.clone());
            }
            return match previous {
                Some(previous_mac) if previous_mac != mac => IdentityMatch::Ambiguous {
                    candidate: self
                        .asset_by_mac
                        .get(&previous_mac)
                        .cloned()
                        .unwrap_or_else(|| format!("asset:unknown-mac:{previous_mac}")),
                    reason: format!(
                        "IP {ip} drive patrilo MAC {previous_mac}, nyni MAC {mac} - mozna vymena zarizeni nebo NAT, neslucuji automaticky"
                    ),
                },
                _ => IdentityMatch::New(id),
            };
        }
        if let Some(name) = name {
            if let Some(existing) = self.asset_by_hostname.get(&name).cloned() {
                self.asset_by_ip_only.insert(ip.clone(), existing.clone());
                self.hostname_at_ip.insert(ip, name);
                return IdentityMatch::Same(existing);
            }
            let id = self.new_id();
            self.asset_by_hostname.insert(name.clone(), id.clone());
            self.asset_by_ip_only.insert(ip.clone(), id.clone());
            self.hostname_at_ip.insert(ip, name);
            return IdentityMatch::New(id);
        }
        // bez MAC i jmena: IP, ale ne pres asset, ktery na te IP mel jine jmeno
        if self.hostname_at_ip.contains_key(&ip) {
            self.hostname_at_ip.remove(&ip);
            let id = self.new_id();
            self.asset_by_ip_only.insert(ip, id.clone());
            return IdentityMatch::New(id);
        }
        if let Some(existing) = self.asset_by_ip_only.get(&ip).cloned() {
            return IdentityMatch::Same(existing);
        }
        let id = self.new_id();
        self.asset_by_ip_only.insert(ip, id.clone());
        IdentityMatch::New(id)
    }

    pub fn registered_assets(&self) -> usize {
        self.next_id as usize
    }
}

/// Jako `resolve_and_annotate`, ale s vícesignálovým resolverem v3 a vlastní registrací.
pub fn resolve_and_annotate_v3(
    hosts: &mut [HostReport],
    registry_path: &Path,
) -> Result<Vec<IdentityMatch>> {
    let mut resolver: IdentityResolverV3 = if registry_path.exists() {
        let bytes = fs::read(registry_path)?;
        serde_json::from_slice(&bytes).map_err(crate::error::BakulaError::Json)?
    } else {
        IdentityResolverV3::new()
    };
    let matches = resolver.resolve_snapshot(hosts);
    for (host, identity_match) in hosts.iter_mut().zip(&matches) {
        host.asset_id = Some(identity_match.asset_id().to_string());
        host.identity_note = match identity_match {
            IdentityMatch::Ambiguous { reason, .. } => Some(reason.clone()),
            IdentityMatch::Same(_) | IdentityMatch::New(_) => None,
        };
    }
    let bytes = serde_json::to_vec_pretty(&resolver).map_err(crate::error::BakulaError::Json)?;
    storage::write_atomic(registry_path, &bytes)?;
    Ok(matches)
}

/// Produkční plán (core wiring, 30.10.2026): první skutečný produkční vstupní
/// bod pro tuhle vrstvu - dřív se `IdentityResolver` volal jen z `src/lab.rs`/
/// `src/identity_lab.rs` (testovací harness), nikdy z `pipeline::run_pipeline`.
/// Stínově/aditivně (stejná disciplína jako H2 fúze): `host_key`/`host_id` se
/// nemění, jen se doplní `asset_id`/`identity_note` na každý `HostReport`.
///
/// `IdentityResolver` je stavový a vyžaduje chronologické pořadí volání mezi
/// běhy - CLI invokace jsou ale jednorázové procesy, takže stav musí žít v
/// souboru (`registry_path`), ne v paměti. **Známé omezení, vědomě
/// nedořešené**: načtení→úprava→zápis tady NENÍ zamčené proti souběžným
/// zápisům - dva pipeline běhy nad stejným workspace souběžně by si mohly
/// tiše přepsat jeden druhého přiřazení nových asset_id (ztracená aktualizace,
/// ne korupce - `storage::write_atomic` korupci už vylučuje). Stejná
/// nedořešená třída rizika jako `storage.rs`'s `save_run` read-modify-write
/// na `index.json` - není to nová regrese, je to existující mezera v tom, jak
/// tenhle workspace dnes řeší souběžný přístup víc procesů. Řešení (zámek
/// nebo DB) je budoucí práce, ne blokátor pro tenhle aditivní krok.
/// Vraci `IdentityMatch` pro kazdy host (stejne poradi jako `hosts`) - volajici
/// (`pipeline::run_pipeline`) to pouziva pro `hypothesis::build_hypotheses_for_report`,
/// aniz by musel zpetne odhadovat match-druh z uz zplostene `asset_id`/`identity_note`
/// dvojice (coz by bylo presne to "fabrikovani chybejici informace", co modulova
/// dokumentace `hypothesis.rs` vyslovne zakazuje).
pub fn resolve_and_annotate(
    hosts: &mut [HostReport],
    registry_path: &Path,
) -> Result<Vec<IdentityMatch>> {
    let mut resolver: IdentityResolver = if registry_path.exists() {
        let bytes = fs::read(registry_path)?;
        serde_json::from_slice(&bytes).map_err(crate::error::BakulaError::Json)?
    } else {
        IdentityResolver::new()
    };

    let mut matches = Vec::with_capacity(hosts.len());
    for host in hosts.iter_mut() {
        let identity_match = resolver.resolve(host);
        host.asset_id = Some(identity_match.asset_id().to_string());
        host.identity_note = match &identity_match {
            IdentityMatch::Ambiguous { reason, .. } => Some(reason.clone()),
            IdentityMatch::Same(_) | IdentityMatch::New(_) => None,
        };
        matches.push(identity_match);
    }

    let bytes = serde_json::to_vec_pretty(&resolver).map_err(crate::error::BakulaError::Json)?;
    storage::write_atomic(registry_path, &bytes)?;
    Ok(matches)
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
            asset_id: None,
            identity_note: None,
            device_class: None,
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

    /// Audit nalez (skeptik, produkcni gap analyza 30.10.2026): `identity.rs`
    /// nemel zadny produkcni vstupni bod - `IdentityResolver` zil jen v
    /// pameti jednoho testu/labu, nikdy ne pres 2 ODDELENE procesy (coz CLI
    /// invokace vzdy jsou). Tenhle test overuje presne tu cross-run
    /// kontinuitu pres skutecny soubor na disku - 2 nezavisla volani
    /// `resolve_and_annotate` (simulace 2 samostatnych `bakula-program`
    /// behu) musi dat stejny `asset_id` pri DHCP renewal (stejna MAC, nova IP).
    #[test]
    fn resolve_and_annotate_persists_identity_across_two_separate_calls() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let registry_path = temp.path().join("identity-registry.json");

        // Prvni beh vidi 2 zarizeni (A, pak B) - B tedy NENI prvni MAC, co
        // resolver kdy videl (dostane "druhe" ID). Bez perzistence by druhy
        // beh zacinal s cerstvym resolverem, kde by B byla (chybne) prvni
        // MAC, co kdy videl - a dostala by "prvni" ID, ne to, co uz ma z
        // prvniho behu. Zamerne NEporovnavam jen stejnou pozici v obou behu
        // (to by nahodne vyslo stejne i bez perzistence).
        let mut run1_hosts = vec![
            host("10.0.0.5", Some("aa:bb:cc:00:00:0a")), // A
            host("10.0.0.6", Some("aa:bb:cc:00:00:0b")), // B
        ];
        resolve_and_annotate(&mut run1_hosts, &registry_path).expect("prvni beh");
        let b_asset_id_run1 = run1_hosts[1].asset_id.clone().expect("asset_id nastaven");

        // Druhy, NEZAVISLY beh (nova fn volani = jako novy CLI proces) - jen
        // DHCP renewal zarizeni B (stejna MAC, nova IP), B je tu JEDINY host.
        let mut run2_hosts = vec![host("10.0.0.9", Some("aa:bb:cc:00:00:0b"))];
        resolve_and_annotate(&mut run2_hosts, &registry_path).expect("druhy beh");
        let b_asset_id_run2 = run2_hosts[0].asset_id.clone().expect("asset_id nastaven");

        assert_eq!(
            b_asset_id_run1, b_asset_id_run2,
            "DHCP renewal pres 2 nezavisla volani (ruzne procesy) musi dat stejny asset_id, ne 'prvni ID cerstveho resolveru'"
        );
        assert!(run2_hosts[0].identity_note.is_none());
    }

    fn named(ip: &str, mac: Option<&str>, name: Option<&str>) -> HostReport {
        HostReport {
            hostname: name.map(ToString::to_string),
            ..host(ip, mac)
        }
    }

    /// Regrese v2b (35 % falesne rozdeleno): zarizeni bez MAC (mimo L2 dosah) zmeni
    /// DHCP adresu; jedinecne jmeno hostu identitu udrzi, IP-only resolver ne.
    #[test]
    fn v3_keeps_identity_across_dhcp_change_without_mac_via_unique_hostname() {
        let mut legacy = IdentityResolver::new();
        let mut v3 = IdentityResolverV3::new();
        let a = named("10.0.5.120", None, Some("ws-17.corp.local"));
        let b = named("10.0.5.188", None, Some("WS-17"));
        let legacy_ids = [legacy.resolve(&a), legacy.resolve(&b)];
        assert_ne!(legacy_ids[0].asset_id(), legacy_ids[1].asset_id());
        let first = v3.resolve_snapshot(std::slice::from_ref(&a));
        let second = v3.resolve_snapshot(std::slice::from_ref(&b));
        assert_eq!(first[0].asset_id(), second[0].asset_id());
    }

    /// Regrese v2b (26 % falesne slouceno): jine zarizeni na stejne IP bez MAC
    /// se s predchozim nesmi slit, kdyz ma jine (nebo zadne) jmeno.
    #[test]
    fn v3_does_not_merge_different_device_taking_over_ip() {
        let mut v3 = IdentityResolverV3::new();
        let first = v3.resolve_snapshot(&[named("10.0.5.120", None, Some("ws-17"))]);
        let other = v3.resolve_snapshot(&[named("10.0.5.120", None, Some("printer-3"))]);
        let nameless = v3.resolve_snapshot(&[named("10.0.5.120", None, None)]);
        assert_ne!(first[0].asset_id(), other[0].asset_id());
        assert_ne!(other[0].asset_id(), nameless[0].asset_id());
    }

    #[test]
    fn v3_ignores_generic_or_duplicate_names_and_prefers_mac() {
        let mut v3 = IdentityResolverV3::new();
        // dva telefony "iPhone" ve stejnem snimku: jmeno nenese identitu
        let snap = v3.resolve_snapshot(&[
            named("10.0.5.10", None, Some("iPhone")),
            named("10.0.5.11", None, Some("iPhone")),
            named("10.0.5.12", None, Some("tablet-9")),
            named("10.0.5.13", None, Some("tablet-9")),
        ]);
        let ids: std::collections::HashSet<_> =
            snap.iter().map(|m| m.asset_id().to_string()).collect();
        assert_eq!(ids.len(), 4);
        // MAC vyhrava nad jmenem; po zmene IP se stejnou MAC zustava asset
        let with_mac =
            v3.resolve_snapshot(&[named("10.0.0.5", Some("aa:00:00:00:00:01"), Some("srv-1"))]);
        let moved = v3.resolve_snapshot(&[named(
            "10.0.0.6",
            Some("aa:00:00:00:00:01"),
            Some("srv-renamed"),
        )]);
        assert_eq!(with_mac[0].asset_id(), moved[0].asset_id());
    }

    #[test]
    fn v3_registry_survives_restart() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let path = temp.path().join("identity-registry-v3.json");
        let mut run1 = vec![named("10.0.9.100", None, Some("cam-4"))];
        resolve_and_annotate_v3(&mut run1, &path).unwrap();
        let mut run2 = vec![named("10.0.9.150", None, Some("cam-4"))];
        resolve_and_annotate_v3(&mut run2, &path).unwrap();
        assert_eq!(run1[0].asset_id, run2[0].asset_id);
    }

    #[test]
    fn resolve_and_annotate_surfaces_ambiguous_match_as_identity_note() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let registry_path = temp.path().join("identity-registry.json");

        let mut run1_hosts = vec![host("10.0.0.5", Some("aa:bb:cc:00:00:01"))];
        resolve_and_annotate(&mut run1_hosts, &registry_path).expect("prvni beh");

        // Stejna IP, JINA MAC - NAT/vymena zarizeni, nesmi se tise slit.
        let mut run2_hosts = vec![host("10.0.0.5", Some("aa:bb:cc:00:00:02"))];
        resolve_and_annotate(&mut run2_hosts, &registry_path).expect("druhy beh");

        assert!(
            run2_hosts[0].identity_note.is_some(),
            "ambiguous shoda (NAT/vymena HW) musi zustat viditelna, ne tise zmizet"
        );
    }
}
