//! Kontextové vyloučení (engine v3, krok 1D; 00-zaver R6, Dodatek A.2, H-A2, H-A3).
//!
//! Rozhraní `ContextProvider` dodává známý kontext: kalendář údržby a záloh, dávky,
//! patch okna, autorizované skenery, výpadky služeb a senzoru, životní cyklus zařízení
//! (inventář/CMDB). V produkci ho plní soubor `context-calendar.json` ve workspace
//! (`StaticCalendar`, každý záznam musí mít schvalovatele a expiraci, B7), v simulaci
//! `soak::v3::SimContext` REALISTICKY NEÚPLNĚ (parametr pokrytí, posunuté okraje oken
//! a fantomová okna, která se nekonala), aby se nezavedl únik pravdy.
//!
//! `ContextGate` rozhoduje, zda nález spadá do známého kontextu. Mantinely
//! (Dodatek A.2): (a) důvod do auditu a vratnost (zapisuje `finding_memory`),
//! (b) náhodný audit vzorku s měřenou mírou omylu a AUTOMATICKÉ VYPNUTÍ druhu kontextu,
//! jehož horní mez 95% Wilsonova intervalu omylu překročí mez (H-A3), (c) žádné
//! zavření nejzávažnějších typů bez doloženého vysvětlení (explicitně vyjmenovaný typ
//! i host v záznamu), statické expozice z inventáře se kontextem nezavírají nikdy,
//! (d) „nic nenalezeno“ není vysvětlení: zavírá se jen při shodě s konkrétním záznamem.
//! Strop počtu zavření za cyklus brání tomu, aby jeden chybný záznam spolkl vše.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    error::{SalticusError, Result},
    model::Severity,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextKind {
    Maintenance,
    Backup,
    BatchJob,
    PatchWindow,
    AuthorizedScanner,
    ServiceOutage,
    SensorOutage,
    DeviceOnboarding,
    DeviceDecommission,
}

impl ContextKind {
    /// Vysvětluje druh nárůst objemu (pro paměť: eskalace objemu v okně se nezobrazí)?
    pub fn explains_volume(self) -> bool {
        matches!(self, ContextKind::Backup | ContextKind::BatchJob)
    }

    /// Zdrojově citlivý druh: dominantní zdroj nálezu musí být v záznamu (host nebo
    /// zdroj), jinak vysvětlení neplatí (útok uvnitř okna údržby, Dodatek A.2 c).
    pub fn source_sensitive(self) -> bool {
        !matches!(
            self,
            ContextKind::SensorOutage | ContextKind::AuthorizedScanner
        )
    }

    pub const ALL: [ContextKind; 9] = [
        ContextKind::Maintenance,
        ContextKind::Backup,
        ContextKind::BatchJob,
        ContextKind::PatchWindow,
        ContextKind::AuthorizedScanner,
        ContextKind::ServiceOutage,
        ContextKind::SensorOutage,
        ContextKind::DeviceOnboarding,
        ContextKind::DeviceDecommission,
    ];

    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.label() == label)
    }

    pub fn label(self) -> &'static str {
        match self {
            ContextKind::Maintenance => "maintenance",
            ContextKind::Backup => "backup",
            ContextKind::BatchJob => "batch_job",
            ContextKind::PatchWindow => "patch_window",
            ContextKind::AuthorizedScanner => "authorized_scanner",
            ContextKind::ServiceOutage => "service_outage",
            ContextKind::SensorOutage => "sensor_outage",
            ContextKind::DeviceOnboarding => "device_onboarding",
            ContextKind::DeviceDecommission => "device_decommission",
        }
    }

    /// Typy nálezů, které druh kontextu umí vysvětlit (výchozí, když záznam neuvádí `covers`).
    pub fn default_covers(self) -> &'static [&'static str] {
        match self {
            // restarty a vypadky: timeouty klientu, ne narust objemu
            ContextKind::Maintenance | ContextKind::PatchWindow => &[
                "connection_timeout_burst",
                "service_overload_risk",
                "service_unreachable",
            ],
            ContextKind::Backup | ContextKind::BatchJob => &[
                "inductive_volume_anomaly",
                "packet_rate_spike",
                "service_overload_risk",
            ],
            ContextKind::AuthorizedScanner => &[
                "scan_attempts",
                "unexpected_traffic",
                "connection_timeout_burst",
                "unmapped_passive_event",
            ],
            ContextKind::ServiceOutage | ContextKind::DeviceDecommission => &[
                "connection_timeout_burst",
                "service_overload_risk",
                "service_unreachable",
            ],
            ContextKind::SensorOutage => &["inductive_volume_anomaly", "packet_rate_spike"],
            ContextKind::DeviceOnboarding => &[
                "unexpected_traffic",
                "unmapped_passive_event",
                "new_exposed_service",
                "identification_gap",
            ],
        }
    }
}

/// Jeden záznam známého kontextu.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextEntry {
    pub kind: ContextKind,
    /// Cílové hosty (IP nebo asset id). Prázdné = celá síť (jen `SensorOutage`).
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Zdroje (např. IP autorizovaného skeneru). Prázdné = nerozhoduje.
    #[serde(default)]
    pub sources: Vec<String>,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// Explicitně vysvětlené typy; prázdné = `kind.default_covers()`.
    #[serde(default)]
    pub covers: Vec<String>,
    pub approved_by: String,
    /// Po expiraci záznam neplatí (TTL proti trvalým slepým skvrnám, B7).
    pub expires: DateTime<Utc>,
}

impl ContextEntry {
    fn covers(&self, finding_type: &str) -> bool {
        if self.covers.is_empty() {
            self.kind.default_covers().contains(&finding_type)
        } else {
            self.covers.iter().any(|c| c == finding_type)
        }
    }

    fn explicitly_covers(&self, finding_type: &str) -> bool {
        self.covers.iter().any(|c| c == finding_type)
    }

    fn active(&self, at: DateTime<Utc>) -> bool {
        at >= self.start && at <= self.end && at <= self.expires
    }

    fn validate(&self) -> std::result::Result<(), String> {
        if self.approved_by.trim().is_empty() {
            return Err(format!("{}: chybi schvalovatel", self.kind.label()));
        }
        if self.end < self.start || self.expires < self.start {
            return Err(format!("{}: neplatne okno", self.kind.label()));
        }
        if (self.end - self.start).num_days() > 31 {
            return Err(format!("{}: okno delsi nez 31 dni", self.kind.label()));
        }
        if self.hosts.is_empty()
            && self.kind != ContextKind::SensorOutage
            && (self.kind != ContextKind::AuthorizedScanner || self.sources.is_empty())
        {
            return Err(format!(
                "{}: zaznam bez hostu nebo zdroje by vysvetlil celou sit",
                self.kind.label()
            ));
        }
        Ok(())
    }
}

/// Zdroj kontextu (produkce: soubor/CMDB/monitoring; simulace: neúplný kalendář).
pub trait ContextProvider {
    fn entries(&self) -> &[ContextEntry];
}

/// Produkční kalendář ze souboru (`context-calendar.json`, pole `ContextEntry`).
#[derive(Debug, Clone, Default)]
pub struct StaticCalendar {
    entries: Vec<ContextEntry>,
    pub rejected: Vec<String>,
}

impl StaticCalendar {
    pub fn new(entries: Vec<ContextEntry>) -> Self {
        let mut calendar = Self::default();
        for entry in entries {
            match entry.validate() {
                Ok(()) => calendar.entries.push(entry),
                Err(reason) => calendar.rejected.push(reason),
            }
        }
        calendar
    }

    /// Chybějící soubor = prázdný kalendář (nic se nezavírá).
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)?;
        let entries: Vec<ContextEntry> = serde_json::from_str(&text).map_err(SalticusError::Json)?;
        Ok(Self::new(entries))
    }
}

impl ContextProvider for StaticCalendar {
    fn entries(&self) -> &[ContextEntry] {
        &self.entries
    }
}

/// Mantinely brány.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatePolicy {
    /// Typy, které se zavřou jen s explicitním (doloženým) vysvětlením.
    pub most_severe: BTreeSet<String>,
    /// Statické expozice: nikdy kontextem.
    pub never: BTreeSet<String>,
    pub max_closures_per_cycle: usize,
    /// H-A3: vypnout druh kontextu, když DOLNÍ mez 95% intervalu omylu > cíl
    /// (máme doklad, že omyl překračuje cíl 2 %; Dodatek A, H-A2).
    pub audit_error_target: f64,
    pub audit_min_samples: u64,
    /// Krok 6 (kandidát 1): výpadek senzoru nezavírá a není ani podpůrným neškodným
    /// důkazem. Absence dat není vysvětlení (Dodatek A.2 d, RQ6 Z3); v kroku 5 kontext
    /// výpadku zavřel 147 nálezů útoků (impl-krok5.md, G).
    #[serde(default)]
    pub sensor_strict: bool,
    /// Krok 6 (kandidát 6): zdrojově citlivý kontext vysvětlí nález jen s
    /// identifikovaným dominantním zdrojem; výjimka je objem v okně zálohy a dávky.
    #[serde(default)]
    pub require_identified_source: bool,
    /// Krok 7 (A1): chráněné nálezy kontext nevysvětlí ani nepodpoří; nález vysoké
    /// závažnosti nebo bez identifikovaného zdroje zavře jen shoda dvou různých druhů
    /// kontextu (P6), jinak je nejednoznačný (P5).
    #[serde(default)]
    pub protect: bool,
}

impl GatePolicy {
    /// Mantinely podle konfigurace jádra (krok 6 a 7).
    pub fn for_engine(engine: &crate::engine::EngineConfig) -> Self {
        Self {
            sensor_strict: engine.sensor_strict(),
            require_identified_source: engine.context_guard(),
            protect: engine.protect(),
            ..Self::default()
        }
    }

    /// Chráněný vstup (typ P1 až P3, nebo signál P4 a P5 od volajícího).
    fn shields(&self, input: &GateInput<'_>) -> bool {
        self.protect
            && (input.protected || crate::protection::is_protected_type(input.finding_type))
    }

    /// P6: vyžaduje zavření dva nezávislé druhy kontextu?
    fn needs_corroboration(&self, input: &GateInput<'_>) -> bool {
        self.protect && (input.severity == Severity::High || input.sources.is_empty())
    }

    /// Smí záznam vysvětlit nález vzhledem k pravidlům kroku 6?
    fn admits(&self, entry: &ContextEntry, input: &GateInput<'_>) -> bool {
        if self.sensor_strict && entry.kind == ContextKind::SensorOutage {
            return false;
        }
        // P6: vypadek senzoru neni nezavisly druh kontextu (absence dat)
        if self.protect && entry.kind == ContextKind::SensorOutage {
            return false;
        }
        if self.require_identified_source
            && entry.kind.source_sensitive()
            && input.sources.is_empty()
        {
            let volume = matches!(
                input.finding_type,
                "inductive_volume_anomaly" | "packet_rate_spike"
            );
            return entry.kind.explains_volume() && volume;
        }
        true
    }
}

impl Default for GatePolicy {
    fn default() -> Self {
        let set = |items: &[&str]| items.iter().map(|s| s.to_string()).collect();
        Self {
            most_severe: set(&[
                "suricata_alert",
                "ids_alert",
                "multi_target_pattern",
                "external_flow_observed",
                "service_overload_risk",
            ]),
            never: set(&[
                "known_exploited_vulnerability",
                "high_risk_cve_exposure",
                "probable_exploitation_interest",
                "plaintext_management_protocol",
                "management_surface_exposure",
                "correlation_uncertainty",
            ]),
            max_closures_per_cycle: 200,
            audit_error_target: 0.02,
            audit_min_samples: 30,
            sensor_strict: false,
            require_identified_source: false,
            protect: false,
        }
    }
}

/// Vstup brány pro jeden nález.
#[derive(Debug, Clone)]
pub struct GateInput<'a> {
    pub finding_type: &'a str,
    /// IP cíle a/nebo asset id; shoda s kterýmkoli stačí.
    pub host_ids: &'a [String],
    pub sources: &'a [String],
    pub severity: Severity,
    pub at: DateTime<Utc>,
    /// Krok 7: volající zjistil ochranu P4 nebo P5 (degradace, nejednoznačná identita).
    pub protected: bool,
}

/// Výsledek: druh kontextu a čitelný důvod pro audit/UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    pub kind: ContextKind,
    pub reason: String,
}

/// Rozhodnutí brány včetně nejednoznačnosti (krok 7, P5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GateDecision {
    pub explanation: Option<Explanation>,
    /// Záznam odpovídá hostu a typu, ale zdroj je mimo záznam nebo chybí druhý
    /// nezávislý druh kontextu (P6). Jen s `protect`.
    pub ambiguous: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct GateStats {
    pub explained: u64,
    pub refused_severe: u64,
    pub refused_cap: u64,
    pub refused_disabled: u64,
    pub refused_source: u64,
    pub disabled_kinds: Vec<String>,
    /// Krok 7: odmítnuto kvůli ochraně (P1 až P5) a kvůli jedinému druhu (P6).
    #[serde(default)]
    pub refused_protected: u64,
    #[serde(default)]
    pub refused_corroboration: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ContextGate {
    pub policy: GatePolicy,
    closures_this_cycle: usize,
    audit: BTreeMap<ContextKind, (u64, u64)>,
    disabled: BTreeSet<ContextKind>,
    pub stats: GateStats,
}

fn wilson_bounds(k: u64, n: u64) -> (f64, f64) {
    if n == 0 {
        return (0.0, 1.0);
    }
    let z = 1.959_963_984_540_054_f64;
    let n_f = n as f64;
    let p = k as f64 / n_f;
    let denom = 1.0 + z * z / n_f;
    let center = (p + z * z / (2.0 * n_f)) / denom;
    let margin = z * ((p * (1.0 - p) / n_f) + z * z / (4.0 * n_f * n_f)).sqrt() / denom;
    (
        if k == 0 {
            0.0
        } else {
            (center - margin).max(0.0)
        },
        if k == n {
            1.0
        } else {
            (center + margin).min(1.0)
        },
    )
}

/// Horní mez 95% Wilsonova intervalu pro k/n.
pub fn wilson_upper(k: u64, n: u64) -> f64 {
    wilson_bounds(k, n).1
}

/// Dolní mez 95% Wilsonova intervalu pro k/n.
pub fn wilson_lower(k: u64, n: u64) -> f64 {
    wilson_bounds(k, n).0
}

impl ContextGate {
    pub fn new(policy: GatePolicy) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }

    pub fn begin_cycle(&mut self) {
        self.closures_this_cycle = 0;
    }

    pub fn is_disabled(&self, kind: ContextKind) -> bool {
        self.disabled.contains(&kind)
    }

    /// Vypne druh kontextu (krok 7, A3: trvalé vypnutí z provozního auditu).
    pub fn disable(&mut self, kind: ContextKind) {
        if self.disabled.insert(kind) {
            self.stats.disabled_kinds.push(kind.label().to_string());
        }
    }

    /// Najde neškodné vysvětlení podle mantinelů; `None` = nezavírat.
    pub fn explain(
        &mut self,
        provider: &dyn ContextProvider,
        input: &GateInput<'_>,
    ) -> Option<Explanation> {
        self.explain_decision(provider, input).explanation
    }

    /// Mezera v telemetrii (P4): v čase `at` nebo v předchozím cyklu platí záznam
    /// výpadku senzoru.
    pub fn sensor_gap(&self, provider: &dyn ContextProvider, at: DateTime<Utc>) -> bool {
        let before = at - chrono::Duration::seconds(1800);
        provider
            .entries()
            .iter()
            .any(|e| e.kind == ContextKind::SensorOutage && (e.active(at) || e.active(before)))
    }

    /// Jako `explain`, navíc vrací nejednoznačnost kontextu (krok 7, P5 a P6).
    pub fn explain_decision(
        &mut self,
        provider: &dyn ContextProvider,
        input: &GateInput<'_>,
    ) -> GateDecision {
        // novost vztahu kontext nikdy nevysvetli (A7, review kola 1 S2)
        if self.policy.never.contains(input.finding_type)
            || crate::behavior::novelty::is_novelty_type(input.finding_type)
            || input.finding_type.starts_with("intel:")
            || input.finding_type.starts_with("active_check:")
        {
            return GateDecision::default();
        }
        // krok 7 (A1): chraneny nalez kontext nezavre
        if self.policy.shields(input) {
            if provider
                .entries()
                .iter()
                .any(|e| e.active(input.at) && e.covers(input.finding_type))
            {
                self.stats.refused_protected += 1;
            }
            return GateDecision::default();
        }
        let corroborate = self.policy.needs_corroboration(input);
        let mut kinds: BTreeSet<ContextKind> = BTreeSet::new();
        let mut first: Option<&ContextEntry> = None;
        let mut ambiguous = false;
        let severe = self.policy.most_severe.contains(input.finding_type);
        let mut refused_severe = false;
        let mut refused_disabled = false;
        let mut refused_source = false;
        for entry in provider.entries() {
            if !entry.active(input.at) || !entry.covers(input.finding_type) {
                continue;
            }
            if !self.policy.admits(entry, input) {
                refused_source = true;
                continue;
            }
            let host_match = if entry.hosts.is_empty() {
                entry.kind == ContextKind::SensorOutage || (!entry.sources.is_empty() && !severe)
            } else {
                entry.hosts.iter().any(|h| input.host_ids.contains(h))
            };
            if !host_match {
                continue;
            }
            if !entry.sources.is_empty() && !input.sources.iter().any(|s| entry.sources.contains(s))
            {
                continue; // zdrojovy kontext (skener) plati jen pri shode zdroje
            }
            if entry.kind.source_sensitive()
                && input
                    .sources
                    .iter()
                    .any(|s| !entry.hosts.contains(s) && !entry.sources.contains(s))
            {
                refused_source = true; // neocekavany dominantni zdroj v okne kontextu
                ambiguous |= self.policy.protect;
                continue;
            }
            if (severe || input.severity == Severity::High)
                && (!entry.explicitly_covers(input.finding_type) || entry.hosts.is_empty())
            {
                refused_severe = true; // zavazny typ jen s doloženym vysvetlenim
                continue;
            }
            if self.disabled.contains(&entry.kind) {
                refused_disabled = true;
                continue;
            }
            if corroborate {
                // P6: sbirat druhy, zavrit az pri dvou nezavislych
                kinds.insert(entry.kind);
                first.get_or_insert(entry);
                continue;
            }
            return GateDecision {
                explanation: self.close(entry, None),
                ambiguous: false,
            };
        }
        if refused_severe {
            self.stats.refused_severe += 1;
        }
        if refused_disabled {
            self.stats.refused_disabled += 1;
        }
        if refused_source {
            self.stats.refused_source += 1;
        }
        if corroborate && let Some(entry) = first {
            if kinds.len() >= 2 {
                let all: Vec<&str> = kinds.iter().map(|k| k.label()).collect();
                return GateDecision {
                    explanation: self.close(entry, Some(all.join("+"))),
                    ambiguous: false,
                };
            }
            self.stats.refused_corroboration += 1;
            ambiguous = true;
        }
        GateDecision {
            explanation: None,
            ambiguous,
        }
    }

    /// Zavření jedním záznamem (strop za cyklus); `joint` = seznam druhů u P6.
    fn close(&mut self, entry: &ContextEntry, joint: Option<String>) -> Option<Explanation> {
        if self.closures_this_cycle >= self.policy.max_closures_per_cycle {
            self.stats.refused_cap += 1;
            return None;
        }
        self.closures_this_cycle += 1;
        self.stats.explained += 1;
        let base = format!(
            "{} ({} az {}, schvalil {})",
            entry.kind.label(),
            entry.start.format("%Y-%m-%d %H:%M"),
            entry.end.format("%Y-%m-%d %H:%M"),
            entry.approved_by
        );
        Some(Explanation {
            kind: entry.kind,
            reason: match joint {
                Some(kinds) => format!("{base}; potvrzeno druhy {kinds}"),
                None => base,
            },
        })
    }

    /// Podpůrný (ne zavírající) kontext pro žebřík ověřování L1 (krok 2B): shoda okna,
    /// typu, hostu a zdrojové konzistence, BEZ výjimky pro závažné typy (ty brána
    /// sama nezavře, ale kontext smí snížit pravděpodobnost). Vypnuté druhy se
    /// nepoužijí. Vrací druh a důvod.
    pub fn supporting_context(
        &self,
        provider: &dyn ContextProvider,
        input: &GateInput<'_>,
    ) -> Option<(ContextKind, String)> {
        if self.policy.never.contains(input.finding_type)
            || crate::behavior::novelty::is_novelty_type(input.finding_type)
            || self.policy.shields(input)
        {
            return None;
        }
        let corroborate = self.policy.needs_corroboration(input);
        let mut matching = provider.entries().iter().filter_map(|entry| {
            let host_match = if entry.hosts.is_empty() {
                entry.kind == ContextKind::SensorOutage || !entry.sources.is_empty()
            } else {
                entry.hosts.iter().any(|h| input.host_ids.contains(h))
            };
            let source_ok = (entry.sources.is_empty()
                || input.sources.iter().any(|s| entry.sources.contains(s)))
                && !(entry.kind.source_sensitive()
                    && input
                        .sources
                        .iter()
                        .any(|s| !entry.hosts.contains(s) && !entry.sources.contains(s)));
            (entry.active(input.at)
                && entry.covers(input.finding_type)
                && self.policy.admits(entry, input)
                && host_match
                && source_ok
                && !self.disabled.contains(&entry.kind))
            .then(|| {
                (
                    entry.kind,
                    format!("{} (schvalil {})", entry.kind.label(), entry.approved_by),
                )
            })
        });
        if !corroborate {
            return matching.next();
        }
        // P6: podpurny dukaz jen pri dvou nezavislych druzich
        let all: Vec<(ContextKind, String)> = matching.collect();
        let kinds: BTreeSet<ContextKind> = all.iter().map(|(k, _)| *k).collect();
        (kinds.len() >= 2).then(|| all.into_iter().next()).flatten()
    }

    /// Výsledek auditu jednoho vzorku zavřeného nálezu (člověk: byl to omyl?).
    /// Při překročení meze se druh kontextu vypne (H-A3) a vrátí `true`.
    pub fn record_audit(&mut self, kind: ContextKind, wrong: bool) -> bool {
        let entry = self.audit.entry(kind).or_default();
        entry.0 += 1;
        entry.1 += wrong as u64;
        let (n, k) = *entry;
        if n >= self.policy.audit_min_samples
            && wilson_lower(k, n) > self.policy.audit_error_target
            && self.disabled.insert(kind)
        {
            self.stats.disabled_kinds.push(kind.label().to_string());
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(hours: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_767_571_200 + hours * 3600, 0).unwrap()
    }

    fn entry(kind: ContextKind, host: &str, start: i64, end: i64) -> ContextEntry {
        ContextEntry {
            kind,
            hosts: vec![host.to_string()],
            sources: Vec::new(),
            start: at(start),
            end: at(end),
            covers: Vec::new(),
            approved_by: "spravce".to_string(),
            expires: at(end + 24),
        }
    }

    fn input<'a>(
        kind: &'a str,
        hosts: &'a [String],
        sources: &'a [String],
        hour: i64,
        severity: Severity,
    ) -> GateInput<'a> {
        GateInput {
            finding_type: kind,
            host_ids: hosts,
            sources,
            severity,
            at: at(hour),
            protected: false,
        }
    }

    fn protect_policy() -> GatePolicy {
        GatePolicy {
            protect: true,
            sensor_strict: true,
            ..GatePolicy::default()
        }
    }

    /// Krok 7 (A1): chráněný typ ani signál volajícího kontext nezavře ani nepodpoří.
    #[test]
    fn protected_findings_are_never_explained_nor_supported() {
        let mut maintenance = entry(ContextKind::Maintenance, "10.0.0.5", 0, 10);
        maintenance.covers = vec![
            "pivot_chain".to_string(),
            "suricata_alert".to_string(),
            "connection_timeout_burst".to_string(),
        ];
        maintenance.hosts.push("10.0.0.9".to_string());
        let calendar = StaticCalendar::new(vec![maintenance]);
        let host = vec!["10.0.0.5".to_string()];
        let src = vec!["10.0.0.9".to_string()];
        let mut gate = ContextGate::new(protect_policy());
        for kind in ["pivot_chain", "suricata_alert"] {
            let case = input(kind, &host, &src, 1, Severity::Medium);
            assert!(gate.explain(&calendar, &case).is_none(), "{kind}");
            assert!(gate.supporting_context(&calendar, &case).is_none());
        }
        let mut degraded = input("connection_timeout_burst", &host, &src, 1, Severity::Medium);
        degraded.protected = true;
        assert!(gate.explain(&calendar, &degraded).is_none());
        assert!(gate.supporting_context(&calendar, &degraded).is_none());
        degraded.protected = false;
        assert!(gate.explain(&calendar, &degraded).is_some());
        assert_eq!(gate.stats.refused_protected, 3);
        // bez protect se chovani nemeni
        let mut loose = ContextGate::new(GatePolicy::default());
        let ids = input("suricata_alert", &host, &src, 1, Severity::Medium);
        assert!(loose.explain(&calendar, &ids).is_some());
    }

    /// Krok 7 (P6): bez zdroje nebo s vysokou závažností zavřou až dva druhy kontextu,
    /// jeden druh = nejednoznačné (P5) a bez podpůrného důkazu.
    #[test]
    fn sourceless_or_high_needs_two_independent_kinds() {
        let one = StaticCalendar::new(vec![entry(ContextKind::PatchWindow, "10.0.0.5", 0, 10)]);
        let mut two_entries = vec![
            entry(ContextKind::PatchWindow, "10.0.0.5", 0, 10),
            entry(ContextKind::ServiceOutage, "10.0.0.5", 0, 10),
        ];
        let two = StaticCalendar::new(two_entries.clone());
        let host = vec!["10.0.0.5".to_string()];
        let mut gate = ContextGate::new(protect_policy());
        let sourceless = input("connection_timeout_burst", &host, &[], 1, Severity::Medium);
        let decision = gate.explain_decision(&one, &sourceless);
        assert!(decision.explanation.is_none() && decision.ambiguous);
        assert!(gate.supporting_context(&one, &sourceless).is_none());
        let decision = gate.explain_decision(&two, &sourceless);
        let closed = decision.explanation.expect("dva druhy");
        assert!(closed.reason.contains("patch_window+service_outage"));
        assert!(gate.supporting_context(&two, &sourceless).is_some());
        // vypadek senzoru neni druhym druhem
        two_entries[1] = ContextEntry {
            hosts: Vec::new(),
            ..entry(ContextKind::SensorOutage, "-", 0, 10)
        };
        let with_outage = StaticCalendar::new(two_entries);
        assert!(gate.explain(&with_outage, &sourceless).is_none());
        // se zdrojem a stredni zavaznosti staci jeden druh
        let own = vec!["10.0.0.5".to_string()];
        let sourced = input("connection_timeout_burst", &host, &own, 1, Severity::Medium);
        assert!(gate.explain(&one, &sourced).is_some());
        assert_eq!(gate.stats.refused_corroboration, 2);
        // zdroj mimo zaznam = nejednoznacne
        let stranger = vec!["10.9.9.9".to_string()];
        let odd = input(
            "connection_timeout_burst",
            &host,
            &stranger,
            1,
            Severity::Medium,
        );
        assert!(gate.explain_decision(&one, &odd).ambiguous);
        assert!(gate.sensor_gap(&with_outage, at(3)));
        assert!(!gate.sensor_gap(&one, at(3)));
    }

    #[test]
    fn backup_window_explains_volume_on_listed_host_only_in_time() {
        let calendar = StaticCalendar::new(vec![entry(ContextKind::Backup, "10.0.0.5", 2, 4)]);
        let mut gate = ContextGate::new(GatePolicy::default());
        let host = vec!["10.0.0.5".to_string()];
        let other = vec!["10.0.0.6".to_string()];
        let found = gate
            .explain(
                &calendar,
                &input("inductive_volume_anomaly", &host, &[], 3, Severity::Medium),
            )
            .expect("v okne zalohy");
        assert_eq!(found.kind, ContextKind::Backup);
        assert!(found.reason.contains("spravce"));
        assert!(
            gate.explain(
                &calendar,
                &input("inductive_volume_anomaly", &host, &[], 6, Severity::Medium)
            )
            .is_none()
        );
        assert!(
            gate.explain(
                &calendar,
                &input("inductive_volume_anomaly", &other, &[], 3, Severity::Medium)
            )
            .is_none()
        );
        assert!(
            gate.explain(
                &calendar,
                &input("scan_attempts", &host, &[], 3, Severity::Medium)
            )
            .is_none()
        );
    }

    #[test]
    fn severe_types_need_explicit_coverage_and_static_exposures_never_close() {
        let mut generic = entry(ContextKind::Maintenance, "10.0.0.5", 0, 10);
        let calendar = StaticCalendar::new(vec![generic.clone()]);
        let mut gate = ContextGate::new(GatePolicy::default());
        let host = vec!["10.0.0.5".to_string()];
        assert!(
            gate.explain(
                &calendar,
                &input("service_overload_risk", &host, &[], 1, Severity::High)
            )
            .is_none()
        );
        assert!(
            gate.explain(
                &calendar,
                &input("connection_timeout_burst", &host, &[], 1, Severity::High)
            )
            .is_none()
        );
        assert_eq!(gate.stats.refused_severe, 2);
        generic.covers = vec!["service_overload_risk".to_string()];
        let explicit = StaticCalendar::new(vec![generic]);
        assert!(
            gate.explain(
                &explicit,
                &input("service_overload_risk", &host, &[], 1, Severity::High)
            )
            .is_some()
        );
        assert!(
            gate.explain(
                &explicit,
                &input(
                    "known_exploited_vulnerability",
                    &host,
                    &[],
                    1,
                    Severity::High
                )
            )
            .is_none()
        );
    }

    #[test]
    fn novelty_types_are_never_explained_nor_supported_even_if_covered() {
        // review kola 1 (S2): zaznam, ktery novost vyslovne pokryva, ji nesmi zavrit
        let mut maintenance = entry(ContextKind::Maintenance, "10.0.0.5", 0, 10);
        maintenance.hosts.push("203.0.113.9".to_string());
        maintenance.covers = vec![
            "novel_persistent_peer".to_string(),
            "novel_fanout".to_string(),
            "unexpected_traffic".to_string(),
        ];
        let calendar = StaticCalendar::new(vec![maintenance]);
        let mut gate = ContextGate::new(GatePolicy::default());
        let host = vec!["10.0.0.5".to_string()];
        let sources = vec!["203.0.113.9".to_string()];
        for kind in ["novel_persistent_peer", "novel_fanout"] {
            let case = input(kind, &host, &sources, 1, Severity::Medium);
            assert!(gate.explain(&calendar, &case).is_none(), "{kind}");
            assert!(
                gate.supporting_context(&calendar, &case).is_none(),
                "{kind}"
            );
        }
        // kontrola: tentyz zaznam jiny pokryty typ vysvetli
        let other = input("unexpected_traffic", &host, &sources, 1, Severity::Medium);
        assert!(gate.supporting_context(&calendar, &other).is_some());
        assert!(gate.explain(&calendar, &other).is_some());
    }

    #[test]
    fn scanner_context_requires_source_match() {
        let scanner = ContextEntry {
            hosts: Vec::new(),
            sources: vec!["10.0.0.200".to_string()],
            ..entry(ContextKind::AuthorizedScanner, "-", 0, 4)
        };
        let calendar = StaticCalendar::new(vec![scanner]);
        assert!(calendar.rejected.is_empty());
        let mut gate = ContextGate::new(GatePolicy::default());
        let host = vec!["10.0.0.9".to_string()];
        let ok = vec!["10.0.0.200".to_string()];
        let attacker = vec!["203.0.113.5".to_string()];
        assert!(
            gate.explain(
                &calendar,
                &input("scan_attempts", &host, &ok, 1, Severity::Medium)
            )
            .is_some()
        );
        assert!(
            gate.explain(
                &calendar,
                &input("scan_attempts", &host, &attacker, 1, Severity::Medium)
            )
            .is_none()
        );
        assert!(
            gate.explain(
                &calendar,
                &input("scan_attempts", &host, &[], 1, Severity::Medium)
            )
            .is_none()
        );
    }

    #[test]
    fn invalid_entries_are_rejected_and_expired_ones_ignored() {
        let mut no_approver = entry(ContextKind::Backup, "10.0.0.5", 0, 2);
        no_approver.approved_by = String::new();
        let mut whole_network = entry(ContextKind::Maintenance, "x", 0, 2);
        whole_network.hosts.clear();
        let mut expired = entry(ContextKind::Backup, "10.0.0.5", 0, 10);
        expired.expires = at(1);
        let calendar = StaticCalendar::new(vec![no_approver, whole_network, expired]);
        assert_eq!(calendar.rejected.len(), 2);
        let mut gate = ContextGate::new(GatePolicy::default());
        let host = vec!["10.0.0.5".to_string()];
        assert!(
            gate.explain(
                &calendar,
                &input("inductive_volume_anomaly", &host, &[], 5, Severity::Medium)
            )
            .is_none()
        );
    }

    /// Útok uvnitř okna zálohy: dominantní zdroj, který záznam nezná, vysvětlení ruší.
    #[test]
    fn unexpected_dominant_source_inside_window_is_not_explained() {
        let mut backup = entry(ContextKind::Backup, "10.0.0.5", 0, 10);
        backup.hosts.push("10.0.0.7".to_string());
        let calendar = StaticCalendar::new(vec![backup]);
        let mut gate = ContextGate::new(GatePolicy::default());
        let host = vec!["10.0.0.5".to_string()];
        let expected = vec!["10.0.0.7".to_string()];
        let insider = vec!["10.0.0.66".to_string()];
        assert!(
            gate.explain(
                &calendar,
                &input(
                    "inductive_volume_anomaly",
                    &host,
                    &expected,
                    1,
                    Severity::Medium
                )
            )
            .is_some()
        );
        assert!(
            gate.explain(
                &calendar,
                &input(
                    "inductive_volume_anomaly",
                    &host,
                    &insider,
                    1,
                    Severity::Medium
                )
            )
            .is_none()
        );
        assert_eq!(gate.stats.refused_source, 1);
        assert!(
            ContextKind::Backup.explains_volume() && !ContextKind::PatchWindow.explains_volume()
        );
    }

    /// Krok 6 (kandidát 1): výpadek senzoru bez přísného režimu zavírá, v přísném
    /// režimu nezavře nic a nedá ani podpůrný důkaz žebříku.
    #[test]
    fn strict_sensor_outage_neither_closes_nor_supports() {
        let outage = ContextEntry {
            hosts: Vec::new(),
            ..entry(ContextKind::SensorOutage, "-", 0, 4)
        };
        let calendar = StaticCalendar::new(vec![outage]);
        assert!(calendar.rejected.is_empty());
        let host = vec!["10.0.0.5".to_string()];
        let probe = input("packet_rate_spike", &host, &[], 1, Severity::Medium);
        let mut loose = ContextGate::new(GatePolicy::default());
        assert!(loose.explain(&calendar, &probe).is_some());
        assert!(loose.supporting_context(&calendar, &probe).is_some());
        let mut strict = ContextGate::new(GatePolicy {
            sensor_strict: true,
            ..GatePolicy::default()
        });
        assert!(strict.explain(&calendar, &probe).is_none());
        assert!(strict.supporting_context(&calendar, &probe).is_none());
    }

    /// Krok 6 (kandidát 6): nález bez identifikovaného zdroje zavře jen objem v okně
    /// zálohy; timeouty v patch okně bez zdroje ne.
    #[test]
    fn guard_requires_identified_source_except_backup_volume() {
        let calendar = StaticCalendar::new(vec![
            entry(ContextKind::PatchWindow, "10.0.0.5", 0, 10),
            entry(ContextKind::Backup, "10.0.0.6", 0, 10),
        ]);
        let patch = vec!["10.0.0.5".to_string()];
        let backup = vec!["10.0.0.6".to_string()];
        let policy = GatePolicy {
            require_identified_source: true,
            ..GatePolicy::default()
        };
        let mut gate = ContextGate::new(policy.clone());
        let timeout = input("connection_timeout_burst", &patch, &[], 1, Severity::Medium);
        assert!(gate.explain(&calendar, &timeout).is_none());
        assert!(gate.supporting_context(&calendar, &timeout).is_none());
        let own = vec!["10.0.0.5".to_string()];
        assert!(
            gate.explain(
                &calendar,
                &input(
                    "connection_timeout_burst",
                    &patch,
                    &own,
                    1,
                    Severity::Medium
                )
            )
            .is_some()
        );
        assert!(
            gate.explain(
                &calendar,
                &input(
                    "inductive_volume_anomaly",
                    &backup,
                    &[],
                    1,
                    Severity::Medium
                )
            )
            .is_some()
        );
        let mut loose = ContextGate::new(GatePolicy::default());
        assert!(loose.explain(&calendar, &timeout).is_some());
        let engine = crate::engine::EngineConfig::v3();
        assert!(!GatePolicy::for_engine(&engine).require_identified_source);
    }

    #[test]
    fn closures_are_capped_per_cycle() {
        let calendar = StaticCalendar::new(vec![entry(ContextKind::Backup, "10.0.0.5", 0, 10)]);
        let mut gate = ContextGate::new(GatePolicy {
            max_closures_per_cycle: 3,
            ..GatePolicy::default()
        });
        let host = vec!["10.0.0.5".to_string()];
        let closed = (0..10)
            .filter(|_| {
                gate.explain(
                    &calendar,
                    &input("packet_rate_spike", &host, &[], 1, Severity::Medium),
                )
                .is_some()
            })
            .count();
        assert_eq!(closed, 3);
        gate.begin_cycle();
        assert!(
            gate.explain(
                &calendar,
                &input("packet_rate_spike", &host, &[], 1, Severity::Medium)
            )
            .is_some()
        );
    }

    #[test]
    fn audit_disables_kind_when_error_upper_bound_exceeds_limit() {
        let mut gate = ContextGate::new(GatePolicy::default());
        for _ in 0..200 {
            assert!(!gate.record_audit(ContextKind::Backup, false));
        }
        assert!(
            !gate.is_disabled(ContextKind::Backup),
            "0/200 omylu: zustava"
        );
        for i in 0..60 {
            gate.record_audit(ContextKind::Backup, i == 0);
        }
        assert!(
            !gate.is_disabled(ContextKind::Backup),
            "1/260 omylu: zustava"
        );
        let mut switched = false;
        for i in 0..40 {
            switched |= gate.record_audit(ContextKind::PatchWindow, i % 5 == 0);
        }
        assert!(switched && gate.is_disabled(ContextKind::PatchWindow));
        let calendar =
            StaticCalendar::new(vec![entry(ContextKind::PatchWindow, "10.0.0.5", 0, 10)]);
        let host = vec!["10.0.0.5".to_string()];
        assert!(
            gate.explain(
                &calendar,
                &input("connection_timeout_burst", &host, &[], 1, Severity::Medium)
            )
            .is_none()
        );
        assert_eq!(gate.stats.refused_disabled, 1);
        assert!((wilson_upper(0, 200) - 0.0188).abs() < 1e-3);
    }
}
