//! Žebřík okamžitého ověřování (krok 2B; 00-zaver Dodatek A.3, §5.b R10, RQ3, RQ6).
//!
//! Hypotéza = otevřený behaviorální nález (jeden případ na stabilní klíč nálezu,
//! idempotentně: nový plán jen pro nový, znovuotevřený nebo eskalovaný stav, ne pro
//! každý nález v každém cyklu; dřív 90,6 % plánů mimo rozpočet, D5/A24).
//!
//! Sekvenční ověřování (RQ3 Z1, nízká až střední jistota): stav hypotézy je
//! log-šance, každá kontrola přičte ln věrohodnostního poměru (LR) a po KAŽDÉ kontrole
//! se testují pravidla zastavení:
//! - potvrzeno: p ≥ `p_confirm`,
//! - vyvráceno: p ≤ `p_refute` A aspoň jeden doložený neškodný důkaz (LR < 1);
//!   prázdný výsledek dotazu NENÍ důkaz neškodnosti, je to stav „nezjištěno“
//!   (RQ6 Z3: prázdné vyhledávání souvisí se zamítnutím útoku v 98,6 % případů),
//! - eskalace člověku: strop počtu kontrol (`max_checks`, RQ3 Z3: bez stropu zůstává
//!   > 80 % nerozhodnuto, strop sám nerozhodnutost neřeší), vyčerpaný plán nebo
//!   opakovaně chybějící rozpočet.
//!
//! Úrovně od nejlevnější a nejbezpečnější (Dodatek A.3, pořadí v A.4):
//! - L0 uložená historie toků („stalo se to už dřív?“, `flow_history`),
//! - L1 kontext a reputace (kalendář, reputace zdroje, KEV/EPSS cílové služby, typ
//!   zařízení), v simulaci s neúplným pokrytím,
//! - L2 cílené pasivní přezkoumání (další cykly a srovnání s peer skupinou),
//! - L3 aktivní kontrola (`verification_exec`: rozsah, schválení, rozpočet; křehká
//!   zařízení jen se schválením, RQ3 Z10),
//! - L4 pivot po souvisejících zařízeních (komunikační hrany, hloubka ≤ 3, jen v rozsahu).
//!
//! Pořadí: globálně podle EVOI proxy = dopad × entropie víry / cena kontroly (RQ3 Z12,
//! jen simulace, nízká jistota), část výběru (`explore`) se losuje a pořadí kontrol
//! uvnitř úrovně je náhodné s tajným klíčem (RQ3 Z11: předvídatelné pořadí je
//! zneužitelné). Dřív rozhodovala abeceda `finding_id` (audit A23).
//!
//! LR v `LrTable` jsou volba autora (kvalitativní síla důkazu), ne odhad z dat; jejich
//! správnost se měří (přesnost rozhodnutí, zavřeno omylem) a učí se v kroku 2C.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::{
    device_class::{DeviceClass, DeviceKind},
    finding_memory::FindingKey,
    flow_history::Recurrence,
};

/// Výchozí apriorní pravděpodobnost útoku u behaviorálního nálezu bez naučeného
/// odhadu (volba autora; v kroku 2C ji nahrazuje kalibrovaný odhad Case Memory).
pub const DEFAULT_PRIOR: f64 = 0.15;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Level {
    L0,
    L1,
    L2,
    L3,
    L4,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::L0 => "L0",
            Level::L1 => "L1",
            Level::L2 => "L2",
            Level::L3 => "L3",
            Level::L4 => "L4",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckId {
    /// L0: stalo se to už dřív (stejná hodina, předchozí dny)?
    History,
    /// L1: schválený kontext (kalendář, CMDB, registr skenerů).
    Context,
    /// L1: reputace dominantního zdroje.
    Reputation,
    /// L1: zranitelnost cílové služby (CISA KEV, EPSS z intel modulu).
    Intel,
    /// L1: služba nebo chování neobvyklé pro typ zařízení.
    DeviceProfile,
    /// L2: srovnání s peer skupinou (stejný typ zařízení a podsíť) v tomtéž okně.
    Peers,
    /// L2: přetrvá jev v dalších cyklech (čeká se)?
    Persistence,
    /// L3: aktivní kontrola dostupnosti služby.
    Liveness,
    /// L4: podezřelé nálezy na souvisejících zařízeních.
    Pivot,
}

impl CheckId {
    pub fn level(self) -> Level {
        match self {
            CheckId::History => Level::L0,
            CheckId::Context | CheckId::Reputation | CheckId::Intel | CheckId::DeviceProfile => {
                Level::L1
            }
            CheckId::Peers | CheckId::Persistence => Level::L2,
            CheckId::Liveness => Level::L3,
            CheckId::Pivot => Level::L4,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            CheckId::History => "history",
            CheckId::Context => "context",
            CheckId::Reputation => "reputation",
            CheckId::Intel => "intel",
            CheckId::DeviceProfile => "device_profile",
            CheckId::Peers => "peers",
            CheckId::Persistence => "persistence",
            CheckId::Liveness => "liveness",
            CheckId::Pivot => "pivot",
        }
    }
}

/// Výsledek jedné kontroly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Outcome {
    /// Důkaz s věrohodnostním poměrem P(o|útok)/P(o|neškodné).
    Evidence { lr: f64, detail: String },
    /// Kontrola nic nezjistila (prázdný dotaz, chybí pokrytí): bez změny víry.
    Undetermined(String),
    /// Kontrolu nešlo provést (mimo rozsah, čeká na schválení, selhání).
    Unavailable(String),
    /// Kontrola potřebuje čas: znovu v cyklu `until`.
    Wait(u64),
}

/// Reputace adresy z poskytovatele (neúplná: `Unknown` je nejčastější).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reputation {
    Bad(String),
    Good(String),
    Unknown,
}

/// Zranitelnost cílové služby.
#[derive(Debug, Clone, PartialEq)]
pub enum IntelSignal {
    KnownExploited(String),
    HighEpss(f64),
    NothingKnown,
}

/// Výsledek aktivní kontroly dostupnosti.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Liveness {
    Up,
    Down,
    NeedsApproval,
    OutOfScope,
    Failed(String),
}

/// Přetrvání jevu (L2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Persistence {
    /// Jev se opakoval v `cycles` cyklech; `same_source` = s týmž dominantním zdrojem.
    Recurring {
        cycles: u32,
        same_source: bool,
    },
    Gone,
}

/// Vstup případu (z nálezu a paměti nálezů).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseInput {
    pub key: FindingKey,
    pub finding_id: String,
    pub finding_type: String,
    /// IP entity nálezu (cíl; u zdrojových typů zdroj).
    pub host_ip: String,
    pub port: Option<u16>,
    /// Dominantní zdroje nálezu.
    pub sources: Vec<String>,
    /// Objem pozorování (pro L0 srovnání s historií).
    pub volume: f64,
    /// Klíč metriky v `flow_history` (None = L0 neplatí).
    pub history_key: Option<String>,
    pub high_impact: bool,
    /// Apriorní pravděpodobnost útoku (Case Memory nebo výchozí).
    pub prior: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Open,
    Confirmed,
    Refuted,
    Escalated,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Step {
    pub check: CheckId,
    pub cycle: u64,
    pub outcome: Outcome,
    pub posterior: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub input: CaseInput,
    pub opened: u64,
    log_odds: f64,
    plan: VecDeque<CheckId>,
    pub steps: Vec<Step>,
    wait_until: Option<u64>,
    deferred: u32,
    pub status: Status,
    benign_evidence: bool,
    /// Cykly po otevření, ve kterých se nález znovu objevil (L2 přetrvání).
    #[serde(default)]
    seen_after_open: u32,
    #[serde(default)]
    same_source_seen: bool,
    #[serde(default)]
    last_seen_cycle: u64,
}

impl Case {
    pub fn posterior(&self) -> f64 {
        1.0 / (1.0 + (-self.log_odds).exp())
    }
}

/// Rozhodnutí případu (zapisuje se do paměti nálezů a auditu).
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub key: FindingKey,
    pub finding_id: String,
    pub finding_type: String,
    pub status: Status,
    pub host_ip: String,
    /// Pravděpodobnost útoku při rozhodnutí (po kalibraci, pokud je zapnutá).
    pub posterior: f64,
    /// Surová posteriora (bez kalibrace), pro kalibrační křivku.
    pub raw_posterior: f64,
    pub opened: u64,
    pub decided: u64,
    /// Proč (kontroly s výsledkem), pro audit a UI.
    pub reason: String,
    pub checks: usize,
    pub budget_escalation: bool,
    /// Vysoký dopad: zobrazeno už při otevření.
    pub high_impact: bool,
    /// Provedené kontroly a značka výsledku (pro měření a učení LR, krok 2C).
    pub steps: Vec<(CheckId, &'static str)>,
}

/// Rozhodnutí v reportu (UI, API, audit).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub finding_id: String,
    pub finding_type: String,
    pub status: Status,
    pub posterior: f64,
    pub checks: usize,
    pub reason: String,
}

impl From<&Decision> for DecisionRecord {
    fn from(d: &Decision) -> Self {
        Self {
            finding_id: d.finding_id.clone(),
            finding_type: d.finding_type.clone(),
            status: d.status,
            posterior: d.posterior,
            checks: d.checks,
            reason: d.reason.clone(),
        }
    }
}

/// Záznam reputačního zdroje (`reputation.json` ve workspace): síť, verdikt, zdroj,
/// expirace. Plní člověk nebo import feedu (Pásmo B); chybějící soubor = vše neznámé.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReputationEntry {
    pub net: ipnet::IpNet,
    /// `bad` | `good`
    pub verdict: String,
    pub source: String,
    pub expires: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct StaticReputation {
    entries: Vec<ReputationEntry>,
}

impl StaticReputation {
    pub fn new(entries: Vec<ReputationEntry>) -> Self {
        Self { entries }
    }

    pub fn load(path: &std::path::Path) -> crate::error::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)?;
        let entries: Vec<ReputationEntry> =
            serde_json::from_str(&text).map_err(crate::error::BakulaError::Json)?;
        Ok(Self::new(entries))
    }

    /// Nejužší platná shoda; vypršelé záznamy se ignorují.
    pub fn lookup(&self, ip: &str, at: chrono::DateTime<chrono::Utc>) -> Reputation {
        let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
            return Reputation::Unknown;
        };
        self.entries
            .iter()
            .filter(|e| e.expires > at && e.net.contains(&addr))
            .max_by_key(|e| e.net.prefix_len())
            .map(|e| match e.verdict.as_str() {
                "bad" => Reputation::Bad(e.source.clone()),
                "good" => Reputation::Good(e.source.clone()),
                _ => Reputation::Unknown,
            })
            .unwrap_or(Reputation::Unknown)
    }
}

/// Věrohodnostní poměry (volba autora, kvalitativní síla důkazu; měří se v A/B).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LrTable {
    pub history_seen: f64,
    pub history_new: f64,
    pub context: f64,
    pub reputation_bad: f64,
    pub reputation_good: f64,
    pub intel_kev: f64,
    pub intel_epss: f64,
    pub device_unusual: f64,
    pub peers_widespread: f64,
    pub peers_isolated: f64,
    pub persistence_same_source: f64,
    pub persistence_recurring: f64,
    pub liveness_down_outage: f64,
    pub liveness_up_unreachable: f64,
    pub pivot_per_hit: f64,
}

impl Default for LrTable {
    fn default() -> Self {
        Self {
            history_seen: 0.25,
            history_new: 2.0,
            context: 0.3,
            reputation_bad: 8.0,
            reputation_good: 0.4,
            intel_kev: 3.0,
            intel_epss: 1.8,
            device_unusual: 2.5,
            peers_widespread: 0.25,
            peers_isolated: 1.3,
            persistence_same_source: 2.0,
            persistence_recurring: 1.4,
            liveness_down_outage: 0.15,
            liveness_up_unreachable: 1.5,
            pivot_per_hit: 2.0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LadderPolicy {
    pub p_confirm: f64,
    pub p_refute: f64,
    /// Přísnější mez vyvrácení pro vysoký dopad (Dodatek A.2 c).
    pub p_refute_high_impact: f64,
    /// Strop počtu provedených kontrol na případ (RQ3 Překlad bod 2: 3 až 10; plán
    /// má nejvýš 9 kontrol, většina jsou levné pasivní dotazy).
    pub max_checks: usize,
    /// Rozpočet ceny kontrol za cyklus a strop aktivních kontrol.
    pub budget_per_cycle: f64,
    pub active_per_cycle: usize,
    /// Podíl výběru losem (RQ3 Překlad bod 8: 10 až 20 %, extrapolace).
    pub explore: f64,
    /// Kolik cyklů se čeká na L2 přetrvání.
    pub persistence_wait: u64,
    /// Kolikrát smí případ nedostat rozpočet, než se eskaluje.
    pub max_deferred: u32,
    pub pivot_depth: usize,
    pub pivot_max_nodes: usize,
    pub max_open_cases: usize,
    pub lr: LrTable,
}

impl Default for LadderPolicy {
    fn default() -> Self {
        Self {
            p_confirm: 0.9,
            p_refute: 0.03,
            p_refute_high_impact: 0.01,
            max_checks: 8,
            budget_per_cycle: 500.0,
            active_per_cycle: 10,
            explore: 0.15,
            persistence_wait: 2,
            max_deferred: 4,
            pivot_depth: 3,
            pivot_max_nodes: 5,
            max_open_cases: 5_000,
            lr: LrTable::default(),
        }
    }
}

fn cost(check: CheckId) -> f64 {
    match check.level() {
        Level::L0 => 0.05,
        Level::L1 => 0.1,
        Level::L2 => 0.05,
        Level::L3 => 1.0,
        Level::L4 => 0.3,
    }
}

/// Datové zdroje žebříku (produkce: SQLite, kalendář, intel, exekutor; soak: simulace).
pub trait LadderEvidence {
    fn recurrence(&self, history_key: &str, value: f64) -> Recurrence;
    fn context(&self, case: &CaseInput) -> Option<String>;
    fn reputation(&self, ip: &str) -> Reputation;
    fn intel(&self, case: &CaseInput) -> IntelSignal;
    fn device(&self, ip: &str) -> Option<DeviceClass>;
    /// (zasažení peer členové se stejným typem nálezu, velikost peer skupiny).
    fn peers(&self, case: &CaseInput) -> Option<(usize, usize)>;
    fn liveness(&mut self, case: &CaseInput) -> Liveness;
    fn neighbors(&self, ip: &str) -> Vec<String>;
    fn in_scope(&self, ip: &str) -> bool;
    /// Typy podezřelých otevřených nálezů na zařízení (pro pivot).
    fn suspicious_on(&self, ip: &str) -> usize;
}

/// Statistiky žebříku (pro měření a report).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LadderStats {
    pub cases_opened: u64,
    pub cases_merged: u64,
    pub checks_by_level: BTreeMap<String, u64>,
    pub outcomes: BTreeMap<String, u64>,
    pub checks_deferred: u64,
    pub cases_deferred: u64,
    pub explored: u64,
    pub confirmed: u64,
    pub refuted: u64,
    pub escalated: u64,
    pub escalated_budget: u64,
    pub needs_approval: u64,
    pub cases_capped: u64,
}

fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

fn hash_text(text: &str) -> u64 {
    mix(text.bytes().fold(0xcbf2_9ce4_8422_2325u64, |a, b| {
        (a ^ b as u64).wrapping_mul(0x100_0000_01b3)
    }))
}

fn logit(p: f64) -> f64 {
    let p = p.clamp(1e-6, 1.0 - 1e-6);
    (p / (1.0 - p)).ln()
}

fn entropy(p: f64) -> f64 {
    let p = p.clamp(1e-9, 1.0 - 1e-9);
    -(p * p.log2() + (1.0 - p) * (1.0 - p).log2())
}

/// Kontroly, které pro typ nálezu dávají smysl (bez kontroly bez exekutoru, R10-lite).
fn checks_for(input: &CaseInput) -> Vec<CheckId> {
    let kind = input.finding_type.as_str();
    let mut checks = Vec::new();
    if input.history_key.is_some() {
        checks.push(CheckId::History);
    }
    checks.push(CheckId::Context);
    if !input.sources.is_empty() {
        checks.push(CheckId::Reputation);
    }
    if matches!(
        kind,
        "suricata_alert"
            | "source_volume_outlier"
            | "packet_rate_spike"
            | "inductive_volume_anomaly"
    ) && input.port.is_some()
    {
        checks.push(CheckId::Intel);
    }
    if matches!(
        kind,
        "unexpected_traffic" | "multi_target_pattern" | "source_volume_outlier" | "scan_attempts"
    ) {
        checks.push(CheckId::DeviceProfile);
    }
    if matches!(
        kind,
        "inductive_volume_anomaly"
            | "packet_rate_spike"
            | "unexpected_traffic"
            | "service_unreachable"
            | "connection_timeout_burst"
            | "service_overload_risk"
    ) {
        checks.push(CheckId::Peers);
    }
    checks.push(CheckId::Persistence);
    if matches!(kind, "service_unreachable" | "connection_timeout_burst") && input.port.is_some() {
        checks.push(CheckId::Liveness);
    }
    if matches!(
        kind,
        "scan_attempts"
            | "multi_target_pattern"
            | "suricata_alert"
            | "source_volume_outlier"
            | "unexpected_traffic"
    ) {
        checks.push(CheckId::Pivot);
    }
    checks
}

/// Plán kontrol: po úrovních (nejlevnější první), uvnitř úrovně náhodně podle tajného
/// klíče a klíče případu (RQ3 Z11). Přetrvání (L2) je úplně poslední: stojí čas, ne
/// zdroje, a okamžité kontroly (L3 dostupnost služby při výpadku) by po čekání
/// viděly už jiný stav.
fn plan_for(input: &CaseInput, secret: u64) -> VecDeque<CheckId> {
    let mut checks = checks_for(input);
    let salt = mix(secret ^ hash_text(&input.finding_id));
    checks.sort_by_key(|check| {
        let wait_last = (*check == CheckId::Persistence) as u8;
        (
            wait_last,
            check.level(),
            mix(salt ^ hash_text(check.label())),
        )
    });
    checks.into_iter().collect()
}

/// Značka výsledku kontroly pro měření a učení (`benign`, `malicious`, `undetermined`,
/// `unavailable`).
pub fn outcome_tag(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Evidence { lr, .. } if *lr < 1.0 => "benign",
        Outcome::Evidence { .. } => "malicious",
        Outcome::Undetermined(_) => "undetermined",
        Outcome::Unavailable(_) => "unavailable",
        Outcome::Wait(_) => "wait",
    }
}

fn is_fragile(class: &Option<DeviceClass>) -> bool {
    class.as_ref().is_some_and(|c| {
        c.kind.is_fragile() && c.confidence >= crate::device_class::ClassConfidence::Medium
    })
}

/// Učení věrohodnostních poměrů z ověřených případů (krok 2C). Štítky přicházejí jen
/// přes Case Memory (verdikt člověka nebo audit, s ochranou proti otrávení), počty se
/// drží po (kontrola, značka výsledku). Naučený LR je smrštěný k autorskému
/// (váha `n / (n + 20)`) a má bezpečnostní meze: neškodný důkaz smí jen snižovat
/// (0,02 až 1), podezřelý jen zvyšovat (1 až 50); „nezjištěno“ a „neprovedeno“ se
/// neučí vůbec a zůstávají bez vlivu (RQ6 Z3: prázdný výsledek není důkaz).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LadderLearner {
    /// zdroj štítku -> (kontrola:značka -> (útok, neškodné)); po zdrojích, aby šlo
    /// vyřadit zdroj, který Case Memory označí za otrávený (i zpětně).
    counts: BTreeMap<String, BTreeMap<String, (f64, f64)>>,
    totals: BTreeMap<String, (f64, f64)>,
    #[serde(default)]
    excluded: std::collections::BTreeSet<String>,
}

impl LadderLearner {
    const SHRINK: f64 = 20.0;
    const MIN_PER_CLASS: f64 = 10.0;

    /// Zapíše výsledek ověřeného případu (`attack` = verdikt útok) od zdroje `source`.
    pub fn record(
        &mut self,
        source: &str,
        steps: &[(CheckId, &'static str)],
        attack: bool,
        weight: f64,
    ) {
        let weight = weight.clamp(0.0, 1.0);
        let totals = self.totals.entry(source.to_string()).or_default();
        if attack {
            totals.0 += weight;
        } else {
            totals.1 += weight;
        }
        let counts = self.counts.entry(source.to_string()).or_default();
        let mut seen = HashSet::new();
        for (check, tag) in steps {
            if !seen.insert((*check, *tag)) {
                continue;
            }
            let entry = counts
                .entry(format!("{}:{tag}", check.label()))
                .or_default();
            if attack {
                entry.0 += weight;
            } else {
                entry.1 += weight;
            }
        }
    }

    /// Vyřadí zdroj (Case Memory ho označila za otrávený); jeho štítky přestanou platit.
    pub fn exclude(&mut self, source: &str) {
        self.excluded.insert(source.to_string());
    }

    fn sum<'a>(
        &'a self,
        pick: impl Fn(&'a BTreeMap<String, (f64, f64)>) -> Option<&'a (f64, f64)>,
    ) -> Option<(f64, f64)> {
        let mut out: Option<(f64, f64)> = None;
        for (source, counts) in &self.counts {
            if self.excluded.contains(source) {
                continue;
            }
            if let Some((a, b)) = pick(counts) {
                let entry = out.get_or_insert((0.0, 0.0));
                entry.0 += a;
                entry.1 += b;
            }
        }
        out
    }

    pub fn cases(&self) -> (f64, f64) {
        self.totals
            .iter()
            .filter(|(source, _)| !self.excluded.contains(*source))
            .fold((0.0, 0.0), |acc, (_, t)| (acc.0 + t.0, acc.1 + t.1))
    }

    /// Naučený LR pro výsledek kontroly; `author` = výchozí LR z `LrTable`.
    pub fn lr(&self, check: CheckId, tag: &str, author: f64) -> f64 {
        let (bounds_lo, bounds_hi) = match tag {
            "benign" => (0.02, 1.0),
            "malicious" => (1.0, 50.0),
            _ => return author,
        };
        let (attack_total, benign_total) = self.cases();
        let name = format!("{}:{tag}", check.label());
        let Some((a, b)) = self.sum(|counts| counts.get(&name)) else {
            return author;
        };
        if attack_total < Self::MIN_PER_CLASS || benign_total < Self::MIN_PER_CLASS {
            return author;
        }
        let empirical = ((a + 0.5) / (attack_total + 1.0)) / ((b + 0.5) / (benign_total + 1.0));
        let n = a + b;
        let w = n / (n + Self::SHRINK);
        let blended = (w * empirical.ln() + (1.0 - w) * author.max(1e-6).ln()).exp();
        blended.clamp(bounds_lo, bounds_hi)
    }
}

/// Žebřík: otevřené případy, pořadí a rozpočet napříč případy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ladder {
    pub policy: LadderPolicy,
    secret: u64,
    #[serde(with = "cases_as_list")]
    cases: HashMap<FindingKey, Case>,
    #[serde(default)]
    pub stats: LadderStats,
    /// Naučené LR (krok 2C); `None` = autorské LR.
    #[serde(default)]
    pub learner: Option<LadderLearner>,
    /// Kalibrace posteriory před pravidly zastavení (krok 2C); fit offline.
    #[serde(skip)]
    pub calibrator: Option<crate::calibration::IsotonicCalibrator>,
}

/// JSON neumi strukturovane klice map: pripady se ukladaji jako seznam.
mod cases_as_list {
    use super::{Case, FindingKey};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    pub fn serialize<S: Serializer>(
        cases: &HashMap<FindingKey, Case>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut list: Vec<&Case> = cases.values().collect();
        list.sort_by(|a, b| a.input.key.cmp(&b.input.key));
        list.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<HashMap<FindingKey, Case>, D::Error> {
        let list: Vec<Case> = Vec::deserialize(deserializer)?;
        Ok(list
            .into_iter()
            .map(|case| (case.input.key.clone(), case))
            .collect())
    }
}

impl Ladder {
    /// `secret` = tajný klíč instalace (náhodný při prvním startu, perzistentní).
    pub fn new(policy: LadderPolicy, secret: u64) -> Self {
        Self {
            policy,
            secret,
            cases: HashMap::new(),
            stats: LadderStats::default(),
            learner: None,
            calibrator: None,
        }
    }

    pub fn open_cases(&self) -> usize {
        self.cases.len()
    }

    pub fn is_open(&self, key: &FindingKey) -> bool {
        self.cases.contains_key(key)
    }

    /// Otevře případ pro nový stav nálezu. Idempotentní: stejný klíč s otevřeným
    /// případem = jen sloučení zdrojů (žádný nový plán). Vrací `true` při otevření.
    pub fn open(&mut self, input: CaseInput, cycle: u64) -> bool {
        if let Some(case) = self.cases.get_mut(&input.key) {
            for source in input.sources {
                if !case.input.sources.contains(&source) && case.input.sources.len() < 16 {
                    case.input.sources.push(source);
                }
            }
            case.input.volume = case.input.volume.max(input.volume);
            self.stats.cases_merged += 1;
            return false;
        }
        if self.cases.len() >= self.policy.max_open_cases {
            self.stats.cases_capped += 1;
            return false;
        }
        let plan = plan_for(&input, self.secret);
        self.cases.insert(
            input.key.clone(),
            Case {
                log_odds: logit(input.prior),
                input,
                opened: cycle,
                plan,
                steps: Vec::new(),
                wait_until: None,
                deferred: 0,
                status: Status::Open,
                benign_evidence: false,
                seen_after_open: 0,
                same_source_seen: false,
                last_seen_cycle: cycle,
            },
        );
        self.stats.cases_opened += 1;
        true
    }

    /// Nález s otevřeným případem se v cyklu znovu objevil (vstup pro L2 přetrvání).
    pub fn observe(&mut self, key: &FindingKey, sources: &[String], cycle: u64) {
        let Some(case) = self.cases.get_mut(key) else {
            return;
        };
        if cycle <= case.last_seen_cycle {
            return;
        }
        case.last_seen_cycle = cycle;
        case.seen_after_open += 1;
        if sources.iter().any(|s| case.input.sources.contains(s)) {
            case.same_source_seen = true;
        }
    }

    /// Zruší případ (nález uzavřel člověk nebo kontext).
    pub fn drop_case(&mut self, key: &FindingKey) {
        self.cases.remove(key);
    }

    /// Jeden cyklus: provede kontroly v pořadí EVOI proxy pod rozpočtem a vrátí
    /// rozhodnuté případy (ty se z žebříku odeberou).
    pub fn step(&mut self, cycle: u64, env: &mut dyn LadderEvidence) -> Vec<Decision> {
        let mut decisions = Vec::new();
        let mut budget = self.policy.budget_per_cycle;
        let mut active_left = self.policy.active_per_cycle;
        let mut keys: Vec<FindingKey> = self.cases.keys().cloned().collect();
        keys.sort();
        let mut touched: HashSet<FindingKey> = HashSet::new();
        // opakovane vybirat nejlepsi pripravenou kontrolu, dokud je rozpocet
        loop {
            let ready: Vec<(f64, &FindingKey)> = keys
                .iter()
                .filter_map(|key| {
                    let case = self.cases.get(key)?;
                    if case.status != Status::Open
                        || case.wait_until.is_some_and(|until| until > cycle)
                    {
                        return None;
                    }
                    let check = *case.plan.front()?;
                    if check.level() == Level::L3 && active_left == 0 {
                        return None;
                    }
                    let impact = if case.input.high_impact { 1.0 } else { 0.5 };
                    let score = impact * entropy(case.posterior()) / cost(check);
                    Some((score, key))
                })
                .collect();
            if ready.is_empty() {
                break;
            }
            let roll = mix(self.secret
                ^ cycle.wrapping_mul(0x51ED)
                ^ self.stats.checks_by_level.values().sum::<u64>());
            let explore = (roll % 10_000) as f64 / 10_000.0 < self.policy.explore;
            let pick = if explore {
                self.stats.explored += 1;
                ready[(mix(roll) % ready.len() as u64) as usize].1.clone()
            } else {
                ready
                    .iter()
                    .max_by(|a, b| {
                        a.0.total_cmp(&b.0)
                            .then_with(|| hash_text(&b.1.entity).cmp(&hash_text(&a.1.entity)))
                            .then_with(|| b.1.cmp(a.1))
                    })
                    .map(|(_, key)| (*key).clone())
                    .expect("neprazdne")
            };
            let check = *self.cases[&pick].plan.front().expect("plan");
            let price = cost(check);
            if price > budget {
                break;
            }
            budget -= price;
            if check.level() == Level::L3 {
                active_left -= 1;
            }
            touched.insert(pick.clone());
            let decision = self.run_check(&pick, check, cycle, env);
            if let Some(decision) = decision {
                decisions.push(decision);
            }
        }
        // pripady, na ktere nezbyl rozpocet: odlozit, po `max_deferred` eskalovat
        let mut budget_escalations = Vec::new();
        for key in &keys {
            let Some(case) = self.cases.get_mut(key) else {
                continue;
            };
            if case.status != Status::Open || touched.contains(key) {
                continue;
            }
            let ready = case.wait_until.is_none_or(|until| until <= cycle) && !case.plan.is_empty();
            if !ready {
                continue;
            }
            case.deferred += 1;
            self.stats.checks_deferred += 1;
            if case.deferred == 1 {
                self.stats.cases_deferred += 1;
            }
            if case.deferred > self.policy.max_deferred {
                budget_escalations.push(key.clone());
            }
        }
        for key in budget_escalations {
            if let Some(decision) = self.finish(&key, Status::Escalated, cycle, true) {
                decisions.push(decision);
            }
        }
        decisions
    }

    fn run_check(
        &mut self,
        key: &FindingKey,
        check: CheckId,
        cycle: u64,
        env: &mut dyn LadderEvidence,
    ) -> Option<Decision> {
        let lr = self.policy.lr;
        let case = self.cases.get(key)?;
        let input = case.input.clone();
        let opened = case.opened;
        let persistence = if case.seen_after_open == 0 {
            Persistence::Gone
        } else {
            Persistence::Recurring {
                cycles: case.seen_after_open,
                same_source: case.same_source_seen,
            }
        };
        let outcome = evaluate(
            check,
            &input,
            (opened, persistence),
            cycle,
            env,
            &lr,
            &self.policy,
            self.secret,
        );
        *self
            .stats
            .checks_by_level
            .entry(check.level().label().to_string())
            .or_default() += 1;
        let tag = outcome_tag(&outcome);
        *self
            .stats
            .outcomes
            .entry(format!("{}:{tag}", check.label()))
            .or_default() += 1;
        if matches!(&outcome, Outcome::Unavailable(d) if d.contains("schvaleni")) {
            self.stats.needs_approval += 1;
        }
        let case = self.cases.get_mut(key)?;
        case.deferred = 0;
        match &outcome {
            Outcome::Wait(until) => {
                case.wait_until = Some(*until);
                return None; // kontrola zustava v planu, vrati se po cekani
            }
            Outcome::Evidence { lr, .. } => {
                let lr = match &self.learner {
                    Some(learner) => learner.lr(check, tag, *lr),
                    None => *lr,
                };
                case.log_odds += lr.max(1e-6).ln();
                if lr < 1.0 {
                    case.benign_evidence = true;
                }
            }
            Outcome::Undetermined(_) | Outcome::Unavailable(_) => {}
        }
        case.plan.pop_front();
        case.wait_until = None;
        let raw = case.posterior();
        let posterior = self
            .calibrator
            .as_ref()
            .map_or(raw, |calibrator| calibrator.predict(raw));
        case.steps.push(Step {
            check,
            cycle,
            outcome,
            posterior,
        });
        let executed = case
            .steps
            .iter()
            .filter(|s| !matches!(s.outcome, Outcome::Unavailable(_)))
            .count();
        let refute_at = if case.input.high_impact {
            self.policy.p_refute_high_impact
        } else {
            self.policy.p_refute
        };
        let status = if posterior >= self.policy.p_confirm {
            Some(Status::Confirmed)
        } else if posterior <= refute_at && case.benign_evidence {
            Some(Status::Refuted)
        } else if executed >= self.policy.max_checks || case.plan.is_empty() {
            Some(Status::Escalated)
        } else {
            None
        };
        status.and_then(|status| self.finish(key, status, cycle, false))
    }

    fn finish(
        &mut self,
        key: &FindingKey,
        status: Status,
        cycle: u64,
        budget: bool,
    ) -> Option<Decision> {
        let case = self.cases.remove(key)?;
        match status {
            Status::Confirmed => self.stats.confirmed += 1,
            Status::Refuted => self.stats.refuted += 1,
            Status::Escalated => {
                self.stats.escalated += 1;
                self.stats.escalated_budget += budget as u64;
            }
            Status::Open => {}
        }
        let reason = case
            .steps
            .iter()
            .map(|step| {
                let what = match &step.outcome {
                    Outcome::Evidence { lr, detail } => format!("LR {lr:.2}: {detail}"),
                    Outcome::Undetermined(d) => format!("nezjisteno: {d}"),
                    Outcome::Unavailable(d) => format!("neprovedeno: {d}"),
                    Outcome::Wait(_) => "ceka".to_string(),
                };
                format!(
                    "{} {} [{what}]",
                    step.check.level().label(),
                    step.check.label()
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let raw = case.posterior();
        let calibrated = self
            .calibrator
            .as_ref()
            .map_or(raw, |calibrator| calibrator.predict(raw));
        Some(Decision {
            raw_posterior: raw,
            host_ip: case.input.host_ip.clone(),
            finding_id: case.input.finding_id.clone(),
            finding_type: case.input.finding_type.clone(),
            key: case.input.key.clone(),
            status,
            posterior: calibrated,
            opened: case.opened,
            decided: cycle,
            reason: if budget {
                format!("rozpocet vycerpan opakovane; {reason}")
            } else {
                reason
            },
            checks: case.steps.len(),
            budget_escalation: budget,
            high_impact: case.input.high_impact,
            steps: case
                .steps
                .iter()
                .map(|step| (step.check, outcome_tag(&step.outcome)))
                .collect(),
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate(
    check: CheckId,
    input: &CaseInput,
    (opened, persistence): (u64, Persistence),
    cycle: u64,
    env: &mut dyn LadderEvidence,
    lr: &LrTable,
    policy: &LadderPolicy,
    secret: u64,
) -> Outcome {
    match check {
        CheckId::History => {
            let Some(key) = &input.history_key else {
                return Outcome::Undetermined("bez metriky historie".into());
            };
            match env.recurrence(key, input.volume) {
                Recurrence::Seen { days } => Outcome::Evidence {
                    lr: lr.history_seen,
                    detail: format!("stejny jev uz {days} dny ve stejne hodine"),
                },
                Recurrence::New { history_days } => Outcome::Evidence {
                    lr: lr.history_new,
                    detail: format!("za {history_days} dni historie nikdy"),
                },
                Recurrence::Insufficient { history_days } => {
                    Outcome::Undetermined(format!("historie jen {history_days} dny"))
                }
            }
        }
        CheckId::Context => match env.context(input) {
            Some(reason) => Outcome::Evidence {
                lr: lr.context,
                detail: format!("schvaleny kontext: {reason}"),
            },
            None => Outcome::Undetermined("zadny zaznam kontextu".into()),
        },
        CheckId::Reputation => {
            let mut good = None;
            for source in &input.sources {
                match env.reputation(source) {
                    Reputation::Bad(from) => {
                        return Outcome::Evidence {
                            lr: lr.reputation_bad,
                            detail: format!("{source} ma spatnou reputaci ({from})"),
                        };
                    }
                    Reputation::Good(from) => good = Some(format!("{source} ({from})")),
                    Reputation::Unknown => {}
                }
            }
            match good {
                // vsechny zname zdroje dobre a zadny spatny
                Some(detail) if input.sources.len() == 1 => Outcome::Evidence {
                    lr: lr.reputation_good,
                    detail: format!("duveryhodny zdroj {detail}"),
                },
                _ => Outcome::Undetermined("zdroj bez reputace".into()),
            }
        }
        CheckId::Intel => match env.intel(input) {
            IntelSignal::KnownExploited(cve) => Outcome::Evidence {
                lr: lr.intel_kev,
                detail: format!("cilova sluzba ma aktivne zneuzivanou zranitelnost {cve} (KEV)"),
            },
            IntelSignal::HighEpss(score) => Outcome::Evidence {
                lr: lr.intel_epss,
                detail: format!("cilova sluzba ma zranitelnost s EPSS {score:.2}"),
            },
            IntelSignal::NothingKnown => Outcome::Undetermined("o zranitelnosti nic nevime".into()),
        },
        CheckId::DeviceProfile => {
            let Some(class) = env.device(&input.host_ip) else {
                return Outcome::Undetermined("typ zarizeni neznamy".into());
            };
            let unusual = match input.finding_type.as_str() {
                "multi_target_pattern" | "scan_attempts" => {
                    // spravcovsky rozptyl z tiskarny, kamery, IoT, PLC je neobvykly
                    class.kind.is_fragile() || class.kind == DeviceKind::Voip
                }
                _ => input.port.is_some_and(|port| class.unusual_service(port)),
            };
            if unusual {
                Outcome::Evidence {
                    lr: lr.device_unusual,
                    detail: format!(
                        "neobvykle pro {} ({})",
                        class.kind.label(),
                        class.reasons.first().cloned().unwrap_or_default()
                    ),
                }
            } else {
                Outcome::Undetermined(format!("bezne pro {}", class.kind.label()))
            }
        }
        CheckId::Peers => match env.peers(input) {
            Some((affected, size)) if size >= 3 && affected * 2 >= size => Outcome::Evidence {
                lr: lr.peers_widespread,
                detail: format!("totez u {affected} z {size} zarizeni stejneho typu"),
            },
            Some((affected, size)) if size >= 5 && affected * 10 <= size => Outcome::Evidence {
                lr: lr.peers_isolated,
                detail: format!("jen {affected} z {size} zarizeni stejneho typu"),
            },
            Some((affected, size)) => {
                Outcome::Undetermined(format!("{affected} z {size} v peer skupine"))
            }
            None => Outcome::Undetermined("bez peer skupiny".into()),
        },
        CheckId::Persistence => {
            if cycle < opened + policy.persistence_wait {
                return Outcome::Wait(opened + policy.persistence_wait);
            }
            match persistence {
                Persistence::Recurring {
                    cycles,
                    same_source: true,
                } if !input.sources.is_empty() => Outcome::Evidence {
                    lr: lr.persistence_same_source,
                    detail: format!("pretrvava {cycles} cyklu se stejnym zdrojem"),
                },
                Persistence::Recurring { cycles, .. } if cycles >= 2 => Outcome::Evidence {
                    lr: lr.persistence_recurring,
                    detail: format!("pretrvava {cycles} cyklu"),
                },
                Persistence::Recurring { cycles, .. } => {
                    Outcome::Undetermined(format!("opakovani jen {cycles}x"))
                }
                // prechodny jev NENI dukaz neskodnosti (kratke utoky jsou prechodne)
                Persistence::Gone => Outcome::Undetermined("jev se neopakoval".into()),
            }
        }
        CheckId::Liveness => {
            if !env.in_scope(&input.host_ip) {
                return Outcome::Unavailable("mimo rozsah".into());
            }
            if is_fragile(&env.device(&input.host_ip)) {
                // kontrola krehkeho zarizeni jen se schvalenim (RQ3 Z10)
                return Outcome::Unavailable("krehke zarizeni, ceka na schvaleni".into());
            }
            let dominant = !input.sources.is_empty();
            match env.liveness(input) {
                Liveness::Down if !dominant => Outcome::Evidence {
                    lr: lr.liveness_down_outage,
                    detail: "sluzba neodpovida ani kontrole: vypadek vysvetluje selhani".into(),
                },
                Liveness::Down => {
                    Outcome::Undetermined("sluzba dole, ale s dominantnim zdrojem".into())
                }
                Liveness::Up if input.finding_type == "service_unreachable" => Outcome::Evidence {
                    lr: lr.liveness_up_unreachable,
                    detail: "sluzba odpovida kontrole, klientum ne".into(),
                },
                Liveness::Up => Outcome::Undetermined("sluzba odpovida".into()),
                Liveness::NeedsApproval => {
                    Outcome::Unavailable("aktivni kontrola ceka na schvaleni".into())
                }
                Liveness::OutOfScope => Outcome::Unavailable("mimo rozsah".into()),
                Liveness::Failed(reason) => Outcome::Unavailable(reason),
            }
        }
        CheckId::Pivot => {
            // BFS po komunikacnich hranach z entity a zdroju, jen v rozsahu
            let mut frontier: Vec<String> = std::iter::once(input.host_ip.clone())
                .chain(input.sources.iter().cloned())
                .filter(|ip| env.in_scope(ip))
                .collect();
            let mut seen: HashSet<String> = frontier.iter().cloned().collect();
            let mut visited = 0usize;
            let mut hits = 0usize;
            let salt = mix(secret ^ hash_text(&input.finding_id) ^ 0x9137);
            for _ in 0..policy.pivot_depth {
                let mut next = Vec::new();
                for node in &frontier {
                    let mut peers = env.neighbors(node);
                    peers.retain(|p| !seen.contains(p) && env.in_scope(p));
                    peers.sort_by_key(|p| mix(salt ^ hash_text(p)));
                    for peer in peers {
                        if visited >= policy.pivot_max_nodes {
                            break;
                        }
                        visited += 1;
                        seen.insert(peer.clone());
                        if env.suspicious_on(&peer) > 0 {
                            hits += 1;
                        }
                        next.push(peer);
                    }
                }
                if visited >= policy.pivot_max_nodes || next.is_empty() {
                    break;
                }
                frontier = next;
            }
            if hits == 0 {
                Outcome::Undetermined(format!("{visited} souvisejicich zarizeni bez podezreni"))
            } else {
                Outcome::Evidence {
                    lr: lr.pivot_per_hit.powi(hits.min(2) as i32),
                    detail: format!("podezreni na {hits} z {visited} souvisejicich zarizeni"),
                }
            }
        }
    }
}

/// Klíč metriky v historii toků pro typ nálezu (L0). `service` = `ip/proto/port`.
pub fn history_key_for(
    finding_type: &str,
    service: Option<&str>,
    entity_ip: &str,
    sources: &[String],
) -> Option<String> {
    use crate::flow_history::{Metric, key};
    match finding_type {
        "inductive_volume_anomaly"
        | "packet_rate_spike"
        | "service_overload_risk"
        | "unexpected_traffic" => service.map(|s| key(s, Metric::ServiceFlows)),
        "connection_timeout_burst" | "service_unreachable" => {
            service.map(|s| key(s, Metric::ServiceFailures))
        }
        "scan_attempts" => sources.first().map(|s| key(s, Metric::SourceAttempts)),
        "multi_target_pattern" => Some(key(entity_ip, Metric::SourceFanout)),
        "source_volume_outlier" => sources.first().map(|s| key(s, Metric::SourceFlows)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_class::ClassConfidence;

    #[derive(Default)]
    struct Env {
        recurrence: Option<Recurrence>,
        context: Option<String>,
        bad: HashSet<String>,
        peers: Option<(usize, usize)>,
        liveness: Option<Liveness>,
        device: Option<DeviceClass>,
        edges: HashMap<String, Vec<String>>,
        suspicious: HashSet<String>,
        liveness_calls: usize,
        kev: bool,
    }

    impl LadderEvidence for Env {
        fn recurrence(&self, _: &str, _: f64) -> Recurrence {
            self.recurrence
                .unwrap_or(Recurrence::Insufficient { history_days: 0 })
        }
        fn context(&self, _: &CaseInput) -> Option<String> {
            self.context.clone()
        }
        fn reputation(&self, ip: &str) -> Reputation {
            if self.bad.contains(ip) {
                Reputation::Bad("feed".into())
            } else {
                Reputation::Unknown
            }
        }
        fn intel(&self, _: &CaseInput) -> IntelSignal {
            if self.kev {
                IntelSignal::KnownExploited("CVE-2021-41773".into())
            } else {
                IntelSignal::NothingKnown
            }
        }
        fn device(&self, _: &str) -> Option<DeviceClass> {
            self.device.clone()
        }
        fn peers(&self, _: &CaseInput) -> Option<(usize, usize)> {
            self.peers
        }
        fn liveness(&mut self, _: &CaseInput) -> Liveness {
            self.liveness_calls += 1;
            self.liveness.clone().unwrap_or(Liveness::Up)
        }
        fn neighbors(&self, ip: &str) -> Vec<String> {
            self.edges.get(ip).cloned().unwrap_or_default()
        }
        fn in_scope(&self, ip: &str) -> bool {
            ip.starts_with("10.")
        }
        fn suspicious_on(&self, ip: &str) -> usize {
            self.suspicious.contains(ip) as usize
        }
    }

    fn input(kind: &str, entity: &str, sources: &[&str]) -> CaseInput {
        CaseInput {
            key: FindingKey::new(entity, kind, "tcp/80"),
            finding_id: format!("finding:{kind}:{entity}"),
            finding_type: kind.to_string(),
            host_ip: entity.to_string(),
            port: Some(80),
            sources: sources.iter().map(|s| s.to_string()).collect(),
            volume: 100.0,
            history_key: Some(format!("{entity}/tcp/80#flows")),
            high_impact: false,
            prior: 0.15,
        }
    }

    fn run_until_decided(ladder: &mut Ladder, env: &mut Env) -> Decision {
        run_observed(ladder, env, &[])
    }

    /// Jako `run_until_decided`, ale nález se každý cyklus znovu objeví se `sources`.
    fn run_observed(ladder: &mut Ladder, env: &mut Env, sources: &[&str]) -> Decision {
        let sources: Vec<String> = sources.iter().map(|s| s.to_string()).collect();
        let keys: Vec<FindingKey> = ladder.cases.keys().cloned().collect();
        for cycle in 0..20 {
            if !sources.is_empty() {
                for key in &keys {
                    ladder.observe(key, &sources, cycle);
                }
            }
            if let Some(d) = ladder.step(cycle, env).into_iter().next() {
                return d;
            }
        }
        panic!("nerozhodnuto");
    }

    #[test]
    fn empty_results_never_refute_and_case_escalates_after_cap() {
        let mut ladder = Ladder::new(LadderPolicy::default(), 7);
        let mut env = Env::default();
        assert!(ladder.open(input("inductive_volume_anomaly", "10.0.0.5", &[]), 0));
        let decision = run_until_decided(&mut ladder, &mut env);
        assert_eq!(decision.status, Status::Escalated, "{}", decision.reason);
        assert!(decision.reason.contains("nezjisteno"));
        assert!(
            (decision.posterior - 0.15).abs() < 1e-9,
            "prazdne dotazy viru nemeni"
        );
    }

    #[test]
    fn recurring_and_widespread_pattern_is_refuted_with_reason() {
        let mut ladder = Ladder::new(LadderPolicy::default(), 7);
        let mut env = Env {
            recurrence: Some(Recurrence::Seen { days: 4 }),
            peers: Some((5, 6)),
            ..Env::default()
        };
        ladder.open(input("inductive_volume_anomaly", "10.0.0.5", &[]), 0);
        let decision = run_until_decided(&mut ladder, &mut env);
        assert_eq!(decision.status, Status::Refuted, "{}", decision.reason);
        assert!(decision.reason.contains("history") && decision.reason.contains("peers"));
        assert_eq!(decision.decided, 0, "rozhodnuto okamzite, bez cekani");
    }

    #[test]
    fn bad_reputation_new_behaviour_and_persistence_confirm() {
        // bez KEV: silne podezreni, ale pod mezi potvrzeni -> eskalace cloveku
        let mut ladder = Ladder::new(LadderPolicy::default(), 7);
        let mut env = Env {
            recurrence: Some(Recurrence::New { history_days: 5 }),
            bad: ["203.0.113.9".to_string()].into_iter().collect(),
            ..Env::default()
        };
        ladder.open(
            input("source_volume_outlier", "10.0.0.5", &["203.0.113.9"]),
            0,
        );
        let decision = run_observed(&mut ladder, &mut env, &["203.0.113.9"]);
        assert_eq!(decision.status, Status::Escalated, "{}", decision.reason);
        assert!(decision.posterior > 0.8);

        let mut ladder = Ladder::new(LadderPolicy::default(), 7);
        let mut env = Env {
            kev: true,
            recurrence: Some(Recurrence::New { history_days: 5 }),
            bad: ["203.0.113.9".to_string()].into_iter().collect(),
            ..Env::default()
        };
        ladder.open(
            input("source_volume_outlier", "10.0.0.5", &["203.0.113.9"]),
            0,
        );
        let decision = run_observed(&mut ladder, &mut env, &["203.0.113.9"]);
        assert_eq!(decision.status, Status::Confirmed, "{}", decision.reason);
        assert!(decision.posterior >= 0.9);
    }

    #[test]
    fn open_is_idempotent_and_merges_sources() {
        let mut ladder = Ladder::new(LadderPolicy::default(), 7);
        assert!(ladder.open(input("scan_attempts", "10.0.0.5", &["198.51.100.1"]), 0));
        assert!(!ladder.open(input("scan_attempts", "10.0.0.5", &["198.51.100.2"]), 1));
        assert_eq!(ladder.open_cases(), 1);
        assert_eq!(ladder.stats.cases_merged, 1);
    }

    #[test]
    fn fragile_device_gets_no_active_probe_and_outage_refutes_otherwise() {
        let printer = DeviceClass {
            kind: DeviceKind::Printer,
            confidence: ClassConfidence::High,
            reasons: vec!["tiskovy protokol".into()],
        };
        let mut ladder = Ladder::new(LadderPolicy::default(), 7);
        let mut env = Env {
            device: Some(printer),
            liveness: Some(Liveness::Down),
            ..Env::default()
        };
        ladder.open(input("service_unreachable", "10.0.0.20", &[]), 0);
        let decision = run_until_decided(&mut ladder, &mut env);
        assert_eq!(
            env.liveness_calls, 0,
            "krehke zarizeni bez schvaleni neproklepnout"
        );
        assert_eq!(decision.status, Status::Escalated);
        assert_eq!(ladder.stats.needs_approval, 1);

        let mut ladder = Ladder::new(LadderPolicy::default(), 7);
        let mut env = Env {
            liveness: Some(Liveness::Down),
            ..Env::default()
        };
        ladder.open(input("service_unreachable", "10.0.0.21", &[]), 0);
        let decision = run_until_decided(&mut ladder, &mut env);
        assert_eq!(env.liveness_calls, 1);
        assert_eq!(decision.status, Status::Refuted, "{}", decision.reason);
    }

    #[test]
    fn pivot_stays_in_scope_and_respects_depth_and_node_cap() {
        let mut env = Env::default();
        env.edges
            .insert("10.0.0.5".into(), vec!["10.0.0.6".into(), "8.8.8.8".into()]);
        env.edges.insert("10.0.0.6".into(), vec!["10.0.0.7".into()]);
        env.edges.insert("10.0.0.7".into(), vec!["10.0.0.8".into()]);
        env.edges.insert("10.0.0.8".into(), vec!["10.0.0.9".into()]);
        env.suspicious.insert("10.0.0.9".into());
        env.suspicious.insert("10.0.0.8".into());
        let policy = LadderPolicy::default();
        let case = input("scan_attempts", "10.0.0.5", &[]);
        let out = evaluate(
            CheckId::Pivot,
            &case,
            (0, Persistence::Gone),
            0,
            &mut env,
            &policy.lr,
            &policy,
            1,
        );
        // hloubka 3: 10.0.0.6, .7, .8 (ne .9, ne 8.8.8.8 mimo rozsah)
        match out {
            Outcome::Evidence { lr, detail } => {
                assert!((lr - 2.0).abs() < 1e-9, "{detail}");
                assert!(detail.contains("z 3"), "{detail}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn budget_defers_and_escalates_and_order_is_not_alphabetical() {
        let policy = LadderPolicy {
            budget_per_cycle: 0.12,
            max_deferred: 2,
            explore: 0.0,
            ..LadderPolicy::default()
        };
        let mut ladder = Ladder::new(policy, 99);
        for i in 0..6 {
            ladder.open(
                input("inductive_volume_anomaly", &format!("10.0.0.{i}"), &[]),
                0,
            );
        }
        let mut env = Env::default();
        let mut decided = Vec::new();
        for cycle in 0..6 {
            decided.extend(ladder.step(cycle, &mut env));
        }
        assert!(ladder.stats.checks_deferred > 0);
        assert!(decided.iter().any(|d| d.budget_escalation));
        // stejny tajny klic = stejne poradi (reprodukovatelnost), jiny klic = jine poradi
        let order = |secret: u64| {
            let mut l = Ladder::new(LadderPolicy::default(), secret);
            let case = input("unexpected_traffic", "10.0.0.5", &["10.0.1.1"]);
            l.open(case.clone(), 0);
            plan_for(&case, secret).into_iter().collect::<Vec<_>>()
        };
        assert_eq!(order(1), order(1));
        let plan = order(1);
        assert_eq!(
            plan.last(),
            Some(&CheckId::Persistence),
            "cekani az nakonec"
        );
        let levels: Vec<Level> = plan[..plan.len() - 1].iter().map(|c| c.level()).collect();
        let mut sorted = levels.clone();
        sorted.sort();
        assert_eq!(levels, sorted, "urovne od nejlevnejsi");
        assert!(
            (0..40).any(|s| order(s) != order(1)),
            "pořadí uvnitř úrovně je náhodné"
        );
    }

    #[test]
    fn ladder_state_roundtrips_through_json() {
        let mut ladder = Ladder::new(LadderPolicy::default(), 3);
        ladder.open(input("scan_attempts", "10.0.0.5", &["198.51.100.1"]), 0);
        let mut env = Env::default();
        ladder.step(0, &mut env);
        let json = serde_json::to_string(&ladder).unwrap();
        let back: Ladder = serde_json::from_str(&json).unwrap();
        assert_eq!(back.open_cases(), ladder.open_cases());
    }

    #[test]
    fn learner_shrinks_toward_author_respects_bounds_and_drops_poisoned_source() {
        let mut learner = LadderLearner::default();
        let steps = [
            (CheckId::History, "benign"),
            (CheckId::Context, "undetermined"),
        ];
        assert_eq!(
            learner.lr(CheckId::History, "benign", 0.25),
            0.25,
            "bez dat autorsky"
        );
        for _ in 0..200 {
            learner.record("operator:op", &steps, false, 1.0);
        }
        for _ in 0..50 {
            learner.record(
                "operator:op",
                &[(CheckId::Context, "undetermined")],
                true,
                1.0,
            );
        }
        let lr = learner.lr(CheckId::History, "benign", 0.25);
        assert!(lr < 0.25 && lr >= 0.02, "{lr}");
        assert_eq!(
            learner.lr(CheckId::Context, "undetermined", 1.0),
            1.0,
            "prazdny vysledek se neuci"
        );
        // benigni znacka nikdy nad 1, i kdyby data rikala opak
        for _ in 0..500 {
            learner.record("operator:mallory", &steps, true, 1.0);
        }
        assert!(learner.lr(CheckId::History, "benign", 0.25) <= 1.0);
        learner.exclude("operator:mallory");
        assert!((learner.lr(CheckId::History, "benign", 0.25) - lr).abs() < 1e-12);
    }
}
