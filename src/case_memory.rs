//! Case Memory (navrh sekce 5.6): verzovana pamet OVERENYCH pripadu (potvrzeny /
//! vyvraceny nalez), ze ktere se odhaduje, jak casto je dany typ nalezu skutecny.
//! Odhad plni `SecurityHypothesis.probability` - a jen kdyz je dost dukazu; jinak
//! zustava `None` (zadna fabrikovana hodnota, viz `hypothesis.rs`).
//!
//! Odhad: pro kazdy `finding_type` Beta(1,1) prior + vazene potvrzene/vyvracene
//! pripady -> posteriorni stred = pravdepodobnost, ze nalez je skutecny, plus 95 %
//! credible interval (regularizovana neuplna beta funkce, viz `beta_quantile`).
//! `Inconclusive` se nikdy nepocita.
//!
//! Poisoning guard (ucenim z neoverenych/utocnikovych dat by se tise zfalsovalo
//! rozhodovani) - vsechny mantinely jsou testovane utocnymi scenari:
//! 1. **Rate limit**: max `MAX_RECORDS_PER_HOUR` zaznamu za hodinu od jednoho
//!    zdroje, nadlimitni jdou do karanteny.
//! 2. **Strop jednoho zdroje**: pozdni zdroj (ne zakladajici) smi po `>= 10`
//!    efektivnich pripadech tvorit nejvyse 50 % vahy typu. Zakladajici zdroj (ten
//!    s nejstarsim zaznamem typu) je vyjmut - bez nej by typ s jedinym legitimnim
//!    zdrojem po 10. pripadu prestal ucit. Typy s jedinym zdrojem nemaji
//!    krizovou kontrolu (`Estimate::distinct_sources == 1` to dava vedet).
//! 3. **Kontradikce**: zaznam proti robustnimu konsenzu (`>= 10` efektivnich
//!    pripadu a stred `> 0.85` nebo `< 0.15`) od zdroje, jehoz posledni rozporuplne
//!    zaznamy tvori `> 60 %` (aspon `MIN_RECENT_FOR_FLAG` zaznamu), jde do karanteny
//!    a zdroj je oznacen - dalsi zaznamy z oznaceneho zdroje se karantenuji.
//!
//! Karantenovane zaznamy se nemazou (`quarantine_list`).
//!
//! Persistence: `case-memory.json` (atomicky zapis) + poslednich 20 snapshotu
//! `case-memory/v{N}.json`; verze je monotonni, `rollback_to` obnovi obsah starsi
//! verze jako NOVOU verzi (historie se neprepisuje).

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    error::{SalticusError, Result},
    storage::write_atomic,
    verification_exec::VerificationResult,
};

pub const MIN_CASES: f64 = 5.0;
pub const MAX_RECORDS_PER_HOUR: usize = 30;
pub const SOURCE_CAP_MIN_EFFECTIVE: f64 = 10.0;
pub const SOURCE_CAP_SHARE: f64 = 0.5;
pub const CONSENSUS_MIN_EFFECTIVE: f64 = 10.0;
pub const CONSENSUS_HIGH: f64 = 0.85;
pub const CONSENSUS_LOW: f64 = 0.15;
pub const CONTRADICTION_SHARE: f64 = 0.6;
pub const MIN_RECENT_FOR_FLAG: usize = 3;
pub const RECENT_WINDOW: usize = 10;
pub const SNAPSHOTS_KEPT: usize = 20;
/// Vaha automatickych overeni (operator = 1.0): stroj muze mylit, clovek nikoli.
pub const VERIFICATION_WEIGHT: f64 = 0.8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Confirmed,
    Refuted,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CaseSource {
    Verification { method: String },
    Operator { actor: String },
    External { name: String },
}

impl CaseSource {
    pub fn key(&self) -> String {
        match self {
            Self::Verification { method } => format!("verification:{method}"),
            Self::Operator { actor } => format!("operator:{actor}"),
            Self::External { name } => format!("external:{name}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaseRecord {
    pub case_id: String,
    pub at: DateTime<Utc>,
    pub finding_type: String,
    pub asset_key: Option<String>,
    pub outcome: Outcome,
    pub source: CaseSource,
    pub weight: f64,
}

impl CaseRecord {
    pub fn new(
        finding_type: &str,
        asset_key: Option<&str>,
        outcome: Outcome,
        source: CaseSource,
        weight: f64,
        at: DateTime<Utc>,
    ) -> Self {
        Self {
            case_id: uuid::Uuid::new_v4().to_string(),
            at,
            finding_type: finding_type.to_string(),
            asset_key: asset_key.map(ToString::to_string),
            outcome,
            source,
            weight,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineReason {
    InvalidWeight,
    SourceFlagged,
    RateLimited,
    Contradiction,
    SourceCap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordOutcome {
    Accepted,
    Quarantined(QuarantineReason),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantinedCase {
    pub record: CaseRecord,
    pub reason: QuarantineReason,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Estimate {
    pub probability: f64,
    pub lo95: f64,
    pub hi95: f64,
    pub effective_cases: f64,
    pub version: u64,
    pub distinct_sources: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct State {
    version: u64,
    records: Vec<CaseRecord>,
    quarantine: Vec<QuarantinedCase>,
    flagged_sources: BTreeSet<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CaseMemory {
    path: Option<PathBuf>,
    state: State,
}

impl CaseMemory {
    /// Pamet jen v RAM (testy, eval) - `save()` bez cesty je chyba.
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Chybejici/poskozeny soubor = prazdna pamet (nikdy panika, nikdy tiche
    /// vymysleni dat).
    pub fn load_or_default(path: &Path) -> Self {
        let state = fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str::<State>(&text).ok())
            .unwrap_or_default();
        Self {
            path: Some(path.to_path_buf()),
            state,
        }
    }

    pub fn version(&self) -> u64 {
        self.state.version
    }

    pub fn quarantine_list(&self) -> &[QuarantinedCase] {
        &self.state.quarantine
    }

    pub fn flagged_sources(&self) -> &BTreeSet<String> {
        &self.state.flagged_sources
    }

    pub fn accepted_len(&self) -> usize {
        self.state.records.len()
    }

    /// Cte-uprav-uloz pod zamkem (pipeline i server zapisuji do stejneho souboru).
    pub fn update<T>(path: &Path, change: impl FnOnce(&mut CaseMemory) -> T) -> Result<T> {
        with_file_lock(path, || {
            let mut memory = Self::load_or_default(path);
            let value = change(&mut memory);
            memory.save()?;
            Ok(value)
        })
    }

    fn effective_weights(&self, finding_type: &str) -> (f64, f64) {
        let mut confirmed = 0.0;
        let mut refuted = 0.0;
        for record in self
            .state
            .records
            .iter()
            .filter(|record| record.finding_type == finding_type)
        {
            match record.outcome {
                Outcome::Confirmed => confirmed += record.weight,
                Outcome::Refuted => refuted += record.weight,
                Outcome::Inconclusive => {}
            }
        }
        (confirmed, refuted)
    }

    /// `None` pod `MIN_CASES` efektivnich pripadu.
    pub fn estimate(&self, finding_type: &str) -> Option<Estimate> {
        let (confirmed, refuted) = self.effective_weights(finding_type);
        let effective = confirmed + refuted;
        if effective < MIN_CASES {
            return None;
        }
        let a = 1.0 + confirmed;
        let b = 1.0 + refuted;
        let sources: BTreeSet<String> = self
            .state
            .records
            .iter()
            .filter(|record| {
                record.finding_type == finding_type && record.outcome != Outcome::Inconclusive
            })
            .map(|record| record.source.key())
            .collect();
        Some(Estimate {
            probability: a / (a + b),
            lo95: beta_quantile(0.025, a, b),
            hi95: beta_quantile(0.975, a, b),
            effective_cases: effective,
            version: self.state.version,
            distinct_sources: sources.len(),
        })
    }

    fn source_attempts_last_hour(&self, source_key: &str, at: DateTime<Utc>) -> usize {
        let since = at - chrono::Duration::hours(1);
        let accepted = self
            .state
            .records
            .iter()
            .filter(|record| {
                record.source.key() == source_key && record.at > since && record.at <= at
            })
            .count();
        let quarantined = self
            .state
            .quarantine
            .iter()
            .filter(|item| {
                item.record.source.key() == source_key
                    && item.record.at > since
                    && item.record.at <= at
            })
            .count();
        accepted + quarantined
    }

    /// Zakladajici zdroj typu = zdroj nejstarsiho akceptovaneho rozhodneho zaznamu.
    fn founding_source(&self, finding_type: &str) -> Option<String> {
        self.state
            .records
            .iter()
            .filter(|record| {
                record.finding_type == finding_type && record.outcome != Outcome::Inconclusive
            })
            .min_by_key(|record| record.at)
            .map(|record| record.source.key())
    }

    fn source_effective_weight(&self, finding_type: &str, source_key: &str) -> f64 {
        self.state
            .records
            .iter()
            .filter(|record| {
                record.finding_type == finding_type
                    && record.outcome != Outcome::Inconclusive
                    && record.source.key() == source_key
            })
            .map(|record| record.weight)
            .sum()
    }

    /// Podil poslednich rozhodnych zaznamu zdroje (akceptovanych i karantenovanych,
    /// vcetne noveho), ktere jdou proti konsenzu `direction`.
    fn recent_contradiction(&self, record: &CaseRecord, direction: Outcome) -> Option<f64> {
        let source_key = record.source.key();
        let mut recent: Vec<(DateTime<Utc>, Outcome)> = self
            .state
            .records
            .iter()
            .chain(self.state.quarantine.iter().map(|item| &item.record))
            .filter(|other| {
                other.finding_type == record.finding_type
                    && other.outcome != Outcome::Inconclusive
                    && other.source.key() == source_key
            })
            .map(|other| (other.at, other.outcome))
            .collect();
        recent.push((record.at, record.outcome));
        recent.sort_by_key(|(at, _)| *at);
        let start = recent.len().saturating_sub(RECENT_WINDOW);
        let window = &recent[start..];
        if window.len() < MIN_RECENT_FOR_FLAG {
            return None;
        }
        let contradicting = window
            .iter()
            .filter(|(_, outcome)| *outcome != direction)
            .count();
        Some(contradicting as f64 / window.len() as f64)
    }

    /// Zaznamena pripad; kazde volani zvysi verzi (i karantena je zmena stavu).
    pub fn record(&mut self, mut record: CaseRecord) -> RecordOutcome {
        self.state.version += 1;
        let source_key = record.source.key();

        if !record.weight.is_finite() {
            return self.quarantine(record, QuarantineReason::InvalidWeight);
        }
        record.weight = record.weight.clamp(0.0, 1.0);

        if self.state.flagged_sources.contains(&source_key) {
            return self.quarantine(record, QuarantineReason::SourceFlagged);
        }
        if self.source_attempts_last_hour(&source_key, record.at) >= MAX_RECORDS_PER_HOUR {
            return self.quarantine(record, QuarantineReason::RateLimited);
        }

        if record.outcome != Outcome::Inconclusive {
            // Konsenzus se meri BEZ zaznamu posuzovaneho zdroje - utocnik by jinak
            // svymi drive akceptovanymi zaznamy konsenzus podkopal pod prah.
            let (mean, effective) =
                self.posterior_mean_excluding(&record.finding_type, &source_key);
            if effective >= CONSENSUS_MIN_EFFECTIVE {
                let direction = if mean > CONSENSUS_HIGH {
                    Some(Outcome::Confirmed)
                } else if mean < CONSENSUS_LOW {
                    Some(Outcome::Refuted)
                } else {
                    None
                };
                if let Some(direction) = direction
                    && record.outcome != direction
                    && self
                        .recent_contradiction(&record, direction)
                        .is_some_and(|share| share > CONTRADICTION_SHARE)
                {
                    self.state.flagged_sources.insert(source_key.clone());
                    self.quarantine_contradicting_history(
                        &record.finding_type,
                        &source_key,
                        direction,
                    );
                    return self.quarantine(record, QuarantineReason::Contradiction);
                }
            }

            let (confirmed, refuted) = self.effective_weights(&record.finding_type);
            let total_after = confirmed + refuted + record.weight;
            let source_after =
                self.source_effective_weight(&record.finding_type, &source_key) + record.weight;
            let founder = self.founding_source(&record.finding_type);
            let is_late_joiner = founder.is_some_and(|founder| founder != source_key);
            if is_late_joiner
                && total_after >= SOURCE_CAP_MIN_EFFECTIVE
                && source_after / total_after > SOURCE_CAP_SHARE
            {
                return self.quarantine(record, QuarantineReason::SourceCap);
            }
        }

        self.state.records.push(record);
        RecordOutcome::Accepted
    }

    fn posterior_mean_excluding(&self, finding_type: &str, source_key: &str) -> (f64, f64) {
        let mut confirmed = 0.0;
        let mut refuted = 0.0;
        for record in self.state.records.iter().filter(|record| {
            record.finding_type == finding_type && record.source.key() != source_key
        }) {
            match record.outcome {
                Outcome::Confirmed => confirmed += record.weight,
                Outcome::Refuted => refuted += record.weight,
                Outcome::Inconclusive => {}
            }
        }
        (
            (1.0 + confirmed) / (2.0 + confirmed + refuted),
            confirmed + refuted,
        )
    }

    /// Oznaceny zdroj: jeho drive akceptovane zaznamy proti konsenzu se
    /// zpetne presunou do karanteny (byly soucasti stejneho utoku).
    fn quarantine_contradicting_history(
        &mut self,
        finding_type: &str,
        source_key: &str,
        direction: Outcome,
    ) {
        let (tainted, kept): (Vec<CaseRecord>, Vec<CaseRecord>) =
            std::mem::take(&mut self.state.records)
                .into_iter()
                .partition(|record| {
                    record.finding_type == finding_type
                        && record.source.key() == source_key
                        && record.outcome != Outcome::Inconclusive
                        && record.outcome != direction
                });
        self.state.records = kept;
        for record in tainted {
            self.state.quarantine.push(QuarantinedCase {
                record,
                reason: QuarantineReason::Contradiction,
            });
        }
    }

    fn quarantine(&mut self, record: CaseRecord, reason: QuarantineReason) -> RecordOutcome {
        self.state.quarantine.push(QuarantinedCase {
            record,
            reason: reason.clone(),
        });
        RecordOutcome::Quarantined(reason)
    }

    fn snapshot_dir(path: &Path) -> PathBuf {
        path.with_extension("")
    }

    pub fn save(&self) -> Result<()> {
        let path = self.path.as_ref().ok_or_else(|| {
            SalticusError::Processing("CaseMemory bez cesty nelze ulozit".to_string())
        })?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_string_pretty(&self.state)?;
        write_atomic(path, bytes.as_bytes())?;

        let dir = Self::snapshot_dir(path);
        fs::create_dir_all(&dir)?;
        write_atomic(
            &dir.join(format!("v{}.json", self.state.version)),
            bytes.as_bytes(),
        )?;
        let mut versions: Vec<u64> = fs::read_dir(&dir)?
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().to_string();
                name.strip_prefix('v')?
                    .strip_suffix(".json")?
                    .parse::<u64>()
                    .ok()
            })
            .collect();
        versions.sort_unstable();
        if versions.len() > SNAPSHOTS_KEPT {
            for old in &versions[..versions.len() - SNAPSHOTS_KEPT] {
                let _ = fs::remove_file(dir.join(format!("v{old}.json")));
            }
        }
        Ok(())
    }

    /// Obnovi OBSAH snapshotu `version` jako novou, vyssi verzi (monotonie).
    pub fn rollback_to(&mut self, version: u64) -> Result<()> {
        let path = self.path.as_ref().ok_or_else(|| {
            SalticusError::Processing("CaseMemory bez cesty nelze vratit".to_string())
        })?;
        let snapshot = Self::snapshot_dir(path).join(format!("v{version}.json"));
        let text = fs::read_to_string(&snapshot).map_err(|_| {
            SalticusError::Processing(format!(
                "snapshot v{version} neexistuje (drzi se poslednich {SNAPSHOTS_KEPT})"
            ))
        })?;
        let restored: State = serde_json::from_str(&text)?;
        let next_version = self.state.version.max(restored.version) + 1;
        self.state = State {
            version: next_version,
            ..restored
        };
        Ok(())
    }
}

// --- mapovani vysledku overeni na pripady ------------------------------------

const EXPOSURE_TYPES: &[&str] = &[
    "management_surface_exposure",
    "new_exposed_service",
    "plaintext_management_protocol",
    "http_basic_without_tls",
    "insecure_auth_possible",
];
const CVE_TYPES: &[&str] = &[
    "high_risk_cve_exposure",
    "known_exploited_vulnerability",
    "probable_exploitation_interest",
];

fn http_statuses(outcome: &str) -> Vec<u16> {
    outcome
        .split("-> ")
        .skip(1)
        .filter_map(|rest| rest.split(',').next()?.trim().parse::<u16>().ok())
        .collect()
}

fn leading_count(outcome: &str) -> Option<u32> {
    outcome.split_whitespace().next()?.parse().ok()
}

fn highest_cvss(outcome: &str) -> Option<f64> {
    let rest = outcome.split("nejvyssi CVSS ").nth(1)?;
    rest.split(|c: char| c == ',' || c.is_whitespace())
        .next()?
        .parse()
        .ok()
}

/// Konzervativni mapovani: jen to, co vysledek kontroly skutecne dokazuje.
/// Vse ostatni (reused, needs_approval, skipped, neznama metoda, nejednoznacny
/// text) se NEZAZNAMENAVA.
pub fn case_from_verification_result(
    result: &VerificationResult,
    at: DateTime<Utc>,
) -> Option<CaseRecord> {
    let outcome_text = result.outcome.as_deref().unwrap_or("");
    let outcome = match (result.method.as_str(), result.status.as_str()) {
        ("read_only_content_inspection", "executed")
            if EXPOSURE_TYPES.contains(&result.hypothesis_type.as_str()) =>
        {
            if http_statuses(outcome_text)
                .iter()
                .any(|status| *status < 400)
            {
                Outcome::Confirmed
            } else {
                Outcome::Refuted
            }
        }
        ("read_only_content_inspection", "failed")
            if EXPOSURE_TYPES.contains(&result.hypothesis_type.as_str())
                && outcome_text.contains("nema otevreny webovy port") =>
        {
            Outcome::Refuted
        }
        ("cve_intel_relookup", "executed")
            if CVE_TYPES.contains(&result.hypothesis_type.as_str()) =>
        {
            match (leading_count(outcome_text), highest_cvss(outcome_text)) {
                (Some(0), _) => Outcome::Refuted,
                (Some(count), Some(cvss)) if count >= 1 && cvss >= 7.0 => Outcome::Confirmed,
                _ => return None,
            }
        }
        _ => return None,
    };
    Some(CaseRecord::new(
        &result.hypothesis_type,
        Some(&result.asset),
        outcome,
        CaseSource::Verification {
            method: result.method.clone(),
        },
        VERIFICATION_WEIGHT,
        at,
    ))
}

// --- zamek souboru ------------------------------------------------------------

struct LockGuard(PathBuf);

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Jednoduchy zamek (`<soubor>.lock`, `create_new`): pipeline a server zapisuji do
/// stejne pameti z ruznych procesu. Zamek starsi nez 30 s se povazuje za
/// opusteny (pad procesu).
pub(crate) fn with_file_lock<T>(path: &Path, work: impl FnOnce() -> Result<T>) -> Result<T> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let lock_path = path.with_extension("lock");
    let started = Instant::now();
    loop {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let stale = fs::metadata(&lock_path)
                    .and_then(|meta| meta.modified())
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .is_some_and(|age| age > Duration::from_secs(60));
                if stale {
                    let _ = fs::remove_file(&lock_path);
                    continue;
                }
                if started.elapsed() > Duration::from_secs(30) {
                    return Err(SalticusError::Processing(format!(
                        "zamek {} se nepodarilo ziskat",
                        lock_path.display()
                    )));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error.into()),
        }
    }
    let _guard = LockGuard(lock_path);
    work()
}

// --- Beta rozdeleni -----------------------------------------------------------

fn ln_gamma(x: f64) -> f64 {
    // Lanczos (g = 7, n = 9).
    const COEF: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if x < 0.5 {
        return (std::f64::consts::PI / (std::f64::consts::PI * x).sin()).ln() - ln_gamma(1.0 - x);
    }
    let x = x - 1.0;
    let mut sum = COEF[0];
    for (index, coef) in COEF.iter().enumerate().skip(1) {
        sum += coef / (x + index as f64);
    }
    let t = x + 7.5;
    0.5 * (2.0 * std::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + sum.ln()
}

fn beta_continued_fraction(a: f64, b: f64, x: f64) -> f64 {
    let tiny = 1e-300;
    let (qab, qap, qam) = (a + b, a + 1.0, a - 1.0);
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < tiny {
        d = tiny;
    }
    d = 1.0 / d;
    let mut h = d;
    for m in 1..=300 {
        let m = m as f64;
        let m2 = 2.0 * m;
        let aa = m * (b - m) * x / ((qam + m2) * (a + m2));
        d = 1.0 + aa * d;
        if d.abs() < tiny {
            d = tiny;
        }
        c = 1.0 + aa / c;
        if c.abs() < tiny {
            c = tiny;
        }
        d = 1.0 / d;
        h *= d * c;
        let aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2));
        d = 1.0 + aa * d;
        if d.abs() < tiny {
            d = tiny;
        }
        c = 1.0 + aa / c;
        if c.abs() < tiny {
            c = tiny;
        }
        d = 1.0 / d;
        let delta = d * c;
        h *= delta;
        if (delta - 1.0).abs() < 1e-14 {
            break;
        }
    }
    h
}

/// Regularizovana neuplna beta funkce I_x(a, b) = CDF Beta(a, b) v bode x.
pub fn regularized_incomplete_beta(x: f64, a: f64, b: f64) -> f64 {
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let ln_front = ln_gamma(a + b) - ln_gamma(a) - ln_gamma(b) + a * x.ln() + b * (1.0 - x).ln();
    let front = ln_front.exp();
    if x < (a + 1.0) / (a + b + 2.0) {
        front * beta_continued_fraction(a, b, x) / a
    } else {
        1.0 - front * beta_continued_fraction(b, a, 1.0 - x) / b
    }
}

/// Kvantil Beta(a, b) puleni intervalu (200 iteraci -> presnost na strojove epsilon).
pub fn beta_quantile(p: f64, a: f64, b: f64) -> f64 {
    let (mut low, mut high) = (0.0_f64, 1.0_f64);
    for _ in 0..200 {
        let mid = 0.5 * (low + high);
        if regularized_incomplete_beta(mid, a, b) < p {
            low = mid;
        } else {
            high = mid;
        }
    }
    0.5 * (low + high)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 1, 10, 0, 0).unwrap()
    }

    fn op(name: &str) -> CaseSource {
        CaseSource::Operator {
            actor: name.to_string(),
        }
    }

    fn rec(ft: &str, outcome: Outcome, source: CaseSource, minutes: i64) -> CaseRecord {
        CaseRecord::new(
            ft,
            Some("10.0.0.1"),
            outcome,
            source,
            1.0,
            t0() + chrono::Duration::minutes(minutes),
        )
    }

    fn feed(
        memory: &mut CaseMemory,
        ft: &str,
        outcome: Outcome,
        source: CaseSource,
        n: usize,
        start_min: i64,
    ) {
        for i in 0..n {
            assert_eq!(
                memory.record(rec(ft, outcome, source.clone(), start_min + i as i64 * 3)),
                RecordOutcome::Accepted
            );
        }
    }

    // --- Beta matematika ---

    #[test]
    fn incomplete_beta_matches_closed_forms() {
        // Beta(1,1): CDF(x)=x; Beta(2,1): x^2; Beta(1,3): 1-(1-x)^3; Beta(2,2): 3x^2-2x^3.
        for x in [0.1, 0.37, 0.5, 0.9] {
            assert!((regularized_incomplete_beta(x, 1.0, 1.0) - x).abs() < 1e-10);
            assert!((regularized_incomplete_beta(x, 2.0, 1.0) - x * x).abs() < 1e-10);
            assert!(
                (regularized_incomplete_beta(x, 1.0, 3.0) - (1.0 - (1.0 - x).powi(3))).abs()
                    < 1e-10
            );
            assert!(
                (regularized_incomplete_beta(x, 2.0, 2.0) - (3.0 * x * x - 2.0 * x.powi(3))).abs()
                    < 1e-10
            );
        }
    }

    #[test]
    fn beta_quantile_inverts_the_cdf_and_matches_known_values() {
        // Beta(1,1) kvantil p je p; Beta(2,1): sqrt(p).
        assert!((beta_quantile(0.025, 1.0, 1.0) - 0.025).abs() < 1e-9);
        assert!((beta_quantile(0.975, 2.0, 1.0) - 0.975_f64.sqrt()).abs() < 1e-9);
        // Beta(10,3): cela cisla -> CDF = P(Binomial(12, x) >= 10) (nezavisly vzorec).
        fn binom_tail(x: f64) -> f64 {
            let n = 12u32;
            (10..=n)
                .map(|j| {
                    let mut c = 1.0;
                    for i in 0..j {
                        c = c * f64::from(n - i) / f64::from(i + 1);
                    }
                    c * x.powi(j as i32) * (1.0 - x).powi((n - j) as i32)
                })
                .sum()
        }
        let (lo, hi) = (
            beta_quantile(0.025, 10.0, 3.0),
            beta_quantile(0.975, 10.0, 3.0),
        );
        assert!((binom_tail(lo) - 0.025).abs() < 1e-9, "lo={lo}");
        assert!((binom_tail(hi) - 0.975).abs() < 1e-9, "hi={hi}");
        assert!(lo < hi && lo > 0.5 && hi < 0.95);
    }

    // --- odhad ---

    #[test]
    fn estimate_is_none_below_min_cases_and_never_fabricated() {
        let mut memory = CaseMemory::in_memory();
        assert!(memory.estimate("x").is_none());
        feed(&mut memory, "x", Outcome::Confirmed, op("a"), 4, 0);
        assert!(memory.estimate("x").is_none(), "4 < MIN_CASES");
        feed(&mut memory, "x", Outcome::Confirmed, op("a"), 1, 100);
        let estimate = memory.estimate("x").expect("5 pripadu staci");
        assert!(estimate.probability > 0.8);
    }

    #[test]
    fn inconclusive_never_counts() {
        let mut memory = CaseMemory::in_memory();
        feed(&mut memory, "x", Outcome::Inconclusive, op("a"), 20, 0);
        assert!(memory.estimate("x").is_none());
    }

    #[test]
    fn posterior_mean_and_interval_are_consistent() {
        let mut memory = CaseMemory::in_memory();
        feed(&mut memory, "x", Outcome::Confirmed, op("a"), 9, 0);
        feed(&mut memory, "x", Outcome::Refuted, op("a"), 1, 60);
        let e = memory.estimate("x").unwrap();
        assert!((e.probability - 10.0 / 12.0).abs() < 1e-12);
        assert!(e.lo95 < e.probability && e.probability < e.hi95);
        assert_eq!(e.effective_cases, 10.0);
        assert_eq!(e.distinct_sources, 1);
    }

    // --- poisoning guard ---

    #[test]
    fn rate_limit_quarantines_excess_records_from_one_source() {
        let mut memory = CaseMemory::in_memory();
        let source = op("spammer");
        let mut quarantined = 0;
        for i in 0..40 {
            // vsech 40 behem jedne hodiny (po 1 minute)
            let outcome = memory.record(rec("x", Outcome::Confirmed, source.clone(), i));
            if outcome == RecordOutcome::Quarantined(QuarantineReason::RateLimited) {
                quarantined += 1;
            }
        }
        assert_eq!(quarantined, 10, "30 projde, 10 nadlimitnich");
        assert_eq!(memory.quarantine_list().len(), 10);
        // Po hodine se okno uvolni.
        assert_eq!(
            memory.record(rec("x", Outcome::Confirmed, source, 200)),
            RecordOutcome::Accepted
        );
    }

    #[test]
    fn contradiction_attack_against_robust_consensus_is_quarantined_and_flags_source() {
        let mut memory = CaseMemory::in_memory();
        feed(&mut memory, "x", Outcome::Confirmed, op("honest"), 12, 0);
        let attacker = op("attacker");
        let results: Vec<RecordOutcome> = (0..5)
            .map(|i| memory.record(rec("x", Outcome::Refuted, attacker.clone(), 500 + i)))
            .collect();
        assert!(
            results.contains(&RecordOutcome::Quarantined(QuarantineReason::Contradiction)),
            "{results:?}"
        );
        assert!(memory.flagged_sources().contains("operator:attacker"));
        // Po oznaceni se karantenuje vse z toho zdroje.
        assert_eq!(
            memory.record(rec("x", Outcome::Confirmed, attacker, 900)),
            RecordOutcome::Quarantined(QuarantineReason::SourceFlagged)
        );
        let e = memory.estimate("x").unwrap();
        assert!(
            e.probability > 0.8,
            "konsenzus prezil utok: {}",
            e.probability
        );
        // Drive akceptovane utocnikovy zaznamy proti konsenzu se zpetne karantenuji.
        assert_eq!(memory.accepted_len(), 12);
    }

    #[test]
    fn honest_occasional_disagreement_is_not_flagged() {
        let mut memory = CaseMemory::in_memory();
        feed(&mut memory, "x", Outcome::Confirmed, op("honest"), 12, 0);
        let other = op("careful");
        feed(&mut memory, "x", Outcome::Confirmed, other.clone(), 3, 400);
        // jediny nesouhlas z 4 zaznamu = 25 %, pod prahem.
        assert_eq!(
            memory.record(rec("x", Outcome::Refuted, other, 600)),
            RecordOutcome::Accepted
        );
        assert!(memory.flagged_sources().is_empty());
    }

    #[test]
    fn late_joining_source_is_capped_at_half_of_effective_weight() {
        let mut memory = CaseMemory::in_memory();
        feed(&mut memory, "x", Outcome::Confirmed, op("founder"), 10, 0);
        let late = op("late");
        // Pozdni zdroj muze pridat jen tolik, aby nepresahl 50 %: 10 vs 10.
        let mut accepted = 0;
        let mut capped = 0;
        for i in 0..20 {
            // stridavy vysledek, aby nespustil kontradikcni guard (konsenzus = potvrzeno,
            // ale mean 11/12 > .85 -> potvrzujici zaznamy nejsou kontradikce)
            match memory.record(rec("x", Outcome::Confirmed, late.clone(), 1000 + i * 5)) {
                RecordOutcome::Accepted => accepted += 1,
                RecordOutcome::Quarantined(QuarantineReason::SourceCap) => capped += 1,
                other => panic!("necekany vysledek {other:?}"),
            }
        }
        assert_eq!(accepted, 10);
        assert_eq!(capped, 10);
        // Zakladajici zdroj neni omezen.
        assert_eq!(
            memory.record(rec("x", Outcome::Confirmed, op("founder"), 3000)),
            RecordOutcome::Accepted
        );
    }

    #[test]
    fn single_source_type_is_not_blocked_by_source_cap() {
        let mut memory = CaseMemory::in_memory();
        // 25 zaznamu z jedineho zdroje pres vice hodin (aby nebyl rate limit).
        for i in 0..25 {
            assert_eq!(
                memory.record(rec("x", Outcome::Confirmed, op("only"), i * 70)),
                RecordOutcome::Accepted
            );
        }
        assert_eq!(memory.estimate("x").unwrap().distinct_sources, 1);
    }

    #[test]
    fn invalid_weight_is_quarantined_and_weight_is_clamped() {
        let mut memory = CaseMemory::in_memory();
        let mut bad = rec("x", Outcome::Confirmed, op("a"), 0);
        bad.weight = f64::NAN;
        assert_eq!(
            memory.record(bad),
            RecordOutcome::Quarantined(QuarantineReason::InvalidWeight)
        );
        let mut big = rec("x", Outcome::Confirmed, op("a"), 1);
        big.weight = 50.0;
        assert_eq!(memory.record(big), RecordOutcome::Accepted);
        assert_eq!(memory.effective_weights("x").0, 1.0);
    }

    // --- persistence ---

    #[test]
    fn version_is_monotonic_and_survives_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("case-memory.json");
        let mut memory = CaseMemory::load_or_default(&path);
        assert_eq!(memory.version(), 0);
        memory.record(rec("x", Outcome::Confirmed, op("a"), 0));
        memory.record(rec("x", Outcome::Refuted, op("a"), 5));
        memory.save().unwrap();
        let reloaded = CaseMemory::load_or_default(&path);
        assert_eq!(reloaded.version(), 2);
        assert_eq!(reloaded.accepted_len(), 2);
    }

    #[test]
    fn corrupt_file_means_empty_memory_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("case-memory.json");
        fs::write(&path, "{ not json").unwrap();
        assert_eq!(CaseMemory::load_or_default(&path).version(), 0);
    }

    #[test]
    fn only_last_20_snapshots_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("case-memory.json");
        let mut memory = CaseMemory::load_or_default(&path);
        for i in 0..30 {
            memory.record(rec("x", Outcome::Confirmed, op("a"), i * 70));
            memory.save().unwrap();
        }
        let snapshots = fs::read_dir(dir.path().join("case-memory"))
            .unwrap()
            .count();
        assert_eq!(snapshots, SNAPSHOTS_KEPT);
        assert!(dir.path().join("case-memory").join("v30.json").exists());
        assert!(!dir.path().join("case-memory").join("v1.json").exists());
    }

    #[test]
    fn rollback_restores_old_content_under_a_new_higher_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("case-memory.json");
        let mut memory = CaseMemory::load_or_default(&path);
        for i in 0..3 {
            memory.record(rec("x", Outcome::Confirmed, op("a"), i * 70));
        }
        memory.save().unwrap(); // v3
        for i in 3..6 {
            memory.record(rec("x", Outcome::Refuted, op("a"), i * 70));
        }
        memory.save().unwrap(); // v6
        assert_eq!(memory.accepted_len(), 6);
        memory.rollback_to(3).unwrap();
        assert_eq!(memory.accepted_len(), 3);
        assert_eq!(memory.version(), 7, "verze nikdy neklesa");
        assert!(memory.rollback_to(999).is_err());
    }

    #[test]
    fn update_helper_serialises_concurrent_writers_without_losing_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("case-memory.json");
        std::thread::scope(|scope| {
            for worker in 0..6 {
                let path = path.clone();
                scope.spawn(move || {
                    for i in 0..5 {
                        CaseMemory::update(&path, |memory| {
                            memory.record(rec(
                                "x",
                                Outcome::Confirmed,
                                op(&format!("w{worker}")),
                                (worker * 5 + i) as i64 * 70,
                            ));
                        })
                        .unwrap();
                    }
                });
            }
        });
        let memory = CaseMemory::load_or_default(&path);
        assert_eq!(memory.accepted_len() + memory.quarantine_list().len(), 30);
        assert_eq!(memory.version(), 30);
    }

    // --- mapovani vysledku overeni ---

    fn result(ft: &str, method: &str, status: &str, outcome: Option<&str>) -> VerificationResult {
        VerificationResult {
            hypothesis_type: ft.to_string(),
            method: method.to_string(),
            asset: "192.168.1.5".to_string(),
            status: status.to_string(),
            outcome: outcome.map(ToString::to_string),
            runtime_ms: 10,
        }
    }

    #[test]
    fn inspection_with_http_below_400_confirms_exposure() {
        let r = result(
            "management_surface_exposure",
            "read_only_content_inspection",
            "executed",
            Some("GET http://192.168.1.5:80/ -> 200, server: nginx, 120 B"),
        );
        let case = case_from_verification_result(&r, t0()).unwrap();
        assert_eq!(case.outcome, Outcome::Confirmed);
        assert_eq!(case.weight, VERIFICATION_WEIGHT);
    }

    #[test]
    fn inspection_with_only_errors_or_4xx_refutes_exposure() {
        let r = result(
            "plaintext_management_protocol",
            "read_only_content_inspection",
            "executed",
            Some(
                "GET http://192.168.1.5:80/ -> 404, server: -, 0 B; GET https://192.168.1.5:443/ selhal: timeout",
            ),
        );
        assert_eq!(
            case_from_verification_result(&r, t0()).unwrap().outcome,
            Outcome::Refuted
        );
        let no_port = result(
            "new_exposed_service",
            "read_only_content_inspection",
            "failed",
            Some("192.168.1.5 nema otevreny webovy port k inspekci"),
        );
        assert_eq!(
            case_from_verification_result(&no_port, t0())
                .unwrap()
                .outcome,
            Outcome::Refuted
        );
    }

    #[test]
    fn inspection_on_non_exposure_hypothesis_is_not_recorded() {
        let r = result(
            "unexpected_traffic",
            "read_only_content_inspection",
            "executed",
            Some("GET http://192.168.1.5:80/ -> 200, server: x, 1 B"),
        );
        assert!(case_from_verification_result(&r, t0()).is_none());
    }

    #[test]
    fn cve_relookup_maps_high_cvss_to_confirmed_and_zero_to_refuted() {
        let high = result(
            "high_risk_cve_exposure",
            "cve_intel_relookup",
            "executed",
            Some("3 CVE zaznamu z lokalni intel cache, nejvyssi CVSS 9.8, s exploit kontextem: 1"),
        );
        assert_eq!(
            case_from_verification_result(&high, t0()).unwrap().outcome,
            Outcome::Confirmed
        );
        let none = result(
            "high_risk_cve_exposure",
            "cve_intel_relookup",
            "executed",
            Some("0 CVE zaznamu z lokalni intel cache, nejvyssi CVSS 0.0, s exploit kontextem: 0"),
        );
        assert_eq!(
            case_from_verification_result(&none, t0()).unwrap().outcome,
            Outcome::Refuted
        );
        let low = result(
            "high_risk_cve_exposure",
            "cve_intel_relookup",
            "executed",
            Some("2 CVE zaznamu z lokalni intel cache, nejvyssi CVSS 5.0, s exploit kontextem: 0"),
        );
        assert!(
            case_from_verification_result(&low, t0()).is_none(),
            "nejednoznacne"
        );
    }

    #[test]
    fn reused_needs_approval_skipped_and_unknown_methods_are_never_recorded() {
        for status in [
            "reused",
            "needs_approval",
            "skipped_budget",
            "skipped_out_of_scope",
        ] {
            let r = result(
                "management_surface_exposure",
                "read_only_content_inspection",
                status,
                Some("GET http://x -> 200, a, 1 B"),
            );
            assert!(
                case_from_verification_result(&r, t0()).is_none(),
                "{status}"
            );
        }
        let passive = result(
            "unexpected_traffic",
            "passive_extended_observation",
            "executed",
            Some("bez aktivniho kroku"),
        );
        assert!(case_from_verification_result(&passive, t0()).is_none());
    }
}
