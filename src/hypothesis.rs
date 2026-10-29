//! Typovana nejistota a `SecurityHypothesis` (Deliverable 4), navazuje na Deliverable 2
//! (`identity.rs`) a Deliverable 3 (`correlation_v2.rs`). Zije VEDLE `decision.rs` - nic
//! v `rank_finding`/`RankedDecision` se nemeni, tohle je doplnkova obohacovaci vrstva nad
//! existujicim `Finding`.
//!
//! Navrhovy dokument (sekce 5.3) chce rozlisit 6 typu nejistoty (aleatoricka,
//! epistemicka, identity, observation, state, interpretation) misto jedineho
//! `Confidence` enum, a explicitne zakazuje smesovat duveru v identitu s
//! pravdepodobnosti kompromitace: "pokud nejsou odhady kalibrovane, radeji vracet
//! ordinalni skore nez falesne presne procento."
//!
//! **Co tento modul NEDELA:** nepocita `aleatoric`/`epistemic`/`interpretation`
//! nejistotu (zustavaji `None`) - vyzadovaly by historickou baseline/Case Memory
//! (navrh sekce 5.6), ktera v systemu jeste neexistuje. `probability` je VZDY `None` -
//! zadny placeholder odvozeny z `Confidence::weight()`, protoze by to jen presunulo
//! presne ten problem, ktery navrh zakazuje, o jednu vrstvu dal. Napojeni na
//! `decision.rs::rank_finding` (nahrazeni ad-hoc scoringu) je navazujici krok, ne tento.

use crate::identity::IdentityMatch;
use crate::model::{Confidence, CorrelationInfo, Finding, InventoryRecord, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UncertaintyKind {
    /// Prirozena promenlivost provozu (noise, fluktuace) - v tomto kroku nepocitano.
    Aleatoric,
    /// Neznalost/nezjistene informace, kterou lze snizit dalsi kontrolou - v tomto
    /// kroku nepocitano (vyzaduje Verification Planner, navazujici krok).
    Epistemic,
    /// Ktera fyzicka/logicka entita udalost vytvorila - odvozeno z `IdentityMatch`.
    Identity,
    /// Spolehlivost/coverage/presnost korelace eventu k assetu - odvozeno z
    /// `Confidence`/`CorrelationInfo.method`.
    Observation,
    /// Verze sluzby, konfigurace, skutecna zranitelnost - odvozeno z `InventoryRecord`.
    State,
    /// Jestli indikator znamena utok, administraci nebo normalni provoz - v tomto
    /// kroku nepocitano (vyzaduje historickou baseline, navazujici krok).
    Interpretation,
}

/// NE `BTreeMap<UncertaintyKind, f64>` - explicitni `Option<f64>` pole vynucuji na
/// volajicim rozhodnuti pro kazdy typ zvlast (`match`/`unwrap_or`), zatimco chybejici
/// klic v mape by vypadal identicky jako "zamerne nepocitano" i jako "zapomenuto".
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TypedUncertainty {
    pub aleatoric: Option<f64>,
    pub epistemic: Option<f64>,
    pub identity: Option<f64>,
    pub observation: Option<f64>,
    pub state: Option<f64>,
    pub interpretation: Option<f64>,
}

impl TypedUncertainty {
    pub fn get(&self, kind: UncertaintyKind) -> Option<f64> {
        match kind {
            UncertaintyKind::Aleatoric => self.aleatoric,
            UncertaintyKind::Epistemic => self.epistemic,
            UncertaintyKind::Identity => self.identity,
            UncertaintyKind::Observation => self.observation,
            UncertaintyKind::State => self.state,
            UncertaintyKind::Interpretation => self.interpretation,
        }
    }

    pub fn known_kinds(&self) -> Vec<UncertaintyKind> {
        [
            UncertaintyKind::Aleatoric,
            UncertaintyKind::Epistemic,
            UncertaintyKind::Identity,
            UncertaintyKind::Observation,
            UncertaintyKind::State,
            UncertaintyKind::Interpretation,
        ]
        .into_iter()
        .filter(|kind| self.get(*kind).is_some())
        .collect()
    }
}

#[derive(Debug, Clone)]
pub struct SecurityHypothesis {
    pub affected_assets: Vec<String>,
    pub hypothesis_type: String,
    pub supporting_evidence: Vec<String>,
    /// Zadny mechanismus na detekci rozporujicich dukazu dnes neexistuje - vzdy
    /// prazdne, dokud nebude Case Memory (navrh sekce 5.6).
    pub contradicting_evidence: Vec<String>,
    /// VZDY `None` v tomto kroku - viz modulova dokumentace.
    pub probability: Option<f64>,
    pub uncertainty: TypedUncertainty,
    pub potential_impact: f64,
    pub model_version: String,
}

/// `correlation`/`identity`/`inventory` jsou `Option`, protoze ne kazdy `Finding` ma
/// vsechny tyto signaly dostupne (napr. ablace B/C z `correlation_v2.rs` dnes
/// neprodukuji `CorrelationInfo`; ne kazdy finding ma spojenou `InventoryRecord`).
pub fn build_hypothesis(
    finding: &Finding,
    correlation: Option<&CorrelationInfo>,
    identity: Option<&IdentityMatch>,
    inventory: Option<&InventoryRecord>,
) -> SecurityHypothesis {
    let identity_uncertainty = identity.map(|identity_match| match identity_match {
        IdentityMatch::Same(_) => 0.1,
        IdentityMatch::New(_) => 0.5,
        IdentityMatch::Ambiguous { .. } => 0.85,
    });

    // "unmapped" korelace znamena, ze nevime, ktery asset to vubec je - to je horsi
    // nez jen nizka Confidence na znamem assetu, proto prebiji vychozi mapovani.
    let observation_uncertainty = Some(
        if correlation.map(|info| info.method.as_str()) == Some("unmapped") {
            0.95
        } else {
            match finding.confidence {
                Confidence::High => 0.15,
                Confidence::Medium => 0.45,
                Confidence::Low => 0.8,
            }
        },
    );

    let state_uncertainty = inventory.map(|record| match (&record.version, record.confidence) {
        (Some(_), Confidence::High) => 0.15,
        (Some(_), Confidence::Medium) => 0.45,
        _ => 0.8,
    });

    let uncertainty = TypedUncertainty {
        identity: identity_uncertainty,
        observation: observation_uncertainty,
        state: state_uncertainty,
        ..Default::default()
    };

    let potential_impact = match finding.severity {
        Severity::High => 0.9,
        Severity::Medium => 0.5,
        Severity::Low => 0.2,
    };

    SecurityHypothesis {
        affected_assets: finding.host_key.clone().into_iter().collect(),
        hypothesis_type: finding.finding_type.clone(),
        supporting_evidence: finding.evidence.clone(),
        contradicting_evidence: Vec::new(),
        probability: None,
        uncertainty,
        potential_impact,
        model_version: "hypothesis-v0-heuristic".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(confidence: Confidence, severity: Severity) -> Finding {
        Finding {
            finding_id: "finding:test:1".to_string(),
            finding_type: "unexpected_traffic".to_string(),
            title: "test finding".to_string(),
            severity,
            confidence,
            host_key: Some("10.0.0.1".to_string()),
            service_key: None,
            rationale: "test".to_string(),
            evidence: vec!["evidence:1".to_string()],
            recommendation: "test".to_string(),
        }
    }

    fn correlation(method: &str) -> CorrelationInfo {
        CorrelationInfo {
            method: method.to_string(),
            confidence: Confidence::High,
            time_window_s: 300,
            host_id: Some("host:1".to_string()),
            service_id: None,
        }
    }

    fn inventory(version: Option<&str>, confidence: Confidence) -> InventoryRecord {
        InventoryRecord {
            service_name: "http".to_string(),
            product: None,
            version: version.map(ToString::to_string),
            extrainfo: None,
            detection_source: "nmap".to_string(),
            confidence,
        }
    }

    #[test]
    fn identity_uncertainty_tracks_identity_match_variant() {
        let f = finding(Confidence::High, Severity::Low);

        let same = build_hypothesis(
            &f,
            None,
            Some(&IdentityMatch::Same("asset:1".to_string())),
            None,
        );
        let new = build_hypothesis(
            &f,
            None,
            Some(&IdentityMatch::New("asset:2".to_string())),
            None,
        );
        let ambiguous = build_hypothesis(
            &f,
            None,
            Some(&IdentityMatch::Ambiguous {
                candidate: "asset:1".to_string(),
                reason: "test".to_string(),
            }),
            None,
        );
        let unknown = build_hypothesis(&f, None, None, None);

        assert!(same.uncertainty.identity.unwrap() < new.uncertainty.identity.unwrap());
        assert!(new.uncertainty.identity.unwrap() < ambiguous.uncertainty.identity.unwrap());
        assert_eq!(unknown.uncertainty.identity, None);
    }

    #[test]
    fn observation_uncertainty_tracks_confidence_and_unmapped_correlation() {
        let high = build_hypothesis(&finding(Confidence::High, Severity::Low), None, None, None);
        let low = build_hypothesis(&finding(Confidence::Low, Severity::Low), None, None, None);
        assert!(high.uncertainty.observation.unwrap() < low.uncertainty.observation.unwrap());

        // "unmapped" prebiji i vysokou Confidence - nevime, ktery asset to je.
        let unmapped = build_hypothesis(
            &finding(Confidence::High, Severity::Low),
            Some(&correlation("unmapped")),
            None,
            None,
        );
        assert!(unmapped.uncertainty.observation.unwrap() > high.uncertainty.observation.unwrap());
    }

    #[test]
    fn state_uncertainty_requires_confirmed_version_and_high_confidence() {
        let confirmed = build_hypothesis(
            &finding(Confidence::High, Severity::Low),
            None,
            None,
            Some(&inventory(Some("2.4.1"), Confidence::High)),
        );
        let no_version = build_hypothesis(
            &finding(Confidence::High, Severity::Low),
            None,
            None,
            Some(&inventory(None, Confidence::High)),
        );
        let unknown = build_hypothesis(&finding(Confidence::High, Severity::Low), None, None, None);

        assert!(confirmed.uncertainty.state.unwrap() < no_version.uncertainty.state.unwrap());
        assert_eq!(unknown.uncertainty.state, None);
    }

    #[test]
    fn aleatoric_epistemic_interpretation_and_probability_are_never_fabricated() {
        // Regresni test na dokumentovane omezeni - pokud tohle v budoucnu zacne padat,
        // je to ZAMERNA zmena (Case Memory implementovano), aktualizovat test a
        // modulovou dokumentaci soucasne, ne jen "opravit" test zpet na None.
        let hypothesis = build_hypothesis(
            &finding(Confidence::High, Severity::High),
            Some(&correlation("ip+port")),
            Some(&IdentityMatch::Same("asset:1".to_string())),
            Some(&inventory(Some("1.0"), Confidence::High)),
        );
        assert_eq!(hypothesis.uncertainty.aleatoric, None);
        assert_eq!(hypothesis.uncertainty.epistemic, None);
        assert_eq!(hypothesis.uncertainty.interpretation, None);
        assert_eq!(hypothesis.probability, None);
        assert!(hypothesis.contradicting_evidence.is_empty());
    }

    #[test]
    fn known_kinds_lists_only_populated_uncertainty_types() {
        let hypothesis = build_hypothesis(
            &finding(Confidence::Medium, Severity::Medium),
            None,
            Some(&IdentityMatch::New("asset:3".to_string())),
            None,
        );
        let known = hypothesis.uncertainty.known_kinds();
        assert!(known.contains(&UncertaintyKind::Identity));
        assert!(known.contains(&UncertaintyKind::Observation));
        assert!(!known.contains(&UncertaintyKind::State));
        assert!(!known.contains(&UncertaintyKind::Aleatoric));
    }
}
