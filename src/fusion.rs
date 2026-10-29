//! Deliverable 27 (H2 krok 3, `docs/diplomka/produkcni-plan.md`): dependency-aware
//! evidence fusion. Implementuje literalni H2 claim (navrh sekce 5.1): "stejny tok
//! pozorovany Suricatou, Zeekem a firewallem nejsou tri nezavisle dukazy."
//!
//! Evidence se stejnym `community_id` (Deliverable 25/26) pochazi ze stejneho
//! fyzickeho toku - sloucena na JEDNU polozku (MAX skore mezi senzory, ne SOUCET),
//! protoze dalsi senzor potvrzujici uz zachyceny tok neprinasi nezavislou informaci.
//! Evidence BEZ spolecneho `community_id` (ruzne toky, nebo chybejici join-key) se
//! pocita jako nezavisla a jeji skore se SCITAJI - presne naopak nez u zavisle
//! evidence, a presne ten rozdil je cely obsah H2 claim.
//!
//! `#![allow(dead_code)]`: fuzni logika je hotova a testovana (overuje presne tu
//! vlastnost, co H2 claim tvrdi), ale jeste nezapojena do `correlation_v2.rs`/
//! `decision.rs` - zapojeni do produkcniho rozhodovaciho kodu a re-validace ablaci
//! B/C/E na dual-sensor datech (Suricata+Zeek na stejnem labu) je dalsi, samostatny
//! krok (produkcni-plan.md, Faze 2).
#![allow(dead_code)]

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub(crate) struct EvidenceItem {
    pub(crate) community_id: Option<String>,
    pub(crate) sensor: String,
    pub(crate) score: f64,
}

#[derive(Debug, Clone)]
pub(crate) struct FusedEvidence {
    pub(crate) community_id: Option<String>,
    pub(crate) combined_score: f64,
    pub(crate) contributing_sensors: Vec<String>,
}

/// Naivni fuze: kazda polozka evidence se pocita jako nezavisla, skore se scitaji.
/// Tohle je presne to, co "prosty scoring eventu" (H2's protiklad) dela - zadna
/// korekce zavislosti zdrojů.
pub(crate) fn naive_independent_sum(items: &[EvidenceItem]) -> f64 {
    items.iter().map(|item| item.score).sum()
}

/// Dependency-aware fuze: evidence se stejnym `community_id` (stejny fyzicky tok)
/// se slouci do jedne polozky (MAX skore, ne SOUCET) - dalsi senzor potvrzujici uz
/// zachyceny tok neprinasi nezavislou informaci, i kdyz ma vlastni, jinak vypadajici
/// skore. Evidence bez `community_id` (ruzne toky nebo chybejici join-key) zustava
/// samostatna - zadny zaklad pro tvrzeni zavislosti bez spolecneho klice.
pub(crate) fn dependency_corrected_fusion(items: &[EvidenceItem]) -> Vec<FusedEvidence> {
    let mut grouped: HashMap<String, Vec<&EvidenceItem>> = HashMap::new();
    let mut independent: Vec<FusedEvidence> = Vec::new();

    for item in items {
        match &item.community_id {
            Some(id) => grouped.entry(id.clone()).or_default().push(item),
            None => independent.push(FusedEvidence {
                community_id: None,
                combined_score: item.score,
                contributing_sensors: vec![item.sensor.clone()],
            }),
        }
    }

    let mut fused: Vec<FusedEvidence> = grouped
        .into_iter()
        .map(|(community_id, group)| {
            let combined_score = group.iter().map(|item| item.score).fold(0.0_f64, f64::max);
            FusedEvidence {
                community_id: Some(community_id),
                combined_score,
                contributing_sensors: group.iter().map(|item| item.sensor.clone()).collect(),
            }
        })
        .collect();

    fused.extend(independent);
    fused
}

/// Souhrnne skore pro rozhodovani (secte vsechny FUZOVANE polozky) - pro srovnani s
/// `naive_independent_sum` na stejnem vstupu.
pub(crate) fn fused_total_score(fused: &[FusedEvidence]) -> f64 {
    fused.iter().map(|item| item.combined_score).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(community_id: Option<&str>, sensor: &str, score: f64) -> EvidenceItem {
        EvidenceItem {
            community_id: community_id.map(ToString::to_string),
            sensor: sensor.to_string(),
            score,
        }
    }

    /// Presne ten pripad, co H2 claim popisuje: 2 senzory (Zeek+Suricata) vidi
    /// STEJNY tok (stejne community_id) - naivni scoring by to spocital jako 2
    /// nezavisle potvrzeni (soucet 1.4), dependency-corrected fuze to spravne pozna
    /// jako 1 fyzicky tok (MAX 0.8, ne soucet).
    #[test]
    fn same_flow_from_two_sensors_is_not_double_counted() {
        let items = vec![
            item(Some("1:abc"), "zeek", 0.6),
            item(Some("1:abc"), "suricata", 0.8),
        ];

        let naive = naive_independent_sum(&items);
        assert!((naive - 1.4).abs() < 1e-9, "naivni soucet: {naive}");

        let fused = dependency_corrected_fusion(&items);
        assert_eq!(
            fused.len(),
            1,
            "stejne community_id musi dat JEDNU fuzovanou polozku"
        );
        let corrected = fused_total_score(&fused);
        assert!(
            (corrected - 0.8).abs() < 1e-9,
            "korigovane skore: {corrected}"
        );
        assert!(
            corrected < naive,
            "korigovane skore ({corrected}) musi byt nizsi nez naivni soucet ({naive}) - presne ten rozdil je H2 claim"
        );
    }

    /// Opacny pripad: 2 ruzne toky (ruzne community_id) jsou skutecne nezavisla
    /// evidence - tady se SPRAVNE scita, dependency-corrected fuze nesmi zbytecne
    /// snizovat skore, kde zavislost neexistuje.
    #[test]
    fn different_flows_remain_independent_and_scores_sum() {
        let items = vec![
            item(Some("1:abc"), "zeek", 0.6),
            item(Some("1:xyz"), "zeek", 0.5),
        ];

        let naive = naive_independent_sum(&items);
        let fused = dependency_corrected_fusion(&items);
        assert_eq!(
            fused.len(),
            2,
            "2 ruzne toky musi zustat 2 samostatne polozky"
        );
        let corrected = fused_total_score(&fused);
        assert!(
            (corrected - naive).abs() < 1e-9,
            "u skutecne nezavisle evidence (ruzne toky) se korigovane a naivni skore musi shodovat: corrected={corrected} naive={naive}"
        );
    }

    /// Evidence bez community_id (napr. aktivni sken bez prirazeneho toku) nesmi
    /// byt tise slucovana s jinou evidenci bez community_id, jako by sly o stejny
    /// tok - to by byla NOVA, horsi chyba (falesna zavislost tam, kde neni zadny
    /// zaklad to tvrdit).
    #[test]
    fn evidence_without_community_id_never_merges_with_other_unlabeled_evidence() {
        let items = vec![
            item(None, "active-scan", 0.3),
            item(None, "active-scan", 0.4),
        ];
        let fused = dependency_corrected_fusion(&items);
        assert_eq!(
            fused.len(),
            2,
            "evidence bez community_id musi zustat samostatna, ne se tise slucovat"
        );
    }

    #[test]
    fn three_sensors_on_same_flow_still_cap_at_max_not_sum() {
        let items = vec![
            item(Some("1:abc"), "zeek", 0.3),
            item(Some("1:abc"), "suricata", 0.5),
            item(Some("1:abc"), "active-scan", 0.9),
        ];
        let fused = dependency_corrected_fusion(&items);
        assert_eq!(fused.len(), 1);
        assert!((fused[0].combined_score - 0.9).abs() < 1e-9);
        assert_eq!(fused[0].contributing_sensors.len(), 3);
    }
}
