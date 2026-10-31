//! Jeden zdroj pravdy pro kategorie typu nalezu. Driv byl seznam 7 "traffic-like"
//! typu doslovne opsany na 6 mistech (`decision.rs` x2, `triage.rs`,
//! `validation.rs`, `intel.rs` x2) a uz jednou se rozesel (triage.rs pokryvalo
//! jen 3 ze 7). Pridani noveho typu ted znamena zmenu na jednom miste.

/// Nalezy popisujici anomalii v provozu (objem, rychlost, timeouty, ztraty).
pub const TRAFFIC_LIKE: &[&str] = &[
    "unexpected_traffic",
    "external_flow_observed",
    "connection_timeout_burst",
    "packet_rate_spike",
    "packet_loss_signal",
    "service_overload_risk",
    "inductive_volume_anomaly",
];

pub fn is_traffic_like(finding_type: &str) -> bool {
    TRAFFIC_LIKE.contains(&finding_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_recognises_every_traffic_type_and_nothing_else() {
        for kind in TRAFFIC_LIKE {
            assert!(is_traffic_like(kind));
        }
        assert!(!is_traffic_like("plaintext_management_protocol"));
        assert!(!is_traffic_like(""));
    }

    #[test]
    fn registry_has_no_duplicates() {
        let mut sorted = TRAFFIC_LIKE.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), TRAFFIC_LIKE.len());
    }
}
