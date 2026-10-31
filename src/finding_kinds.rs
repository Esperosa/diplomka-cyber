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

/// Nalezy odvozene z CVE/KEV/EPSS kontextu navazanych na sluzbu.
pub const CVE_LIKE: &[&str] = &[
    "high_risk_cve_exposure",
    "known_exploited_vulnerability",
    "probable_exploitation_interest",
];

pub fn is_cve_like(finding_type: &str) -> bool {
    CVE_LIKE.contains(&finding_type)
}

/// Nalezy o nesifrovane autentizaci/sprave (telnet/ftp/HTTP Basic bez TLS).
pub const PLAINTEXT_LIKE: &[&str] = &["plaintext_management_protocol", "http_basic_without_tls"];

pub fn is_plaintext_like(finding_type: &str) -> bool {
    PLAINTEXT_LIKE.contains(&finding_type)
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
        for list in [TRAFFIC_LIKE, CVE_LIKE, PLAINTEXT_LIKE] {
            let mut sorted = list.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), list.len());
        }
    }

    #[test]
    fn categories_are_disjoint() {
        for kind in CVE_LIKE {
            assert!(!is_traffic_like(kind) && !is_plaintext_like(kind));
        }
        for kind in PLAINTEXT_LIKE {
            assert!(!is_traffic_like(kind) && !is_cve_like(kind));
        }
    }

    #[test]
    fn cve_and_plaintext_helpers_match_their_lists() {
        assert!(is_cve_like("known_exploited_vulnerability"));
        assert!(!is_cve_like("unexpected_traffic"));
        assert!(is_plaintext_like("http_basic_without_tls"));
        assert!(!is_plaintext_like("insecure_auth_possible"));
    }
}
