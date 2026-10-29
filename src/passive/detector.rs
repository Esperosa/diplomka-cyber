//! Fáze 2 (produkční plán, framework-style wiring): sjednocuje ablace A/B/C/D
//! (`passive::anomaly::detect_connection_anomalies`,
//! `correlation_v2::detect_windowed_anomalies[_linked]`,
//! `correlation_v2::detect_multiscale_windowed_anomalies`) za jeden trait
//! místo toho, aby produkce (`load_and_normalize`) a eval
//! (`eval::dataset_replay::run_ablation`) volaly ty samé funkce odděleně,
//! dvěma různými cestami. Teď je to doslova STEJNÁ implementace na obou
//! místech - žádná z ablací B/C/D se tímhle nestává produkčním výchozím
//! chováním (to zůstává `LegacyAnomalyDetector`, ablace A), jen se zavádí
//! společné rozhraní, přes které by se to dalo bezpečně přepnout, až to bude
//! podložené měřením.

use std::collections::HashSet;

use crate::model::NormalizedEvent;

use super::ConnectionObservation;

type ServiceKey = (String, String, u16);

pub(crate) trait ConnectionDetector {
    /// Zatim nepouzite v produkcnim/eval kodu (jen v testech nize) - stejny
    /// vzor jako `eval::source::ScenarioSource::id()`, pripraveno pro
    /// budouci logovani/registry dispatch, az se detektor bude vybirat
    /// za behu, ne natvrdo konstruovat v kazdem volacim miste.
    #[allow(dead_code)]
    fn id(&self) -> &'static str;
    fn detect(
        &self,
        connections: Vec<ConnectionObservation>,
        known_services: &HashSet<ServiceKey>,
    ) -> Vec<NormalizedEvent>;
}

/// Ablace A - nezměněný produkční výchozí detektor dnes.
pub(crate) struct LegacyAnomalyDetector;

impl ConnectionDetector for LegacyAnomalyDetector {
    fn id(&self) -> &'static str {
        "a-legacy"
    }

    fn detect(
        &self,
        connections: Vec<ConnectionObservation>,
        known_services: &HashSet<ServiceKey>,
    ) -> Vec<NormalizedEvent> {
        super::anomaly::detect_connection_anomalies(connections, known_services)
    }
}

/// Ablace B - tumbling okna, `time_window_s` je konfigurace detektoru, ne
/// argument volaný při každém `detect()`.
pub(crate) struct WindowedDetector {
    pub(crate) time_window_s: i64,
}

impl ConnectionDetector for WindowedDetector {
    fn id(&self) -> &'static str {
        "b-windowed"
    }

    fn detect(
        &self,
        connections: Vec<ConnectionObservation>,
        known_services: &HashSet<ServiceKey>,
    ) -> Vec<NormalizedEvent> {
        crate::correlation_v2::detect_windowed_anomalies(
            connections,
            known_services,
            self.time_window_s,
        )
    }
}

/// Ablace C - tumbling okna + graph-linking stejného `src_ip` napříč cíli.
pub(crate) struct LinkedDetector {
    pub(crate) time_window_s: i64,
}

impl ConnectionDetector for LinkedDetector {
    fn id(&self) -> &'static str {
        "c-linked"
    }

    fn detect(
        &self,
        connections: Vec<ConnectionObservation>,
        known_services: &HashSet<ServiceKey>,
    ) -> Vec<NormalizedEvent> {
        crate::correlation_v2::detect_windowed_anomalies_linked(
            connections,
            known_services,
            self.time_window_s,
        )
    }
}

/// Ablace D - sjednocení více škál oken (fragmentační hypotéza).
pub(crate) struct MultiscaleDetector {
    pub(crate) window_scales: Vec<i64>,
}

impl ConnectionDetector for MultiscaleDetector {
    fn id(&self) -> &'static str {
        "d-multiscale"
    }

    fn detect(
        &self,
        connections: Vec<ConnectionObservation>,
        known_services: &HashSet<ServiceKey>,
    ) -> Vec<NormalizedEvent> {
        crate::correlation_v2::detect_multiscale_windowed_anomalies(
            connections,
            known_services,
            &self.window_scales,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection_at(dst_ip: &str, proto: &str, port: u16) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: chrono::Utc::now(),
            src_ip: Some("10.0.0.1".to_string()),
            src_port: Some(1234),
            dst_ip: dst_ip.to_string(),
            proto: proto.to_string(),
            dst_port: Some(port),
            conn_state: None,
            history: None,
            duration_s: Some(1.0),
            orig_pkts: Some(1),
            resp_pkts: Some(1),
            orig_bytes: Some(100),
            resp_bytes: Some(100),
            total_pkts: None,
            total_bytes: None,
            missed_bytes: None,
        }
    }

    /// Regresní pojistka na samotné sjednocení (Deliverable "Fáze 2 detektor
    /// trait"): `LegacyAnomalyDetector::detect` musí vracet BAJTOVĚ stejný
    /// výsledek jako přímé volání `detect_connection_anomalies` - jinak by
    /// trait wrapper tiše změnil produkční chování.
    #[test]
    fn legacy_detector_matches_direct_function_call() {
        let connections = vec![
            connection_at("10.0.0.5", "tcp", 4444),
            connection_at("10.0.0.5", "tcp", 4444),
            connection_at("10.0.0.5", "tcp", 4444),
        ];
        let known_services = HashSet::new();

        let via_trait = LegacyAnomalyDetector.detect(connections.clone(), &known_services);
        let direct =
            super::super::anomaly::detect_connection_anomalies(connections, &known_services);

        assert_eq!(via_trait.len(), direct.len());
        for (left, right) in via_trait.iter().zip(direct.iter()) {
            assert_eq!(left.event_id, right.event_id);
            assert_eq!(left.event_type, right.event_type);
        }
        assert!(
            !via_trait.is_empty(),
            "test fixture musi skutecne vyprodukovat nejaky event, jinak srovnani nic nerika"
        );
    }

    #[test]
    fn each_detector_reports_its_own_id() {
        assert_eq!(LegacyAnomalyDetector.id(), "a-legacy");
        assert_eq!(WindowedDetector { time_window_s: 300 }.id(), "b-windowed");
        assert_eq!(LinkedDetector { time_window_s: 300 }.id(), "c-linked");
        assert_eq!(
            MultiscaleDetector {
                window_scales: vec![60, 300]
            }
            .id(),
            "d-multiscale"
        );
    }
}
