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

/// Engine v3 (krok 1C): stavový detektor s historií klíčů a pokusů zdrojů. Stav
/// drží `Mutex` (detektor běží v paralelním kolektoru pipeline), po běhu se uloží
/// do `engine-state.sqlite`. `extra_known` = perzistentní inventář s hysterezí.
pub(crate) struct V3StatefulDetector {
    state: std::sync::Mutex<super::anomaly_v3::DetectorState>,
    sources: std::sync::Mutex<super::anomaly_v3::SourceMap>,
    switches: super::anomaly_v3::V3Switches,
    thresholds: super::anomaly_v3::V3Thresholds,
    extra_known: HashSet<ServiceKey>,
    known_hosts: HashSet<String>,
    now: chrono::DateTime<chrono::Utc>,
}

impl V3StatefulDetector {
    pub(crate) fn new(
        state: super::anomaly_v3::DetectorState,
        switches: super::anomaly_v3::V3Switches,
        extra_known: HashSet<ServiceKey>,
        known_hosts: HashSet<String>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        Self {
            state: std::sync::Mutex::new(state),
            sources: std::sync::Mutex::new(Default::default()),
            switches,
            thresholds: Default::default(),
            extra_known,
            known_hosts,
            now,
        }
    }

    /// Stav detektoru a dominantní zdroje posledního běhu.
    pub(crate) fn into_parts(
        self,
    ) -> (
        super::anomaly_v3::DetectorState,
        super::anomaly_v3::SourceMap,
    ) {
        (
            self.state.into_inner().unwrap_or_else(|p| p.into_inner()),
            self.sources.into_inner().unwrap_or_else(|p| p.into_inner()),
        )
    }
}

impl ConnectionDetector for V3StatefulDetector {
    fn id(&self) -> &'static str {
        "v3-baseline"
    }

    fn detect(
        &self,
        connections: Vec<ConnectionObservation>,
        known_services: &HashSet<ServiceKey>,
    ) -> Vec<NormalizedEvent> {
        let mut known = known_services.clone();
        known.extend(self.extra_known.iter().cloned());
        let mut hosts = self.known_hosts.clone();
        hosts.extend(known.iter().map(|key| key.0.clone()));
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let out = super::anomaly_v3::detect_v3(
            &connections,
            &known,
            &hosts,
            &mut state,
            self.switches,
            &self.thresholds,
            self.now,
        );
        *self.sources.lock().unwrap_or_else(|p| p.into_inner()) = out.sources;
        out.events
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

    /// Komplexnejsi fixtura nez trivialni "3 identicke spojeni" - vice zdroju,
    /// vice cilu, spojeni rozlozena pres nekolik tumbling oken (300s), jeden
    /// zdroj skenujici mnoho cilu (ma vyvolat multi_target_pattern v C), a
    /// timeout-like spojeni (S0) mix s normalnimi. Cilem je, aby paritni
    /// testy nize overovaly neco netrivialniho, ne jen "prazdny vstup -> prazdny
    /// vystup".
    fn complex_connection_fixture() -> Vec<ConnectionObservation> {
        let base = chrono::Utc::now();
        let mut connections = Vec::new();

        // Zdroj A sken pres 6 ruznych cilu v ramci jednoho okna - KAZDY cil
        // zasazen 3x (hranice `count >= 3` pro "unexpected_traffic" v
        // `windowed_events`), aby kazdy jednotlive prekrocil zakladni
        // anomalni prah a vsech 6 se pak spojilo stejnym `src_ip` do jednoho
        // "multi_target_pattern" nalezu (ablace C). Puvodni verze (1x na
        // cil) tohle nevyvolala vubec - zadny base event se neudelal, takze
        // test nic neoveroval; najito prave diky tomuto testu.
        for (index, port) in [21u16, 22, 23, 80, 443, 8080].into_iter().enumerate() {
            for repeat in 0..3 {
                connections.push(ConnectionObservation {
                    timestamp: base + chrono::Duration::seconds(index as i64 * 5 + repeat as i64),
                    src_ip: Some("10.0.0.9".to_string()),
                    src_port: Some(50000 + index as u16),
                    dst_ip: format!("10.0.1.{}", index + 1),
                    proto: "tcp".to_string(),
                    dst_port: Some(port),
                    conn_state: Some("S0".to_string()),
                    history: None,
                    duration_s: Some(0.01),
                    orig_pkts: Some(1),
                    resp_pkts: Some(0),
                    orig_bytes: Some(40),
                    resp_bytes: Some(0),
                    total_pkts: None,
                    total_bytes: None,
                    missed_bytes: None,
                });
            }
        }

        // Zdroj B opakovane zasahuje JEDEN cil - 4x v prvnim okne (t=0..300s),
        // 4x ve druhem okne (t=400..700s) - overuje spravne rozdeleni pres
        // tumbling hranice (ablace B/D).
        for window in 0..2 {
            for repeat in 0..4 {
                connections.push(connection_at_offset(
                    base,
                    window * 400 + repeat * 10,
                    "10.0.2.1",
                    "10.0.9.9",
                    "tcp",
                    9999,
                ));
            }
        }

        // Zdroj C - normalni, nizko-objemovy provoz, nema vyvolat zadny nalez.
        connections.push(connection_at_offset(
            base,
            0,
            "10.0.3.1",
            "10.0.9.50",
            "tcp",
            443,
        ));

        connections
    }

    fn connection_at_offset(
        base: chrono::DateTime<chrono::Utc>,
        offset_s: i64,
        src_ip: &str,
        dst_ip: &str,
        proto: &str,
        port: u16,
    ) -> ConnectionObservation {
        ConnectionObservation {
            timestamp: base + chrono::Duration::seconds(offset_s),
            src_ip: Some(src_ip.to_string()),
            src_port: Some(12345),
            dst_ip: dst_ip.to_string(),
            proto: proto.to_string(),
            dst_port: Some(port),
            conn_state: Some("S0".to_string()),
            history: None,
            duration_s: Some(0.01),
            orig_pkts: Some(1),
            resp_pkts: Some(0),
            orig_bytes: Some(40),
            resp_bytes: Some(0),
            total_pkts: None,
            total_bytes: None,
            missed_bytes: None,
        }
    }

    /// Stejny princip jako `legacy_detector_matches_direct_function_call`, ale
    /// pro ablace B/C/D na netrivialni fixture - BEZE ZMENY chovani by melo
    /// `Detector::detect` vracet presne to, co vrati primy zavolani funkce,
    /// kterou obaluje. Srovnani pres JSON serializaci zachyti i pole, na ktera
    /// by se rucni per-field srovnani mohlo zapomenout.
    #[test]
    fn windowed_detector_matches_direct_function_call_on_complex_fixture() {
        let connections = complex_connection_fixture();
        let known_services = HashSet::new();

        let via_trait =
            WindowedDetector { time_window_s: 300 }.detect(connections.clone(), &known_services);
        let direct =
            crate::correlation_v2::detect_windowed_anomalies(connections, &known_services, 300);

        assert!(
            !via_trait.is_empty(),
            "fixtura musi skutecne neco vyprodukovat"
        );
        assert_eq!(
            serde_json::to_string(&via_trait).unwrap(),
            serde_json::to_string(&direct).unwrap()
        );
    }

    #[test]
    fn linked_detector_matches_direct_function_call_on_complex_fixture() {
        let connections = complex_connection_fixture();
        let known_services = HashSet::new();

        let via_trait =
            LinkedDetector { time_window_s: 300 }.detect(connections.clone(), &known_services);
        let direct = crate::correlation_v2::detect_windowed_anomalies_linked(
            connections,
            &known_services,
            300,
        );

        assert!(
            via_trait
                .iter()
                .any(|event| event.event_type == "multi_target_pattern"),
            "fixtura ma zdroj skenujici 6 cilu - multi_target_pattern se musi objevit, jinak test nic neoveruje"
        );
        assert_eq!(
            serde_json::to_string(&via_trait).unwrap(),
            serde_json::to_string(&direct).unwrap()
        );
    }

    #[test]
    fn multiscale_detector_matches_direct_function_call_on_complex_fixture() {
        let connections = complex_connection_fixture();
        let known_services = HashSet::new();
        let scales = vec![60, 300, 1800, 7200];

        let via_trait = MultiscaleDetector {
            window_scales: scales.clone(),
        }
        .detect(connections.clone(), &known_services);
        let direct = crate::correlation_v2::detect_multiscale_windowed_anomalies(
            connections,
            &known_services,
            &scales,
        );

        assert!(
            !via_trait.is_empty(),
            "fixtura musi skutecne neco vyprodukovat"
        );
        assert_eq!(
            serde_json::to_string(&via_trait).unwrap(),
            serde_json::to_string(&direct).unwrap()
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
