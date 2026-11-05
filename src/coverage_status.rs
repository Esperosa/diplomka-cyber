//! Viditelnost degradace pokrytí (krok 7, A4; docs/diplomka/eval/impl-krok7.md).
//!
//! Engine nesmí mlčky předstírat plné pokrytí: když chybí IDS, profily jsou nezralé,
//! v telemetrii je mezera nebo je málo dat průmyslových protokolů, report (API a data
//! UI) to řekne a nasazení s mezerou, kterou tokový detektor nenahradí, se označí
//! jako blokované. Vzhled UI se tu neřeší, jen pole.

use serde::{Deserialize, Serialize};

/// Porty průmyslových protokolů (Modbus, S7, DNP3, EtherNet/IP, OPC UA, BACnet).
pub const ICS_PORTS: &[u16] = &[502, 102, 20000, 44818, 4840, 47808];
/// Pod tolika toky průmyslových protokolů v okně jsou data ICS „málo“.
pub const ICS_MIN_FLOWS: usize = 10;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CoverageStatus {
    pub degraded: bool,
    /// `no_ids`, `immature_profiles`, `telemetry_gap`, `low_ics_data`
    pub reasons: Vec<String>,
    /// Nasazení s touto mezerou nemá plný deklarovaný rozsah (exploit bez IDS, okno
    /// bez dat): vyžaduje vědomé rozhodnutí člověka.
    pub deployment_blocking: bool,
    /// Vnitřní hosté v tocích okna s profilem mladším než 48 h (z kolika).
    pub immature_hosts: usize,
    pub observed_hosts: usize,
    pub ics_devices: usize,
    pub ics_flows: usize,
    /// `exploit_attempt` (IDS typy) se vždy ukáže člověku a nikdy se nezavře (A1, P3).
    pub exploit_always_shown: bool,
}

/// Vstupy jednoho běhu.
#[derive(Debug, Clone, Default)]
pub struct CoverageInput {
    pub ids_configured: bool,
    pub sensor_gap: bool,
    pub flows_in_window: usize,
    pub observed_hosts: usize,
    pub immature_hosts: usize,
    pub ics_devices: usize,
    pub ics_flows: usize,
    pub protect: bool,
}

pub fn assess(input: &CoverageInput) -> CoverageStatus {
    let mut reasons = Vec::new();
    if !input.ids_configured {
        reasons.push("no_ids".to_string());
    }
    if input.observed_hosts > 0 && input.immature_hosts > 0 {
        reasons.push("immature_profiles".to_string());
    }
    let gap = input.sensor_gap || input.flows_in_window == 0;
    if gap {
        reasons.push("telemetry_gap".to_string());
    }
    if input.ics_devices > 0 && input.ics_flows < ICS_MIN_FLOWS {
        reasons.push("low_ics_data".to_string());
    }
    CoverageStatus {
        degraded: !reasons.is_empty(),
        deployment_blocking: !input.ids_configured || gap,
        reasons,
        immature_hosts: input.immature_hosts,
        observed_hosts: input.observed_hosts,
        ics_devices: input.ics_devices,
        ics_flows: input.ics_flows,
        exploit_always_shown: input.protect,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_coverage_is_not_degraded_and_gaps_are_named() {
        let ok = assess(&CoverageInput {
            ids_configured: true,
            flows_in_window: 100,
            observed_hosts: 5,
            protect: true,
            ..Default::default()
        });
        assert!(!ok.degraded && !ok.deployment_blocking && ok.exploit_always_shown);
        let bad = assess(&CoverageInput {
            ids_configured: false,
            flows_in_window: 0,
            observed_hosts: 5,
            immature_hosts: 2,
            ics_devices: 1,
            ics_flows: 3,
            ..Default::default()
        });
        assert!(bad.degraded && bad.deployment_blocking);
        assert_eq!(
            bad.reasons,
            vec![
                "no_ids",
                "immature_profiles",
                "telemetry_gap",
                "low_ics_data"
            ]
        );
    }
}
