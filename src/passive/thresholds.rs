//! Fáze 2 (produkční plán, framework-style wiring): `src/passive/anomaly.rs`,
//! `src/correlation_v2.rs` a `src/lanes.rs` měly stejné dva prahy (2 500 pps,
//! 35 Mbps) jako tři nezávisle opsané magické konstanty - změna jednoho bez
//! ostatních by tiše rozjela inkonzistentní chování mezi pasivní detekcí,
//! okénkovanou detekcí a flow-rate lanes. Hodnoty beze změny, jen na jednom
//! místě.

pub(crate) const HIGH_PPS_THRESHOLD: f64 = 2_500.0;
pub(crate) const HIGH_BPS_THRESHOLD: f64 = 35_000_000.0;
