//! Soak/zatezovy harness: dlouhodoby (desitky hodin) beh simulovanych siti s ground
//! truth, mereni a invariantami. Viz docs/diplomka/eval/soak-harness.md.

pub mod alloc;
pub mod episode;
pub mod hist;
pub mod kernel;
pub mod ladder_env;
pub mod legs;
pub mod netmodel;
pub mod report;
pub mod rng;
pub mod runner;
pub mod scoring;
pub mod stats;
pub mod traffic;
pub mod v3;
