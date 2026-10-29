//! Evaluacni ramec pro replay realnych labelovanych datasetu proti nezmenenemu
//! analytickemu enginu (ablace A dle docs/diplomka/BAKULA_kompletni_technicky_navrh...md,
//! sekce 9 a 13). Zalozeno jako samostatny modul, ne roubovano na `evaluation.rs`/
//! `verification.rs`, ktere jsou svazane se syntetickym scenario-manifest workflow.
//!
//! Invariant label-leakage-safety: `ground_truth::GroundTruthLabel` se nikdy nestane
//! polem v `model::Observation`/`Finding`/`RunReport` typech a nikdy se neposila do
//! `correlation::correlate_events`/`decision::rank_finding`/`report::score_services`.
//! Zaruka je strukturni (parallel Vec, ne join pres klic) - viz `ground_truth::LabeledDataset`.

// Tato faze dodava a overuje infrastrukturu pres inline testy (#[cfg(test)] v
// dataset_replay.rs a sources/iot23.rs); CLI/report wiring je dalsi navazujici krok,
// proto je modul z pohledu produkcniho (ne-testovaciho) buildu "nevolany".
#![allow(dead_code)]

pub mod dataset_replay;
pub mod ground_truth;
pub mod source;
pub mod sources;
