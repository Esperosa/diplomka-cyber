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

pub mod calibration;
pub mod dataset_replay;
pub mod ground_truth;
pub mod source;
pub mod sources;

#[cfg(test)]
mod tests {
    use std::path::Path;

    use sha2::{Digest, Sha256};

    /// Regresni test na konkretni bug (29.10.2026): vsechny 3 hashe v
    /// `docs/diplomka/dataset-registry.md` byly useknute o 1 hex znak pri rucnim
    /// prepisu ze `sha256sum` vystupu - odhaleno nezavislou kontrolou (Opus Plan
    /// agent). Ted se hash committed souboru pocita a porovnava automaticky, ne
    /// znovu rucne prepisuje - zadny budouci prepis uz nemuze tise rozejit kod a
    /// dokumentaci.
    fn sha256_hex(path: &Path) -> String {
        let bytes = std::fs::read(path).expect("read dataset file for hash check");
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn committed_iot23_files_match_hashes_recorded_in_dataset_registry() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let expected = [
            (
                "labs/datasets/iot23/CTU-IoT-Malware-Capture-44-1/conn.log.labeled",
                "12cd99bcda78140dd5f31cf3d786642f150e42e0ebc3599190f35314e406f71f",
            ),
            (
                "labs/datasets/iot23/CTU-Honeypot-Capture-7-1-Somfy-01/conn.log.labeled",
                "fb37fb38393c48b064d3afd373b075ffe31063d4924a2df1c5d13fc490b830cc",
            ),
        ];

        for (relative_path, expected_hash) in expected {
            let actual_hash = sha256_hex(&root.join(relative_path));
            assert_eq!(
                actual_hash, expected_hash,
                "hash souboru {relative_path} se neshoduje s docs/diplomka/dataset-registry.md - oprav jedno nebo druhe"
            );
        }
    }
}
