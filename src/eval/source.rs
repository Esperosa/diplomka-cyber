use std::path::Path;

use crate::error::Result;
use crate::eval::ground_truth::LabeledDataset;

/// Metadata zdroje pro `docs/diplomka/dataset-registry.md` - jedno misto, odkud se
/// citovanou licenci/URL/vlnu bere i v kodu, aby se neduplikovaly rucne na dvou mistech.
#[derive(Debug, Clone)]
pub(crate) struct DatasetSourceInfo {
    pub(crate) dataset_id: &'static str,
    /// Vlna nabalovani zdroju (0 = prvni overeny zdroj, viz plan diplomky).
    pub(crate) wave: u8,
    pub(crate) license: &'static str,
    pub(crate) url: &'static str,
}

/// Jedna implementace = jeden zdroj dat (realny dataset nebo pozdeji simulacni
/// generator z Mininet/Containerlab). Pridani dalsiho zdroje v dalsi vlne znamena
/// novou implementaci tohoto traitu, ne zasah do `dataset_replay.rs`.
pub(crate) trait ScenarioSource {
    fn info(&self) -> DatasetSourceInfo;
    fn load(&self, path: &Path) -> Result<LabeledDataset>;
}
