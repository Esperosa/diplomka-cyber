//! Přepínač jádra (`engine.mode = legacy | v3`) a volby jednotlivých změn v3.
//!
//! Stará cesta (`legacy`) zůstává výchozí, dokud párové A/B na stejných seedech
//! neprojde laťkou (00-zaver Dodatek A, §5A.2). Každou změnu v3 jde vypnout zvlášť,
//! aby šlo změřit její samostatný přínos (ablace, krok 1, docs/diplomka/eval/impl-krok1.md).

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineMode {
    #[default]
    Legacy,
    V3,
}

impl EngineMode {
    pub fn label(self) -> &'static str {
        match self {
            EngineMode::Legacy => "legacy",
            EngineMode::V3 => "v3",
        }
    }
}

impl fmt::Display for EngineMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for EngineMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "legacy" => Ok(EngineMode::Legacy),
            "v3" => Ok(EngineMode::V3),
            other => Err(format!("neznamy rezim jadra '{other}' (legacy | v3)")),
        }
    }
}

/// Jednotlivé změny jádra v3. Výchozí: vše zapnuto. V režimu `legacy` se ignorují.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct V3Features {
    /// Paměť nálezů: stabilní identita, stav, TTL, strop, deduplikace (krok B).
    pub memory: bool,
    /// Robustní `packet_rate_spike` (p95 kvalifikovaných toků + historie, krok C).
    pub rate: bool,
    /// `inductive_volume_anomaly` proti vlastní historii a skupině (krok C).
    pub volume: bool,
    /// `unexpected_traffic`: úspěch vs. pokusy, perzistentní inventář, agregace unmapped (krok C).
    pub unexpected: bool,
    /// Kontextové vyloučení s auditem (krok D).
    pub context: bool,
    /// Vícesignálová identita (krok E).
    pub identity: bool,
}

impl Default for V3Features {
    fn default() -> Self {
        Self::all()
    }
}

impl V3Features {
    pub const NAMES: [&'static str; 6] = [
        "memory",
        "rate",
        "volume",
        "unexpected",
        "context",
        "identity",
    ];

    pub fn all() -> Self {
        Self {
            memory: true,
            rate: true,
            volume: true,
            unexpected: true,
            context: true,
            identity: true,
        }
    }

    pub fn none() -> Self {
        Self {
            memory: false,
            rate: false,
            volume: false,
            unexpected: false,
            context: false,
            identity: false,
        }
    }

    fn slot(&mut self, name: &str) -> Option<&mut bool> {
        Some(match name {
            "memory" => &mut self.memory,
            "rate" => &mut self.rate,
            "volume" => &mut self.volume,
            "unexpected" => &mut self.unexpected,
            "context" => &mut self.context,
            "identity" => &mut self.identity,
            _ => return None,
        })
    }

    /// Vypne vyjmenované změny (seznam oddělený čárkami, např. `rate,volume`).
    pub fn disable_list(mut self, list: &str) -> Result<Self, String> {
        for name in list.split(',').map(str::trim).filter(|n| !n.is_empty()) {
            *self.slot(name).ok_or_else(|| {
                format!(
                    "neznama zmena v3 '{name}' (povolene: {})",
                    Self::NAMES.join(", ")
                )
            })? = false;
        }
        Ok(self)
    }

    /// Krátký popis zapnutých změn (do reportu a statusu).
    pub fn label(&self) -> String {
        let mut copy = *self;
        let on: Vec<&str> = Self::NAMES
            .iter()
            .copied()
            .filter(|name| copy.slot(name).is_some_and(|value| *value))
            .collect();
        if on.is_empty() {
            "zadne".to_string()
        } else {
            on.join("+")
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineConfig {
    pub mode: EngineMode,
    pub v3: V3Features,
}

impl EngineConfig {
    pub fn legacy() -> Self {
        Self::default()
    }

    pub fn v3() -> Self {
        Self {
            mode: EngineMode::V3,
            v3: V3Features::all(),
        }
    }

    fn on(&self, pick: impl Fn(&V3Features) -> bool) -> bool {
        self.mode == EngineMode::V3 && pick(&self.v3)
    }

    pub fn memory(&self) -> bool {
        self.on(|f| f.memory)
    }
    pub fn robust_rate(&self) -> bool {
        self.on(|f| f.rate)
    }
    pub fn volume_baseline(&self) -> bool {
        self.on(|f| f.volume)
    }
    pub fn unexpected_v3(&self) -> bool {
        self.on(|f| f.unexpected)
    }
    pub fn context_gate(&self) -> bool {
        self.on(|f| f.context)
    }
    pub fn identity_v3(&self) -> bool {
        self.on(|f| f.identity)
    }
    /// Běží v3 detektor (aspoň jedna detekční změna)?
    pub fn v3_detector(&self) -> bool {
        self.robust_rate() || self.volume_baseline() || self.unexpected_v3()
    }

    pub fn label(&self) -> String {
        match self.mode {
            EngineMode::Legacy => "legacy".to_string(),
            EngineMode::V3 => format!("v3[{}]", self.v3.label()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_legacy_and_v3_flags_are_inert_in_legacy() {
        let cfg = EngineConfig::default();
        assert_eq!(cfg.mode, EngineMode::Legacy);
        assert!(!cfg.memory() && !cfg.v3_detector() && !cfg.context_gate());
        assert_eq!(cfg.label(), "legacy");
    }

    #[test]
    fn parse_mode_and_disable_list() {
        assert_eq!("V3".parse::<EngineMode>().unwrap(), EngineMode::V3);
        assert!("v4".parse::<EngineMode>().is_err());
        let features = V3Features::all().disable_list("rate, volume").unwrap();
        assert!(!features.rate && !features.volume && features.memory);
        assert!(V3Features::all().disable_list("nic").is_err());
        let cfg = EngineConfig {
            mode: EngineMode::V3,
            v3: features,
        };
        assert_eq!(cfg.label(), "v3[memory+unexpected+context+identity]");
    }

    #[test]
    fn config_toml_roundtrip_with_missing_section_defaults_to_legacy() {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(default)]
            engine: EngineConfig,
        }
        let parsed: Wrapper = toml::from_str("").unwrap();
        assert_eq!(parsed.engine.mode, EngineMode::Legacy);
        let parsed: Wrapper =
            toml::from_str("[engine]\nmode = \"v3\"\n[engine.v3]\ncontext = false\n").unwrap();
        assert!(parsed.engine.memory());
        assert!(!parsed.engine.context_gate());
    }
}
