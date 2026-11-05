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
    /// Obnova recallu (krok 2A): eskalace při prvním dominantním zdroji, pokusy i na
    /// známé služby, IDS nálezy podle signatury, zdrojová odlehlost, timeouty podle
    /// rozložení zdrojů.
    pub recall: bool,
    /// Žebřík okamžitého ověřování (krok 2B).
    pub ladder: bool,
    /// Učení z výsledků ověření a kalibrace (krok 2C).
    pub learning: bool,
    /// Typ zařízení v jádru: kontext ověřování a ochrana křehkých zařízení (krok 2D).
    pub devices: bool,
    /// Peer baseline detektoru podle typu zařízení a podsítě (krok 2D, zvlášť měřeno).
    #[serde(default)]
    pub peers: bool,
    /// Viditelnost odchozího provozu: toky a alerty se zdrojem NEBO cílem v rozsahu,
    /// se směrem a vzorkováním (krok 3A, audit 01 A10/R2).
    pub egress: bool,
    /// Beaconing na dvojici zdroj-cíl (krok 3B, RQ4 Z1/Z2, hypotéza).
    pub beacon: bool,
    /// Interaktivní relace a dlouhé tunely ven (krok 3C, RQ4 Z13, hypotéza).
    pub interactive: bool,
    /// Graf spojení: nové hrany a řetěz A→B→C (krok 3D, RQ4 Z10/Z11).
    pub graph: bool,
    /// Profil hostu a známé neškodné vzory jako pozitivní důkaz žebříku (krok 3E).
    pub profile: bool,
    /// Krok 6 (kandidát 1): výpadek senzoru nic nezavře a není neškodný důkaz žebříku
    /// (Dodatek A.2 d, RQ6 Z3: chybějící data nejsou důkaz neškodnosti).
    #[serde(default)]
    pub sensor_strict: bool,
    /// Krok 6 (kandidát 2): třída „provozní problém“ s pozitivním důkazem provozní
    /// příčiny; nezavírá se, jen jde do fronty provoz místo podezření na útok.
    #[serde(default)]
    pub ops_class: bool,
    /// Krok 6 (kandidáti 4 a 5): obecná novost vztahů hostu (nová trvalá vazba ven,
    /// nové vnitřní vazby), nezávislá na rodině útoku.
    #[serde(default)]
    pub novelty: bool,
    /// Krok 6 (kandidát 6): zdrojově citlivý kontext nezavře nález bez
    /// identifikovaného zdroje (kromě objemu v okně zálohy a dávky).
    #[serde(default)]
    pub context_guard: bool,
}

impl Default for V3Features {
    fn default() -> Self {
        Self::recommended()
    }
}

impl V3Features {
    pub const NAMES: [&'static str; 20] = [
        "memory",
        "rate",
        "volume",
        "unexpected",
        "context",
        "identity",
        "recall",
        "ladder",
        "learning",
        "devices",
        "peers",
        "egress",
        "beacon",
        "interactive",
        "graph",
        "profile",
        "sensor_strict",
        "ops_class",
        "novelty",
        "context_guard",
    ];

    pub fn all() -> Self {
        Self {
            memory: true,
            rate: true,
            volume: true,
            unexpected: true,
            context: true,
            identity: true,
            recall: true,
            ladder: true,
            learning: true,
            devices: true,
            peers: true,
            egress: true,
            beacon: true,
            interactive: true,
            graph: true,
            profile: true,
            sensor_strict: true,
            ops_class: true,
            novelty: true,
            context_guard: true,
        }
    }

    /// Doporučené (výchozí) nastavení v3: vše kromě peer baseline detektoru, která
    /// v párovém A/B kroku 2 neměla měřitelný přínos (impl-krok2.md, D), a kromě
    /// grafu nových hran (`pivot_chain`), který v A/B kroku 4 na ladicích seedech
    /// přidal +3,7 % zobrazených FP při zisku detekce jen u malých rodin
    /// (impl-krok4.md, A). Graf zůstává volitelný.
    /// Změny kroku 6 jsou mimo preset, dokud je nevybere předregistrované A/B
    /// (impl-krok6.md, B5).
    pub fn recommended() -> Self {
        Self {
            peers: false,
            graph: false,
            sensor_strict: false,
            ops_class: false,
            novelty: false,
            context_guard: false,
            ..Self::all()
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
            recall: false,
            ladder: false,
            learning: false,
            devices: false,
            peers: false,
            egress: false,
            beacon: false,
            interactive: false,
            graph: false,
            profile: false,
            sensor_strict: false,
            ops_class: false,
            novelty: false,
            context_guard: false,
        }
    }

    /// Stav po kroku 2 (bez změn kroku 3), pro párové srovnání kroku 3.
    pub fn step2() -> Self {
        Self {
            egress: false,
            beacon: false,
            interactive: false,
            graph: false,
            profile: false,
            ..Self::recommended()
        }
    }

    /// Stav po kroku 1 (bez změn kroku 2), pro párové srovnání kroku 2.
    pub fn step1() -> Self {
        Self {
            recall: false,
            ladder: false,
            learning: false,
            devices: false,
            peers: false,
            ..Self::step2()
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
            "recall" => &mut self.recall,
            "ladder" => &mut self.ladder,
            "learning" => &mut self.learning,
            "devices" => &mut self.devices,
            "peers" => &mut self.peers,
            "egress" => &mut self.egress,
            "beacon" => &mut self.beacon,
            "interactive" => &mut self.interactive,
            "graph" => &mut self.graph,
            "profile" => &mut self.profile,
            "sensor_strict" => &mut self.sensor_strict,
            "ops_class" => &mut self.ops_class,
            "novelty" => &mut self.novelty,
            "context_guard" => &mut self.context_guard,
            _ => return None,
        })
    }

    /// Vypne vyjmenované změny (seznam oddělený čárkami, např. `rate,volume`).
    pub fn disable_list(self, list: &str) -> Result<Self, String> {
        self.set_list(list, false)
    }

    /// Zapne vyjmenované změny mimo preset (ablace kroku 5, např. `graph`).
    pub fn enable_list(self, list: &str) -> Result<Self, String> {
        self.set_list(list, true)
    }

    fn set_list(mut self, list: &str, on: bool) -> Result<Self, String> {
        for name in list.split(',').map(str::trim).filter(|n| !n.is_empty()) {
            *self.slot(name).ok_or_else(|| {
                format!(
                    "neznama zmena v3 '{name}' (povolene: {})",
                    Self::NAMES.join(", ")
                )
            })? = on;
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
            v3: V3Features::recommended(),
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
    pub fn recall(&self) -> bool {
        self.on(|f| f.recall)
    }
    /// Žebřík potřebuje paměť nálezů (ověřuje se jen otevřený stav).
    pub fn ladder(&self) -> bool {
        self.on(|f| f.ladder && f.memory)
    }
    pub fn learning(&self) -> bool {
        self.on(|f| f.learning)
    }
    pub fn devices(&self) -> bool {
        self.on(|f| f.devices)
    }
    /// Peer baseline detektoru podle typu zařízení (vyžaduje rozpoznání zařízení).
    pub fn peer_baseline(&self) -> bool {
        self.on(|f| f.devices && f.peers)
    }
    /// Odchozí toky a alerty (zdroj nebo cíl v rozsahu, krok 3A).
    pub fn egress(&self) -> bool {
        self.on(|f| f.egress)
    }
    /// Detektory nad odchozím provozem potřebují viditelnost ven (krok 3A).
    pub fn beacon(&self) -> bool {
        self.on(|f| f.egress && f.beacon)
    }
    pub fn interactive(&self) -> bool {
        self.on(|f| f.egress && f.interactive)
    }
    pub fn graph(&self) -> bool {
        self.on(|f| f.graph)
    }
    /// Profil hostu je důkaz žebříku, bez žebříku nemá smysl.
    pub fn profile(&self) -> bool {
        self.on(|f| f.profile && f.ladder && f.memory)
    }
    /// Krok 6: výpadek senzoru není vysvětlení (jen s kontextovou bránou).
    pub fn sensor_strict(&self) -> bool {
        self.on(|f| f.context && f.sensor_strict)
    }
    /// Krok 6: třída provozní problém (jen s pamětí nálezů, rozhoduje o zobrazení).
    pub fn ops_class(&self) -> bool {
        self.on(|f| f.ops_class && f.memory)
    }
    /// Krok 6: novost vztahů stojí na profilu hostu a viditelnosti ven.
    pub fn novelty(&self) -> bool {
        self.profile() && self.egress() && self.v3.novelty
    }
    /// Krok 6: kontext bez identifikovaného zdroje nezavírá.
    pub fn context_guard(&self) -> bool {
        self.on(|f| f.context && f.context_guard)
    }
    /// Běží behaviorální vrstva kroku 3 (aspoň jedna její část)?
    pub fn behavior(&self) -> bool {
        self.egress() || self.graph() || self.profile()
    }
    /// Běží v3 detektor (aspoň jedna detekční změna)?
    pub fn v3_detector(&self) -> bool {
        self.robust_rate() || self.volume_baseline() || self.unexpected_v3()
    }

    /// Konfigurace paměti nálezů podle zapnutých změn.
    pub fn memory_config(&self) -> crate::finding_memory::MemoryConfig {
        crate::finding_memory::MemoryConfig {
            escalate_first_source: self.recall(),
            ..Default::default()
        }
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
        // krok 5: zapnuti mimo preset (graf neni v doporucenem presetu)
        let with_graph = V3Features::recommended().enable_list("graph").unwrap();
        assert!(with_graph.graph && !V3Features::recommended().graph);
        assert!(V3Features::recommended().enable_list("nic").is_err());
        let cfg = EngineConfig {
            mode: EngineMode::V3,
            v3: features,
        };
        assert_eq!(
            cfg.label(),
            "v3[memory+unexpected+context+identity+recall+ladder+learning+devices+peers+egress+beacon+interactive+graph+profile+sensor_strict+ops_class+novelty+context_guard]"
        );
        let step2 = EngineConfig {
            mode: EngineMode::V3,
            v3: V3Features::step2(),
        };
        assert_eq!(
            step2.label(),
            "v3[memory+rate+volume+unexpected+context+identity+recall+ladder+learning+devices]"
        );
        assert!(!step2.behavior() && !step2.egress());
        // krok 4 A: graf nových hran není ve výchozím presetu
        let recommended = V3Features::recommended();
        assert!(!recommended.graph && !recommended.peers && recommended.beacon);
        let no_egress = EngineConfig {
            mode: EngineMode::V3,
            v3: V3Features::all().disable_list("egress").unwrap(),
        };
        // beacon a interaktivni relace bez viditelnosti ven nebezi
        assert!(!no_egress.beacon() && !no_egress.interactive() && no_egress.graph());
        let step1 = EngineConfig {
            mode: EngineMode::V3,
            v3: V3Features::step1(),
        };
        assert_eq!(
            step1.label(),
            "v3[memory+rate+volume+unexpected+context+identity]"
        );
        assert!(!step1.ladder() && !step1.recall());
        // krok 6: nove zmeny mimo preset, zapinaji se jmenem
        let k6 = EngineConfig {
            mode: EngineMode::V3,
            v3: V3Features::recommended()
                .enable_list("sensor_strict,ops_class,novelty,context_guard")
                .unwrap(),
        };
        assert!(k6.sensor_strict() && k6.ops_class() && k6.novelty() && k6.context_guard());
        let preset = EngineConfig::v3();
        assert!(!preset.sensor_strict() && !preset.ops_class() && !preset.novelty());
        assert!(!preset.context_guard());
        let no_profile = EngineConfig {
            mode: EngineMode::V3,
            v3: V3Features::recommended()
                .enable_list("novelty")
                .unwrap()
                .disable_list("profile")
                .unwrap(),
        };
        assert!(!no_profile.novelty(), "novost potrebuje profil hostu");
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
