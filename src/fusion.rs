//! Deliverable 27 (H2 krok 3, `docs/diplomka/produkcni-plan.md`): dependency-aware
//! evidence fusion. Implementuje literalni H2 claim (navrh sekce 5.1): "stejny tok
//! pozorovany Suricatou, Zeekem a firewallem nejsou tri nezavisle dukazy."
//!
//! Evidence se stejnym `community_id` (Deliverable 25/26) pochazi ze stejneho
//! fyzickeho toku - sloucena na JEDNU polozku (MAX skore mezi senzory, ne SOUCET),
//! protoze dalsi senzor potvrzujici uz zachyceny tok neprinasi nezavislou informaci.
//! Evidence BEZ spolecneho `community_id` (ruzne toky, nebo chybejici join-key) se
//! pocita jako nezavisla a jeji skore se SCITAJI - presne naopak nez u zavisle
//! evidence, a presne ten rozdil je cely obsah H2 claim.
//!
//! H2 krok 4 (produkcni-plan.md): `fuse_same_flow_events` zapojuje `dependency_corrected_fusion`
//! do produkcni cesty (`passive::load_and_normalize`). Eventy od >=2 RUZNYCH senzoru
//! (`NormalizedEvent::source`) se stejnym `community_id` (Deliverable 25/26 join-key,
//! `passive::normalized_event_community_id`) jsou stejny fyzicky tok - slouci se do JEDNOHO
//! reprezentativniho eventu (nejvyssi severity mezi senzory), presne stejny princip jako
//! `dependency_corrected_fusion` nize, jen na produkcnim typu `NormalizedEvent` misto
//! testovaciho `EvidenceItem`. `decision.rs::rank_finding` pak rozpozna [H2 fuze: ...]
//! marker v `message` a korektni cross-senzor korroboraci odmeni malym, ohranicenym
//! bonusem na confidence/score - NE naivnim zvysenim poctu "nezavislych" nalezu.

use std::collections::{BTreeSet, HashMap};

use crate::model::{NormalizedEvent, Severity};
use crate::passive::normalized_event_community_id;

#[derive(Debug, Clone)]
pub(crate) struct EvidenceItem {
    pub(crate) community_id: Option<String>,
    pub(crate) sensor: String,
    pub(crate) score: f64,
}

#[derive(Debug, Clone)]
pub(crate) struct FusedEvidence {
    /// Produkcni `merge_cross_sensor_group` ho nepotrebuje (skupina uz je vybrana
    /// podle jedineho community_id predem) - testy ho ale ctou jako primy dukaz, ze
    /// `dependency_corrected_fusion` spravne zachovalo puvodni join-key.
    #[allow(dead_code)]
    pub(crate) community_id: Option<String>,
    pub(crate) combined_score: f64,
    pub(crate) contributing_sensors: Vec<String>,
}

/// Naivni fuze: kazda polozka evidence se pocita jako nezavisla, skore se scitaji.
/// Tohle je presne to, co "prosty scoring eventu" (H2's protiklad) dela - zadna
/// korekce zavislosti zdrojů. Pouzito jen v testech jako kontrastni baseline k
/// `dependency_corrected_fusion` - produkcni `fuse_same_flow_events` naivni soucet
/// nikdy nepocita.
#[allow(dead_code)]
pub(crate) fn naive_independent_sum(items: &[EvidenceItem]) -> f64 {
    items.iter().map(|item| item.score).sum()
}

/// Dependency-aware fuze: evidence se stejnym `community_id` (stejny fyzicky tok)
/// se slouci do jedne polozky (MAX skore, ne SOUCET) - dalsi senzor potvrzujici uz
/// zachyceny tok neprinasi nezavislou informaci, i kdyz ma vlastni, jinak vypadajici
/// skore. Evidence bez `community_id` (ruzne toky nebo chybejici join-key) zustava
/// samostatna - zadny zaklad pro tvrzeni zavislosti bez spolecneho klice.
pub(crate) fn dependency_corrected_fusion(items: &[EvidenceItem]) -> Vec<FusedEvidence> {
    let mut grouped: HashMap<String, Vec<&EvidenceItem>> = HashMap::new();
    let mut independent: Vec<FusedEvidence> = Vec::new();

    for item in items {
        match &item.community_id {
            Some(id) => grouped.entry(id.clone()).or_default().push(item),
            None => independent.push(FusedEvidence {
                community_id: None,
                combined_score: item.score,
                contributing_sensors: vec![item.sensor.clone()],
            }),
        }
    }

    let mut fused: Vec<FusedEvidence> = grouped
        .into_iter()
        .map(|(community_id, group)| {
            let combined_score = group.iter().map(|item| item.score).fold(0.0_f64, f64::max);
            FusedEvidence {
                community_id: Some(community_id),
                combined_score,
                contributing_sensors: group.iter().map(|item| item.sensor.clone()).collect(),
            }
        })
        .collect();

    fused.extend(independent);
    fused
}

/// Souhrnne skore pro rozhodovani (secte vsechny FUZOVANE polozky) - pro srovnani s
/// `naive_independent_sum` na stejnem vstupu. Produkcni `merge_cross_sensor_group`
/// cte `combined_score` primo z jedine `FusedEvidence` polozky (skupina ma vzdy
/// presne 1 community_id), takze soucet pres VICE polozek potrebuji jen testy
/// demonstrujici kontrast s `naive_independent_sum`.
#[allow(dead_code)]
pub(crate) fn fused_total_score(fused: &[FusedEvidence]) -> f64 {
    fused.iter().map(|item| item.combined_score).sum()
}

/// Mapovani Severity<->score je presne (0.2/0.5/0.9), ne lossy bucketovani - MAX
/// mezi diskretnimi hodnotami vzdy vrati jednu z puvodnich hodnot, takze
/// `severity_from_score(severity_score(x))` je pro kazde `x: Severity` identita.
fn severity_score(severity: Severity) -> f64 {
    match severity {
        Severity::Low => 0.2,
        Severity::Medium => 0.5,
        Severity::High => 0.9,
    }
}

fn severity_from_score(score: f64) -> Severity {
    if score >= 0.9 {
        Severity::High
    } else if score >= 0.5 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Community ID nema casovou slozku (jen 5-tuple) - bez tohoto stropu by znovu-
/// pouziti efemerniho portu po dlouhe dobe (ruzne, nesouvisejici spojeni se
/// STEJNYM 5-tuple) mohlo sloucit 2 eventy, ktere spolu fakticky nesouvisi. Audit
/// nalez (Haiku, 30.10.2026). 900s (15 min) je vedomy, konzervativni odhad - realny
/// dual-senzor capture (Deliverable 25) mel rozdil v radu sekund mezi senzory.
const MAX_FUSION_TIME_GAP_S: i64 = 900;

/// H2 krok 4: produkcni vstupni bod, viz modulova dokumentace. Eventy bez
/// `community_id` (chybejici src_port/nepodporovany protokol - typicky ablace A nebo
/// multi-cil `multi_target_pattern`), eventy se stejnym jedinym senzorem (opakovane
/// pozorovani JEDNIM senzorem, ne MEZI-senzorova zavislost), a skupiny, jejichz
/// rozptyl timestampu presahuje `MAX_FUSION_TIME_GAP_S`, projdou beze zmeny.
///
/// Puvodni index si neseme podel celeho grupovani a pouzivame ho jako sekundarni
/// sort klic - bez neho by poradi eventu se stejnym `timestamp` zaviselo na
/// iteraci `HashMap` (nedeterministicke mezi behy, ruzny hash seed), coz by rozbilo
/// golden-snapshot reprodukovatelnost. Audit nalez behem H2 wiring (30.10.2026).
pub(crate) fn fuse_same_flow_events(events: Vec<NormalizedEvent>) -> Vec<NormalizedEvent> {
    let mut by_flow: HashMap<String, Vec<(usize, NormalizedEvent)>> = HashMap::new();
    let mut passthrough: Vec<(usize, NormalizedEvent)> = Vec::new();

    for (index, event) in events.into_iter().enumerate() {
        match normalized_event_community_id(&event) {
            Some(community_id) => by_flow
                .entry(community_id)
                .or_default()
                .push((index, event)),
            None => passthrough.push((index, event)),
        }
    }

    let mut fused: Vec<(usize, NormalizedEvent)> = Vec::new();
    for group in by_flow.into_values() {
        let sensors: BTreeSet<String> = group
            .iter()
            .map(|(_, event)| event.source.clone())
            .collect();
        let within_time_gap = {
            let timestamps: Vec<_> = group.iter().map(|(_, event)| event.timestamp).collect();
            match (timestamps.iter().min(), timestamps.iter().max()) {
                (Some(min), Some(max)) => (*max - *min).num_seconds() <= MAX_FUSION_TIME_GAP_S,
                _ => true,
            }
        };
        if sensors.len() < 2 || !within_time_gap {
            // Jeden a tyz senzor pozoroval tok vicekrat (opakovani, ne zavislost MEZI
            // senzory), nebo je rozptyl timestampu prilis velky na to, aby slo o
            // stejnou udalost - v obou pripadech H2 claim neplati, nic se nesluci.
            fused.extend(group);
            continue;
        }
        let tie_break_index = group.iter().map(|(index, _)| *index).min().unwrap_or(0);
        let members: Vec<NormalizedEvent> = group.into_iter().map(|(_, event)| event).collect();
        fused.push((tie_break_index, merge_cross_sensor_group(members)));
    }

    fused.extend(passthrough);
    fused.sort_by(|(left_index, left), (right_index, right)| {
        left.timestamp
            .cmp(&right.timestamp)
            .then(left_index.cmp(right_index))
    });
    fused.into_iter().map(|(_, event)| event).collect()
}

/// Slouci skupinu eventu se stejnym community_id od >=2 ruznych senzoru do JEDNOHO
/// reprezentativniho eventu pres `dependency_corrected_fusion` (nejvyssi severity, ne
/// soucet). Marker `[H2 fuze: ...]` v `message` + joined `source` dava
/// `decision.rs::rank_finding` explicitni, string-matchovatelny signal pro genuine
/// cross-senzor korroboraci - stejny idiom, co uz `is_cve_signal`/`is_plaintext_signal`
/// pouzivaji pro cteni evidence.
fn merge_cross_sensor_group(group: Vec<NormalizedEvent>) -> NormalizedEvent {
    let items: Vec<EvidenceItem> = group
        .iter()
        .map(|event| EvidenceItem {
            community_id: normalized_event_community_id(event),
            sensor: event.source.clone(),
            score: severity_score(event.severity),
        })
        .collect();
    // Skupina ma vzdy stejne, Some(..) community_id (sestavena v `fuse_same_flow_events`
    // podle klice `by_flow`), takze `dependency_corrected_fusion` nad ni vzdy vrati
    // presne JEDNU polozku - `contributing_sensors` z ni je presna, uz-deduplikovana
    // mnozina senzoru, nemusime ji pocitat znovu rucne.
    let fused = dependency_corrected_fusion(&items);
    let representative_fused = fused
        .first()
        .expect("skupina se spolecnym community_id musi dat alespon 1 fuzovanou polozku");
    let representative_severity = severity_from_score(representative_fused.combined_score);
    let mut sensors = representative_fused.contributing_sensors.clone();
    sensors.sort();
    sensors.dedup();

    // Audit nalez (Haiku, 30.10.2026): drive se zprava vzala jen z JEDNOHO (nejvyssi
    // severity) vybraneho eventu - text ostatnich (napr. CVE/plaintext klicove slovo
    // u jineho senzoru s nizsi severity) se tise zahodil, cimz mohl zmizet signal, na
    // ktery `decision.rs::is_cve_signal`/`is_plaintext_signal` spoleha (ctou text
    // evidence stringovym matchem, ne jen `finding_type`). Zprava ted obsahuje text
    // VSECH prispivajicich eventu.
    let mut combined_messages: Vec<String> = group
        .iter()
        .map(|event| format!("{}: {}", event.source, event.message))
        .collect();
    combined_messages.sort();
    combined_messages.dedup();

    // MAX, ne SOUCET - stejny princip jako u severity/score. Soucet `count` pres
    // senzory by znovu zavedl presne to naivni "kolik nezavislych potvrzeni"
    // pocitani, ktere cela tahle fuze ma odstranit.
    let max_count = group.iter().map(|event| event.count).max().unwrap_or(0);

    let mut representative = group
        .into_iter()
        .find(|event| event.severity == representative_severity)
        .expect(
            "fuzovana skupina musi obsahovat alespon jeden event s max severity ze vstupnich polozek",
        );

    let sensor_list = sensors.join("+");
    representative.message = format!(
        "[H2 fuze: potvrzeno senzory {sensor_list}, stejny tok] {}",
        combined_messages.join(" | ")
    );
    representative.source = sensor_list;
    representative.count = max_count;
    representative
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    fn item(community_id: Option<&str>, sensor: &str, score: f64) -> EvidenceItem {
        EvidenceItem {
            community_id: community_id.map(ToString::to_string),
            sensor: sensor.to_string(),
            score,
        }
    }

    /// Presne ten pripad, co H2 claim popisuje: 2 senzory (Zeek+Suricata) vidi
    /// STEJNY tok (stejne community_id) - naivni scoring by to spocital jako 2
    /// nezavisle potvrzeni (soucet 1.4), dependency-corrected fuze to spravne pozna
    /// jako 1 fyzicky tok (MAX 0.8, ne soucet).
    #[test]
    fn same_flow_from_two_sensors_is_not_double_counted() {
        let items = vec![
            item(Some("1:abc"), "zeek", 0.6),
            item(Some("1:abc"), "suricata", 0.8),
        ];

        let naive = naive_independent_sum(&items);
        assert!((naive - 1.4).abs() < 1e-9, "naivni soucet: {naive}");

        let fused = dependency_corrected_fusion(&items);
        assert_eq!(
            fused.len(),
            1,
            "stejne community_id musi dat JEDNU fuzovanou polozku"
        );
        assert_eq!(
            fused[0].community_id,
            Some("1:abc".to_string()),
            "fuzovana polozka si musi pamatovat, pod kterym community_id byla sloucena"
        );
        let corrected = fused_total_score(&fused);
        assert!(
            (corrected - 0.8).abs() < 1e-9,
            "korigovane skore: {corrected}"
        );
        assert!(
            corrected < naive,
            "korigovane skore ({corrected}) musi byt nizsi nez naivni soucet ({naive}) - presne ten rozdil je H2 claim"
        );
    }

    /// Opacny pripad: 2 ruzne toky (ruzne community_id) jsou skutecne nezavisla
    /// evidence - tady se SPRAVNE scita, dependency-corrected fuze nesmi zbytecne
    /// snizovat skore, kde zavislost neexistuje.
    #[test]
    fn different_flows_remain_independent_and_scores_sum() {
        let items = vec![
            item(Some("1:abc"), "zeek", 0.6),
            item(Some("1:xyz"), "zeek", 0.5),
        ];

        let naive = naive_independent_sum(&items);
        let fused = dependency_corrected_fusion(&items);
        assert_eq!(
            fused.len(),
            2,
            "2 ruzne toky musi zustat 2 samostatne polozky"
        );
        let corrected = fused_total_score(&fused);
        assert!(
            (corrected - naive).abs() < 1e-9,
            "u skutecne nezavisle evidence (ruzne toky) se korigovane a naivni skore musi shodovat: corrected={corrected} naive={naive}"
        );
    }

    /// Evidence bez community_id (napr. aktivni sken bez prirazeneho toku) nesmi
    /// byt tise slucovana s jinou evidenci bez community_id, jako by sly o stejny
    /// tok - to by byla NOVA, horsi chyba (falesna zavislost tam, kde neni zadny
    /// zaklad to tvrdit).
    #[test]
    fn evidence_without_community_id_never_merges_with_other_unlabeled_evidence() {
        let items = vec![
            item(None, "active-scan", 0.3),
            item(None, "active-scan", 0.4),
        ];
        let fused = dependency_corrected_fusion(&items);
        assert_eq!(
            fused.len(),
            2,
            "evidence bez community_id musi zustat samostatna, ne se tise slucovat"
        );
    }

    #[test]
    fn three_sensors_on_same_flow_still_cap_at_max_not_sum() {
        let items = vec![
            item(Some("1:abc"), "zeek", 0.3),
            item(Some("1:abc"), "suricata", 0.5),
            item(Some("1:abc"), "active-scan", 0.9),
        ];
        let fused = dependency_corrected_fusion(&items);
        assert_eq!(fused.len(), 1);
        assert!((fused[0].combined_score - 0.9).abs() < 1e-9);
        assert_eq!(fused[0].contributing_sensors.len(), 3);
    }

    fn event(
        source: &str,
        severity: Severity,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        message: &str,
    ) -> NormalizedEvent {
        NormalizedEvent {
            event_id: format!("{source}:{dst_ip}:{dst_port}"),
            timestamp: chrono::Utc::now(),
            src_ip: Some(src_ip.to_string()),
            src_port: Some(src_port),
            dst_ip: dst_ip.to_string(),
            proto: "tcp".to_string(),
            dst_port: Some(dst_port),
            event_type: "unexpected_traffic".to_string(),
            severity,
            source: source.to_string(),
            rule_id: None,
            message: message.to_string(),
            raw_ref: None,
            count: 1,
        }
    }

    /// Literalni H2 claim na produkcnim `NormalizedEvent`: Zeek (Low) a Suricata (High)
    /// vidi STEJNY tok (stejne src/dst/port/proto => stejne community_id) - fuze musi
    /// dat JEDEN event, ne 2, s nejvyssi severity (High), ne obe zvlast.
    #[test]
    fn events_from_two_sensors_on_same_flow_collapse_to_one_with_max_severity() {
        let events = vec![
            event(
                "zeek",
                Severity::Low,
                "10.0.0.5",
                4444,
                "10.0.0.1",
                80,
                "pasivni pozorovani",
            ),
            event(
                "suricata",
                Severity::High,
                "10.0.0.5",
                4444,
                "10.0.0.1",
                80,
                "signaturovy alert",
            ),
        ];

        let fused = fuse_same_flow_events(events);
        assert_eq!(
            fused.len(),
            1,
            "stejny tok od 2 senzoru musi dat 1 event, ne 2 nezavisla potvrzeni"
        );
        assert_eq!(fused[0].severity, Severity::High);
        assert_eq!(fused[0].source, "suricata+zeek");
        assert!(
            fused[0].message.contains("[H2 fuze:"),
            "fuzovany event musi nest marker pro decision.rs::rank_finding: {}",
            fused[0].message
        );
    }

    /// Opacny pripad: 2 JINE toky (jiny dst_port) od ruznych senzoru nejsou zavisle -
    /// musi zustat 2 samostatne eventy, fuze nesmi zbytecne slucovat nesouvisejici toky.
    #[test]
    fn events_from_two_sensors_on_different_flows_stay_separate() {
        let events = vec![
            event(
                "zeek",
                Severity::Low,
                "10.0.0.5",
                4444,
                "10.0.0.1",
                80,
                "tok A",
            ),
            event(
                "suricata",
                Severity::High,
                "10.0.0.5",
                5555,
                "10.0.0.1",
                443,
                "tok B",
            ),
        ];
        let fused = fuse_same_flow_events(events);
        assert_eq!(
            fused.len(),
            2,
            "2 ruzne toky musi zustat 2 samostatne eventy"
        );
    }

    /// Opakovane pozorovani JEDNIM senzorem (ne MEZI-senzorova zavislost) se nemusi -
    /// a nesmi - slucovat; H2 claim se tyka jen cross-senzorove korroborace.
    #[test]
    fn repeated_observations_from_a_single_sensor_are_left_untouched() {
        let events = vec![
            event(
                "zeek",
                Severity::Low,
                "10.0.0.5",
                4444,
                "10.0.0.1",
                80,
                "pozorovani 1",
            ),
            event(
                "zeek",
                Severity::Medium,
                "10.0.0.5",
                4444,
                "10.0.0.1",
                80,
                "pozorovani 2",
            ),
        ];
        let fused = fuse_same_flow_events(events);
        assert_eq!(
            fused.len(),
            2,
            "opakovane pozorovani jednim senzorem neni cross-senzor zavislost"
        );
    }

    /// Eventy bez community_id (chybejici src_port - typicky ablace A nebo
    /// multi_target_pattern) projdou beze zmeny, i kdyz by jinak "vypadaly" podobne.
    #[test]
    fn events_without_src_port_pass_through_unmerged() {
        let mut without_port = event(
            "zeek",
            Severity::Low,
            "10.0.0.5",
            4444,
            "10.0.0.1",
            80,
            "bez src_port",
        );
        without_port.src_port = None;
        let mut also_without_port = event(
            "suricata",
            Severity::High,
            "10.0.0.5",
            4444,
            "10.0.0.1",
            80,
            "take bez src_port",
        );
        also_without_port.src_port = None;

        let fused = fuse_same_flow_events(vec![without_port, also_without_port]);
        assert_eq!(
            fused.len(),
            2,
            "bez community_id se nesmi tise slucovat, i kdyz jsou od ruznych senzoru"
        );
    }

    /// Validace na REALNYCH dual-senzorovych datech (ne jen syntetickych fixturach):
    /// 172.17.0.1:49818 -> 172.17.0.2:80 tcp je presne ten tok, na kterem Deliverable 25
    /// (`docs/diplomka/eval/h2-community-id-joinkey.md`) nezavisle overil, ze realny
    /// Zeek 9.0.1 (`policy/protocols/conn/community-id-logging`) vraci
    /// `1:nTs1CSdTGlG13eI4k9WSGFAbjAw=` pro tenhle presny 5-tuple. Tenhle test overuje,
    /// ze produkcni fuze na TOMHLE realne zmerenem toku (ne na vymyslenem) spravne pozna
    /// 2 senzory jako stejny fyzicky tok - znovu-pouziva uz overenou realnou hodnotu,
    /// nespousti znovu Docker/Zeek (to uz zbytecne, hodnota je nemenna funkce 5-tuple).
    #[test]
    fn fuses_real_zeek_verified_flow_observed_by_two_sensors() {
        let real_flow_community_id = "1:nTs1CSdTGlG13eI4k9WSGFAbjAw=";

        let zeek_event = event(
            "zeek",
            Severity::Low,
            "172.17.0.1",
            49818,
            "172.17.0.2",
            80,
            "conn.log pozorovani",
        );
        assert_eq!(
            crate::passive::normalized_event_community_id(&zeek_event),
            Some(real_flow_community_id.to_string()),
            "nas vypocet community_id musi souhlasit s realne zmerenou Zeek referencni hodnotou"
        );

        let suricata_event = event(
            "suricata",
            Severity::High,
            "172.17.0.1",
            49818,
            "172.17.0.2",
            80,
            "eve.json alert",
        );

        let fused = fuse_same_flow_events(vec![zeek_event, suricata_event]);
        assert_eq!(
            fused.len(),
            1,
            "realny, nezavisle overeny tok pozorovany 2 senzory musi dat 1 fuzovany event"
        );
        assert_eq!(fused[0].severity, Severity::High);
    }

    /// Regresni test na audit nalez (Haiku, 30.10.2026): merge drive vzal `message`
    /// jen z reprezentativniho (nejvyssi severity) eventu - text ostatnich senzoru
    /// (tady CVE klicove slovo u Low-severity Zeek eventu) se tise zahodil, cimz by
    /// `decision.rs::is_cve_signal` (string-match na evidence) prestalo fungovat pro
    /// tento nalez, i kdyz CVE signal skutecne existoval.
    #[test]
    fn merged_message_preserves_text_from_every_contributing_sensor_not_just_representative() {
        let events = vec![
            event(
                "zeek",
                Severity::Low,
                "10.0.0.5",
                4444,
                "10.0.0.1",
                80,
                "CVE-2024-99999 signature observed",
            ),
            event(
                "suricata",
                Severity::High,
                "10.0.0.5",
                4444,
                "10.0.0.1",
                80,
                "generic high-severity alert",
            ),
        ];
        let fused = fuse_same_flow_events(events);
        assert_eq!(fused.len(), 1);
        assert!(
            fused[0].message.contains("CVE-2024-99999"),
            "text Zeek eventu (nizsi severity) nesmi zmizet z fuzovane zpravy: {}",
            fused[0].message
        );
        assert!(
            fused[0].message.contains("generic high-severity alert"),
            "text reprezentativniho (nejvyssi severity) eventu musi take zustat: {}",
            fused[0].message
        );
    }

    /// Regresni test na audit nalez: `count` se drive bral jen z reprezentativniho
    /// eventu, i kdyz jiny senzor ve skupine mel vyssi `count` - stejna MAX-ne-SOUCET
    /// disciplina musi platit i pro `count`, ne jen pro severity.
    #[test]
    fn merged_count_is_max_across_group_not_just_representatives_own() {
        let mut low_count_high_severity = event(
            "suricata",
            Severity::High,
            "10.0.0.5",
            4444,
            "10.0.0.1",
            80,
            "alert",
        );
        low_count_high_severity.count = 1;
        let mut high_count_low_severity = event(
            "zeek",
            Severity::Low,
            "10.0.0.5",
            4444,
            "10.0.0.1",
            80,
            "observation",
        );
        high_count_low_severity.count = 7;

        let fused = fuse_same_flow_events(vec![low_count_high_severity, high_count_low_severity]);
        assert_eq!(fused.len(), 1);
        assert_eq!(
            fused[0].count, 7,
            "count musi byt MAX pres celou skupinu (7), ne jen reprezentativniho eventu (1)"
        );
    }

    /// Regresni test na audit nalez: community_id nema casovou slozku, takze bez
    /// stropu by se znovu-pouziti efemerniho portu po dlouhe dobe (2 nesouvisejici
    /// spojeni se STEJNYM 5-tuple, hodiny od sebe) tise sloucilo, jako by slo o
    /// jeden fyzicky tok.
    #[test]
    fn events_with_same_flow_but_far_apart_in_time_do_not_merge() {
        let anchor = chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let mut early = event(
            "zeek",
            Severity::Low,
            "10.0.0.5",
            4444,
            "10.0.0.1",
            80,
            "prvni, davno promlcene spojeni",
        );
        early.timestamp = anchor;
        let mut much_later = event(
            "suricata",
            Severity::High,
            "10.0.0.5",
            4444,
            "10.0.0.1",
            80,
            "mnohem pozdejsi, nesouvisejici spojeni se stejnym efemernim portem",
        );
        much_later.timestamp = anchor + chrono::Duration::hours(3);

        let fused = fuse_same_flow_events(vec![early, much_later]);
        assert_eq!(
            fused.len(),
            2,
            "stejne community_id, ale rozptyl timestampu 3h presahuje MAX_FUSION_TIME_GAP_S - nesmi se sloucit"
        );
    }

    /// Regresni test na audit nalez behem H2 wiring: puvodni implementace grupovala
    /// eventy pres `HashMap`, jejiz iteracni poradi NENI garantovane mezi behy (ruzny
    /// hash seed) - u eventu se STEJNYM `timestamp` by to vedlo k nedeterministickemu
    /// vystupnimu poradi (presne to, co golden-snapshot test nesmi nikdy dovolit).
    /// Tenhle test ma 4 eventy se stejnym timestampem (2 nezavisle toky, kazdy
    /// pozorovany 1 senzorem - zadny z nich se neslucuje) a overuje, ze vystupni
    /// poradi vzdy presne odpovida vstupnimu poradi, opakovane.
    #[test]
    fn events_with_identical_timestamp_keep_stable_input_order_across_repeated_runs() {
        let fixed_ts = chrono::Utc::now();
        let build = || {
            vec![
                NormalizedEvent {
                    timestamp: fixed_ts,
                    ..event("zeek", Severity::Low, "10.0.0.1", 1111, "10.0.0.9", 80, "a")
                },
                NormalizedEvent {
                    timestamp: fixed_ts,
                    ..event("zeek", Severity::Low, "10.0.0.2", 2222, "10.0.0.9", 80, "b")
                },
                NormalizedEvent {
                    timestamp: fixed_ts,
                    ..event("zeek", Severity::Low, "10.0.0.3", 3333, "10.0.0.9", 80, "c")
                },
                NormalizedEvent {
                    timestamp: fixed_ts,
                    ..event("zeek", Severity::Low, "10.0.0.4", 4444, "10.0.0.9", 80, "d")
                },
            ]
        };

        let expected_order: Vec<String> =
            build().iter().map(|event| event.message.clone()).collect();
        for _ in 0..20 {
            let fused = fuse_same_flow_events(build());
            let actual_order: Vec<String> =
                fused.iter().map(|event| event.message.clone()).collect();
            assert_eq!(
                actual_order, expected_order,
                "poradi eventu se stejnym timestampem musi byt deterministicke, ne zavisle na HashMap iteraci"
            );
        }
    }

    // --- Velkoobjemovy property-based fuzz test (na zadost uzivatele: "pripravit
    // testovaci scenare a necha to paralelne testovat aspon par set tisic ruznych
    // scenaru"). Bezi PRIMO nad cistou funkci (zadne Docker/IO), proto je realne
    // provest stovky tisic az miliony scenaru v radu sekund - spoustet celý CLI
    // pipeline tolikrat by trvalo dny az tydny a nebylo by to "testovani scenaru",
    // jen zbytecne pomale opakovani stejneho byte-for-byte vstupu.

    const FUZZ_FLOWS: &[(&str, u16, &str, u16, &str)] = &[
        ("10.0.1.1", 40001, "10.0.9.1", 80, "tcp"),
        ("10.0.1.2", 40002, "10.0.9.1", 443, "tcp"),
        ("10.0.1.3", 40003, "10.0.9.2", 53, "udp"),
        ("10.0.1.4", 40004, "10.0.9.2", 22, "tcp"),
        ("10.0.1.5", 40005, "10.0.9.3", 21, "tcp"),
        ("10.0.1.6", 40006, "10.0.9.3", 23, "tcp"),
    ];
    const FUZZ_SENSORS: &[&str] = &["zeek", "suricata", "firewall"];

    fn fuzz_timestamp() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 0)
            .expect("pevny epoch timestamp")
    }

    /// Vraci (event, Some(flow_slot)) pro event se znamym, NEZAVISLE sledovanym
    /// fyzickym tokem (index do `FUZZ_FLOWS`), nebo (event, None) pro event bez
    /// src_port (community_id musi byt `None`, stejne jako u ablace A).
    fn random_fuzz_event(
        rng: &mut StdRng,
        scenario_seed: u64,
        event_index: usize,
    ) -> (NormalizedEvent, Option<usize>) {
        let sensor = FUZZ_SENSORS[rng.random_range(0..FUZZ_SENSORS.len())];
        let severity = match rng.random_range(0..3) {
            0 => Severity::Low,
            1 => Severity::Medium,
            _ => Severity::High,
        };
        let event_id = format!("fuzz:{scenario_seed}:{event_index}");
        let base = NormalizedEvent {
            event_id: event_id.clone(),
            timestamp: fuzz_timestamp(),
            src_ip: None,
            src_port: None,
            dst_ip: String::new(),
            proto: "tcp".to_string(),
            dst_port: None,
            event_type: "fuzz_event".to_string(),
            severity,
            source: sensor.to_string(),
            rule_id: None,
            message: format!("fuzz scenario={scenario_seed} idx={event_index}"),
            raw_ref: None,
            count: 1,
        };
        if rng.random_bool(0.85) {
            let slot = rng.random_range(0..FUZZ_FLOWS.len());
            let (src_ip, src_port, dst_ip, dst_port, proto) = FUZZ_FLOWS[slot];
            (
                NormalizedEvent {
                    src_ip: Some(src_ip.to_string()),
                    src_port: Some(src_port),
                    dst_ip: dst_ip.to_string(),
                    proto: proto.to_string(),
                    dst_port: Some(dst_port),
                    ..base
                },
                Some(slot),
            )
        } else {
            (base, None)
        }
    }

    /// Jeden nahodny scenar + overeni invariantu, ktere musi `fuse_same_flow_events`
    /// splnit na JAKEMKOLIV vstupu, ne jen na rucne psanych prikladech vyse.
    /// `expected_output_count`/`max_severity_by_slot` jsou pocitany NEZAVISLE na
    /// `normalized_event_community_id` (jen z vlastni znalosti, ktery event patri
    /// do ktereho `FUZZ_FLOWS` slotu) - jinak by test jen overoval produkcni kod
    /// proti sobe samemu.
    fn check_fusion_scenario(rng: &mut StdRng, scenario_seed: u64) -> Option<String> {
        let event_count = rng.random_range(1..=8usize);
        let mut events = Vec::with_capacity(event_count);
        let mut flow_slots = Vec::with_capacity(event_count);
        for event_index in 0..event_count {
            let (event, slot) = random_fuzz_event(rng, scenario_seed, event_index);
            events.push(event);
            flow_slots.push(slot);
        }
        let input_snapshot: Vec<(String, Severity)> = events
            .iter()
            .map(|event| (event.event_id.clone(), event.severity))
            .collect();

        let mut sensors_by_slot: HashMap<usize, BTreeSet<String>> = HashMap::new();
        let mut max_severity_by_slot: HashMap<usize, Severity> = HashMap::new();
        let mut event_ids_by_slot: HashMap<usize, Vec<String>> = HashMap::new();
        let mut no_flow_count = 0usize;
        for (index, slot) in flow_slots.iter().enumerate() {
            match slot {
                Some(slot) => {
                    sensors_by_slot
                        .entry(*slot)
                        .or_default()
                        .insert(events[index].source.clone());
                    event_ids_by_slot
                        .entry(*slot)
                        .or_default()
                        .push(input_snapshot[index].0.clone());
                    let entry = max_severity_by_slot
                        .entry(*slot)
                        .or_insert(input_snapshot[index].1);
                    if input_snapshot[index].1 > *entry {
                        *entry = input_snapshot[index].1;
                    }
                }
                None => no_flow_count += 1,
            }
        }
        let mergeable_slots: Vec<usize> = sensors_by_slot
            .iter()
            .filter(|(_, sensors)| sensors.len() >= 2)
            .map(|(slot, _)| *slot)
            .collect();
        let passthrough_from_slots: usize = flow_slots
            .iter()
            .filter(|slot| slot.is_some_and(|slot| sensors_by_slot[&slot].len() < 2))
            .count();
        let expected_output_count = mergeable_slots.len() + passthrough_from_slots + no_flow_count;

        let input_len = events.len();
        let fused_once = fuse_same_flow_events(events.clone());
        let fused_twice = fuse_same_flow_events(events);

        if fused_once.len() > input_len {
            return Some(format!(
                "scenar {scenario_seed}: fuze ZVYSILA pocet eventu ({input_len} -> {})",
                fused_once.len()
            ));
        }
        if fused_once.len() != expected_output_count {
            return Some(format!(
                "scenar {scenario_seed}: nezavisle pocitany ocekavany pocet ({expected_output_count}) \
                 nesouhlasi se skutecnym vystupem ({}) - flow_slots={flow_slots:?}",
                fused_once.len()
            ));
        }

        let key_of = |events: &[NormalizedEvent]| -> Vec<(String, String, Severity)> {
            events
                .iter()
                .map(|event| (event.event_id.clone(), event.source.clone(), event.severity))
                .collect()
        };
        if key_of(&fused_once) != key_of(&fused_twice) {
            return Some(format!(
                "scenar {scenario_seed}: fuze neni deterministicka na stejnem vstupu spustenem 2x"
            ));
        }

        for slot in mergeable_slots {
            let candidate_ids = &event_ids_by_slot[&slot];
            let matches: Vec<&NormalizedEvent> = fused_once
                .iter()
                .filter(|event| candidate_ids.contains(&event.event_id))
                .collect();
            if matches.len() != 1 {
                return Some(format!(
                    "scenar {scenario_seed}: slot {slot} (>=2 senzory) musi dat PRESNE 1 vystupni event, ma {}",
                    matches.len()
                ));
            }
            let expected_severity = max_severity_by_slot[&slot];
            if matches[0].severity != expected_severity {
                return Some(format!(
                    "scenar {scenario_seed}: slot {slot} - fuzovana severity {:?} != nezavisle pocitane MAX {:?}",
                    matches[0].severity, expected_severity
                ));
            }
        }

        None
    }

    fn run_fuzz_worker(base_seed: u64, scenario_count: usize) -> Option<String> {
        let mut rng = StdRng::seed_from_u64(base_seed);
        for scenario_index in 0..scenario_count {
            if let Some(violation) =
                check_fusion_scenario(&mut rng, base_seed.wrapping_add(scenario_index as u64))
            {
                return Some(violation);
            }
        }
        None
    }

    /// Vychozi pocet scenaru je zvoleny tak, aby test bezel v radu sekund pri
    /// kazdem `cargo test`. Pro tezsi, zamerny stres-beh (uzivatel chtel "idealne
    /// pres milion") nastav `BAKULA_FUZZ_SCENARIOS=1000000 cargo test --lib
    /// fusion::tests::fuse_same_flow_events_holds_invariants_across_many_random_scenarios`.
    #[test]
    fn fuse_same_flow_events_holds_invariants_across_many_random_scenarios() {
        let total_scenarios: usize = std::env::var("BAKULA_FUZZ_SCENARIOS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(200_000);
        let worker_count = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(4);
        let base_seed: u64 = 0x5A17_u64;

        let started = std::time::Instant::now();
        let violation = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..worker_count)
                .map(|worker_index| {
                    let scenarios_for_worker = total_scenarios / worker_count
                        + usize::from(worker_index < total_scenarios % worker_count);
                    let worker_seed = base_seed.wrapping_add((worker_index as u64) * 1_000_000_007);
                    scope.spawn(move || run_fuzz_worker(worker_seed, scenarios_for_worker))
                })
                .collect();
            handles
                .into_iter()
                .find_map(|handle| handle.join().expect("fuzz worker nesmi panikarit"))
        });
        let elapsed = started.elapsed();
        println!(
            "fuse_same_flow_events fuzz: {total_scenarios} scenaru na {worker_count} OS vlaknech za {elapsed:.2?}"
        );

        if let Some(message) = violation {
            panic!("{message}");
        }
    }
}
