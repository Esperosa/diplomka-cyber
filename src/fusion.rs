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

/// H2 krok 4: produkcni vstupni bod, viz modulova dokumentace. Eventy bez
/// `community_id` (chybejici src_port/nepodporovany protokol - typicky ablace A nebo
/// multi-cil `multi_target_pattern`) a eventy se stejnym jedinym senzorem (opakovane
/// pozorovani JEDNIM senzorem, ne MEZI-senzorova zavislost) projdou beze zmeny.
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
        if sensors.len() < 2 {
            // Jeden a tyz senzor pozoroval tok vicekrat - opakovani, ne zavislost
            // MEZI senzory. H2 claim se tyka jen cross-senzorove korroborace.
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

    let mut representative = group
        .into_iter()
        .find(|event| event.severity == representative_severity)
        .expect(
            "fuzovana skupina musi obsahovat alespon jeden event s max severity ze vstupnich polozek",
        );

    let sensor_list = sensors.join("+");
    representative.message = format!(
        "[H2 fuze: potvrzeno senzory {sensor_list}, stejny tok] {}",
        representative.message
    );
    representative.source = sensor_list;
    representative
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
