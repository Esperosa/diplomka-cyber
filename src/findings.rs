use std::collections::BTreeSet;

use crate::model::{
    Confidence, CveRecord, Finding, HostReport, RunReport, ServiceReport, Severity,
};

/// Cil, do ktereho pravidla pridavaji nalezy. Poradi pridani je soucasti
/// kontraktu: `deduplicate_findings` nechava prvni vyskyt `finding_id` a final
/// razeni je stabilni, takze poradi pravidel ovlivnuje vystup.
pub(crate) type FindingSink = Vec<Finding>;

/// Pravidlo nad celym reportem (nezavisle na konkretni sluzbe).
type ReportRule = fn(&RunReport, &mut FindingSink);
/// Pravidlo nad jednou sluzbou jednoho hosta.
type ServiceRule = fn(&ServiceContext<'_>, &mut FindingSink);

struct ServiceContext<'a> {
    report: &'a RunReport,
    host: &'a HostReport,
    service: &'a ServiceReport,
}

/// Pravidla PRED prochazenim sluzeb (puvodni poradi: nejdriv unmapped udalosti).
const PRE_RULES: &[(&str, ReportRule)] = &[("unmapped_passive_event", rule_unmapped_passive_event)];

/// Pravidla uvnitr smycky host -> sluzba, VZDY ve stejnem poradi pro kazdou
/// sluzbu (puvodni poradi `generate_findings` - interleaving per sluzba).
const SERVICE_RULES: &[(&str, ServiceRule)] = &[
    ("active_checks", rule_active_checks),
    (
        "known_exploited_vulnerability",
        rule_known_exploited_vulnerability,
    ),
    (
        "probable_exploitation_interest",
        rule_probable_exploitation_interest,
    ),
    ("high_risk_cve_exposure", rule_high_risk_cve_exposure),
    (
        "plaintext_management_protocol",
        rule_plaintext_management_protocol,
    ),
    ("http_basic_without_tls", rule_http_basic_without_tls),
    ("insecure_auth_possible", rule_insecure_auth_possible),
    ("unexpected_traffic", rule_unexpected_traffic),
    ("connection_timeout_burst", rule_connection_timeout_burst),
    ("packet_rate_spike", rule_packet_rate_spike),
    ("packet_loss_signal", rule_packet_loss_signal),
    ("service_overload_risk", rule_service_overload_risk),
    ("inductive_volume_anomaly", rule_inductive_volume_anomaly),
    (
        "management_surface_exposure",
        rule_management_surface_exposure,
    ),
    ("identification_gap", rule_identification_gap),
    ("correlation_uncertainty", rule_correlation_uncertainty),
];

/// Pravidla PO prochazeni sluzeb (diff, externi intel).
const POST_RULES: &[(&str, ReportRule)] = &[
    ("new_exposed_service", rule_new_exposed_service),
    ("intel_match", rule_intel_match),
];

/// Nazvy pravidel v poradi vykonani (pro test stability poradi).
#[cfg(test)]
fn rule_names() -> Vec<&'static str> {
    PRE_RULES
        .iter()
        .map(|(name, _)| *name)
        .chain(SERVICE_RULES.iter().map(|(name, _)| *name))
        .chain(POST_RULES.iter().map(|(name, _)| *name))
        .collect()
}

pub fn generate_findings(report: &RunReport) -> Vec<Finding> {
    let mut findings: FindingSink = Vec::new();

    for (_, rule) in PRE_RULES {
        rule(report, &mut findings);
    }
    for host in &report.hosts {
        for service in &host.services {
            let context = ServiceContext {
                report,
                host,
                service,
            };
            for (_, rule) in SERVICE_RULES {
                rule(&context, &mut findings);
            }
        }
    }
    for (_, rule) in POST_RULES {
        rule(report, &mut findings);
    }

    deduplicate_findings(findings)
}

/// Engine v3 (krok 1C, R13): nálezy, které legacy pravidla neznají. `scan_attempts`
/// = pokusy bez odpovědi přičtené ZDROJI (sken, průzkum), připojené k nejčastějšímu
/// cíli. Legacy detektor tyto události nevydává, takže legacy výstup se nemění.
pub fn v3_extra_findings(report: &RunReport) -> Vec<Finding> {
    let mut findings = Vec::new();
    for host in &report.hosts {
        for service in &host.services {
            let events: Vec<_> = service
                .events
                .iter()
                .filter(|item| item.event.event_type == "scan_attempts")
                .collect();
            let Some(strongest) = events.iter().max_by_key(|item| item.event.severity) else {
                continue;
            };
            findings.push(Finding {
                finding_id: build_finding_id(
                    "scan_attempts",
                    Some(&host.host_key),
                    Some(&service.service_key),
                ),
                finding_type: "scan_attempts".to_string(),
                title: format!(
                    "Na cíl {} míří opakované pokusy o spojení bez odpovědi (sken)",
                    service.service_key
                ),
                severity: strongest.event.severity,
                confidence: Confidence::Medium,
                host_key: Some(host.host_key.clone()),
                service_key: Some(service.service_key.clone()),
                rationale:
                    "Jeden zdroj zkouší mnoho cílů nebo portů a nedostává odpověď; pokusy se přičítají zdroji, ne cílové službě."
                        .to_string(),
                evidence: build_protocol_evidence(service, "scan_attempts"),
                recommendation:
                    "Ověřit, zda je zdroj autorizovaný skener; jinak omezit jeho přístup a prověřit, zda nenásleduje úspěšné spojení."
                        .to_string(),
            });
        }
    }
    findings
}

/// Engine v3 (krok 1C, audit A13): `unmapped_passive_event` se neskládá po
/// jednotlivých událostech (id obsahovalo `event_id` s počtem, takže každý cyklus
/// vznikl nový nález), ale jeden nález na (cíl, protokol, port, typ události).
pub fn aggregate_unmapped_findings(findings: &mut Vec<Finding>, report: &RunReport) {
    let by_event: std::collections::HashMap<&str, &crate::model::CorrelatedEvent> = report
        .unmapped_events
        .iter()
        .map(|event| (event.event.event_id.as_str(), event))
        .collect();
    let prefix = "finding:unmapped_passive_event:-:";
    for finding in findings.iter_mut() {
        if finding.finding_type != "unmapped_passive_event" {
            continue;
        }
        let Some(event) = finding
            .finding_id
            .strip_prefix(prefix)
            .and_then(|id| by_event.get(id))
        else {
            continue;
        };
        let e = &event.event;
        let target = format!(
            "{}/{}/{}",
            e.dst_ip,
            e.proto,
            e.dst_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".into())
        );
        finding.finding_id = format!(
            "finding:unmapped_passive_event:{}:{target}:{}",
            e.dst_ip, e.event_type
        );
        finding.service_key = Some(target);
    }
    let mut seen = BTreeSet::new();
    findings.retain(|finding| seen.insert(finding.finding_id.clone()));
}

/// Pasivni udalost bez mapovani na aktivni inventar.
fn rule_unmapped_passive_event(report: &RunReport, findings: &mut FindingSink) {
    for event in &report.unmapped_events {
        findings.push(Finding {
            finding_id: format!("finding:unmapped_passive_event:-:{}", event.event.event_id),
            finding_type: "unmapped_passive_event".to_string(),
            title: "Pasivní událost jsem nespároval s aktivním inventářem".to_string(),
            severity: event.event.severity,
            confidence: event.correlation.confidence,
            host_key: None,
            service_key: None,
            rationale:
                "Pasivní vrstva mi ukázala bezpečnostní signál pro cíl, který v aktivním inventáři nemám. Nezahazuji ho, protože může jít o skrytou službu, host mimo rozsah skenu nebo mezeru ve viditelnosti aktivního běhu."
                    .to_string(),
            evidence: build_unmapped_event_evidence(event),
            recommendation:
                "Zkontrolovat rozsah Nmap skenu, dostupnost senzoru a podle cílové IP nebo portu spustit cílený follow-up scan."
                    .to_string(),
        });
    }
}

/// Nova sluzba mezi behy (diff).
fn rule_new_exposed_service(report: &RunReport, findings: &mut FindingSink) {
    if let Some(diff) = &report.diff {
        for service_change in &diff.changed_services {
            if service_change.change_type != "nova_sluzba" {
                continue;
            }
            findings.push(Finding {
                finding_id: build_finding_id(
                    "new_exposed_service",
                    None,
                    Some(&service_change.service_key),
                ),
                finding_type: "new_exposed_service".to_string(),
                title: format!(
                    "Mezi běhy se objevila nově exponovaná služba {}",
                    service_change.service_key
                ),
                severity: service_change_severity(&service_change.service_key),
                confidence: Confidence::High,
                host_key: Some(extract_host_key(&service_change.service_key)),
                service_key: Some(service_change.service_key.clone()),
                rationale:
                    "Diff potvrdil změnu inventáře proti předchozímu běhu; nová služba může představovat legitimní změnu i nové riziko."
                        .to_string(),
                evidence: vec![
                    format!("change_type={}", service_change.change_type),
                    format!("after={}", service_change.after.clone().unwrap_or_default()),
                ],
                recommendation:
                    "Ověřit důvod zpřístupnění služby, zkontrolovat vlastnictví změny, autorizaci a případně doplnit monitorovací nebo hardening opatření."
                        .to_string(),
            });
        }
    }
}

/// Shoda z externiho intel feedu.
fn rule_intel_match(report: &RunReport, findings: &mut FindingSink) {
    for intel in &report.intel_matches {
        findings.push(Finding {
            finding_id: format!("finding:intel:{}", intel.match_id),
            finding_type: format!("intel:{}", intel.source.to_ascii_lowercase().replace(' ', "-")),
            title: format!("Externí intel vrstva vrátila shodu pro {}", intel.indicator),
            severity: intel.severity,
            confidence: intel.confidence,
            host_key: intel.linked_host_key.clone(),
            service_key: intel.linked_service_key.clone(),
            rationale:
                "Shoda z reputačního nebo IOC feedu sama o sobě nenahrazuje lokální důkaz, ale zvyšuje prioritu ručního ověření a doplnění kontextu."
                    .to_string(),
            evidence: intel
                .references
                .iter()
                .cloned()
                .chain(std::iter::once(format!("status={}", intel.status)))
                .collect(),
            recommendation:
                "Potvrdit indikátor proti lokálním logům, flow telemetrii nebo host-level artefaktům a zachovat oddělení mezi externí reputací a doloženým lokálním stavem."
                    .to_string(),
        });
    }
}

/// Aktivni webove kontroly (nuclei/httpx) potvrzene na sluzbe.
fn rule_active_checks(context: &ServiceContext<'_>, findings: &mut FindingSink) {
    let ServiceContext { host, service, .. } = context;
    for check in &service.active_checks {
        findings.push(Finding {
            finding_id: build_finding_id(
                &format!("active_check_{}", check.template_id),
                Some(&host.host_key),
                Some(&service.service_key),
            ),
            finding_type: format!("active_check:{}", check.template_id),
            title: format!(
                "Aktivní webová kontrola potvrdila nález na {}",
                service.service_key
            ),
            severity: check.severity,
            confidence: check.confidence,
            host_key: Some(host.host_key.clone()),
            service_key: Some(service.service_key.clone()),
            rationale: active_check_rationale(check),
            evidence: build_active_check_evidence(check),
            recommendation: active_check_recommendation(&check.template_id),
        });
    }
}

/// CVE vedena v CISA KEV.
fn rule_known_exploited_vulnerability(context: &ServiceContext<'_>, findings: &mut FindingSink) {
    let ServiceContext { host, service, .. } = context;
    let kev_cves = service
        .cves
        .iter()
        .filter(|item| is_known_exploited(item))
        .collect::<Vec<_>>();
    if !kev_cves.is_empty() {
        findings.push(Finding {
            finding_id: build_finding_id(
                "known_exploited_vulnerability",
                Some(&host.host_key),
                Some(&service.service_key),
            ),
            finding_type: "known_exploited_vulnerability".to_string(),
            title: format!(
                "Služba {} obsahuje zranitelnost vedenou v CISA KEV",
                service.service_key
            ),
            severity: Severity::High,
            confidence: Confidence::High,
            host_key: Some(host.host_key.clone()),
            service_key: Some(service.service_key.clone()),
            rationale:
                "Minimálně jedna navázaná CVE je vedena v katalogu CISA Known Exploited Vulnerabilities, tedy existuje veřejně doložený kontext reálného zneužívání."
                    .to_string(),
            evidence: build_specific_cve_evidence(&kev_cves),
            recommendation:
                "Zařadit službu mezi prioritní kandidáty k bezprostřednímu ověření, potvrdit skutečnou verzi a stav patchingu a podle potřeby urychlit mitigaci nebo omezení expozice."
                    .to_string(),
        });
    }
}

/// EPSS >= 0.3 u navazanych CVE.
fn rule_probable_exploitation_interest(context: &ServiceContext<'_>, findings: &mut FindingSink) {
    let ServiceContext { host, service, .. } = context;
    let high_epss = service
        .cves
        .iter()
        .filter_map(|item| {
            item.exploit_context
                .as_ref()
                .and_then(|context| context.epss.as_ref())
                .map(|epss| (item, epss.score))
        })
        .filter(|(_, score)| *score >= 0.3)
        .collect::<Vec<_>>();
    if !high_epss.is_empty() {
        let max_epss = high_epss
            .iter()
            .map(|(_, score)| *score)
            .fold(0.0_f64, f64::max);
        findings.push(Finding {
            finding_id: build_finding_id(
                "probable_exploitation_interest",
                Some(&host.host_key),
                Some(&service.service_key),
            ),
            finding_type: "probable_exploitation_interest".to_string(),
            title: format!(
                "Služba {} má zvýšený pravděpodobnostní zájem útočníků",
                service.service_key
            ),
            severity: if max_epss >= 0.7 {
                Severity::High
            } else {
                Severity::Medium
            },
            confidence: Confidence::Medium,
            host_key: Some(host.host_key.clone()),
            service_key: Some(service.service_key.clone()),
            rationale: format!(
                "EPSS signalizuje zvýšenou pravděpodobnost zneužití u navázaných CVE; maximální zjištěná hodnota je {:.3}.",
                max_epss
            ),
            evidence: build_epss_evidence(service, 0.3),
            recommendation:
                "Použít výsledek pro priorizaci ručního ověření a patchingu, ale zachovat auditní stopu: EPSS je pomocný pravděpodobnostní signál, nikoli důkaz exploitu v konkrétní síti."
                    .to_string(),
        });
    }
}

/// Nejvyssi CVSS >= 7.0.
fn rule_high_risk_cve_exposure(context: &ServiceContext<'_>, findings: &mut FindingSink) {
    let ServiceContext { host, service, .. } = context;
    let max_cvss = service
        .cves
        .iter()
        .filter_map(|item| item.cvss.as_ref().map(|cvss| cvss.base_score))
        .fold(0.0_f64, f64::max);

    if max_cvss >= 7.0 {
        let severity = if max_cvss >= 9.0 {
            Severity::High
        } else {
            Severity::Medium
        };
        let confidence = service
            .cpe
            .first()
            .map(|candidate| candidate.confidence)
            .unwrap_or(Confidence::Medium);
        findings.push(Finding {
            finding_id: build_finding_id(
                "high_risk_cve_exposure",
                Some(&host.host_key),
                Some(&service.service_key),
            ),
            finding_type: "high_risk_cve_exposure".to_string(),
            title: format!(
                "Služba {} obsahuje zranitelnosti s vysokou prioritou",
                service.service_key
            ),
            severity,
            confidence,
            host_key: Some(host.host_key.clone()),
            service_key: Some(service.service_key.clone()),
            rationale: format!(
                "Nejvyšší nalezené CVSS je {:.1}; výstup slouží jako podklad pro priorizaci a další ověření.",
                max_cvss
            ),
            evidence: build_cve_evidence(service),
            recommendation: "Ověřit skutečnou verzi a konfiguraci služby proti vendor advisory, naplánovat patch nebo kompenzační opatření a případně omezit síťovou expozici.".to_string(),
        });
    }
}

/// Telnet/FTP/... bez sifrovani.
fn rule_plaintext_management_protocol(context: &ServiceContext<'_>, findings: &mut FindingSink) {
    let ServiceContext { host, service, .. } = context;
    if is_plaintext_management(service) {
        let protocol = plaintext_protocol_label(service);
        findings.push(Finding {
            finding_id: build_finding_id(
                "plaintext_management_protocol",
                Some(&host.host_key),
                Some(&service.service_key),
            ),
            finding_type: "plaintext_management_protocol".to_string(),
            title: format!(
                "{} na službě {} nepoužívá šifrovaný přenos",
                protocol, service.service_key
            ),
            severity: if service
                .inventory
                .service_name
                .eq_ignore_ascii_case("telnet")
            {
                Severity::High
            } else {
                Severity::Medium
            },
            confidence: event_confidence(service, "plaintext_protocol")
                .unwrap_or(service.inventory.confidence),
            host_key: Some(host.host_key.clone()),
            service_key: Some(service.service_key.clone()),
            rationale: plaintext_protocol_rationale(service),
            evidence: build_protocol_evidence(service, "plaintext_protocol"),
            recommendation: plaintext_protocol_recommendation(service),
        });
    }
}

/// HTTP Basic bez TLS (ne pro nove exponovanou sluzbu).
fn rule_http_basic_without_tls(context: &ServiceContext<'_>, findings: &mut FindingSink) {
    let ServiceContext {
        report,
        host,
        service,
        ..
    } = context;
    let has_http_basic_without_tls = service
        .events
        .iter()
        .any(|item| item.event.event_type == "http_basic_without_tls");
    if has_http_basic_without_tls && !is_new_exposed_service_target(report, &service.service_key) {
        findings.push(Finding {
            finding_id: build_finding_id(
                "http_basic_without_tls",
                Some(&host.host_key),
                Some(&service.service_key),
            ),
            finding_type: "http_basic_without_tls".to_string(),
            title: format!(
                "Na službě {} byla pozorována autentizace bez TLS",
                service.service_key
            ),
            severity: Severity::High,
            confidence: event_confidence(service, "http_basic_without_tls")
                .unwrap_or(Confidence::Medium),
            host_key: Some(host.host_key.clone()),
            service_key: Some(service.service_key.clone()),
            rationale:
                "Použití HTTP Basic bez šifrovaného kanálu vystavuje přihlašovací údaje odposlechu."
                    .to_string(),
            evidence: build_protocol_evidence(service, "http_basic_without_tls"),
            recommendation:
                "Vynutit TLS, odstranit Basic autentizaci na HTTP endpointu nebo ji přesunout za reverzní proxy s TLS terminací a silnějším ověřením."
                    .to_string(),
        });
    }
}

/// Heuristika mozneho nezabezpeceneho prihlaseni.
fn rule_insecure_auth_possible(context: &ServiceContext<'_>, findings: &mut FindingSink) {
    let ServiceContext { host, service, .. } = context;
    if service
        .events
        .iter()
        .any(|item| item.event.event_type == "insecure_auth_possible")
    {
        findings.push(Finding {
            finding_id: build_finding_id(
                "insecure_auth_possible",
                Some(&host.host_key),
                Some(&service.service_key),
            ),
            finding_type: "insecure_auth_possible".to_string(),
            title: format!(
                "Na službě {} byla zjištěna heuristika možného nezabezpečeného přihlášení",
                service.service_key
            ),
            severity: Severity::Low,
            confidence: event_confidence(service, "insecure_auth_possible")
                .unwrap_or(Confidence::Low),
            host_key: Some(host.host_key.clone()),
            service_key: Some(service.service_key.clone()),
            rationale:
                "Heuristika signalizuje přístup na přihlašovací endpoint bez důkazu přenesených credentials; slouží jen jako podnět k ručnímu ověření."
                    .to_string(),
            evidence: build_protocol_evidence(service, "insecure_auth_possible"),
            recommendation:
                "Prověřit, zda endpoint skutečně pracuje bez TLS, a případně sjednotit přihlašování výhradně přes HTTPS."
                    .to_string(),
        });
    }
}

/// Provoz mimo aktivni inventar (ne pro nove exponovanou sluzbu).
fn rule_unexpected_traffic(context: &ServiceContext<'_>, findings: &mut FindingSink) {
    let ServiceContext {
        report,
        host,
        service,
        ..
    } = context;
    let has_unexpected_traffic = service
        .events
        .iter()
        .any(|item| item.event.event_type == "unexpected_traffic");
    if has_unexpected_traffic && !is_new_exposed_service_target(report, &service.service_key) {
        findings.push(Finding {
            finding_id: build_finding_id(
                "unexpected_traffic",
                Some(&host.host_key),
                Some(&service.service_key),
            ),
            finding_type: "unexpected_traffic".to_string(),
            title: format!(
                "Na cíli {} byl zaznamenán provoz mimo aktivní inventář",
                service.service_key
            ),
            severity: Severity::Low,
            confidence: event_confidence(service, "unexpected_traffic")
                .unwrap_or(Confidence::Low),
            host_key: Some(host.host_key.clone()),
            service_key: Some(service.service_key.clone()),
            rationale:
                "Pasivní vrstva zaznamenala komunikaci na port nebo službu, které se nepotvrdily aktivním během; může jít o krátkodobou expozici, mezeru ve viditelnosti nebo chybu korelace."
                    .to_string(),
            evidence: build_protocol_evidence(service, "unexpected_traffic"),
            recommendation:
                "Ověřit aktivním opakováním, zda služba nebyla dostupná jen krátce, a prověřit topologii senzoru i pravidla filtrace."
                    .to_string(),
        });
    }
}

/// Opakovane timeouty/retry.
fn rule_connection_timeout_burst(context: &ServiceContext<'_>, findings: &mut FindingSink) {
    let ServiceContext { host, service, .. } = context;
    let timeout_burst_present = service
        .events
        .iter()
        .any(|item| item.event.event_type == "connection_timeout_burst");
    if timeout_burst_present {
        findings.push(Finding {
            finding_id: build_finding_id(
                "connection_timeout_burst",
                Some(&host.host_key),
                Some(&service.service_key),
            ),
            finding_type: "connection_timeout_burst".to_string(),
            title: format!(
                "Na službě {} je zvýšený výskyt timeout/retry provozu",
                service.service_key
            ),
            severity: if max_event_count(service, "connection_timeout_burst") >= 4 {
                Severity::High
            } else {
                Severity::Medium
            },
            confidence: event_confidence(service, "connection_timeout_burst")
                .unwrap_or(Confidence::Medium),
            host_key: Some(host.host_key.clone()),
            service_key: Some(service.service_key.clone()),
            rationale:
                "Pasivní vrstva zachytila opakované timeouty/retry stavy, které často doprovází přetížení, nestabilní cestu nebo agresivní skenovací vzor."
                    .to_string(),
            evidence: build_protocol_evidence(service, "connection_timeout_burst"),
            recommendation:
                "Prověřit limity služby, fronty, firewall a transportní retry chování. Pokud jde o útok nebo burst sken, dočasně aplikovat přísnější rate limit a segmentaci."
                    .to_string(),
        });
    }
}

/// Spicka packet-rate.
fn rule_packet_rate_spike(context: &ServiceContext<'_>, findings: &mut FindingSink) {
    let ServiceContext { host, service, .. } = context;
    let rate_spike_present = service
        .events
        .iter()
        .any(|item| item.event.event_type == "packet_rate_spike");
    if rate_spike_present {
        findings.push(Finding {
            finding_id: build_finding_id(
                "packet_rate_spike",
                Some(&host.host_key),
                Some(&service.service_key),
            ),
            finding_type: "packet_rate_spike".to_string(),
            title: format!(
                "Na službě {} byla detekována špička rychlosti paketů",
                service.service_key
            ),
            severity: if max_event_count(service, "packet_rate_spike") >= 5 {
                Severity::High
            } else {
                Severity::Medium
            },
            confidence: event_confidence(service, "packet_rate_spike")
                .unwrap_or(Confidence::Medium),
            host_key: Some(host.host_key.clone()),
            service_key: Some(service.service_key.clone()),
            rationale:
                "Detektor zaznamenal neobvykle vysokou packet-rate vůči běžnému průběhu služby; to je praktický signál rizika degradace a nedostupnosti."
                    .to_string(),
            evidence: build_protocol_evidence(service, "packet_rate_spike"),
            recommendation:
                "Doplnit limitaci pps/bps, ověřit capacity plán a připravit burst-profil obrany (dočasný shaper, ACL nebo agresivnější WAF/IPS režim)."
                    .to_string(),
        });
    }
}

/// Signaly ztrat paketu.
fn rule_packet_loss_signal(context: &ServiceContext<'_>, findings: &mut FindingSink) {
    let ServiceContext { host, service, .. } = context;
    if service
        .events
        .iter()
        .any(|item| item.event.event_type == "packet_loss_signal")
    {
        findings.push(Finding {
            finding_id: build_finding_id(
                "packet_loss_signal",
                Some(&host.host_key),
                Some(&service.service_key),
            ),
            finding_type: "packet_loss_signal".to_string(),
            title: format!(
                "Na službě {} se objevují signály ztrát paketů",
                service.service_key
            ),
            severity: Severity::Medium,
            confidence: event_confidence(service, "packet_loss_signal")
                .unwrap_or(Confidence::Medium),
            host_key: Some(host.host_key.clone()),
            service_key: Some(service.service_key.clone()),
            rationale:
                "Opakované missed-bytes/loss signály mohou být důsledkem přetížení cesty, front nebo nestability síťového prvku."
                    .to_string(),
            evidence: build_protocol_evidence(service, "packet_loss_signal"),
            recommendation:
                "Prověřit queue drops, duplex/MTU mismatch, policery a využití uplinků; při potvrzení zavést konzervativnější traffic shaping."
                    .to_string(),
        });
    }
}

/// Riziko pretizeni sluzby.
fn rule_service_overload_risk(context: &ServiceContext<'_>, findings: &mut FindingSink) {
    let ServiceContext { host, service, .. } = context;
    let overload_present = service
        .events
        .iter()
        .any(|item| item.event.event_type == "service_overload_risk");
    if overload_present {
        findings.push(Finding {
            finding_id: build_finding_id(
                "service_overload_risk",
                Some(&host.host_key),
                Some(&service.service_key),
            ),
            finding_type: "service_overload_risk".to_string(),
            title: format!(
                "Služba {} vykazuje riziko přetížení a degradace",
                service.service_key
            ),
            severity: Severity::High,
            confidence: event_confidence(service, "service_overload_risk")
                .unwrap_or(Confidence::High),
            host_key: Some(host.host_key.clone()),
            service_key: Some(service.service_key.clone()),
            rationale:
                "Kombinace timeoutů, rate spike a provozního tlaku indikuje, že služba může být na hraně kapacity nebo pod aktivním tlakem."
                    .to_string(),
            evidence: build_protocol_evidence(service, "service_overload_risk"),
            recommendation:
                "Aktivovat agresivnější ochranu: krátkodobý rate-limit, přísnější ACL/WAF pravidla, priorizace provozu a audit kapacitního stropu."
                    .to_string(),
        });
    }
}

/// Indukcni detektor objemu.
fn rule_inductive_volume_anomaly(context: &ServiceContext<'_>, findings: &mut FindingSink) {
    let ServiceContext { host, service, .. } = context;
    if service
        .events
        .iter()
        .any(|item| item.event.event_type == "inductive_volume_anomaly")
    {
        findings.push(Finding {
            finding_id: build_finding_id(
                "inductive_volume_anomaly",
                Some(&host.host_key),
                Some(&service.service_key),
            ),
            finding_type: "inductive_volume_anomaly".to_string(),
            title: format!(
                "Induktivní detektor označil netypický provoz na {}",
                service.service_key
            ),
            severity: Severity::High,
            confidence: event_confidence(service, "inductive_volume_anomaly")
                .unwrap_or(Confidence::Medium),
            host_key: Some(host.host_key.clone()),
            service_key: Some(service.service_key.clone()),
            rationale:
                "Nález vznikl datovou indukcí (outlier model nad objemem a rychlostí), nikoliv přímou šablonou signatur. To rozšiřuje detekci i na dosud neznámé vzory."
                    .to_string(),
            evidence: build_protocol_evidence(service, "inductive_volume_anomaly"),
            recommendation:
                "Spustit cílené forenzní ověření provozu, porovnat s business baseline a podle výsledku upravit adaptivní pravidla pro agresivní mitigaci."
                    .to_string(),
        });
    }
}

/// Exponovana spravcovska/interni plocha.
fn rule_management_surface_exposure(context: &ServiceContext<'_>, findings: &mut FindingSink) {
    let ServiceContext { host, service, .. } = context;
    if is_management_surface(service) {
        findings.push(Finding {
            finding_id: build_finding_id(
                "management_surface_exposure",
                Some(&host.host_key),
                Some(&service.service_key),
            ),
            finding_type: "management_surface_exposure".to_string(),
            title: format!(
                "Služba {} představuje exponovanou správcovskou nebo interní plochu",
                service.service_key
            ),
            severity: management_surface_severity(service.port),
            confidence: service.inventory.confidence,
            host_key: Some(host.host_key.clone()),
            service_key: Some(service.service_key.clone()),
            rationale:
                "Na otevřeném portu byla zjištěna služba typická pro správu, sdílení nebo interní databázový provoz; bez kontextu použití jde o kandidáta k ověření expozice."
                    .to_string(),
            evidence: vec![
                format!("service_key={}", service.service_key),
                format!(
                    "service_name={} | product={} | version={}",
                    service.inventory.service_name,
                    service.inventory.product.clone().unwrap_or_else(|| "-".to_string()),
                    service.inventory.version.clone().unwrap_or_else(|| "-".to_string())
                ),
            ],
            recommendation:
                "Ověřit, zda má být služba dostupná z daného segmentu, a případně omezit přístup segmentací, firewall pravidly nebo přesunem za VPN či správní zónu."
                    .to_string(),
        });
    }
}

/// Otevrena sluzba bez presne identifikace.
fn rule_identification_gap(context: &ServiceContext<'_>, findings: &mut FindingSink) {
    let ServiceContext { host, service, .. } = context;
    if service.port_state == "open" && has_identification_gap(service) {
        findings.push(Finding {
            finding_id: build_finding_id(
                "identification_gap",
                Some(&host.host_key),
                Some(&service.service_key),
            ),
            finding_type: "identification_gap".to_string(),
            title: format!(
                "Otevřená služba {} nemá dostatečně přesnou identifikaci",
                service.service_key
            ),
            severity: Severity::Low,
            confidence: Confidence::Low,
            host_key: Some(host.host_key.clone()),
            service_key: Some(service.service_key.clone()),
            rationale:
                "Služba je dostupná, ale chybí přesná verze nebo jednoznačný produkt; to omezuje kvalitu následného CPE/CVE obohacení."
                    .to_string(),
            evidence: vec![
                format!("service_key={}", service.service_key),
                format!(
                    "service_name={} | product={} | version={} | confidence={:?}",
                    service.inventory.service_name,
                    service.inventory.product.clone().unwrap_or_else(|| "-".to_string()),
                    service.inventory.version.clone().unwrap_or_else(|| "-".to_string()),
                    service.inventory.confidence
                ),
            ],
            recommendation:
                "Doplnit detailnější fingerprinting, banner grab nebo kurátorované mapování služby, aby bylo možné přesněji hodnotit riziko a verzní stav."
                    .to_string(),
        });
    }
}

/// Udalosti s nizsi jistotou korelace.
fn rule_correlation_uncertainty(context: &ServiceContext<'_>, findings: &mut FindingSink) {
    let ServiceContext { host, service, .. } = context;
    let uncertain_events = service
        .events
        .iter()
        .filter(|item| item.correlation.method != "ip+port")
        .collect::<Vec<_>>();
    if !uncertain_events.is_empty() {
        findings.push(Finding {
            finding_id: build_finding_id(
                "correlation_uncertainty",
                Some(&host.host_key),
                Some(&service.service_key),
            ),
            finding_type: "correlation_uncertainty".to_string(),
            title: format!(
                "Korelace pro {} obsahuje události s nižší jistotou",
                service.service_key
            ),
            severity: Severity::Low,
            confidence: Confidence::Low,
            host_key: Some(host.host_key.clone()),
            service_key: Some(service.service_key.clone()),
            rationale:
                "Část událostí byla přiřazena pouze na úrovni hostu nebo zůstala neúplně mapována; to je z metodického hlediska korektní, ale snižuje přesnost závěru."
                    .to_string(),
            evidence: uncertain_events
                .iter()
                .map(|item| {
                    format!(
                        "{} | {} | {}",
                        item.event.event_type, item.correlation.method, item.event.message
                    )
                })
                .collect(),
            recommendation:
                "Rozšířit viditelnost senzoru, doplnit portový kontext nebo kurátorované korelační výjimky tam, kde je vazba opakovaně nejednoznačná."
                    .to_string(),
        });
    }
}

fn deduplicate_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen = BTreeSet::new();
    let mut unique = Vec::new();
    for finding in findings {
        if seen.insert(finding.finding_id.clone()) {
            unique.push(finding);
        }
    }
    unique.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then(right.confidence.cmp(&left.confidence))
            .then(left.title.cmp(&right.title))
    });
    unique
}

fn build_finding_id(
    finding_type: &str,
    host_key: Option<&str>,
    service_key: Option<&str>,
) -> String {
    format!(
        "finding:{}:{}:{}",
        finding_type,
        host_key.unwrap_or("-"),
        service_key.unwrap_or("-")
    )
}

fn build_cve_evidence(service: &ServiceReport) -> Vec<String> {
    let mut evidence = vec![format!("service_key={}", service.service_key)];
    if let Some(candidate) = service.cpe.first() {
        evidence.push(format!(
            "cpe={} | method={} | confidence={:?}",
            candidate.cpe23_uri, candidate.method, candidate.confidence
        ));
    }
    evidence.extend(service.cves.iter().filter_map(|item| {
        let mut parts = Vec::new();
        if let Some(cvss) = &item.cvss {
            parts.push(format!("CVSS {} {:.1}", cvss.version, cvss.base_score));
        }
        if let Some(epss) = item
            .exploit_context
            .as_ref()
            .and_then(|context| context.epss.as_ref())
        {
            parts.push(format!("EPSS {:.3}", epss.score));
        }
        if item
            .exploit_context
            .as_ref()
            .and_then(|context| context.cisa_kev.as_ref())
            .is_some()
        {
            parts.push("CISA-KEV".to_string());
        }
        (!parts.is_empty()).then(|| format!("{} | {}", item.cve_id, parts.join(" | ")))
    }));
    evidence
}

fn build_specific_cve_evidence(cves: &[&CveRecord]) -> Vec<String> {
    cves.iter()
        .map(|item| {
            let kev = item
                .exploit_context
                .as_ref()
                .and_then(|context| context.cisa_kev.as_ref());
            format!(
                "{} | vendor={} | product={} | date_added={} | due_date={}",
                item.cve_id,
                kev.and_then(|record| record.vendor_project.clone())
                    .unwrap_or_else(|| "-".to_string()),
                kev.and_then(|record| record.product.clone())
                    .unwrap_or_else(|| "-".to_string()),
                kev.and_then(|record| record.date_added.clone())
                    .unwrap_or_else(|| "-".to_string()),
                kev.and_then(|record| record.due_date.clone())
                    .unwrap_or_else(|| "-".to_string())
            )
        })
        .collect()
}

fn build_epss_evidence(service: &ServiceReport, threshold: f64) -> Vec<String> {
    service
        .cves
        .iter()
        .filter_map(|item| {
            let epss = item
                .exploit_context
                .as_ref()
                .and_then(|context| context.epss.as_ref())?;
            (epss.score >= threshold).then(|| {
                format!(
                    "{} | EPSS {:.3} | percentile {:.3} | date {}",
                    item.cve_id, epss.score, epss.percentile, epss.date
                )
            })
        })
        .collect()
}

fn build_protocol_evidence(service: &ServiceReport, event_type: &str) -> Vec<String> {
    let mut evidence = vec![
        format!("service_key={}", service.service_key),
        format!("service_name={}", service.inventory.service_name),
        format!(
            "product={} | version={} | port_state={}",
            service
                .inventory
                .product
                .clone()
                .unwrap_or_else(|| "-".to_string()),
            service
                .inventory
                .version
                .clone()
                .unwrap_or_else(|| "-".to_string()),
            service.port_state
        ),
    ];
    evidence.extend(
        service
            .events
            .iter()
            .filter(|item| item.event.event_type == event_type)
            .map(|item| {
                format!(
                    "{} | {} | {} | {}",
                    item.event.source,
                    item.event.event_type,
                    item.correlation.method,
                    item.event.message
                )
            }),
    );
    evidence
}

fn build_active_check_evidence(check: &crate::model::ActiveCheckRecord) -> Vec<String> {
    let mut evidence = vec![
        format!("template_id={}", check.template_id),
        format!("matched_url={}", check.matched_url),
    ];
    if let Some(matcher) = &check.matcher_name {
        evidence.push(format!("matcher_name={matcher}"));
    }
    if let Some(description) = &check.description {
        evidence.push(format!("description={description}"));
    }
    evidence.extend(check.evidence.iter().cloned());
    evidence
}

fn build_unmapped_event_evidence(event: &crate::model::CorrelatedEvent) -> Vec<String> {
    let mut evidence = vec![
        format!("event_id={}", event.event.event_id),
        format!("source={}", event.event.source),
        format!("type={}", event.event.event_type),
        format!(
            "dst={}:{}",
            event.event.dst_ip,
            event.event.dst_port.unwrap_or(0)
        ),
        format!("proto={}", event.event.proto),
        format!("method={}", event.correlation.method),
        format!("message={}", event.event.message),
    ];
    if let Some(src_ip) = &event.event.src_ip {
        evidence.push(format!("src={src_ip}"));
    }
    if let Some(rule_id) = &event.event.rule_id {
        evidence.push(format!("rule_id={rule_id}"));
    }
    evidence
}

fn active_check_rationale(check: &crate::model::ActiveCheckRecord) -> String {
    match check.template_id.as_str() {
        "bakula-basic-auth-over-http" => {
            "Kontrolovaný HTTP check potvrdil Basic autentizační challenge nad nešifrovaným HTTP kanálem."
                .to_string()
        }
        "bakula-prometheus-metrics-exposed" => {
            "Kontrolovaný check potvrdil veřejně dosažitelný endpoint /metrics, který může zpřístupňovat provozní informace o systému."
                .to_string()
        }
        "bakula-swagger-ui-exposed" => {
            "Kontrolovaný check potvrdil veřejně dostupné interaktivní rozhraní API dokumentace."
                .to_string()
        }
        "bakula-directory-listing-exposed" => {
            "Kontrolovaný check potvrdil vystavené directory listing rozhraní na kořenové cestě webu."
                .to_string()
        }
        "bakula-directory-listing-root" => {
            "Interní obsahová forenzika potvrdila directory listing přímo na kořenové cestě webu."
                .to_string()
        }
        "bakula-login-surface-over-http" => {
            "Interní pentest našel přihlašovací nebo administrační povrch přes nešifrované HTTP."
                .to_string()
        }
        "bakula-missing-security-headers" => {
            "Interní HTTP kontrola potvrdila chybějící základní obranné hlavičky."
                .to_string()
        }
        "bakula-versioned-server-header" => {
            "Agresivnější interní pentest našel Server hlavičku s produktovým nebo verzovacím detailem."
                .to_string()
        }
        "bakula-ftp-port-reachable" => {
            "Interní TCP validace potvrdila dosažitelný FTP port."
                .to_string()
        }
        "bakula-telnet-port-reachable" => {
            "Interní TCP validace potvrdila dosažitelný Telnet port."
                .to_string()
        }
        "bakula-openssh-legacy-banner" => {
            "Agresivnější interní TCP validace zachytila starší OpenSSH banner."
                .to_string()
        }
        "bakula-openapi-json-exposed" => {
            "Interní pentest potvrdil dostupný OpenAPI JSON, který může prozrazovat strukturu API."
                .to_string()
        }
        "bakula-actuator-health-exposed" => {
            "Interní pentest potvrdil dostupný actuator health endpoint s provozním kontextem služby."
                .to_string()
        }
        "bakula-server-status-exposed" => {
            "Interní pentest potvrdil dostupný server-status endpoint s technickými detaily serveru."
                .to_string()
        }
        "bakula-git-head-exposed" => {
            "Agresivnější interní pentest potvrdil dostupnost Git metadata cesty. Obsah nebyl uložen, jen stav odpovědi."
                .to_string()
        }
        "bakula-env-file-accessible" => {
            "Agresivnější interní pentest potvrdil odpověď na cestě .env. Obsah nebyl uložen, aby se neukládala tajná data."
                .to_string()
        }
        "bakula-debug-pprof-exposed" => {
            "Agresivnější interní pentest potvrdil dostupný debug pprof endpoint."
                .to_string()
        }
        "bakula-phpinfo-exposed" => {
            "Agresivnější interní pentest potvrdil dostupnou phpinfo stránku."
                .to_string()
        }
        "bakula-backup-directory-exposed" | "bakula-backup-archive-exposed" => {
            "Agresivnější interní pentest potvrdil odpověď na backup cestě. Obsah nebyl uložen."
                .to_string()
        }
        "bakula-svn-entries-exposed" => {
            "Agresivnější interní pentest potvrdil dostupnost SVN metadata cesty. Obsah nebyl uložen."
                .to_string()
        }
        "bakula-config-yaml-accessible" => {
            "Agresivnější interní pentest potvrdil odpověď na konfigurační cestě. Obsah nebyl uložen."
                .to_string()
        }
        "bakula-actuator-env-exposed" => {
            "Agresivnější interní pentest potvrdil dostupný actuator env endpoint."
                .to_string()
        }
        "bakula-dangerous-http-methods" => {
            "Agresivnější interní pentest zjistil, že server inzeruje rizikové HTTP metody."
                .to_string()
        }
        "bakula-trace-method-enabled" => {
            "Agresivnější interní pentest ověřil, že server přijímá HTTP TRACE požadavek."
                .to_string()
        }
        "bakula-cors-wildcard-origin" => {
            "Agresivnější interní pentest potvrdil wildcard CORS hlavičku na kontrolované službě."
                .to_string()
        }
        "bakula-cookie-missing-security-flags" => {
            "Agresivnější interní pentest našel cookie bez kompletní sady běžných bezpečnostních flagů."
                .to_string()
        }
        "bakula-hsts-missing" => {
            "Agresivnější interní pentest potvrdil HTTPS odpověď bez HSTS hlavičky."
                .to_string()
        }
        "bakula-admin-product-exposed" => {
            "Obsahová forenzika rozpoznala administrační produkt dostupný z testovaného rozsahu."
                .to_string()
        }
        "bakula-admin-endpoint-reachable" => {
            "Agresivnější interní pentest potvrdil dosažitelnou administrační nebo login cestu."
                .to_string()
        }
        "bakula-private-key-accessible" => {
            "Agresivnější interní pentest potvrdil odpověď na cestě privátního klíče. Obsah nebyl uložen."
                .to_string()
        }
        "bakula-wp-config-backup-accessible" | "bakula-config-php-backup-accessible" => {
            "Agresivnější interní pentest potvrdil odpověď na záložní konfigurační cestě. Obsah nebyl uložen."
                .to_string()
        }
        _ => "Aktivní ověřovací krok potvrdil webový nález nad konkrétní URL.".to_string(),
    }
}

fn active_check_recommendation(template_id: &str) -> String {
    match template_id {
        "bakula-basic-auth-over-http" => {
            "Vynutit TLS před autentizací, omezit přístup k rozhraní a odstranit přihlašování přes čisté HTTP."
                .to_string()
        }
        "bakula-prometheus-metrics-exposed" => {
            "Omezit endpoint /metrics autentizací, segmentací nebo reverzní proxy a ověřit, zda má být dostupný z daného segmentu."
                .to_string()
        }
        "bakula-swagger-ui-exposed" => {
            "Omezit dokumentační rozhraní na interní síť nebo autentizované uživatele a ověřit, zda neprozrazuje citlivé detaily API."
                .to_string()
        }
        "bakula-directory-listing-exposed" => {
            "Zakázat directory listing a ověřit, zda webový server neodhaluje citlivé soubory nebo strukturu aplikace."
                .to_string()
        }
        "bakula-directory-listing-root" => {
            "Zakázat directory listing na web serveru a projít, zda nejsou dostupné zálohy, logy nebo interní soubory."
                .to_string()
        }
        "bakula-login-surface-over-http" => {
            "Přesměrovat přihlašování na HTTPS, vynutit TLS a do opravy omezit přístup jen na správcovské adresy."
                .to_string()
        }
        "bakula-missing-security-headers" => {
            "Doplnit minimálně X-Frame-Options, X-Content-Type-Options a Content-Security-Policy podle role aplikace."
                .to_string()
        }
        "bakula-versioned-server-header" => {
            "Omezit detail Server hlavičky a hlavně ověřit, zda deklarovaná verze odpovídá záplatovanému balíčku."
                .to_string()
        }
        "bakula-ftp-port-reachable" => {
            "Vypnout FTP, nahradit ho SFTP/FTPS nebo port 21 omezit jen na nutné zdrojové adresy."
                .to_string()
        }
        "bakula-telnet-port-reachable" => {
            "Vypnout Telnet, nahradit ho SSH a port 23 odstranit z běžně dosažitelných segmentů."
                .to_string()
        }
        "bakula-openssh-legacy-banner" => {
            "Ověřit skutečnou OpenSSH verzi na systému a záplatování distribučního balíčku."
                .to_string()
        }
        "bakula-openapi-json-exposed" => {
            "Omezit OpenAPI dokumentaci na interní nebo autentizovaný přístup a zkontrolovat, zda nepopisuje neveřejné endpointy."
                .to_string()
        }
        "bakula-actuator-health-exposed" => {
            "Omezit actuator endpointy na monitoring segment nebo autentizovanou reverzní proxy."
                .to_string()
        }
        "bakula-server-status-exposed" => {
            "Vypnout veřejný server-status nebo ho povolit jen pro správce z interní sítě."
                .to_string()
        }
        "bakula-git-head-exposed" => {
            "Okamžitě zablokovat přístup k .git adresáři a ověřit, zda nebyl dostupný celý repozitář."
                .to_string()
        }
        "bakula-env-file-accessible" => {
            "Zablokovat přístup k .env, zkontrolovat historii přístupů a rotovat tajné hodnoty, pokud mohl být soubor dostupný."
                .to_string()
        }
        "bakula-debug-pprof-exposed" => {
            "Vypnout debug endpoint nebo ho omezit pouze na izolovanou administrátorskou síť."
                .to_string()
        }
        "bakula-phpinfo-exposed" => {
            "Odstranit phpinfo stránku z produkce a ověřit, zda neprozrazuje citlivou konfiguraci."
                .to_string()
        }
        "bakula-backup-directory-exposed" | "bakula-backup-archive-exposed" => {
            "Zablokovat backup cesty přes web, přesunout zálohy mimo webroot a zkontrolovat přístupové logy."
                .to_string()
        }
        "bakula-svn-entries-exposed" => {
            "Zablokovat .svn metadata, odstranit je z webrootu a ověřit, zda nebyl dostupný zdrojový kód."
                .to_string()
        }
        "bakula-config-yaml-accessible" => {
            "Zablokovat přístup ke konfiguračním souborům a rotovat tajné hodnoty, pokud mohly být zveřejněné."
                .to_string()
        }
        "bakula-actuator-env-exposed" => {
            "Omezit actuator env endpoint jen na chráněný monitoring segment nebo ho v produkci vypnout."
                .to_string()
        }
        "bakula-dangerous-http-methods" => {
            "Ověřit, zda jsou metody PUT/DELETE/PATCH/TRACE skutečně potřebné, a na proxy nebo serveru zakázat ty, které nejsou."
                .to_string()
        }
        "bakula-trace-method-enabled" => {
            "Zakázat HTTP TRACE na web serveru nebo reverzní proxy."
                .to_string()
        }
        "bakula-cors-wildcard-origin" => {
            "Ověřit, zda endpoint pracuje s citlivými daty, a místo wildcard CORS povolit jen konkrétní důvěryhodné originy."
                .to_string()
        }
        "bakula-cookie-missing-security-flags" => {
            "Doplnit HttpOnly, SameSite a u HTTPS také Secure na session cookie; u login povrchů ověřit délku platnosti relace."
                .to_string()
        }
        "bakula-hsts-missing" => {
            "Doplnit Strict-Transport-Security na HTTPS službu po ověření, že celý přístup funguje přes TLS."
                .to_string()
        }
        "bakula-admin-product-exposed" => {
            "Omezit administrační produkt segmentací, autentizovanou proxy nebo VPN a projít přístupové logy."
                .to_string()
        }
        "bakula-admin-endpoint-reachable" => {
            "Ověřit, zda má být admin/login cesta dostupná z daného rozsahu, a jinak ji omezit firewallem nebo reverzní proxy."
                .to_string()
        }
        "bakula-private-key-accessible" => {
            "Okamžitě zablokovat cestu ke klíči, ověřit přístupové logy a klíč rotovat, pokud mohl být dostupný."
                .to_string()
        }
        "bakula-wp-config-backup-accessible" | "bakula-config-php-backup-accessible" => {
            "Odstranit záložní konfigurace z webrootu, zablokovat jejich cesty a rotovat tajné hodnoty, pokud mohly být dostupné."
                .to_string()
        }
        _ => "Ověřit dopad zjištění a omezit expozici pouze na legitimní uživatele nebo interní segment.".to_string(),
    }
}

fn is_plaintext_management(service: &ServiceReport) -> bool {
    let name = service.inventory.service_name.to_ascii_lowercase();
    let observed_plaintext_event = service
        .events
        .iter()
        .any(|item| item.event.event_type == "plaintext_protocol");
    observed_plaintext_event
        || (service.port_state == "open" && matches!(name.as_str(), "telnet" | "ftp"))
}

fn plaintext_protocol_label(service: &ServiceReport) -> &'static str {
    let name = service.inventory.service_name.to_ascii_lowercase();
    if name == "telnet" || service.port == 23 {
        "Telnet"
    } else if name == "ftp" || service.port == 21 {
        "FTP"
    } else {
        "Plaintext protokol"
    }
}

fn plaintext_protocol_rationale(service: &ServiceReport) -> String {
    match plaintext_protocol_label(service) {
        "Telnet" => {
            "Telnet přenáší přihlašovací údaje i správcovské příkazy bez šifrování, takže je v běžné síti citlivý na odposlech a převzetí relace."
                .to_string()
        }
        "FTP" => {
            "FTP přenáší řídicí kanál a často i přihlašovací údaje bez šifrování. I když nejde vždy o správu systému, pořád jde o slabý přístupový kanál."
                .to_string()
        }
        _ => {
            "Služba používá nešifrovaný protokol pro přístup nebo správu. Bez další ochrany může prozrazovat citlivá data nebo řídicí informace."
                .to_string()
        }
    }
}

fn plaintext_protocol_recommendation(service: &ServiceReport) -> String {
    match plaintext_protocol_label(service) {
        "Telnet" => {
            "Nahradit Telnet za SSH, zablokovat port 23 mimo nezbytný správcovský segment a ověřit, zda služba není jen zbytková nebo testovací."
                .to_string()
        }
        "FTP" => {
            "Přesunout přenos na SFTP nebo FTPS, omezit port 21 jen na nutné zdroje a ověřit, zda se přes službu nepřenáší citlivé údaje."
                .to_string()
        }
        _ => {
            "Nahradit plaintext variantu šifrovaným protokolem, omezit přístup firewall pravidly a ověřit skutečnou potřebu služby."
                .to_string()
        }
    }
}

fn is_known_exploited(item: &CveRecord) -> bool {
    item.exploit_context
        .as_ref()
        .and_then(|context| context.cisa_kev.as_ref())
        .map(|kev| kev.known_exploited)
        .unwrap_or(false)
}

fn event_confidence(service: &ServiceReport, event_type: &str) -> Option<Confidence> {
    service
        .events
        .iter()
        .find(|item| item.event.event_type == event_type)
        .map(|item| item.correlation.confidence)
}

fn max_event_count(service: &ServiceReport, event_type: &str) -> u32 {
    service
        .events
        .iter()
        .filter(|item| item.event.event_type == event_type)
        .map(|item| item.event.count)
        .max()
        .unwrap_or(0)
}

fn service_change_severity(service_key: &str) -> Severity {
    let port = service_key
        .rsplit('/')
        .next()
        .and_then(|item| item.parse::<u16>().ok());
    match port {
        Some(21 | 23 | 3389 | 8080) => Severity::High,
        Some(80 | 443 | 8443 | 3306) => Severity::Medium,
        _ => Severity::Low,
    }
}

fn extract_host_key(service_key: &str) -> String {
    service_key
        .split('/')
        .next()
        .unwrap_or_default()
        .to_string()
}

fn is_management_surface(service: &ServiceReport) -> bool {
    if service.port_state != "open" {
        return false;
    }
    matches!(
        service.port,
        135 | 139 | 445 | 2179 | 3306 | 3389 | 8080 | 9993
    )
}

fn management_surface_severity(port: u16) -> Severity {
    match port {
        445 | 2179 | 3306 | 3389 => Severity::High,
        135 | 139 | 8080 | 9993 => Severity::Medium,
        _ => Severity::Low,
    }
}

fn has_identification_gap(service: &ServiceReport) -> bool {
    service.inventory.version.is_none()
        && (service.inventory.product.is_none() || service.inventory.confidence != Confidence::High)
}

fn is_new_exposed_service_target(report: &RunReport, service_key: &str) -> bool {
    report
        .diff
        .as_ref()
        .map(|diff| {
            diff.changed_services.iter().any(|change| {
                change.change_type == "nova_sluzba" && change.service_key == service_key
            })
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod rule_tests {
    use chrono::Utc;

    use super::*;
    use crate::model::{
        ActiveCheckRecord, CorrelatedEvent, CorrelationInfo, CvssRecord, DiffReport, EpssRecord,
        ExploitContext, IntelMatch, InventoryRecord, KevRecord, NormalizedEvent, PassiveWindow,
        ServiceChange, SourceMetadata,
    };

    fn empty_report() -> RunReport {
        let now = Utc::now();
        crate::report::build_report(
            "rules-test",
            "rules-test",
            now,
            now,
            Vec::new(),
            Vec::new(),
            "test",
            "test",
            "passive-only",
            PassiveWindow {
                start: now,
                end: now,
                time_window_s: 3600,
            },
            SourceMetadata::default(),
            Vec::new(),
            Vec::new(),
        )
    }

    fn service(port: u16, name: &str) -> ServiceReport {
        ServiceReport {
            service_id: format!("svc:10.0.0.1/tcp/{port}"),
            service_key: format!("10.0.0.1/tcp/{port}"),
            proto: "tcp".to_string(),
            port,
            port_state: "open".to_string(),
            state_reason: None,
            inventory: InventoryRecord {
                service_name: name.to_string(),
                product: Some("prod".to_string()),
                version: Some("1.0".to_string()),
                extrainfo: None,
                detection_source: "nmap".to_string(),
                confidence: Confidence::High,
            },
            cpe: Vec::new(),
            cves: Vec::new(),
            events: Vec::new(),
            web_probe: None,
            active_checks: Vec::new(),
            score: 0.0,
            priorita: "nizka".to_string(),
        }
    }

    fn event(event_type: &str, method: &str, count: u32) -> CorrelatedEvent {
        CorrelatedEvent {
            event: NormalizedEvent {
                event_id: format!("evt:{event_type}"),
                timestamp: Utc::now(),
                src_ip: Some("10.0.0.99".to_string()),
                src_port: None,
                dst_ip: "10.0.0.1".to_string(),
                proto: "tcp".to_string(),
                dst_port: Some(80),
                event_type: event_type.to_string(),
                severity: Severity::Medium,
                source: "zeek".to_string(),
                rule_id: None,
                message: "test".to_string(),
                raw_ref: None,
                count,
            },
            correlation: CorrelationInfo {
                method: method.to_string(),
                confidence: Confidence::High,
                time_window_s: 3600,
                host_id: None,
                service_id: None,
            },
        }
    }

    fn cve(cvss: Option<f64>, epss: Option<f64>, kev: bool) -> CveRecord {
        CveRecord {
            cve_id: "CVE-2026-0001".to_string(),
            summary: None,
            cvss: cvss.map(|score| CvssRecord {
                version: "3.1".to_string(),
                base_score: score,
                severity: None,
            }),
            source: "test".to_string(),
            retrieved_at: Utc::now(),
            references: Vec::new(),
            exploit_context: Some(ExploitContext {
                epss: epss.map(|score| EpssRecord {
                    score,
                    percentile: 0.5,
                    date: "2026-01-01".to_string(),
                    source: "test".to_string(),
                }),
                cisa_kev: kev.then(|| KevRecord {
                    known_exploited: true,
                    vendor_project: None,
                    product: None,
                    vulnerability_name: None,
                    short_description: None,
                    date_added: None,
                    due_date: None,
                    required_action: None,
                    known_ransomware_campaign_use: None,
                    source: "test".to_string(),
                }),
            }),
        }
    }

    fn report_with(service: ServiceReport) -> RunReport {
        let mut report = empty_report();
        report.hosts = vec![HostReport {
            host_id: "host:10.0.0.1".to_string(),
            host_key: "10.0.0.1".to_string(),
            ip: "10.0.0.1".to_string(),
            hostname: None,
            mac: None,
            vendor: None,
            asset_id: None,
            identity_note: None,
            device_class: None,
            services: vec![service],
        }];
        report
    }

    fn types(report: &RunReport) -> Vec<String> {
        generate_findings(report)
            .into_iter()
            .map(|finding| finding.finding_type)
            .collect()
    }

    fn has(report: &RunReport, finding_type: &str) -> bool {
        types(report).iter().any(|kind| kind == finding_type)
    }

    fn severity_of(report: &RunReport, finding_type: &str) -> Severity {
        generate_findings(report)
            .iter()
            .find(|finding| finding.finding_type == finding_type)
            .unwrap_or_else(|| panic!("{finding_type} nevznikl"))
            .severity
    }

    fn diff_with(changes: Vec<ServiceChange>) -> DiffReport {
        DiffReport {
            base_run_id: "old".to_string(),
            new_hosts: Vec::new(),
            removed_hosts: Vec::new(),
            changed_services: changes,
            new_cves: Vec::new(),
            new_events: Vec::new(),
        }
    }

    fn new_service_change(service_key: &str) -> ServiceChange {
        ServiceChange {
            service_key: service_key.to_string(),
            change_type: "nova_sluzba".to_string(),
            before: None,
            after: Some("open".to_string()),
        }
    }

    /// Cista sluzba (zname, vysoce jiste identifikovana, bez udalosti) nesmi
    /// vyprodukovat zadny nalez - spolecny zaklad vsech "nefiruje" testu nize.
    #[test]
    fn clean_service_produces_no_findings() {
        assert!(types(&report_with(service(443, "https"))).is_empty());
    }

    #[test]
    fn rule_order_is_stable() {
        assert_eq!(
            rule_names(),
            vec![
                "unmapped_passive_event",
                "active_checks",
                "known_exploited_vulnerability",
                "probable_exploitation_interest",
                "high_risk_cve_exposure",
                "plaintext_management_protocol",
                "http_basic_without_tls",
                "insecure_auth_possible",
                "unexpected_traffic",
                "connection_timeout_burst",
                "packet_rate_spike",
                "packet_loss_signal",
                "service_overload_risk",
                "inductive_volume_anomaly",
                "management_surface_exposure",
                "identification_gap",
                "correlation_uncertainty",
                "new_exposed_service",
                "intel_match",
            ]
        );
    }

    #[test]
    fn rule_names_are_unique() {
        let mut names = rule_names();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len());
    }

    #[test]
    fn unmapped_event_rule_fires_only_with_unmapped_events() {
        let mut report = empty_report();
        assert!(!has(&report, "unmapped_passive_event"));
        report.unmapped_events = vec![event("unexpected_traffic", "unmapped", 1)];
        assert!(has(&report, "unmapped_passive_event"));
    }

    #[test]
    fn active_check_rule_fires_per_check() {
        let mut svc = service(443, "https");
        assert!(types(&report_with(svc.clone())).is_empty());
        svc.active_checks = vec![ActiveCheckRecord {
            check_id: "c1".to_string(),
            source: "nuclei".to_string(),
            template_id: "tpl-1".to_string(),
            template_name: "Tpl".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            matched_at: Utc::now(),
            matched_url: "https://10.0.0.1/".to_string(),
            matcher_name: None,
            description: None,
            evidence: Vec::new(),
        }];
        assert!(has(&report_with(svc), "active_check:tpl-1"));
    }

    #[test]
    fn kev_rule_requires_known_exploited_flag() {
        let mut svc = service(443, "https");
        svc.cves = vec![cve(None, None, false)];
        assert!(!has(
            &report_with(svc.clone()),
            "known_exploited_vulnerability"
        ));
        svc.cves = vec![cve(None, None, true)];
        assert!(has(&report_with(svc), "known_exploited_vulnerability"));
    }

    #[test]
    fn epss_rule_threshold_is_point_three_and_severity_steps_at_point_seven() {
        let mut svc = service(443, "https");
        svc.cves = vec![cve(None, Some(0.29), false)];
        assert!(!has(
            &report_with(svc.clone()),
            "probable_exploitation_interest"
        ));
        svc.cves = vec![cve(None, Some(0.3), false)];
        assert_eq!(
            severity_of(&report_with(svc.clone()), "probable_exploitation_interest"),
            Severity::Medium
        );
        svc.cves = vec![cve(None, Some(0.7), false)];
        assert_eq!(
            severity_of(&report_with(svc), "probable_exploitation_interest"),
            Severity::High
        );
    }

    #[test]
    fn high_cvss_rule_threshold_and_severity() {
        let mut svc = service(443, "https");
        svc.cves = vec![cve(Some(6.9), None, false)];
        assert!(!has(&report_with(svc.clone()), "high_risk_cve_exposure"));
        svc.cves = vec![cve(Some(7.0), None, false)];
        assert_eq!(
            severity_of(&report_with(svc.clone()), "high_risk_cve_exposure"),
            Severity::Medium
        );
        svc.cves = vec![cve(Some(9.0), None, false)];
        assert_eq!(
            severity_of(&report_with(svc), "high_risk_cve_exposure"),
            Severity::High
        );
    }

    #[test]
    fn plaintext_rule_fires_for_open_telnet_not_for_closed_or_https() {
        assert!(has(
            &report_with(service(23, "telnet")),
            "plaintext_management_protocol"
        ));
        let mut closed = service(23, "telnet");
        closed.port_state = "closed".to_string();
        assert!(!has(&report_with(closed), "plaintext_management_protocol"));
        assert!(!has(
            &report_with(service(443, "https")),
            "plaintext_management_protocol"
        ));
    }

    #[test]
    fn http_basic_rule_is_suppressed_for_newly_exposed_service() {
        let mut svc = service(80, "http");
        svc.events = vec![event("http_basic_without_tls", "ip+port", 1)];
        let mut report = report_with(svc.clone());
        assert!(has(&report, "http_basic_without_tls"));
        report.diff = Some(diff_with(vec![new_service_change(&svc.service_key)]));
        let after = types(&report);
        assert!(!after.iter().any(|kind| kind == "http_basic_without_tls"));
        assert!(after.iter().any(|kind| kind == "new_exposed_service"));
    }

    #[test]
    fn insecure_auth_rule_needs_its_event() {
        let mut svc = service(80, "http");
        assert!(!has(&report_with(svc.clone()), "insecure_auth_possible"));
        svc.events = vec![event("insecure_auth_possible", "ip+port", 1)];
        assert!(has(&report_with(svc), "insecure_auth_possible"));
    }

    #[test]
    fn traffic_rules_each_fire_on_their_event_only() {
        for kind in [
            "unexpected_traffic",
            "connection_timeout_burst",
            "packet_rate_spike",
            "packet_loss_signal",
            "service_overload_risk",
            "inductive_volume_anomaly",
        ] {
            let mut svc = service(443, "https");
            assert!(!has(&report_with(svc.clone()), kind), "{kind} bez udalosti");
            svc.events = vec![event(kind, "ip+port", 1)];
            assert!(has(&report_with(svc), kind), "{kind} s udalosti");
        }
    }

    #[test]
    fn unexpected_traffic_is_suppressed_for_newly_exposed_service() {
        let mut svc = service(443, "https");
        svc.events = vec![event("unexpected_traffic", "ip+port", 1)];
        let mut report = report_with(svc.clone());
        assert!(has(&report, "unexpected_traffic"));
        report.diff = Some(diff_with(vec![new_service_change(&svc.service_key)]));
        assert!(!has(&report, "unexpected_traffic"));
    }

    #[test]
    fn timeout_severity_depends_on_event_count() {
        let mut svc = service(443, "https");
        svc.events = vec![event("connection_timeout_burst", "ip+port", 3)];
        assert_eq!(
            severity_of(&report_with(svc.clone()), "connection_timeout_burst"),
            Severity::Medium
        );
        svc.events = vec![event("connection_timeout_burst", "ip+port", 4)];
        assert_eq!(
            severity_of(&report_with(svc), "connection_timeout_burst"),
            Severity::High
        );
    }

    #[test]
    fn rate_spike_severity_depends_on_event_count() {
        let mut svc = service(443, "https");
        svc.events = vec![event("packet_rate_spike", "ip+port", 4)];
        assert_eq!(
            severity_of(&report_with(svc.clone()), "packet_rate_spike"),
            Severity::Medium
        );
        svc.events = vec![event("packet_rate_spike", "ip+port", 5)];
        assert_eq!(
            severity_of(&report_with(svc), "packet_rate_spike"),
            Severity::High
        );
    }

    #[test]
    fn management_surface_rule_depends_on_port_and_state() {
        assert!(has(
            &report_with(service(3389, "ms-wbt-server")),
            "management_surface_exposure"
        ));
        assert!(!has(
            &report_with(service(443, "https")),
            "management_surface_exposure"
        ));
        let mut closed = service(3389, "ms-wbt-server");
        closed.port_state = "closed".to_string();
        assert!(!has(&report_with(closed), "management_surface_exposure"));
    }

    #[test]
    fn identification_gap_rule_needs_open_port_without_version() {
        let mut svc = service(443, "https");
        svc.inventory.version = None;
        svc.inventory.product = None;
        assert!(has(&report_with(svc.clone()), "identification_gap"));
        svc.port_state = "closed".to_string();
        assert!(!has(&report_with(svc), "identification_gap"));
        assert!(!has(
            &report_with(service(443, "https")),
            "identification_gap"
        ));
    }

    #[test]
    fn correlation_uncertainty_rule_fires_for_non_ip_port_methods_only() {
        let mut svc = service(443, "https");
        svc.events = vec![event("unexpected_traffic", "ip+port", 1)];
        assert!(!has(&report_with(svc.clone()), "correlation_uncertainty"));
        svc.events = vec![event("unexpected_traffic", "ip-only", 1)];
        assert!(has(&report_with(svc), "correlation_uncertainty"));
    }

    #[test]
    fn new_exposed_service_rule_only_for_nova_sluzba_changes() {
        let mut report = empty_report();
        let mut other = new_service_change("10.0.0.5/tcp/22");
        other.change_type = "zmena_verze".to_string();
        report.diff = Some(diff_with(vec![other]));
        assert!(!has(&report, "new_exposed_service"));
        report.diff = Some(diff_with(vec![new_service_change("10.0.0.5/tcp/22")]));
        let findings = generate_findings(&report);
        let finding = findings
            .iter()
            .find(|f| f.finding_type == "new_exposed_service")
            .expect("fires");
        assert_eq!(finding.host_key.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn intel_rule_maps_each_match_to_a_typed_finding() {
        let mut report = empty_report();
        assert!(types(&report).is_empty());
        report.intel_matches = vec![IntelMatch {
            match_id: "m1".to_string(),
            source: "Abuse IPDB".to_string(),
            indicator_type: "ip".to_string(),
            indicator: "203.0.113.9".to_string(),
            status: "listed".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            summary: "s".to_string(),
            references: vec!["ref".to_string()],
            linked_host_key: None,
            linked_service_key: None,
        }];
        assert_eq!(types(&report), vec!["intel:abuse-ipdb".to_string()]);
    }

    #[test]
    fn duplicate_finding_ids_are_collapsed_keeping_the_first() {
        let mut svc = service(80, "http");
        svc.events = vec![
            event("insecure_auth_possible", "ip+port", 1),
            event("insecure_auth_possible", "ip+port", 1),
        ];
        let count = types(&report_with(svc))
            .iter()
            .filter(|kind| *kind == "insecure_auth_possible")
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn output_is_sorted_by_severity_descending() {
        let mut svc = service(3389, "ms-wbt-server");
        svc.events = vec![event("service_overload_risk", "ip+port", 1)];
        let findings = generate_findings(&report_with(svc));
        let severities: Vec<Severity> = findings.iter().map(|f| f.severity).collect();
        let mut sorted = severities.clone();
        sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(severities, sorted);
        assert!(findings.len() >= 2);
    }
}
