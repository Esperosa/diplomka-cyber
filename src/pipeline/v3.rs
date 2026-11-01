//! Produkční zapojení jádra v3 do `run_pipeline` (krok 1, `engine.mode = "v3"`).
//!
//! Jeden běh CLI = jeden cyklus. Stav mezi běhy žije ve `workspace/engine-state.sqlite`
//! (historie detektoru, perzistentní inventář, paměť nálezů s auditem); kontext
//! ve `workspace/context-calendar.json` (záznamy se schvalovatelem a expirací);
//! identita v `workspace/identity-registry-v3.json`. V režimu `legacy` se nic z toho
//! nevolá a výstup je beze změny (golden snapshot).

use std::{collections::HashSet, path::Path};

use chrono::{DateTime, Utc};

use crate::{
    context_gate::{ContextGate, GateInput, GatePolicy, StaticCalendar},
    engine::EngineConfig,
    engine_state::{EngineStateStore, PersistentInventory},
    error::Result,
    finding_memory::{
        FindingMemory, LifecycleRecord, Observation, key_for_finding, split_service_key,
    },
    findings,
    identity::IdentityMatch,
    model::{HostReport, RunReport},
    passive::{
        V3StatefulDetector,
        anomaly_v3::{DetectorState, SourceMap, V3Switches},
    },
};

pub(crate) struct V3Session {
    engine: EngineConfig,
    store: EngineStateStore,
    inventory: PersistentInventory,
    detector: Option<V3StatefulDetector>,
    sources: SourceMap,
    /// Souhrn okna toků z detekce (pro uloženou historii, L0 žebříku).
    summary: Option<crate::flow_history::WindowSummary>,
}

/// Data žebříku v produkčním běhu (krok 2B): historie toků a hrany ze SQLite,
/// kalendář, reputace ze souboru, CVE/KEV z reportu, typ zařízení, peer skupiny,
/// aktivní kontrola dostupnosti jen s `--execute-verification` a jen v rozsahu.
struct ProdEvidence<'a> {
    history: &'a crate::flow_history::FlowHistory,
    gate: &'a ContextGate,
    calendar: &'a StaticCalendar,
    reputation: &'a crate::verify_ladder::StaticReputation,
    services: &'a std::collections::HashMap<&'a str, &'a crate::model::ServiceReport>,
    devices: &'a std::collections::HashMap<String, crate::device_class::DeviceClass>,
    groups: &'a std::collections::HashMap<String, String>,
    group_sizes: &'a std::collections::HashMap<String, usize>,
    group_hits: &'a std::collections::HashMap<(String, String), usize>,
    suspicious: &'a std::collections::HashMap<String, usize>,
    scope: &'a crate::scope_policy::ScopePolicy,
    active: bool,
    now: DateTime<Utc>,
}

impl crate::verify_ladder::LadderEvidence for ProdEvidence<'_> {
    fn recurrence(&self, key: &str, value: f64) -> crate::flow_history::Recurrence {
        self.history.recurrence(key, self.now, value)
    }

    fn context(&self, case: &crate::verify_ladder::CaseInput) -> Option<String> {
        let ids = [case.host_ip.clone(), case.key.entity.clone()];
        self.gate
            .supporting_context(
                self.calendar,
                &GateInput {
                    finding_type: &case.finding_type,
                    host_ids: &ids,
                    sources: &case.sources,
                    severity: crate::model::Severity::Medium,
                    at: self.now,
                },
            )
            .map(|(_, reason)| reason)
    }

    fn reputation(&self, ip: &str) -> crate::verify_ladder::Reputation {
        if self.scope.contains(ip) {
            return crate::verify_ladder::Reputation::Unknown;
        }
        self.reputation.lookup(ip, self.now)
    }

    fn intel(&self, case: &crate::verify_ladder::CaseInput) -> crate::verify_ladder::IntelSignal {
        use crate::verify_ladder::IntelSignal;
        let service = case.key.service.split('#').next().unwrap_or("");
        let Some(service) = self
            .services
            .get(format!("{}/{service}", case.host_ip).as_str())
        else {
            return IntelSignal::NothingKnown;
        };
        let mut best = 0.0f64;
        for cve in &service.cves {
            if let Some(context) = &cve.exploit_context {
                if context.cisa_kev.is_some() {
                    return IntelSignal::KnownExploited(cve.cve_id.clone());
                }
                if let Some(epss) = &context.epss {
                    best = best.max(epss.score);
                }
            }
        }
        if best >= 0.5 {
            IntelSignal::HighEpss(best)
        } else {
            IntelSignal::NothingKnown
        }
    }

    fn device(&self, ip: &str) -> Option<crate::device_class::DeviceClass> {
        self.devices.get(ip).cloned()
    }

    fn peers(&self, case: &crate::verify_ladder::CaseInput) -> Option<(usize, usize)> {
        let group = self.groups.get(&case.host_ip)?;
        let size = *self.group_sizes.get(group)?;
        let hits = self
            .group_hits
            .get(&(case.finding_type.clone(), group.clone()))
            .copied()
            .unwrap_or(0);
        Some((hits, size))
    }

    fn liveness(
        &mut self,
        case: &crate::verify_ladder::CaseInput,
    ) -> crate::verify_ladder::Liveness {
        use crate::verify_ladder::Liveness;
        if !self.scope.contains(&case.host_ip) {
            return Liveness::OutOfScope;
        }
        if !self.active {
            return Liveness::NeedsApproval; // aktivni kontroly jen s --execute-verification
        }
        let Some(port) = case.port else {
            return Liveness::Failed("bez portu".into());
        };
        if !case.key.service.starts_with("tcp/") {
            return Liveness::Failed("dostupnost UDP spojenim overit nelze".into());
        }
        let Ok(addr) = format!("{}:{port}", case.host_ip).parse::<std::net::SocketAddr>() else {
            return Liveness::Failed("neplatna adresa".into());
        };
        // jedno TCP spojeni bez dat (read-only), timeout 2 s
        match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(2)) {
            Ok(_) => Liveness::Up,
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => Liveness::Down,
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Liveness::Down,
            Err(error) => Liveness::Failed(error.to_string()),
        }
    }

    fn neighbors(&self, ip: &str) -> Vec<String> {
        self.history.neighbors(ip, self.now)
    }

    fn in_scope(&self, ip: &str) -> bool {
        self.scope.contains(ip)
    }

    fn suspicious_on(&self, ip: &str) -> usize {
        self.suspicious.get(ip).copied().unwrap_or(0)
    }
}

impl V3Session {
    /// `None` v režimu legacy. Sloučí aktuální sken do perzistentního inventáře.
    pub(crate) fn open(
        workspace: &Path,
        engine: EngineConfig,
        hosts: &[HostReport],
        now: DateTime<Utc>,
    ) -> Result<Option<Self>> {
        if engine.mode != crate::engine::EngineMode::V3 {
            return Ok(None);
        }
        let store = EngineStateStore::open(&workspace.join("engine-state.sqlite"))?;
        let mut inventory: PersistentInventory = store.load("inventory")?.unwrap_or_default();
        if !hosts.is_empty() {
            inventory.merge_scan(hosts);
        }
        let tables = crate::device_class::ClassifierTables::default();
        let peer_groups: std::collections::HashMap<String, String> = if engine.peer_baseline() {
            inventory
                .hosts()
                .iter()
                .filter_map(|host| {
                    let class = crate::device_class::classify(host, None, &tables);
                    crate::device_class::peer_group_key(&host.ip, &class)
                        .map(|group| (host.ip.clone(), group))
                })
                .collect()
        } else {
            Default::default()
        };
        let detector = engine.v3_detector().then(|| {
            let state: DetectorState = store.load("detector").ok().flatten().unwrap_or_default();
            let mut known = HashSet::new();
            let mut known_hosts = HashSet::new();
            if engine.unexpected_v3() {
                for host in inventory.hosts() {
                    known_hosts.insert(host.ip.clone());
                    for service in host.services.iter().filter(|s| s.port_state == "open") {
                        known.insert((host.ip.clone(), service.proto.clone(), service.port));
                    }
                }
            }
            V3StatefulDetector::new(
                state,
                V3Switches {
                    rate: engine.robust_rate(),
                    volume: engine.volume_baseline(),
                    unexpected: engine.unexpected_v3(),
                    recall: engine.recall(),
                },
                known,
                known_hosts,
                now,
                peer_groups,
            )
        });
        Ok(Some(Self {
            engine,
            store,
            inventory,
            detector,
            sources: SourceMap::new(),
            summary: None,
        }))
    }

    pub(crate) fn detector(&self) -> Option<&V3StatefulDetector> {
        self.detector.as_ref()
    }

    /// Po detekci: uložit stav detektoru, převzít dominantní zdroje.
    pub(crate) fn finish_detection(&mut self) -> Result<()> {
        if let Some(detector) = self.detector.take() {
            self.summary = detector.take_summary();
            let (state, sources) = detector.into_parts();
            self.store.save("detector", &state)?;
            self.sources = sources;
        }
        self.store.save("inventory", &self.inventory)
    }

    /// Po `generate_findings`: v3 nálezy, agregace unmapped, paměť a kontext.
    pub(crate) fn post_findings(
        &mut self,
        workspace: &Path,
        report: &mut RunReport,
        identity: &std::collections::HashMap<String, IdentityMatch>,
        now: DateTime<Utc>,
        execute_verification: bool,
    ) -> Result<()> {
        // krok 2D: typ zarizeni v modelu hostu a v API (pole deviceClass hostu)
        let mut devices: std::collections::HashMap<String, crate::device_class::DeviceClass> =
            Default::default();
        if self.engine.devices() {
            let tables = crate::device_class::ClassifierTables::default();
            crate::device_class::classify_hosts(&mut report.hosts, &report.network_assets, &tables);
            for host in &report.hosts {
                if let Some(class) = &host.device_class {
                    devices.insert(host.ip.clone(), class.clone());
                }
            }
        }
        if self.engine.unexpected_v3() {
            let mut list = std::mem::take(&mut report.findings);
            list.extend(findings::v3_extra_findings(report, self.engine.recall()));
            findings::aggregate_unmapped_findings(&mut list, report);
            list.sort_by(|l, r| l.finding_id.cmp(&r.finding_id));
            list.dedup_by(|l, r| l.finding_id == r.finding_id);
            report.findings = list;
        }
        if !self.engine.memory() {
            return Ok(());
        }
        let calendar = if self.engine.context_gate() {
            StaticCalendar::load(&workspace.join("context-calendar.json"))?
        } else {
            StaticCalendar::default()
        };
        for reason in &calendar.rejected {
            tracing::warn!(%reason, "kontextovy zaznam odmitnut");
        }
        let mut gate = ContextGate::new(GatePolicy::default());
        let mut memory = FindingMemory::load(self.store.conn(), self.engine.memory_config())?;
        let services: std::collections::HashMap<&str, &crate::model::ServiceReport> = report
            .hosts
            .iter()
            .flat_map(|h| h.services.iter())
            .map(|s| (s.service_key.as_str(), s))
            .collect();
        let mut lifecycle = Vec::with_capacity(report.findings.len());
        let ladder_on = self.engine.ladder();
        let mut ladder = if ladder_on {
            match self.store.load::<crate::verify_ladder::Ladder>("ladder")? {
                Some(ladder) => ladder,
                None => crate::verify_ladder::Ladder::new(
                    crate::verify_ladder::LadderPolicy::default(),
                    u64::from_le_bytes(
                        uuid::Uuid::new_v4().as_bytes()[..8]
                            .try_into()
                            .expect("8 bajtu"),
                    ),
                ),
            }
        } else {
            crate::verify_ladder::Ladder::new(Default::default(), 0)
        };
        if ladder_on && self.engine.learning() && ladder.learner.is_none() {
            ladder.learner = Some(Default::default());
        }
        let cycle = (now.timestamp() / 1800).max(0) as u64;
        let severe = GatePolicy::default().most_severe;
        let mut keys: Vec<crate::finding_memory::FindingKey> = Vec::new();
        let mut signal_sources: Vec<Vec<String>> = Vec::new();
        for finding in &report.findings {
            let service_key = finding.service_key.as_deref().unwrap_or("-");
            let (_, key_ip) = split_service_key(service_key);
            let host_ip = finding
                .host_key
                .clone()
                .unwrap_or_else(|| key_ip.to_string());
            let entity_host = finding
                .host_key
                .as_ref()
                .and_then(|k| identity.get(k))
                .map(|m| m.asset_id().to_string())
                .unwrap_or_else(|| host_ip.clone());
            let (count, sources) = findings::finding_signal(
                finding,
                services.get(service_key).copied(),
                |dst, proto, port, kind| {
                    self.sources
                        .get(&(dst.to_string(), proto.to_string(), port, kind.to_string()))
                        .map(Vec::as_slice)
                        .unwrap_or(&[])
                },
            );
            let key = key_for_finding(finding, &entity_host, &sources);
            let ids = [host_ip, entity_host];
            let explanation = gate.explain(
                &calendar,
                &GateInput {
                    finding_type: &finding.finding_type,
                    host_ids: &ids,
                    sources: &sources,
                    severity: finding.severity,
                    at: now,
                },
            );
            let disposition = memory.observe(
                &Observation {
                    key: key.clone(),
                    severity: finding.severity,
                    count,
                    sources: &sources,
                    at: now,
                    volume_explained: explanation
                        .as_ref()
                        .is_some_and(|e| e.kind.explains_volume()),
                },
                explanation.as_ref().map(|e| e.reason.as_str()),
            );
            let behavioral = !crate::finding_kinds::is_static_exposure(&finding.finding_type);
            let auto_closed = matches!(
                disposition,
                crate::finding_memory::Disposition::AutoResolved(_)
            );
            if ladder_on && behavioral && !auto_closed {
                if disposition.displayed() {
                    let service_key_full = finding.service_key.as_deref().unwrap_or("-");
                    let (service, _) = split_service_key(service_key_full);
                    let host_ip = ids[0].clone();
                    ladder.open(
                        crate::verify_ladder::CaseInput {
                            key: key.clone(),
                            finding_id: finding.finding_id.clone(),
                            finding_type: finding.finding_type.clone(),
                            host_ip: host_ip.clone(),
                            port: service.rsplit('/').next().and_then(|p| p.parse().ok()),
                            sources: sources.clone(),
                            volume: count as f64,
                            history_key: crate::verify_ladder::history_key_for(
                                &finding.finding_type,
                                service_key_full.contains('/').then_some(service_key_full),
                                &host_ip,
                                &sources,
                            ),
                            high_impact: finding.severity == crate::model::Severity::High
                                || severe.contains(&finding.finding_type),
                            prior: crate::verify_ladder::DEFAULT_PRIOR,
                        },
                        cycle,
                    );
                } else {
                    ladder.observe(&key, &sources, cycle);
                }
            }
            lifecycle.push(LifecycleRecord::new(
                &finding.finding_id,
                &disposition,
                memory.get(&key),
                now,
            ));
            keys.push(key);
            signal_sources.push(sources);
        }
        if ladder_on {
            let history = crate::flow_history::FlowHistory::load(self.store.conn())?;
            let reputation =
                crate::verify_ladder::StaticReputation::load(&workspace.join("reputation.json"))?;
            let scope = crate::scope_policy::ScopePolicy::new(report.run.scope.clone());
            let groups: std::collections::HashMap<String, String> = devices
                .iter()
                .filter_map(|(ip, class)| {
                    crate::device_class::peer_group_key(ip, class).map(|g| (ip.clone(), g))
                })
                .collect();
            let mut typed_hosts = std::collections::HashSet::new();
            let mut suspicious: std::collections::HashMap<String, usize> = Default::default();
            for (index, finding) in report.findings.iter().enumerate() {
                if crate::finding_kinds::is_static_exposure(&finding.finding_type) {
                    continue;
                }
                let suspicious_type = matches!(
                    finding.finding_type.as_str(),
                    "scan_attempts"
                        | "multi_target_pattern"
                        | "suricata_alert"
                        | "source_volume_outlier"
                        | "connection_timeout_burst"
                );
                if let Some(host) = &finding.host_key {
                    typed_hosts.insert((finding.finding_type.clone(), host.clone()));
                    if suspicious_type {
                        *suspicious.entry(host.clone()).or_default() += 1;
                    }
                }
                if suspicious_type {
                    for source in &signal_sources[index] {
                        *suspicious.entry(source.clone()).or_default() += 1;
                    }
                }
            }
            let mut group_sizes: std::collections::HashMap<String, usize> = Default::default();
            for group in groups.values() {
                *group_sizes.entry(group.clone()).or_default() += 1;
            }
            let mut group_hits: std::collections::HashMap<(String, String), usize> =
                Default::default();
            for (kind, ip) in &typed_hosts {
                if let Some(group) = groups.get(ip) {
                    *group_hits.entry((kind.clone(), group.clone())).or_default() += 1;
                }
            }
            let mut env = ProdEvidence {
                history: &history,
                gate: &gate,
                calendar: &calendar,
                reputation: &reputation,
                services: &services,
                devices: &devices,
                groups: &groups,
                group_sizes: &group_sizes,
                group_hits: &group_hits,
                suspicious: &suspicious,
                scope: &scope,
                active: execute_verification,
                now,
            };
            let decisions = ladder.step(cycle, &mut env);
            for decision in &decisions {
                use crate::verify_ladder::Status;
                match decision.status {
                    Status::Refuted => {
                        memory.refute(&decision.key, &decision.reason, now);
                    }
                    Status::Confirmed => {
                        memory.confirm(&decision.key, "verify_ladder", now);
                        memory.note(&decision.key, "verify_confirm", &decision.reason, now);
                    }
                    Status::Escalated | Status::Open => {
                        memory.note(&decision.key, "verify_escalate", &decision.reason, now);
                    }
                }
            }
            report.verification_decisions = decisions
                .iter()
                .map(crate::verify_ladder::DecisionRecord::from)
                .collect();
            self.store.save("ladder", &ladder)?;
            // L0: zapsat okno do historie; klice s alarmem v tomto behu se neuci
            if let Some(summary) = self.summary.take() {
                let mut frozen = std::collections::HashSet::new();
                for (index, finding) in report.findings.iter().enumerate() {
                    if crate::finding_kinds::is_static_exposure(&finding.finding_type) {
                        continue;
                    }
                    if let Some(service) = &finding.service_key {
                        frozen.insert(service.clone());
                    }
                    if let Some(host) = &finding.host_key {
                        frozen.insert(host.clone());
                    }
                    frozen.extend(signal_sources[index].iter().cloned());
                }
                let mut history = history;
                history.ingest(&summary, &frozen, now);
                history.flush(self.store.conn_mut())?;
            }
        }
        memory.sweep(now);
        memory.flush(self.store.conn_mut())?;
        report.finding_lifecycle = lifecycle;
        Ok(())
    }
}
