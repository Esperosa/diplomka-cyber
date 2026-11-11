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
    /// Odchozí a vnitřní toky okna pro behaviorální vrstvu (krok 3).
    behavior_flows: Option<crate::passive::BehaviorFlows>,
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
    /// Profil hostu (krok 3E); `None` = vypnuto.
    profile: Option<(
        &'a crate::behavior::profile::HostProfiles,
        &'a crate::behavior::profile::ProfilePolicy,
    )>,
    /// Koncová telemetrie běhu (krok 8); `None` = vypnuto.
    endpoint: Option<&'a crate::endpoint::correlate::EndpointView>,
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
                    protected: case.protected,
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

    fn profile(
        &self,
        case: &crate::verify_ladder::CaseInput,
    ) -> crate::behavior::profile::ProfileVerdict {
        use crate::behavior::profile::{ProfileVerdict, case_pair, case_verdict};
        let Some((profiles, policy)) = self.profile else {
            return ProfileVerdict::Unknown("profil vypnut".into());
        };
        let group = case_pair(case).and_then(|(actor, ..)| {
            self.groups
                .get(&actor)
                .and_then(|g| self.group_sizes.get(g))
                .copied()
        });
        case_verdict(profiles, policy, case, group, self.now.timestamp())
    }

    fn endpoint(
        &self,
        case: &crate::verify_ladder::CaseInput,
    ) -> crate::endpoint::correlate::EndpointSignal {
        match self.endpoint {
            Some(view) => view.signal(&case.host_ip, &case.sources),
            None => crate::endpoint::correlate::EndpointSignal::NoCoverage(
                "koncova telemetrie vypnuta".into(),
            ),
        }
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
            behavior_flows: None,
        }))
    }

    /// Běží behaviorální vrstva (v3 s viditelností ven, grafem nebo profilem)?
    pub(crate) fn behavior_enabled(&self) -> bool {
        self.engine.behavior()
    }

    /// Toky okna pro behaviorální vrstvu z pasivního importu.
    pub(crate) fn set_behavior_flows(&mut self, flows: Option<crate::passive::BehaviorFlows>) {
        self.behavior_flows = flows;
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
        // krok 3: behavioralni vrstva (stav v kv `behavior`, prezije mezi behy)
        let mut behavior_state: crate::behavior::BehaviorState = if self.engine.behavior() {
            self.store.load("behavior")?.unwrap_or_default()
        } else {
            Default::default()
        };
        let mut behavior_signal: std::collections::HashMap<String, (u32, Vec<String>)> =
            Default::default();
        let mut consented_pairs: Vec<(String, Vec<String>)> = Vec::new();
        // krok 7 (B1, B4): klientela sluzeb a dukazy okna (pred ucenim z tohoto okna)
        let ops_policy = crate::ops_evidence::OpsPolicy::default();
        let mut clientele: crate::ops_evidence::Clientele = if self.engine.ops_evidence() {
            self.store.load("clientele")?.unwrap_or_default()
        } else {
            Default::default()
        };
        let ops_window = self
            .behavior_flows
            .as_ref()
            .filter(|_| self.engine.ops_evidence())
            .map(|flows| clientele.evidence(&flows.to_scope, now.timestamp(), &ops_policy));
        if let Some(flows) = self.behavior_flows.as_ref() {
            let out = crate::behavior::run_window(
                &mut behavior_state,
                crate::behavior::BehaviorSwitches::from_engine(&self.engine),
                &crate::behavior::BehaviorThresholds::default(),
                &crate::behavior::BehaviorInput {
                    outbound: &flows.outbound,
                    internal: &flows.internal,
                    outbound_alerts: &flows.outbound_alerts,
                    now,
                },
            );
            if flows.outbound_dropped > 0 {
                tracing::info!(
                    seen = flows.outbound_seen,
                    dropped = flows.outbound_dropped,
                    level = flows.sample_level,
                    "odchozi toky vzorkovany po dvojici"
                );
            }
            // krok 7 (B5): souhlas cloveka s presnou dvojici potlaci jen novy poplach
            // novosti; dvojice zustava pro uceni profilu zmrazena (zadne uceni z trvani)
            let consents: std::collections::HashSet<String> = if self.engine.saas_group() {
                crate::novelty_consent::active(self.store.conn(), now)?
                    .iter()
                    .map(crate::novelty_consent::Consent::pair_key)
                    .collect()
            } else {
                Default::default()
            };
            for item in out.findings {
                if let Some(pair) = crate::novelty_consent::finding_pair(&item.finding)
                    && consents.contains(&pair)
                {
                    consented_pairs.push((item.actor.clone(), item.sources.clone()));
                    continue;
                }
                behavior_signal.insert(item.finding.finding_id.clone(), (item.count, item.sources));
                report.findings.push(item.finding);
            }
            report
                .findings
                .sort_by(|l, r| l.finding_id.cmp(&r.finding_id));
            report
                .findings
                .dedup_by(|l, r| l.finding_id == r.finding_id);
        }
        // krok 7 (B4): agregace pres zdroje (jen podezreni, chraneny typ)
        if self.engine.cross_source()
            && let Some(window) = ops_window.as_ref()
        {
            for (finding, count, top, _) in crate::ops_evidence::distributed_findings(window) {
                behavior_signal.insert(finding.finding_id.clone(), (count, top));
                report.findings.push(finding);
            }
            report
                .findings
                .sort_by(|l, r| l.finding_id.cmp(&r.finding_id));
            report
                .findings
                .dedup_by(|l, r| l.finding_id == r.finding_id);
        }
        // krok 8: koncova telemetrie (identita proti inventari, sklad s limity, verdikty)
        let endpoint_view = if self.engine.endpoint() {
            Some(self.endpoint_view(report, &mut behavior_signal, now)?)
        } else {
            None
        };
        if !self.engine.memory() {
            report.coverage_status = Some(self.coverage(report, &behavior_state, false, now));
            if self.engine.behavior() {
                self.store.save("behavior", &behavior_state)?;
            }
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
        let mut gate = ContextGate::new(GatePolicy::for_engine(&self.engine));
        let mut memory = FindingMemory::load(self.store.conn(), self.engine.memory_config())?;
        // krok 7 (A3): provozni audit uzavreni (vzorky, verdikty cloveka, trvale vypnuti,
        // fail-safe po terminu nebo pri backlogu)
        let audit_policy = crate::closure_audit::AuditPolicy::load(workspace)?;
        let mut audit: crate::closure_audit::ClosureAudit =
            self.store.load("closure_audit")?.unwrap_or_default();
        audit.ensure_secret();
        for event in audit.apply_reviews(self.store.conn(), &audit_policy)? {
            use crate::closure_audit::AuditEvent;
            match event {
                AuditEvent::Reviewed {
                    sample,
                    wrong,
                    actor,
                } => memory.record(
                    now,
                    &actor,
                    "audit_review",
                    &sample.key,
                    &format!("vzorek {} ({}): omyl={wrong}", sample.id, sample.kind),
                ),
                AuditEvent::Disabled { kind, n, wrong } => {
                    tracing::warn!(%kind, n, wrong, "druh automatickeho zavirani trvale vypnut");
                    memory.record(
                        now,
                        "engine",
                        "audit_disable",
                        &crate::finding_memory::FindingKey::new("-", &kind, "-"),
                        &format!("{wrong} omylu z {n} recenzi, dolni mez Wilsona nad cilem"),
                    );
                }
                AuditEvent::Enabled { kind, actor } => memory.record(
                    now,
                    &actor,
                    "audit_enable",
                    &crate::finding_memory::FindingKey::new("-", &kind, "-"),
                    "druh obnoven clovekem",
                ),
            }
        }
        let auto_allowed = audit.auto_close_allowed(&audit_policy, now);
        if !auto_allowed {
            tracing::warn!(
                pending = audit.samples.len(),
                overdue = audit.overdue(now),
                "fail-safe: automaticke zavirani zastaveno (recenze po terminu nebo backlog)"
            );
        }
        for kind in crate::context_gate::ContextKind::ALL {
            if !auto_allowed || audit.is_disabled(kind.label()) {
                gate.disable(kind);
            }
        }
        let ladder_closes = auto_allowed && !audit.is_disabled(crate::closure_audit::LADDER_KIND);
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
        // ulozene pripady novosti s drive prijatym zakazanym dukazem (review kola 2)
        let reset = ladder.reset_forbidden_novelty_evidence();
        if reset > 0 {
            tracing::warn!(
                reset,
                "pripady novosti s kontextem nebo zvykem profilu resetovany"
            );
        }
        if ladder_on && self.engine.learning() && ladder.learner.is_none() {
            ladder.learner = Some(Default::default());
        }
        // profil je dukaz zebriku jen ve v3 s profilem (plati i pro ulozeny zebrik)
        ladder.policy.profile = self.engine.profile();
        // krok 7 (A1): chranene pripady se nevyvraci (plati i pro ulozeny zebrik)
        ladder.policy.protect = self.engine.protect();
        ladder.policy.endpoint = self.engine.endpoint();
        if self.engine.protect() {
            let reset = ladder.reset_forbidden_novelty_evidence();
            if reset > 0 {
                tracing::warn!(reset, "chranene pripady s neskodnym dukazem resetovany");
            }
        }
        let sensor_gap = self.engine.protect() && gate.sensor_gap(&calendar, now);
        let profile_policy = crate::behavior::profile::ProfilePolicy {
            keep_tainted: self.engine.protect(),
            ..Default::default()
        };
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
            let (count, sources) = match behavior_signal.get(&finding.finding_id) {
                Some((count, sources)) => (*count, sources.clone()),
                None => findings::finding_signal(
                    finding,
                    services.get(service_key).copied(),
                    |dst, proto, port, kind| {
                        self.sources
                            .get(&(dst.to_string(), proto.to_string(), port, kind.to_string()))
                            .map(Vec::as_slice)
                            .unwrap_or(&[])
                    },
                ),
            };
            let key = key_for_finding(finding, &entity_host, &sources);
            // krok 7 (A1): P4 degradace (mezera v telemetrii, nezraly profil aktera) a
            // P5 nejednoznacna identita
            let protect = self.engine.protect();
            let degraded = protect
                && (sensor_gap
                    || (self.engine.profile()
                        && crate::protection::immature_actor(
                            &behavior_state.profile,
                            &finding.finding_type,
                            &host_ip,
                            now.timestamp(),
                        )));
            let ambiguous_identity = protect
                && finding
                    .host_key
                    .as_ref()
                    .and_then(|k| identity.get(k))
                    .is_some_and(|m| matches!(m, IdentityMatch::Ambiguous { .. }));
            let ids = [host_ip, entity_host];
            let decision = gate.explain_decision(
                &calendar,
                &GateInput {
                    finding_type: &finding.finding_type,
                    host_ids: &ids,
                    sources: &sources,
                    severity: finding.severity,
                    at: now,
                    protected: degraded || ambiguous_identity,
                },
            );
            let signals = crate::protection::Signals {
                degraded,
                ambiguous: ambiguous_identity || decision.ambiguous,
            };
            let protection = protect
                .then(|| crate::protection::protection(&finding.finding_type, signals))
                .flatten();
            let explanation = decision.explanation;
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
                    protected: protection.is_some(),
                },
                explanation.as_ref().map(|e| e.reason.as_str()),
            );
            let behavioral = !crate::finding_kinds::is_static_exposure(&finding.finding_type);
            let auto_closed = matches!(
                disposition,
                crate::finding_memory::Disposition::AutoResolved(_)
            );
            if let (crate::finding_memory::Disposition::AutoResolved(reason), Some(kind)) =
                (&disposition, explanation.as_ref().map(|e| e.kind))
                && let Some(sample) = audit.maybe_sample(
                    &audit_policy,
                    kind.label(),
                    &key,
                    &finding.finding_id,
                    reason,
                    now,
                )
            {
                memory.record(
                    now,
                    "engine",
                    "audit_sample",
                    &key,
                    &format!("vzorek {} do {}", sample.id, sample.deadline),
                );
            }
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
                            protected: protection.is_some(),
                        },
                        cycle,
                    );
                } else {
                    ladder.observe(&key, &sources, cycle);
                }
            }
            let mut record =
                LifecycleRecord::new(&finding.finding_id, &disposition, memory.get(&key), now);
            record.protection = protection.map(|p| p.label().to_string());
            lifecycle.push(record);
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
                ) || crate::behavior::is_behavior_type(&finding.finding_type);
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
                profile: self
                    .engine
                    .profile()
                    .then_some((&behavior_state.profile, &profile_policy)),
                endpoint: endpoint_view.as_ref(),
            };
            let decisions = ladder.step(cycle, &mut env);
            for decision in &decisions {
                use crate::verify_ladder::Status;
                match decision.status {
                    Status::Refuted if !ladder_closes => {
                        // krok 7 (A3): fail-safe nebo vypnuty druh, rozhodnuti jde cloveku
                        memory.note(
                            &decision.key,
                            "verify_escalate",
                            &format!("audit uzavreni: vyvraceni pozastaveno; {}", decision.reason),
                            now,
                        );
                    }
                    Status::Refuted => {
                        if memory.refute(&decision.key, &decision.reason, now)
                            && let Some(sample) = audit.maybe_sample(
                                &audit_policy,
                                crate::closure_audit::LADDER_KIND,
                                &decision.key,
                                &decision.finding_id,
                                &decision.reason,
                                now,
                            )
                        {
                            memory.record(
                                now,
                                "engine",
                                "audit_sample",
                                &decision.key,
                                &format!("vzorek {} do {}", sample.id, sample.deadline),
                            );
                        }
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
                .map(|d| {
                    let mut record = crate::verify_ladder::DecisionRecord::from(d);
                    if record.status == crate::verify_ladder::Status::Refuted && !ladder_closes {
                        record.status = crate::verify_ladder::Status::Escalated;
                    }
                    record
                })
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
        // krok 3E: profil hostu se uci az po rozhodnuti; dvojice s poplachem ne
        if self.engine.behavior() {
            if self.engine.profile()
                && let Some(flows) = self.behavior_flows.as_ref()
            {
                let frozen = crate::behavior::profile::frozen_pairs(
                    report
                        .findings
                        .iter()
                        .zip(&signal_sources)
                        .filter(|(f, _)| !crate::finding_kinds::is_static_exposure(&f.finding_type))
                        .filter_map(|(f, s)| f.host_key.as_deref().map(|h| (h, s.as_slice())))
                        // krok 7 (B5): souhlasena dvojice se z trvani nenauci
                        .chain(
                            consented_pairs
                                .iter()
                                .map(|(h, s)| (h.as_str(), s.as_slice())),
                        ),
                );
                crate::behavior::learn_profile(
                    &mut behavior_state,
                    &crate::behavior::BehaviorInput {
                        outbound: &flows.outbound,
                        internal: &flows.internal,
                        outbound_alerts: &[],
                        now,
                    },
                    &frozen,
                    &profile_policy,
                );
            }
            self.store.save("behavior", &behavior_state)?;
        }
        // krok 6 (kandidat 2): zobrazeny nalez s dukazem provozni priciny jde do fronty
        // provoz (zaznam v zivotnim cyklu), nic se nezavira
        if let (Some(flows), Some(window)) = (self.behavior_flows.as_ref(), ops_window.as_ref()) {
            let policy = ops_policy.clone();
            let mut marks: crate::ops_evidence::OpsMarks =
                self.store.load("ops_marks")?.unwrap_or_default();
            let at = now.timestamp();
            let mut frozen = std::collections::HashSet::new();
            for ((finding, record), sources) in report
                .findings
                .iter()
                .zip(lifecycle.iter_mut())
                .zip(&signal_sources)
            {
                if !crate::finding_kinds::is_static_exposure(&finding.finding_type) {
                    frozen.extend(sources.iter().cloned());
                }
                let service_key = finding.service_key.as_deref();
                let (_, key_ip) = split_service_key(service_key.unwrap_or("-"));
                let host_ip = finding.host_key.as_deref().unwrap_or(key_ip);
                let fresh = crate::ops_evidence::classify(
                    window,
                    &finding.finding_type,
                    service_key,
                    host_ip,
                    sources,
                    &report.run.scope,
                );
                // znacka plati jen pro epizodu sveho dukazu (review kola 1 S1)
                let escalated =
                    crate::ops_evidence::OpsMarks::memory_contradicts(&record.disposition);
                let reason = marks.update(
                    &finding.finding_id,
                    at,
                    fresh,
                    service_key,
                    sources,
                    escalated,
                );
                // krok 7 (A1): chraneny nalez fronta provoz neodkloni; (B1) anotace
                if record.displayed && self.engine.ops_class() && record.protection.is_none() {
                    record.ops_reason = reason.map(str::to_string);
                }
                if record.displayed && self.engine.ops_annotate() {
                    record.ops_note = reason.map(str::to_string);
                }
            }
            marks.sweep(at);
            clientele.learn(&flows.to_scope, &frozen, at, &policy);
            self.store.save("clientele", &clientele)?;
            self.store.save("ops_marks", &marks)?;
        }
        memory.sweep(now);
        memory.flush(self.store.conn_mut())?;
        self.store.save("closure_audit", &audit)?;
        report.closure_audit = Some(audit.status(&audit_policy, now));
        report.coverage_status = Some(self.coverage(report, &behavior_state, sensor_gap, now));
        report.finding_lifecycle = lifecycle;
        Ok(())
    }

    /// Krok 8: načte uložené koncové události, přiřadí je hostům podle inventáře
    /// (nejednoznačné a neznámé se do verdiktu nedostanou), přidá nálezy `endpoint_alert`
    /// a zapíše pokrytí do reportu.
    fn endpoint_view(
        &self,
        report: &mut RunReport,
        behavior_signal: &mut std::collections::HashMap<String, (u32, Vec<String>)>,
        now: DateTime<Utc>,
    ) -> Result<crate::endpoint::correlate::EndpointView> {
        use crate::endpoint::correlate::{
            EndpointStore, EndpointView, HostDirectory, Limits, Policy,
        };
        let policy = Policy::default();
        let limits = Limits::default();
        let mut directory = HostDirectory::default();
        for host in self.inventory.hosts().iter().chain(report.hosts.iter()) {
            directory.add(
                &host.ip,
                host.hostname.as_deref(),
                std::slice::from_ref(&host.ip),
                host.mac.as_deref(),
            );
        }
        let mut store = EndpointStore::new(limits.clone());
        let events =
            crate::endpoint::persist::load_recent(self.store.conn(), now, &policy, &limits)?;
        for event in events {
            let resolution = directory.resolve(&event.host);
            store.ingest(event, &resolution, now.timestamp());
        }
        let view = EndpointView::build(&store, &directory, now.timestamp(), &policy);
        for assessment in view.suspicious_hosts() {
            let (finding, count, peers) = crate::endpoint::correlate::alert_finding(assessment);
            behavior_signal.insert(finding.finding_id.clone(), (count, peers));
            report.findings.push(finding);
        }
        report
            .findings
            .sort_by(|l, r| l.finding_id.cmp(&r.finding_id));
        report
            .findings
            .dedup_by(|l, r| l.finding_id == r.finding_id);
        report.endpoint_coverage = Some(view.coverage.clone());
        Ok(view)
    }

    /// Krok 7 (A4): degradace pokrytí z dat běhu.
    fn coverage(
        &self,
        report: &RunReport,
        behavior: &crate::behavior::BehaviorState,
        sensor_gap: bool,
        now: DateTime<Utc>,
    ) -> crate::coverage_status::CoverageStatus {
        use crate::coverage_status::{CoverageInput, ICS_PORTS, assess};
        let mut hosts: std::collections::BTreeSet<&str> = Default::default();
        let mut flows_in_window = 0usize;
        let mut ics_flows = 0usize;
        if let Some(flows) = self.behavior_flows.as_ref() {
            for flow in flows.outbound.iter().chain(flows.internal.iter()) {
                flows_in_window += 1;
                if let Some(src) = flow.src_ip.as_deref() {
                    hosts.insert(src);
                }
            }
            for flow in flows.internal.iter().chain(flows.to_scope.iter()) {
                if flow.dst_port.is_some_and(|p| ICS_PORTS.contains(&p)) {
                    ics_flows += 1;
                }
            }
            flows_in_window = flows_in_window.max(flows.to_scope.len());
        }
        let immature_hosts = hosts
            .iter()
            .filter(|h| {
                behavior.profile.host_first(h).is_none_or(|first| {
                    now.timestamp() - first < crate::protection::PROFILE_MATURE_S
                })
            })
            .count();
        let ics_devices = report
            .hosts
            .iter()
            .filter(|h| h.services.iter().any(|s| ICS_PORTS.contains(&s.port)))
            .count();
        assess(&CoverageInput {
            ids_configured: report.run.sources.suricata_eve.is_some(),
            sensor_gap,
            flows_in_window,
            observed_hosts: hosts.len(),
            immature_hosts: if self.engine.profile() {
                immature_hosts
            } else {
                0
            },
            ics_devices,
            ics_flows,
            protect: self.engine.protect(),
        })
    }
}
