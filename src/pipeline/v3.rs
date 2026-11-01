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
        let peer_groups: std::collections::HashMap<String, String> = if engine.devices() {
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
        }))
    }

    pub(crate) fn detector(&self) -> Option<&V3StatefulDetector> {
        self.detector.as_ref()
    }

    /// Po detekci: uložit stav detektoru, převzít dominantní zdroje.
    pub(crate) fn finish_detection(&mut self) -> Result<()> {
        if let Some(detector) = self.detector.take() {
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
    ) -> Result<()> {
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
            lifecycle.push(LifecycleRecord::new(
                &finding.finding_id,
                &disposition,
                memory.get(&key),
                now,
            ));
        }
        memory.sweep(now);
        memory.flush(self.store.conn_mut())?;
        report.finding_lifecycle = lifecycle;
        Ok(())
    }
}
