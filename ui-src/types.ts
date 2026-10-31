// Tvary dat z API Bakuly. Pole, ktera server nemusi poslat, jsou volitelna -
// UI nikdy nedoplnuje vymyslene hodnoty, chybejici data se zobrazi jako "neznamé".

export type RunIndexEntry = {
  run_id: string;
  nazev: string;
  hosts_total: number;
  services_total: number;
  cves_total: number;
};

export type Severity = "high" | "medium" | "low";

export type Cve = {
  cveId: string;
  cvss?: { base_score: number; severity: string; version?: string } | null;
  summary?: string;
  source?: string;
  references?: string[];
};

export type Service = {
  service_id: string;
  service_key: string;
  proto: string;
  port: number;
  port_state: string;
  state_reason?: string | null;
  inventory: {
    service_name: string;
    product?: string | null;
    version?: string | null;
    extrainfo?: string | null;
    detection_source?: string;
    confidence?: string;
  };
  cpe?: Array<{ cpe23Uri: string; method?: string; confidence?: string; note?: string | null }>;
  cves: Cve[];
  events?: Array<{
    correlation?: { method?: string; confidence?: string };
    event: { source?: string; message?: string; severity?: string; event_type?: string; count?: number };
  }>;
  score: number;
  priorita: string;
};

export type Host = {
  host_id: string;
  host_key: string;
  ip: string;
  hostname?: string | null;
  mac?: string | null;
  vendor?: string | null;
  asset_id?: string | null;
  identity_note?: string | null;
  services: Service[];
};

export type Finding = {
  finding_id: string;
  finding_type: string;
  title: string;
  severity: Severity;
  confidence: string;
  host_key?: string | null;
  service_key?: string | null;
  rationale: string;
  evidence: string[];
  recommendation: string;
};

export type Uncertainty = {
  identity: number | null;
  observation: number | null;
  state: number | null;
  interpretation: number | null;
  aleatoric: number | null;
  epistemic: number | null;
};

export type Hypothesis = {
  affected_assets: string[];
  hypothesis_type: string;
  supporting_evidence: string[];
  contradicting_evidence: string[];
  probability: number | null;
  uncertainty: Partial<Uncertainty>;
  potential_impact: number;
  model_version: string;
};

export type Candidate = {
  method: string;
  estimated_information_gain: number;
  estimated_network_cost: number;
  estimated_runtime_ms: number;
  disruption_risk: number;
  requires_approval: boolean;
};

export type RankedCandidate = { candidate: Candidate; utility: number };

export type VerificationPlan = {
  hypothesis_type: string;
  in_scope_assets: string[];
  excluded_out_of_scope: string[];
  plan: { chosen: RankedCandidate | null; ranked: RankedCandidate[] };
};

export type VerificationResult = {
  hypothesis_type: string;
  method: string;
  asset: string;
  status: "executed" | "reused" | "skipped_out_of_scope" | "skipped_budget" | "needs_approval" | "failed";
  outcome?: string | null;
  runtime_ms?: number | null;
};

export type TriageAction = {
  action_id: string;
  action_type: string;
  title: string;
  priority: string;
  rationale: string;
  evidence: string[];
  recommended_tools: string[];
  target_service_key?: string | null;
  target_asset_id?: string | null;
};

export type NetworkAsset = {
  asset_id: string;
  asset_type: string;
  name: string;
  source: string;
  confidence: string;
  ip?: string | null;
  mac?: string | null;
  vendor?: string | null;
  model?: string | null;
  status?: string | null;
  location?: string | null;
  serial?: string | null;
  linked_host_key?: string | null;
};

/** Skutecna vazba mezi aktivy (LLDP, klient-AP, ARP ...). `details` jsou retezce "klic=hodnota"; "?" = neznamo. */
export type TopologyEdge = {
  edge_id: string;
  relation: string;
  source: string;
  source_asset_id: string;
  target_asset_id: string;
  confidence?: string;
  details?: string[];
};

export type MonitoringLane = {
  lane_id: string;
  lane_type: string;
  source: string;
  status: string;
  title: string;
  summary: string;
  evidence?: string[];
  recommended_tools?: string[];
};

export type Report = {
  schemaVersion?: string;
  run: {
    run_id: string;
    nazev: string;
    started_at: string;
    finished_at: string;
    scope: string[];
    profile: string;
    provider: string;
    enrichment_mode?: string;
  };
  summary: Record<string, number | string>;
  hosts: Host[];
  findings: Finding[];
  hypotheses?: Hypothesis[];
  verification_plans?: VerificationPlan[];
  verification_results?: VerificationResult[];
  triageActions?: TriageAction[];
  networkAssets?: NetworkAsset[];
  topologyEdges?: TopologyEdge[];
  monitoringLanes?: MonitoringLane[];
  unmappedEvents?: unknown[];
  diff?: unknown;
};

export type EnforcementStatus = "proposed" | "approved" | "rejected" | "applied" | "expired" | "failed";

export type EnforcementAction = {
  id: number;
  ip: string;
  ttl_seconds: number;
  reason: string;
  finding_id: string | null;
  status: EnforcementStatus;
  nft_command: string[];
  proposed_at: string;
  decided_by: string | null;
  decided_at: string | null;
  applied_at: string | null;
};

export type EnforcementList = { mode: "dry_run" | "enforce"; actions: EnforcementAction[] };

export type AuditEntry = {
  id: number;
  at: string;
  actor: string;
  action: string;
  subject: string;
  detail: string;
};

export type AuditVerify = { chain_ok: boolean };

export type VerificationLatest = { summary: { total: number; passed: number; failed: number } } | null;

export type AutomationLatest = {
  summary: {
    cycles_total: number;
    tooling_coverage_ratio: number;
    service_identity_coverage_ratio: number;
    automation_agents_total: number;
    automation_rounds_total: number;
    forensic_targets_total: number;
    mas_consensus_score: number;
    mas_consensus_state: string;
    run_ids: string[];
  };
  agents: Array<{ agent_id: string; role: string; status: string; summary: string }>;
  capabilities: Array<{ capability_id: string; label: string; available: boolean; activated: boolean }>;
} | null;

export type AutomationStatus = {
  state: string;
  current_cycle: number;
  total_cycles: number;
  progress_pct: number;
  progress_ratio: number;
  current_phase: string;
  current_phase_label: string;
  message: string;
  latest_run_id?: string | null;
  process_running?: boolean;
  phases: Array<{ phase_id: string; label: string; status: string; progress_pct: number; summary: string }>;
  agents: Array<{ agent_id: string; role: string; status: string; summary: string }>;
} | null;

export type Readiness = {
  status: string;
  grade: string;
  score: number;
  blockers: string[];
  next_steps: string[];
  checks: Array<{ check_id: string; label: string; status: string; score: number; evidence: string[]; next_step: string }>;
} | null;

export type Meta = { auth_required?: boolean };

export type ChatMessage = { role: "assistant" | "user"; text: string; sources?: string[]; streaming?: boolean };

export type PentestMode = "off" | "smart" | "aggressive";
