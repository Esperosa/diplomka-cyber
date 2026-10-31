// Maketa API pro vyvoj a testy UI. Data vychazeji z tests/golden/full_visibility_stack.json
// (skutecny tvar RunReport), doplnena o nove endpointy (zasahy, audit, vysledky overovani).
// NIKDY se nepouziva v produkci - UI samo zadna mock data neobsahuje.
//
//   node scripts/mock-server.mjs [port]     (vychozi port 8787)
//   MOCK_ROLE=analyst   -> approve/reject vraci 403 (test oprávnění)
//   MOCK_AUTH=1         -> vyzaduje Authorization: Bearer test
//   MOCK_EMPTY=1        -> server bez bezu a bez novych endpointu (404)

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const uiDir = join(root, "ui");
const port = Number(process.argv[2] ?? process.env.PORT ?? 8787);
const ROLE = process.env.MOCK_ROLE ?? "operator";
const AUTH = process.env.MOCK_AUTH === "1";
const EMPTY = process.env.MOCK_EMPTY === "1";

const golden = JSON.parse(await readFile(join(root, "tests/golden/full_visibility_stack.json"), "utf8"));

const CLEAN_TEXT = {
  connection_timeout_burst: ["Pasivní vrstva zachytila opakované timeouty a retry stavy, které často doprovází přetížení nebo agresivní skenovací vzor.", "Prověřit limity služby, fronty a firewall. Při útoku dočasně zpřísnit rate limit."],
  default: ["Nález vznikl z korelace pasivních událostí a aktivního inventáře.", "Ověřit nález na stanici a rozhodnout o dalším kroku."],
};
const fix = (text, type, index) => (typeof text === "string" && text.includes("�") ? (CLEAN_TEXT[type] ?? CLEAN_TEXT.default)[index] : text);

function cleanReport(report) {
  const r = structuredClone(report);
  for (const f of r.findings) {
    f.rationale = fix(f.rationale, f.finding_type, 0);
    f.recommendation = fix(f.recommendation, f.finding_type, 1);
    f.evidence = f.evidence.map((e) => (e.includes("�") ? e.replace(/�+/g, "") : e));
    f.title = fix(f.title, f.finding_type, 0);
  }
  for (const t of r.triageActions ?? []) {
    t.rationale = fix(t.rationale, "default", 0);
    t.title = fix(t.title, "default", 0);
  }
  return r;
}

function baseReport(id, nazev, minutesAgo) {
  const r = cleanReport(golden);
  const now = Date.now() - minutesAgo * 60000;
  r.run.run_id = id;
  r.run.nazev = nazev;
  r.run.started_at = new Date(now - 7 * 60000).toISOString();
  r.run.finished_at = new Date(now).toISOString();
  r.summary.mas_parallelism_ratio = 0.78;
  r.summary.mas_queue_wait_ms_avg = 41.2;
  r.summary.mas_agent_sla_ratio = 0.94;
  r.verification_results = [
    { hypothesis_type: "high_risk_cve_exposure", method: "cve_intel_relookup", asset: "192.168.56.10", status: "executed", outcome: "2 CVE potvrzeno v KEV", runtime_ms: 412 },
    { hypothesis_type: "high_risk_cve_exposure", method: "cve_intel_relookup", asset: "192.168.56.10", status: "reused", outcome: "převzato z dřívější kontroly", runtime_ms: 0 },
    { hypothesis_type: "http_basic_without_tls", method: "read_only_content_inspection", asset: "192.168.56.20", status: "executed", outcome: "přihlašovací formulář bez TLS", runtime_ms: 1380 },
    { hypothesis_type: "correlation_uncertainty", method: "nmap_targeted_followup", asset: "192.168.56.30", status: "needs_approval", outcome: null, runtime_ms: null },
    { hypothesis_type: "unexpected_traffic", method: "passive_extended_observation", asset: "203.0.113.50", status: "skipped_out_of_scope", outcome: null, runtime_ms: null },
  ];
  return r;
}

// Rozsahly bezr pro test rozlozeni pole (14 stanic).
function largeReport(id, nazev, minutesAgo) {
  const r = baseReport(id, nazev, minutesAgo);
  const templates = r.hosts;
  const findings = [];
  const hypotheses = [];
  const hosts = [];
  for (let i = 0; i < 14; i += 1) {
    const t = structuredClone(templates[i % templates.length]);
    const ip = `192.168.56.${40 + i * 3}`;
    t.ip = ip;
    t.host_key = ip;
    t.host_id = `host:${ip}`;
    t.asset_id = `asset:${100 + i}`;
    t.hostname = ["web", "db", "cache", "vpn", "nas", "print", "iot", "cam", "ap", "mail", "git", "ci", "dns", "bak"][i] + `-${i + 1}`;
    t.services = t.services.slice(0, 1 + (i % 3)).map((s) => ({ ...s, service_key: `${ip}/${s.proto}/${s.port}`, service_id: `svc:${ip}/${s.proto}/${s.port}`, cves: i % 4 === 0 ? s.cves : i % 4 === 1 ? s.cves.slice(0, 1) : [] }));
    hosts.push(t);
    const source = r.findings.filter((f) => f.host_key === templates[i % templates.length].host_key);
    source.forEach((f, k) => {
      if (k > 1 && i % 2) return;
      const nf = structuredClone(f);
      nf.host_key = ip;
      nf.finding_id = `${f.finding_id}:${i}`;
      nf.severity = i % 5 === 0 ? "high" : i % 3 === 0 ? "medium" : f.severity;
      findings.push(nf);
      const hyp = r.hypotheses.find((h) => h.hypothesis_type === f.finding_type) ?? r.hypotheses[0];
      const nh = structuredClone(hyp);
      nh.affected_assets = [ip];
      hypotheses.push(nh);
    });
  }
  r.hosts = hosts;
  r.findings = findings;
  r.hypotheses = hypotheses;
  r.verification_plans = hypotheses.slice(0, 18).map((h, i) => {
    const base = structuredClone(r.verification_plans[i % r.verification_plans.length]);
    base.in_scope_assets = h.affected_assets;
    base.hypothesis_type = h.hypothesis_type;
    if (i % 7 === 3) base.excluded_out_of_scope = ["203.0.113.50"];
    return base;
  });
  return r;
}

const RUNS = [
  { id: "run-20261031120000-1-demo", nazev: "Full visibility stack", build: () => baseReport("run-20261031120000-1-demo", "Full visibility stack", 6) },
  { id: "run-20261031090000-1-large", nazev: "Rozsáhlá síť (ukázka, 14 stanic)", build: () => largeReport("run-20261031090000-1-large", "Rozsáhlá síť (ukázka, 14 stanic)", 190) },
];

// ---------- stav zasahu ----------
const nowIso = () => new Date().toISOString();
let enforcementMode = process.env.MOCK_MODE ?? "dry_run";
let nextId = 4;
const actions = [
  { id: 1, ip: "203.0.113.50", ttl_seconds: 3600, reason: "Opakované skenování portů z vnější adresy", finding_id: null, status: "applied", nft_command: ["add", "element", "inet", "bakula", "blocked_ips", "{ 203.0.113.50 timeout 3600s }"], proposed_at: new Date(Date.now() - 22 * 60000).toISOString(), decided_by: "operator", decided_at: new Date(Date.now() - 20 * 60000).toISOString(), applied_at: new Date(Date.now() - 20 * 60000).toISOString() },
  { id: 2, ip: "198.51.100.7", ttl_seconds: 900, reason: "Podezřelý C2 provoz na 4444/tcp", finding_id: golden.findings[0].finding_id, status: "proposed", nft_command: ["add", "element", "inet", "bakula", "blocked_ips", "{ 198.51.100.7 timeout 900s }"], proposed_at: new Date(Date.now() - 3 * 60000).toISOString(), decided_by: null, decided_at: null, applied_at: null },
  { id: 3, ip: "198.51.100.99", ttl_seconds: 600, reason: "Zkušební návrh", finding_id: null, status: "rejected", nft_command: ["add", "element", "inet", "bakula", "blocked_ips", "{ 198.51.100.99 timeout 600s }"], proposed_at: new Date(Date.now() - 90 * 60000).toISOString(), decided_by: "operator", decided_at: new Date(Date.now() - 85 * 60000).toISOString(), applied_at: null },
];
const audit = [
  { id: 1, at: new Date(Date.now() - 95 * 60000).toISOString(), actor: "analyst", action: "enforcement.propose", subject: "198.51.100.99", detail: "ttl=600s" },
  { id: 2, at: new Date(Date.now() - 85 * 60000).toISOString(), actor: "operator", action: "enforcement.reject", subject: "#3", detail: "zamítnuto" },
  { id: 3, at: new Date(Date.now() - 22 * 60000).toISOString(), actor: "analyst", action: "enforcement.propose", subject: "203.0.113.50", detail: "ttl=3600s" },
  { id: 4, at: new Date(Date.now() - 20 * 60000).toISOString(), actor: "operator", action: "enforcement.approve", subject: "#1", detail: "schváleno" },
  { id: 5, at: new Date(Date.now() - 3 * 60000).toISOString(), actor: "analyst", action: "enforcement.propose", subject: "198.51.100.7", detail: "ttl=900s" },
].reverse();

const PROTECTED = [/^127\./, /^169\.254\./, /^22[4-9]\.|^23\d\./, /^192\.168\.56\.1$/];

// ---------- pomocne ----------
const send = (res, status, body, headers = {}) => {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, { "content-type": typeof body === "string" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8", "cache-control": "no-store", ...headers });
  res.end(payload);
};
const readBody = (req) => new Promise((resolve) => {
  let data = "";
  req.on("data", (c) => (data += c));
  req.on("end", () => { try { resolve(data ? JSON.parse(data) : {}); } catch { resolve({}); } });
});
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".json": "application/json", ".png": "image/png", ".svg": "image/svg+xml" };

const automationStatus = {
  state: "idle", current_cycle: 3, total_cycles: 3, progress_pct: 100, progress_ratio: 1, current_phase: "finalize", current_phase_label: "Dokončeno", message: "Poslední cyklus doběhl bez chyby.", latest_run_id: RUNS[0].id, process_running: process.env.MOCK_RUNNING === "1",
  phases: [
    { phase_id: "inventory", label: "Inventář služeb", status: "done", progress_pct: 100, summary: "" },
    { phase_id: "followup", label: "Cílený follow-up", status: "done", progress_pct: 100, summary: "" },
    { phase_id: "forensic", label: "Forenzní vrstva", status: "done", progress_pct: 100, summary: "" },
    { phase_id: "finalize", label: "Uzavření běhu", status: "done", progress_pct: 100, summary: "" },
  ],
  agents: [],
};

createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const path = url.pathname;
  try {
    if (path.startsWith("/api/")) return await api(req, res, url, path);
    let file = normalize(path === "/" ? "/index.html" : path).replace(/^(\.\.[/\\])+/, "");
    const data = await readFile(join(uiDir, file)).catch(() => null);
    if (!data) return send(res, 404, "Nenalezeno");
    res.writeHead(200, { "content-type": MIME[extname(file)] ?? "application/octet-stream", "cache-control": "no-store" });
    res.end(data);
  } catch (error) {
    send(res, 500, { error: String(error) });
  }
}).listen(port, "127.0.0.1", () => console.log(`Mock API + UI na http://127.0.0.1:${port}/ (role=${ROLE}, auth=${AUTH}, empty=${EMPTY})`));

async function api(req, res, url, path) {
  const method = req.method ?? "GET";
  if (AUTH && path !== "/api/meta" && req.headers.authorization !== "Bearer test") return send(res, 401, { error: "token" });
  if (method !== "GET" && req.headers["x-bakula-csrf"] !== "1") return send(res, 403, { error: "Chybí hlavička X-Bakula-Csrf." });

  if (path === "/api/meta") return send(res, 200, { auth_required: AUTH });
  if (path === "/api/runs") return send(res, 200, EMPTY ? [] : RUNS.map((run) => { const r = run.build(); return { run_id: run.id, nazev: run.nazev, hosts_total: r.hosts.length, services_total: r.hosts.reduce((n, h) => n + h.services.length, 0), cves_total: Number(r.summary.cves_total) }; }));
  const runMatch = path.match(/^\/api\/runs\/([^/]+)(?:\/(export|assistant)(?:\/(stream|json|md|txt))?)?$/);
  if (runMatch) {
    const run = RUNS.find((r) => r.id === decodeURIComponent(runMatch[1]));
    if (!run || EMPTY) return send(res, 404, { error: "run" });
    if (!runMatch[2]) return send(res, 200, run.build());
    if (runMatch[2] === "export") return send(res, 200, JSON.stringify(run.build()), { "content-disposition": `attachment; filename="${run.id}.${runMatch[3]}"` });
    if (runMatch[2] === "assistant") {
      const body = await readBody(req);
      const text = `K dotazu „${String(body.prompt ?? "").slice(0, 60)}“: nejdřív ověř službu s nejvyšším CVSS a teprve potom navrhuj zásah. Plán ověřování k tomu doporučuje čtecí kontrolu bez schválení.`;
      if (runMatch[3] === "stream") {
        res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store" });
        for (const word of text.split(" ")) { res.write(`data: ${JSON.stringify({ type: "chunk", text: word + " " })}\n\n`); await new Promise((r) => setTimeout(r, 15)); }
        res.write(`data: ${JSON.stringify({ type: "done", mode: "mock", sources: ["finding"] })}\n\n`);
        return res.end();
      }
      return send(res, 200, { answer: text, mode: "mock", sources: [{ label: "finding" }] });
    }
  }
  if (path === "/api/verification/latest") return send(res, 200, EMPTY ? null : { summary: { total: 6, passed: 6, failed: 0 } });
  if (path === "/api/automation/status") return send(res, 200, EMPTY ? null : automationStatus);
  if (path === "/api/automation/latest") return send(res, 200, EMPTY ? null : {
    summary: { cycles_total: 3, tooling_coverage_ratio: 0.8, service_identity_coverage_ratio: 1, automation_agents_total: 22, automation_rounds_total: 3, forensic_targets_total: 3, mas_consensus_score: 0.65, mas_consensus_state: "review", run_ids: [RUNS[0].id] },
    agents: [], capabilities: [{ capability_id: "nmap", label: "Nmap inventář", available: true, activated: true }, { capability_id: "zeek", label: "Zeek pasivní senzor", available: true, activated: true }, { capability_id: "suricata", label: "Suricata alerty", available: true, activated: false }, { capability_id: "nuclei", label: "Nuclei šablony", available: false, activated: false }],
  });
  if (path === "/api/automation/restart" || path === "/api/automation/reset") return send(res, 200, { ok: true });
  if (path === "/api/readiness") return send(res, 200, EMPTY ? null : { status: "partial", grade: "B", score: 78, blockers: ["Chybí produkční Zeek sensor"], next_steps: ["Připojit Zeek log adresář", "Zapnout API token"], checks: [{ check_id: "auth", label: "Autentizace API", status: "ok", score: 100, evidence: ["require_api_token=true"], next_step: "" }, { check_id: "passive", label: "Pasivní telemetrie", status: "warn", score: 40, evidence: ["zeek: nenalezeno"], next_step: "Připojit Zeek log adresář" }] });
  if (path === "/api/ai/status") return send(res, 200, { mode: "mock" });

  if (EMPTY && (path.startsWith("/api/enforcement") || path.startsWith("/api/audit"))) return send(res, 404, { error: "nenalezeno" });

  if (path === "/api/enforcement/actions") return send(res, 200, { mode: enforcementMode, actions });
  if (path === "/api/enforcement/propose" && method === "POST") {
    if (ROLE === "viewer") return send(res, 403, { error: "Forbidden" });
    const body = await readBody(req);
    const ip = String(body.ip ?? "");
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip) && !ip.includes(":")) return send(res, 422, { error: "UnparseableIp" });
    if (PROTECTED.some((re) => re.test(ip))) return send(res, 422, { error: "ProtectedRange" });
    if (!(body.ttl_seconds >= 1 && body.ttl_seconds <= 86400)) return send(res, 422, { error: "TtlExceedsMaximum" });
    if (actions.some((a) => a.ip === ip && ["proposed", "approved", "applied"].includes(a.status))) return send(res, 422, { error: "AlreadyActive" });
    const action = { id: nextId++, ip, ttl_seconds: body.ttl_seconds, reason: body.reason ?? "", finding_id: body.finding_id ?? null, status: "proposed", nft_command: ["add", "element", "inet", "bakula", "blocked_ips", `{ ${ip} timeout ${body.ttl_seconds}s }`], proposed_at: nowIso(), decided_by: null, decided_at: null, applied_at: null };
    actions.push(action);
    audit.unshift({ id: audit.length + 1, at: nowIso(), actor: ROLE, action: "enforcement.propose", subject: ip, detail: `ttl=${body.ttl_seconds}s` });
    return send(res, 200, action);
  }
  const decide = path.match(/^\/api\/enforcement\/(\d+)\/(approve|reject)$/);
  if (decide && method === "POST") {
    if (ROLE !== "operator" && ROLE !== "admin") return send(res, 403, { error: "Forbidden" });
    const action = actions.find((a) => a.id === Number(decide[1]));
    if (!action) return send(res, 404, { error: "action" });
    action.status = decide[2] === "approve" ? (enforcementMode === "enforce" ? "applied" : "approved") : "rejected";
    action.decided_by = ROLE;
    action.decided_at = nowIso();
    if (action.status === "applied") action.applied_at = nowIso();
    audit.unshift({ id: audit.length + 1, at: nowIso(), actor: ROLE, action: `enforcement.${decide[2]}`, subject: `#${action.id}`, detail: decide[2] === "approve" ? "schváleno" : "zamítnuto" });
    return send(res, 200, action);
  }
  if (path === "/api/audit") return send(res, 200, audit.slice(0, Number(url.searchParams.get("limit") ?? 100)));
  if (path === "/api/audit/verify") return send(res, 200, { chain_ok: process.env.MOCK_CHAIN_BAD !== "1" });
  return send(res, 404, { error: "nenalezeno" });
}
