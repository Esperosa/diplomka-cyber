import { api } from "./api";
import { state, update } from "./state";

let inFlight = false;
let lastSignature = "";

/** Nacte vsechno potrebne pro aktualni zobrazeni. `silent` = pozadi, bez blikani. */
export async function refreshAll(silent = false) {
  if (inFlight) return;
  inFlight = true;
  if (!silent) update({ loading: true }, true);
  try {
    const meta = await api.meta();
    const [runs, verification, automationLatest, automationStatus, readiness, enforcement] = await Promise.all([
      api.runs(),
      api.verificationLatest(),
      api.automationLatest(),
      api.automationStatus(),
      api.readiness(),
      api.enforcement().catch(() => null),
    ]);

    const latestFromAutopilot =
      automationStatus?.latest_run_id && runs.some((r) => r.run_id === automationStatus.latest_run_id)
        ? automationStatus.latest_run_id
        : (runs[0]?.run_id ?? null);
    const keepCurrent = !state.followLatest && state.activeRunId && runs.some((r) => r.run_id === state.activeRunId);
    const activeRunId = keepCurrent ? state.activeRunId : latestFromAutopilot;
    const report = activeRunId ? await api.run(activeRunId) : null;

    const signature = JSON.stringify([meta, runs, verification, automationLatest, automationStatus, readiness, enforcement, activeRunId, report]);
    if (silent && signature === lastSignature && !state.error && state.connection === "ok") {
      state.lastUpdated = new Date().toISOString();
      return; // nic se nezmenilo: stranku neprekreslujeme (zachova rozbalene radky, vyber i scroll)
    }
    lastSignature = signature;
    update(
      {
        meta,
        runs,
        verification,
        automationLatest,
        automationStatus,
        readiness,
        enforcement,
        activeRunId,
        report,
        error: null,
        connection: "ok",
        loading: false,
        lastUpdated: new Date().toISOString(),
      },
      !silent,
    );
  } catch (error) {
    update(
      {
        error: error instanceof Error ? error.message : String(error),
        connection: "error",
        loading: false,
      },
      !silent,
    );
  } finally {
    inFlight = false;
  }
}

export async function refreshEnforcement() {
  const enforcement = await api.enforcement().catch(() => null);
  update({ enforcement }, true);
}

export async function refreshAudit() {
  try {
    const [audit, auditChain] = await Promise.all([api.audit(state.auditLimit), api.auditVerify().catch(() => null)]);
    update({ audit, auditChain }, true);
  } catch (error) {
    update({ audit: null, error: error instanceof Error ? error.message : String(error) }, true);
  }
}
