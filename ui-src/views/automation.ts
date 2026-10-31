import { api } from "../api";
import { refreshAll } from "../data";
import { confirmDialog } from "../dialogs";
import { dotMatrix } from "../dotmatrix";
import { state, update, type View } from "../state";
import type { PentestMode } from "../types";
import { notify } from "../notify";
import { esc, pct } from "../ui";
import { chip, emptyState, paneHead, readout } from "./common";

const PENTEST_LABEL: Record<PentestMode, string> = {
  off: "vypnuto (bez aktivních sond)",
  smart: "chytrý (omezené aktivní sondy)",
  aggressive: "agresivní (intenzivní sondy)",
};

const PENTEST_HINT: Record<PentestMode, string> = {
  off: "Další běh poběží bez zapnutého pentestu.",
  smart: "Další běh zapne aktivní kontroly (pentest) v omezeném režimu. Před spuštěním se ptáme na potvrzení.",
  aggressive: "Další běh zapne agresivní pentest s intenzivnějšími sondami. Před spuštěním se ptáme na potvrzení.",
};

async function failureText(response: Response, fallback: string): Promise<string> {
  let detail = "";
  try {
    detail = (await response.text()).trim();
    const parsed = JSON.parse(detail) as { error?: string };
    if (parsed?.error) detail = String(parsed.error);
  } catch {
    /* odpoved neni JSON, pouzijeme text */
  }
  return detail && detail.length < 240 ? `${fallback} ${detail}` : `${fallback} (${response.status})`;
}

const PHASE_STATE: Record<string, string> = {
  done: "hotovo",
  completed: "hotovo",
  running: "běží",
  active: "běží",
  pending: "čeká",
  queued: "čeká",
  failed: "selhalo",
};

const STATE_LABEL: Record<string, string> = {
  idle: "nečinný",
  running: "běží",
  done: "dokončeno",
  completed: "dokončeno",
  failed: "selhalo",
  error: "chyba",
  queued: "čeká",
  pending: "čeká",
};

const CHECK_STATE: Record<string, string> = {
  ok: "v pořádku",
  pass: "v pořádku",
  warn: "pozor",
  warning: "pozor",
  fail: "nevyhovuje",
  error: "chyba",
  partial: "částečně připraveno",
  ready: "připraveno",
  not_ready: "nepřipraveno",
};
const checkState = (value: string) => CHECK_STATE[value] ?? value;

function ring(percent: number): string {
  const r = 52;
  const c = 2 * Math.PI * r;
  const filled = (Math.max(0, Math.min(100, percent)) / 100) * c;
  return `<svg class="ring" viewBox="0 0 120 120" aria-hidden="true"><circle class="ring-track" cx="60" cy="60" r="${r}"/><circle class="ring-fill" cx="60" cy="60" r="${r}" stroke-dasharray="${filled.toFixed(1)} ${c.toFixed(1)}" transform="rotate(-90 60 60)"/></svg>`;
}

function statusBlock(): string {
  const status = state.automationStatus;
  if (!status) return emptyState("Autopilot neodpovídá", "Server neposlal stav automatizace.");
  const running = Boolean(status.process_running);
  return `<section class="auto-status" aria-label="Stav autopilota">
    <div class="ring-wrap">${ring(status.progress_pct)}<div class="ring-dm">${dotMatrix(`${status.progress_pct}%`)}</div></div>
    <div>
      <p class="eyebrow">Autopilot</p>
      <p class="auto-state" role="status">${running ? "běží" : esc(STATE_LABEL[status.state] ?? status.state)}</p>
      <p class="small muted">cyklus ${status.current_cycle} z ${status.total_cycles} · ${esc(status.current_phase_label)}</p>
      <p class="small">${esc(status.message)}</p>
      ${running ? `<button type="button" class="btn btn-hot" data-action="auto-stop">Zastavit autopilota</button>` : ""}
    </div>
  </section>
  <ul class="phases" aria-label="Fáze">${status.phases
    .map((p) => `<li><span class="dot dot-${esc(p.status)}"></span><span>${esc(p.label)}</span><span class="small muted">${esc(PHASE_STATE[p.status] ?? p.status)}</span></li>`)
    .join("")}</ul>`;
}

function controls(): string {
  const options = (["off", "smart", "aggressive"] as PentestMode[])
    .map((m) => `<option value="${m}"${state.pentestMode === m ? " selected" : ""}>${PENTEST_LABEL[m]}</option>`)
    .join("");
  const running = Boolean(state.automationStatus?.process_running);
  return `<div class="controls">
    <label class="field"><span>Aktivní kontroly (pentest) pro další běh</span><select data-action="pentest-mode" aria-describedby="pentest-hint">${options}</select></label>
    <p id="pentest-hint" class="small ${state.pentestMode === "off" ? "muted" : "hot-text"}">${esc(PENTEST_HINT[state.pentestMode])}${state.pentestMode === "aggressive" ? " Použij jen v autorizovaném rozsahu." : ""}</p>
    <div class="actions-row">
      <button type="button" class="btn" data-action="auto-restart"${running ? ' disabled aria-describedby="restart-why"' : ""}>Spustit nový běh</button>
      <button type="button" class="btn btn-ghost" data-action="auto-reset">${running ? "Zastavit a vynulovat" : "Vynulovat stav"}</button>
    </div>
    ${running ? `<p id="restart-why" class="small muted">Autopilot právě běží. Nový běh jde spustit až po jeho dokončení nebo zastavení.</p>` : ""}
  </div>`;
}

function readinessBlock(): string {
  const r = state.readiness;
  if (!r) return emptyState("Připravenost není k dispozici", "Server neposlal hodnocení připravenosti.");
  return `<section aria-label="Připravenost">
    <div class="grade-row"><div class="grade-dm">${dotMatrix(r.grade || "?")}</div><div><p class="eyebrow">Připravenost</p><p class="mono">${Math.round(r.score)} / 100 · ${esc(checkState(r.status))}</p></div></div>
    ${r.blockers.length ? `<h3 class="eyebrow">Blokující</h3><ul class="plain">${r.blockers.map((b) => `<li class="small"><i class="note-dot"></i>${esc(b)}</li>`).join("")}</ul>` : ""}
    ${r.next_steps.length ? `<h3 class="eyebrow">Další kroky</h3><ul class="plain">${r.next_steps.map((b) => `<li class="small">${esc(b)}</li>`).join("")}</ul>` : ""}
    <h3 class="eyebrow">Kontroly (${r.checks.length})</h3>
    <div class="checks">${r.checks
      .map(
        (c) =>
          `<details class="check"><summary><span>${esc(c.label)}</span><span class="mono small">${Math.round(c.score)}</span>${chip(checkState(c.status), c.status === "ok" || c.status === "pass" ? "ink" : "mute")}</summary><div class="check-body">${c.evidence.map((e) => `<p class="mono small">${esc(e)}</p>`).join("")}${c.next_step ? `<p class="small">${esc(c.next_step)}</p>` : ""}</div></details>`,
      )
      .join("")}</div>
  </section>`;
}

function agentsBlock(): string {
  const latest = state.automationLatest;
  const ver = state.verification;
  const parts: string[] = [];
  if (latest) {
    const s = latest.summary;
    parts.push(`<div class="readouts readouts-row">
      ${readout(s.automation_agents_total, "agenti")}
      ${readout(s.cycles_total, "cykly")}
      ${readout(s.forensic_targets_total, "forenzní cíle")}
      ${readout(String(s.mas_consensus_state).slice(0, 6), "shoda", "", true)}
    </div>
    <p class="small muted">Pokrytí nástroji ${pct(s.tooling_coverage_ratio)} · identita služeb ${pct(s.service_identity_coverage_ratio)}</p>`);
    parts.push(`<h3 class="eyebrow">Schopnosti</h3><ul class="caps">${latest.capabilities
      .map((c) => `<li class="${c.available ? "" : "is-off"}"><span class="dot ${c.activated ? "dot-active" : c.available ? "dot-pending" : "dot-off"}"></span>${esc(c.label)}</li>`)
      .join("")}</ul>`);
  }
  if (ver) {
    parts.push(`<p class="small">Ověřovací scénáře: <span class="mono">${ver.summary.passed} / ${ver.summary.total}</span> prošlo${ver.summary.failed ? `, ${ver.summary.failed} selhalo` : ""}.</p>`);
  }
  return parts.join("") || `<p class="muted small">Žádná data o agentech.</p>`;
}

function render(): string {
  return `${paneHead("Automat")}
  <div class="auto scroll" data-keep="auto">
    <div class="auto-col">${statusBlock()}${controls()}${agentsBlock()}</div>
    <div class="auto-col">${readinessBlock()}</div>
  </div>`;
}

async function stopAutopilot() {
  const running = Boolean(state.automationStatus?.process_running);
  const ok = await confirmDialog(
    running ? "Zastavit autopilota?" : "Vynulovat stav autopilota?",
    running
      ? "Okamžitě ukončí běžící proces autopilota a smaže jeho rozpracovaný stav. Právě probíhající běh se nedokončí."
      : "Smaže se rozpracovaný stav automatizace.",
    running ? "Zastavit" : "Vynulovat",
    running,
    { impact: "Už uložené běhy a zásahy zůstanou. Nový běh pak spustíš tlačítkem Spustit nový běh." },
  );
  if (!ok) return;
  const response = await api.resetAutomation();
  if (!response.ok) update({ error: await failureText(response, "Zastavení selhalo.") });
  else notify(running ? "Autopilot zastaven, jeho stav je vynulovaný." : "Stav autopilota je vynulovaný.");
  await refreshAll(true);
}

export const automation: View = {
  id: "automat",
  label: "Automat",
  abbr: "AT",
  render,
  actions: {
    "pentest-mode": (el) => {
      const mode = (el as HTMLSelectElement).value as PentestMode;
      window.localStorage.setItem("bakulaPentestMode", mode);
      update({ pentestMode: mode });
    },
    "auto-restart": async () => {
      if (state.pentestMode !== "off") {
        const aggressive = state.pentestMode === "aggressive";
        const scope = state.report?.run.scope?.join(", ");
        const ok = await confirmDialog(
          aggressive ? "Spustit agresivní běh?" : "Spustit běh s aktivními kontrolami?",
          aggressive
            ? "Agresivní režim posílá intenzivnější sondy na všechny stanice v rozsahu. Pokračuj jen s oprávněním k testování."
            : "Běh zapne aktivní kontroly (pentest) v omezeném režimu. Do sítě se pošle skutečný provoz.",
          "Spustit",
          true,
          { details: [["Režim", PENTEST_LABEL[state.pentestMode]], ...(scope ? ([["Rozsah předchozího běhu", scope]] as Array<[string, string]>) : [])], impact: "Spuštěný autopilot jde zastavit tlačítkem Zastavit autopilota." },
        );
        if (!ok) return;
      }
      const response = await api.restartAutomation(state.pentestMode);
      if (!response.ok) update({ error: await failureText(response, "Spuštění běhu selhalo.") });
      else {
        update({ error: null, followLatest: true });
        notify("Autopilot se spouští. Stav se obnoví za několik sekund.");
      }
      await refreshAll(true);
    },
    "auto-stop": () => stopAutopilot(),
    "auto-reset": () => stopAutopilot(),
  },
};
