import { api } from "../api";
import { refreshAll } from "../data";
import { confirmDialog } from "../dialogs";
import { dotMatrix } from "../dotmatrix";
import { state, update, type View } from "../state";
import type { PentestMode } from "../types";
import { esc, pct } from "../ui";
import { chip, emptyState, paneHead, readout } from "./common";

const PENTEST_LABEL: Record<PentestMode, string> = {
  off: "vypnuto",
  smart: "chytrý (omezený)",
  aggressive: "agresivní",
};

const PHASE_STATE: Record<string, string> = {
  done: "hotovo",
  completed: "hotovo",
  running: "běží",
  active: "běží",
  pending: "čeká",
  queued: "čeká",
  failed: "selhalo",
};

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
      <p class="auto-state">${running ? "běží" : esc(status.state)}</p>
      <p class="small muted">cyklus ${status.current_cycle} z ${status.total_cycles} · ${esc(status.current_phase_label)}</p>
      <p class="small">${esc(status.message)}</p>
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
  return `<div class="controls">
    <label class="field"><span>Aktivní kontroly (pentest)</span><select data-action="pentest-mode">${options}</select></label>
    <div class="actions-row">
      <button type="button" class="btn" data-action="auto-restart">Spustit nový běh</button>
      <button type="button" class="btn btn-ghost" data-action="auto-reset">Vynulovat stav</button>
    </div>
    ${state.pentestMode === "aggressive" ? `<p class="small hot-text">Agresivní režim posílá intenzivnější sondy. Použij jen v autorizovaném rozsahu.</p>` : ""}
  </div>`;
}

function readinessBlock(): string {
  const r = state.readiness;
  if (!r) return emptyState("Připravenost není k dispozici", "Server neposlal hodnocení připravenosti.");
  return `<section aria-label="Připravenost">
    <div class="grade-row"><div class="grade-dm">${dotMatrix(r.grade || "?")}</div><div><p class="eyebrow">Připravenost</p><p class="mono">${Math.round(r.score)} / 100 · ${esc(r.status)}</p></div></div>
    ${r.blockers.length ? `<h3 class="eyebrow">Blokující</h3><ul class="plain">${r.blockers.map((b) => `<li class="small"><i class="note-dot"></i>${esc(b)}</li>`).join("")}</ul>` : ""}
    ${r.next_steps.length ? `<h3 class="eyebrow">Další kroky</h3><ul class="plain">${r.next_steps.map((b) => `<li class="small">${esc(b)}</li>`).join("")}</ul>` : ""}
    <h3 class="eyebrow">Kontroly (${r.checks.length})</h3>
    <div class="checks">${r.checks
      .map(
        (c) =>
          `<details class="check"><summary><span>${esc(c.label)}</span><span class="mono small">${Math.round(c.score)}</span>${chip(c.status, c.status === "ok" || c.status === "pass" ? "ink" : "mute")}</summary><div class="check-body">${c.evidence.map((e) => `<p class="mono small">${esc(e)}</p>`).join("")}${c.next_step ? `<p class="small">${esc(c.next_step)}</p>` : ""}</div></details>`,
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
      if (state.pentestMode === "aggressive") {
        const ok = await confirmDialog(
          "Spustit agresivní běh?",
          "Agresivní režim posílá intenzivnější sondy na všechny stanice v rozsahu. Pokračuj jen s oprávněním k testování.",
          "Spustit",
          true,
        );
        if (!ok) return;
      }
      const response = await api.restartAutomation(state.pentestMode);
      if (!response.ok) update({ error: `Spuštění běhu selhalo (${response.status}).` });
      else update({ error: null, followLatest: true });
      await refreshAll(true);
    },
    "auto-reset": async () => {
      const ok = await confirmDialog("Vynulovat stav autopilota?", "Smaže se rozpracovaný stav automatizace. Uložené běhy zůstanou.", "Vynulovat");
      if (!ok) return;
      const response = await api.resetAutomation();
      if (!response.ok) update({ error: `Vynulování selhalo (${response.status}).` });
      await refreshAll(true);
    },
  },
};
