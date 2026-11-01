import { actions as map, barHtml, currentScope, ctxModel, loadFromHash, mapFrameHtml, modelFor, mountMap, selectedItem } from "../mapctl";
import { statusLabel } from "../netmodel";
import { profileHtml, statsHtml } from "../panels";
import { navigate } from "../router";
import { sendPrompt, setAssistantOpen } from "../assistant";
import { state, type View } from "../state";
import { methodLabel } from "../glossary";
import { esc, fmtDate, num } from "../ui";
import type { DeviceKind } from "../devices";
import type { NetModel } from "../netmodel";
import { noDataState, paneHead, readout } from "./common";

function sideHtml(): string {
  const report = state.report!;
  const model = ctxModel()!;
  const sel = selectedItem();
  const high = report.findings.filter((f) => f.severity === "high").length;
  const plans = report.verification_plans ?? [];
  const pending = state.enforcement ? state.enforcement.actions.filter((a) => a.status === "proposed").length : null;
  const consensus = String(report.summary.mas_consensus_state ?? "");
  const hops = model.hops;
  return `${sel ? `<div class="host-card profile" role="region" aria-label="Profil zařízení ${esc(sel.ip)}">${profileHtml(model, report, sel)}</div>` : ""}
    ${statsHtml(model, report, currentScope())}
    ${hops.length ? hopList(hops) : ""}
    <div class="run-meta">
      <p class="eyebrow">Běh</p>
      <p class="run-name">${esc(report.run.nazev)}</p>
      <p class="mono small muted">${esc(fmtDate(report.run.finished_at))}</p>
      <p class="mono small muted">rozsah ${esc(report.run.scope.join(", "))} · ${esc(report.run.profile)}</p>
      ${consensus ? `<p class="consensus"><span class="eyebrow">Shoda agentů</span><span class="mono">${esc(consensus)}</span></p>` : ""}
    </div>
    <div class="readouts">
      ${readout(report.hosts.length, "stanice")}
      ${readout(num(report.summary.services_total) || report.hosts.reduce((n, h) => n + h.services.length, 0), "služby")}
      ${readout(report.findings.length, "nálezy")}
      ${readout(high, "vysoké", high ? "hot" : "")}
      ${readout(num(report.summary.cves_total), "CVE")}
      ${readout(plans.length, "plány ověření")}
    </div>
    <p class="pending-line">${
      pending === null
        ? `<span class="muted small">Zásahy: server je neposkytuje.</span>`
        : pending > 0
          ? `<button type="button" class="btn btn-hot" data-action="goto" data-key="zasahy">${pending} ${pending === 1 ? "zásah čeká" : "zásahy čekají"} na schválení</button>`
          : `<span class="muted small">Žádný zásah nečeká na schválení.</span>`
    }</p>`;
}

function render(): string {
  const report = state.report;
  if (!report) return noDataState("Mapa sítě");
  if (!report.hosts.length) return `${paneHead("Mapa sítě")}<div class="overview"><p class="muted">Běh neobsahuje žádné stanice.</p></div>`;
  const model = modelFor(report);
  loadFromHash(model);
  if (state.selectedHost && !model.byKey.has(state.selectedHost)) state.selectedHost = null;
  return `<h1 class="sr-only">Mapa sítě</h1>
  <div class="overview${state.selectedHost ? " has-profile" : ""}">
    <section class="field-wrap" aria-label="Mapa sítě">
      ${barHtml(model)}
      ${mapFrameHtml(model, report.run.run_id)}
    </section>
    <aside class="side" aria-label="Statistika a profil zařízení" data-keep="side"><div id="sideBody"></div></aside>
  </div>`;
}

function hopList(hops: NetModel["hops"]): string {
  return `<div class="hops-card">
    <p class="eyebrow">Cesta skoků agenta</p>
    <p class="small muted">Agent při ověřování podezřelého uzlu postupně zkontroloval tyto stanice. Klepnutím doletíš na stanici na mapě.</p>
    <ol class="hop-list">${hops
      .map((hop) => {
        const host = ctxModel()?.byIp.get(hop.asset);
        const inner = `<span class="hop-no">${hop.index}</span><span class="hop-main"><span class="mono">${esc(hop.asset)}</span><span class="small muted">${esc(methodLabel(hop.method))} · ${esc(statusLabel(hop.status))}${hop.outcome ? ` · ${esc(hop.outcome)}` : ""}${host ? "" : " · mimo mapu (vnější adresa)"}</span></span>`;
        return host
          ? `<li class="st-${hop.status}"><button type="button" class="hop-btn" data-action="select-hop" data-host="${esc(host.key)}" aria-pressed="${state.selectedHost === host.key}">${inner}</button></li>`
          : `<li class="st-${hop.status}"><div class="hop-btn is-static">${inner}</div></li>`;
      })
      .join("")}</ol>
  </div>`;
}

export const overview: View = {
  id: "prehled",
  label: "Mapa sítě",
  abbr: "MA",
  render,
  after: () => {
    const field = document.querySelector<HTMLElement>(".field-wrap");
    if (field && state.report?.hosts.length) mountMap(field, state.report, sideHtml);
  },
  actions: {
    "select-pebble": (el) => map.select(el.dataset.host ?? null),
    "select-hop": (el) => {
      if (el.dataset.host) map.pick(el.dataset.host);
    },
    "pick-host": (el) => {
      if (el.dataset.host) map.pick(el.dataset.host);
    },
    zone: (el) => {
      if (el.dataset.zone) map.zone(el.dataset.zone);
    },
    "chip-zone": (el) => {
      if (el.dataset.zone) map.chipZone(el.dataset.zone);
    },
    "chip-kind": (el) => {
      if (el.dataset.kind) map.chipKind(el.dataset.kind as DeviceKind);
    },
    "chip-sev": (el) => map.chipSev(Number(el.dataset.sev)),
    "clear-filter": () => map.clearFilter(),
    crumb: (el) => map.crumb(el.dataset.level ?? "all"),
    deselect: () => map.deselect(),
    "toggle-bar": () => map.toggleBar(),
    "ask-scan": (el) => {
      const item = el.dataset.host ? ctxModel()?.byKey.get(el.dataset.host) : null;
      setAssistantOpen(true);
      void sendPrompt(`Zařízení ${item?.ip ?? ""} se nepodařilo rozpoznat. Jak ho bezpečně ověřit aktivním skenem a co před tím schválit?`);
    },
    "open-finding": (el) => navigate("nalezy", el.dataset.key ?? null),
    "open-host": (el) => {
      state.selectedHost = el.dataset.key ?? null;
      navigate("hostitele", el.dataset.key ?? null);
    },
    goto: (el) => navigate((el.dataset.key as never) ?? "prehled"),
  },
};
