import { navigate } from "../router";
import { state, update, type View } from "../state";
import type { Finding, Hypothesis } from "../types";
import {
  esc,
  hypothesisForFinding,
  meter,
  pct,
  severityMarker,
  SEVERITY_LABEL,
  UNCERTAINTY_AXES,
} from "../ui";
import { backButton, chip, emptyState, paneHead } from "./common";

function filtered(): Finding[] {
  const all = state.report?.findings ?? [];
  const rank = { high: 0, medium: 1, low: 2 } as const;
  return all
    .filter((f) => state.findingFilter === "all" || f.severity === state.findingFilter)
    .sort((a, b) => rank[a.severity] - rank[b.severity] || a.title.localeCompare(b.title, "cs"));
}

function filters(): string {
  const all = state.report?.findings ?? [];
  const mk = (id: typeof state.findingFilter, label: string, count: number) =>
    `<button type="button" class="seg${state.findingFilter === id ? " is-on" : ""}" aria-pressed="${state.findingFilter === id}" data-action="finding-filter" data-key="${id}">${label} <span class="mono">${count}</span></button>`;
  return `<div class="segmented" role="group" aria-label="Filtr závažnosti">${mk("all", "Vše", all.length)}${mk("high", "Vysoké", all.filter((f) => f.severity === "high").length)}${mk("medium", "Střední", all.filter((f) => f.severity === "medium").length)}${mk("low", "Nízké", all.filter((f) => f.severity === "low").length)}</div>`;
}

function hypothesisBlock(hypothesis: Hypothesis | null): string {
  if (!hypothesis) {
    return `<section class="hyp"><h3 class="eyebrow">Hypotéza</h3><p class="muted small">K tomuto nálezu server neposlal hypotézu.</p></section>`;
  }
  const axes = UNCERTAINTY_AXES.map((axis) => {
    const value = hypothesis.uncertainty?.[axis.key];
    const known = typeof value === "number";
    return `<li class="axis${known ? "" : " is-unknown"}"><span class="axis-name" title="${esc(axis.hint)}">${axis.label}</span>${meter(value ?? null, axis.label)}<span class="mono small">${known ? pct(value) : "neznámé"}</span></li>`;
  }).join("");
  const unknownCount = UNCERTAINTY_AXES.filter((a) => typeof hypothesis.uncertainty?.[a.key] !== "number").length;
  return `<section class="hyp" aria-label="Hypotéza">
    <h3 class="eyebrow">Hypotéza <span class="mono muted">${esc(hypothesis.model_version)}</span></h3>
    <dl class="kv">
      <dt>dopad</dt><dd>${meter(hypothesis.potential_impact, "Dopad")} <span class="mono small">${pct(hypothesis.potential_impact)}</span></dd>
      <dt>pravděpodobnost</dt><dd>${typeof hypothesis.probability === "number" ? pct(hypothesis.probability) : `<span class="muted">neznámé</span> <span class="small muted">(model ji zatím nepočítá)</span>`}</dd>
      <dt>dotčené</dt><dd class="mono">${esc(hypothesis.affected_assets.join(", ") || "neznámé")}</dd>
    </dl>
    <h4 class="eyebrow">Nejistota po osách</h4>
    <ul class="axes">${axes}</ul>
    ${unknownCount ? `<p class="small muted">Prázdné osy (${unknownCount}) nejsou nula. Nejsou změřené.</p>` : ""}
    <p class="small muted">Protiargumenty: ${hypothesis.contradicting_evidence.length ? esc(hypothesis.contradicting_evidence.join("; ")) : "nezaznamenány"}.</p>
  </section>`;
}

function planBlock(finding: Finding): string {
  const plans = state.report?.verification_plans ?? [];
  const plan = plans.find(
    (p) => p.hypothesis_type === finding.finding_type && (!finding.host_key || p.in_scope_assets.includes(finding.host_key)),
  );
  if (!plan) {
    return `<section><h3 class="eyebrow">Další ověření</h3><p class="muted small">Pro tento nález není naplánované žádné ověření (host je mimo rozsah nebo plán nevznikl).</p></section>`;
  }
  const chosen = plan.plan.chosen;
  return `<section><h3 class="eyebrow">Další ověření</h3>
    ${
      chosen
        ? `<p><span class="mono">${esc(chosen.candidate.method)}</span> ${chosen.candidate.requires_approval ? chip("vyžaduje schválení", "hot") : chip("bez schválení", "mute")}</p>
           <p class="small muted">užitečnost <span class="mono">${chosen.utility.toFixed(2)}</span> · riziko narušení ${pct(chosen.candidate.disruption_risk)}</p>`
        : `<p class="muted small">Žádný kandidát.</p>`
    }
    <button type="button" class="btn btn-ghost" data-action="goto" data-key="overovani">Všechny plány</button></section>`;
}

function detail(finding: Finding): string {
  const report = state.report!;
  const host = report.hosts.find((h) => h.host_key === finding.host_key);
  return `${backButton()}
  <div class="detail-head">
    <p class="eyebrow">${severityMarker(finding.severity)} ${esc(SEVERITY_LABEL[finding.severity])} závažnost · jistota ${esc(finding.confidence)}</p>
    <h2>${esc(finding.title)}</h2>
    <p class="small muted mono">${esc(finding.finding_type)}${finding.host_key ? ` · ${esc(finding.host_key)}` : ""}${finding.service_key ? ` · ${esc(finding.service_key)}` : ""}</p>
  </div>
  <section><h3 class="eyebrow">Proč</h3><p>${esc(finding.rationale)}</p></section>
  <section><h3 class="eyebrow">Doporučení</h3><p>${esc(finding.recommendation)}</p></section>
  <section><h3 class="eyebrow">Důkazy (${finding.evidence.length})</h3><ul class="plain evidence">${finding.evidence.map((e) => `<li class="mono small">${esc(e)}</li>`).join("")}</ul></section>
  ${hypothesisBlock(hypothesisForFinding(report, finding))}
  ${planBlock(finding)}
  <div class="actions-row">
    ${host ? `<button type="button" class="btn btn-ghost" data-action="open-host" data-key="${esc(host.host_key)}">Stanice ${esc(host.ip)}</button>` : ""}
    ${host ? `<button type="button" class="btn btn-ghost" data-action="propose-block" data-key="${esc(finding.finding_id)}" data-ip="${esc(host.ip)}">Navrhnout zásah…</button>` : ""}
    <button type="button" class="btn btn-ghost" data-action="ask" data-key="${esc(finding.finding_id)}">Zeptat se asistenta</button>
  </div>`;
}

function render(): string {
  const report = state.report;
  if (!report) return `${paneHead("Nálezy")}${emptyState("Bez dat", "Není načtený žádný běh.")}`;
  const list = filtered();
  const selected = report.findings.find((f) => f.finding_id === state.selectedFinding) ?? null;
  return `${paneHead("Nálezy a hypotézy", filters())}
  <div class="split${selected ? " has-detail" : ""}">
    <div class="split-list"><nav class="list" aria-label="Seznam nálezů" data-keep="findings-list">${
      list.length
        ? list
            .map((f) => {
              const sel = f.finding_id === state.selectedFinding;
              return `<button type="button" class="row${sel ? " is-selected" : ""}" data-action="select-finding" data-key="${esc(f.finding_id)}" aria-current="${sel}">
                ${severityMarker(f.severity)}
                <span class="row-main"><span>${esc(f.title)}</span><span class="small muted mono">${esc(f.host_key ?? "bez stanice")} · ${esc(f.finding_type)}</span></span>
              </button>`;
            })
            .join("")
        : `<p class="muted small pad">Pro tento filtr nejsou žádné nálezy.</p>`
    }</nav></div>
    <article class="split-detail scroll" data-keep="finding-detail" aria-label="Detail nálezu">${
      selected ? detail(selected) : emptyState("Vyber nález", `V běhu je ${report.findings.length} nálezů. U každého je vedle důkazů i hypotéza s nejistotou po osách.`)
    }</article>
  </div>`;
}

export const findings: View = {
  id: "nalezy",
  label: "Nálezy",
  abbr: "NA",
  render,
  actions: {
    "finding-filter": (el) => update({ findingFilter: (el.dataset.key as typeof state.findingFilter) ?? "all" }),
    "select-finding": (el) => update({ selectedFinding: el.dataset.key ?? null }),
    back: () => update({ selectedFinding: null }),
    "open-host": (el) => {
      update({ selectedHost: el.dataset.key ?? null }, false);
      navigate("hostitele", el.dataset.key ?? null);
    },
    goto: (el) => navigate((el.dataset.key as never) ?? "prehled"),
    "propose-block": (el) => {
      update({ proposeDraft: { ...state.proposeDraft, ip: el.dataset.ip ?? "", finding_id: el.dataset.key ?? "" }, proposeError: null }, false);
      navigate("zasahy");
    },
  },
};
