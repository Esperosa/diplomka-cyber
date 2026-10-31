import { state, update, type View } from "../state";
import type { RankedCandidate, VerificationPlan, VerificationResult } from "../types";
import { esc, pct } from "../ui";
import { hypothesisLabel, METHOD_INFO, methodLabel } from "../glossary";
import { chip, emptyState, noDataState, paneHead, readout } from "./common";

const RESULT_LABEL: Record<VerificationResult["status"], string> = {
  executed: "provedeno",
  reused: "převzato",
  skipped_out_of_scope: "mimo rozsah",
  skipped_budget: "mimo rozpočet",
  needs_approval: "čeká na schválení",
  failed: "selhalo",
};

function planKey(plan: VerificationPlan, index: number) {
  return `${plan.hypothesis_type}|${plan.in_scope_assets.join(",")}|${index}`;
}

function bars(ranked: RankedCandidate[], chosen: RankedCandidate | null): string {
  const scale = Math.max(0.5, ...ranked.map((r) => Math.abs(r.utility)));
  return `<ul class="ranked" aria-label="Pořadí kandidátů podle užitečnosti">${ranked
    .map((r) => {
      const isChosen = chosen && r.candidate.method === chosen.candidate.method;
      const width = Math.min(50, (Math.abs(r.utility) / scale) * 50);
      const neg = r.utility < 0;
      return `<li class="${isChosen ? "is-chosen" : ""}">
        <span class="cand-name"><span title="${esc(r.candidate.method)}">${esc(methodLabel(r.candidate.method))}</span>${r.candidate.requires_approval ? chip("vyžaduje schválení", "hot") : ""}${isChosen ? chip("vybráno", "ink") : ""}</span>
        <span class="ubar" role="img" aria-label="užitečnost ${r.utility.toFixed(2)}"><i class="${neg ? "neg" : "pos"}" style="width:${width.toFixed(1)}%"></i></span>
        <span class="mono small u-num">${r.utility >= 0 ? "+" : ""}${r.utility.toFixed(2)}</span>
        <span class="small muted cand-meta">zisk ${pct(r.candidate.estimated_information_gain)} · náklad ${r.candidate.estimated_network_cost.toFixed(2)} · ${r.candidate.estimated_runtime_ms} ms · narušení ${pct(r.candidate.disruption_risk)}</span>
      </li>`;
    })
    .join("")}</ul>`;
}

function chosenBlock(chosen: RankedCandidate | null): string {
  if (!chosen) return `<p class="small muted">Pro tuto hypotézu není žádný kandidát na ověření.</p>`;
  const c = chosen.candidate;
  const info = METHOD_INFO[c.method];
  return `<section class="chosen-box" aria-label="Vybraná kontrola">
    <h3 class="eyebrow">Co se provede</h3>
    <p><strong>${esc(methodLabel(c.method))}</strong></p>
    <p class="small">${info ? esc(info.does) : "Popis této metody server neposlal."}</p>
    <dl class="kv small">
      <dt>dotkne se sítě</dt><dd>${info ? (info.touchesNetwork ? "ano, posílá provoz na cíl" : "ne") : "neznámé"}</dd>
      <dt>riziko narušení</dt><dd>${pct(c.disruption_risk)}</dd>
      <dt>odhad trvání</dt><dd>${c.estimated_runtime_ms} ms</dd>
      <dt>schválení</dt><dd>${c.requires_approval ? "<strong>vyžaduje</strong> · samo se nespustí, dokud ji někdo nepovolí (v tomto okně se schvalovat nedá)" : "nevyžaduje · jde o čtecí kontrolu"}</dd>
    </dl>
  </section>`;
}

function render(): string {
  const report = state.report;
  if (!report) return noDataState("Ověřování");
  const plans = report.verification_plans ?? [];
  const results = report.verification_results ?? [];
  const needsApproval = plans.filter((p) => p.plan.chosen?.candidate.requires_approval).length;
  const excluded = plans.reduce((n, p) => n + p.excluded_out_of_scope.length, 0);
  const waiting = results.filter((r) => r.status === "needs_approval");
  const executed = results.filter((r) => r.status === "executed" || r.status === "reused").length;

  const visible = plans
    .map((plan, index) => ({ plan, index }))
    .filter(({ plan }) =>
      state.verifFilter === "all"
        ? true
        : state.verifFilter === "approval"
          ? plan.plan.chosen?.candidate.requires_approval
          : plan.excluded_out_of_scope.length > 0,
    );

  const mk = (id: typeof state.verifFilter, label: string) =>
    `<button type="button" class="seg${state.verifFilter === id ? " is-on" : ""}" aria-pressed="${state.verifFilter === id}" data-action="verif-filter" data-key="${id}">${label}</button>`;
  const tools = `<div class="segmented" role="group" aria-label="Filtr plánů">${mk("all", "Vše")}${mk("approval", "Se schválením")}${mk("excluded", "S vyřazenými")}</div>`;

  return `${paneHead("Ověřování", tools)}
  <div class="verif scroll" data-keep="verif">
    <div class="readouts readouts-row">
      ${readout(plans.length, "plány")}
      ${readout(results.length ? waiting.length : needsApproval, results.length ? "čeká na schválení" : "plány se schválením", (results.length ? waiting.length : needsApproval) ? "hot" : "")}
      ${readout(excluded, "vyřazeno mimo rozsah")}
      ${readout(results.length ? executed : "-", "provedeno")}
    </div>
    ${
      waiting.length || needsApproval
        ? `<div class="approval-note" role="note"><p><strong>${waiting.length ? `${waiting.length} ${waiting.length === 1 ? "kontrola čeká" : waiting.length < 5 ? "kontroly čekají" : "kontrol čeká"} na schválení.` : `${needsApproval} ${needsApproval === 1 ? "plán počítá" : "plány počítají"} s kontrolou, která vyžaduje schválení.`}</strong> Aktivní kontroly nad úrovní čtení se nikdy nespustí samy. V tomto okně je schvalovat nejde: dokud je někdo nepovolí, zůstanou nespuštěné a cíl se jich nedotkne.</p>${
            waiting.length
              ? `<ul class="plain small">${waiting
                  .slice(0, 6)
                  .map((r) => `<li><span class="mono">${esc(r.asset)}</span> · ${esc(methodLabel(r.method))} · <span class="muted">${esc(hypothesisLabel(r.hypothesis_type))}</span></li>`)
                  .join("")}${waiting.length > 6 ? `<li class="muted">a dalších ${waiting.length - 6}</li>` : ""}</ul>`
              : ""
          }<p class="small muted">U každého plánu níže je vidět, co přesně by se provedlo a jaké je riziko narušení.</p></div>`
        : `<p class="small muted note-line">Plán jen doporučuje další kontrolu. Aktivní kontroly nad úrovní čtení se bez schválení nespustí.</p>`
    }    ${
      visible.length
        ? `<div class="plans">${visible
            .map(({ plan, index }) => {
              const key = planKey(plan, index);
              const open = state.openPlans.has(key);
              const chosen = plan.plan.chosen;
              return `<details class="plan"${open ? " open" : ""} data-plan="${esc(key)}">
                <summary>
                  <span class="plan-type" title="${esc(plan.hypothesis_type)}">${esc(hypothesisLabel(plan.hypothesis_type))}</span>
                  <span class="mono small muted">${esc(plan.in_scope_assets.join(", "))}</span>
                  <span class="plan-pick">${chosen ? `<span>${esc(methodLabel(chosen.candidate.method))}</span>${chosen.candidate.requires_approval ? chip("čeká na schválení", "hot") : ""}` : `<span class="muted">bez kandidáta</span>`}</span>
                  <span class="mono small">${chosen ? (chosen.utility >= 0 ? "+" : "") + chosen.utility.toFixed(2) : "-"}</span>
                </summary>
                <div class="plan-body">
                  ${chosenBlock(chosen)}
                  <h3 class="eyebrow">Porovnané možnosti</h3>
                  ${bars(plan.plan.ranked, chosen)}
                  ${plan.excluded_out_of_scope.length ? `<p class="small"><span class="eyebrow">Mimo rozsah</span> <span class="mono">${esc(plan.excluded_out_of_scope.join(", "))}</span> byly vyřazeny před plánováním.</p>` : ""}
                </div>
              </details>`;
            })
            .join("")}</div>`
        : emptyState(plans.length ? "Filtr nic nenašel" : "Žádné plány", plans.length ? "Zkus jiný filtr." : "Tento běh nemá žádné plány ověření.")
    }
    <h2 class="eyebrow section-h">Výsledky provedených kontrol</h2>
    ${
      results.length
        ? `<table class="data"><caption class="sr-only">Výsledky ověřování</caption><thead><tr><th>Typ</th><th>Metoda</th><th>Cíl</th><th>Stav</th><th>Výsledek</th><th>Čas</th></tr></thead><tbody>${results
            .map(
              (r) =>
                `<tr><td data-label="Typ" title="${esc(r.hypothesis_type)}">${esc(hypothesisLabel(r.hypothesis_type))}</td><td data-label="Metoda" title="${esc(r.method)}">${esc(methodLabel(r.method))}</td><td class="mono" data-label="Cíl">${esc(r.asset)}</td><td data-label="Stav">${chip(RESULT_LABEL[r.status] ?? r.status, r.status === "failed" ? "hot" : r.status === "executed" || r.status === "reused" ? "ink" : "mute")}</td><td data-label="Výsledek">${esc(r.outcome ?? (r.status === "needs_approval" ? "nespuštěno, čeká na schválení" : "neznámé"))}</td><td class="mono small" data-label="Čas">${typeof r.runtime_ms === "number" ? `${r.runtime_ms} ms` : "neznámé"}</td></tr>`,
            )
            .join("")}</tbody></table>`
        : `<p class="muted small">Tento běh neobsahuje výsledky vykonaných kontrol. Server je buď neprovedl, nebo je zatím neposílá.</p>`
    }
  </div>`;
}

export const verification: View = {
  id: "overovani",
  label: "Ověřování",
  abbr: "OV",
  render,
  actions: {
    "verif-filter": (el) => update({ verifFilter: (el.dataset.key as typeof state.verifFilter) ?? "all" }),
  },
  after() {
    document.querySelectorAll<HTMLDetailsElement>("details.plan").forEach((node) => {
      node.addEventListener("toggle", () => {
        const key = node.dataset.plan ?? "";
        if (node.open) state.openPlans.add(key);
        else state.openPlans.delete(key);
      });
    });
  },
};
