import { bindNetMap, centerMapOn, netMapTools } from "../mapview";
import { hopsOf, renderNetMap, statusLabel } from "../netmap";
import { navigate } from "../router";
import { activeHost, state, update, type View } from "../state";
import { methodLabel } from "../glossary";
import { esc, fmtDate, hostFindings, maxSeverityLevel, meanUncertainty, hypothesesForHost, pct, num, SEVERITY_LABEL } from "../ui";
import { emptyState, noDataState, paneHead, readout } from "./common";

function render(): string {
  const report = state.report;
  if (!report) return noDataState("Mapa sítě");
  const high = report.findings.filter((f) => f.severity === "high").length;
  const plans = report.verification_plans ?? [];
  const pending = state.enforcement ? state.enforcement.actions.filter((a) => a.status === "proposed").length : null;
  const consensus = String(report.summary.mas_consensus_state ?? "");
  const selected = activeHost();

  const hostCard = selected ? hostSummary(selected) : `<p class="muted small">Vyber stanici na mapě, nebo se po ní pohybuj šipkami.</p>`;
  const hops = hopsOf(report);

  return `${paneHead("Mapa sítě")}
  <div class="overview">
    <section class="field-wrap" aria-label="Mapa sítě">
      ${renderNetMap(report, state.selectedHost)}
      ${netMapTools()}
      <ul class="legend" id="mapLegend" aria-label="Legenda">
        <li><i class="lg lg-size"></i>velikost: význam stanice</li>
        <li><i class="lg lg-ring"></i>tečky kolem: riziko</li>
        <li><i class="lg lg-dash"></i>přerušený obrys: nejistota</li>
        <li><i class="lg lg-hop"></i>červená cesta: skoky agenta</li>
      </ul>
    </section>
    <aside class="side" aria-label="Souhrn běhu" data-keep="side">
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
      }</p>
      <div class="host-card${selected ? "" : " is-empty"}" aria-live="polite">${hostCard}</div>
      ${hops.length ? hopList(hops) : ""}
    </aside>
  </div>`;
}

function hopList(hops: ReturnType<typeof hopsOf>): string {
  return `<div class="hops-card">
    <p class="eyebrow">Cesta skoků agenta</p>
    <p class="small muted">Agent při ověřování podezřelého uzlu postupně zkontroloval tyto stanice. Klepnutím vybereš stanici na mapě.</p>
    <ol class="hop-list">${hops
      .map((hop) => {
        const host = state.report?.hosts.find((h) => h.ip === hop.asset);
        const inner = `<span class="hop-no">${hop.index}</span><span class="hop-main"><span class="mono">${esc(hop.asset)}</span><span class="small muted">${esc(methodLabel(hop.method))} · ${esc(statusLabel(hop.status))}${hop.outcome ? ` · ${esc(hop.outcome)}` : ""}${host ? "" : " · mimo mapu (vnější adresa)"}</span></span>`;
        return host
          ? `<li class="st-${hop.status}"><button type="button" class="hop-btn" data-action="select-hop" data-host="${esc(host.host_key)}" aria-pressed="${state.selectedHost === host.host_key}">${inner}</button></li>`
          : `<li class="st-${hop.status}"><div class="hop-btn is-static">${inner}</div></li>`;
      })
      .join("")}</ol>
  </div>`;
}

function hostSummary(host: NonNullable<ReturnType<typeof activeHost>>): string {
  const report = state.report!;
  const findings = hostFindings(report, host);
  const sev = maxSeverityLevel(findings);
  const sevText = sev === 3 ? SEVERITY_LABEL.high : sev === 2 ? SEVERITY_LABEL.medium : sev === 1 ? SEVERITY_LABEL.low : "bez nálezů";
  const unc = meanUncertainty(hypothesesForHost(report, host));
  const rank: Record<string, number> = { high: 3, medium: 2, low: 1 };
  const top = [...findings].sort((a, b) => (rank[b.severity] ?? 0) - (rank[a.severity] ?? 0))[0] ?? null;
  return `<p class="eyebrow">Vybraná stanice</p>
    <p class="host-ip mono">${esc(host.ip)}</p>
    <p class="small muted">${esc(host.hostname ?? "bez jména")}</p>
    <dl class="kv small">
      <dt>služby</dt><dd>${host.services.length}</dd>
      <dt>nálezy</dt><dd>${findings.length} · nejvyšší: ${esc(sevText)}</dd>
      <dt>nejistota</dt><dd>${esc(pct(unc))}</dd>
    </dl>
    ${top ? `<p class="small"><span class="eyebrow">Nejzávažnější nález</span><br><button type="button" class="link" data-action="open-finding" data-key="${esc(top.finding_id)}">${esc(top.title.slice(0, 80))}</button></p>` : ""}
    <div class="actions-row"><button type="button" class="btn" data-action="open-host" data-key="${esc(host.host_key)}">Detail stanice</button>${top ? `<button type="button" class="btn btn-ghost" data-action="open-finding" data-key="${esc(top.finding_id)}">Detail nálezu</button>` : ""}</div>`;
}

/** Karta stanice je v postranním panelu; po výběru ji dovedeme do výhledu (hlavně na telefonu). */
function revealHostCard() {
  const side = document.querySelector<HTMLElement>(".side");
  const card = side?.querySelector<HTMLElement>(".host-card");
  if (!side || !card) return;
  const box = card.getBoundingClientRect();
  const room = side.getBoundingClientRect();
  if (box.bottom > room.bottom || box.top < room.top) side.scrollTop += box.top - room.top - 4;
}

export const overview: View = {
  id: "prehled",
  label: "Mapa sítě",
  abbr: "MA",
  render,
  after: () => {
    const field = document.querySelector<HTMLElement>(".field-wrap");
    if (field) bindNetMap(field);
  },
  actions: {
    "select-pebble": (el) => {
      const key = el.dataset.host ?? null;
      update({ selectedHost: state.selectedHost === key ? null : key });
      if (key) revealHostCard();
    },
    "select-hop": (el) => {
      const key = el.dataset.host ?? null;
      const node = key ? document.querySelector<SVGGElement>(`.node[data-host="${CSS.escape(key)}"]`) : null;
      if (node) centerMapOn(Number(node.dataset.x), Number(node.dataset.y));
      update({ selectedHost: key });
      if (key) revealHostCard();
    },
    "open-finding": (el) => navigate("nalezy", el.dataset.key ?? null),
    "open-host": (el) => {
      update({ selectedHost: el.dataset.key ?? null }, false);
      navigate("hostitele", el.dataset.key ?? null);
    },
    goto: (el) => navigate((el.dataset.key as never) ?? "prehled"),
  },
};
