import { dotMatrix } from "../dotmatrix";
import { renderField } from "../pebbles";
import { navigate } from "../router";
import { activeHost, state, update, type View } from "../state";
import { esc, fmtDate, hostFindings, maxSeverityLevel, meanUncertainty, hypothesesForHost, pct, num, SEVERITY_LABEL } from "../ui";
import { emptyState, paneHead, readout } from "./common";

function render(): string {
  const report = state.report;
  if (!report) {
    return `${paneHead("Přehled")}${emptyState(
      state.loading ? "Načítám…" : "Zatím žádný běh",
      state.loading ? "Čekám na odpověď serveru." : "Server zatím nemá žádný uložený běh. Spusť autopilota v sekci Automat.",
      state.loading ? "" : `<button type="button" class="btn" data-action="goto" data-key="automat">Otevřít Automat</button>`,
    )}`;
  }
  const high = report.findings.filter((f) => f.severity === "high").length;
  const plans = report.verification_plans ?? [];
  const pending = state.enforcement ? state.enforcement.actions.filter((a) => a.status === "proposed").length : null;
  const consensus = String(report.summary.mas_consensus_state ?? "");
  const selected = activeHost();

  const hostCard = selected ? hostSummary(selected) : `<p class="muted small">Vyber stanici v poli. Velikost oblázku odpovídá významu stanice, tečky na obvodu riziku, přerušení obrysu nejistotě.</p>`;

  return `${paneHead("Přehled")}
  <div class="overview">
    <section class="field-wrap" aria-label="Pole stanic">
      ${renderField(report, state.selectedHost)}
      <ul class="legend" aria-label="Legenda">
        <li><i class="lg lg-size"></i>velikost: význam stanice</li>
        <li><i class="lg lg-ring"></i>tečky na obvodu: riziko</li>
        <li><i class="lg lg-dash"></i>přerušený obrys: nejistota</li>
        <li><i class="lg lg-out"></i>vnější kroužky: ostatní aktiva</li>
      </ul>
    </section>
    <aside class="side" aria-label="Souhrn běhu">
      <div class="run-meta">
        <p class="eyebrow">Běh</p>
        <p class="run-name">${esc(report.run.nazev)}</p>
        <p class="mono small muted">${esc(fmtDate(report.run.finished_at))}</p>
        <p class="mono small muted">rozsah ${esc(report.run.scope.join(", "))} · ${esc(report.run.profile)}</p>
        ${consensus ? `<p class="consensus"><span class="eyebrow">Shoda agentů</span>${dotMatrix(consensus, {})}</p>` : ""}
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
      <div class="host-card" aria-live="polite">${hostCard}</div>
    </aside>
  </div>`;
}

function hostSummary(host: NonNullable<ReturnType<typeof activeHost>>): string {
  const report = state.report!;
  const findings = hostFindings(report, host);
  const sev = maxSeverityLevel(findings);
  const sevText = sev === 3 ? SEVERITY_LABEL.high : sev === 2 ? SEVERITY_LABEL.medium : sev === 1 ? SEVERITY_LABEL.low : "bez nálezů";
  const unc = meanUncertainty(hypothesesForHost(report, host));
  return `<p class="eyebrow">Vybraná stanice</p>
    <p class="host-ip mono">${esc(host.ip)}</p>
    <p class="small muted">${esc(host.hostname ?? "bez jména")}</p>
    <dl class="kv small">
      <dt>služby</dt><dd>${host.services.length}</dd>
      <dt>nálezy</dt><dd>${findings.length} · nejvyšší: ${esc(sevText)}</dd>
      <dt>nejistota</dt><dd>${esc(pct(unc))}</dd>
    </dl>
    <button type="button" class="btn" data-action="open-host" data-key="${esc(host.host_key)}">Detail stanice</button>`;
}

export const overview: View = {
  id: "prehled",
  label: "Přehled",
  abbr: "PR",
  render,
  actions: {
    "select-pebble": (el) => {
      const key = el.dataset.host ?? null;
      update({ selectedHost: state.selectedHost === key ? null : key });
    },
    "open-host": (el) => {
      update({ selectedHost: el.dataset.key ?? null }, false);
      navigate("hostitele", el.dataset.key ?? null);
    },
    goto: (el) => navigate((el.dataset.key as never) ?? "prehled"),
  },
};
