import { miniPebble } from "../pebbles";
import { navigate } from "../router";
import { activeHost, state, update, type View } from "../state";
import {
  esc,
  fmtDate,
  hostFindings,
  maxCvss,
  maxSeverityLevel,
  severityMarker,
  SEVERITY_LABEL,
  num,
} from "../ui";
import type { Host, Service } from "../types";
import { backButton, chip, emptyState, noDataState, paneHead } from "./common";

function tabs(): string {
  const mk = (id: "stanice" | "aktiva", label: string) =>
    `<button type="button" class="seg${state.hostsTab === id ? " is-on" : ""}" aria-pressed="${state.hostsTab === id}" data-action="hosts-tab" data-key="${id}">${label}</button>`;
  return `<div class="segmented" role="group" aria-label="Typ položek">${mk("stanice", "Stanice")}${mk("aktiva", "Síťová zařízení")}</div>`;
}

const PORT_STATE: Record<string, string> = { open: "otevřený", closed: "zavřený", filtered: "filtrovaný" };

function plural(n: number, one: string, few: string, many: string): string {
  return `${n} ${n === 1 ? one : n >= 2 && n <= 4 ? few : many}`;
}

function list(): string {
  const report = state.report!;
  const hosts = [...report.hosts].sort((a, b) => a.ip.localeCompare(b.ip, "cs", { numeric: true }));
  return `<nav class="list" aria-label="Seznam stanic">${hosts
    .map((host) => {
      const findings = hostFindings(report, host);
      const sev = maxSeverityLevel(findings);
      const selected = state.selectedHost === host.host_key;
      return `<button type="button" class="row${selected ? " is-selected" : ""}" data-action="select-host" data-key="${esc(host.host_key)}" aria-current="${selected}">
        ${miniPebble(host, sev)}
        <span class="row-main"><span class="mono">${esc(host.ip)}</span><span class="small muted">${esc(host.hostname ?? "bez jména")}</span></span>
        <span class="row-side small muted">${plural(host.services.length, "služba", "služby", "služeb")} · ${plural(findings.length, "nález", "nálezy", "nálezů")}</span>
        ${sev ? severityMarker(sev === 3 ? "high" : sev === 2 ? "medium" : "low") : ""}
      </button>`;
    })
    .join("")}</nav>`;
}

function serviceRow(service: Service): string {
  const product = [service.inventory.product, service.inventory.version].filter(Boolean).join(" ") || "neznámé";
  const cvss = service.cves.reduce((m, c) => Math.max(m, c.cvss?.base_score ?? 0), 0);
  const cves = service.cves.length
    ? `<table class="data"><caption class="sr-only">CVE služby ${esc(service.service_key)}</caption><thead><tr><th>CVE</th><th>CVSS</th><th>Popis</th></tr></thead><tbody>${service.cves
        .map(
          (cve) =>
            `<tr><td class="mono" data-label="CVE">${esc(cve.cveId)}</td><td class="mono" data-label="CVSS">${cve.cvss ? esc(cve.cvss.base_score.toFixed(1)) : "neznámé"}</td><td data-label="Popis">${esc(cve.summary ?? "")}</td></tr>`,
        )
        .join("")}</tbody></table>`
    : `<p class="muted small">Pro tuto službu nejsou známé žádné CVE.</p>`;
  const cpes = (service.cpe ?? []).map((c) => `<li class="mono small">${esc(c.cpe23Uri)}</li>`).join("");
  const events = (service.events ?? [])
    .map(
      (e) =>
        `<li class="small event"><span class="mono muted">${esc(e.event.source ?? "")}</span> ${severityMarker(e.event.severity ?? "")} ${esc(e.event.message ?? "")}${e.event.count && e.event.count > 1 ? ` <span class="mono muted">×${e.event.count}</span>` : ""}</li>`,
    )
    .join("");
  return `<details class="service"${state.openServices.has(service.service_key) ? " open" : ""} data-svc="${esc(service.service_key)}">
    <summary>
      <span class="mono port">${service.port}/${esc(service.proto)}</span>
      <span>${esc(service.inventory.service_name)}</span>
      <span class="muted">${esc(product)}</span>
      <span class="mono small ${service.port_state === "open" ? "" : "muted"}">${esc(PORT_STATE[service.port_state] ?? service.port_state)}</span>
      <span class="mono small" title="Skóre služby">${num(service.score).toFixed(1)}</span>
      <span class="small ${service.cves.length ? "hot-text" : "muted"}">${service.cves.length ? `${service.cves.length} CVE${cvss ? ` · ${cvss.toFixed(1)}` : ""}` : "bez CVE"}</span>
    </summary>
    <div class="service-body">
      ${cves}
      ${cpes ? `<p class="eyebrow">CPE</p><ul class="plain">${cpes}</ul>` : ""}
      ${events ? `<p class="eyebrow">Události</p><ul class="plain">${events}</ul>` : ""}
      <p class="small muted">zdroj detekce: ${esc(service.inventory.detection_source ?? "neznámé")} · jistota ${esc(service.inventory.confidence ?? "neznámé")}</p>
    </div>
  </details>`;
}

function detail(host: Host): string {
  const report = state.report!;
  const findings = hostFindings(report, host);
  return `${backButton()}
  <div class="detail-head">
    <h2 class="mono big">${esc(host.ip)}</h2>
    <p class="muted">${esc(host.hostname ?? "bez jména")}${host.vendor ? ` · ${esc(host.vendor)}` : ""}${host.mac ? ` · <span class="mono">${esc(host.mac)}</span>` : ""}</p>
    <p class="small muted">ID zařízení <span class="mono">${esc(host.asset_id ?? "neznámé")}</span> · nejvyšší CVSS ${maxCvss(host) ? maxCvss(host).toFixed(1) : "neznámé"}</p>
    ${host.identity_note ? `<p class="note"><i class="note-dot"></i>Nejednoznačná identita: ${esc(host.identity_note)}</p>` : ""}
  </div>
  <h3 class="eyebrow">Služby (${host.services.length})</h3>
  <div class="services" role="list">${host.services.map(serviceRow).join("") || `<p class="muted small">Žádné služby.</p>`}</div>
  <h3 class="eyebrow">Nálezy (${findings.length})</h3>
  ${
    findings.length
      ? `<ul class="plain finding-links">${findings
          .map(
            (f) =>
              `<li><button type="button" class="link-row" data-action="open-finding" data-key="${esc(f.finding_id)}">${severityMarker(f.severity)}<span>${esc(f.title)}</span><span class="small muted">${esc(SEVERITY_LABEL[f.severity])}</span></button></li>`,
          )
          .join("")}</ul>`
      : `<p class="muted small">K této stanici nejsou žádné nálezy.</p>`
  }`;
}

function assetsTable(): string {
  const assets = state.report?.networkAssets ?? [];
  if (!assets.length) return emptyState("Žádná síťová zařízení", "Tento běh nenačetl žádná další zařízení (AP, klienti, switche).");
  return `<div class="scroll" data-keep="assets"><table class="data"><caption class="sr-only">Síťová zařízení</caption><thead><tr><th>Název</th><th>Typ</th><th>IP</th><th>Zdroj</th><th>Stav</th><th>Jistota</th></tr></thead><tbody>${assets
    .map(
      (a) =>
        `<tr><td data-label="Název">${esc(a.name)}</td><td data-label="Typ">${esc(a.asset_type)}</td><td class="mono" data-label="IP">${esc(a.ip ?? "neznámé")}</td><td data-label="Zdroj">${esc(a.source)}</td><td data-label="Stav">${esc(a.status ?? "neznámé")}</td><td data-label="Jistota">${chip(a.confidence, "mute")}</td></tr>`,
    )
    .join("")}</tbody></table></div>`;
}

function render(): string {
  const report = state.report;
  if (!report) return noDataState("Stanice");
  if (state.hostsTab === "aktiva") return `${paneHead("Stanice", tabs())}${assetsTable()}`;
  const host = activeHost();
  return `${paneHead("Stanice", tabs())}
  <div class="split${host ? " has-detail" : ""}">
    <div class="split-list" data-keep="hosts-list">${list()}</div>
    <article class="split-detail scroll" data-keep="host-detail" aria-label="Detail stanice">${
      host ? detail(host) : emptyState("Vyber stanici", `V běhu je ${report.hosts.length} stanic. Poslední průchod: ${fmtDate(report.run.finished_at)}.`)
    }</article>
  </div>`;
}

export const hosts: View = {
  id: "hostitele",
  label: "Stanice",
  abbr: "ST",
  render,
  actions: {
    "hosts-tab": (el) => update({ hostsTab: (el.dataset.key as "stanice" | "aktiva") ?? "stanice" }),
    "select-host": (el) => update({ selectedHost: el.dataset.key ?? null }),
    back: () => update({ selectedHost: null }),
    "open-finding": (el) => navigate("nalezy", el.dataset.key ?? null),
  },
  after() {
    document.querySelectorAll<HTMLDetailsElement>("details.service").forEach((node) => {
      node.addEventListener("toggle", () => {
        const key = node.dataset.svc ?? "";
        if (node.open) state.openServices.add(key);
        else state.openServices.delete(key);
      });
    });
  },
};
