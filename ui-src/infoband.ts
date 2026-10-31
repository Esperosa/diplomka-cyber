// Informacni pas pod horni listou: kde uzivatel prave je. Jen skutecna data, ktera UI uz ma
// (state.report, stav serveru, autopilota a tokenu). Chybi-li hodnota, polozka se nezobrazi.
import { getToken } from "./api";
import { state } from "./state";
import { esc } from "./ui";

export function ago(iso: string | null | undefined, now = Date.now()): string | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return null;
  const min = Math.max(0, Math.round((now - t) / 60000));
  if (min < 1) return "před okamžikem";
  if (min < 60) return `před ${min} min`;
  const h = Math.round(min / 60);
  if (h < 48) return `před ${h} h`;
  return `před ${Math.round(h / 24)} dny`;
}

type Item = { key: string; label: string; value: string; tone?: "hot" | "ok"; primary?: boolean };

function count(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

export function infoItems(now = Date.now()): Item[] {
  // Poradi = dulezitost: co se do pasu nevejde, zustane v nabidce "vse".
  const items: Item[] = [];
  const report = state.report;
  if (report) {
    const run = report.run;
    const when = ago(run.finished_at, now);
    if (when) items.push({ key: "when", label: "běh skončil", value: when, primary: true });
    if (run.scope?.length) items.push({ key: "scope", label: "rozsah", value: run.scope.join(", "), primary: true });
    items.push({ key: "hosts", label: "stanice", value: String(report.hosts.length), primary: true });
    for (const [key, label, field] of [
      ["events", "události", "events_total"],
      ["realtime", "zdroje", "realtime_sources_total"],
    ] as const) {
      const n = count(report.summary[field]);
      if (n !== null) items.push({ key, label, value: String(n), primary: true });
    }
  }
  const serverValue = state.connection === "error" ? "bez spojení" : state.loading && !report ? "načítám" : "odpovídá";
  items.push({ key: "server", label: "server", value: serverValue, tone: state.connection === "error" ? "hot" : undefined, primary: true });
  if (state.meta) {
    const token = getToken();
    const required = Boolean(state.meta.auth_required);
    let value: string;
    let tone: Item["tone"];
    if (!required) value = "bez přihlášení";
    else if (state.authNeeded && token) {
      value = "token odmítnut";
      tone = "hot";
    } else if (token) value = "přihlášen tokenem";
    else {
      value = "token chybí";
      tone = "hot";
    }
    items.push({ key: "token", label: "API", value, tone, primary: true });
  }
  if (report) {
    const run = report.run;
    if (run.profile) items.push({ key: "profile", label: "profil", value: run.profile, primary: true });
    const services = count(report.summary.services_total) ?? report.hosts.reduce((n, h) => n + h.services.length, 0);
    items.push({ key: "services", label: "služby", value: String(services), primary: true });
    for (const [key, label, field] of [
      ["wifi", "klienti Wi-Fi", "wireless_clients_total"],
      ["edges", "spoje topologie", "topology_edges_total"],
    ] as const) {
      const n = count(report.summary[field]);
      if (n !== null) items.push({ key, label, value: String(n), primary: key === "wifi" });
    }
  }
  const status = state.automationStatus;
  if (status) {
    const running = Boolean(status.process_running);
    items.push({
      key: "auto",
      label: "autopilot",
      value: running ? `běží, cyklus ${status.current_cycle} z ${status.total_cycles}` : "nečinný",
      primary: true,
    });
  }
  return items;
}

export function infoBandHtml(): string {
  const items = infoItems();
  const pills = items
    .filter((i) => i.primary)
    .map((i) => `<span class="ipill${i.tone ? ` is-${i.tone}` : ""}" data-info="${i.key}"><span class="ipill-k">${esc(i.label)}</span><span class="ipill-v">${esc(i.value)}</span></span>`)
    .join("");
  const rows = items
    .map((i) => `<div class="irow${i.tone ? ` is-${i.tone}` : ""}"><dt>${esc(i.label)}</dt><dd>${esc(i.value)}</dd></div>`)
    .join("");
  return `<div class="info-pills">${pills}</div>
    <details class="menu info-more" id="infoMenu">
      <summary class="info-sum" aria-label="Plný výpis údajů o běhu"><span class="ipill ipill-more" aria-hidden="true"><span class="ipill-k">vše</span><span class="ipill-dots"></span></span></summary>
      <div class="menu-pop info-pop" role="group" aria-label="Údaje o běhu a serveru"><dl>${rows}</dl></div>
    </details>`;
}
