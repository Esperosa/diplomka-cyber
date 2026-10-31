import type { Finding, Host, Hypothesis, Report, Severity } from "./types";

export function esc(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const dateFormat = new Intl.DateTimeFormat("cs-CZ", { dateStyle: "medium", timeStyle: "short" });
const timeFormat = new Intl.DateTimeFormat("cs-CZ", { timeStyle: "medium" });

export function fmtDate(value: string | null | undefined): string {
  if (!value) return "neznámé";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? esc(value) : dateFormat.format(date);
}

export function fmtTime(value: string | null | undefined): string {
  if (!value) return "neznámé";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? esc(value) : timeFormat.format(date);
}

export function fmtDuration(totalSeconds: number): string {
  const s = Math.max(0, Math.round(totalSeconds));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${s % 60 ? `${s % 60} s` : ""}`.trim();
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return `${h} h${m ? ` ${m} min` : ""}`;
}

export function countdown(totalSeconds: number): string {
  const s = Math.max(0, Math.floor(totalSeconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(h)}:${pad(m)}:${pad(sec)}`;
}

export const SEVERITY_LABEL: Record<Severity, string> = { high: "vysoká", medium: "střední", low: "nízká" };
export const SEVERITY_WEIGHT: Record<string, number> = { high: 3, medium: 2, low: 1 };

export function severityMarker(severity: string): string {
  const level = SEVERITY_WEIGHT[severity] ?? 0;
  const cls = level === 3 ? "sev-high" : level === 2 ? "sev-medium" : "sev-low";
  return `<span class="sev ${cls}" role="img" aria-label="závažnost ${esc(SEVERITY_LABEL[severity as Severity] ?? severity)}"></span>`;
}

export function hostFindings(report: Report, host: Host): Finding[] {
  return report.findings.filter((finding) => finding.host_key === host.host_key);
}

export function maxSeverityLevel(findings: Finding[]): number {
  return findings.reduce((max, finding) => Math.max(max, SEVERITY_WEIGHT[finding.severity] ?? 0), 0);
}

export function maxCvss(host: Host): number {
  let best = 0;
  for (const service of host.services) {
    for (const cve of service.cves) best = Math.max(best, cve.cvss?.base_score ?? 0);
  }
  return best;
}

/** 0..1: z nejvyssi zavaznosti nalezu (70 %) a nejvyssiho CVSS (30 %). */
export function hostRisk(report: Report, host: Host): number {
  const level = maxSeverityLevel(hostFindings(report, host));
  return Math.min(1, (level / 3) * 0.7 + Math.min(1, maxCvss(host) / 10) * 0.3);
}

export function hostImportance(report: Report, host: Host): number {
  return host.services.filter((s) => s.port_state === "open").length + hostFindings(report, host).length * 0.5;
}

export const UNCERTAINTY_AXES: Array<{ key: keyof NonNullable<Hypothesis["uncertainty"]>; label: string; hint: string }> = [
  { key: "identity", label: "Identita", hint: "Je to opravdu to zařízení, o kterém si myslíme, že je?" },
  { key: "observation", label: "Pozorování", hint: "Jak spolehlivé je samotné pozorování (senzor, jistota detekce)." },
  { key: "state", label: "Stav", hint: "Nakolik je známý aktuální stav služby." },
  { key: "interpretation", label: "Interpretace", hint: "Nejistota výkladu, co pozorování znamená. Zatím se nepočítá." },
  { key: "aleatoric", label: "Náhodnost", hint: "Nevyhnutelný šum v datech. Zatím se nepočítá." },
  { key: "epistemic", label: "Znalosti", hint: "Co model neví kvůli nedostatku dat. Zatím se nepočítá." },
];

/** Průměr jen z naměřených os; žádná osa -> null (neznámé), nikdy 0. */
export function meanUncertainty(hypotheses: Hypothesis[]): number | null {
  const values: number[] = [];
  for (const hypothesis of hypotheses) {
    for (const axis of UNCERTAINTY_AXES) {
      const value = hypothesis.uncertainty?.[axis.key];
      if (typeof value === "number") values.push(value);
    }
  }
  return values.length ? values.reduce((a, b) => a + b, 0) / values.length : null;
}

export function hypothesesForHost(report: Report, host: Host): Hypothesis[] {
  return (report.hypotheses ?? []).filter((h) => h.affected_assets.includes(host.ip) || h.affected_assets.includes(host.host_key));
}

export function hypothesisForFinding(report: Report, finding: Finding): Hypothesis | null {
  const list = report.hypotheses ?? [];
  const index = report.findings.indexOf(finding);
  const byIndex = list[index];
  if (byIndex && byIndex.hypothesis_type === finding.finding_type) return byIndex;
  return (
    list.find(
      (h) => h.hypothesis_type === finding.finding_type && (!finding.host_key || h.affected_assets.includes(finding.host_key)),
    ) ?? null
  );
}

/** Meter z deseti teček; null se vykreslí jako přerušovaný obrys, ne jako nula. */
export function meter(value: number | null | undefined, label: string): string {
  if (typeof value !== "number") {
    return `<span class="meter is-unknown" role="img" aria-label="${esc(label)}: neznámé">${'<i></i>'.repeat(10)}</span>`;
  }
  const filled = Math.round(Math.max(0, Math.min(1, value)) * 10);
  const dots = Array.from({ length: 10 }, (_, i) => `<i class="${i < filled ? "on" : ""}"></i>`).join("");
  return `<span class="meter" role="img" aria-label="${esc(label)}: ${Math.round(value * 100)} %">${dots}</span>`;
}

export function pct(value: number | null | undefined): string {
  return typeof value === "number" ? `${Math.round(value * 100)} %` : "neznámé";
}

export function num(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}
