// Panely vedle mapy: statistika vybraneho rozsahu (cela sit / podsit / filtr) a profil zarizeni.
// Vsechna cisla jsou z dat reportu; co report neobsahuje, se rika otevrene ("neznamé", "zatim nic").
import { CONFIDENCE_LABEL, iconSvg, isInfrastructure, kindLabel, portMeaning, type DeviceKind } from "./devices";
import { hypothesisLabel, methodLabel } from "./glossary";
import { type Item, type NetModel, statusLabel, uplinkChain } from "./netmodel";
import type { Report } from "./types";
import { SEVERITY_LABEL, SEVERITY_WEIGHT, esc, hypothesesForHost, pct } from "./ui";
import { readout } from "./views/common";

export type Scope = { eyebrow: string; title: string; sub: string; items: Item[] };

const SEV_NAME = ["bez nálezů", "nízká", "střední", "vysoká"];
const sevDot = (level: number) => `<span class="sev ${level === 3 ? "sev-high" : level === 2 ? "sev-medium" : "sev-low"}" aria-hidden="true"></span>`;

function gooBar(parts: Array<{ n: number; tone: number; label: string }>, total: number): string {
  const W = 300;
  const R = 8;
  const gap = 3;
  let x = 0;
  const lines = parts
    .filter((p) => p.n > 0)
    .map((p) => {
      const len = (p.n / total) * W;
      const a = x + R;
      const b = Math.max(a, x + len - R - gap);
      x += len;
      return `<line class="gb t${Math.min(p.tone, 5)}" x1="${a.toFixed(1)}" y1="12" x2="${b.toFixed(1)}" y2="12"><title>${esc(p.label)}: ${p.n}</title></line>`;
    })
    .join("");
  return `<svg class="goobar" viewBox="0 0 ${W} 24" role="img" aria-label="${esc(parts.filter((p) => p.n > 0).map((p) => `${p.label} ${p.n}`).join(", "))}"><g filter="url(#goo)"><rect width="${W}" height="24" fill="transparent"/>${lines}</g></svg>`;
}

export function statsHtml(model: NetModel, report: Report, scope: Scope): string {
  const items = scope.items;
  const n = items.length;
  if (!n) return `<section class="stats" aria-label="Statistika"><p class="eyebrow">${esc(scope.eyebrow)}</p><p class="small muted">Žádné zařízení neodpovídá filtru.</p></section>`;
  const kinds = new Map<DeviceKind, number>();
  for (const it of items) kinds.set(it.kind, (kinds.get(it.kind) ?? 0) + 1);
  const kindRows = [...kinds.entries()].sort((a, b) => b[1] - a[1]);
  const findings = items.flatMap((i) => i.findings);
  const bySev = { high: 0, medium: 0, low: 0 };
  for (const f of findings) bySev[f.severity] += 1;
  let services = 0;
  let cves = 0;
  const cveIds = new Set<string>();
  for (const it of items) {
    services += it.host.services.filter((s) => s.port_state === "open" || !s.port_state).length;
    for (const s of it.host.services) for (const c of s.cves) { cves += 1; cveIds.add(c.cveId); }
  }
  const known = items.filter((i) => i.kind !== "unknown" && i.cls.confidence !== "low").length;
  const unknown = items.filter((i) => i.kind === "unknown").length;
  const guess = n - known - unknown;
  const agentHosts = items.filter((i) => i.results.length).length;
  const waiting = items.filter((i) => i.agent === "waiting").length;
  const top = [...items].filter((i) => i.sev > 0 || i.risk > 0.05).sort((a, b) => b.sev - a.sev || b.risk - a.risk).slice(0, 5);

  const kindList = kindRows
    .map(
      ([kind, count]) =>
        `<li><button type="button" class="kind-row" data-action="chip-kind" data-kind="${kind}" title="Zobrazit jen: ${esc(kindLabel(kind))}">${iconSvg(kind, 18, "ico")}<span class="kr-name">${esc(kindLabel(kind))}</span><span class="kr-n mono">${count}</span></button></li>`,
    )
    .join("");

  return `<section class="stats" aria-label="Statistika: ${esc(scope.title)}">
    <p class="eyebrow">${esc(scope.eyebrow)}</p>
    <h2 class="stat-title">${esc(scope.title)}</h2>
    ${scope.sub ? `<p class="small muted">${esc(scope.sub)}</p>` : ""}
    <div class="readouts stat-nums">${readout(n, "zařízení", "", true)}${readout(findings.length, "nálezy", "", true)}${readout(bySev.high, "vysoké", bySev.high ? "hot" : "", true)}</div>
    <div class="stat-block">
      <p class="eyebrow">Typy zařízení</p>
      ${gooBar(kindRows.map(([k, c], i) => ({ n: c, tone: i, label: kindLabel(k) })), n)}
      <ul class="kind-list plain">${kindList}</ul>
    </div>
    <div class="stat-block">
      <p class="eyebrow">Nálezy podle závažnosti</p>
      ${findings.length ? gooBar([{ n: bySev.high, tone: 6, label: "vysoké" }, { n: bySev.medium, tone: 0, label: "střední" }, { n: bySev.low, tone: 3, label: "nízké" }], findings.length) : ""}
      <ul class="plain sev-list">
        <li>${sevDot(3)}<span>vysoké</span><b class="mono">${bySev.high}</b></li>
        <li>${sevDot(2)}<span>střední</span><b class="mono">${bySev.medium}</b></li>
        <li>${sevDot(1)}<span>nízké</span><b class="mono">${bySev.low}</b></li>
      </ul>
      <p class="small muted">${services} otevřených služeb · ${cves} výskytů CVE (${cveIds.size} různých)</p>
    </div>
    <div class="stat-block">
      <p class="eyebrow">Pokrytí identity</p>
      ${gooBar([{ n: known, tone: 0, label: "rozpoznáno" }, { n: guess, tone: 2, label: "odhad" }, { n: unknown, tone: 4, label: "neznámé" }], n)}
      <p class="small">rozpoznáno <b class="mono">${known}</b> z ${n}${guess ? ` · odhad <b class="mono">${guess}</b>` : ""} · neznámé <b class="mono">${unknown}</b></p>
      ${unknown ? `<button type="button" class="link" data-action="chip-kind" data-kind="unknown">Zobrazit neznámá zařízení</button>` : ""}
    </div>
    <div class="stat-block">
      <p class="eyebrow">Agent</p>
      <p class="small">Kontroly agenta se týkaly <b class="mono">${agentHosts}</b> z ${n} zařízení${waiting ? `, <b class="mono">${waiting}</b> čeká na schválení` : ""}.</p>
    </div>
    ${
      top.length
        ? `<div class="stat-block"><p class="eyebrow">Nejrizikovější zařízení</p><ol class="top-list plain">${top
            .map(
              (i) =>
                `<li><button type="button" class="top-row" data-action="pick-host" data-host="${esc(i.key)}">${iconSvg(i.kind, 18, "ico")}<span class="tr-main"><span class="mono">${esc(i.ip)}</span><span class="small muted">${esc(i.host.hostname ?? kindLabel(i.kind))}</span></span>${sevDot(i.sev || 1)}<span class="small">${esc(SEV_NAME[i.sev])}</span></button></li>`,
            )
            .join("")}</ol></div>`
        : ""
    }
  </section>`;
}

function eventsOf(item: Item) {
  const groups = new Map<string, { type: string; count: number; sources: Set<string>; sev: string; sample: string; ports: Set<number> }>();
  for (const service of item.host.services) {
    for (const entry of service.events ?? []) {
      const e = entry.event;
      const type = e.event_type || e.message || "událost";
      const g = groups.get(type) ?? { type, count: 0, sources: new Set<string>(), sev: e.severity ?? "", sample: e.message ?? "", ports: new Set<number>() };
      g.count += e.count ?? 1;
      if (e.source) g.sources.add(e.source);
      g.ports.add(service.port);
      if ((SEVERITY_WEIGHT[e.severity ?? ""] ?? 0) > (SEVERITY_WEIGHT[g.sev] ?? 0)) g.sev = e.severity ?? "";
      groups.set(type, g);
    }
  }
  return [...groups.values()].sort((a, b) => (SEVERITY_WEIGHT[b.sev] ?? 0) - (SEVERITY_WEIGHT[a.sev] ?? 0) || b.count - a.count);
}

export function profileHtml(model: NetModel, report: Report, item: Item): string {
  const cls = item.cls;
  const host = item.host;
  const asset = item.asset;
  const unknown = item.kind === "unknown";
  const findings = [...item.findings].sort((a, b) => (SEVERITY_WEIGHT[b.severity] ?? 0) - (SEVERITY_WEIGHT[a.severity] ?? 0));
  const hyps = [...hypothesesForHost(report, host)].sort((a, b) => (b.probability ?? 0) - (a.probability ?? 0));
  const kv = (k: string, v: string | null | undefined) => (v ? `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>` : "");

  const reasons = cls.reasons.length
    ? `<ul class="reasons plain">${cls.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>`
    : `<p class="small muted">Žádný jednoznačný důvod.</p>`;
  const identity = unknown
    ? `<div class="unknown-box"><p><b>Neznámé zařízení, protože ${esc(cls.reasons[0] ?? "o něm chybí údaje")}.</b></p>
        <p class="small">Další krok: ověřit aktivním skenem. Sken zařízení uvidí a může na něj reagovat, proto ho spouští agent až po schválení v sekci Ověřování.</p>
        <button type="button" class="btn btn-ghost" data-action="ask-scan" data-host="${esc(item.key)}">Zeptat se asistenta, jak zařízení ověřit</button></div>`
    : `<p class="small">Jistota rozpoznání: <b>${esc(CONFIDENCE_LABEL[cls.confidence])}</b></p>
       <p class="eyebrow">Proč si to myslíme</p>${reasons}`;

  const services = [...host.services].sort((a, b) => a.port - b.port);
  const svcRows = services
    .slice(0, 12)
    .map((s) => {
      const meaning = portMeaning(s.port);
      const prod = [s.inventory.product, s.inventory.version].filter(Boolean).join(" ");
      return `<li><span class="mono svc-port">${s.port}/${esc(s.proto)}</span><span class="svc-main"><span>${esc(meaning ?? s.inventory.service_name ?? "neznámá služba")}</span><span class="small muted">${esc(prod || s.inventory.service_name || "")}${s.cves.length ? ` · ${s.cves.length} CVE` : ""}${s.port_state && s.port_state !== "open" ? ` · ${esc(s.port_state)}` : ""}</span></span></li>`;
    })
    .join("");

  const events = eventsOf(item);
  const behaviour = events.length
    ? `<ul class="plain beh-list">${events
        .slice(0, 6)
        .map(
          (e) =>
            `<li><span class="mono beh-n">${e.count}×</span><span class="svc-main"><span>${esc(e.type.replace(/_/g, " "))}</span><span class="small muted">zdroj ${esc([...e.sources].join(", ") || "neuvedeno")} · port ${esc([...e.ports].join(", "))}${e.sev ? ` · ${esc(e.sev)}` : ""}</span>${e.sample && e.sample !== e.type ? `<span class="small muted">${esc(e.sample.slice(0, 120))}</span>` : ""}</span></li>`,
        )
        .join("")}</ul>`
    : `<p class="small muted">Pasivní vrstva k tomuto zařízení zatím nezachytila žádné události.</p>`;

  // agenti a kontroly
  const doneTypes = new Set(item.results.map((r) => r.hypothesis_type));
  const planned = (report.verification_plans ?? []).filter((p) => p.in_scope_assets.includes(host.ip) && !doneTypes.has(p.hypothesis_type));
  const hopOf = (r: (typeof item.results)[number]) => model.hops.find((h) => h.asset === r.asset && h.method === r.method && h.status === r.status)?.index;
  const checks =
    item.results.length || planned.length
      ? `<ol class="plain chk-list">${item.results
          .map((r) => {
            const no = hopOf(r);
            return `<li class="st-${r.status}"><span class="chk-state">${esc(statusLabel(r.status))}</span><span class="svc-main"><span>${esc(methodLabel(r.method))}</span><span class="small muted">${esc(hypothesisLabel(r.hypothesis_type))}${no ? ` · krok ${no} cesty skoků` : ""}${r.outcome ? ` · ${esc(r.outcome)}` : ""}${typeof r.runtime_ms === "number" && r.runtime_ms > 0 ? ` · ${r.runtime_ms} ms` : ""}</span>${r.status === "needs_approval" ? `<span class="small">Čeká na lidské schválení. Tady se neschvaluje, kontrola se sama nespustí.</span>` : ""}</span></li>`;
          })
          .join("")}${planned
          .map(
            (p) =>
              `<li class="st-planned"><span class="chk-state">naplánováno</span><span class="svc-main"><span>${esc(p.plan.chosen ? methodLabel(p.plan.chosen.candidate.method) : "metoda zatím nevybrána")}</span><span class="small muted">${esc(hypothesisLabel(p.hypothesis_type))} · zatím neběželo</span></span></li>`,
          )
          .join("")}</ol>`
      : `<p class="small muted">Na tomto zařízení agent zatím nic neověřoval a nic není naplánováno.</p>`;

  const chain = uplinkChain(model, item);
  const links = model.links.filter((l) => l.a === item.key || l.b === item.key);
  const topology =
    chain.length > 1 || item.vlan || item.ssid || links.length
      ? `<dl class="kv small">${kv("VLAN", item.vlan ? `VLAN ${item.vlan}` : null)}${kv("Wi-Fi síť (SSID)", item.ssid)}</dl>${
          chain.length > 1
            ? `<p class="eyebrow">Připojeno přes</p><ol class="chain plain">${chain.map((c) => `<li>${c === item ? `<span class="chain-cur">${iconSvg(c.kind, 16, "ico")}${esc(c.host.hostname ?? c.ip)}</span>` : `<button type="button" class="link" data-action="pick-host" data-host="${esc(c.key)}">${iconSvg(c.kind, 16, "ico")}${esc(c.host.hostname ?? c.ip)}</button>`}</li>`).join("")}</ol>`
            : ""
        }`
      : "";

  const fl = findings.length
    ? `<ul class="plain fnd-list">${findings
        .slice(0, 6)
        .map((f) => `<li>${sevDot(SEVERITY_WEIGHT[f.severity] ?? 1)}<button type="button" class="link" data-action="open-finding" data-key="${esc(f.finding_id)}">${esc(f.title.slice(0, 90))}</button><span class="small muted">${esc(SEVERITY_LABEL[f.severity])}</span></li>`)
        .join("")}${findings.length > 6 ? `<li class="small muted">a dalších ${findings.length - 6}</li>` : ""}</ul>`
    : `<p class="small muted">Žádný nález.</p>`;
  const hl = hyps.length
    ? `<ul class="plain hyp-list">${hyps.slice(0, 5).map((h) => `<li><span>${esc(hypothesisLabel(h.hypothesis_type))}</span><span class="small muted mono">${esc(pct(h.probability))}</span></li>`).join("")}</ul>`
    : "";

  const typeLine = `${esc(kindLabel(item.kind))}${isInfrastructure(item.kind) ? " · síťová infrastruktura" : ""}`;
  return `<div class="profile-head">
      <span class="pf-ico k-${item.kind}">${iconSvg(item.kind, 40, "ico ico-xl")}</span>
      <div class="pf-title"><p class="eyebrow">${typeLine}</p><p class="host-ip mono">${esc(host.ip)}</p><p class="small muted">${esc(host.hostname ?? asset?.name ?? "bez jména")}</p></div>
      <button type="button" class="pf-close" data-action="deselect" aria-label="Zavřít profil zařízení"><svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/></svg></button>
    </div>
    <section class="pf-sec" aria-label="Rozpoznání">${identity}</section>
    <section class="pf-sec" aria-label="Údaje o zařízení"><p class="eyebrow">Zařízení</p>
      <dl class="kv small">${kv("Výrobce", host.vendor ?? asset?.vendor)}${kv("Model", asset?.model)}${kv("MAC", host.mac ?? asset?.mac)}${kv("Stav", asset?.status)}${kv("Umístění", asset?.location)}${kv("Zdroj údajů", asset ? `${asset.source} (${asset.confidence})` : null)}${kv("Poznámka k identitě", host.identity_note)}</dl>
      ${!host.vendor && !asset?.vendor && !host.mac && !asset?.mac ? `<p class="small muted">Výrobce ani MAC adresa nejsou známé.</p>` : ""}
      ${topology}
    </section>
    <section class="pf-sec" aria-label="Služby"><p class="eyebrow">Otevřené služby (${services.length})</p>${services.length ? `<ul class="plain svc-list">${svcRows}</ul>${services.length > 12 ? `<p class="small muted">a dalších ${services.length - 12}</p>` : ""}` : `<p class="small muted">Žádná otevřená služba nebyla zjištěna.</p>`}</section>
    <section class="pf-sec" aria-label="Nálezy"><p class="eyebrow">Nálezy a hypotézy</p>${fl}${hl}</section>
    <section class="pf-sec" aria-label="Chování"><p class="eyebrow">Chování v síti</p>${behaviour}</section>
    <section class="pf-sec" aria-label="Agenti a kontroly"><p class="eyebrow">Agenti a kontroly</p>${checks}</section>
    <div class="actions-row">${item.inventoryOnly ? "" : `<button type="button" class="btn" data-action="open-host" data-key="${esc(item.key)}">Detail stanice</button>`}${findings[0] ? `<button type="button" class="btn btn-ghost" data-action="open-finding" data-key="${esc(findings[0].finding_id)}">Detail nálezu</button>` : ""}</div>`;
}
