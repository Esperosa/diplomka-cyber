// Mapa site Skakavky: Internet -> brana -> podsite (zony) -> stanice. Uzly a spoje jsou
// organicke "goo" bubliny (spojene tecky), nad nimi lezi ostra vrstva: kruhy rizika,
// stitky a CESTA SKOKU agenta (pivoting): po cem agent poskakoval, kdyz overoval podezrely uzel.
import { blobPath, hashString, rng, type P } from "./pebbles";
import type { Host, Report, VerificationResult } from "./types";
import { esc, hostFindings, hostImportance, hostRisk, hypothesesForHost, maxSeverityLevel, meanUncertainty } from "./ui";

type Node = {
  host: Host;
  r: number;
  x: number;
  y: number;
  risk: number;
  sev: number;
  uncertainty: number | null;
};

type Zone = {
  key: string;
  label: string;
  nodes: Node[];
  R: number;
  cx: number;
  cy: number;
};

export type Hop = {
  index: number;
  asset: string;
  method: string;
  status: VerificationResult["status"];
  outcome: string | null | undefined;
  hypothesis: string;
  onMap: boolean;
};

const GOLDEN = 2.399963;

function subnetOf(ip: string): { key: string; label: string } {
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.\d+$/);
  if (!m) return { key: "other", label: "ostatní" };
  return { key: `${m[1]}.${m[2]}.${m[3]}`, label: `${m[1]}.${m[2]}.${m[3]}.0/24` };
}

/** Brana: aktivum typu router/firewall/gateway, host s koncovkou .1 nebo nazvem "gw/gateway/router/brana". */
function pickGateway(report: Report): string | null {
  const assets = report.networkAssets ?? [];
  for (const asset of assets) {
    if (/router|gateway|firewall|brana|brána/i.test(`${asset.asset_type} ${asset.name}`) && asset.linked_host_key) {
      if (report.hosts.some((h) => h.host_key === asset.linked_host_key)) return asset.linked_host_key;
    }
  }
  const named = report.hosts.find((h) => /(^|[-_.])(gw|gateway|router|brana)([-_.]|\d|$)/i.test(h.hostname ?? ""));
  if (named) return named.host_key;
  const dotOne = report.hosts.find((h) => /\.1$/.test(h.ip));
  return dotOne ? dotOne.host_key : null;
}

function statusLabel(status: VerificationResult["status"]): string {
  switch (status) {
    case "executed":
      return "provedeno";
    case "reused":
      return "převzato";
    case "needs_approval":
      return "čeká na schválení";
    case "skipped_out_of_scope":
      return "mimo rozsah";
    case "skipped_budget":
      return "mimo rozpočet";
    default:
      return "selhalo";
  }
}
export { statusLabel };

/** Skoky agenta: poradi overovacich kontrol, po sobe jdouci kontroly stejneho aktiva se slouci. */
export function hopsOf(report: Report): Hop[] {
  const onMap = new Set(report.hosts.map((h) => h.ip));
  const hops: Hop[] = [];
  for (const result of report.verification_results ?? []) {
    const previous = hops[hops.length - 1];
    if (previous && previous.asset === result.asset && previous.status === result.status) continue;
    hops.push({
      index: hops.length + 1,
      asset: result.asset,
      method: result.method,
      status: result.status,
      outcome: result.outcome,
      hypothesis: result.hypothesis_type,
      onMap: onMap.has(result.asset),
    });
  }
  return hops;
}

function arc(a: P, b: P, bend = 0.22): string {
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2;
  const dx = b.x - a.x;
  const dy = b.y - a.y;
  const cx = mx - dy * bend;
  const cy = my + dx * bend;
  return `Q${cx.toFixed(1)},${cy.toFixed(1)} ${b.x.toFixed(1)},${b.y.toFixed(1)}`;
}

export function renderNetMap(report: Report, selected: string | null): string {
  const hosts = [...report.hosts].sort((a, b) => a.host_key.localeCompare(b.host_key));
  if (!hosts.length) return `<p class="muted">Běh neobsahuje žádné stanice.</p>`;

  const gatewayKey = pickGateway(report);
  const importances = new Map(hosts.map((h) => [h.host_key, hostImportance(report, h)]));
  const maxImp = Math.max(...importances.values(), 1);
  const mkNode = (host: Host, r: number, x = 0, y = 0): Node => {
    const findings = hostFindings(report, host);
    return {
      host,
      r,
      x,
      y,
      risk: hostRisk(report, host),
      sev: maxSeverityLevel(findings),
      uncertainty: meanUncertainty(hypothesesForHost(report, host)),
    };
  };

  // ---- zony (podsite) ----
  const groups = new Map<string, { label: string; hosts: Host[] }>();
  for (const host of hosts) {
    if (host.host_key === gatewayKey) continue;
    const sub = subnetOf(host.ip);
    const group = groups.get(sub.key) ?? { label: sub.label, hosts: [] };
    group.hosts.push(host);
    groups.set(sub.key, group);
  }
  const SPACING = 38;
  const zones: Zone[] = [...groups.entries()]
    .sort((a, b) => b[1].hosts.length - a[1].hosts.length || a[0].localeCompare(b[0]))
    .map(([key, group]) => {
      const ordered = [...group.hosts].sort((a, b) => (importances.get(b.host_key) ?? 0) - (importances.get(a.host_key) ?? 0));
      const n = ordered.length;
      const nodes = ordered.map((host, k) => {
        const imp = (importances.get(host.host_key) ?? 0) / maxImp;
        const r = Math.min(22, Math.max(6.5, SPACING * (0.3 + 0.17 * imp)));
        const dist = SPACING * Math.sqrt(k + 0.55);
        const angle = k * GOLDEN + hashString(key) * 0.001;
        return mkNode(host, r, Math.cos(angle) * dist, Math.sin(angle) * dist);
      });
      const R = Math.max(62, SPACING * Math.sqrt(n + 0.55) + 30);
      return { key, label: group.label, nodes, R, cx: 0, cy: 0 };
    });

  // ---- umisteni zon do sloupcu vpravo od brany ----
  const columns = zones.length <= 3 ? 1 : zones.length <= 8 ? 2 : 3;
  const cols: Zone[][] = Array.from({ length: columns }, () => []);
  const heights = new Array(columns).fill(0);
  for (const zone of zones) {
    let best = 0;
    for (let c = 1; c < columns; c += 1) if (heights[c] < heights[best]) best = c;
    cols[best].push(zone);
    heights[best] += zone.R * 2 + 44;
  }
  const GATE = { x: 0, y: 0 };
  let colStart = 215;
  cols.forEach((column) => {
    const maxR = Math.max(...column.map((z) => z.R), 0);
    const total = column.reduce((sum, z) => sum + z.R * 2 + 44, -44);
    let y = -total / 2;
    for (const zone of column) {
      zone.cx = colStart + maxR;
      zone.cy = y + zone.R;
      y += zone.R * 2 + 44;
    }
    colStart += maxR * 2 + 110;
  });
  for (const zone of zones) {
    for (const node of zone.nodes) {
      node.x += zone.cx;
      node.y += zone.cy;
    }
  }

  const gatewayHost = gatewayKey ? hosts.find((h) => h.host_key === gatewayKey) ?? null : null;
  const gatewayNode = gatewayHost ? mkNode(gatewayHost, 21, GATE.x, GATE.y) : null;
  const INTERNET: P = { x: -200, y: 0 };

  // ---- skoky agenta ----
  const hops = hopsOf(report);
  const positions = new Map<string, P>();
  for (const zone of zones) for (const node of zone.nodes) positions.set(node.host.ip, { x: node.x, y: node.y });
  if (gatewayNode) positions.set(gatewayNode.host.ip, GATE);
  const outsiders = hops.filter((h) => !h.onMap);
  const outsiderIps = [...new Set(outsiders.map((h) => h.asset))];
  outsiderIps.forEach((ip, i) => positions.set(ip, { x: INTERNET.x - 78, y: (i - (outsiderIps.length - 1) / 2) * 64 + (outsiderIps.length === 1 ? 74 : 0) }));

  // ---- rozsah pohledu ----
  let minX = INTERNET.x - 78 - 90;
  let maxX = 60;
  let minY = -60;
  let maxY = 60;
  for (const zone of zones) {
    minX = Math.min(minX, zone.cx - zone.R - 14);
    maxX = Math.max(maxX, zone.cx + zone.R + 14);
    minY = Math.min(minY, zone.cy - zone.R - 30);
    maxY = Math.max(maxY, zone.cy + zone.R + 14);
  }
  const pad = 24;
  const vb = `${(minX - pad).toFixed(0)} ${(minY - pad).toFixed(0)} ${(maxX - minX + pad * 2).toFixed(0)} ${(maxY - minY + pad * 2).toFixed(0)}`;

  // ---- goo vrstva: spoje + vyplne uzlu ----
  const goo: string[] = [];
  goo.push(`<path class="gl" d="M${INTERNET.x},${INTERNET.y} L${GATE.x},${GATE.y}"/>`);
  goo.push(`<circle class="g-net" cx="${INTERNET.x}" cy="${INTERNET.y}" r="30"/>`);
  goo.push(`<circle class="g-gate" cx="${GATE.x}" cy="${GATE.y}" r="${gatewayNode ? 21 : 15}"/>`);
  for (const zone of zones) {
    const hub = { x: zone.cx, y: zone.cy };
    const near = zone.cx - zone.R;
    goo.push(`<path class="gl" d="M${GATE.x},${GATE.y} C${(GATE.x + near) / 2},${GATE.y} ${(GATE.x + near) / 2},${hub.y} ${near + 12},${hub.y}"/>`);
    goo.push(`<circle class="g-hub" cx="${hub.x}" cy="${hub.y}" r="7"/>`);
    for (const node of zone.nodes) {
      goo.push(`<path class="gs" d="M${hub.x.toFixed(1)},${hub.y.toFixed(1)} L${node.x.toFixed(1)},${node.y.toFixed(1)}"/>`);
    }
    for (const node of zone.nodes) {
      goo.push(`<circle class="g-node s${node.sev}" cx="${node.x.toFixed(1)}" cy="${node.y.toFixed(1)}" r="${node.r.toFixed(1)}"/>`);
    }
  }
  if (gatewayNode) goo.push(`<circle class="g-node s${gatewayNode.sev}" cx="${GATE.x}" cy="${GATE.y}" r="21"/>`);

  // ---- ostra vrstva ----
  const zoneOutlines = zones
    .map((zone) => {
      const d = blobPath(`${report.run.run_id}:${zone.key}`, 1, 0.045, 13);
      return `<g class="zone"><path class="zone-outline" transform="translate(${zone.cx.toFixed(1)} ${zone.cy.toFixed(1)}) scale(${zone.R.toFixed(1)})" d="${d}"/>
        <text class="zone-label" x="${zone.cx.toFixed(1)}" y="${(zone.cy - zone.R - 8).toFixed(1)}">${esc(zone.label)}</text>
        <text class="zone-count" x="${zone.cx.toFixed(1)}" y="${(zone.cy + zone.R + 16).toFixed(1)}">${zone.nodes.length} stanic</text></g>`;
    })
    .join("");

  const RING = 14;
  const nodeOverlay = (node: Node): string => {
    const seed = hashString(node.host.host_key);
    const random = rng(seed);
    const isSel = selected === node.host.host_key;
    const filled = Math.round(node.risk * RING);
    const ringR = node.r + 5.5;
    let dots = "";
    if (node.sev > 0 || node.risk > 0.05) {
      const start = (seed % 360) * (Math.PI / 180);
      for (let i = 0; i < RING; i += 1) {
        const angle = start + (i / RING) * Math.PI * 2;
        const on = i < filled;
        dots += `<circle class="ring-dot${on ? (node.sev === 3 ? " hot" : " on") : ""}" cx="${(Math.cos(angle) * ringR).toFixed(1)}" cy="${(Math.sin(angle) * ringR).toFixed(1)}" r="${on ? 1.9 : 1.2}"/>`;
      }
    }
    const dashed = node.uncertainty !== null && node.uncertainty >= 0.5;
    const octet = node.host.ip.includes(".") ? `.${node.host.ip.split(".").pop()}` : node.host.ip.slice(-4);
    const showLabel = node.r >= 11 || isSel;
    const risk = node.sev === 3 ? "vysoké" : node.sev === 2 ? "střední" : node.sev === 1 ? "nízké" : "bez nálezů";
    const unc = node.uncertainty === null ? "neznámá" : `${Math.round(node.uncertainty * 100)} %`;
    const label = `${node.host.ip}${node.host.hostname ? `, ${node.host.hostname}` : ""}. Riziko ${risk}. Nejistota ${unc}.`;
    const drift = random();
    return `<g transform="translate(${node.x.toFixed(1)} ${node.y.toFixed(1)})">
      <g class="node${isSel ? " is-selected" : ""}" tabindex="0" role="button" aria-pressed="${isSel}" aria-label="${esc(label)}" data-action="select-pebble" data-host="${esc(node.host.host_key)}" style="--wob:${(drift * 1.4).toFixed(2)}px">
        <title>${esc(label)}</title>
        <circle class="hit" r="${(node.r + 8).toFixed(1)}"/>
        ${dots}
        <circle class="node-edge${dashed ? " is-dashed" : ""}" r="${node.r.toFixed(1)}"/>
        ${showLabel ? `<text class="node-ip s${node.sev}" y="1" font-size="${Math.max(12, Math.min(17, node.r * 0.8)).toFixed(1)}">${esc(octet)}</text>` : ""}
        ${isSel ? `<circle class="sel-ring" r="${(node.r + 11).toFixed(1)}"/>` : ""}
      </g></g>`;
  };

  const gatewayOverlay = gatewayNode
    ? nodeOverlay(gatewayNode)
    : "";
  const gatewayLabel = `<text class="net-label" x="${GATE.x}" y="${gatewayNode ? 40 : 32}">${gatewayNode ? "brána" : "brána (neznámá)"}</text>`;
  const internetOverlay = `<g class="internet"><circle class="net-edge" cx="${INTERNET.x}" cy="${INTERNET.y}" r="30"/><text class="net-label" x="${INTERNET.x}" y="${INTERNET.y + 4}">internet</text></g>`;
  const outsiderOverlay = outsiderIps
    .map((ip) => {
      const p = positions.get(ip)!;
      return `<g class="outsider"><circle class="out-edge" cx="${p.x}" cy="${p.y}" r="12"/><text class="out-ip" x="${p.x}" y="${p.y + 30}">${esc(ip)}</text></g>`;
    })
    .join("");

  // cesta skoku: oblouky mezi po sobe jdoucimi aktivy + cislovane znacky + skakajici tecka
  const route: P[] = [];
  const route_assets: string[] = [];
  for (const hop of hops) {
    const p = positions.get(hop.asset);
    if (!p) continue;
    if (route_assets[route_assets.length - 1] === hop.asset) continue;
    route.push(p);
    route_assets.push(hop.asset);
  }
  let hopArcs = "";
  let hopPath = "";
  if (route.length >= 2) {
    hopPath = `M${route[0].x.toFixed(1)},${route[0].y.toFixed(1)}`;
    for (let i = 1; i < route.length; i += 1) hopPath += arc(route[i - 1], route[i]);
    for (let i = 1; i < route.length; i += 1) {
      const a = route[i - 1];
      const b = route[i];
      hopArcs += `<path class="hop-arc" d="M${a.x.toFixed(1)},${a.y.toFixed(1)}${arc(a, b)}"/>`;
    }
  }
  const markers = hops
    .filter((h) => positions.has(h.asset))
    .map((hop) => {
      const p = positions.get(hop.asset)!;
      return `<g class="hop-mark st-${hop.status}" transform="translate(${(p.x + 16).toFixed(1)} ${(p.y - 18).toFixed(1)})"><circle r="12"/><text y="0.5">${hop.index}</text></g>`;
    })
    .join("");
  const reduced = typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const hopper =
    hopPath && !reduced
      ? `<circle class="hopper" r="6"><animateMotion dur="${Math.max(4, route.length * 1.4)}s" repeatCount="indefinite" path="${hopPath}" calcMode="spline" keyTimes="0;1" keySplines="0.4 0 0.2 1"/></circle>`
      : "";

  const allNodes = zones.flatMap((z) => z.nodes);
  const overlay = allNodes.map(nodeOverlay).join("");

  return `<svg class="netmap" viewBox="${vb}" role="group" aria-label="Mapa sítě" preserveAspectRatio="xMidYMid meet">
    <g class="zones">${zoneOutlines}</g>
    <g class="goo">${goo.join("")}</g>
    <g class="hops">${hopArcs}${hopper}</g>
    <g class="overlay">${internetOverlay}${gatewayLabel}${outsiderOverlay}${gatewayOverlay}${overlay}${markers}</g>
  </svg>`;
}
