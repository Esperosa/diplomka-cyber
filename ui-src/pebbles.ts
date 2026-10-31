import type { Host, Report } from "./types";
import { esc, hostFindings, hostImportance, hostRisk, hypothesesForHost, maxSeverityLevel, meanUncertainty } from "./ui";

const W = 1000;
const H = 640;
const CX = W / 2;
const CY = H / 2;

function hashString(value: string): number {
  let h = 2166136261;
  for (let i = 0; i < value.length; i += 1) {
    h ^= value.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function rng(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

type P = { x: number; y: number };

/** Uzavrena hladka krivka (Catmull-Rom -> Bezier) pres body. */
function smoothClosed(points: P[]): string {
  const n = points.length;
  const f = (v: number) => v.toFixed(1);
  let d = `M${f(points[0].x)},${f(points[0].y)}`;
  for (let i = 0; i < n; i += 1) {
    const p0 = points[(i - 1 + n) % n];
    const p1 = points[i];
    const p2 = points[(i + 1) % n];
    const p3 = points[(i + 2) % n];
    const c1 = { x: p1.x + (p2.x - p0.x) / 6, y: p1.y + (p2.y - p0.y) / 6 };
    const c2 = { x: p2.x - (p3.x - p1.x) / 6, y: p2.y - (p3.y - p1.y) / 6 };
    d += `C${f(c1.x)},${f(c1.y)} ${f(c2.x)},${f(c2.y)} ${f(p2.x)},${f(p2.y)}`;
  }
  return `${d}Z`;
}

export function blobPath(seed: string, radius: number, wobble = 0.12, points = 9, rx = 1, ry = 1): string {
  const random = rng(hashString(seed));
  const pts: P[] = [];
  for (let i = 0; i < points; i += 1) {
    const angle = (i / points) * Math.PI * 2;
    const r = radius * (1 - wobble + random() * wobble * 2);
    pts.push({ x: Math.cos(angle) * r * rx, y: Math.sin(angle) * r * ry });
  }
  return smoothClosed(pts);
}

type Node = { host: Host; r: number; x: number; y: number; risk: number; sev: number; uncertainty: number | null };

export function layoutHosts(report: Report): Node[] {
  const hosts = [...report.hosts].sort((a, b) => a.host_key.localeCompare(b.host_key));
  const n = hosts.length;
  if (!n) return [];
  const importances = hosts.map((host) => hostImportance(report, host));
  const maxImp = Math.max(...importances, 1);
  const base = n <= 3 ? 118 : n <= 6 ? 88 : n <= 12 ? 60 : 42;
  const nodes: Node[] = hosts.map((host, i) => {
    const findings = hostFindings(report, host);
    return {
      host,
      r: base * (0.72 + 0.5 * (importances[i] / maxImp)),
      x: 0,
      y: 0,
      risk: hostRisk(report, host),
      sev: maxSeverityLevel(findings),
      uncertainty: meanUncertainty(hypothesesForHost(report, host)),
    };
  });

  // Fyllotaxe jako start (organicke rozlozeni), pak relaxace kolizi.
  nodes.forEach((node, i) => {
    const angle = i * 2.399963 + 0.6;
    const dist = n === 1 ? 0 : 46 * Math.sqrt(i + 0.6) * (n <= 6 ? 3.1 : 2.1);
    node.x = CX + Math.cos(angle) * dist;
    node.y = CY + Math.sin(angle) * dist * 0.72;
  });
  const rx = 430;
  const ry = 270;
  for (let iter = 0; iter < 400; iter += 1) {
    for (let i = 0; i < n; i += 1) {
      for (let j = i + 1; j < n; j += 1) {
        const a = nodes[i];
        const b = nodes[j];
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        let dist = Math.hypot(dx, dy) || 0.01;
        const min = a.r + b.r + 64;
        if (dist < min) {
          const push = (min - dist) / 2;
          dx /= dist;
          dy /= dist;
          a.x -= dx * push;
          a.y -= dy * push;
          b.x += dx * push;
          b.y += dy * push;
          dist = min;
        }
      }
    }
    for (const node of nodes) {
      node.x += (CX - node.x) * 0.004;
      node.y += (CY - node.y) * 0.004;
      const bx = rx - node.r * 0.35;
      const by = ry - node.r * 0.35;
      const nx = (node.x - CX) / bx;
      const ny = (node.y - CY) / by;
      const len = Math.hypot(nx, ny);
      if (len > 1) {
        node.x = CX + (nx / len) * bx;
        node.y = CY + (ny / len) * by;
      }
    }
  }
  return nodes;
}

function dashFor(uncertainty: number | null): string {
  if (uncertainty === null) return "";
  if (uncertainty < 0.25) return "";
  if (uncertainty < 0.5) return "9 5";
  if (uncertainty < 0.75) return "5 7";
  return "2 8";
}

const RING_SLOTS = 28;

function ring(node: Node, seed: number): string {
  const filled = Math.round(node.risk * RING_SLOTS);
  const start = (seed % 360) * (Math.PI / 180);
  const radius = node.r + 15;
  const hot = node.sev === 3;
  const dots: string[] = [];
  for (let i = 0; i < RING_SLOTS; i += 1) {
    const angle = start + (i / RING_SLOTS) * Math.PI * 2;
    const x = Math.cos(angle) * radius;
    const y = Math.sin(angle) * radius;
    const on = i < filled;
    dots.push(`<circle class="ring-dot${on ? (hot ? " hot" : " on") : ""}" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${on ? 3.4 : 2.2}"/>`);
  }
  return dots.join("");
}

export function renderField(report: Report, selected: string | null): string {
  const nodes = layoutHosts(report);
  const contour = [1, 0.8, 0.6]
    .map(
      (scale, i) =>
        `<path class="contour c${i}" transform="translate(${CX} ${CY}) rotate(${i * 7}) scale(${scale})" d="${blobPath(`${report.run.run_id}:field`, 1, 0.07, 11, 505, 315)}"/>`,
    )
    .join("");

  const assets = (report.networkAssets ?? []).filter((asset) => !asset.linked_host_key);
  const assetDots = assets
    .map((asset, i) => {
      const angle = (i / Math.max(assets.length, 1)) * Math.PI * 2 + 0.3;
      const x = CX + Math.cos(angle) * 478;
      const y = CY + Math.sin(angle) * 296;
      return `<circle class="outer-dot" cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="4.5"><title>${esc(asset.name)} (${esc(asset.asset_type)})</title></circle>`;
    })
    .join("");

  const pebbles = nodes
    .map((node) => {
      const { host } = node;
      const seed = hashString(host.host_key);
      const random = rng(seed);
      const dash = dashFor(node.uncertainty);
      const octet = host.ip.includes(".") ? `.${host.ip.split(".").pop()}` : host.ip.slice(-4);
      const isSel = selected === host.host_key;
      const name = host.hostname ? esc(host.hostname.slice(0, 14)) : "";
      const dur = 9 + random() * 7;
      const delay = -random() * dur;
      const dx = (random() - 0.5) * 7;
      const dy = (random() - 0.5) * 7;
      const risk = node.sev === 3 ? "vysoké" : node.sev === 2 ? "střední" : node.sev === 1 ? "nízké" : "bez nálezů";
      const unc = node.uncertainty === null ? "neznámá" : `${Math.round(node.uncertainty * 100)} %`;
      const label = `${host.ip}${host.hostname ? `, ${host.hostname}` : ""}. Riziko ${risk}. Nejistota ${unc}.`;
      return `<g transform="translate(${node.x.toFixed(1)} ${node.y.toFixed(1)})">
        <g class="pebble${isSel ? " is-selected" : ""}" tabindex="0" role="button" aria-pressed="${isSel}" aria-label="${esc(label)}" data-action="select-pebble" data-host="${esc(host.host_key)}" style="--dx:${dx.toFixed(1)}px;--dy:${dy.toFixed(1)}px;--dur:${dur.toFixed(1)}s;--delay:${delay.toFixed(1)}s">
          ${ring(node, seed)}
          <path class="pebble-body" d="${blobPath(host.host_key, node.r, 0.1, 9)}"${dash ? ` stroke-dasharray="${dash}"` : ""}/>
          <text class="pebble-ip" y="${name ? -2 : 6}" font-size="${Math.round(node.r * 0.4)}">${esc(octet)}</text>
          ${name && node.r > 50 ? `<text class="pebble-name" y="${Math.round(node.r * 0.34)}" font-size="${Math.round(node.r * 0.17)}">${name}</text>` : ""}
        </g>
      </g>`;
    })
    .join("");

  return `<svg class="pebble-field" viewBox="0 0 ${W} ${H}" role="group" aria-label="Pole stanic">${contour}${assetDots}${pebbles}</svg>`;
}

/** Malý oblázek pro seznamy (stejný tvar jako v poli, ať je poznat). */
export function miniPebble(host: Host, sev: number): string {
  const path = blobPath(host.host_key, 17, 0.1, 9);
  return `<svg class="mini-pebble${sev === 3 ? " hot" : ""}" viewBox="-22 -22 44 44" aria-hidden="true"><path d="${path}"/></svg>`;
}
