import type { Host } from "./types";

export function hashString(value: string): number {
  let h = 2166136261;
  for (let i = 0; i < value.length; i += 1) {
    h ^= value.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

export function rng(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export type P = { x: number; y: number };

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

/** Malý oblázek pro seznamy (stejný tvar jako v poli, ať je poznat). */
export function miniPebble(host: Host, sev: number): string {
  const path = blobPath(host.host_key, 17, 0.1, 9);
  return `<svg class="mini-pebble${sev === 3 ? " hot" : ""}" viewBox="-22 -22 44 44" aria-hidden="true"><path d="${path}"/></svg>`;
}
