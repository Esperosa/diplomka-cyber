// Kresleni mapy site. Vrstvy: zony (velke goo bubliny, po rozkvetu pole se zarizenimi), zarizeni
// (tekute bubliny s ikonou typu, oblouk rizika), tekute mosty (vyplnene tvary, ne cary) a CESTA SKOKU.
// Nic tu nepouziva rasterovy filtr na cele mape: mosty a oblouky jsou geometrie, takze 300 zarizeni
// zustava plynulych. Pohyb (rozkvet, utlum) resi CSS ve styles/netmap.css pres sdilene tokeny.
import { iconInner, kindLabel, type DeviceKind } from "./devices";
import { metaballBridge } from "./metaball";
import { blobPath, hashString, type P } from "./pebbles";
import { type Hop, type Item, type NetModel, type Zone, hopsOf, statusLabel, zoneSeed } from "./netmodel";
import { esc } from "./ui";

export { hopsOf, statusLabel };
export type { Hop };

const f1 = (v: number) => v.toFixed(1);

// ---------- geometrie ----------
/** Tekuty most: jedna souvisla uzavrena krivka kolem dvojice kruhu (metaball, G1 navaznost na oblouky). */
export function bridgePath(a: P, ra: number, b: P, rb: number, _wEnd: number, wMid: number, _bend = 0): string {
  return metaballBridge(a, ra, b, rb, wMid)?.d ?? "";
}

export function arcPath(r: number, a0: number, a1: number): string {
  const sweep = a1 - a0;
  if (sweep >= Math.PI * 2 - 0.02) {
    return `M${f1(r)},0A${f1(r)},${f1(r)} 0 1 1 ${f1(-r)},0A${f1(r)},${f1(r)} 0 1 1 ${f1(r)},0`;
  }
  const x0 = Math.cos(a0) * r;
  const y0 = Math.sin(a0) * r;
  const x1 = Math.cos(a1) * r;
  const y1 = Math.sin(a1) * r;
  return `M${f1(x0)},${f1(y0)}A${f1(r)},${f1(r)} 0 ${sweep > Math.PI ? 1 : 0} 1 ${f1(x1)},${f1(y1)}`;
}

/** Goo oblouk: tucny oblouk s kulatymi konci a kapkou na hlave (spojene tecky jako cislice). */
function gooArc(r: number, a0: number, sweep: number, width: number, cls: string): string {
  const a1 = a0 + Math.min(sweep, Math.PI * 2);
  const head = { x: Math.cos(a1) * r, y: Math.sin(a1) * r };
  const tail = { x: Math.cos(a0) * r, y: Math.sin(a0) * r };
  return `<g class="${cls}"><path d="${arcPath(r, a0, a1)}" style="stroke-width:${f1(width)}px"/><circle cx="${f1(head.x)}" cy="${f1(head.y)}" r="${f1(width * 0.82)}"/><circle cx="${f1(tail.x)}" cy="${f1(tail.y)}" r="${f1(width * 0.62)}"/></g>`;
}

const SEV_TEXT = ["bez nálezů", "nízké", "střední", "vysoké"];
const AGENT_TEXT: Record<string, string> = {
  waiting: "kontrola čeká na schválení",
  done: "kontrola agenta provedena",
  failed: "kontrola agenta selhala",
  skipped: "kontrola agenta přeskočena",
};

// ---------- uzel ----------
function agentBadge(item: Item): string {
  if (!item.agent) return "";
  const r = item.r;
  const x = r * 0.78 + 3;
  const y = -r * 0.78 - 3;
  // tvar nese stav i bez barvy: plny kruh = provedeno, preruseny = ceka, krizek = selhalo, tecky = preskoceno
  const lens = `<circle cx="-0.8" cy="-0.8" r="2.3"/><path d="M0.9 0.9l2.3 2.3"/>`;
  const inner = item.agent === "failed" ? `<path d="M-2.4-2.4l4.8 4.8M2.4-2.4l-4.8 4.8"/>` : lens;
  return `<g class="agent a-${item.agent}" transform="translate(${f1(x)} ${f1(y)})"><circle class="ab" r="6"/><g class="ai">${inner}</g></g>`;
}

function nodeMarkup(item: Item, zone: Zone | null, selected: string | null, index: number): string {
  const seed = hashString(item.key);
  const sel = selected === item.key;
  const bx = zone ? zone.cx - item.x : 0;
  const by = zone ? zone.cy - item.y : 0;
  const octet = item.ip.includes(".") ? `.${item.ip.split(".").pop()}` : item.ip.slice(-4);
  const name = item.host.hostname ?? "";
  const unc = item.uncertainty === null ? "neznámá" : `${Math.round(item.uncertainty * 100)} %`;
  const agent = item.agent ? ` Agent: ${AGENT_TEXT[item.agent]}.` : "";
  const label = `${kindLabel(item.kind)} ${item.ip}${name ? `, ${name}` : ""}. Riziko ${SEV_TEXT[item.sev]}. Nejistota ${unc}.${agent}`;
  const dashed = item.uncertainty !== null && item.uncertainty >= 0.5;
  const ring = item.sev > 0 || item.risk > 0.05 ? gooArc(item.r + 6.5, ((seed % 360) * Math.PI) / 180, Math.max(0.55, Math.min(1, item.risk)) * Math.PI * 2 * 0.94, 2.4, item.sev === 3 ? "ra hot" : "ra") : "";
  const k = (item.r * 1.15) / 24;
  const delay = Math.min(260, (index % 40) * 7);
  return `<g class="n" transform="translate(${f1(item.x)} ${f1(item.y)})">
    <g class="node nb s${item.sev} k-${item.kind}${sel ? " is-selected" : ""}" data-x="${f1(item.x)}" data-y="${f1(item.y)}" data-r="${f1(item.r)}" tabindex="-1" role="button" aria-pressed="${sel}" aria-label="${esc(label)}" data-action="select-pebble" data-host="${esc(item.key)}" data-zone="${esc(item.zone)}" style="--bx:${f1(bx)}px;--by:${f1(by)}px;--d:${delay}ms">
      <title>${esc(label)}</title>
      <g class="nk">
      <circle class="hit" r="${f1(item.r + 8)}"/>
      ${ring}
      <circle class="nbody" r="${f1(item.r)}"/>
      <circle class="node-edge${dashed ? " is-dashed" : ""}" r="${f1(item.r)}"/>
      <g class="nicon" transform="scale(${k.toFixed(3)}) translate(-12 -12)">${iconInner(item.kind)}</g>
      <text class="nlabel" y="${f1(item.r + 3)}">${esc(name ? name.slice(0, 14) : octet)}</text>
      ${agentBadge(item)}
      <circle class="sel-ring" r="${f1(item.r + 12)}"/>
      </g>
    </g></g>`;
}

// ---------- zona ----------
function zoneComposition(zone: Zone): string {
  const kinds = [...zone.kinds.entries()].sort((a, b) => b[1] - a[1]);
  const n = zone.items.length;
  const top = kinds.slice(0, 5);
  const rest = kinds.slice(5).reduce((s, [, c]) => s + c, 0);
  const parts = rest ? [...top, ["unknown" as DeviceKind, rest] as [DeviceKind, number]] : top;
  const ringR = zone.Rb - 9;
  const gap = 0.1;
  const usable = Math.PI * 2 - gap * parts.length;
  let a = -Math.PI / 2;
  let segs = "";
  parts.forEach(([kind, count], i) => {
    const sweep = Math.max(0.16, (count / n) * usable);
    const a1 = a + sweep - 0.14;
    segs += `<path class="zseg t${Math.min(i, 5)}" d="${arcPath(ringR, a, Math.max(a + 0.02, a1))}"><title>${esc(kindLabel(kind))}: ${count}</title></path>`;
    a += sweep + gap;
  });
  // ikony nejvetsich skupin uvnitr
  const icons = kinds.slice(0, Math.min(4, kinds.length));
  const sz = Math.min(zone.Rb * 0.36, 44);
  const off = icons.length === 1 ? 0 : zone.Rb * 0.3;
  const spots: P[] =
    icons.length === 1
      ? [{ x: 0, y: -sz * 0.1 }]
      : icons.length === 2
        ? [{ x: -off, y: 0 }, { x: off, y: 0 }]
        : icons.length === 3
          ? [{ x: 0, y: -off * 0.85 }, { x: -off, y: off * 0.6 }, { x: off, y: off * 0.6 }]
          : [{ x: -off, y: -off * 0.8 }, { x: off, y: -off * 0.8 }, { x: -off, y: off * 0.8 }, { x: off, y: off * 0.8 }];
  const glyphs = icons
    .map(([kind, count], i) => {
      const p = spots[i];
      const k = sz / 24;
      return `<g class="zi" transform="translate(${f1(p.x)} ${f1(p.y)})"><g class="zi-g" transform="scale(${k.toFixed(3)}) translate(-12 -12)">${iconInner(kind)}</g><text class="zi-n" y="${f1(sz * 0.85)}" style="font-size:${f1(Math.max(9, sz * 0.4))}px">${count}</text><title>${esc(kindLabel(kind))}: ${count}</title></g>`;
    })
    .join("");
  return `<g class="zinner">${segs}${glyphs}</g>`;
}

function zoneMarkup(model: NetModel, zone: Zone, selected: string | null): string {
  const n = zone.items.length;
  const fieldD = blobPath(zoneSeed(model, zone), 1, 0.045, 13);
  const bridges = zone.items
    .filter((it) => it.parent && model.byKey.get(it.parent)?.zone === zone.key)
    .map((it) => {
      const p = model.byKey.get(it.parent!)!;
      return bridgePath({ x: p.x, y: p.y }, p.r, { x: it.x, y: it.y }, it.r, 8, 3.2);
    });
  // zarizeni bez skutecneho spojeni: mekke "sousedstvi" (nejblizsi dalsi zarizeni), ne cary do stredu
  const linked = new Set(zone.items.filter((it) => it.parent && model.byKey.get(it.parent)?.zone === zone.key).flatMap((it) => [it.key, it.parent!]));
  const free = zone.items.filter((it) => !linked.has(it.key));
  const tree = [...free].sort((a, b) => Math.hypot(a.x - zone.cx, a.y - zone.cy) - Math.hypot(b.x - zone.cx, b.y - zone.cy));
  const near: string[] = [];
  const placed: Item[] = [];
  for (const it of tree) {
    let best: Item | null = null;
    let bd = Infinity;
    for (const o of placed) {
      const d = Math.hypot(o.x - it.x, o.y - it.y) - o.r - it.r;
      if (d < bd) {
        bd = d;
        best = o;
      }
    }
    if (best && bd < 22) near.push(bridgePath({ x: best.x, y: best.y }, best.r, { x: it.x, y: it.y }, it.r, 7, 3));
    placed.push(it);
  }
  const anyFind = zone.withFindings / n;
  const highFrac = zone.high / n;
  const ringR = zone.Rb + 11;
  const riskArcs =
    zone.withFindings > 0
      ? gooArc(ringR, -Math.PI / 2, Math.max(0.35, anyFind) * Math.PI * 2 * 0.94, 5, "zra") + (zone.high > 0 ? gooArc(ringR, -Math.PI / 2, Math.max(0.3, highFrac) * Math.PI * 2 * 0.94, 5, "zra hot") : "")
      : "";
  const sevText = SEV_TEXT[zone.sevMax];
  const aria = `${zone.label}, ${n} zařízení, ${zone.findings} nálezů, nejhorší závažnost ${sevText}. Enter rozbalí podsíť.`;
  const nodes = zone.items.map((it, i) => nodeMarkup(it, zone, selected, i)).join("");
  return `<g class="zone" data-zone="${esc(zone.key)}" style="--zs:${(zone.Rd / zone.Rb).toFixed(3)};--fs:${(zone.Rb / zone.Rd).toFixed(3)}">
    <path class="zbridge" d="${bridgePath(model.gate, 21, { x: zone.cx, y: zone.cy }, zone.Rb, 16, 5.5, 0.05)}"/>
    <g transform="translate(${f1(zone.cx)} ${f1(zone.cy)})"><g class="zfs"><path class="zfield" transform="scale(${f1(zone.Rd)})" d="${fieldD}"/></g></g>
    <g class="zbridges"><path d="${[...bridges, ...near].join("")}"/></g>
    <g class="zcore" transform="translate(${f1(zone.cx)} ${f1(zone.cy)})">
      <g class="zcore-s">
        <circle class="zb" r="${f1(zone.Rb)}"/>
        ${zoneComposition(zone)}
      </g>
      ${riskArcs}
      <g class="zbub fx" tabindex="-1" role="button" aria-pressed="false" aria-label="${esc(aria)}" data-action="zone" data-zone="${esc(zone.key)}" data-x="${f1(zone.cx)}" data-y="${f1(zone.cy)}">
        <title>${esc(aria)}</title>
        <circle class="zhit" r="${f1(zone.Rb + 18)}"/>
      </g>
    </g>
    <g class="zl zl-c" transform="translate(${f1(zone.cx)} ${f1(zone.cy + zone.Rb + 22)})">
      <text class="zl-name" y="0">${esc(zone.label)}</text>
      <text class="zl-sub" y="0" dy="1.35em">${esc(zone.sub)}</text>
      <text class="zl-cnt" y="0" dy="2.7em">${n} zařízení · ${zone.findings} nálezů${zone.sevMax ? ` · ${sevText}` : ""}</text>
    </g>
    <g class="zl zl-o" transform="translate(${f1(zone.cx)} ${f1(zone.cy - zone.Rd - 8)})">
      <text class="zl-name" y="0">${esc(zone.label)} · ${n} zařízení</text>
    </g>
    <g class="nodes">${nodes}</g>
  </g>`;
}

// ---------- cesta skoku ----------
type Stop = { p: P; r: number; core: number; zoneKey: string | null; key: string };

function rot(angle: number): P {
  return { x: Math.cos(angle), y: Math.sin(angle) };
}

function segment(a: Stop, b: Stop, side: number): { s: P; e: P; c1: P; c2: P; len: number } | null {
  const dx = b.p.x - a.p.x;
  const dy = b.p.y - a.p.y;
  const dist = Math.hypot(dx, dy);
  if (dist < a.r + b.r + 8) return null;
  const d = Math.atan2(dy, dx);
  const th = 0.6;
  const u0 = rot(d - side * th);
  const s = { x: a.p.x + u0.x * a.r, y: a.p.y + u0.y * a.r };
  const u1 = rot(d + Math.PI + side * th);
  const e = { x: b.p.x + u1.x * b.r, y: b.p.y + u1.y * b.r };
  const tS = rot(d + side * (Math.PI / 2 - th));
  const tE = rot(d + side * (th - Math.PI / 2));
  const k = Math.hypot(e.x - s.x, e.y - s.y) * 0.4;
  return { s, e, c1: { x: s.x + tS.x * k, y: s.y + tS.y * k }, c2: { x: e.x - tE.x * k, y: e.y - tE.y * k }, len: 0 };
}

function bez(seg: { s: P; c1: P; c2: P; e: P }, t: number): P {
  const m = 1 - t;
  return {
    x: m * m * m * seg.s.x + 3 * m * m * t * seg.c1.x + 3 * m * t * t * seg.c2.x + t * t * t * seg.e.x,
    y: m * m * m * seg.s.y + 3 * m * m * t * seg.c1.y + 3 * m * t * t * seg.c2.y + t * t * t * seg.e.y,
  };
}

function bezLen(seg: { s: P; c1: P; c2: P; e: P }): number {
  let len = 0;
  let prev = seg.s;
  for (let i = 1; i <= 24; i += 1) {
    const p = bez(seg, i / 24);
    len += Math.hypot(p.x - prev.x, p.y - prev.y);
    prev = p;
  }
  return len;
}

function routeLayer(stops: Stop[], idPrefix: string, reduced: boolean): { svg: string; defs: string } {
  const segs: Array<NonNullable<ReturnType<typeof segment>> & { a: Stop; b: Stop }> = [];
  for (let i = 1; i < stops.length; i += 1) {
    const seg = segment(stops[i - 1], stops[i], i % 2 ? 1 : -1);
    if (seg) {
      seg.len = bezLen(seg);
      segs.push({ ...seg, a: stops[i - 1], b: stops[i] });
    }
  }
  if (!segs.length) return { svg: "", defs: "" };
  let defs = "";
  let paths = "";
  segs.forEach((seg, i) => {
    const id = `${idPrefix}${i}`;
    defs += `<linearGradient id="${id}" gradientUnits="userSpaceOnUse" x1="${f1(seg.s.x)}" y1="${f1(seg.s.y)}" x2="${f1(seg.e.x)}" y2="${f1(seg.e.y)}"><stop offset="0" class="hg-e"/><stop offset="0.16" class="hg-f"/><stop offset="0.84" class="hg-f"/><stop offset="1" class="hg-e"/></linearGradient>`;
    // vstup cesty do uzlu: tekuty krček (metaball) od okraje uzlu k prvni a posledni tecce, bez sve
    const sockA = metaballBridge(seg.a.p, seg.a.core, seg.s, 3.4, 2.4)?.d ?? "";
    const sockB = metaballBridge(seg.b.p, seg.b.core, seg.e, 3.4, 2.4)?.d ?? "";
    paths += `<path class="hop-seg hop-sock" data-a="${esc(seg.a.key)}" data-b="${esc(seg.b.key)}" data-za="${esc(seg.a.zoneKey ?? "")}" data-zb="${esc(seg.b.zoneKey ?? "")}" d="${sockA}${sockB}"/>`;
    paths += `<path class="hop-seg" data-a="${esc(seg.a.key)}" data-b="${esc(seg.b.key)}" data-za="${esc(seg.a.zoneKey ?? "")}" data-zb="${esc(seg.b.zoneKey ?? "")}" stroke="url(#${id})" d="M${f1(seg.s.x)},${f1(seg.s.y)}C${f1(seg.c1.x)},${f1(seg.c1.y)} ${f1(seg.c2.x)},${f1(seg.c2.y)} ${f1(seg.e.x)},${f1(seg.e.y)}"/>`;
  });
  // skakajici tecka: jedna souvisla draha (kroky + kratke tetivy po obvodu uzlu), prodlevy v uzlech
  let full = "";
  const lens: number[] = [];
  segs.forEach((seg, i) => {
    full += i === 0 ? `M${f1(seg.s.x)},${f1(seg.s.y)}` : `L${f1(seg.s.x)},${f1(seg.s.y)}`;
    full += `C${f1(seg.c1.x)},${f1(seg.c1.y)} ${f1(seg.c2.x)},${f1(seg.c2.y)} ${f1(seg.e.x)},${f1(seg.e.y)}`;
    lens.push(seg.len);
  });
  let hopper = "";
  if (!reduced) {
    const chords = segs.slice(1).map((seg, i) => Math.hypot(seg.s.x - segs[i].e.x, seg.s.y - segs[i].e.y));
    const total = lens.reduce((a, b) => a + b, 0) + chords.reduce((a, b) => a + b, 0);
    const MOVE = 1.15;
    const DWELL = 0.55;
    const REST = 1.3;
    const times: number[] = [0];
    const points: number[] = [0];
    const splines: string[] = [];
    let t = 0;
    let cum = 0;
    segs.forEach((_, i) => {
      t += MOVE;
      cum += lens[i];
      times.push(t);
      points.push(cum / total);
      splines.push("0.45 0 0.2 1");
      if (i < segs.length - 1) {
        t += DWELL;
        cum += chords[i];
        times.push(t);
        points.push(cum / total);
        splines.push("0.3 0 0.7 1");
      }
    });
    t += REST;
    times.push(t);
    points.push(1);
    splines.push("0 0 1 1");
    const keyTimes = times.map((x) => (x / t).toFixed(4)).join(";");
    hopper = `<g class="hopper-g"><circle class="hopper"><animateMotion dur="${t.toFixed(2)}s" repeatCount="indefinite" path="${full}" calcMode="spline" keyTimes="${keyTimes}" keyPoints="${points.map((x) => x.toFixed(4)).join(";")}" keySplines="${splines.join(";")}"/></circle><animate attributeName="opacity" dur="${t.toFixed(2)}s" repeatCount="indefinite" values="0;1;1;0" keyTimes="0;0.03;0.95;1"/></g>`;
  }
  return { svg: `<g class="route">${paths}${hopper}</g>`, defs };
}

function hopMarks(model: NetModel, stops: Stop[], level: "node" | "zone"): string {
  // jeden znacka na stanici/zonu: cislo prvniho skoku, umistena na obvodu na opacne strane nez cesta
  const out: string[] = [];
  const seen = new Map<string, { stop: Stop; nos: number[]; dirs: P[] }>();
  const hops = model.hops;
  stops.forEach((stop, i) => {
    const entry = seen.get(stop.key) ?? { stop, nos: [], dirs: [] };
    const prev = stops[i - 1];
    const next = stops[i + 1];
    for (const o of [prev, next]) {
      if (!o) continue;
      const dx = o.p.x - stop.p.x;
      const dy = o.p.y - stop.p.y;
      const l = Math.hypot(dx, dy) || 1;
      entry.dirs.push({ x: dx / l, y: dy / l });
    }
    seen.set(stop.key, entry);
  });
  // cisla skoku patri k zarizeni (level node) nebo k zone (level zone)
  for (const hop of hops) {
    const item = model.byIp.get(hop.asset);
    let key: string | null = null;
    if (level === "node") key = item ? item.key : `out:${hop.asset}`;
    else key = item ? (item === model.gateway ? "gw" : item.zone) : `out:${hop.asset}`;
    const e = key ? seen.get(key) : undefined;
    if (e) e.nos.push(hop.index);
  }
  for (const [key, e] of seen) {
    if (!e.nos.length) continue;
    let ax = 0;
    let ay = 0;
    for (const d of e.dirs) {
      ax -= d.x;
      ay -= d.y;
    }
    const ang = ax || ay ? Math.atan2(ay, ax) : -2.3;
    const rr = e.stop.r + (level === "zone" ? 16 : 17);
    const x = e.stop.p.x + Math.cos(ang) * rr;
    const y = e.stop.p.y + Math.sin(ang) * rr;
    const first = model.hops.find((h) => e.nos.includes(h.index))!;
    const text = e.nos.length > 1 ? `${e.nos[0]}+` : String(e.nos[0]);
    out.push(
      `<g class="hm-pos" transform="translate(${f1(x)} ${f1(y)})" data-key="${esc(key)}" data-zone="${esc(e.stop.zoneKey ?? "")}"><g class="hop-mark st-${first.status}"><title>Skok ${e.nos.join(", ")}: ${esc(statusLabel(first.status))}</title><circle r="11"/><text y="0.5">${text}</text></g></g>`,
    );
  }
  return out.join("");
}

// ---------- provoz mezi zarizenimi ----------
/** Kandidati v DOM (serazeni podle objemu); mapctl zobrazi nejsilnejsich TRAFFIC_VISIBLE z tech, jejichz oba konce jsou videt. */
const TRAFFIC_MAX = 160;
const TRAFFIC_PARTICLES = 60;

/** Nejsilnejsi spojnice provozu: tloustka podle objemu (log), pohyblive castice ve smeru zdroj -> cil. */
function trafficLayer(model: NetModel, reduced: boolean): string {
  const rows = model.traffic
    .map((t) => ({ t, a: model.byIp.get(t.src), b: model.byIp.get(t.dst), v: t.bytes ?? (t.flows ?? 0) * 1000 }))
    .filter((r) => r.a && r.b && r.a !== r.b && r.v > 0)
    .sort((x, y) => y.v - x.v)
    .slice(0, TRAFFIC_MAX);
  if (!rows.length) return "";
  const vmax = rows[0].v;
  const vmin = rows[rows.length - 1].v;
  const span = Math.log(vmax / Math.max(vmin, 1)) || 1;
  const parts = rows.map(({ t, a, b, v }, i) => {
    const A = a!;
    const B = b!;
    const k = rows.length === 1 ? 1 : Math.log(v / Math.max(vmin, 1)) / span; // 0..1
    const dx = B.x - A.x;
    const dy = B.y - A.y;
    const len = Math.hypot(dx, dy) || 1;
    const ux = dx / len;
    const uy = dy / len;
    const s = { x: A.x + ux * A.r, y: A.y + uy * A.r };
    const e = { x: B.x - ux * B.r, y: B.y - uy * B.r };
    const bend = 0.12 * len * (i % 2 ? 1 : -1);
    const c = { x: (s.x + e.x) / 2 - uy * bend, y: (s.y + e.y) / 2 + ux * bend };
    const d = `M${f1(s.x)},${f1(s.y)}Q${f1(c.x)},${f1(c.y)} ${f1(e.x)},${f1(e.y)}`;
    const w = 1.3 + k * 4.2;
    const n = 1 + Math.round(k * 2);
    const dur = 4.2 - k * 2;
    let dots = "";
    if (!reduced && i < TRAFFIC_PARTICLES) {
      for (let j = 0; j < n; j += 1) {
        dots += `<circle class="tp" r="${f1(1.5 + k * 1.6)}"><animateMotion dur="${dur.toFixed(2)}s" begin="${((j * dur) / n + (i % 5) * 0.37).toFixed(2)}s" repeatCount="indefinite" path="${d}"/></circle>`;
      }
    }
    const label = `${t.src} → ${t.dst}${t.protocol ? ` (${t.protocol})` : ""}: ${t.bytes ? `${(t.bytes / 1e6).toFixed(1)} MB` : `${t.flows} toků`}`;
    return `<g class="t-edge" data-a="${esc(A.key)}" data-b="${esc(B.key)}" data-za="${esc(A === model.gateway ? "" : A.zone)}" data-zb="${esc(B === model.gateway ? "" : B.zone)}" style="--w:${w.toFixed(2)}"><title>${esc(label)}</title><path d="${d}"/>${dots}</g>`;
  });
  return `<g class="traffic" aria-hidden="true">${parts.join("")}</g>`;
}

// ---------- hlavni vykres ----------
export function renderNetMap(model: NetModel, selected: string | null, runId: string): string {
  const { bounds: b } = model;
  const vb = `${b.x.toFixed(0)} ${b.y.toFixed(0)} ${b.w.toFixed(0)} ${b.h.toFixed(0)}`;
  const reduced = typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const gate = model.gateway;

  // zastavky cesty: uzel (urovne zarizeni) a zona (urovne prehledu)
  const nodeStops: Stop[] = [];
  const zoneStops: Stop[] = [];
  const push = (list: Stop[], stop: Stop) => {
    if (list[list.length - 1]?.key !== stop.key) list.push(stop);
  };
  for (const hop of model.hops) {
    const item = model.byIp.get(hop.asset);
    if (item) {
      const isGate = item === gate;
      push(nodeStops, { p: { x: item.x, y: item.y }, r: item.r + (isGate ? 9 : 11.5), core: item.r, zoneKey: isGate ? null : item.zone, key: item.key });
      const zone = isGate ? null : model.zoneByKey.get(item.zone);
      if (zone) push(zoneStops, { p: { x: zone.cx, y: zone.cy }, r: zone.Rb + 23, core: zone.Rb, zoneKey: zone.key, key: zone.key });
      else push(zoneStops, { p: { x: model.gate.x, y: model.gate.y }, r: 30, core: gate ? 21 : 15, zoneKey: null, key: "gw" });
    } else {
      const out = model.outsiders.find((o) => o.ip === hop.asset);
      if (out) {
        push(nodeStops, { p: { x: out.x, y: out.y }, r: 17, core: 12, zoneKey: null, key: `out:${out.ip}` });
        push(zoneStops, { p: { x: out.x, y: out.y }, r: 17, core: 12, zoneKey: null, key: `out:${out.ip}` });
      }
    }
  }
  const nodeRoute = routeLayer(nodeStops, "hgn", reduced);
  const zoneRoute = routeLayer(zoneStops, "hgz", reduced);

  const zones = model.zones.map((z) => zoneMarkup(model, z, selected)).join("");
  const internet = `<g class="internet"><circle class="net-edge" cx="${model.internet.x}" cy="${model.internet.y}" r="30"/><g class="net-ico" transform="translate(${model.internet.x} ${model.internet.y - 6}) scale(0.9) translate(-12 -12)">${iconInner("internet")}</g><text class="net-label" x="${model.internet.x}" y="${model.internet.y + 18}">internet</text></g>`;
  const gateOverlay = gate ? nodeMarkup(gate, null, selected, 0) : "";
  const gateLabel = `<text class="net-label" x="${model.gate.x}" y="${gate ? 42 : 32}">${gate ? "brána" : "brána (neznámá)"}</text>`;
  const outsiderOverlay = model.outsiders
    .map((o) => `<g class="outsider"><circle class="out-edge" cx="${o.x}" cy="${o.y}" r="12"/><text class="out-ip" x="${o.x}" y="${o.y + 30}">${esc(o.ip)}</text></g>`)
    .join("");
  const gooFixed = `<path class="zbridge" d="${bridgePath(model.internet, 30, model.gate, gate ? 21 : 15, 14, 5)}"/><circle class="g-net" cx="${model.internet.x}" cy="${model.internet.y}" r="30"/>${gate ? "" : `<circle class="g-gate" cx="${model.gate.x}" cy="${model.gate.y}" r="15"/>`}`;

  return `<svg class="netmap no-anim" viewBox="${vb}" data-vb="${vb}" data-run="${esc(runId)}" role="group" aria-label="Mapa sítě. Tabulátor vstoupí na mapu, šipky přeskakují mezi podsítěmi a zařízeními, Enter rozbalí podsíť nebo vybere zařízení, Esc se vrací o úroveň zpět, plus a mínus přibližují, nula zobrazí celou mapu." preserveAspectRatio="none">
    <defs>${nodeRoute.defs}${zoneRoute.defs}</defs>
    <g class="links">${gooFixed}</g>
    <g class="sel-links"></g>
    ${trafficLayer(model, reduced)}
    <g class="zones">${zones}</g>
    <g class="route-node">${nodeRoute.svg}</g>
    <g class="route-zone">${zoneRoute.svg}</g>
    <g class="overlay">${internet}${gateLabel}${outsiderOverlay}${gateOverlay}</g>
    <g class="marks marks-node">${hopMarks(model, nodeStops, "node")}</g>
    <g class="marks marks-zone">${hopMarks(model, zoneStops, "zone")}</g>
  </svg>`;
}
