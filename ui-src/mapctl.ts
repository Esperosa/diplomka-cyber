// Rizeni mapy: filtry (podsite/VLAN, typy, zavaznost, hledani), rozbaleni zon, vyber zarizeni, drobeckova
// navigace, adresa (hash) a hlaseni pro ctecky. Mapa se po zmene NEPREKRESLUJE: meni se jen tridy a pohled,
// takze rozkvet, utlum a prelet kamery bezi plynule pres CSS a sdilene tokeny pohybu.
import { KIND_ORDER, iconSvg, kindLabel, type DeviceKind } from "./devices";
import { bindMapView, netMapTools, type Box, type Cam, type MapView } from "./mapview";
import { arcPath, bridgePath, renderNetMap } from "./netmap";
import {
  AUTO_OPEN_MAX,
  EMPTY_FILTER,
  attributeFilterActive,
  buildNetModel,
  filterActive,
  itemMatches,
  type Item,
  type MapFilter,
  type NetModel,
  uplinkChain,
} from "./netmodel";
import type { Scope } from "./panels";
import { hashQuery } from "./router";
import { state } from "./state";
import type { Report } from "./types";
import { esc } from "./ui";

export const ui = { filter: { ...EMPTY_FILTER } as MapFilter, barOpen: null as boolean | null };

type Ctx = {
  model: NetModel;
  report: Report;
  host: HTMLElement;
  svg: SVGSVGElement;
  view: MapView;
  renderSide: () => string;
  sig: string;
};
let ctx: Ctx | null = null;
let cache: { report: Report; model: NetModel } | null = null;
let saved: { run: string; cam: Cam } | null = null;
let lastHash = "";
let escBound = false;
let levelLockUntil = 0;
const TRAFFIC_VISIBLE = 30;
export const LEVEL_IN = 1.9;
export const LEVEL_OUT = 1.25;
let appliedSig = "";

export function modelFor(report: Report): NetModel {
  if (cache?.report !== report) cache = { report, model: buildNetModel(report) };
  return cache.model;
}

// ---------- stav z adresy ----------
const csv = (v: string | null) => (v ? v.split(",").map((x) => x.trim()).filter(Boolean) : []);

/** Nacte filtr a vyber z hashe, pokud ho nezapsala mapa sama (zmena adresy rucne nebo odkaz). */
export function loadFromHash(model: NetModel): void {
  const hash = window.location.hash;
  if (hash === lastHash) return;
  const q = hashQuery(hash);
  if (!hash.includes("?")) return;
  const zones = csv(q.get("v")).filter((k) => model.zoneByKey.has(k));
  const kinds = csv(q.get("t")).filter((k): k is DeviceKind => (KIND_ORDER as string[]).includes(k));
  const sev = csv(q.get("s")).map(Number).filter((n) => n >= 0 && n <= 3);
  ui.filter = { zones, kinds, sev, q: q.get("q") ?? "" };
  const h = q.get("h");
  if (h && model.byKey.has(h)) state.selectedHost = h;
}

function writeHash(): void {
  if (state.section !== "prehled") return;
  const f = ui.filter;
  const parts: string[] = [];
  if (f.zones.length) parts.push(`v=${f.zones.map(encodeURIComponent).join(",")}`);
  if (f.kinds.length) parts.push(`t=${f.kinds.join(",")}`);
  if (f.sev.length) parts.push(`s=${f.sev.join(",")}`);
  if (f.q.trim()) parts.push(`q=${encodeURIComponent(f.q.trim())}`);
  if (state.selectedHost && ctx?.model.byKey.has(state.selectedHost)) parts.push(`h=${encodeURIComponent(state.selectedHost)}`);
  const next = `#/prehled${parts.length ? `?${parts.join("&")}` : ""}`;
  lastHash = next;
  if (window.location.hash !== next) window.history.replaceState(null, "", next);
}

// ---------- odvozeni stavu ----------
function derive(model: NetModel, f: MapFilter) {
  const attr = attributeFilterActive(f);
  const isolated = f.zones.length > 0;
  const autoOpen = model.items.length <= AUTO_OPEN_MAX || model.zones.length <= 1;
  const open = new Set<string>();
  const away = new Set<string>();
  for (const z of model.zones) {
    const included = !isolated || f.zones.includes(z.key);
    if (!included) away.add(z.key);
    else if (isolated || attr || autoOpen) open.add(z.key);
  }
  return { attr, isolated, open, away };
}

function visibleItems(model: NetModel, f: MapFilter): Item[] {
  return model.items.filter((i) => (i === model.gateway ? !attributeFilterActive(f) || itemMatches(i, f, true) : itemMatches(i, f)));
}

function targetBox(model: NetModel, f: MapFilter): { box: Box | null; maxS: number } {
  const st = derive(model, f);
  if (st.isolated) {
    const zs = model.zones.filter((z) => f.zones.includes(z.key));
    if (!zs.length) return { box: null, maxS: Infinity };
    // zaroven jen zarizeni, ktera odpovidaji (kdyz je i dalsi filtr), jinak cela zona
    if (st.attr) {
      const hit = zs.flatMap((z) => z.items).filter((i) => itemMatches(i, f));
      if (hit.length) return { box: itemsBox(hit), maxS: 3.4 };
    }
    const x0 = Math.min(...zs.map((z) => z.cx - z.Rd));
    const x1 = Math.max(...zs.map((z) => z.cx + z.Rd));
    const y0 = Math.min(...zs.map((z) => z.cy - z.Rd - 30));
    const y1 = Math.max(...zs.map((z) => z.cy + z.Rd));
    return { box: { x: x0, y: y0, w: x1 - x0, h: y1 - y0 }, maxS: 4 };
  }
  if (st.attr) {
    const hit = model.items.filter((i) => itemMatches(i, f));
    if (hit.length) return { box: itemsBox(hit), maxS: 3.4 };
  }
  if (!st.open.size && model.zones.length) {
    // prehled: stacilo by se vejit bubliny, ne cela pole zarizeni
    const pts: Box[] = [
      { x: model.internet.x - 60, y: model.internet.y - 40, w: 120, h: 80 },
      ...model.outsiders.map((o) => ({ x: o.x - 40, y: o.y - 20, w: 80, h: 70 })),
      ...model.zones.map((z) => ({ x: z.cx - z.Rb - 24, y: z.cy - z.Rb - 24, w: (z.Rb + 24) * 2, h: z.Rb * 2 + 24 + 84 })),
    ];
    const x0 = Math.min(...pts.map((b) => b.x));
    const y0 = Math.min(...pts.map((b) => b.y));
    const x1 = Math.max(...pts.map((b) => b.x + b.w));
    const y1 = Math.max(...pts.map((b) => b.y + b.h));
    return { box: { x: x0, y: y0, w: x1 - x0, h: y1 - y0 }, maxS: Infinity };
  }
  return { box: null, maxS: Infinity };
}

function itemsBox(items: Item[]): Box {
  const x0 = Math.min(...items.map((i) => i.x - i.r - 14));
  const x1 = Math.max(...items.map((i) => i.x + i.r + 14));
  const y0 = Math.min(...items.map((i) => i.y - i.r - 14));
  const y1 = Math.max(...items.map((i) => i.y + i.r + 22));
  return { x: x0, y: y0, w: Math.max(80, x1 - x0), h: Math.max(80, y1 - y0) };
}

function sigOf(f: MapFilter): string {
  return JSON.stringify([f.zones, f.kinds, f.sev, f.q.trim().toLowerCase()]);
}

// ---------- panely HTML ----------
const SEV_CHIPS: Array<[number, string]> = [
  [3, "Vysoká"],
  [2, "Střední"],
  [1, "Nízká"],
  [0, "Bez nálezů"],
];

function miniRisk(withFindings: number, n: number, high: number): string {
  if (!withFindings) return `<svg class="mc-risk" viewBox="-10 -10 20 20" aria-hidden="true"><circle class="mcr-track" r="7"/></svg>`;
  const frac = Math.max(0.16, withFindings / n);
  const a1 = -Math.PI / 2 + frac * Math.PI * 2 * 0.96;
  return `<svg class="mc-risk" viewBox="-10 -10 20 20" aria-hidden="true"><circle class="mcr-track" r="7"/><path class="mcr-arc${high ? " hot" : ""}" d="${arcPath(7, -Math.PI / 2, a1)}"/></svg>`;
}

export function barHtml(model: NetModel): string {
  const zoneChips = model.zones
    .map((z) => {
      const tip = `${z.label}: ${z.items.length} zařízení, ${z.withFindings} s nálezem, ${z.high} s vysokou závažností`;
      return `<button type="button" class="mchip" data-action="chip-zone" data-zone="${esc(z.key)}" aria-pressed="false" title="${esc(tip)}" aria-label="${esc(tip)}">${miniRisk(z.withFindings, z.items.length, z.high)}<span class="mc-name">${esc(z.label)}</span><span class="mc-n mono" data-n>${z.items.length}</span></button>`;
    })
    .join("");
  const present = new Map<DeviceKind, number>();
  for (const i of model.items) present.set(i.kind, (present.get(i.kind) ?? 0) + 1);
  const kindChips = KIND_ORDER.filter((k) => present.has(k))
    .map((k) => `<button type="button" class="mchip" data-action="chip-kind" data-kind="${k}" aria-pressed="false">${iconSvg(k, 16, "ico")}<span class="mc-name">${esc(kindLabel(k))}</span><span class="mc-n mono" data-n>${present.get(k)}</span></button>`)
    .join("");
  const sevChips = SEV_CHIPS.map(
    ([level, label]) =>
      `<button type="button" class="mchip" data-action="chip-sev" data-sev="${level}" aria-pressed="false">${level ? `<span class="sev ${level === 3 ? "sev-high" : level === 2 ? "sev-medium" : "sev-low"}" aria-hidden="true"></span>` : `<span class="sev sev-none" aria-hidden="true"></span>`}<span class="mc-name">${label}</span><span class="mc-n mono" data-n>0</span></button>`,
  ).join("");
  // Lista filtru je rozbalovaci levy panel uvnitr mapy (vychozi zavreny). Sekce jsou <details>,
  // aby sly sbalit; pocet v zahlavi ukazuje kolik voleb sekce nabizi a kolik je aktivnich.
  const open = ui.barOpen ?? false;
  const sec = (title: string, total: string, body: string, actKey: string) =>
    `<details class="mb-sec" open><summary class="mb-sec-h"><span class="mb-sec-t">${title}</span><span class="mb-sec-n mono">${total}</span><span class="mb-sec-act mono" data-sec-act="${actKey}" hidden></span></summary>${body}</details>`;
  const searchBody = `<label class="mb-search"><span class="sr-only">Hledat zařízení</span><input type="search" id="mapSearch" autocomplete="off" spellcheck="false" placeholder="IP, název, výrobce, služba" value="${esc(ui.filter.q)}"></label>`;
  return `<div class="mapbar${open ? " is-open" : ""}" role="region" aria-label="Filtry a poloha na mapě">
    <div class="mb-top">
      <button type="button" class="mb-toggle" data-action="toggle-bar" aria-expanded="${open}" aria-controls="mapFilters"><svg class="mb-ico" viewBox="0 0 16 16" aria-hidden="true"><path d="M2 3h12l-4.6 5.4V13l-2.8-1.6V8.4z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/></svg><span>Filtry</span><span class="mb-badge mono" data-badge hidden></span></button>
      <div class="mb-caption">
        <nav class="crumbs" aria-label="Kde jsem"></nav>
        <span class="mb-count mono" id="mapCount"><span class="mb-shown"></span><button type="button" class="link mb-clear" data-action="clear-filter" hidden>zrušit</button></span>
      </div>
    </div>
    <div class="mb-body" id="mapFilters">
      ${sec("Hledat", "", searchBody, "q")}
      ${sec("Závažnost", String(SEV_CHIPS.length), `<div class="chiprow" role="group" aria-label="Závažnost nálezů">${sevChips}</div>`, "sev")}
      ${sec("Podsíť / VLAN", String(model.zones.length), `<div class="chiprow" role="group" aria-label="Podsítě a VLAN">${zoneChips}</div>`, "zone")}
      ${sec("Typ zařízení", String(present.size), `<div class="chiprow" role="group" aria-label="Typ zařízení">${kindChips}</div>`, "kind")}
    </div>
    <p class="sr-only" id="mapLive" role="status" aria-live="polite"></p>
  </div>`;
}

export function mapFrameHtml(model: NetModel, runId: string): string {
  return `<div class="map-frame">${renderNetMap(model, state.selectedHost, runId)}${netMapTools()}
      <ul class="legend" id="mapLegend" aria-label="Legenda">
        <li><i class="lg lg-size"></i>velikost: význam zařízení</li>
        <li><i class="lg lg-ring"></i>oblouk kolem: riziko</li>
        <li><i class="lg lg-dash"></i>přerušený obrys: nejistota</li>
        <li><i class="lg lg-agent"></i>lupa: kontrola agenta</li>
        <li><i class="lg lg-hop"></i>tečky: cesta skoků</li>
        <li>${model.traffic.length ? "šedé čáry: provoz, tloušťka = objem" : "provoz mezi zařízeními: backend zatím neposílá"}</li>
      </ul>
      <p class="map-empty" hidden>Žádné zařízení neodpovídá filtru.</p>
    </div>`;
}

// ---------- aplikace stavu ----------
function bySel(root: ParentNode, sel: string): HTMLElement[] {
  return [...root.querySelectorAll<HTMLElement>(sel)];
}

export function currentScope(): Scope {
  const c = ctx!;
  const f = ui.filter;
  const items = visibleItems(c.model, f);
  const st = derive(c.model, f);
  if (st.attr) {
    const bits: string[] = [];
    if (f.kinds.length) bits.push(f.kinds.map(kindLabel).join(", "));
    if (f.sev.length) bits.push(`závažnost ${f.sev.map((n) => ["bez nálezů", "nízká", "střední", "vysoká"][n]).join(", ")}`);
    if (f.q.trim()) bits.push(`hledání „${f.q.trim()}“`);
    if (st.isolated) bits.push(f.zones.map((k) => c.model.zoneByKey.get(k)?.label ?? k).join(", "));
    return { eyebrow: "Filtr", title: `Zobrazeno ${items.length} z ${c.model.items.length}`, sub: bits.join(" · "), items };
  }
  if (f.zones.length === 1) {
    const z = c.model.zoneByKey.get(f.zones[0])!;
    return { eyebrow: "Podsíť", title: z.label, sub: z.sub, items: z.items };
  }
  if (f.zones.length > 1) return { eyebrow: "Vybrané podsítě", title: `${f.zones.length} podsítí`, sub: f.zones.map((k) => c.model.zoneByKey.get(k)?.label ?? k).join(", "), items };
  return { eyebrow: "Celá síť", title: `${c.model.items.length} zařízení`, sub: `${c.model.zones.length} ${c.model.zones.length === 1 ? "podsíť" : "podsítí"}${c.model.topology ? " · skutečná topologie" : " · podle adresních rozsahů"}`, items };
}

export function selectedItem(): Item | null {
  return ctx && state.selectedHost ? ctx.model.byKey.get(state.selectedHost) ?? null : null;
}

function syncCrumbs(c: Ctx) {
  const f = ui.filter;
  const sel = selectedItem();
  const nav = c.host.querySelector<HTMLElement>(".crumbs");
  if (!nav) return;
  const parts: string[] = [];
  const zoneLabel = f.zones.length === 1 ? c.model.zoneByKey.get(f.zones[0])?.label : f.zones.length > 1 ? `${f.zones.length} podsítí` : null;
  const attr = attributeFilterActive(f);
  const levels: Array<{ label: string; level: string }> = [{ label: "Celá síť", level: "all" }];
  if (zoneLabel) levels.push({ label: zoneLabel, level: "zone" });
  if (attr && !zoneLabel) levels.push({ label: "Filtr", level: "filter" });
  if (sel) levels.push({ label: sel.host.hostname ?? sel.ip, level: "device" });
  levels.forEach((l, i) => {
    const last = i === levels.length - 1;
    parts.push(last ? `<span class="crumb is-current" aria-current="location">${esc(l.label)}</span>` : `<button type="button" class="crumb" data-action="crumb" data-level="${l.level}">${esc(l.label)}</button>`);
  });
  nav.innerHTML = parts.join(`<span class="crumb-sep" aria-hidden="true">›</span>`);
}

function facet(model: NetModel, f: MapFilter, skip: "zones" | "kinds" | "sev", test: (i: Item) => boolean): number {
  const g: MapFilter = { ...f, [skip]: [] };
  let n = 0;
  for (const i of model.items) if (i !== model.gateway && itemMatches(i, g) && test(i)) n += 1;
  return n;
}

function syncBar(c: Ctx, announce: boolean) {
  const f = ui.filter;
  const bar = c.host.querySelector<HTMLElement>(".mapbar");
  if (!bar) return;
  for (const chip of bySel(bar, '[data-action="chip-zone"]')) {
    const key = chip.dataset.zone!;
    chip.setAttribute("aria-pressed", String(f.zones.includes(key)));
    const n = facet(c.model, f, "zones", (i) => i.zone === key);
    chip.querySelector("[data-n]")!.textContent = String(n);
    chip.classList.toggle("is-zero", n === 0);
  }
  for (const chip of bySel(bar, '[data-action="chip-kind"]')) {
    const kind = chip.dataset.kind as DeviceKind;
    chip.setAttribute("aria-pressed", String(f.kinds.includes(kind)));
    const n = facet(c.model, f, "kinds", (i) => i.kind === kind);
    chip.querySelector("[data-n]")!.textContent = String(n);
    chip.classList.toggle("is-zero", n === 0);
  }
  for (const chip of bySel(bar, '[data-action="chip-sev"]')) {
    const level = Number(chip.dataset.sev);
    chip.setAttribute("aria-pressed", String(f.sev.includes(level)));
    const n = facet(c.model, f, "sev", (i) => i.sev === level);
    chip.querySelector("[data-n]")!.textContent = String(n);
    chip.classList.toggle("is-zero", n === 0);
  }
  const shown = visibleItems(c.model, f).length;
  const total = c.model.items.length;
  const active = filterActive(f);
  const shownEl = bar.querySelector<HTMLElement>(".mb-shown")!;
  shownEl.textContent = active ? `Zobrazeno ${shown} z ${total}` : `${total} zařízení v síti`;
  bar.querySelector<HTMLElement>('[data-action="clear-filter"]')!.hidden = !active;
  const badge = bar.querySelector<HTMLElement>("[data-badge]")!;
  const nActive = f.zones.length + f.kinds.length + f.sev.length + (f.q.trim() ? 1 : 0);
  badge.hidden = !nActive;
  badge.textContent = String(nActive);
  const actives: Record<string, number> = { q: f.q.trim() ? 1 : 0, sev: f.sev.length, zone: f.zones.length, kind: f.kinds.length };
  for (const el of bySel(bar, "[data-sec-act]")) {
    const n = actives[el.dataset.secAct ?? ""] ?? 0;
    el.hidden = !n;
    el.textContent = String(n);
  }
  c.host.querySelector<HTMLElement>(".map-empty")!.hidden = !(active && shown === 0);
  const search = bar.querySelector<HTMLInputElement>("#mapSearch");
  if (search && document.activeElement !== search && search.value !== f.q) search.value = f.q;
  if (announce) bar.querySelector<HTMLElement>("#mapLive")!.textContent = active ? `Zobrazeno ${shown} z ${total}` : `Zobrazena celá síť, ${total} zařízení`;
}

function routeVisibility(c: Ctx, open: Set<string>, matching: Set<string>) {
  const ok = (zoneKey: string, key: string) => (zoneKey === "" || open.has(zoneKey)) && (key.startsWith("out:") || matching.has(key));
  let allVisible = true;
  // provoz: z viditelnych spojnic jen TRAFFIC_VISIBLE nejsilnejsich (v DOM jsou serazene podle objemu)
  let shownTraffic = 0;
  for (const edge of bySel(c.svg, ".traffic .t-edge")) {
    const vis = ok(edge.dataset.za ?? "", edge.dataset.a ?? "") && ok(edge.dataset.zb ?? "", edge.dataset.b ?? "") && shownTraffic < TRAFFIC_VISIBLE;
    if (vis) shownTraffic += 1;
    edge.classList.toggle("off", !vis);
  }
  for (const seg of bySel(c.svg, ".route-node .hop-seg")) {
    const vis = ok(seg.dataset.za ?? "", seg.dataset.a ?? "") && ok(seg.dataset.zb ?? "", seg.dataset.b ?? "");
    seg.classList.toggle("off", !vis);
    if (!vis) allVisible = false;
  }
  c.svg.querySelector(".route-node")?.classList.toggle("partial", !allVisible);
  for (const m of bySel(c.svg, ".marks-node .hm-pos")) m.classList.toggle("off", !ok(m.dataset.zone ?? "", m.dataset.key ?? ""));
}

function paint(c: Ctx) {
  const f = ui.filter;
  const st = derive(c.model, f);
  const svg = c.svg;
  svg.classList.toggle("lv-nodes", st.open.size > 0);
  svg.classList.toggle("filtering", st.attr);
  const matching = new Set(visibleItems(c.model, f).map((i) => i.key));
  for (const zoneEl of bySel(svg, ".zone")) {
    const key = zoneEl.dataset.zone!;
    const isOpen = st.open.has(key);
    zoneEl.classList.toggle("is-open", isOpen);
    zoneEl.classList.toggle("is-away", st.away.has(key));
    const z = c.model.zoneByKey.get(key)!;
    zoneEl.classList.toggle("is-empty", isOpen && st.attr && !z.items.some((i) => matching.has(i.key)));
    const bub = zoneEl.querySelector<SVGGElement>(".zbub");
    bub?.setAttribute("aria-pressed", String(f.zones.includes(key)));
  }
  for (const node of bySel(svg, ".node")) {
    const key = node.dataset.host!;
    node.classList.toggle("is-off", !matching.has(key));
    const sel = key === state.selectedHost;
    node.classList.toggle("is-selected", sel);
    node.setAttribute("aria-pressed", String(sel));
  }
  routeVisibility(c, st.open, matching);
  // spojeni vybraneho zarizeni (cesta k brane a podrizena zarizeni), i pres hranice podsiti
  const sl = svg.querySelector(".sel-links");
  const sel = selectedItem();
  let d = "";
  if (sel && sl) {
    const vis = (it: Item) => it === c.model.gateway || (st.open.has(it.zone) && matching.has(it.key));
    const chain = uplinkChain(c.model, sel);
    const pairs: Array<[Item, Item]> = [];
    for (let i = 1; i < chain.length; i += 1) pairs.push([chain[i - 1], chain[i]]);
    for (const k of sel.children) {
      const ch = c.model.byKey.get(k);
      if (ch) pairs.push([sel, ch]);
    }
    for (const [a, b] of pairs) if (vis(a) && vis(b)) d += bridgePath({ x: a.x, y: a.y }, a.r, { x: b.x, y: b.y }, b.r, 7, 2.6, 0.1);
  }
  if (sl) sl.innerHTML = d ? `<path class="sel-link" d="${d}"/>` : "";
  const isNav = (el: SVGGElement) => {
    if (el.classList.contains("zbub")) {
      const zone = el.closest<SVGGElement>(".zone")!;
      return !zone.classList.contains("is-open") && !zone.classList.contains("is-away");
    }
    if (el.classList.contains("is-off")) return false;
    const zone = el.closest<SVGGElement>(".zone");
    if (!zone) return true; // brana
    return zone.classList.contains("is-open");
  };
  c.view.refreshNav(isNav, state.selectedHost ? svg.querySelector(`.node[data-host="${CSS.escape(state.selectedHost)}"]`) : null);
}

function fitToState(c: Ctx, instant: boolean) {
  const { box, maxS } = targetBox(c.model, ui.filter);
  c.view.lock(instant ? 0 : 650);
  if (box) c.view.fitBox(box, 28, instant, maxS);
  else c.view.fitAll(instant);
}

function refreshSide(c: Ctx, resetScroll: boolean) {
  const slot = document.querySelector<HTMLElement>("#sideBody");
  if (!slot) return;
  const side = slot.closest<HTMLElement>(".side");
  const top = side?.scrollTop ?? 0;
  slot.innerHTML = c.renderSide();
  if (side) side.scrollTop = resetScroll ? 0 : top;
  document.querySelector<HTMLElement>(".overview")?.classList.toggle("has-profile", Boolean(selectedItem()));
}

/** Zmena stavu: prekresli jen tridy, pohled a panely. */
function commit(opts: { fit?: boolean; announce?: boolean; resetSide?: boolean; instant?: boolean } = {}) {
  const c = ctx;
  if (!c) return;
  const sig = sigOf(ui.filter);
  const changed = sig !== c.sig;
  c.sig = sig;
  appliedSig = sig;
  paint(c);
  syncCrumbs(c);
  syncBar(c, Boolean(opts.announce) && changed);
  if (opts.fit ?? changed) fitToState(c, Boolean(opts.instant));
  refreshSide(c, opts.resetSide ?? changed);
  writeHash();
}

// ---------- verejne akce ----------
function mutate(fn: (f: MapFilter) => void, opts: Parameters<typeof commit>[0] = {}) {
  const f = ui.filter;
  fn(f);
  ui.filter = { zones: [...f.zones], kinds: [...f.kinds], sev: [...f.sev], q: f.q };
  // vybrane zarizeni, ktere uz neni videt, se uvolni (profil by ukazoval neco, co na mape neni)
  const sel = selectedItem();
  if (sel && ctx && !visibleItems(ctx.model, ui.filter).includes(sel)) state.selectedHost = null;
  commit({ announce: true, ...opts });
}
const toggle = <T,>(list: T[], v: T) => {
  const i = list.indexOf(v);
  if (i >= 0) list.splice(i, 1);
  else list.push(v);
};

/** Na telefonu profil prekryva spodni cast mapy: vybrane zarizeni se posune do horni poloviny. */
function liftSelected(c: Ctx, item: Item | null) {
  if (!item || !window.matchMedia("(max-width: 40rem)").matches) return;
  const cam = c.view.cam();
  const h = c.svg.getBoundingClientRect().height;
  c.view.lock(500);
  c.view.animateTo({ cx: item.x, cy: item.y + (h * 0.36) / cam.s, s: Math.max(cam.s, 1.2) });
}

export const actions = {
  zone(key: string) {
    mutate((f) => {
      f.zones = f.zones.length === 1 && f.zones[0] === key ? [] : [key];
    });
  },
  chipZone(key: string) {
    mutate((f) => toggle(f.zones, key));
  },
  chipKind(kind: DeviceKind) {
    mutate((f) => toggle(f.kinds, kind));
  },
  chipSev(level: number) {
    mutate((f) => toggle(f.sev, level));
  },
  setQuery(q: string) {
    mutate((f) => {
      f.q = q;
    });
  },
  clearFilter() {
    mutate((f) => {
      f.zones = [];
      f.kinds = [];
      f.sev = [];
      f.q = "";
    });
  },
  /** Vyber zarizeni kliknutim na mape (kamera se nehybe). */
  select(key: string | null) {
    state.selectedHost = state.selectedHost === key ? null : key;
    commit({ fit: false, resetSide: true });
    if (ctx) liftSelected(ctx, selectedItem());
    announce(selectedItem() ? `Vybráno: ${kindLabel(selectedItem()!.kind)} ${selectedItem()!.ip}` : "Výběr zrušen");
  },
  deselect() {
    state.selectedHost = null;
    commit({ fit: false, resetSide: true });
    announce("Výběr zrušen");
  },
  /** Vyber ze seznamu (skok, nejrizikovejsi, retez pripojeni): zona se rozbali a kamera doletí k zarizeni. */
  pick(key: string) {
    const c = ctx;
    const item = c?.model.byKey.get(key);
    if (!c || !item) return;
    const f = ui.filter;
    const st = derive(c.model, f);
    let refit = false;
    if (item !== c.model.gateway) {
      if (!st.open.has(item.zone)) {
        f.zones = [item.zone];
        refit = true;
      }
      if (!itemMatches(item, ui.filter, true)) {
        f.kinds = [];
        f.sev = [];
        f.q = "";
      }
    }
    ui.filter = { zones: [...f.zones], kinds: [...f.kinds], sev: [...f.sev], q: f.q };
    state.selectedHost = key;
    commit({ fit: refit, announce: true, resetSide: true });
    if (!refit) {
      const cam = c.view.cam();
      c.view.lock(500);
      c.view.animateTo({ cx: item.x, cy: item.y, s: Math.max(cam.s, 1.5) });
      liftSelected(c, item);
    }
    announce(`Vybráno: ${kindLabel(item.kind)} ${item.ip}`);
  },
  crumb(level: string) {
    if (level === "all") {
      mutate((f) => {
        f.zones = [];
      });
      state.selectedHost = null;
      commit({ fit: true, resetSide: true });
    } else if (level === "zone" || level === "filter") {
      state.selectedHost = null;
      commit({ fit: false, resetSide: true });
    }
  },
  toggleBar() {
    const bar = ctx?.host.querySelector<HTMLElement>(".mapbar");
    if (!bar) return;
    const open = !bar.classList.contains("is-open");
    ui.barOpen = open;
    bar.classList.toggle("is-open", open);
    bar.querySelector(".mb-toggle")?.setAttribute("aria-expanded", String(open));
  },
  /** O uroven zpet (Esc, dvojklik na prazdno). Vraci true, pokud se neco zmenilo. */
  back(): boolean {
    const c = ctx;
    if (!c) return false;
    if (state.selectedHost) {
      actions.deselect();
      return true;
    }
    if (ui.filter.zones.length) {
      mutate((f) => {
        f.zones = [];
      });
      return true;
    }
    if (filterActive(ui.filter)) {
      actions.clearFilter();
      return true;
    }
    return false;
  },
  fit() {
    if (ctx) fitToState(ctx, false);
  },
};

function announce(text: string) {
  const el = ctx?.host.querySelector<HTMLElement>("#mapLive");
  if (el) el.textContent = text;
}

// ---------- pripojeni na DOM ----------
export function mountMap(host: HTMLElement, report: Report, renderSide: () => string): void {
  const model = modelFor(report);
  const svg = host.querySelector<SVGSVGElement>("svg.netmap");
  if (!svg) return;
  const fresh = saved?.run !== model.runId;
  const view = bindMapView(
    host,
    svg,
    {
      bounds: model.bounds,
      onCam: (cam) => {
        saved = { run: model.runId, cam };
      },
      // Prechod mezi urovnemi s hysterezi: rozbaleni zony pri priblizeni nad 1,9x meritka celku, navrat na
      // celou sit az pri oddaleni pod 1,25x. Mezi prahy se nic nedeje, po prepnuti je 700 ms klid.
      onUserZoom: (cam, fit, _client, world, factor) => {
        const c = ctx;
        const now = performance.now();
        if (!c || now < levelLockUntil) return;
        if (factor < 1) {
          if (ui.filter.zones.length && cam.s <= fit * LEVEL_OUT) {
            levelLockUntil = now + 700;
            actions.crumb("all");
          }
          return;
        }
        if (cam.s < fit * LEVEL_IN) return;
        if (derive(c.model, ui.filter).open.size) return;
        const z = c.model.zones.find((zz) => Math.hypot(world.x - zz.cx, world.y - zz.cy) <= zz.Rb * 1.35);
        if (z) {
          levelLockUntil = now + 700;
          actions.zone(z.key);
        }
      },
      onBackgroundDouble: () => (ui.filter.zones.length || state.selectedHost ? actions.back() : false),
    },
    fresh ? null : saved!.cam,
  );
  ctx = { model, report, host, svg, view, renderSide, sig: sigOf(ui.filter) };
  host.querySelector<HTMLButtonElement>('[data-map="fit"]')?.addEventListener("click", () => actions.fit());
  host.querySelector<HTMLInputElement>("#mapSearch")?.addEventListener("input", (event) => {
    const value = (event.target as HTMLInputElement).value;
    window.clearTimeout(searchTimer);
    searchTimer = window.setTimeout(() => actions.setQuery(value), 140);
  });
  if (!escBound) {
    escBound = true;
    document.addEventListener(
      "keydown",
      (event) => {
        if (event.key !== "Escape" || state.section !== "prehled" || !ctx || !document.contains(ctx.host)) return;
        if (state.assistantOpen || document.querySelector("dialog[open], details.menu[open]")) return;
        const target = event.target as HTMLElement;
        if (target.id === "mapSearch" && (target as HTMLInputElement).value) {
          (target as HTMLInputElement).value = "";
          actions.setQuery("");
          event.preventDefault();
          return;
        }
        if (actions.back()) event.preventDefault();
      },
      true,
    );
  }
  // prvni stav bez animace; potom se pohyb zapne
  paint(ctx);
  syncCrumbs(ctx);
  syncBar(ctx, false);
  refreshSide(ctx, false);
  fitStartup(ctx, fresh || sigOf(ui.filter) !== appliedSig);
  if (fresh) window.setTimeout(() => ctx && liftSelected(ctx, selectedItem()), 60);
  appliedSig = sigOf(ui.filter);
  writeHash();
  requestAnimationFrame(() => requestAnimationFrame(() => svg.classList.remove("no-anim")));
}

let searchTimer = 0;

function fitStartup(c: Ctx, refit: boolean) {
  if (refit) fitToState(c, true);
}

export function ctxModel(): NetModel | null {
  return ctx?.model ?? null;
}
