// Pohled na mapu: priblizeni, posun (mys, kolecko, stipnuti, klavesnice) a plynule prelety kamery.
// Pohled je (stred, meritko v px na jednotku) a viewBox vzdy presne odpovida prvku, takze nikde nevznikaji
// okraje. Prelety pouzivaji sdilene tokeny pohybu (--dur-page, --ease-soft) z tokens.css.
import { tokenMs } from "./motion";

export type Cam = { cx: number; cy: number; s: number };
export type Box = { x: number; y: number; w: number; h: number };

const DRAG_PX = 8;

export function netMapTools(): string {
  const icon = (d: string) =>
    `<svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true" focusable="false"><path d="${d}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
  return `<div class="map-tools" role="group" aria-label="Přiblížení mapy">
    <button type="button" class="map-btn" data-map="in" aria-label="Přiblížit">${icon("M12 5v14M5 12h14")}</button>
    <button type="button" class="map-btn" data-map="out" aria-label="Oddálit">${icon("M5 12h14")}</button>
    <button type="button" class="map-btn" data-map="fit" aria-label="Zobrazit vše">${icon("M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5")}</button>
    <button type="button" class="map-btn map-legend-btn" data-map="legend" aria-label="Legenda" aria-expanded="false" aria-controls="mapLegend">${icon("M12 11v6M12 7.5v.01M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z")}</button>
  </div>`;
}

function readEase(): (t: number) => number {
  const raw = getComputedStyle(document.documentElement).getPropertyValue("--ease-soft");
  const m = raw.match(/cubic-bezier\(([^)]+)\)/);
  const [x1, y1, x2, y2] = m ? m[1].split(",").map(Number) : [0.3, 0.7, 0.2, 1];
  const cx = 3 * x1;
  const bx = 3 * (x2 - x1) - cx;
  const ax = 1 - cx - bx;
  const cy = 3 * y1;
  const by = 3 * (y2 - y1) - cy;
  const ay = 1 - cy - by;
  const X = (t: number) => ((ax * t + bx) * t + cx) * t;
  const Y = (t: number) => ((ay * t + by) * t + cy) * t;
  return (x) => {
    let lo = 0;
    let hi = 1;
    let t = x;
    for (let i = 0; i < 20; i += 1) {
      t = (lo + hi) / 2;
      if (X(t) < x) lo = t;
      else hi = t;
    }
    return Y(t);
  };
}

export type MapViewOptions = {
  bounds: Box;
  /** uzivatel priblizuje; controller muze zonu rozbalit */
  onUserZoom?: (cam: Cam, fit: number, client: { x: number; y: number }, world: { x: number; y: number }, factor: number) => void;
  /** dvojklik/dvojtap na prazdne plose; vraci true, kdyz ho controller zpracoval */
  onBackgroundDouble?: () => boolean;
  /** po zmene meritka (prahy popisku) */
  onScale?: (s: number) => void;
  /** kamera se zmenila (ulozeni pohledu pres prekresleni) */
  onCam?: (cam: Cam) => void;
};

export type MapView = {
  cam: () => Cam;
  fitScale: () => number;
  animateTo: (cam: Cam, instant?: boolean) => void;
  fitBox: (box: Box, pad?: number, instant?: boolean, maxS?: number) => void;
  fitAll: (instant?: boolean) => void;
  zoomBy: (factor: number, client?: { x: number; y: number }) => void;
  /** po dobu ms ignoruje zoom koleckem (probiha prelet kamery) */
  lock: (ms: number) => void;
  refreshNav: (isActive: (el: SVGGElement) => boolean, prefer?: Element | null) => void;
  destroy: () => void;
};

/** Nejmensi polomer bubliny zarizeni na obrazovce (px). Pod tim by ikona v bublině nebyla citelna. */
const MIN_NODE_PX = 7;

export function bindMapView(host: HTMLElement, svg: SVGSVGElement, opts: MapViewOptions, start?: Cam | null): MapView {
  const { bounds } = opts;
  const bx = bounds.x;
  const by = bounds.y;
  const bw = bounds.w;
  const bh = bounds.h;
  let rectW = 1;
  let rectH = 1;
  let cam: Cam = start ?? { cx: bx + bw / 2, cy: by + bh / 2, s: 1 };
  let anim = 0;
  let classes = "";
  let lockUntil = 0;
  let minNodeR = 0;
  const btn = (name: string) => host.querySelector<HTMLButtonElement>(`[data-map="${name}"]`);

  const measure = () => {
    const r = svg.getBoundingClientRect();
    rectW = r.width || 1;
    rectH = r.height || 1;
  };
  const fitScale = () => Math.min(rectW / bw, rectH / bh);
  const limits = () => {
    const fit = fitScale();
    return { min: fit * 0.8, max: Math.max(fit * 14, 5) };
  };
  const clamp = (c: Cam): Cam => {
    const { min, max } = limits();
    const s = Math.min(max, Math.max(min, c.s));
    return { s, cx: Math.min(bx + bw, Math.max(bx, c.cx)), cy: Math.min(by + bh, Math.max(by, c.cy)) };
  };

  const apply = () => {
    const w = rectW / cam.s;
    const h = rectH / cam.s;
    svg.setAttribute("viewBox", `${(cam.cx - w / 2).toFixed(2)} ${(cam.cy - h / 2).toFixed(2)} ${w.toFixed(2)} ${h.toFixed(2)}`);
    svg.style.setProperty("--u", Math.min(1 / cam.s, 3.2).toFixed(4));
    svg.style.setProperty("--um", Math.min(1 / cam.s, 2.2).toFixed(4));
    // Nejmensi bublina musi mit na obrazovce aspon MIN_NODE_PX polomeru, aby v ni byla ikona.
    // Skaluje se jen vnitrek uzlu (.nk), ne .nb (ten nese prechody sbaleni a vypnuti).
    if (!minNodeR) {
      const radii = [...svg.querySelectorAll<SVGGElement>(".nb")].map((g) => Number(g.dataset.r)).filter(Number.isFinite);
      if (radii.length) minNodeR = Math.min(...radii);
    }
    const nk = minNodeR ? Math.min(6, Math.max(1, MIN_NODE_PX / (minNodeR * cam.s))) : 1;
    svg.style.setProperty("--nk", nk.toFixed(3));
    const next = [cam.s >= 0.95 ? "show-icons" : "", cam.s >= 1.9 ? "show-labels" : "", cam.s < 0.55 ? "is-far" : ""].filter(Boolean).join(" ");
    if (next !== classes) {
      for (const c of ["show-icons", "show-labels", "is-far"]) svg.classList.toggle(c, next.includes(c));
      classes = next;
    }
    const fit = fitScale();
    const zin = btn("in");
    const zout = btn("out");
    const fitBtn = btn("fit");
    const { min, max } = limits();
    if (zin) zin.disabled = cam.s >= max * 0.999;
    if (zout) zout.disabled = cam.s <= min * 1.001;
    if (fitBtn) fitBtn.disabled = false;
    opts.onScale?.(cam.s / (fit || 1));
    opts.onCam?.(cam);
  };

  const animateTo = (target: Cam, instant = false) => {
    cancelAnimationFrame(anim);
    const to = clamp(target);
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (instant || reduced) {
      cam = to;
      apply();
      return;
    }
    const from = { ...cam };
    const dur = tokenMs("--dur-page", 540) + 120;
    const ease = readEase();
    const t0 = performance.now();
    const step = (now: number) => {
      const k = Math.min(1, (now - t0) / dur);
      const e = ease(k);
      cam = { s: from.s * Math.pow(to.s / from.s, e), cx: from.cx + (to.cx - from.cx) * e, cy: from.cy + (to.cy - from.cy) * e };
      apply();
      if (k < 1) anim = requestAnimationFrame(step);
    };
    anim = requestAnimationFrame(step);
  };

  const fitBox = (box: Box, pad = 36, instant = false, maxS = Infinity) => {
    measure();
    const s = Math.min(rectW / (box.w + pad * 2), rectH / (box.h + pad * 2), maxS);
    animateTo({ cx: box.x + box.w / 2, cy: box.y + box.h / 2, s }, instant);
  };
  const fitAll = (instant = false) => fitBox(bounds, 0, instant);

  const toWorld = (clientX: number, clientY: number) => {
    const r = svg.getBoundingClientRect();
    return { x: cam.cx + (clientX - (r.left + r.width / 2)) / cam.s, y: cam.cy + (clientY - (r.top + r.height / 2)) / cam.s };
  };

  const zoomBy = (factor: number, client?: { x: number; y: number }) => {
    cancelAnimationFrame(anim);
    const r = svg.getBoundingClientRect();
    const px = (client?.x ?? r.left + r.width / 2) - (r.left + r.width / 2);
    const py = (client?.y ?? r.top + r.height / 2) - (r.top + r.height / 2);
    const { min, max } = limits();
    const s = Math.min(max, Math.max(min, cam.s * factor));
    if (s === cam.s) return;
    const ux = cam.cx + px / cam.s;
    const uy = cam.cy + py / cam.s;
    cam = clamp({ s, cx: ux - px / s, cy: uy - py / s });
    apply();
    if (factor !== 1) opts.onUserZoom?.(cam, fitScale(), { x: client?.x ?? r.left + r.width / 2, y: client?.y ?? r.top + r.height / 2 }, toWorld(client?.x ?? r.left + r.width / 2, client?.y ?? r.top + r.height / 2), factor);
  };
  const panBy = (dx: number, dy: number) => {
    cancelAnimationFrame(anim);
    cam = clamp({ ...cam, cx: cam.cx - dx / cam.s, cy: cam.cy - dy / cam.s });
    apply();
  };

  btn("in")?.addEventListener("click", () => zoomBy(1.6));
  btn("out")?.addEventListener("click", () => zoomBy(1 / 1.6));
  btn("legend")?.addEventListener("click", (event) => {
    const open = !host.classList.contains("legend-open");
    host.classList.toggle("legend-open", open);
    (event.currentTarget as HTMLElement).setAttribute("aria-expanded", String(open));
  });

  const controller = new AbortController();
  const on = <K extends keyof SVGElementEventMap>(type: K, fn: (e: SVGElementEventMap[K]) => void, o?: AddEventListenerOptions) =>
    svg.addEventListener(type, fn as EventListener, { signal: controller.signal, ...o });

  on("wheel", (event) => {
    event.preventDefault();
    if (performance.now() < lockUntil) return;
    zoomBy(Math.exp(-event.deltaY * (event.ctrlKey ? 0.01 : 0.0016)), { x: event.clientX, y: event.clientY });
  }, { passive: false });

  on("dblclick", (event) => {
    if ((event.target as Element).closest(".node, .zbub")) return;
    if (opts.onBackgroundDouble?.()) return;
    zoomBy(2, { x: event.clientX, y: event.clientY });
  });

  const pointers = new Map<number, { x: number; y: number }>();
  let travelled = 0;
  let pinch = 0;
  let lastTap = 0;
  on("pointerdown", (event) => {
    pointers.set(event.pointerId, { x: event.clientX, y: event.clientY });
    if (pointers.size === 1) travelled = 0;
    if (pointers.size === 2) {
      const [a, b] = [...pointers.values()];
      pinch = Math.hypot(a.x - b.x, a.y - b.y);
      travelled = DRAG_PX + 1;
    }
  });
  on("pointermove", (event) => {
    const prev = pointers.get(event.pointerId);
    if (!prev) return;
    const next = { x: event.clientX, y: event.clientY };
    pointers.set(event.pointerId, next);
    if (pointers.size === 1) {
      travelled += Math.abs(next.x - prev.x) + Math.abs(next.y - prev.y);
      if (travelled > DRAG_PX) {
        if (!svg.hasPointerCapture(event.pointerId)) svg.setPointerCapture(event.pointerId);
        svg.classList.add("is-dragging");
        panBy(next.x - prev.x, next.y - prev.y);
      }
    } else if (pointers.size === 2) {
      const [a, b] = [...pointers.values()];
      const dist = Math.hypot(a.x - b.x, a.y - b.y);
      if (pinch > 0) zoomBy(dist / pinch, { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 });
      pinch = dist;
    }
  });
  const release = (event: PointerEvent) => {
    const wasTap = pointers.size === 1 && travelled <= DRAG_PX;
    pointers.delete(event.pointerId);
    if (pointers.size < 2) pinch = 0;
    if (pointers.size === 0) window.setTimeout(() => svg.classList.remove("is-dragging"), 0);
    if (event.type === "pointerup" && event.pointerType === "touch" && wasTap && !(event.target as Element).closest(".node, .zbub")) {
      if (event.timeStamp - lastTap < 320) {
        if (!opts.onBackgroundDouble?.()) zoomBy(2, { x: event.clientX, y: event.clientY });
      }
      lastTap = event.timeStamp;
    }
  };
  on("pointerup", release);
  on("pointercancel", release);
  on("click", (event) => {
    if (travelled > DRAG_PX) {
      event.stopPropagation();
      event.preventDefault();
      travelled = 0;
    }
  }, { capture: true });

  host.addEventListener(
    "keydown",
    (event) => {
      const key = event.key;
      if ((event.target as Element).closest("input, select, textarea")) return;
      if (key === "+" || key === "=") zoomBy(1.4);
      else if (key === "-" || key === "_") zoomBy(1 / 1.4);
      else if (key === "0") fitAll();
      else if (key.startsWith("Arrow")) {
        const current = (event.target as Element).closest<SVGGElement>(".node, .zbub");
        if (!current) return;
        nearestNav(svg, current, key)?.focus();
      } else return;
      event.preventDefault();
    },
    { signal: controller.signal },
  );

  on("focusin", (event) => {
    const el = (event.target as Element).closest<SVGGElement>(".node, .zbub");
    if (!el) return;
    setEntry(el);
    const rect = svg.getBoundingClientRect();
    const box = el.getBoundingClientRect();
    const m = 28;
    if (box.left < rect.left + m || box.right > rect.right - m || box.top < rect.top + m || box.bottom > rect.bottom - m) {
      const world = { x: Number(el.dataset.x), y: Number(el.dataset.y) };
      if (Number.isFinite(world.x)) animateTo({ ...cam, cx: world.x, cy: world.y });
    }
  });

  const navItems = () => [...svg.querySelectorAll<SVGGElement>(".node, .zbub")];
  const setEntry = (target: Element | null | undefined) => {
    for (const n of navItems()) n.setAttribute("tabindex", n === target ? "0" : "-1");
  };
  const refreshNav = (isActive: (el: SVGGElement) => boolean, prefer?: Element | null) => {
    const all = navItems();
    for (const n of all) n.toggleAttribute("data-fx", isActive(n));
    const active = all.filter((n) => n.hasAttribute("data-fx"));
    const entry = (prefer && active.includes(prefer as SVGGElement) ? prefer : null) ?? active.find((n) => n.classList.contains("is-selected")) ?? active.find((n) => /Riziko vysoké|nejhorší závažnost vysoké/.test(n.getAttribute("aria-label") ?? "")) ?? active[0];
    setEntry(entry);
  };

  const ro = new ResizeObserver(() => {
    const keepFit = Math.abs(cam.s / (fitScale() || 1) - 1) < 0.001;
    measure();
    if (keepFit) cam = { ...cam, s: fitScale() };
    apply();
  });
  ro.observe(svg);
  measure();
  if (!start) cam = { cx: bx + bw / 2, cy: by + bh / 2, s: fitScale() };
  else cam = clamp(cam);
  apply();

  return {
    cam: () => ({ ...cam }),
    fitScale,
    animateTo,
    fitBox,
    fitAll,
    zoomBy,
    lock: (ms) => {
      lockUntil = performance.now() + ms;
    },
    refreshNav,
    destroy: () => {
      cancelAnimationFrame(anim);
      ro.disconnect();
      controller.abort();
    },
  };
}

function nearestNav(svg: SVGSVGElement, from: SVGGElement, key: string): SVGGElement | null {
  const a = from.getBoundingClientRect();
  const ax = a.left + a.width / 2;
  const ay = a.top + a.height / 2;
  let best: SVGGElement | null = null;
  let bestScore = Infinity;
  for (const node of svg.querySelectorAll<SVGGElement>("[data-fx]")) {
    if (node === from) continue;
    const b = node.getBoundingClientRect();
    const dx = b.left + b.width / 2 - ax;
    const dy = b.top + b.height / 2 - ay;
    const along = key === "ArrowRight" ? dx : key === "ArrowLeft" ? -dx : key === "ArrowDown" ? dy : -dy;
    if (along <= 1) continue;
    const across = key === "ArrowRight" || key === "ArrowLeft" ? Math.abs(dy) : Math.abs(dx);
    const score = along + across * 2;
    if (score < bestScore) {
      bestScore = score;
      best = node;
    }
  }
  return best;
}
