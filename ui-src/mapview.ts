// Priblizeni a posun mapy site: kolecko, stipnuti, tazeni, dvojklik / dvojtap, tlacitka a klavesnice.
// Stav pohledu preziva prekresleni (vyber stanice prekresluje celou plochu).
const view = { run: "", k: 1, cx: 0, cy: 0, touched: false };
const K_MAX = 10;
const DRAG_PX = 8;

/** Posune pohled na souřadnice stanice (jen když je mapa přiblížená; celá mapa je vidět celá). */
export function centerMapOn(x: number, y: number): void {
  if (view.k <= 1 || !Number.isFinite(x) || !Number.isFinite(y)) return;
  view.cx = x;
  view.cy = y;
  view.touched = true;
}

export function netMapTools(): string {
  const icon = (d: string) =>
    `<svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true" focusable="false"><path d="${d}" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
  return `<div class="map-tools" role="group" aria-label="Přiblížení mapy">
    <button type="button" class="map-btn" data-map="in" aria-label="Přiblížit">${icon("M12 5v14M5 12h14")}</button>
    <button type="button" class="map-btn" data-map="out" aria-label="Oddálit">${icon("M5 12h14")}</button>
    <button type="button" class="map-btn" data-map="fit" aria-label="Celá mapa">${icon("M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5")}</button>
    <button type="button" class="map-btn map-legend-btn" data-map="legend" aria-label="Legenda" aria-expanded="false" aria-controls="mapLegend">${icon("M12 11v6M12 7.5v.01M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z")}</button>
  </div>`;
}

/** Napoji ovladani na prave vykreslenou mapu (volat po kazdem vykresleni). */
export function bindNetMap(host: HTMLElement): void {
  const svg = host.querySelector<SVGSVGElement>("svg.netmap");
  if (!svg || !svg.dataset.vb) return;
  const [bx, by, bw, bh] = svg.dataset.vb.split(" ").map(Number);
  const baseCx = bx + bw / 2;
  const baseCy = by + bh / 2;
  const run = svg.dataset.run ?? "";
  if (view.run !== run) Object.assign(view, { run, k: 1, cx: baseCx, cy: baseCy, touched: false });

  // jedno tabulatorove zastaveni na mape: vybrana stanice, jinak prvni vysoke riziko, jinak prvni.
  // Mezi stanicemi se chodi sipkami (viz nize), takze Tab neprojde 90 bublin.
  const nodes = [...svg.querySelectorAll<SVGGElement>(".node")];
  const entry = nodes.find((n) => n.classList.contains("is-selected")) ?? nodes.find((n) => /Riziko vysoké/.test(n.getAttribute("aria-label") ?? "")) ?? nodes[0];
  const setEntry = (target: SVGGElement | undefined) => nodes.forEach((n) => n.setAttribute("tabindex", n === target ? "0" : "-1"));
  setEntry(entry);
  const labels = [...svg.querySelectorAll<SVGTextElement>(".node-ip")];
  const hits = [...svg.querySelectorAll<SVGCircleElement>(".node .hit")];
  const hitBase = hits.map((c) => Number(c.getAttribute("r")));
  const btn = (name: string) => host.querySelector<HTMLButtonElement>(`[data-map="${name}"]`);

  const scale = () => {
    const rect = svg.getBoundingClientRect();
    return Math.min(rect.width / (bw / view.k), rect.height / (bh / view.k)) || 1;
  };

  const apply = () => {
    view.k = Math.min(K_MAX, Math.max(1, view.k));
    view.cx = Math.min(bx + bw, Math.max(bx, view.cx));
    view.cy = Math.min(by + bh, Math.max(by, view.cy));
    const w = bw / view.k;
    const h = bh / view.k;
    svg.setAttribute("viewBox", `${(view.cx - w / 2).toFixed(2)} ${(view.cy - h / 2).toFixed(2)} ${w.toFixed(2)} ${h.toFixed(2)}`);
    const s = scale();
    // pismo drzime kolem konstantni velikosti na obrazovce, ale pri velkem oddaleni nesmi zahltit mapu
    svg.style.setProperty("--u", Math.min(1 / s, 3.2).toFixed(4));
    svg.style.setProperty("--um", Math.min(1 / s, 2.2).toFixed(4));
    svg.classList.toggle("is-far", s < 0.7);
    // popisek stanice se ukaze, az se do bubliny vejde
    for (const label of labels) label.style.display = label.dataset.sel || s >= Number(label.dataset.need) ? "" : "none";
    // dotykova plocha roste s priblizenim, ale nepresahne rozestup stanic
    hits.forEach((c, i) => c.setAttribute("r", Math.max(hitBase[i] - 2, Math.min(18, 22 / s)).toFixed(1)));
    const zoomIn = btn("in");
    const zoomOut = btn("out");
    const fit = btn("fit");
    if (zoomIn) zoomIn.disabled = view.k >= K_MAX;
    if (zoomOut) zoomOut.disabled = view.k <= 1;
    if (fit) fit.disabled = view.k <= 1 && !view.touched;
  };

  const zoomAt = (factor: number, clientX?: number, clientY?: number) => {
    const rect = svg.getBoundingClientRect();
    const px = (clientX ?? rect.left + rect.width / 2) - (rect.left + rect.width / 2);
    const py = (clientY ?? rect.top + rect.height / 2) - (rect.top + rect.height / 2);
    const before = scale();
    const k = Math.min(K_MAX, Math.max(1, view.k * factor));
    if (k === view.k) return;
    const ux = view.cx + px / before;
    const uy = view.cy + py / before;
    view.k = k;
    const after = scale();
    view.cx = ux - px / after;
    view.cy = uy - py / after;
    view.touched = true;
    apply();
  };
  const panBy = (dxPx: number, dyPx: number) => {
    const s = scale();
    view.cx -= dxPx / s;
    view.cy -= dyPx / s;
    view.touched = true;
    apply();
  };
  const reset = () => {
    Object.assign(view, { k: 1, cx: baseCx, cy: baseCy, touched: false });
    apply();
  };

  btn("in")?.addEventListener("click", () => zoomAt(1.6));
  btn("out")?.addEventListener("click", () => zoomAt(1 / 1.6));
  btn("fit")?.addEventListener("click", reset);
  btn("legend")?.addEventListener("click", (event) => {
    const open = !host.classList.contains("legend-open");
    host.classList.toggle("legend-open", open);
    (event.currentTarget as HTMLElement).setAttribute("aria-expanded", String(open));
  });

  svg.addEventListener(
    "wheel",
    (event) => {
      event.preventDefault();
      zoomAt(Math.exp(-event.deltaY * (event.ctrlKey ? 0.01 : 0.0016)), event.clientX, event.clientY);
    },
    { passive: false },
  );
  svg.addEventListener("dblclick", (event) => {
    if (!(event.target as Element).closest(".node")) zoomAt(2, event.clientX, event.clientY);
  });

  // jeden prst nebo mys = posun, dva prsty = stipnuti
  const pointers = new Map<number, { x: number; y: number }>();
  let travelled = 0;
  let pinch = 0;
  let lastTap = 0;
  svg.addEventListener("pointerdown", (event) => {
    pointers.set(event.pointerId, { x: event.clientX, y: event.clientY });
    if (pointers.size === 1) travelled = 0;
    if (pointers.size === 2) {
      const [a, b] = [...pointers.values()];
      pinch = Math.hypot(a.x - b.x, a.y - b.y);
      travelled = DRAG_PX + 1;
    }
  });
  svg.addEventListener("pointermove", (event) => {
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
      if (pinch > 0) zoomAt(dist / pinch, (a.x + b.x) / 2, (a.y + b.y) / 2);
      pinch = dist;
    }
  });
  const release = (event: PointerEvent) => {
    const wasTap = pointers.size === 1 && travelled <= DRAG_PX;
    pointers.delete(event.pointerId);
    if (pointers.size < 2) pinch = 0;
    if (pointers.size === 0) window.setTimeout(() => svg.classList.remove("is-dragging"), 0);
    if (event.type === "pointerup" && event.pointerType === "touch" && wasTap && !(event.target as Element).closest(".node")) {
      if (event.timeStamp - lastTap < 320) zoomAt(2, event.clientX, event.clientY);
      lastTap = event.timeStamp;
    }
  };
  svg.addEventListener("pointerup", release);
  svg.addEventListener("pointercancel", release);
  // po tazeni se nema vybrat stanice pod prstem
  svg.addEventListener(
    "click",
    (event) => {
      if (travelled > DRAG_PX) {
        event.stopPropagation();
        event.preventDefault();
        travelled = 0;
      }
    },
    true,
  );

  // klavesnice: +/- priblizeni, 0 cela mapa, sipky skoci na nejblizsi stanici ve smeru
  host.addEventListener("keydown", (event) => {
    const key = event.key;
    if (key === "+" || key === "=") zoomAt(1.4);
    else if (key === "-" || key === "_") zoomAt(1 / 1.4);
    else if (key === "0") reset();
    else if (key.startsWith("Arrow")) {
      const current = (event.target as Element).closest<SVGGElement>(".node");
      if (!current) return;
      nearestNode(svg, current, key)?.focus();
    } else return;
    event.preventDefault();
  });

  // fokus na stanici mimo vyrez posune pohled
  svg.addEventListener("focusin", (event) => {
    const node = (event.target as Element).closest<SVGGElement>(".node");
    if (!node) return;
    setEntry(node);
    const rect = svg.getBoundingClientRect();
    const box = node.getBoundingClientRect();
    const m = 24;
    if (box.left < rect.left + m || box.right > rect.right - m || box.top < rect.top + m || box.bottom > rect.bottom - m) {
      view.cx = Number(node.dataset.x);
      view.cy = Number(node.dataset.y);
      view.touched = true;
      apply();
    }
  });

  apply();
  new ResizeObserver(apply).observe(svg);
}

function nearestNode(svg: SVGSVGElement, from: SVGGElement, key: string): SVGGElement | null {
  const a = from.getBoundingClientRect();
  const ax = a.left + a.width / 2;
  const ay = a.top + a.height / 2;
  let best: SVGGElement | null = null;
  let bestScore = Infinity;
  for (const node of svg.querySelectorAll<SVGGElement>(".node")) {
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
