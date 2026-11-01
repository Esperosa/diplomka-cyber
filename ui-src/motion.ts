// Pohyb ovladacich prvku: vlna od mista kliknuti a prelevajici se bublina segmentovych prepinacu.
// Vsechny casy a krivky se ctou ze sdilenych tokenu (tokens.css), ne z konstant tady.

const RIPPLE_SELECTOR = ".btn, .seg, .map-btn, .menu-item, .row";

function reducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/** Cte trvani tokenu (--dur-slow ...) v ms. */
export function tokenMs(name: string, fallback: number): number {
  const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const n = parseFloat(raw);
  if (Number.isNaN(n)) return fallback;
  return raw.endsWith("ms") ? n : n * 1000;
}

function signature(el: Element): string {
  const d = (el as HTMLElement).dataset;
  return JSON.stringify([el.tagName, d.action ?? "", d.key ?? d.host ?? d.plan ?? "", el.id, (el.textContent ?? "").trim().slice(0, 24)]);
}

function fire(el: HTMLElement, rx: number, ry: number) {
  if (reducedMotion() || !el.isConnected) return;
  el.style.setProperty("--rx", `${rx.toFixed(0)}px`);
  el.style.setProperty("--ry", `${ry.toFixed(0)}px`);
  el.classList.remove("rip");
  void el.offsetWidth;
  el.classList.add("rip");
  const done = () => el.classList.remove("rip");
  el.addEventListener("animationend", done, { once: true });
  window.setTimeout(done, tokenMs("--dur-page", 540) + 80);
}

type Pending = { sig: string; rx: number; ry: number; at: number; el: HTMLElement; consumed: boolean };
let pending: Pending | null = null;

/** Vlna vychazi z mista kliknuti. Prvky, ktere se po kliknuti prekresli (radky, filtry), ji dostanou az po prekresleni. */
export function initRipple(app: HTMLElement, stage: () => HTMLElement) {
  app.addEventListener(
    "pointerdown",
    (event) => {
      const el = (event.target as HTMLElement).closest<HTMLElement>(RIPPLE_SELECTOR);
      if (!el || (el as HTMLButtonElement).disabled) return;
      const rect = el.getBoundingClientRect();
      const p: Pending = { sig: signature(el), rx: event.clientX - rect.left, ry: event.clientY - rect.top, at: performance.now(), el, consumed: false };
      pending = p;
      if (!stage().contains(el)) {
        p.consumed = true;
        fire(el, p.rx, p.ry);
        return;
      }
      // pokud se plocha po kliknuti neprekresli, vlna se spusti na puvodnim prvku
      window.setTimeout(() => {
        if (!p.consumed) {
          p.consumed = true;
          fire(p.el, p.rx, p.ry);
        }
      }, 160);
    },
    true,
  );
}

/** Volat po prekresleni plochy: prvek stejne identity dostane vlnu a segmenty animuji bublinu. */
export function afterStageRender(stage: HTMLElement, section: string) {
  if (pending && !pending.consumed && performance.now() - pending.at < 700) {
    pending.consumed = true;
    const sig = pending.sig;
    for (const el of stage.querySelectorAll<HTMLElement>(RIPPLE_SELECTOR)) {
      if (signature(el) === sig) {
        fire(el, pending.rx, pending.ry);
        break;
      }
    }
  }
  enhanceSegments(stage, section);
}

const previous = new Map<string, { l: number; w: number }>();

/** Aktivni volba segmentoveho prepinace je jedna "bublina", ktera se tekute prelevá a pri pohybu se mirne stlaci. */
function enhanceSegments(stage: HTMLElement, section: string) {
  stage.querySelectorAll<HTMLElement>(".segmented").forEach((group, index) => {
    const on = group.querySelector<HTMLElement>(".seg.is-on");
    if (!on) return;
    const key = `${section}:${index}`;
    const l = on.offsetLeft;
    const w = on.offsetWidth;
    let bubble = group.querySelector<HTMLElement>(":scope > .seg-bubble");
    if (!bubble) {
      bubble = document.createElement("span");
      bubble.className = "seg-bubble";
      bubble.setAttribute("aria-hidden", "true");
      group.prepend(bubble);
    }
    bubble.style.cssText = `left:${l}px;top:${on.offsetTop}px;width:${w}px;height:${on.offsetHeight}px`;
    group.classList.add("has-bubble");
    const before = previous.get(key);
    previous.set(key, { l, w });
    if (!before || (before.l === l && before.w === w) || reducedMotion()) return;
    const dx = before.l - l;
    const sx = before.w / w;
    bubble.animate(
      [
        { transform: `translateX(${dx}px) scale(${sx}, 1)` },
        { transform: `translateX(${dx * 0.42}px) scale(${((sx + 1) / 2) * 1.14}, 0.88)`, offset: 0.45 },
        { transform: "translateX(0) scale(1, 1)" },
      ],
      { duration: tokenMs("--dur-slow", 440) + 60, easing: "cubic-bezier(0.3, 0.7, 0.2, 1)" },
    );
  });
}
