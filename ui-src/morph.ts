// Klicove (podle ID) aktualizace DOM: z noveho HTML se do existujici plochy prenesou jen skutecne zmeny.
// Prvky se shodnymi klici zustavaji v DOM, takze se neresetuje scroll, fokus, rozepsany text ani stav
// <details>. SVG a mapa se berou jako nedelitelne celky (porovnaji se a pripadne vymeni).

const KEY_ATTRS = ["data-host", "data-key", "data-plan", "data-svc", "data-finding", "data-i"];

function keyOf(el: Element): string | null {
  if (el.id) return `#${el.id}`;
  for (const a of KEY_ATTRS) {
    const v = el.getAttribute(a);
    if (v !== null) return `${el.tagName}|${el.getAttribute("data-action") ?? ""}|${a}=${v}`;
  }
  return null;
}

function isAtomic(el: Element): boolean {
  return el.tagName.toLowerCase() === "svg" || el.classList.contains("map-frame");
}

// tridy, ktere pridava JS po vykresleni (bublina prepinace, vlna); morph je nesmi smazat
const RUNTIME_CLASSES = ["has-bubble", "rip"];

function syncAttributes(o: Element, n: Element) {
  for (const attr of Array.from(o.attributes)) {
    if (!n.hasAttribute(attr.name)) o.removeAttribute(attr.name);
  }
  for (const attr of Array.from(n.attributes)) {
    let value = attr.value;
    if (attr.name === "class") {
      const keep = RUNTIME_CLASSES.filter((c) => o.classList.contains(c) && !n.classList.contains(c));
      if (keep.length) value = `${value} ${keep.join(" ")}`;
    }
    if (o.getAttribute(attr.name) !== value) o.setAttribute(attr.name, value);
  }
  if (o instanceof HTMLInputElement && n instanceof HTMLInputElement && document.activeElement !== o) {
    if (o.value !== n.value) o.value = n.value;
    if (o.checked !== n.checked) o.checked = n.checked;
  }
  if (o instanceof HTMLTextAreaElement && n instanceof HTMLTextAreaElement && document.activeElement !== o && o.value !== n.value) o.value = n.value;
  if (o instanceof HTMLSelectElement && n instanceof HTMLSelectElement && document.activeElement !== o && o.value !== n.value) o.value = n.value;
}

export type MorphResult = { replacedAtomic: boolean; changed: number };

function morphNode(o: Node, n: Node, res: MorphResult): Node {
  if (o.nodeType === Node.TEXT_NODE || o.nodeType === Node.COMMENT_NODE) {
    if (o.nodeValue !== n.nodeValue) {
      o.nodeValue = n.nodeValue;
      res.changed += 1;
    }
    return o;
  }
  const oe = o as Element;
  const ne = n as Element;
  if (isAtomic(ne)) {
    if (oe.outerHTML !== ne.outerHTML) {
      const fresh = document.importNode(ne, true);
      oe.replaceWith(fresh);
      res.replacedAtomic = true;
      res.changed += 1;
      return fresh;
    }
    return oe;
  }
  const before = oe.attributes.length;
  syncAttributes(oe, ne);
  void before;
  morphChildren(oe, ne, res);
  return oe;
}

function morphChildren(op: Element, np: Element, res: MorphResult) {
  const oldKeyed = new Map<string, Element>();
  for (const c of Array.from(op.children)) {
    const k = keyOf(c);
    if (k && !oldKeyed.has(k)) oldKeyed.set(k, c);
  }
  const used = new Set<Node>();
  let cursor: Node | null = op.firstChild;
  const skipUsed = () => {
    while (cursor && used.has(cursor)) cursor = cursor.nextSibling;
  };
  for (const nc of Array.from(np.childNodes)) {
    let match: Node | null = null;
    if (nc.nodeType === Node.ELEMENT_NODE) {
      const k = keyOf(nc as Element);
      if (k) {
        const found = oldKeyed.get(k);
        if (found && !used.has(found)) match = found;
      } else {
        skipUsed();
        // bezklicovy prvek: jen dalsi bezklicovy sourozenec stejneho tagu
        let probe: Node | null = cursor;
        while (probe && (used.has(probe) || (probe.nodeType === Node.ELEMENT_NODE && keyOf(probe as Element)))) probe = probe.nextSibling;
        if (probe && probe.nodeType === Node.ELEMENT_NODE && (probe as Element).tagName === (nc as Element).tagName) match = probe;
      }
    } else {
      skipUsed();
      let probe: Node | null = cursor;
      while (probe && (used.has(probe) || probe.nodeType === Node.ELEMENT_NODE)) probe = probe.nextSibling;
      if (probe && probe.nodeType === nc.nodeType) match = probe;
    }
    if (match) {
      skipUsed();
      const wasCursor = match === cursor;
      const live = morphNode(match, nc, res);
      if (wasCursor) cursor = live.nextSibling;
      else {
        skipUsed();
        op.insertBefore(live, cursor);
      }
      used.add(live);
    } else {
      const fresh = document.importNode(nc, true);
      skipUsed();
      op.insertBefore(fresh, cursor);
      used.add(fresh);
      res.changed += 1;
      if (fresh instanceof Element && isAtomic(fresh)) res.replacedAtomic = true;
    }
  }
  for (const c of Array.from(op.childNodes)) {
    if (!used.has(c) && !(c instanceof Element && (c.classList.contains("stage-ghost") || c.classList.contains("seg-bubble")))) {
      c.remove();
      res.changed += 1;
    }
  }
}

/** Prevede obsah `root` na `html`, zmeni jen to, co se opravdu lisi. */
export function morphInto(root: HTMLElement, html: string): MorphResult {
  const tpl = document.createElement("template");
  tpl.innerHTML = html;
  const shell = document.createElement("div");
  shell.appendChild(tpl.content);
  const res: MorphResult = { replacedAtomic: false, changed: 0 };
  morphChildren(root, shell, res);
  return res;
}
