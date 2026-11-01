// Vlastni pismo z teček: kazdy znak je KOSTRA z malo uzlu (kruhu) spojenych metaball mosty (goo hrdla).
// B ma 8 uzlu, H 6, I 2. Zadne pismo z cizich zdroju, zadny raster ani rasterovy filtr: znak je kruhy
// a jedna cesta (path) s kulatymi konci a zaoblenymi rohy, barva z currentColor. Pri kazdem zvetseni,
// scrollu a zmene velikosti je stejny. Mrizka znaku: 4 x 6 jednotek.

import { metaballBridge } from "./metaball";
import type { P } from "./pebbles";

type Pt = [number, number];
/** Tah: body kostry; "z" na konci uzavre tah do smycky. */
type Stroke = Array<Pt | "z">;
type Glyph = { strokes: Stroke[]; extra?: Pt[] };

const g = (...strokes: Stroke[]): Glyph => ({ strokes });
const turn = (glyph: Glyph): Glyph => ({
  strokes: glyph.strokes.map((s) => s.map((p) => (p === "z" ? p : ([4 - p[0], 6 - p[1]] as Pt)))),
  extra: glyph.extra?.map((p) => [4 - p[0], 6 - p[1]] as Pt),
});

const O: Stroke = [[1, 0], [3, 0], [4, 1], [4, 5], [3, 6], [1, 6], [0, 5], [0, 1], "z"];
const P: Stroke = [[0, 6], [0, 0], [2.6, 0], [4, 1.5], [2.6, 3], [0, 3]];
const SIX = g([[0, 3.8], [1, 2.8], [3, 2.8], [4, 3.8], [4, 5], [3, 6], [1, 6], [0, 5], "z"], [[3.4, 0], [1.4, 0.4], [0, 3], [0, 5]]);

const GLYPHS: Record<string, Glyph> = {
  "0": g([[1.2, 0], [2.8, 0], [3.6, 1], [3.6, 5], [2.8, 6], [1.2, 6], [0.4, 5], [0.4, 1], "z"]),
  "1": g([[0.8, 1.4], [2, 0], [2, 6]]),
  "2": g([[0, 1.2], [1.2, 0], [2.8, 0], [4, 1.2], [0, 6], [4, 6]]),
  "3": g([[0, 0], [4, 0], [2, 2.8], [3.2, 3.2], [4, 4.6], [3, 6], [0, 6]]),
  "4": g([[3, 6], [3, 0], [0, 4], [4, 4]]),
  "5": g([[4, 0], [0, 0], [0, 2.8], [3, 2.6], [4, 4.2], [3, 6], [0, 6]]),
  "6": SIX,
  "7": g([[0, 0], [4, 0], [1.6, 6]]),
  "8": g([[1, 0], [3, 0], [4, 1], [3, 2.9], [1, 2.9], [0, 1], "z"], [[1, 2.9], [3, 2.9], [4, 4.4], [3, 6], [1, 6], [0, 4.4], "z"]),
  "9": turn(SIX),
  A: g([[0, 6], [2, 0], [4, 6]], [[0.67, 4], [3.33, 4]]),
  B: g([[0, 6], [0, 0], [2.6, 0], [4.2, 1.5], [2.6, 3], [0, 3]], [[2.6, 3], [4.6, 4.5], [2.6, 6], [0, 6]]),
  C: g([[4, 1], [3, 0], [1, 0], [0, 1], [0, 5], [1, 6], [3, 6], [4, 5]]),
  D: g([[0, 0], [0, 6], [2, 6], [4, 4.5], [4, 1.5], [2, 0], "z"]),
  E: g([[4, 0], [0, 0], [0, 3], [0, 6], [4, 6]], [[0, 3], [3, 3]]),
  F: g([[4, 0], [0, 0], [0, 3], [0, 6]], [[0, 3], [3, 3]]),
  G: g([[4, 1], [3, 0], [1, 0], [0, 1], [0, 5], [1, 6], [3, 6], [4, 5], [4, 3], [2.2, 3]]),
  H: g([[0, 0], [0, 3], [0, 6]], [[4, 0], [4, 3], [4, 6]], [[0, 3], [4, 3]]),
  I: g([[2, 0], [2, 6]]),
  J: g([[4, 0], [4, 5], [3, 6], [1, 6], [0, 5]]),
  K: g([[0, 0], [0, 3], [0, 6]], [[4, 0], [0, 3], [4, 6]]),
  L: g([[0, 0], [0, 6], [4, 6]]),
  M: g([[0, 6], [0, 0], [2, 3], [4, 0], [4, 6]]),
  N: g([[0, 6], [0, 0], [4, 6], [4, 0]]),
  O: g(O),
  P: g(P),
  Q: g(O, [[2.6, 4.4], [4, 6]]),
  R: g(P, [[1.8, 3], [4, 6]]),
  S: g([[4, 1], [3, 0], [1, 0], [0, 1.2], [1, 3], [3, 3], [4, 4.8], [3, 6], [1, 6], [0, 5]]),
  T: g([[0, 0], [2, 0], [4, 0]], [[2, 0], [2, 6]]),
  U: g([[0, 0], [0, 5], [1, 6], [3, 6], [4, 5], [4, 0]]),
  V: g([[0, 0], [2, 6], [4, 0]]),
  W: g([[0, 0], [1, 6], [2, 2.5], [3, 6], [4, 0]]),
  X: g([[0, 0], [2, 3], [4, 6]], [[4, 0], [2, 3], [0, 6]]),
  Y: g([[0, 0], [2, 3], [4, 0]], [[2, 3], [2, 6]]),
  Z: g([[0, 0], [4, 0], [0, 6], [4, 6]]),
  ".": { strokes: [], extra: [[2, 5.6]] },
  ":": { strokes: [], extra: [[2, 1.9], [2, 5.1]] },
  "-": g([[0.6, 3], [3.4, 3]]),
  "%": { strokes: [[[0, 6], [4, 0]]], extra: [[0.8, 1], [3.2, 5]] },
  "/": g([[0.6, 6], [3.4, 0]]),
  "+": g([[0, 3], [2, 3], [4, 3]], [[2, 1], [2, 3], [2, 5]]),
  "?": { strokes: [[[0, 1], [1, 0], [3, 0], [4, 1], [2, 3], [2, 4]]], extra: [[2, 5.7]] },
  "!": { strokes: [[[2, 0], [2, 3.8]]], extra: [[2, 5.7]] },
  " ": g(),
};

export function normalizeForMatrix(text: string): string {
  return text
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .toUpperCase()
    .replace(/[^0-9A-Z.:%/+!? -]/g, "?");
}

export type DotOptions = {
  /** Ponechano pro zpetnou kompatibilitu volani; kostra nema "zhasnute" body. */
  offDots?: boolean;
};

const ADVANCE = 6;
const BEAD = 0.66; // polomer uzlu
const NECK = 0.78; // sirka krcku mostu (cca 0,6 prumeru uzlu)

const f = (v: number) => +v.toFixed(2);
const circle = (x: number, y: number, r: number) => `M${f(x + r)} ${f(y)}A${r} ${r} 0 1 1 ${f(x - r)} ${f(y)}A${r} ${r} 0 1 1 ${f(x + r)} ${f(y)}Z`;

/** Pocet uzlu znaku (pro kontrolu a testy): jedinecne body vsech tahu plus samostatne tecky. */
export function glyphNodeCount(char: string): number {
  const glyph = GLYPHS[char];
  if (!glyph) return 0;
  const set = new Set<string>();
  for (const s of glyph.strokes) for (const p of s) if (p !== "z") set.add(`${p[0]},${p[1]}`);
  for (const p of glyph.extra ?? []) set.add(`${p[0]},${p[1]}`);
  return set.size;
}

/**
 * Vraci SVG retezec. Velikost se ridi CSS (vyska prvku), ne atributy. Hodnota je v aria-label.
 * Znak = uzly kostry (kruhy) spojene metaball mosty (sdilena funkce metaballBridge): konkavni krcek,
 * Bezierovy krivky navazujici G1 na oblouky kruznic. Vse je JEDEN souvisly path bez cary mezi body.
 */
export function dotMatrix(text: string, _options: DotOptions = {}): string {
  const chars = [...normalizeForMatrix(String(text))];
  const pad = BEAD + 0.2;
  const cols = Math.max(1, chars.length * ADVANCE - (ADVANCE - 4));
  let d = "";
  chars.forEach((char, index) => {
    const glyph = GLYPHS[char] ?? GLYPHS["?"];
    const dx = index * ADVANCE;
    const nodes = new Map<string, P>();
    const edges = new Set<string>();
    const add = (p: Pt) => {
      const k = `${p[0]},${p[1]}`;
      if (!nodes.has(k)) nodes.set(k, { x: p[0] + dx, y: p[1] });
      return k;
    };
    for (const stroke of glyph.strokes) {
      const closed = stroke[stroke.length - 1] === "z";
      const pts = stroke.filter((p): p is Pt => p !== "z");
      const keys = pts.map(add);
      for (let i = 0; i + 1 < keys.length; i += 1) edges.add([keys[i], keys[i + 1]].sort().join("|"));
      if (closed && keys.length > 2) edges.add([keys[keys.length - 1], keys[0]].sort().join("|"));
    }
    for (const p of glyph.extra ?? []) add(p);
    for (const n of nodes.values()) d += circle(n.x, n.y, BEAD);
    for (const e of edges) {
      const [ka, kb] = e.split("|");
      const a = nodes.get(ka)!;
      const b = nodes.get(kb)!;
      d += metaballBridge(a, BEAD, b, BEAD, NECK)?.d ?? "";
    }
  });
  return `<svg class="dm" viewBox="${f(-pad)} ${f(-pad)} ${f(cols + 2 * pad)} ${f(6 + 2 * pad)}" role="img" aria-label="${escapeAttr(String(text))}" focusable="false"><path d="${d}"/></svg>`;
}

function escapeAttr(value: string) {
  return value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
}
