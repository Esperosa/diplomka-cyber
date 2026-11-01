// Vlastni pismo z teček: kazdy znak je KOSTRA z malo uzlu (kruhu) spojenych zaoblenymi tahy.
// B ma 8 uzlu, H 6, I 2. Zadne pismo z cizich zdroju, zadny raster ani rasterovy filtr: znak je kruhy
// a jedna cesta (path) s kulatymi konci a zaoblenymi rohy, barva z currentColor. Pri kazdem zvetseni,
// scrollu a zmene velikosti je stejny. Mrizka znaku: 4 x 6 jednotek.

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
const CORNER = 0.9; // polomer zaobleni rohu tahu
const BEAD = 0.62; // polomer uzlu
const WIDTH = 1.04; // sirka tahu

const f = (v: number) => +v.toFixed(2);

/** Cesta tahu se zaoblenymi rohy (kvadraticka krivka pres roh, G1 napojeni na rovne useky). */
function strokePath(stroke: Stroke, dx: number): string {
  const closed = stroke[stroke.length - 1] === "z";
  const pts = stroke.filter((p): p is Pt => p !== "z").map((p) => [p[0] + dx, p[1]] as Pt);
  const n = pts.length;
  if (n < 2) return "";
  const cut = (v: Pt, to: Pt): Pt => {
    const len = Math.hypot(to[0] - v[0], to[1] - v[1]) || 1;
    const t = Math.min(CORNER, len / 2) / len;
    return [v[0] + (to[0] - v[0]) * t, v[1] + (to[1] - v[1]) * t];
  };
  if (!closed) {
    let d = `M${f(pts[0][0])} ${f(pts[0][1])}`;
    for (let i = 1; i < n - 1; i += 1) {
      const a = cut(pts[i], pts[i - 1]);
      const b = cut(pts[i], pts[i + 1]);
      d += `L${f(a[0])} ${f(a[1])}Q${f(pts[i][0])} ${f(pts[i][1])} ${f(b[0])} ${f(b[1])}`;
    }
    return `${d}L${f(pts[n - 1][0])} ${f(pts[n - 1][1])}`;
  }
  const start = cut(pts[0], pts[1]);
  let d = `M${f(start[0])} ${f(start[1])}`;
  for (let k = 1; k <= n; k += 1) {
    const i = k % n;
    const a = cut(pts[i], pts[(i - 1 + n) % n]);
    const b = cut(pts[i], pts[(i + 1) % n]);
    d += `L${f(a[0])} ${f(a[1])}Q${f(pts[i][0])} ${f(pts[i][1])} ${f(b[0])} ${f(b[1])}`;
  }
  return `${d}Z`;
}

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
 * Kazdy znak: kruhy v uzlech kostry + jedna cesta zaoblenych tahu (bez filtru).
 */
export function dotMatrix(text: string, _options: DotOptions = {}): string {
  const chars = [...normalizeForMatrix(String(text))];
  const pad = BEAD + 0.25;
  const cols = Math.max(1, chars.length * ADVANCE - (ADVANCE - 4));
  let paths = "";
  let beads = "";
  chars.forEach((char, index) => {
    const glyph = GLYPHS[char] ?? GLYPHS["?"];
    const dx = index * ADVANCE;
    paths += glyph.strokes.map((s) => strokePath(s, dx)).join("");
    const nodes = new Map<string, Pt>();
    for (const s of glyph.strokes) for (const p of s) if (p !== "z") nodes.set(`${p[0]},${p[1]}`, [p[0] + dx, p[1]]);
    for (const p of glyph.extra ?? []) nodes.set(`${p[0]},${p[1]}`, [p[0] + dx, p[1]]);
    for (const [x, y] of nodes.values()) beads += `<circle cx="${f(x)}" cy="${f(y)}" r="${BEAD}"/>`;
  });
  const path = paths ? `<path d="${paths}" fill="none" stroke="currentColor" stroke-width="${WIDTH}" stroke-linecap="round" stroke-linejoin="round"/>` : "";
  return `<svg class="dm" viewBox="${f(-pad)} ${f(-pad)} ${f(cols + 2 * pad)} ${f(6 + 2 * pad)}" role="img" aria-label="${escapeAttr(String(text))}" focusable="false"><g>${beads}</g>${path}</svg>`;
}

function escapeAttr(value: string) {
  return value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
}
