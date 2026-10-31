// Vlastni 5x7 bodove pismo. Zadne pismo z cizich zdroju: kazdy znak je sedm radku po peti
// bitech. Sousedni body se tekute spoji do tucnych, souvislych, zaoblenych tahu s ostrymi hranami
// a barvou z currentColor (bez rasterovych filtru).

const GLYPHS: Record<string, string[]> = {
  "0": ["01110", "10001", "10011", "10101", "11001", "10001", "01110"],
  "1": ["00100", "01100", "00100", "00100", "00100", "00100", "01110"],
  "2": ["01110", "10001", "00001", "00010", "00100", "01000", "11111"],
  "3": ["11110", "00001", "00001", "01110", "00001", "00001", "11110"],
  "4": ["00010", "00110", "01010", "10010", "11111", "00010", "00010"],
  "5": ["11111", "10000", "11110", "00001", "00001", "10001", "01110"],
  "6": ["00110", "01000", "10000", "11110", "10001", "10001", "01110"],
  "7": ["11111", "00001", "00010", "00100", "01000", "01000", "01000"],
  "8": ["01110", "10001", "10001", "01110", "10001", "10001", "01110"],
  "9": ["01110", "10001", "10001", "01111", "00001", "00010", "01100"],
  A: ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
  B: ["11110", "10001", "10001", "11110", "10001", "10001", "11110"],
  C: ["01110", "10001", "10000", "10000", "10000", "10001", "01110"],
  D: ["11110", "10001", "10001", "10001", "10001", "10001", "11110"],
  E: ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
  F: ["11111", "10000", "10000", "11110", "10000", "10000", "10000"],
  G: ["01110", "10001", "10000", "10111", "10001", "10001", "01111"],
  H: ["10001", "10001", "10001", "11111", "10001", "10001", "10001"],
  I: ["01110", "00100", "00100", "00100", "00100", "00100", "01110"],
  J: ["00111", "00010", "00010", "00010", "00010", "10010", "01100"],
  K: ["10001", "10010", "10100", "11000", "10100", "10010", "10001"],
  L: ["10000", "10000", "10000", "10000", "10000", "10000", "11111"],
  M: ["10001", "11011", "10101", "10101", "10001", "10001", "10001"],
  N: ["10001", "11001", "10101", "10011", "10001", "10001", "10001"],
  O: ["01110", "10001", "10001", "10001", "10001", "10001", "01110"],
  P: ["11110", "10001", "10001", "11110", "10000", "10000", "10000"],
  Q: ["01110", "10001", "10001", "10001", "10101", "10010", "01101"],
  R: ["11110", "10001", "10001", "11110", "10100", "10010", "10001"],
  S: ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
  T: ["11111", "00100", "00100", "00100", "00100", "00100", "00100"],
  U: ["10001", "10001", "10001", "10001", "10001", "10001", "01110"],
  V: ["10001", "10001", "10001", "10001", "10001", "01010", "00100"],
  W: ["10001", "10001", "10001", "10101", "10101", "10101", "01010"],
  X: ["10001", "10001", "01010", "00100", "01010", "10001", "10001"],
  Y: ["10001", "10001", "01010", "00100", "00100", "00100", "00100"],
  Z: ["11111", "00001", "00010", "00100", "01000", "10000", "11111"],
  ".": ["00000", "00000", "00000", "00000", "00000", "01100", "01100"],
  ":": ["00000", "01100", "01100", "00000", "01100", "01100", "00000"],
  "-": ["00000", "00000", "00000", "11111", "00000", "00000", "00000"],
  "%": ["11001", "11010", "00010", "00100", "01000", "01011", "10011"],
  "/": ["00001", "00010", "00010", "00100", "01000", "01000", "10000"],
  "+": ["00000", "00100", "00100", "11111", "00100", "00100", "00000"],
  "?": ["01110", "10001", "00001", "00010", "00100", "00000", "00100"],
  "!": ["00100", "00100", "00100", "00100", "00100", "00000", "00100"],
  " ": ["00000", "00000", "00000", "00000", "00000", "00000", "00000"],
};

export function normalizeForMatrix(text: string): string {
  return text
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .toUpperCase()
    .replace(/[^0-9A-Z.:%/+!? -]/g, "?");
}

export type DotOptions = {
  /** Vyska jednoho radku v em (pro CSS); sirka se dopocte z pomeru stran. */
  offDots?: boolean;
};

/**
 * Vraci SVG retezec. Velikost se ridi CSS (vyska prvku), ne atributy. Hodnota je v aria-label.
 *
 * Goo bez filtru: kazdy bod je kruh a sousedni body (i diagonalne) spojuje tucna ocka se zaoblenymi
 * konci. Vysledek je jedna souvisla zaoblena silueta s ostrymi hranami, ktera je pri kazdem zvetseni,
 * scrollu i zmene velikosti stejna (zadny rasterovy filtr, ktery by mohl blikat nebo se rozsypat).
 */
export function dotMatrix(text: string, options: DotOptions = {}): string {
  const clean = normalizeForMatrix(String(text));
  const chars = [...clean];
  const cols = Math.max(1, chars.length * 6 - 1);
  const rows = 7;
  const pad = 0.4;
  const beads: string[] = [];
  const links: string[] = [];
  const offs: string[] = [];
  chars.forEach((char, index) => {
    const glyph = GLYPHS[char] ?? GLYPHS["?"];
    const on = (x: number, y: number) => glyph[y]?.[x] === "1";
    glyph.forEach((line, y) => {
      [...line].forEach((bit, x) => {
        const cx = index * 6 + x + 0.5;
        const cy = y + 0.5;
        if (bit !== "1") {
          if (options.offDots) offs.push(`<circle class="off" cx="${cx}" cy="${cy}" r="0.2"/>`);
          return;
        }
        beads.push(`<circle cx="${cx}" cy="${cy}" r="0.62"/>`);
        // spoj k sousedum vpravo, dolu a po obou diagonalach dolu (kazda dvojice jednou)
        for (const [dx, dy] of [[1, 0], [0, 1], [1, 1], [-1, 1]] as const) {
          if (on(x + dx, y + dy)) links.push(`M${cx} ${cy}L${cx + dx} ${cy + dy}`);
        }
      });
    });
  });
  const off = offs.length ? `<g>${offs.join("")}</g>` : "";
  const body = `<g>${beads.join("")}</g><path d="${links.join("")}" fill="none" stroke="currentColor" stroke-width="1.04" stroke-linecap="round"/>`;
  return `<svg class="dm" viewBox="${-pad} ${-pad} ${cols + 2 * pad} ${rows + 2 * pad}" role="img" aria-label="${escapeAttr(String(text))}" focusable="false">${off}${body}</svg>`;
}

function escapeAttr(value: string) {
  return value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");
}
