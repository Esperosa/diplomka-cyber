// Koncepty znaku Salticus ve vizualnim jazyce aplikace: uzly (kruhy) spojene metaball mosty (stejna funkce
// metaballBridge i skelet pismen jako v dotmatrix.ts), barvy z tokens.css (inkoust, papir, signalni cervena).
// Vystup: SVG znaky, ikony aplikace a prehledova stranka v docs/brand/koncepty/. Nic z toho se nepripojuje
// do sestaveni UI; vybrany koncept se rucne dopracuje a presune do ui-src/brand/.
import { buildSync } from "esbuild";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { tmpdir } from "node:os";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = join(root, "docs", "brand", "koncepty");
mkdirSync(out, { recursive: true });

const tmp = join(process.env.BRAND_TMP || tmpdir(), "salticus-brand");
mkdirSync(tmp, { recursive: true });
buildSync({
  stdin: {
    contents: `export { metaballBridge } from "./ui-src/metaball"; export { dotMatrix } from "./ui-src/dotmatrix";`,
    resolveDir: root,
    loader: "ts",
  },
  bundle: true,
  format: "esm",
  platform: "node",
  outfile: join(tmp, "lib.mjs"),
  logLevel: "error",
});
const { metaballBridge, dotMatrix } = await import(pathToFileURL(join(tmp, "lib.mjs")).href);

const INK = "#0e0e0d";
const PAPER = "#efeee9";
const SIGNAL = "#d71921";
const INK_DARK = "#ecebe5";
const f = (v) => +v.toFixed(2);
const circle = (x, y, r) => `M${f(x + r)} ${f(y)}A${r} ${r} 0 1 1 ${f(x - r)} ${f(y)}A${r} ${r} 0 1 1 ${f(x + r)} ${f(y)}Z`;

/** Uzly + mosty jako jeden path; vraci {d, node(i) -> kruh} pro obarveni vybraneho uzlu. */
function chain(nodes, edges, neck, maxGap = null) {
  let d = "";
  for (const n of nodes) d += circle(n.x, n.y, n.r);
  for (const [i, j, nk] of edges) {
    const g = metaballBridge({ x: nodes[i].x, y: nodes[i].y }, nodes[i].r, { x: nodes[j].x, y: nodes[j].y }, nodes[j].r, nk ?? neck, maxGap);
    if (g) d += g.d;
  }
  return d;
}

function svg(viewBox, body, { w, h, title } = {}) {
  const [, , vw, vh] = viewBox.split(" ").map(Number);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${viewBox}" width="${w ?? vw}" height="${h ?? vh}" role="img" aria-label="${title ?? "Salticus"}">${body}</svg>\n`;
}
const fillRule = 'fill-rule="nonzero"';

// ---------- 1. OCI: tvar skakavky zepredu, dva velke predni oci, dve bocni, spojene hrdly ----------
// Asymetrie (leve bocni oko nize, prave vys) je zamerna, stejne jako organicke rohy ploch v aplikaci.
function oci(ink, sig) {
  // zepredu: dve velke oci dole, bocni stredni oci o stupen vys, dve drobna nahore (jako u skutecne skakavky)
  const nodes = [
    { x: 46, y: 62, r: 21 }, // velke leve
    { x: 100, y: 62, r: 21 }, // velke prave (signal)
    { x: 12, y: 46, r: 10 }, // bocni leve
    { x: 134, y: 42, r: 10 }, // bocni prave
    { x: 40, y: 22, r: 5.2 }, // drobne leve
    { x: 106, y: 20, r: 5.2 }, // drobne prave
  ];
  const edges = [[0, 1, 8], [0, 2, 4.6], [1, 3, 4.6], [0, 4, 2.6], [1, 5, 2.6]];
  const dInk = chain(nodes, edges, 6, 40);
  const body = `<path d="${dInk}" fill="${ink}" ${fillRule}/>` + `<path d="${circle(100, 62, 21)}" fill="${sig}"/>`;
  return svg("-4 8 152 90", body, { title: "Salticus, znak oci" });
}

// ---------- 2. SKOK: tri uzly na parabole, hrdla se zuzuji, dopad v signalni cervene ----------
function skok(ink, sig) {
  const nodes = [
    { x: 14, y: 70, r: 11.5 },
    { x: 38, y: 36, r: 6.4 },
    { x: 72, y: 24, r: 5 },
    { x: 106, y: 58, r: 9.5 },
  ];
  const edges = [[0, 1, 5.2], [1, 2, 3.6], [2, 3, 4.2]];
  const dInk = chain(nodes, edges, 4, 60);
  const body = `<path d="${dInk}" fill="${ink}" ${fillRule}/><path d="${circle(106, 58, 9.5)}" fill="${sig}"/>`;
  return svg("-4 8 130 76", body, { title: "Salticus, znak skok" });
}

// ---------- 3. S: monogram ze skeletu pismene S (jako v dotmatrix.ts), konec tahu v signalni cervene ----------
const S_PTS = [[4, 1], [3, 0], [1, 0], [0, 1.2], [1, 3], [3, 3], [4, 4.8], [3, 6], [1, 6], [0, 5]];
function monoS(ink, sig, bead = 0.86, neck = 1.42) {
  const nodes = S_PTS.map(([x, y]) => ({ x, y, r: bead }));
  const edges = S_PTS.slice(1).map((_, i) => [i, i + 1, neck]);
  const dInk = chain(nodes, edges, neck);
  const last = nodes[nodes.length - 1];
  const body = `<path d="${dInk}" fill="${ink}" ${fillRule}/><path d="${circle(last.x, last.y, bead)}" fill="${sig}"/>`;
  const pad = bead + 0.3;
  return svg(`${f(-pad)} ${f(-pad)} ${f(4 + 2 * pad)} ${f(6 + 2 * pad)}`, body, { title: "Salticus, monogram S" });
}

// ---------- 4. WORDMARK: SALTICUS vlastnim pismem z uzlu (dotMatrix), horni uzel pismene I je signal ----------
function wordmark(ink, sig) {
  const BEAD = 0.66;
  const word = [..."SALTICUS"];
  const width = (ch) => (ch === "I" ? 0 : 4);
  const left = (ch) => (ch === "I" ? 2 : 0); // x skeletu v bunce pismene
  let x = 0;
  let d = "";
  let redX = 0;
  for (const ch of word) {
    const raw = dotMatrix(ch);
    const pd = /<path d="([^"]+)"/.exec(raw)[1];
    const dx = x - left(ch);
    d += `<path transform="translate(${f(dx)} 0)" d="${pd}" fill="${ink}" ${fillRule}/>`;
    if (ch === "I") redX = x;
    x += width(ch) + 2.2;
  }
  const total = x - 2.2;
  const pad = BEAD + 0.2;
  const body = d + `<path d="${circle(redX, 0, BEAD)}" fill="${sig}"/>`;
  return svg(`${f(-pad)} ${f(-pad)} ${f(total + 2 * pad)} ${f(6 + 2 * pad)}`, body, { title: "Salticus" });
}

// ---------- ikona aplikace: organicka asymetricka plocha (rohy jako --r-card), znak vystrizeny do papiru ----------
function blob(size, tl, tr, br, bl) {
  const [a, b] = [tl, tr];
  const s = size;
  return (
    `M${tl[0]} 0H${s - tr[0]}A${tr[0]} ${tr[1]} 0 0 1 ${s} ${tr[1]}V${s - br[1]}A${br[0]} ${br[1]} 0 0 1 ${s - br[0]} ${s}` +
    `H${bl[0]}A${bl[0]} ${bl[1]} 0 0 1 0 ${s - bl[1]}V${tl[1]}A${tl[0]} ${tl[1]} 0 0 1 ${tl[0]} 0Z`
  );
}
function appIcon(markSvg, vb, pad = 150) {
  const [vx, vy, vw, vh] = vb.split(" ").map(Number);
  const inner = 1024 - 2 * pad;
  const k = Math.min(inner / vw, inner / vh);
  const tx = (1024 - vw * k) / 2 - vx * k;
  const ty = (1024 - vh * k) / 2 - vy * k;
  const bodyOnly = markSvg.replace(/^<svg[^>]*>/, "").replace(/<\/svg>\s*$/, "");
  const shape = blob(1024, [300, 270], [200, 320], [300, 220], [190, 300]);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024" role="img" aria-label="Salticus"><path d="${shape}" fill="${INK}"/><g transform="translate(${f(tx)} ${f(ty)}) scale(${f(k)})">${bodyOnly}</g></svg>\n`;
}

const sets = {
  skok: { make: skok },
  s: { make: monoS },
  wordmark: { make: wordmark },
};
const files = [];
for (const [name, { make }] of Object.entries(sets)) {
  for (const [variant, ink] of [["svetly", INK], ["tmavy", INK_DARK]]) {
    const file = `${name}-${variant}.svg`;
    writeFileSync(join(out, file), make(ink, SIGNAL));
    files.push(file);
  }
}
// ikony: znak v papirove barve na inkoustove plose
for (const name of ["skok", "s"]) {
  const mark = sets[name].make(PAPER, SIGNAL);
  const vb = /viewBox="([^"]+)"/.exec(mark)[1];
  writeFileSync(join(out, `ikona-${name}.svg`), appIcon(mark, vb, name === "s" ? 230 : 170));
  files.push(`ikona-${name}.svg`);
}

// ---------- prehled ----------
const card = (title, note, content, dark = false) =>
  `<section class="c ${dark ? "dark" : ""}"><h3>${title}</h3><p>${note}</p>${content}</section>`;
const img = (file, h) => `<img src="${file}" style="height:${h}px">`;
const sizes = (file) => [16, 24, 32, 48, 64].map((h) => img(file, h)).join("");
const html = `<!doctype html><meta charset="utf-8"><title>Salticus, koncepty znaku</title>
<style>
@font-face{font-family:"Sedmdvacet Mono";src:url("../../../ui-src/fonts/sedmdvacet-mono/SedmdvacetMono-Regular.woff2")}
@font-face{font-family:"Sedmdvacet Display";src:url("../../../ui-src/fonts/sedmdvacet-display/SedmdvacetDisplay-Medium.woff2")}
body{margin:0;background:${PAPER};color:${INK};font:15px/1.5 "Sedmdvacet Mono",monospace;padding:56px 64px}
h1{font:500 34px "Sedmdvacet Display",sans-serif;margin:0 0 6px} .sub{color:#55544e;margin:0 0 40px}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:28px}
.c{background:#f8f7f3;padding:34px 40px 36px;border-radius:2.2rem 1.5rem 2rem 1.7rem;min-height:260px}
.c.dark{background:#0b0b0a;color:${INK_DARK}}
.c h3{font:500 20px "Sedmdvacet Display",sans-serif;margin:0 0 4px}.c p{margin:0 0 22px;color:#55544e;font-size:13px}
.c.dark p{color:#a7a69f}
.big{display:flex;align-items:center;gap:36px;flex-wrap:wrap}
.row{display:flex;align-items:flex-end;gap:22px;margin-top:26px}
.wide{grid-column:1/-1}
</style>
<h1>Salticus: koncepty znaku</h1>
<p class="sub">Vizualni jazyk aplikace: uzly spojene metaball hrdly, vlastni skelet pismen, papirova a inkoustova barva, jediny signalni akcent. Navrhy k posouzeni, nic z toho neni zapojeno do UI.</p>
<div class="grid">
${card("A &middot; Skok", "Uzel, krátké hrdlo, uzel, dopad v signalni barve: pivot z hosta na hosta.", `<div class="big">${img("skok-svetly.svg", 150)}</div><div class="row">${sizes("skok-svetly.svg")}</div>`)}
${card("A &middot; Skok (tmavy)", "Tmava varianta.", `<div class="big">${img("skok-tmavy.svg", 150)}</div><div class="row">${sizes("skok-tmavy.svg")}</div>`, true)}
${card("B &middot; Monogram S", "Skelet pismene S ze stejnych uzlu jako popisky v aplikaci, konec tahu je signal.", `<div class="big">${img("s-svetly.svg", 200)}</div><div class="row">${sizes("s-svetly.svg")}</div>`)}
${card("B &middot; Monogram S (tmavy)", "Tmava varianta.", `<div class="big">${img("s-tmavy.svg", 200)}</div><div class="row">${sizes("s-tmavy.svg")}</div>`, true)}
${card("Wordmark", "SALTICUS vlastnim pismem z uzlu (stejne jako cisla a popisky v UI); horni uzel pismene I je signal.", `<div class="big">${img("wordmark-svetly.svg", 90)}</div>`, false).replace('class="c ', 'class="c wide ')}
${card("Wordmark (tmavy)", "Tmava varianta.", `<div class="big">${img("wordmark-tmavy.svg", 90)}</div>`, true).replace('class="c ', 'class="c wide ')}
${card("Ikony aplikace", "Znak v papirove barve na organicke inkoustove plose (rohy jako karty v aplikaci). Nahled 256, 96, 48 a 32 px.", `<div class="big">${["skok", "s"].map((n) => `<div><img src="ikona-${n}.svg" style="height:200px"><div class="row" style="margin-top:12px">${[96, 48, 32, 16].map((h) => img(`ikona-${n}.svg`, h)).join("")}</div></div>`).join("")}</div>`).replace('class="c ', 'class="c wide ')}
</div>`;
writeFileSync(join(out, "prehled.html"), html);
console.log("hotovo:", files.length, "souboru v", out);
