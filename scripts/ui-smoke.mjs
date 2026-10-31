// Staticke kontroly sestaveneho UI (bez prohlizece): obsah ui/, tokeny, kontrast, zakazane vzory.
import { readFile, readdir } from "node:fs/promises";
import { JSDOM } from "jsdom";

const failures = [];
const check = (ok, message) => {
  if (!ok) failures.push(message);
};

const html = await readFile("ui/index.html", "utf8");
const css = await readFile("ui/styles.css", "utf8");
const js = await readFile("ui/app.js", "utf8");
const tokens = await readFile("ui-src/styles/tokens.css", "utf8");

const dom = new JSDOM(html);
const doc = dom.window.document;
check(Boolean(doc.querySelector("#app")), "index.html nema #app root");
check(doc.documentElement.lang === "cs", "index.html nema lang=cs");
check(Boolean(doc.querySelector('meta[name="viewport"]')), "chybi meta viewport");
check(/color-scheme/.test(html), "chybi meta color-scheme");

// Zadne zbytky stareho UI
check(!/jumping|spider/i.test(css + js), "bundle obsahuje maskota ze stareho UI");
check((await readdir("ui")).sort().join(",") === "app.js,fonts,index.html,styles.css", "ui/ ma obsahovat jen app.js, fonts, index.html, styles.css");
check((await readdir("ui/fonts")).sort().join(",") === "sedmdvacet-display,sedmdvacet-mono,sedmdvacet-text-c", "ui/fonts ma obsahovat jen rodiny Sedmdvacet");

// Zakazane AI vzory (docs: anti-patterns-ai-look.md)
check(!/#6366f1|#8b5cf6|#a855f7|#7c3aed|indigo|violet/i.test(css), "CSS obsahuje fialovomodrou paletu");
check(!/backdrop-filter/.test(css), "CSS pouziva backdrop-filter (glassmorphism)");
check(!/font-family:[^;]*\bInter\b/i.test(css), "CSS pouziva Inter");
check(!/border-left:\s*[34]px/.test(css), "CSS obsahuje barevny pruh vlevo na kartach");
check(!/sparkle|✨/i.test(js), "bundle obsahuje AI jiskru");
check(/prefers-reduced-motion/.test(css), "CSS nerespektuje prefers-reduced-motion");
check(/prefers-color-scheme:\s*dark/.test(css) && /data-theme/.test(css), "chybi tmavy rezim (system + prepinac)");
check(!/animation:[^;]*infinite[^;]*;[^}]*background/.test(css), "nekonecna animace pozadi");

// Zadne tretistranove zdroje / fonty
check(!/https?:\/\/(?!www\.w3\.org)/.test(css + html), "UI nacita zdroj z cizi domeny");
const faces = [...css.matchAll(/@font-face\{[^}]*\}/g)].map((m) => m[0]);
check(faces.length > 0 && faces.every((f) => /url\(\/fonts\/sedmdvacet-/.test(f)), "@font-face smi odkazovat jen na vlastni pisma Sedmdvacet (SIL OFL) v /fonts/");
check(!/Inter|Roboto|Helvetica Neue|Space Grotesk/.test(css), "CSS pouziva cizi (AI-typicke) pismo");

// Kontrast tokenu (WCAG AA: text 4.5, velke/ikonicke 3)
function parseBlock(source, selector) {
  const start = source.indexOf(selector);
  const open = source.indexOf("{", start);
  const close = source.indexOf("}", open);
  const body = source.slice(open + 1, close);
  const out = {};
  for (const m of body.matchAll(/--([a-z0-9-]+):\s*(#[0-9a-f]{6})/gi)) out[m[1]] = m[2];
  return out;
}
const light = parseBlock(tokens, ":root {");
const dark = parseBlock(tokens, ':root[data-theme="dark"]');
const lum = (hex) => {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const ratio = (a, b) => {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};
for (const [name, set] of [["svetly", light], ["tmavy", dark]]) {
  const pairs = [
    ["ink", "bg", 4.5], ["ink", "surface", 4.5], ["ink", "surface-2", 4.5],
    ["ink-2", "bg", 4.5], ["ink-2", "surface", 4.5], ["ink-2", "surface-2", 4.5],
    ["signal-ink", "surface", 4.5], ["signal-ink", "bg", 4.5],
    ["bg", "ink", 4.5],
  ];
  for (const [fg, bg, min] of pairs) {
    const value = ratio(set[fg], set[bg]);
    check(value >= min, `kontrast ${name}: --${fg} na --${bg} = ${value.toFixed(2)} (< ${min})`);
  }
}
check(ratio(light["on-signal"] ?? "#ffffff", light.signal) >= 4.5, "kontrast: text na --signal (svetly) < 4.5");
check(ratio(dark["on-signal"] ?? "#ffffff", dark.signal) >= 4.5, "kontrast: text na --signal (tmavy) < 4.5");

if (failures.length) {
  console.error("UI smoke: SELHALO\n - " + failures.join("\n - "));
  process.exit(1);
}
console.log(`UI smoke: v poradku (${(js.length / 1024).toFixed(0)} kB JS, ${(css.length / 1024).toFixed(0)} kB CSS)`);
