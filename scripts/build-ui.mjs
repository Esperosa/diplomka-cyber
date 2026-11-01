// Sestaveni UI: TypeScript + CSS -> ui/ (app.js, styles.css, index.html).
// Zadny framework, zadny Tailwind - esbuild sklada obe casti.
import { build } from "esbuild";
import { cp, mkdir, readdir, rm, writeFile } from "node:fs/promises";

await mkdir("ui", { recursive: true });
// Zbytky stareho UI (maskot, Tailwind vstup) nemaji v novem bundlu co delat.
await rm("ui/assets", { recursive: true, force: true });
await rm("ui/.styles.entry.pcss", { force: true });

// Pisma Sedmdvacet (SIL OFL 1.1, vcetne licenci) se kopiruji vedle bundlu.
await rm("ui/fonts", { recursive: true, force: true });
await cp("ui-src/fonts", "ui/fonts", { recursive: true });

await build({
  entryPoints: ["ui-src/main.ts"],
  outfile: "ui/app.js",
  bundle: true,
  format: "esm",
  target: "es2022",
  sourcemap: false,
  minify: true,
  legalComments: "none",
});

await build({
  entryPoints: ["ui-src/styles/index.css"],
  outfile: "ui/styles.css",
  bundle: true,
  external: ["/fonts/*"],
  minify: true,
  target: ["chrome110", "firefox110", "safari16"],
  legalComments: "none",
});

// Ikona aplikace (favicon) je dodana autorem: soubory v ui-src/brand/ se zkopiruji do ui/ a odkazou v index.html.
// Znak se negeneruje; kdyz soubor chybi, odkaz se nevlozi (a favicon se nepozaduje: data: prazdna ikona).
let brandFiles = [];
try {
  brandFiles = await readdir("ui-src/brand");
} catch {
  brandFiles = [];
}
await rm("ui/brand", { recursive: true, force: true });
if (brandFiles.length) await cp("ui-src/brand", "ui/brand", { recursive: true });
const brandLinks = [];
const svg = brandFiles.find((f) => /\.svg$/i.test(f));
const png = brandFiles.find((f) => /^(favicon|icon).*\.png$/i.test(f));
const ico = brandFiles.find((f) => /\.ico$/i.test(f));
const touch = brandFiles.find((f) => /^apple-touch.*\.png$/i.test(f));
if (svg) brandLinks.push(`<link rel="icon" type="image/svg+xml" href="/brand/${svg}">`);
if (png) brandLinks.push(`<link rel="icon" type="image/png" href="/brand/${png}">`);
if (ico) brandLinks.push(`<link rel="icon" href="/brand/${ico}" sizes="any">`);
if (touch) brandLinks.push(`<link rel="apple-touch-icon" href="/brand/${touch}">`);
if (!brandLinks.length) brandLinks.push('<link rel="icon" href="data:,">');
const NL = String.fromCharCode(10) + "  ";
const cacheBust = Date.now().toString(36);
const indexHtml = `<!doctype html>
<html lang="cs">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="color-scheme" content="light dark">
  <title>Skákavka</title>
  <meta name="description" content="Skákavka: korelace aktivního a pasivního pohledu na síť.">
  ${brandLinks.join(NL)}
  <link rel="stylesheet" href="/styles.css?v=${cacheBust}">
</head>
<body>
  <div id="app"></div>
  <noscript>Skákavka potřebuje zapnutý JavaScript.</noscript>
  <script type="module" src="/app.js?v=${cacheBust}"></script>
</body>
</html>
`;

await writeFile("ui/index.html", indexHtml, "utf8");
console.log("UI sestaveno do ui/");
