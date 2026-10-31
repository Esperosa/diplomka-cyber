// Sestaveni UI: TypeScript + CSS -> ui/ (app.js, styles.css, index.html).
// Zadny framework, zadny Tailwind - esbuild sklada obe casti.
import { build } from "esbuild";
import { mkdir, rm, writeFile } from "node:fs/promises";

await mkdir("ui", { recursive: true });
// Zbytky stareho UI (maskot, Tailwind vstup) nemaji v novem bundlu co delat.
await rm("ui/assets", { recursive: true, force: true });
await rm("ui/.styles.entry.pcss", { force: true });

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
  minify: true,
  target: ["chrome110", "firefox110", "safari16"],
  legalComments: "none",
});

const cacheBust = Date.now().toString(36);
const indexHtml = `<!doctype html>
<html lang="cs">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="color-scheme" content="light dark">
  <title>Bakula</title>
  <meta name="description" content="Bakula: korelace aktivního a pasivního pohledu na síť.">
  <link rel="stylesheet" href="/styles.css?v=${cacheBust}">
</head>
<body>
  <div id="app"></div>
  <noscript>Bakula potřebuje zapnutý JavaScript.</noscript>
  <script type="module" src="/app.js?v=${cacheBust}"></script>
</body>
</html>
`;

await writeFile("ui/index.html", indexHtml, "utf8");
console.log("UI sestaveno do ui/");
