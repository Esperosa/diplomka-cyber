// Snimky obrazovek vsech ploch: desktop/tablet/telefon x svetly/tmavy rezim.
// Edge bezi VZDY bez okna (headless). Vystup mimo repozitar (tmp), cesta se vypise.
import { chromium } from "playwright-core";
import { spawn } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const EDGE = process.env.EDGE_PATH ?? "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
const outDir = process.argv[2] ?? join(tmpdir(), "bakula-ui-shots");
const port = 8791;
await mkdir(outDir, { recursive: true });

const server = spawn("node", ["scripts/mock-server.mjs", String(port)], { stdio: ["ignore", "pipe", "inherit"], env: { ...process.env } });
await new Promise((resolve) => server.stdout.on("data", resolve));

const browser = await chromium.launch({ executablePath: EDGE, headless: true });
const viewports = { desktop: { width: 1440, height: 900 }, tablet: { width: 1024, height: 768 }, phone: { width: 390, height: 844 } };
const sections = ["prehled", "hostitele", "nalezy", "overovani", "zasahy", "audit", "automat"];
const only = process.env.SHOTS_ONLY?.split(",");

try {
  for (const [vpName, viewport] of Object.entries(viewports)) {
    for (const scheme of ["light", "dark"]) {
      if (only && !only.includes(`${vpName}-${scheme}`)) continue;
      const context = await browser.newContext({ viewport, colorScheme: scheme, deviceScaleFactor: 1 });
      const page = await context.newPage();
      await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: "networkidle" });
      await page.waitForSelector(".dock-item");
      for (const section of sections) {
        await page.evaluate((s) => { window.location.hash = `#/${s}`; }, section);
        await page.waitForTimeout(350);
        if (section === "prehled") { await page.locator(".pebble").first().click({ force: true }); await page.waitForTimeout(200); }
        if (section === "hostitele" || section === "nalezy") {
          await page.locator(".row").first().click({ timeout: 1500 }).catch(() => {});
          await page.waitForTimeout(200);
          if (section === "hostitele") await page.click("details.service >> nth=0 >> summary").catch(() => {});
        }
        if (section === "overovani") { await page.click("details.plan >> nth=1 >> summary").catch(() => {}); await page.waitForTimeout(150); }
        await page.screenshot({ path: join(outDir, `${vpName}-${scheme}-${section}.png`) });
      }
      // Rozsahly beh (14 stanic) - test rozlozeni pole
      await page.evaluate(() => { window.location.hash = "#/prehled"; });
      await page.selectOption("#runSelect", { index: 1 });
      await page.waitForTimeout(500);
      await page.screenshot({ path: join(outDir, `${vpName}-${scheme}-prehled-large.png`) });
      await context.close();
    }
  }
  console.log(outDir);
} finally {
  await browser.close();
  server.kill();
}
