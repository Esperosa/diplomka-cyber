// Mereni plynulosti mapy na ~300 zarizeni (headless Edge + maketa s MOCK_BIG=1). Vypise snimky (p50/p95/max) pri
// rozkvetu zony, filtru, tazeni a priblizeni. Pouziti: node scripts/ui-perf.mjs [port]
import { chromium } from "playwright-core";
import { spawn } from "node:child_process";

const port = Number(process.argv[2] ?? 8861);
const EDGE = process.env.EDGE_PATH ?? "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
const child = spawn("node", ["scripts/mock-server.mjs", String(port)], { stdio: ["ignore", "pipe", "inherit"], env: { ...process.env, MOCK_BIG: "1" } });
await new Promise((resolve) => child.stdout.once("data", resolve));
const browser = await chromium.launch({ executablePath: EDGE, headless: true });
try {
  const page = await (await browser.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
  const t0 = Date.now();
  await page.goto(`http://127.0.0.1:${port}/#/prehled`, { waitUntil: "networkidle" });
  await page.waitForSelector(".zone");
  const info = await page.evaluate(() => ({ nodes: document.querySelectorAll(".node").length, zones: document.querySelectorAll(".zone").length, dom: document.querySelectorAll("svg.netmap *").length }));
  console.log(`nacteni + prvni vykresleni: ${Date.now() - t0} ms; uzly ${info.nodes}, zony ${info.zones}, SVG prvku ${info.dom}`);
  await page.waitForTimeout(800);
  const measure = (name, fn) =>
    page.evaluate(
      async ({ name, fn }) => {
        const frames = [];
        let last = performance.now();
        let go = true;
        void (async () => {
          while (go) {
            await new Promise((r) => requestAnimationFrame(r));
            const t = performance.now();
            frames.push(t - last);
            last = t;
          }
        })();
        await new Promise((r) => setTimeout(r, 50));
        await (0, eval)(`(${fn})`)();
        go = false;
        await new Promise((r) => setTimeout(r, 30));
        frames.sort((a, b) => a - b);
        const q = (p) => frames[Math.min(frames.length - 1, Math.floor(frames.length * p))];
        return `${name.padEnd(34)} n=${String(frames.length).padStart(3)}  p50=${q(0.5).toFixed(1)} ms  p95=${q(0.95).toFixed(1)} ms  max=${frames[frames.length - 1].toFixed(1)} ms`;
      },
      { name, fn: fn.toString() },
    );
  const wait = "const w=(ms)=>new Promise(r=>setTimeout(r,ms));";
  console.log(await measure("rozkvet zony (vsechny zony 1x)", `async()=>{${wait} const z=document.querySelector('.zbub'); z.dispatchEvent(new MouseEvent('click',{bubbles:true})); await w(1300);}`));
  console.log(await measure("zpet na prehled (Esc)", `async()=>{${wait} document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true})); await w(1300);}`));
  console.log(await measure("filtr: jen tiskarny (vsechny zony)", `async()=>{${wait} document.querySelector('.mchip[data-kind="printer"]').click(); await w(1400);}`));
  console.log(await measure("zruseni filtru", `async()=>{${wait} document.querySelector('[data-action="clear-filter"]').click(); await w(1400);}`));
  await page.evaluate(() => document.querySelector(".mchip[data-kind='workstation']").click());
  await page.waitForTimeout(1400);
  const box = await page.locator("svg.netmap").boundingBox();
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down();
  const drag = page.evaluate(async () => {
    const frames = [];
    let last = performance.now();
    const end = last + 900;
    while (performance.now() < end) {
      await new Promise((r) => requestAnimationFrame(r));
      const t = performance.now();
      frames.push(t - last);
      last = t;
    }
    frames.sort((a, b) => a - b);
    const q = (p) => frames[Math.min(frames.length - 1, Math.floor(frames.length * p))];
    return `tazeni mapy (filtr: pracovni stanice)   n=${frames.length}  p50=${q(0.5).toFixed(1)} ms  p95=${q(0.95).toFixed(1)} ms  max=${frames[frames.length - 1].toFixed(1)} ms`;
  });
  for (let i = 0; i < 40; i += 1) {
    await page.mouse.move(box.x + box.width / 2 + i * 6, box.y + box.height / 2 + i * 3);
    await page.waitForTimeout(18);
  }
  await page.mouse.up();
  console.log(await drag);
  console.log(await measure("kolecko: 8x priblizeni", `async()=>{${wait} const s=document.querySelector('svg.netmap'); const r=s.getBoundingClientRect(); for(let i=0;i<8;i++){ s.dispatchEvent(new WheelEvent('wheel',{deltaY:-240,clientX:r.x+r.width/2,clientY:r.y+r.height/2,bubbles:true,cancelable:true})); await w(60);} }`));
} finally {
  await browser.close();
  child.kill();
}
