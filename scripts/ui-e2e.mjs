// E2E nad novym UI: Edge v headless rezimu + maketa API (scripts/mock-server.mjs).
// Nikdy neotevira okno na plose uzivatele.
import { chromium } from "playwright-core";
import { spawn } from "node:child_process";

const EDGE = process.env.EDGE_PATH ?? "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
const results = [];
const servers = [];

async function startMock(port, env = {}) {
  const child = spawn("node", ["scripts/mock-server.mjs", String(port)], { stdio: ["ignore", "pipe", "inherit"], env: { ...process.env, ...env } });
  servers.push(child);
  await new Promise((resolve) => child.stdout.once("data", resolve));
  return `http://127.0.0.1:${port}/`;
}

async function test(name, fn) {
  try {
    await fn();
    results.push({ name, ok: true });
    console.log(`  ok   ${name}`);
  } catch (error) {
    results.push({ name, ok: false, error });
    console.log(`  FAIL ${name}\n       ${String(error.message ?? error).split("\n")[0]}`);
  }
}
function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const browser = await chromium.launch({ executablePath: EDGE, headless: true });

async function open(url, viewport = { width: 1440, height: 900 }, options = {}, waitUntil = "networkidle") {
  const context = await browser.newContext({ viewport, ...options });
  const page = await context.newPage();
  const problems = [];
  page.on("pageerror", (error) => problems.push(`pageerror: ${error.message}`));
  page.on("console", (message) => {
    if (message.type() === "error" && !/Failed to load resource/.test(message.text())) problems.push(`console: ${message.text()}`);
  });
  await page.goto(url, { waitUntil });
  await page.waitForSelector(".dock-item");
  return { page, context, problems };
}

try {
  const base = await startMock(8801);
  const analystUrl = await startMock(8802, { MOCK_ROLE: "analyst" });
  const brokenChainUrl = await startMock(8803, { MOCK_CHAIN_BAD: "1" });
  const emptyUrl = await startMock(8804, { MOCK_EMPTY: "1" });
  const enforceUrl = await startMock(8805, { MOCK_MODE: "enforce" });
  const authUrl = await startMock(8806, { MOCK_AUTH: "1" });

  console.log("UI e2e (Edge headless + maketa API)");

  await test("vsechny plochy se vykresli bez chyb v konzoli a bez strankoveho scrollu (3 velikosti)", async () => {
    for (const viewport of [{ width: 1440, height: 900 }, { width: 1024, height: 768 }, { width: 390, height: 844 }]) {
      const { page, context, problems } = await open(base, viewport);
      for (const section of ["prehled", "hostitele", "nalezy", "overovani", "zasahy", "audit", "automat"]) {
        await page.evaluate((s) => { window.location.hash = `#/${s}`; }, section);
        await page.waitForTimeout(250);
        const info = await page.evaluate(() => ({
          h1: document.querySelector("#stage h1")?.textContent ?? "",
          docScroll: document.documentElement.scrollHeight - window.innerHeight,
          hScroll: document.documentElement.scrollWidth - window.innerWidth,
        }));
        assert(info.h1.length > 0, `${section}@${viewport.width}: chybi nadpis h1`);
        assert(info.docScroll <= 1, `${section}@${viewport.width}: stranka scrolluje svisle (${info.docScroll}px)`);
        assert(info.hScroll <= 1, `${section}@${viewport.width}: stranka scrolluje vodorovne (${info.hScroll}px)`);
      }
      assert(problems.length === 0, `chyby: ${problems.join(" | ")}`);
      await context.close();
    }
  });

  await test("Prehled: pole ma oblazek pro kazdou stanici, klik i klavesnice vybere stanici", async () => {
    const { page, context } = await open(base);
    const count = await page.locator(".pebble").count();
    assert(count === 3, `ocekavany 3 oblazky, nalezeno ${count}`);
    await page.locator(".pebble").first().click({ force: true });
    assert((await page.locator(".host-card .host-ip").count()) === 1, "po kliku se nezobrazila karta stanice");
    await page.locator(".pebble").nth(1).focus();
    await page.keyboard.press("Enter");
    const ip = await page.locator(".host-card .host-ip").textContent();
    assert(/192\.168\.56\.\d+/.test(ip ?? ""), "klavesnice (Enter) stanici nevybrala");
    const label = await page.locator(".pebble").first().getAttribute("aria-label");
    assert(/Riziko .*Nejistota/.test(label ?? ""), "oblazek nema popisek s rizikem a nejistotou");
    await context.close();
  });

  await test("Nalezy: neznama osa nejistoty se ukaze jako 'neznamé', ne jako 0 %", async () => {
    const { page, context } = await open(base + "#/nalezy");
    await page.locator(".row").first().click();
    const axes = await page.locator(".axes .axis").allTextContents();
    const interp = axes.find((t) => t.includes("Interpretace")) ?? "";
    assert(/neznámé/.test(interp), `Interpretace: ${interp}`);
    assert(!/\b0 %/.test(interp), "neznama osa se tvari jako 0 %");
    const prob = await page.locator(".hyp .kv").textContent();
    assert(/neznámé/.test(prob ?? ""), "pravdepodobnost null neni 'neznamé'");
    await context.close();
  });

  await test("Overovani: plany, schvaleni a vyrazene aktiva jsou videt; zadne vymyslene vysledky", async () => {
    const { page, context } = await open(base + "#/overovani");
    assert((await page.locator("details.plan").count()) >= 10, "malo planu");
    await page.locator("details.plan summary").nth(1).click();
    assert((await page.locator(".ranked li").count()) >= 2, "po rozbaleni chybi poradi kandidatu");
    assert((await page.locator(".chip-hot").count()) >= 1, "chybi znacka 'schváleni'");
    const resultsText = await page.locator("table.data").last().textContent();
    assert(/převzato z dřívější kontroly/.test(resultsText ?? ""), "stav 'reused' neni zobrazen");
    await context.close();
    const empty = await open(emptyUrl + "#/overovani");
    assert(/Není načtený žádný běh/.test((await empty.page.locator("#stage").textContent()) ?? ""), "prazdny server: chybi poctivy prazdny stav");
    await empty.context.close();
  });

  await test("Zasahy: chranena adresa je odmitnuta srozumitelne, duplicita take, navrh a schvaleni funguji", async () => {
    const { page, context } = await open(base + "#/zasahy");
    assert(/Zkušební režim/.test((await page.locator(".mode-banner").textContent()) ?? ""), "chybi banner zkusebniho rezimu");
    await page.fill('input[name="ip"]', "127.0.0.1");
    await page.fill('input[name="reason"]', "test");
    await page.click('form.propose button[type="submit"]');
    await page.waitForSelector(".form-error");
    assert(/chráněného rozsahu/.test((await page.locator(".form-error").textContent()) ?? ""), "ProtectedRange nema srozumitelnou hlasku");
    await page.fill('input[name="ip"]', "198.51.100.7");
    await page.click('form.propose button[type="submit"]');
    await page.waitForFunction(() => /už existuje/.test(document.querySelector(".form-error")?.textContent ?? ""));
    await page.fill('input[name="ip"]', "198.51.100.20");
    await page.fill('input[name="reason"]', "e2e navrh");
    await page.click('form.propose button[type="submit"]');
    await page.waitForFunction(() => document.body.textContent.includes("198.51.100.20"));
    // TTL strop
    await page.fill('input[name="ip"]', "198.51.100.21");
    await page.fill('input[name="reason"]', "moc dlouho");
    await page.selectOption('select[name="unit"]', "h");
    await page.fill('input[name="ttl"]', "30");
    await page.click('form.propose button[type="submit"]');
    await page.waitForFunction(() => /24 hodinami/.test(document.querySelector(".form-error")?.textContent ?? ""));
    // schvaleni pres potvrzovaci dialog
    await page.locator('[data-action="enf-approve"]').first().click();
    await page.waitForSelector("dialog.modal[open]");
    await page.click('dialog.modal button[value="yes"]');
    await page.waitForFunction(() => document.body.textContent.includes("schváleno"));
    await context.close();
  });

  await test("Zasahy: v ostrem rezimu je banner cerveny a dialog varuje, ze se zmeni brana", async () => {
    const { page, context } = await open(enforceUrl + "#/zasahy");
    assert((await page.locator(".mode-banner.is-enforce").count()) === 1, "chybi ostry banner");
    await page.locator('[data-action="enf-approve"]').first().click();
    await page.waitForSelector("dialog.modal[open]");
    assert(/zablokována na bráně/.test((await page.locator("dialog.modal p").textContent()) ?? ""), "dialog nevaruje");
    await page.click('dialog.modal button[value="cancel"]');
    await context.close();
  });

  await test("Zasahy: role bez prava schvalovat dostane vypnute tlacitka s vysvetlenim (403)", async () => {
    const { page, context } = await open(analystUrl + "#/zasahy");
    await page.locator('[data-action="enf-approve"]').first().click();
    await page.waitForSelector("dialog.modal[open]");
    await page.click('dialog.modal button[value="yes"]');
    await page.waitForSelector('[data-action="enf-approve"][disabled]');
    assert(/operátor nebo správce/.test((await page.locator("#deny-why").first().textContent()) ?? ""), "chybi vysvetleni");
    await context.close();
  });

  await test("Audit: zaznamy jsou videt, integrita retezce se hlasi (v poradku i narusena)", async () => {
    const ok = await open(base + "#/audit");
    await ok.page.waitForSelector("table.data tbody tr");
    assert(/řetěz v pořádku/.test((await ok.page.locator(".pane-tools").textContent()) ?? ""), "chybi odznak v poradku");
    await ok.context.close();
    const bad = await open(brokenChainUrl + "#/audit");
    await bad.page.waitForSelector("table.data tbody tr");
    assert(/řetěz narušen/.test((await bad.page.locator(".pane-tools").textContent()) ?? ""), "chybi odznak narusen");
    assert((await bad.page.locator('.chip-hot[role="alert"]').count()) === 1, "narusena integrita nema role=alert");
    await bad.context.close();
    const none = await open(emptyUrl + "#/audit");
    await none.page.waitForSelector(".empty");
    assert(/Audit není dostupný/.test((await none.page.locator("#stage").textContent()) ?? ""), "404 audit neni poctivy prazdny stav");
    await none.context.close();
  });

  await test("Automat: stav, pripravenost a schopnosti se vykresli; agresivni rezim vyzaduje potvrzeni", async () => {
    const { page, context } = await open(base + "#/automat");
    assert((await page.locator(".phases li").count()) === 4, "chybi faze autopilota");
    assert((await page.locator(".grade-dm svg").count()) === 1, "chybi znamka pripravenosti");
    await page.selectOption('select[data-action="pentest-mode"]', "aggressive");
    await page.click('[data-action="auto-restart"]');
    await page.waitForSelector("dialog.modal[open]");
    await page.click('dialog.modal button[value="cancel"]');
    await context.close();
  });

  await test("Asistent: otevre se, odpoved se streamuje, Esc zavre", async () => {
    const { page, context } = await open(base);
    await page.click('[data-global="assistant-toggle"]');
    assert(await page.locator("#assistant").isVisible(), "asistent se neotevrel");
    await page.fill("#chatInput", "Co mam overit jako prvni?");
    await page.keyboard.press("Tab");
    await page.click('#chatForm button[type="submit"]');
    await page.waitForFunction(() => /nejdřív ověř službu/.test(document.querySelector("#chatLog")?.textContent ?? ""));
    await page.keyboard.press("Escape");
    assert(!(await page.locator("#assistant").isVisible()), "Esc asistenta nezavrel");
    await context.close();
  });

  await test("Tmavy/svetly rezim: prepinac nastavi data-theme a respektuje system", async () => {
    const dark = await open(base, undefined, { colorScheme: "dark" });
    const bgDark = await dark.page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    await dark.page.click("details.menu > summary");
    await dark.page.click('[data-global="theme"]');
    const attr = await dark.page.evaluate(() => document.documentElement.dataset.theme);
    const bgLight = await dark.page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    assert(attr === "light" && bgDark !== bgLight, `prepnuti nefunguje (attr=${attr}, ${bgDark} -> ${bgLight})`);
    await dark.context.close();
  });

  await test("Prazdny server: Prehled rika, ze neni zadny beh, a nabidne dalsi krok", async () => {
    const { page, context, problems } = await open(emptyUrl);
    const text = (await page.locator("#stage").textContent()) ?? "";
    assert(/Zatím žádný běh/.test(text), "chybi prazdny stav");
    assert(problems.length === 0, `chyby: ${problems.join(" | ")}`);
    await context.close();
  });

  await test("Token: pri 401 se objevi dialog, po zadani tokenu se data nactou (token jen v sessionStorage)", async () => {
    const { page, context } = await open(authUrl, undefined, {}, "domcontentloaded");
    assert(page, "UI se bez tokenu vubec nevykreslilo");
    await page.waitForSelector("dialog.modal[open]");
    await page.fill('dialog.modal input[name="token"]', "test");
    await page.click('dialog.modal button[value="ok"]');
    await page.waitForFunction(() => document.querySelector(".pebble") !== null, null, { timeout: 8000 });
    const stored = await page.evaluate(() => ({ s: sessionStorage.getItem("bakulaApiToken"), l: localStorage.getItem("bakulaApiToken") }));
    assert(stored.s === "test" && stored.l === null, `token je ulozen spatne: ${JSON.stringify(stored)}`);
    await context.close();
  });

  await test("Dostupnost: tlacitka/formulare maji nazvy, dok ma aria-current, velke cile >= 44 px na telefonu", async () => {
    const { page, context } = await open(base, { width: 390, height: 844 });
    for (const section of ["prehled", "hostitele", "nalezy", "overovani", "zasahy", "audit", "automat"]) {
      await page.evaluate((s) => { window.location.hash = `#/${s}`; }, section);
      await page.waitForTimeout(200);
      const report = await page.evaluate(() => {
        const out = { unnamed: [], small: [] };
        const visible = (el) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== "hidden"; };
        document.querySelectorAll("button, a[href], input, select, textarea, summary, [role=button]").forEach((el) => {
          if (!visible(el)) return;
          const name = (el.getAttribute("aria-label") || el.textContent || el.getAttribute("placeholder") || "").trim() || (el.labels && el.labels[0]?.textContent?.trim()) || el.getAttribute("title");
          if (!name) out.unnamed.push(el.outerHTML.slice(0, 80));
          const r = el.getBoundingClientRect();
          const exempt = el.classList.contains("link") || el.closest(".pebble-field") || el.closest(".dock") && r.height >= 44;
          if (!exempt && (r.height < 43 || r.width < 43)) out.small.push(`${el.tagName}.${el.className} ${Math.round(r.width)}x${Math.round(r.height)}`);
        });
        return out;
      });
      assert(report.unnamed.length === 0, `${section}: prvky bez nazvu: ${report.unnamed.join(" | ")}`);
      assert(report.small.length === 0, `${section}: male dotykove cile: ${report.small.join(" | ")}`);
    }
    assert((await page.locator('.dock-item[aria-current="page"]').count()) === 1, "dok nema aktivni polozku");
    await context.close();
  });

  await test("Pohyb: pri prefers-reduced-motion se oblazky nehybou", async () => {
    const { page, context } = await open(base, undefined, { reducedMotion: "reduce" });
    const name = await page.locator(".pebble").first().evaluate((el) => getComputedStyle(el).animationName);
    assert(name === "none", `animace bezi i pri reduced-motion (${name})`);
    await context.close();
  });
} finally {
  await browser.close();
  servers.forEach((server) => server.kill());
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} testu proslo`);
process.exit(failed.length ? 1 : 0);
