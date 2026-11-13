// E2E nad novym UI: Edge v headless rezimu + maketa API (scripts/mock-server.mjs).
// Nikdy neotevira okno na plose uzivatele.
import { chromium } from "playwright-core";
import { spawn } from "node:child_process";

const EDGE = process.env.EDGE_PATH ?? "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe";
const results = [];
const servers = [];
// vice behu testu naraz (ruzni vyvojari) si nesmi brat porty: E2E_PORT_BASE=8850 posune vsechny
const PORT_BASE = Number(process.env.E2E_PORT_BASE ?? 8800);

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
  const base = await startMock(PORT_BASE + 1);
  const analystUrl = await startMock(PORT_BASE + 2, { MOCK_ROLE: "analyst" });
  const brokenChainUrl = await startMock(PORT_BASE + 3, { MOCK_CHAIN_BAD: "1" });
  const emptyUrl = await startMock(PORT_BASE + 4, { MOCK_EMPTY: "1" });
  const enforceUrl = await startMock(PORT_BASE + 5, { MOCK_MODE: "enforce" });
  const authUrl = await startMock(PORT_BASE + 6, { MOCK_AUTH: "1" });
  const showUrl = await startMock(PORT_BASE + 9, { MOCK_SHOWCASE: "1" });

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
    const count = await page.locator(".node").count();
    // 3 skenovane stanice + 13 sitovych prvku znamych jen z inventare (networkAssets); male site se otevrou rovnou do zarizeni
    assert(count === 16, `ocekavano 16 uzlu, nalezeno ${count}`);
    await page.locator(".node").first().click({ force: true });
    assert((await page.locator(".host-card .host-ip").count()) === 1, "po kliku se nezobrazila karta stanice");
    await page.locator(".node").nth(1).focus();
    await page.keyboard.press("Enter");
    const ip = await page.locator(".host-card .host-ip").textContent();
    assert(/192\.168\.56\.\d+/.test(ip ?? ""), "klavesnice (Enter) stanici nevybrala");
    const label = await page.locator(".node").first().getAttribute("aria-label");
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
    assert(/Zatím žádný běh/.test((await empty.page.locator("#stage").textContent()) ?? ""), "prazdny server: chybi poctivy prazdny stav (a dalsi krok)");
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
    assert(/zablokována na bráně/.test((await page.locator("dialog.modal p").first().textContent()) ?? ""), "dialog nevaruje");
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
    await page.waitForFunction(() => document.getElementById("assistant")?.getBoundingClientRect().width > 100, null, { timeout: 3000 }).catch(() => {});
    assert(await page.locator("#assistant").isVisible(), "asistent se neotevrel");
    await page.fill("#chatInput", "Co mam overit jako prvni?");
    await page.keyboard.press("Tab");
    await page.click('#chatForm button[type="submit"]');
    await page.waitForFunction(() => /nejdřív ověř službu/.test(document.querySelector("#chatLog")?.textContent ?? ""));
    await page.keyboard.press("Escape");
    // zavreni je animovane (~0,4 s): okno zmizi az po dokonceni prechodu
    await page.waitForFunction(() => document.getElementById("assistant")?.hidden === true, null, { timeout: 3000 });
    assert(!(await page.locator("#assistant").isVisible()), "Esc asistenta nezavrel");
    assert(await page.evaluate(() => document.activeElement?.getAttribute("data-global") === "assistant-toggle"), "fokus se po zavreni nevratil na tlacitko Asistent");
    await context.close();
  });

  await test("Asistent: po otevreni ma fokus pole zpravy, aria-expanded sedi, na telefonu je pres celou obrazovku", async () => {
    const { page, context } = await open(base);
    await page.click('[data-global="assistant-toggle"]');
    assert(await page.evaluate(() => document.activeElement?.id === "chatInput"), "fokus neni v poli zpravy");
    assert((await page.getAttribute('[data-global="assistant-toggle"]', "aria-expanded")) === "true", "aria-expanded neni true");
    await page.waitForTimeout(600);
    const box = await page.evaluate(() => { const r = document.getElementById("assistant").getBoundingClientRect(); const b = document.querySelector(".bar").getBoundingClientRect(); const i = document.getElementById("infoband").getBoundingClientRect(); return { top: r.top, barBottom: b.bottom, infoBottom: i.bottom }; });
    assert(box.top >= box.barBottom - 1, `asistent zasahuje do listy/pasu (${JSON.stringify(box)})`);
    await page.click('[data-global="assistant-close"]');
    await page.waitForFunction(() => document.getElementById("assistant")?.hidden === true, null, { timeout: 3000 });
    await context.close();
    const phone = await open(base, { width: 390, height: 844 });
    await phone.page.click('[data-global="assistant-toggle"]');
    await phone.page.waitForTimeout(600);
    const full = await phone.page.evaluate(() => { const r = document.getElementById("assistant").getBoundingClientRect(); return [Math.round(r.width), Math.round(r.height)]; });
    assert(full[0] === 390 && full[1] === 844, `na telefonu neni pres celou obrazovku: ${full}`);
    await phone.context.close();
  });

  await test("Horni lista: informacni pas ma jen skutecna data a plny vypis v rozbalovaci nabidce", async () => {
    const { page, context } = await open(base);
    const text = (await page.locator("#infoband").textContent()) ?? "";
    assert(/rozsah/.test(text) && /profil/.test(text) && /před \d+ (min|h|dny)|před okamžikem/.test(text), `chybi rozsah/profil/cas: ${text}`);
    assert(/server/.test(text) && /autopilot/.test(text) && /API/.test(text), "chybi server/autopilot/token");
    assert(!/Mbit|rychlost|latence/i.test(text), "pas ukazuje nepodlozene hodnoty");
    await page.click("#infoMenu summary");
    const rows = await page.locator("#infoMenu .irow").count();
    assert(rows >= 8, `plny vypis ma jen ${rows} radku`);
    await context.close();
  });

  await test("Dok: bubliny vyplnuji vysku, polozky se neprekryvaji, aktivni kapka sedi na aktivni polozce", async () => {
    for (const height of [480, 600, 700, 900, 1200]) {
      const { page, context } = await open(base, { width: 1440, height });
      await page.waitForTimeout(700);
      const m = await page.evaluate(() => {
        const items = [...document.querySelectorAll(".dock-item")].map((e) => e.getBoundingClientRect());
        const dockEl = document.getElementById("dock"); const dock = dockEl.getBoundingClientRect(); const overflow = dockEl.scrollHeight - dockEl.clientHeight;
        const core = document.querySelector(".dock-core").getBoundingClientRect();
        const active = document.querySelector(".dock-item.is-active").getBoundingClientRect();
        return { tops: items.map((r) => r.top), bottoms: items.map((r) => r.bottom), dockBottom: dock.bottom, overflow, coreY: core.top + core.height / 2, activeY: active.top + active.height / 2, h: items[0].height };
      });
      for (let i = 1; i < m.tops.length; i++) assert(m.tops[i] >= m.bottoms[i - 1] - 0.5, `${height}: polozky se prekryvaji`);
      assert(m.overflow <= 1, `${height}: dok se musi posouvat (preteka o ${m.overflow} px)`);
      assert(m.h >= 44, `${height}: polozka ma jen ${m.h} px`);
      assert(Math.abs(m.coreY - m.activeY) < 2, `${height}: aktivni kapka nesedi na polozce`);
      if (height >= 900) assert(m.dockBottom - m.bottoms[m.bottoms.length - 1] < 40, `${height}: dole zustava prazdne misto`);
      await context.close();
    }
  });

  await test("Cisla: velka cisla jsou bodove pismo s aria-label, jeden goo path (uzly spojene metaball mosty)", async () => {
    const { page, context } = await open(base);
    const info = await page.evaluate(() => { const svg = document.querySelector(".readout-num .dm"); return { label: svg?.getAttribute("aria-label"), paths: svg?.querySelectorAll("path").length, lines: svg?.querySelectorAll("line, circle").length, curves: (svg?.querySelector("path")?.getAttribute("d") ?? "").split("C").length - 1 }; });
    assert(info.label && /^\d+$/.test(info.label) && info.paths === 1 && info.lines === 0 && info.curves > 3, `bodove cislo je spatne: ${JSON.stringify(info)}`);
    await context.close();
  });

  await test("Tmavy/svetly rezim: prepinac nastavi data-theme a respektuje system", async () => {
    const dark = await open(base, undefined, { colorScheme: "dark" });
    const bgDark = await dark.page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    await dark.page.click("#moreMenu > summary");
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
    await page.waitForFunction(() => document.querySelector(".node") !== null, null, { timeout: 8000 });
    const stored = await page.evaluate(() => ({ s: sessionStorage.getItem("salticusApiToken"), l: localStorage.getItem("salticusApiToken") }));
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
          const exempt = el.classList.contains("link") || el.closest(".netmap") || el.closest(".dock") && r.height >= 44;
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

  // ---------- UX audit: bezpecnostne citlive toky a stavy ----------
  await test("Zasahy (ostry rezim): schvaleni bez potvrzeni neprojde, dialog ukaze co presne, vychozi fokus je Zrusit, Esc nic neprovede", async () => {
    const { page, context } = await open(enforceUrl + "#/zasahy");
    const posts = [];
    page.on("request", (r) => { if (r.method() === "POST" && /enforcement\/\d+\/(approve|reject)/.test(r.url())) posts.push(r.url()); });
    const before = await page.locator(".action").first().textContent();
    await page.locator('[data-action="enf-approve"]').first().click();
    await page.waitForSelector("dialog.modal[open]");
    const dialog = (await page.locator("dialog.modal").textContent()) ?? "";
    assert(/Adresa/.test(dialog) && /Platnost/.test(dialog) && /Důvod/.test(dialog), "dialog neukazuje adresu, platnost a duvod");
    assert(/předčasně zrušit nejde/.test(dialog), "dialog nerika, ze blok nejde predcasne zrusit");
    const focused = await page.evaluate(() => document.activeElement?.getAttribute("value"));
    assert(focused === "cancel", `vychozi fokus u ostreho zasahu neni Zrusit (je ${focused})`);
    await page.keyboard.press("Enter"); // nahodny Enter = zruseni
    await page.waitForFunction(() => !document.querySelector("dialog.modal"));
    await page.locator('[data-action="enf-approve"]').first().click();
    await page.waitForSelector("dialog.modal[open]");
    await page.keyboard.press("Escape");
    await page.waitForFunction(() => !document.querySelector("dialog.modal"));
    assert(posts.length === 0, `po zruseni odesel pozadavek: ${posts.join(",")}`);
    assert((await page.locator(".action").first().textContent()) === before, "stav zasahu se po zruseni zmenil");
    assert(await page.locator('[data-action="enf-approve"]').first().isEnabled(), "tlacitko Schvalit zustalo zamcene");
    await context.close();
  });

  await test("Zasahy (ostry rezim): po potvrzeni se zasah provede prave jednou a ohlasi se ctecce (aria-live) i viditelne", async () => {
    const { page, context } = await open(enforceUrl + "#/zasahy");
    const posts = [];
    page.on("request", (r) => { if (r.method() === "POST" && /enforcement\/\d+\/approve/.test(r.url())) posts.push(r.url()); });
    await page.locator('[data-action="enf-approve"]').first().click();
    await page.waitForSelector("dialog.modal[open]");
    await page.click('dialog.modal button[value="yes"]');
    await page.waitForFunction(() => /zablokovaná na bráně/.test(document.getElementById("announcer")?.textContent ?? ""));
    assert(/zablokovaná na bráně/.test((await page.locator("#toast").textContent()) ?? ""), "chybi viditelne potvrzeni");
    assert((await page.locator("#announcer").getAttribute("aria-live")) === "polite", "announcer neni aria-live");
    assert(posts.length === 1, `schvaleni odeslo ${posts.length}x`);
    await page.waitForFunction(() => /blok aktivní/.test(document.querySelector(".actions")?.textContent ?? ""));
    assert(/Blok sám skončí/.test((await page.locator(".actions").textContent()) ?? ""), "u aktivniho bloku chybi vysvetleni, ze nejde predcasne zrusit");
    await context.close();
  });

  await test("Zasahy: zjevne chranena IP se odmitne hned v prohlizeci (bez dotazu na server), s vysvetlenim a bez zmeny seznamu", async () => {
    const { page, context } = await open(base + "#/zasahy");
    const posts = [];
    page.on("request", (r) => { if (r.method() === "POST" && /enforcement\/propose/.test(r.url())) posts.push(r.url()); });
    const countBefore = await page.locator(".action").count();
    for (const ip of ["127.0.0.1", "169.254.10.4", "224.0.0.5", "::1", "300.1.1.1"]) {
      await page.fill('input[name="ip"]', ip);
      const hint = (await page.locator("#ip-hint").textContent()) ?? "";
      assert(hint.length > 10, `${ip}: zivy popisek se neukazal`);
      assert((await page.locator('input[name="ip"]').getAttribute("aria-invalid")) === "true", `${ip}: pole neni aria-invalid`);
      await page.fill('input[name="reason"]', "test");
      await page.click('form.propose button[type="submit"]');
      await page.waitForSelector(".form-error");
      assert((await page.locator('.form-error[role="alert"]').count()) === 1, `${ip}: chyba neni role=alert`);
    }
    assert(posts.length === 0, `chranena IP se poslala na server (${posts.length}x)`);
    assert((await page.locator(".action").count()) === countBefore, "seznam zasahu se zmenil");
    // adresa vlastni stanice: varovani, ale server rozhoduje
    const own = await page.evaluate(async () => {
      const runs = await (await fetch("/api/runs")).json();
      const run = await (await fetch(`/api/runs/${runs[0].run_id}`)).json();
      return run.hosts[0].ip;
    });
    await page.fill('input[name="ip"]', own);
    assert(/patří stanici/.test((await page.locator("#ip-hint").textContent()) ?? ""), "adresa vlastni stanice nema varovani");
    await context.close();
  });

  await test("Zasahy: navrh z nalezu je oznacen jako blok vlastni stanice a ukaze varovani pred odeslanim", async () => {
    const { page, context } = await open(base + "#/nalezy");
    await page.locator(".row").first().click();
    const btn = page.locator('[data-action="propose-block"]');
    assert(/blok této stanice/.test((await btn.textContent()) ?? ""), "tlacitko nerika, ze blokuje vlastni stanici");
    await btn.click();
    await page.waitForSelector("form.propose");
    assert(/patří stanici/.test((await page.locator("#ip-hint").textContent()) ?? ""), "predvyplnena adresa vlastni stanice nema varovani");
    await context.close();
  });

  await test("Overovani: cekajici schvaleni je vysvetleno (co se provede, riziko, schvaleni), schvalit v UI nejde a UI to rika", async () => {
    const { page, context } = await open(base + "#/overovani");
    assert(/nikdy nespustí samy/.test((await page.locator(".approval-note").textContent()) ?? ""), "chybi upozorneni na cekajici schvaleni");
    await page.locator("details.plan summary").first().click();
    const box = (await page.locator(".chosen-box").first().textContent()) ?? "";
    assert(/Co se provede/.test(box) && /riziko narušení/.test(box) && /schválení/.test(box), "chybi popis kontroly, riziko nebo schvaleni");
    assert(/schvalovat nejde/.test((await page.locator(".approval-note").textContent()) ?? ""), "UI nerika, ze se tu schvalovat neda");
    assert((await page.locator('[data-action*="approve"]').count()) === 0, "v Overovani nesmi byt falesne schvalovaci tlacitko");
    await context.close();
  });

  await test("Automat: bezici autopilot jde zastavit s vysvetlenim dopadu; druhy se nespusti; pentest je vychozi vypnuty", async () => {
    const runningUrl = await startMock(PORT_BASE + 7, { MOCK_RUNNING: "1" });
    const { page, context } = await open(runningUrl + "#/automat");
    assert(await page.locator('[data-action="auto-stop"]').isVisible(), "chybi tlacitko Zastavit autopilota");
    assert(await page.locator('[data-action="auto-restart"]').isDisabled(), "novy beh jde spustit pri bezicim autopilotu");
    await page.click('[data-action="auto-stop"]');
    await page.waitForSelector("dialog.modal[open]");
    assert(/ukončí běžící proces/.test((await page.locator("dialog.modal").textContent()) ?? ""), "dialog nevysvetluje dopad zastaveni");
    await page.click('dialog.modal button[value="cancel"]');
    assert(await page.locator('[data-action="auto-stop"]').isVisible(), "zruseni zastavilo autopilota");
    await page.click('[data-action="auto-stop"]');
    await page.waitForSelector("dialog.modal[open]");
    await page.click('dialog.modal button[value="yes"]');
    await page.waitForFunction(() => /Autopilot zastaven/.test(document.getElementById("announcer")?.textContent ?? ""));
    await page.waitForFunction(() => !document.querySelector('[data-action="auto-stop"]'), null, { timeout: 8000 });
    await context.close();
    const fresh = await open(base + "#/automat");
    assert((await fresh.page.locator('select[data-action="pentest-mode"]').inputValue()) === "off", "vychozi rezim pentestu neni vypnuty");
    await fresh.context.close();
  });

  await test("Mapa: jedno tabulatorove zastaveni, sipky chodi mezi stanicemi, krok skoku vybere stanici", async () => {
    const { page, context } = await open(base);
    assert((await page.locator('.node[tabindex="0"]').count()) === 1, "mapa ma vic nez jedno tabulatorove zastaveni");
    const hop = page.locator("button.hop-btn").first();
    if (await hop.count()) {
      const host = await hop.getAttribute("data-host");
      await hop.click();
      assert((await page.locator(`.node[data-host="${host}"]`).getAttribute("aria-pressed")) === "true", "klik na skok nevybral stanici");
    }
    await page.locator('.node[tabindex="0"]').focus();
    await page.keyboard.press("ArrowRight");
    await page.keyboard.press("ArrowLeft");
    assert((await page.locator('.node[tabindex="0"]').count()) === 1, "po sipkach neni prave jedno tabulatorove zastaveni");
    await context.close();
  });


  // ---------- mapa: semanticky zoom, filtry, profil ----------
  const settle = (page, ms = 1100) => page.waitForTimeout(ms);

  await test("Mapa (prehled): vychozi pohled jsou zony s popiskem, ne stovky bublin; klik zonu rozkvete, Esc vrati zpet", async () => {
    const { page, context, problems } = await open(showUrl);
    await settle(page);
    assert((await page.locator(".zone").count()) === 4, "ocekavany 4 zony (VLAN 10, 20, 30, 40)");
    assert((await page.locator(".zone.is-open").count()) === 0, "v prehledu nema byt zadna zona rozbalena");
    const label = await page.locator(".zbub").first().getAttribute("aria-label");
    assert(/VLAN \d+.*zařízení.*nálezů/.test(label ?? ""), `zona nema popisek: ${label}`);
    assert(/Celá síť/.test((await page.locator(".crumbs").textContent()) ?? ""), "chybi drobeckova navigace");
    await page.locator('.zbub[data-zone="vlan:30"]').click({ force: true });
    await settle(page);
    assert((await page.locator(".zone.is-open").count()) === 1, "klik nerozbalil prave jednu zonu");
    assert(/VLAN 30/.test((await page.locator(".crumbs").textContent()) ?? ""), "drobecek nerika, kde jsem");
    assert(/#\/prehled\?v=vlan%3A30/.test(await page.evaluate(() => location.hash)), "stav filtru neni v adrese");
    assert(/Podsíť/.test((await page.locator(".stats .eyebrow").first().textContent()) ?? ""), "panel nerika Podsit");
    await page.keyboard.press("Escape");
    await settle(page, 900);
    assert((await page.locator(".zone.is-open").count()) === 0, "Esc nevratil prehled");
    assert(!/\?v=/.test(await page.evaluate(() => location.hash)), "adresa si pamatuje zrusenou zonu");
    assert(problems.length === 0, `chyby: ${problems.join(" | ")}`);
    await context.close();
  });

  await test("Mapa (filtry): jen AP, hledani, 'Zobrazeno N z M', zruseni filtru a sdileny odkaz", async () => {
    const { page, context } = await open(showUrl);
    await settle(page, 600);
    await page.locator('.mb-toggle').click(); // filtry jsou v rozbalovacim panelu, ve vychozim stavu zavrenem
    await settle(page, 300);
    await page.locator('.mchip[data-kind="ap"]').click();
    await settle(page);
    assert(/Zobrazeno 4 z 100/.test((await page.locator(".mb-shown").textContent()) ?? ""), "filtr AP nehlasi Zobrazeno 4 z 100");
    assert(/Zobrazeno 4 z 100/.test((await page.locator("#mapLive").textContent()) ?? ""), "zmenu nehlasi ctecka (aria-live)");
    assert((await page.locator(".node:not(.is-off)").count()) === 4, "viditelna maji zustat jen 4 AP");
    assert((await page.locator('.mchip[data-kind="ap"]').getAttribute("aria-pressed")) === "true", "cip nema aria-pressed");
    assert(/t=ap/.test(await page.evaluate(() => location.hash)), "filtr neni v adrese");
    await page.locator('[data-action="clear-filter"]').click();
    await settle(page, 700);
    assert((await page.locator(".node.is-off").count()) === 0, "zruseni filtru nevratilo vse");
    await page.locator("#mapSearch").fill("hikvision");
    await settle(page, 900);
    const shown = (await page.locator(".mb-shown").textContent()) ?? "";
    assert(/Zobrazeno \d+ z 100/.test(shown) && !/Zobrazeno 100/.test(shown), `hledani vyrobce nefiltruje: ${shown}`);
    const hash = await page.evaluate(() => location.hash);
    const second = await open(showUrl + hash);
    await second.page.waitForTimeout(900);
    assert(/Zobrazeno \d+ z 100/.test((await second.page.locator(".mb-shown").textContent()) ?? ""), "odkaz s filtrem filtr neobnovil");
    assert((await second.page.locator("#mapSearch").inputValue()) === "hikvision", "hledany text se z adresy nenacetl");
    await second.context.close();
    await context.close();
  });

  await test("Mapa (profil): duvody rozpoznani, sluzby srozumitelne, chovani, kontroly agenta; nerozpoznane rika 'neznamé, protoze'", async () => {
    const { page, context } = await open(showUrl + "#/prehled?v=vlan%3A30");
    await settle(page);
    await page.locator('.node[data-host="10.20.3.31"]').click({ force: true });
    const text = (await page.locator(".profile").textContent()) ?? "";
    assert(/Proč si to myslíme/.test(text) && /Jistota rozpoznání/.test(text), "chybi duvody a jistota rozpoznani");
    assert(/RTSP: video proud z kamery/.test(text), "port neni vysvetlen lidsky");
    assert(/Chování v síti/.test(text) && /6×/.test(text), "chybi chovani s pocty z udalosti");
    assert(/provedeno/.test(text) && /krok 1 cesty skoků/.test(text), "chybi kontrola agenta s krokem cesty skoku");
    assert(/Připojeno přes/.test(text) && /gw-brana/.test(text), "chybi retez pripojeni z topologie");
    assert((await page.locator('.node[data-host="10.20.3.31"] .agent').count()) === 1, "uzel nema indikator agenta");
    await page.evaluate(() => { location.hash = "#/prehled?v=vlan%3A10&h=10.20.1.30"; });
    await settle(page, 800);
    const unk = (await page.locator(".profile").textContent()) ?? "";
    assert(/Neznámé zařízení, protože/.test(unk) && /aktivním skenem/.test(unk), `nerozpoznane zarizeni nema uprimne vysvetleni: ${unk.slice(0, 200)}`);
    await context.close();
  });

  await test("Mapa (statistika): panel Podsit a cela sit maji cisla z dat (typy, nalezy, pokryti identity)", async () => {
    const { page, context } = await open(showUrl);
    await settle(page, 600);
    const all = (await page.locator(".stats").textContent()) ?? "";
    assert(/Celá síť/.test(all) && /Pokrytí identity/.test(all) && /Nálezy podle závažnosti/.test(all), "statistika cele site neni uplna");
    await page.locator('.mb-toggle').click();
    await settle(page, 300);
    await page.locator('.mchip[data-zone="vlan:30"]').click();
    await settle(page);
    const vlan = (await page.locator(".stats").textContent()) ?? "";
    assert(/VLAN 30/.test(vlan) && /Kamera/.test(vlan) && /Tiskárna/.test(vlan), "statistika podsite nema typy zarizeni");
    await context.close();
  });

  await test("Mapa (mobil 390): filtry v rozbalovacim panelu bez vodorovneho scrollu, profil jako spodni panel, cile >= 44 px, bez stranky scrollu", async () => {
    const { page, context } = await open(showUrl, { width: 390, height: 844 });
    await settle(page);
    await page.locator('[data-action="toggle-bar"]').click();
    const small = await page.evaluate(() =>
      [...document.querySelectorAll(".mapbar button, .mapbar input")]
        .filter((e) => e.getBoundingClientRect().width > 0 && e.getBoundingClientRect().height < 43)
        .map((e) => `${e.className} ${Math.round(e.getBoundingClientRect().height)}`),
    );
    assert(small.length === 0, `male dotykove cile ve filtrech: ${small.join(", ")}`);
    assert(await page.evaluate(() => [...document.querySelectorAll(".chiprow")].every((r) => r.scrollWidth <= r.clientWidth + 1)), "cipy presahuji sirku panelu (vodorovny scroll)");
    await page.locator('[data-action="toggle-bar"]').click();
    await page.evaluate(() => { location.hash = "#/prehled?v=vlan%3A30&h=10.20.3.31"; });
    await settle(page, 900);
    const box = await page.locator(".profile").boundingBox();
    assert(box && box.y > 250 && box.y + box.height <= 845, `profil neni spodni panel: ${JSON.stringify(box)}`);
    assert((await page.evaluate(() => document.documentElement.scrollHeight - innerHeight)) <= 1, "stranka scrolluje");
    await context.close();
  });

  await test("Mapa (vykon): 100 zarizeni se rozkvete a filtruje bez dlouhych snimku", async () => {
    const { page, context } = await open(showUrl);
    await settle(page, 600);
    const r = await page.evaluate(async () => {
      const raf = () => new Promise((res) => requestAnimationFrame(res));
      const frames = [];
      let last = performance.now();
      let go = true;
      void (async () => {
        while (go) {
          await raf();
          const t = performance.now();
          frames.push(t - last);
          last = t;
        }
      })();
      document.querySelector('.zbub[data-zone="vlan:40"]').dispatchEvent(new MouseEvent("click", { bubbles: true }));
      await new Promise((res) => setTimeout(res, 1200));
      document.querySelector('.mchip[data-kind="ap"]').click();
      await new Promise((res) => setTimeout(res, 1200));
      go = false;
      frames.sort((a, b) => a - b);
      return { n: frames.length, p50: frames[Math.floor(frames.length / 2)], p95: frames[Math.floor(frames.length * 0.95)], max: frames[frames.length - 1] };
    });
    console.log(`       (info) snimky: n=${r.n}, p50=${r.p50.toFixed(1)} ms, p95=${r.p95.toFixed(1)} ms, max=${r.max.toFixed(1)} ms`);
    assert(r.p95 < 60, `p95 snimku ${r.p95.toFixed(1)} ms je moc`);
    await context.close();
  });

  await test("Chybovy stav: server nedostupny -> srozumitelna hlaska a Zkusit znovu (cerstvy start i vypadek za behu)", async () => {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const p2 = await ctx.newPage();
    await p2.route("**/api/**", (route) => route.abort());
    await p2.goto(base);
    await p2.waitForSelector(".dock-item");
    await p2.waitForFunction(() => /Server neodpovídá/.test(document.querySelector("#stage")?.textContent ?? ""), null, { timeout: 8000 });
    assert(!/Zatím žádný běh/.test((await p2.locator("#stage").textContent()) ?? ""), "vypadek serveru se tvari jako prazdny server");
    assert(await p2.locator('#stage [data-global="retry"]').isVisible(), "chybi tlacitko Zkusit znovu na prazdne obrazovce");
    await p2.unroute("**/api/**");
    await p2.click('#stage [data-global="retry"]');
    await p2.waitForSelector(".node", { timeout: 8000 });
    // vypadek za behu: stranka s daty zustane, ale chybova lista nabidne opakovani
    await p2.route("**/api/**", (route) => route.abort());
    await p2.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
    await p2.waitForSelector('#errorbar [data-global="retry"]', { timeout: 8000 });
    assert(/bez spojení/.test((await p2.locator(".status-text").textContent()) ?? ""), "stav spojeni neni videt v liste");
    await ctx.close();
  });

  await test("Audit: akce maji srozumitelny popis, narusene retezec upozorni (role=alert) s dalsim krokem", async () => {
    const ok = await open(base + "#/audit");
    await ok.page.waitForSelector("table.data tbody tr");
    const text = (await ok.page.locator("table.data").textContent()) ?? "";
    assert(/Zásah navržen/.test(text) && /Zásah schválen/.test(text), "kody akci nejsou prelozene");
    await ok.context.close();
    const bad = await open(brokenChainUrl + "#/audit");
    await bad.page.waitForSelector("table.data tbody tr");
    assert(/nespoléhej/.test((await bad.page.locator('.approval-note[role="alert"]').textContent()) ?? ""), "chybi vysvetleni a dalsi krok pri narusenem retezci");
    await bad.context.close();
  });

  await test("Pohyb: pri prefers-reduced-motion se tecka skoku nehybe", async () => {
    const { page, context } = await open(base, undefined, { reducedMotion: "reduce" });
    assert((await page.locator(".netmap animateMotion").count()) === 0, "skakajici tecka bezi i pri reduced-motion");
    await context.close();
  });
} finally {
  await browser.close();
  servers.forEach((server) => server.kill());
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} testu proslo`);
process.exit(failed.length ? 1 : 0);
