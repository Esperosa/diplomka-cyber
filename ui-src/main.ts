import { api, getToken, setAuthHandler, setToken } from "./api";
import { renderLog, sendPrompt, setAssistantOpen, shellHtml, watchAssistantLayout } from "./assistant";
import { FILTER_DEFS } from "./filters";
import { infoBandHtml } from "./infoband";
import { afterStageRender, initRipple } from "./motion";
import { refreshAll, refreshAudit, refreshEnforcement } from "./data";
import { tokenDialog } from "./dialogs";
import { parseHash, navigate } from "./router";
import { onChange, state, update, type SectionId, type View } from "./state";
import { countdown, esc } from "./ui";
import { metaballBridge } from "./metaball";
import type { PentestMode } from "./types";
import { audit } from "./views/audit";
import { automation } from "./views/automation";
import { enforcement } from "./views/enforcement";
import { findings } from "./views/findings";
import { hosts } from "./views/hosts";
import { overview } from "./views/overview";
import { verification } from "./views/verification";

const VIEWS: View[] = [overview, hosts, findings, verification, enforcement, audit, automation];
const root = document.querySelector<HTMLDivElement>("#app");
if (!root) throw new Error("UI root #app nebyl nalezen.");
const app: HTMLDivElement = root;

let stage!: HTMLElement;
let dirty = false;
let tokenDismissed = false;

// ---------- motiv ----------
function applyTheme() {
  if (state.theme === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.dataset.theme = state.theme;
  const button = app.querySelector<HTMLButtonElement>("[data-global='theme']");
  if (button) button.textContent = effectiveDark() ? "Světlý režim" : "Tmavý režim";
}
function effectiveDark() {
  return state.theme === "dark" || (state.theme === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
}

// ---------- kostra ----------
function renderShell() {
  app.innerHTML = `
  ${FILTER_DEFS}
  <a class="skip" href="#stage">Přeskočit na obsah</a>
  <div class="shell">
    <header class="bar">
      <span class="wordmark">Skákavka</span>
      <label class="run-pick"><span class="sr-only">Běh</span><select id="runSelect" aria-label="Běh"></select></label>
      <span class="status" id="status" role="status"><span class="pulse" data-state="idle"></span><span class="status-text"></span></span>
      <section class="infoband" id="infoband" aria-label="Kde jsem"></section>
      <span class="spacer"></span>
      <button type="button" class="btn btn-ghost" data-global="assistant-toggle" aria-controls="assistant" aria-expanded="false">Asistent</button>
      <details class="menu" id="moreMenu">
        <summary class="btn btn-ghost" aria-label="Další volby">Více</summary>
        <div class="menu-pop" role="group" aria-label="Další volby">
          <button type="button" class="menu-item" data-global="theme">Tmavý režim</button>
          <button type="button" class="menu-item" data-global="token" hidden>Token</button>
          <p class="menu-label">Export běhu</p>
          <button type="button" class="menu-item" data-global="export" data-format="json">JSON</button>
          <button type="button" class="menu-item" data-global="export" data-format="md">Markdown</button>
          <button type="button" class="menu-item" data-global="export" data-format="txt">Text</button>
        </div>
      </details>
    </header>
    <nav class="dock" aria-label="Sekce" id="dock"></nav>
    <div id="errorbar" class="errorbar" role="alert" hidden></div>
    <main id="stage" class="stage" tabindex="-1"></main>
    ${shellHtml()}
  </div>`;
  stage = app.querySelector<HTMLElement>("#stage")!;
  lastStage = { section: "", html: "" };
  applyTheme();
}

function currentView(): View {
  return VIEWS.find((view) => view.id === state.section) ?? overview;
}

function renderChrome() {
  renderDock();
  const infoband = app.querySelector<HTMLElement>("#infoband")!;
  const infoOpen = infoband.querySelector<HTMLDetailsElement>("details")?.open ?? false;
  infoband.innerHTML = infoBandHtml();
  if (infoOpen) infoband.querySelector("details")?.setAttribute("open", "");

  // vyber behu
  const select = app.querySelector<HTMLSelectElement>("#runSelect")!;
  if (!state.runs.length) {
    select.innerHTML = `<option value="">bez běhů</option>`;
    select.disabled = true;
  } else {
    select.disabled = false;
    select.innerHTML = state.runs
      .map((run, i) => `<option value="${esc(run.run_id)}"${run.run_id === state.activeRunId ? " selected" : ""}>${i === 0 ? "nejnovější · " : ""}${esc(run.nazev)}</option>`)
      .join("");
  }

  // stav
  const pulse = app.querySelector<HTMLElement>(".pulse")!;
  const text = app.querySelector<HTMLElement>(".status-text")!;
  const running = Boolean(state.automationStatus?.process_running);
  const mode = state.connection === "error" ? "error" : running ? "live" : "idle";
  pulse.dataset.state = mode;
  text.textContent = mode === "error" ? "bez spojení" : running ? "autopilot běží" : "nečinný";

  // chyba
  const bar = app.querySelector<HTMLElement>("#errorbar")!;
  bar.hidden = !state.error;
  bar.innerHTML = state.error
    ? `<span>${esc(state.error)}</span><span class="errorbar-actions">${state.authNeeded ? `<button type="button" class="btn btn-ghost" data-global="token-open">Zadat token</button>` : state.connection === "error" ? `<button type="button" class="btn btn-ghost" data-global="retry">Zkusit znovu</button>` : ""}<button type="button" class="btn btn-ghost" data-global="dismiss-error">Skrýt</button></span>`
    : "";

  // token
  const tokenBtn = app.querySelector<HTMLButtonElement>("[data-global='token']")!;
  tokenBtn.hidden = !state.meta?.auth_required;
  tokenBtn.textContent = getToken() ? "Změnit token" : "Zadat token";
}

// Dok se vytvori jednou a pak se jen upravuje: tekute prelevani aktivni bubliny potrebuje stejne
// DOM prvky mezi vykreslenimi (kdyby se prepsal innerHTML, animace by se ztratila).
// Retez bublin doku: jedna cesta z metaball mostu mezi sousednimi bublinami (G1 navaznost na kruhy).
function drawDockChain(track: HTMLElement) {
  const goo = track.querySelector<HTMLElement>(".dock-goo");
  const svg = goo?.querySelector<SVGSVGElement>(".dock-chain");
  const path = svg?.querySelector("path");
  const probe = goo?.querySelector<HTMLElement>(".dock-probe");
  if (!goo || !svg || !path || !probe) return;
  const w = goo.clientWidth;
  const h = goo.clientHeight;
  if (!w || !h) return;
  const n = VIEWS.length;
  const pitch = h / n;
  const r = probe.getBoundingClientRect().width / 2;
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  let d = "";
  for (let i = 0; i < n; i += 1) {
    const c = { x: w / 2, y: (i + 0.5) * pitch };
    d += `M${(c.x + r).toFixed(2)},${c.y.toFixed(2)}A${r.toFixed(2)},${r.toFixed(2)} 0 1 1 ${(c.x - r).toFixed(2)},${c.y.toFixed(2)}A${r.toFixed(2)},${r.toFixed(2)} 0 1 1 ${(c.x + r).toFixed(2)},${c.y.toFixed(2)}Z`;
    if (i < n - 1) d += metaballBridge(c, r, { x: c.x, y: c.y + pitch }, r, r * 0.62)?.d ?? "";
  }
  path.setAttribute("d", d);
}

function renderDock() {
  const dock = app.querySelector<HTMLElement>("#dock")!;
  const pending = state.enforcement ? state.enforcement.actions.filter((a) => a.status === "proposed").length : 0;
  let track = dock.querySelector<HTMLElement>(".dock-track");
  if (!track) {
    dock.innerHTML = `<div class="dock-track" style="--n:${VIEWS.length}">
      <div class="dock-goo" aria-hidden="true"><svg class="dock-chain"><path/></svg><span class="dock-probe"></span><span class="dock-blob"></span><span class="dock-blob dock-trail"></span></div>
      <span class="dock-core" aria-hidden="true"></span>
      ${VIEWS.map(
        (view) => `<a class="dock-item" href="#/${view.id}" data-nav="${view.id}" aria-label="${esc(view.label)}" title="${esc(view.label)}">
          <span class="dock-disc"><span class="dock-abbr" aria-hidden="true">${esc(view.abbr)}</span></span><span class="dock-label">${esc(view.label)}</span></a>`,
      ).join("")}
    </div>`;
    track = dock.querySelector<HTMLElement>(".dock-track")!;
    new ResizeObserver(() => drawDockChain(track!)).observe(track);
  }
  const index = Math.max(0, VIEWS.findIndex((view) => view.id === state.section));
  track.style.setProperty("--i", String(index));
  track.querySelectorAll<HTMLAnchorElement>(".dock-item").forEach((item, i) => {
    const active = i === index;
    item.classList.toggle("is-active", active);
    if (active) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
    const disc = item.querySelector<HTMLElement>(".dock-disc")!;
    const badge = disc.querySelector<HTMLElement>(".badge");
    if (VIEWS[i].id === "zasahy" && pending > 0) {
      if (badge) {
        badge.textContent = String(pending);
        badge.setAttribute("aria-label", `${pending} čeká na schválení`);
      } else disc.insertAdjacentHTML("beforeend", `<span class="badge" aria-label="${pending} čeká na schválení">${pending}</span>`);
    } else badge?.remove();
  });
}

function focusSignature(el: Element | null): string | null {
  if (!el || !(el instanceof HTMLElement) || !stage.contains(el)) return null;
  const d = el.dataset;
  return JSON.stringify([el.tagName, d.action ?? "", d.key ?? d.host ?? d.plan ?? "", el.id, el.getAttribute("name") ?? ""]);
}

// Posledni vykreslene HTML sekce. Kdyz obnova dat HTML nezmeni, nic se neprepisuje (zadne blikani,
// zadny reset zoomu, vyberu, scrollu ani fokusu). Mapa i seznamy zustavaji v DOM, jak jsou.
let lastStage = { section: "", html: "" };

function renderStage() {
  const html = currentView().render();
  if (state.section === lastStage.section && html === lastStage.html && stage.childElementCount) return;
  lastStage = { section: state.section, html };

  const sigBefore = focusSignature(document.activeElement);
  const scrolls = new Map<string, number>();
  stage.querySelectorAll<HTMLElement>("[data-keep]").forEach((node) => scrolls.set(node.dataset.keep!, node.scrollTop));
  const hadStageScroll = stage.scrollTop;

  stage.innerHTML = html;
  stage.dataset.section = state.section;

  stage.querySelectorAll<HTMLElement>("[data-keep]").forEach((node) => {
    const top = scrolls.get(node.dataset.keep!);
    if (top) node.scrollTop = top;
  });
  stage.scrollTop = hadStageScroll;

  if (sigBefore) {
    const candidates = stage.querySelectorAll<HTMLElement>("[data-action],[data-host],input,select,textarea,button,summary");
    for (const candidate of candidates) {
      if (focusSignature(candidate) === sigBefore) {
        candidate.focus({ preventScroll: true });
        break;
      }
    }
  }
  currentView().after?.();
  afterStageRender(stage, state.section);
}

function isEditing() {
  const el = document.activeElement;
  return Boolean(el && stage?.contains(el) && /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName));
}

function renderAll() {
  renderChrome();
  renderStage();
  dirty = false;
}

onChange((force) => {
  if (!force && isEditing()) {
    dirty = true;
    renderChrome();
    return;
  }
  renderAll();
});

// ---------- navigace ----------
function applyRoute(focusStage: boolean) {
  const { section, param } = parseHash(window.location.hash);
  const previous = state.section;
  state.section = section;
  state.param = param;
  if (param) {
    if (section === "hostitele") state.selectedHost = param;
    if (section === "nalezy") state.selectedFinding = param;
  }
  if (section === "audit" && (state.audit === undefined || previous !== "audit")) {
    state.audit = undefined;
    void refreshAudit();
  }
  if (section === "zasahy" && previous !== "zasahy") void refreshEnforcement();
  document.title = `${currentView().label} · Skákavka`;
  const changed = previous !== section;
  const commit = () => {
    renderAll();
    if (focusStage && changed) stage.focus({ preventScroll: true });
  };
  if (!changed || !shellReady) {
    commit();
    return;
  }
  transitionSections(Math.sign(indexOf(section) - indexOf(previous)) >= 0 ? "down" : "up", commit);
}

// ---------- prechody mezi plochami ----------
// Dolu v doku = nova plocha prijede zespodu, nahoru = shora. View Transitions API; kde chybi,
// stejny pohyb zajisti CSS trida na .stage. Bez animace pri prefers-reduced-motion.
let shellReady = false;
let transitionEpoch = 0;
function indexOf(id: SectionId) {
  return VIEWS.findIndex((view) => view.id === id);
}
function transitionSections(direction: "down" | "up", commit: () => void) {
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduced) {
    commit();
    return;
  }
  const root = document.documentElement;
  root.dataset.vt = direction;
  const doc = document as Document & { startViewTransition?: (cb: () => void) => { finished: Promise<void> } };
  if (doc.startViewTransition) {
    const t = doc.startViewTransition(commit);
    void t.finished.catch(() => undefined).finally(() => {
      if (root.dataset.vt === direction) delete root.dataset.vt;
    });
    return;
  }
  commit();
  const epoch = ++transitionEpoch;
  stage.classList.remove("enter-down", "enter-up");
  void stage.offsetWidth;
  stage.classList.add(direction === "down" ? "enter-down" : "enter-up");
  window.setTimeout(() => {
    if (epoch === transitionEpoch) stage.classList.remove("enter-down", "enter-up");
  }, 520);
}

async function switchRun(runId: string) {
  if (!runId) return;
  const latest = state.runs[0]?.run_id;
  try {
    const report = await api.run(runId);
    update({
      activeRunId: runId,
      report,
      followLatest: runId === latest,
      selectedHost: null,
      selectedFinding: null,
      error: null,
    });
  } catch (error) {
    update({ error: error instanceof Error ? error.message : String(error) });
  }
}

// ---------- udalosti ----------
async function runAction(el: HTMLElement, event: Event) {
  const name = el.dataset.action ?? "";
  if (name === "ask") {
    const key = el.dataset.key ?? null;
    state.selectedFinding = key;
    setAssistantOpen(true);
    await sendPrompt("Vysvětli tento nález a navrhni další krok.");
    return;
  }
  if (name === "goto") {
    navigate((el.dataset.key as SectionId) ?? "prehled");
    return;
  }
  const handler = currentView().actions[name];
  if (handler) await handler(el, event);
}

function closeMenus() {
  app.querySelectorAll<HTMLDetailsElement>("details.menu[open]").forEach((menu) => menu.removeAttribute("open"));
}

app.addEventListener("click", (event) => {
  const target = event.target as HTMLElement;
  const globalEl = target.closest<HTMLElement>("[data-global]");
  const insideMenu = target.closest("details.menu");
  app.querySelectorAll<HTMLDetailsElement>("details.menu[open]").forEach((menu) => menu !== insideMenu && menu.removeAttribute("open"));
  if (globalEl) {
    if (globalEl.classList.contains("menu-item")) closeMenus();
    void runGlobal(globalEl);
    return;
  }
  const nav = target.closest<HTMLAnchorElement>("[data-nav]");
  if (nav) return; // klasicke #/ odkazy resi hashchange
  const actionEl = target.closest<HTMLElement>("[data-action]");
  if (!actionEl || actionEl.tagName === "SELECT" || actionEl.tagName === "FORM") return;
  void runAction(actionEl, event);
});

app.addEventListener("keydown", (event) => {
  const target = event.target as HTMLElement;
  if ((event.key === "Enter" || event.key === " ") && target.getAttribute("role") === "button" && target.dataset.action) {
    event.preventDefault();
    void runAction(target, event);
  }
  if (event.key === "Escape") {
    const menu = app.querySelector<HTMLDetailsElement>("details.menu[open]");
    if (menu) {
      menu.removeAttribute("open");
      menu.querySelector<HTMLElement>("summary")?.focus();
    } else if (state.assistantOpen) setAssistantOpen(false, true);
  }
});

app.addEventListener("change", (event) => {
  const target = event.target as HTMLElement;
  if (target.id === "runSelect") {
    void switchRun((target as HTMLSelectElement).value);
    return;
  }
  if (target.tagName === "SELECT" && target.dataset.action) void runAction(target, event);
  const draftKey = target.dataset.draft;
  if (draftKey) (state.proposeDraft as Record<string, string>)[draftKey] = (target as HTMLInputElement).value;
});

app.addEventListener("input", (event) => {
  const target = event.target as HTMLInputElement;
  const draftKey = target.dataset?.draft;
  if (draftKey) (state.proposeDraft as Record<string, string>)[draftKey] = target.value;
});

app.addEventListener("submit", (event) => {
  const form = event.target as HTMLFormElement;
  if (form.id === "chatForm") {
    event.preventDefault();
    const input = form.querySelector<HTMLTextAreaElement>("#chatInput")!;
    const value = input.value;
    input.value = "";
    void sendPrompt(value);
    return;
  }
  const name = form.dataset.submit;
  if (!name) return;
  event.preventDefault();
  const handler = currentView().actions[name];
  if (handler) void handler(form, event);
});

app.addEventListener("focusout", () => {
  if (dirty) window.setTimeout(() => !isEditing() && renderAll(), 0);
});

async function runGlobal(el: HTMLElement) {
  switch (el.dataset.global) {
    case "theme":
      state.theme = effectiveDark() ? "light" : "dark";
      window.localStorage.setItem("bakulaTheme", state.theme);
      applyTheme();
      break;
    case "assistant-toggle":
      setAssistantOpen(!state.assistantOpen, true);
      break;
    case "assistant-close":
      setAssistantOpen(false, true);
      break;
    case "retry":
      await refreshAll(false);
      break;
    case "token-open":
    case "token": {
      const token = await tokenDialog();
      if (token) {
        setToken(token);
        tokenDismissed = false;
        await refreshAll(true);
      }
      break;
    }
    case "dismiss-error":
      update({ error: null });
      break;
    case "export": {
      const format = (el.dataset.format as "json" | "md" | "txt") ?? "json";
      if (!state.activeRunId) break;
      try {
        const { blob, name } = await api.exportRun(state.activeRunId, format);
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = name;
        anchor.click();
        window.setTimeout(() => URL.revokeObjectURL(url), 1500);
      } catch (error) {
        update({ error: error instanceof Error ? error.message : String(error) });
      }
      app.querySelector<HTMLDetailsElement>("#moreMenu")?.removeAttribute("open");
      break;
    }
  }
}

// Posledni vstup (mys vs. klavesnice) rozhoduje, jestli se ukaze fokusovy prstenec.
document.addEventListener("pointerdown", () => (document.documentElement.dataset.input = "pointer"), true);
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") document.documentElement.dataset.input = "key";
}, true);

window.addEventListener("hashchange", () => applyRoute(true));

// ---------- casovace ----------
let expiredRefreshQueued = false;
window.setInterval(() => {
  stage?.querySelectorAll<HTMLElement>("[data-expires-at]").forEach((node) => {
    const left = (Number(node.dataset.expiresAt) - Date.now()) / 1000;
    if (left <= 0) {
      node.textContent = "vypršelo";
      if (!expiredRefreshQueued) {
        expiredRefreshQueued = true;
        void refreshEnforcement().finally(() => {
          expiredRefreshQueued = false;
        });
      }
    } else {
      node.textContent = countdown(left);
    }
  });
}, 1000);

function scheduleRefresh() {
  const delay = state.automationStatus?.process_running ? 5000 : 15000;
  window.setTimeout(async () => {
    if (document.visibilityState === "visible") await refreshAll(true);
    scheduleRefresh();
  }, delay);
}
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") void refreshAll(true);
});

// ---------- start ----------
async function init() {
  const storedTheme = window.localStorage.getItem("bakulaTheme");
  if (storedTheme === "light" || storedTheme === "dark") state.theme = storedTheme;
  const storedPentest = window.localStorage.getItem("bakulaPentestMode");
  if (storedPentest === "off" || storedPentest === "smart" || storedPentest === "aggressive") state.pentestMode = storedPentest as PentestMode;

  // Vice soubeznych pozadavku muze dostat 401 naraz - dialog se ale ukaze jen jednou.
  let pendingToken: Promise<string | null> | null = null;
  setAuthHandler(() => {
    if (tokenDismissed) return Promise.resolve(null);
    if (!pendingToken) {
      pendingToken = tokenDialog().then((token) => {
        if (!token) tokenDismissed = true;
        pendingToken = null;
        return token;
      });
    }
    return pendingToken;
  });

  renderShell();
  initRipple(app, () => stage);
  watchAssistantLayout();
  applyRoute(false);
  shellReady = true;
  const { section, param } = parseHash(window.location.hash);
  if (param && section === "hostitele") state.selectedHost = param;
  await refreshAll(false);
  if (state.section === "audit") void refreshAudit();
  renderLog();
  scheduleRefresh();
}

void init();
