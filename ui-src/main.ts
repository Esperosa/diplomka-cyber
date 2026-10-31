import { api, getToken, setAuthHandler, setToken } from "./api";
import { renderLog, sendPrompt, setAssistantOpen, shellHtml } from "./assistant";
import { refreshAll, refreshAudit, refreshEnforcement } from "./data";
import { tokenDialog } from "./dialogs";
import { parseHash, navigate } from "./router";
import { onChange, state, update, type SectionId, type View } from "./state";
import { countdown, esc } from "./ui";
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
  <svg class="goo-defs" aria-hidden="true" focusable="false"><defs><filter id="goo" x="-20%" y="-20%" width="140%" height="140%" color-interpolation-filters="sRGB"><feGaussianBlur in="SourceGraphic" stdDeviation="5" result="blur"/><feColorMatrix in="blur" mode="matrix" values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 20 -8" result="goo"/><feBlend in="SourceGraphic" in2="goo"/></filter></defs></svg>
  <a class="skip" href="#stage">Přeskočit na obsah</a>
  <div class="shell">
    <header class="bar">
      <span class="wordmark">Skákavka</span>
      <label class="run-pick"><span class="sr-only">Běh</span><select id="runSelect" aria-label="Běh"></select></label>
      <span class="status" id="status" role="status"><span class="pulse" data-state="idle"></span><span class="status-text"></span></span>
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
  applyTheme();
}

function currentView(): View {
  return VIEWS.find((view) => view.id === state.section) ?? overview;
}

function renderChrome() {
  // dok
  const dock = app.querySelector<HTMLElement>("#dock")!;
  const pending = state.enforcement ? state.enforcement.actions.filter((a) => a.status === "proposed").length : 0;
  const goo = `<div class="dock-goo" aria-hidden="true">${VIEWS.map((view) => `<i${view.id === state.section ? ' class="on"' : ""}></i>`).join("")}</div>`;
  dock.innerHTML = goo + VIEWS.map((view) => {
    const active = view.id === state.section;
    const badge = view.id === "zasahy" && pending > 0 ? `<span class="badge" aria-label="${pending} čeká na schválení">${pending}</span>` : "";
    return `<a class="dock-item${active ? " is-active" : ""}" href="#/${view.id}" data-nav="${view.id}" ${active ? 'aria-current="page"' : ""} aria-label="${esc(view.label)}">
      <span class="dock-disc">${dockGlyph(view.abbr)}${badge}</span><span class="dock-label">${esc(view.label)}</span></a>`;
  }).join("");

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
    ? `<span>${esc(state.error)}</span><button type="button" class="btn btn-ghost" data-global="dismiss-error">Skrýt</button>`
    : "";

  // token
  const tokenBtn = app.querySelector<HTMLButtonElement>("[data-global='token']")!;
  tokenBtn.hidden = !state.meta?.auth_required;
  tokenBtn.textContent = getToken() ? "Změnit token" : "Zadat token";
}

function dockGlyph(abbr: string): string {
  // Dvoupismenna zkratka v bublině doku; plny nazev je v aria-label a popisku.
  return `<span class="dock-abbr" aria-hidden="true">${esc(abbr)}</span>`;
}

function focusSignature(el: Element | null): string | null {
  if (!el || !(el instanceof HTMLElement) || !stage.contains(el)) return null;
  const d = el.dataset;
  return JSON.stringify([el.tagName, d.action ?? "", d.key ?? d.host ?? d.plan ?? "", el.id, el.getAttribute("name") ?? ""]);
}

function renderStage() {
  const sigBefore = focusSignature(document.activeElement);
  const scrolls = new Map<string, number>();
  stage.querySelectorAll<HTMLElement>("[data-keep]").forEach((node) => scrolls.set(node.dataset.keep!, node.scrollTop));
  const hadStageScroll = stage.scrollTop;

  stage.innerHTML = currentView().render();
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
  renderAll();
  if (focusStage && previous !== section) stage.focus({ preventScroll: true });
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
  if (!target.closest("details.menu")) closeMenus();
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
  if (event.key === "Escape" && state.assistantOpen) setAssistantOpen(false);
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
      setAssistantOpen(!state.assistantOpen);
      app.querySelector("[data-global='assistant-toggle']")?.setAttribute("aria-expanded", String(state.assistantOpen));
      break;
    case "assistant-close":
      setAssistantOpen(false);
      app.querySelector("[data-global='assistant-toggle']")?.setAttribute("aria-expanded", "false");
      (app.querySelector("[data-global='assistant-toggle']") as HTMLElement | null)?.focus();
      break;
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
  applyRoute(false);
  const { section, param } = parseHash(window.location.hash);
  if (param && section === "hostitele") state.selectedHost = param;
  await refreshAll(false);
  if (state.section === "audit") void refreshAudit();
  renderLog();
  scheduleRefresh();
}

void init();
