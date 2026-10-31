import { askAssistantStream, type AssistantContext } from "./api";
import { state, update } from "./state";
import type { ChatMessage } from "./types";
import { esc } from "./ui";

const SECTION_TO_PANEL: Record<string, string> = {
  prehled: "assets",
  hostitele: "assets",
  nalezy: "findings",
  overovani: "triage",
  zasahy: "triage",
  audit: "lanes",
  automat: "lanes",
};

export function shellHtml(): string {
  return `<aside id="assistant" class="assistant" role="complementary" aria-label="Asistent" hidden>
    <div class="assistant-card">
    <header class="assistant-head">
      <h2>Asistent</h2>
      <button type="button" class="btn btn-ghost" data-global="assistant-close" aria-label="Zavřít asistenta">Zavřít</button>
    </header>
    <div id="chatLog" class="chat-log" role="log" aria-live="polite" aria-relevant="additions text"></div>
    <form id="chatForm" class="chat-form" autocomplete="off">
      <label class="sr-only" for="chatInput">Zpráva asistentovi</label>
      <textarea id="chatInput" rows="2" placeholder="Zeptej se na nález, stanici nebo další krok" required></textarea>
      <button type="submit" class="btn">Odeslat</button>
    </form>
    </div>
  </aside>`;
}

function context(): AssistantContext {
  const host = state.selectedHost;
  const asset = state.report?.hosts.find((h) => h.host_key === host)?.asset_id ?? null;
  return {
    detail_panel: SECTION_TO_PANEL[state.section] ?? "findings",
    selected_node_id: host,
    selected_finding_id: state.selectedFinding,
    selected_asset_id: asset,
    selected_action_id: null,
  };
}

function bubble(message: ChatMessage, index: number): string {
  const sources = message.sources?.length ? `<p class="chat-src mono small muted">${message.sources.map(esc).join(" · ")}</p>` : "";
  return `<div class="msg msg-${message.role}" data-i="${index}"><p>${esc(message.text) || "…"}</p>${sources}</div>`;
}

export function renderLog() {
  const log = document.getElementById("chatLog");
  if (!log) return;
  log.innerHTML = state.chat.length
    ? state.chat.map(bubble).join("")
    : `<p class="muted small chat-hint">Asistent odpovídá nad aktuálním během. Vybraný nález nebo stanice se pošle jako kontext.</p>`;
  log.scrollTop = log.scrollHeight;
}

const CLOSE_MS = 360;
let closeTimer = 0;

function reducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * Spocita bod, ze ktereho se karta chatu "zhmotni" (stred tlacitka Asistent), vuci jejimu KONECNEMU
 * umisteni (sloupec se v tu chvili jeste roztahuje). Jedno cteni layoutu, pak jen zapis promennych.
 */
function placeAssistant() {
  const panel = document.getElementById("assistant");
  const card = panel?.querySelector<HTMLElement>(".assistant-card");
  if (!panel || !card) return;
  const phone = window.matchMedia("(max-width: 64.06rem)").matches;
  const btn = document.querySelector<HTMLElement>("[data-global='assistant-toggle']")?.getBoundingClientRect();
  const rootPx = parseFloat(getComputedStyle(document.documentElement).fontSize) || 16;
  let left: number, top: number, width: number, height: number;
  if (phone) {
    left = 0;
    top = 0;
    width = window.innerWidth;
    height = window.innerHeight;
  } else {
    const dock = document.getElementById("dock")?.getBoundingClientRect();
    const asW = parseFloat(getComputedStyle(card).getPropertyValue("--as-w")) || 0;
    const w = asW || Math.min(Math.max(window.innerWidth * 0.3, 22 * rootPx), 28 * rootPx);
    width = card.offsetWidth || w;
    width = Math.min(Math.max(width, w), w);
    left = window.innerWidth - rootPx - width;
    top = dock?.top ?? 0;
    height = (dock?.height ?? window.innerHeight) - rootPx;
  }
  const clamp = (v: number, max: number) => Math.min(Math.max(v, 0), max);
  const ox = btn ? clamp(btn.left + btn.width / 2 - left, width) : width;
  const oy = btn ? clamp(btn.top + btn.height / 2 - top, height) : 0;
  card.style.setProperty("--c-t", `${oy.toFixed(0)}px`);
  card.style.setProperty("--c-l", `${ox.toFixed(0)}px`);
  card.style.setProperty("--c-r", `${(width - ox).toFixed(0)}px`);
  card.style.setProperty("--c-b", `${(height - oy).toFixed(0)}px`);
}

export function watchAssistantLayout() {
  if (typeof ResizeObserver === "undefined") return;
  const observer = new ResizeObserver(() => {
    if (state.assistantOpen) placeAssistant();
  });
  for (const sel of [".bar", "#errorbar"]) {
    const el = document.querySelector(sel);
    if (el) observer.observe(el);
  }
  window.addEventListener("resize", () => state.assistantOpen && placeAssistant());
}

/**
 * Otevre/zavre asistenta. Okno se zhmotni z tlacitka (clip-path + posun, bez odskoku), po otevreni
 * dostane fokus pole zpravy, po zavreni se fokus vrati na tlacitko. Bez animace u prefers-reduced-motion.
 */
export function setAssistantOpen(open: boolean, returnFocus = false) {
  update({ assistantOpen: open }, false);
  const panel = document.getElementById("assistant");
  if (!panel) return;
  const toggle = document.querySelector<HTMLElement>("[data-global='assistant-toggle']");
  toggle?.setAttribute("aria-expanded", String(open));
  window.clearTimeout(closeTimer);
  document.body.classList.toggle("assistant-open", open);
  if (open) {
    panel.hidden = false;
    renderLog();
    placeAssistant(); // vynuti vypocet vychoziho (zavreneho) stavu, aby prechod mel odkud startovat
    panel.classList.add("is-open");
    panel.removeAttribute("inert");
    document.getElementById("chatInput")?.focus({ preventScroll: true });
    return;
  }
  placeAssistant();
  panel.classList.remove("is-open");
  panel.setAttribute("inert", "");
  if (returnFocus) toggle?.focus({ preventScroll: true });
  if (reducedMotion()) panel.hidden = true;
  else closeTimer = window.setTimeout(() => (panel.hidden = true), CLOSE_MS);
}

export async function sendPrompt(prompt: string) {
  const text = prompt.trim();
  if (!text || state.chatBusy) return;
  if (!state.activeRunId) {
    state.chat.push({ role: "user", text }, { role: "assistant", text: "Není načtený žádný běh, na který bych mohl odpovídat." });
    renderLog();
    return;
  }
  const history = state.chat
    .filter((m) => !m.streaming && m.text.trim())
    .slice(-8)
    .map((m) => ({ role: m.role, text: m.text }));
  state.chat.push({ role: "user", text });
  const reply: ChatMessage = { role: "assistant", text: "", streaming: true };
  state.chat.push(reply);
  state.chatBusy = true;
  renderLog();
  try {
    const result = await askAssistantStream(state.activeRunId, text, context(), history, (chunk) => {
      reply.text += chunk;
      const node = document.querySelector<HTMLElement>(`#chatLog .msg[data-i="${state.chat.indexOf(reply)}"] p`);
      if (node) node.textContent = reply.text;
      const log = document.getElementById("chatLog");
      if (log) log.scrollTop = log.scrollHeight;
    });
    reply.text = result.answer || "Asistent nevrátil žádnou odpověď.";
    reply.sources = result.sources;
  } catch (error) {
    reply.text = error instanceof Error ? error.message : String(error);
  } finally {
    reply.streaming = false;
    state.chatBusy = false;
    renderLog();
  }
}
