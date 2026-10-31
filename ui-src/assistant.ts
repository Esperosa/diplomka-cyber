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

export function setAssistantOpen(open: boolean) {
  update({ assistantOpen: open }, false);
  const panel = document.getElementById("assistant");
  if (!panel) return;
  panel.hidden = !open;
  document.body.classList.toggle("assistant-open", open);
  if (open) {
    renderLog();
    document.getElementById("chatInput")?.focus();
  }
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
