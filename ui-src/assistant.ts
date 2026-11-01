import { askAssistantStream, type AssistantContext } from "./api";
import { state, update } from "./state";
import type { ChatMessage } from "./types";
import { esc } from "./ui";
import { tokenMs } from "./motion";

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

function reducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * Zvlnena kapka: polygon se stejnym poctem bodu (aby se dal prolinat), stred v mistě tlacitka, polomer
 * roste od nuly nad nejvzdalenejsi roh, okraj se vlni a ke konci vyhladi do kruhu.
 */
function blobFrames(cx: number, cy: number, w: number, h: number): Keyframe[] {
  const rmax = Math.hypot(Math.max(cx, w - cx), Math.max(cy, h - cy)) * 1.12 + 24;
  const frames: Keyframe[] = [];
  const steps = 14;
  const points = 36;
  for (let i = 0; i <= steps; i += 1) {
    const u = i / steps;
    const wob = 0.16 * Math.sin(Math.PI * Math.min(1, u * 1.1)) ** 1.2;
    const pts: string[] = [];
    for (let k = 0; k < points; k += 1) {
      const th = (k / points) * Math.PI * 2;
      const r = rmax * u * (1 + wob * Math.sin(3 * th + u * 5) + wob * 0.55 * Math.sin(5 * th - u * 7));
      pts.push(`${(cx + Math.cos(th) * r).toFixed(1)}px ${(cy + Math.sin(th) * r).toFixed(1)}px`);
    }
    frames.push({ clipPath: `polygon(${pts.join(", ")})`, offset: u });
  }
  return frames;
}

let animations: Animation[] = [];
let finishClose: (() => void) | null = null;

function cancelAnimations() {
  for (const a of animations) a.cancel();
  animations = [];
  finishClose?.();
  finishClose = null;
}

/**
 * Otevre/zavre asistenta technikou FLIP. Sloupec layoutu se prepne hned na konecny stav (jedno
 * prepocitani), hlavni plocha se animuje pres transform z puvodniho obdelniku a karta se zhmotni z tlacitka
 * zvlnenou hranou (clip-path). Po otevreni dostane fokus pole zpravy, po zavreni se fokus vrati na tlacitko.
 */
export function setAssistantOpen(open: boolean, returnFocus = false) {
  update({ assistantOpen: open }, false);
  const panel = document.getElementById("assistant");
  const card = panel?.querySelector<HTMLElement>(".assistant-card");
  const stage = document.getElementById("stage") ?? document.querySelector<HTMLElement>(".stage");
  if (!panel || !card) return;
  const toggle = document.querySelector<HTMLElement>("[data-global='assistant-toggle']");
  toggle?.setAttribute("aria-expanded", String(open));
  cancelAnimations();
  const phone = window.matchMedia("(max-width: 64.06rem)").matches;
  const animate = !reducedMotion();
  const before = stage?.getBoundingClientRect();
  const btn = toggle?.getBoundingClientRect();
  const duration = tokenMs("--dur-slow", 440);
  const easing = "cubic-bezier(0.3, 0.7, 0.2, 1)";

  if (open) {
    panel.hidden = false;
    renderLog();
    panel.classList.remove("is-closing");
    document.body.classList.add("assistant-open");
    panel.classList.add("is-open");
    panel.removeAttribute("inert");
  } else {
    panel.classList.remove("is-open");
    panel.setAttribute("inert", "");
    document.body.classList.remove("assistant-open");
    if (animate) panel.classList.add("is-closing");
  }
  const flip = () => {
    if (!animate) {
      if (!open) panel.hidden = true;
      return;
    }
    const after = stage?.getBoundingClientRect(); // jedno cteni layoutu po prepnuti sloupce
    const c = card.getBoundingClientRect();
    if (stage && before && after && !phone && after.width > 0) {
      const dx = before.left - after.left;
      const sx = before.width / after.width;
      animations.push(stage.animate([{ transform: `translate3d(${dx}px, 0, 0) scale(${sx}, 1)` }, { transform: "none" }], { duration, easing }));
    }
    const cx = btn ? btn.left + btn.width / 2 - c.left : c.width;
    const cy = btn ? btn.top + btn.height / 2 - c.top : 0;
    let frames = blobFrames(Math.min(Math.max(cx, 0), c.width), Math.min(Math.max(cy, 0), c.height), c.width, c.height);
    if (!open) frames = [...frames].reverse().map((f, i, arr) => ({ ...f, offset: i / (arr.length - 1) }));
    const anim = card.animate(frames, { duration, easing, fill: open ? "none" : "forwards" });
    animations.push(anim);
    if (!open) {
      finishClose = () => {
        panel.hidden = true;
        panel.classList.remove("is-closing");
      };
      anim.onfinish = () => {
        finishClose?.();
        finishClose = null;
      };
    }
  };
  flip();
  if (open) document.getElementById("chatInput")?.focus({ preventScroll: true });
  else if (returnFocus) toggle?.focus({ preventScroll: true });
}

export function watchAssistantLayout() {
  // Rozlozeni se pocita pri kazdem otevreni z aktualnich rozmeru, neni treba nic sledovat.
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
