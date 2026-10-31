import { state } from "../state";
import { dotMatrix } from "../dotmatrix";
import { esc } from "../ui";

export function paneHead(title: string, tools = ""): string {
  return `<header class="pane-head"><h1>${esc(title)}</h1>${tools ? `<div class="pane-tools">${tools}</div>` : ""}</header>`;
}

export function emptyState(title: string, text: string, action = ""): string {
  return `<div class="empty"><p class="empty-title">${esc(title)}</p><p class="empty-text">${esc(text)}</p>${action}</div>`;
}

export function readout(value: string | number, label: string, tone: "" | "hot" = "", small = false): string {
  // Cisla se cte jako tucne bodove pismo (goo); text a dlouhe hodnoty zustavaji klasickym pismem.
  const text = String(value);
  const dots = !small && /^[0-9.:%/-]{1,6}$/.test(text);
  return `<div class="readout${tone ? ` is-${tone}` : ""}${small ? " is-small" : ""}"><div class="readout-num${dots ? " is-dots" : ""}">${dots ? dotMatrix(text) : esc(text)}</div><div class="readout-label">${esc(label)}</div></div>`;
}

export function backButton(label = "Zpět na seznam"): string {
  return `<button type="button" class="btn btn-ghost back-btn" data-action="back">← ${esc(label)}</button>`;
}

export function chip(text: string, tone: "" | "hot" | "ink" | "mute" = ""): string {
  return `<span class="chip${tone ? ` chip-${tone}` : ""}">${esc(text)}</span>`;
}

/**
 * Stav obrazovky, která potřebuje načtený běh. Rozlišuje načítání, výpadek serveru, chybějící token
 * a skutečně prázdný server, aby uživatel vždy věděl, co dál.
 */
export function noDataState(title: string): string {
  const head = paneHead(title);
  if (state.authNeeded) {
    return `${head}${emptyState("Server vyžaduje token", "Bez API tokenu server data nevydá. Zadej token a načtení se zopakuje.", `<button type="button" class="btn" data-global="token-open">Zadat token</button>`)}`;
  }
  if (state.connection === "error") {
    return `${head}${emptyState("Server neodpovídá", "Nepodařilo se načíst data. Zkontroluj, že server běží a že jsi ve správné síti. Obnovení se zkouší samo, nebo to zkus hned.", `<button type="button" class="btn" data-global="retry">Zkusit znovu</button>`)}`;
  }
  if (state.loading) return `${head}${emptyState("Načítám…", "Čekám na odpověď serveru.")}`;
  return `${head}${emptyState("Zatím žádný běh", "Server zatím nemá žádný uložený běh. Spusť autopilota v sekci Automat, po dokončení se tady objeví data.", `<button type="button" class="btn" data-action="goto" data-key="automat">Otevřít Automat</button>`)}`;
}
