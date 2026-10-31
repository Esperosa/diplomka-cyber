import { dotMatrix } from "../dotmatrix";
import { esc } from "../ui";

export function paneHead(title: string, tools = ""): string {
  return `<header class="pane-head"><h1>${esc(title)}</h1>${tools ? `<div class="pane-tools">${tools}</div>` : ""}</header>`;
}

export function emptyState(title: string, text: string, action = ""): string {
  return `<div class="empty"><p class="empty-title">${esc(title)}</p><p class="empty-text">${esc(text)}</p>${action}</div>`;
}

export function readout(value: string | number, label: string, tone: "" | "hot" = "", small = false): string {
  return `<div class="readout${tone ? ` is-${tone}` : ""}${small ? " is-small" : ""}"><div class="readout-dm">${dotMatrix(String(value))}</div><div class="readout-label">${esc(label)}</div></div>`;
}

export function backButton(label = "Zpět na seznam"): string {
  return `<button type="button" class="btn btn-ghost back-btn" data-action="back">← ${esc(label)}</button>`;
}

export function chip(text: string, tone: "" | "hot" | "ink" | "mute" = ""): string {
  return `<span class="chip${tone ? ` chip-${tone}` : ""}">${esc(text)}</span>`;
}
