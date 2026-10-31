import { refreshAudit } from "../data";
import { state, update, type View } from "../state";
import { esc, fmtDate } from "../ui";
import { emptyState, paneHead } from "./common";

function render(): string {
  const chain = state.auditChain;
  const badge =
    chain === undefined || chain === null
      ? ""
      : chain.chain_ok
        ? `<span class="chip chip-ink" title="Řetěz hashů záznamu je neporušený">řetěz v pořádku</span>`
        : `<span class="chip chip-hot" role="alert" title="Řetěz hashů záznamu nesedí. Záznam byl pravděpodobně změněn.">řetěz narušen</span>`;
  const tools = badge + `<label class="inline small"><span>Posledních</span><select data-action="audit-limit" aria-label="Počet záznamů">${[50, 100, 250, 500]
    .map((n) => `<option value="${n}"${state.auditLimit === n ? " selected" : ""}>${n}</option>`)
    .join("")}</select></label><button type="button" class="btn btn-ghost" data-action="audit-reload">Obnovit</button>`;
  if (state.audit === undefined) {
    return `${paneHead("Audit", tools)}${emptyState("Načítám…", "Čekám na odpověď serveru.")}`;
  }
  if (state.audit === null) {
    return `${paneHead("Audit")}${emptyState("Audit není dostupný", "Tento server neposkytuje auditní záznam. Po aktualizaci serveru se tady objeví kdo, kdy a co schválil.")}`;
  }
  if (!state.audit.length) return `${paneHead("Audit", tools)}${emptyState("Prázdný záznam", "Zatím nebyla zaznamenána žádná akce.")}`;
  return `${paneHead("Audit", tools)}
  <div class="scroll audit" data-keep="audit">
    <p class="small muted note-line">Záznam je jen pro čtení. Server do něj přidává, nic nemaže ani nepřepisuje.</p>
    <table class="data">
      <caption class="sr-only">Auditní záznam</caption>
      <thead><tr><th>#</th><th>Čas</th><th>Kdo</th><th>Akce</th><th>Předmět</th><th>Detail</th></tr></thead>
      <tbody>${state.audit
        .map(
          (e) =>
            `<tr><td class="mono small muted">${e.id}</td><td class="mono small">${esc(fmtDate(e.at))}</td><td>${esc(e.actor)}</td><td class="mono">${esc(e.action)}</td><td class="mono">${esc(e.subject)}</td><td class="small">${esc(e.detail)}</td></tr>`,
        )
        .join("")}</tbody>
    </table>
  </div>`;
}

export const audit: View = {
  id: "audit",
  label: "Audit",
  abbr: "AU",
  render,
  actions: {
    "audit-limit": (el) => {
      update({ auditLimit: Number((el as HTMLSelectElement).value) || 100, audit: undefined });
      void refreshAudit();
    },
    "audit-reload": () => {
      update({ audit: undefined });
      void refreshAudit();
    },
  },
};
