import { refreshAudit } from "../data";
import { state, update, type View } from "../state";
import { auditActionLabel } from "../glossary";
import { esc, fmtDate } from "../ui";
import { emptyState, paneHead } from "./common";

function render(): string {
  const chain = state.auditChain;
  const badge =
    chain === undefined || chain === null
      ? ""
      : chain.chain_ok
        ? `<span class="chip chip-ink" title="Každý záznam nese otisk předchozího. Zpětná úprava by řetěz přerušila, a ta nebyla zjištěna.">řetěz v pořádku</span>`
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
    ${
      chain && !chain.chain_ok
        ? `<div class="approval-note" role="alert"><p><strong>Řetěz auditu je narušen.</strong> Záznam byl pravděpodobně změněn, takže ho nelze brát jako neporušený důkaz, kdo co udělal.</p><p class="small muted">Do zjištění příčiny nespoléhej na tyto záznamy a zvaž pozastavení schvalování zásahů.</p></div>`
        : ""
    }
    <p class="small muted note-line">Záznam je jen pro čtení: každý záznam nese otisk předchozího, takže zpětnou změnu server pozná. Nahoře je nejnovější.</p>
    <table class="data">
      <caption class="sr-only">Auditní záznam</caption>
      <thead><tr><th>#</th><th>Čas</th><th>Kdo</th><th>Akce</th><th>Předmět</th><th>Detail</th></tr></thead>
      <tbody>${state.audit
        .map(
          (e) =>
            `<tr><td class="mono small muted" data-label="#">${e.id}</td><td class="mono small" data-label="Čas">${esc(fmtDate(e.at))}</td><td data-label="Kdo">${esc(e.actor === "sweep" ? "sweep (automatická kontrola)" : e.actor)}</td><td data-label="Akce"><span>${esc(auditActionLabel(e.action))}</span> <span class="mono small muted">${esc(e.action)}</span></td><td class="mono" data-label="Předmět">${esc(e.subject)}</td><td class="small" data-label="Detail">${esc(e.detail)}</td></tr>`,
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
