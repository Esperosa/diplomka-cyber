import { api, ApiError } from "../api";
import { refreshAudit, refreshEnforcement } from "../data";
import { confirmDialog } from "../dialogs";
import { notify } from "../notify";
import { state, update, type View } from "../state";
import type { EnforcementAction, EnforcementStatus } from "../types";
import { countdown, esc, fmtDate, fmtDuration, obviousProblemWithIp, ownStationByIp } from "../ui";
import { chip, emptyState, paneHead } from "./common";

const MAX_TTL_SECONDS = 24 * 3600;

const STATUS_LABEL: Record<EnforcementStatus, string> = {
  proposed: "navrženo",
  approved: "schváleno zkušebně",
  rejected: "zamítnuto",
  applied: "blok aktivní",
  expired: "vypršelo",
  failed: "selhalo",
};

const REJECTION_TEXT: Record<string, string> = {
  ProtectedRange:
    "Tuto adresu nelze zablokovat. Patří do chráněného rozsahu (loopback, link-local, multicast nebo adresa, kterou operátor označil jako nedotknutelnou). Server zásah odmítl i přes výslovnou žádost.",
  TtlExceedsMaximum: "Platnost bloku musí být mezi 1 sekundou a 24 hodinami. Trvalý blok server nepřijímá.",
  UnparseableIp: "Zadaná hodnota není platná IPv4 ani IPv6 adresa.",
  AlreadyActive: "Pro tuto adresu už existuje čekající, schválený nebo aktivní zásah. Nový návrh server nepřijme, dokud předchozí nevyprší nebo se nezamítne.",
};

function banner(mode: "dry_run" | "enforce"): string {
  return mode === "enforce"
    ? `<div class="mode-banner is-enforce" role="status"><strong>Ostrý režim.</strong> Schválení zablokuje adresu na bráně hned. Blok nejde z tohoto okna předčasně zrušit, skončí sám po uplynutí platnosti. Režim se tady nemění.</div>`
    : `<div class="mode-banner" role="status"><strong>Zkušební režim.</strong> Schválení se jen zapíše do auditu a do firewallu se nic neposílá, takže si postup můžeš bezpečně vyzkoušet. Režim se tady nemění.</div>`;
}

function statusTone(status: EnforcementStatus) {
  return status === "applied" ? "ink" : status === "failed" || status === "rejected" ? "hot" : "mute";
}

function findingTitle(id: string | null | undefined): string | null {
  if (!id) return null;
  return state.report?.findings.find((f) => f.finding_id === id)?.title ?? null;
}

function outcomeText(action: EnforcementAction, mode: "dry_run" | "enforce"): string {
  switch (action.status) {
    case "proposed":
      return `Čeká na rozhodnutí. ${mode === "enforce" ? "Po schválení se adresa hned zablokuje na bráně." : "Po schválení se nic neblokuje, jen se zapíše rozhodnutí."}`;
    case "approved":
      return "Schváleno ve zkušebním režimu: do firewallu se nic neposlalo, adresa není blokovaná.";
    case "applied":
      return "Adresa je teď blokovaná na bráně. Blok sám skončí, předčasné zrušení tady není.";
    case "expired":
      return "Platnost skončila, blok na bráně už neplatí.";
    case "rejected":
      return "Zamítnuto, na bráně se nic nezměnilo.";
    default:
      return "Provedení selhalo, blok pravděpodobně není aktivní. Podrobnosti jsou v auditu.";
  }
}

function row(action: EnforcementAction, mode: "dry_run" | "enforce"): string {
  const expiresAt = action.applied_at ? Date.parse(action.applied_at) + action.ttl_seconds * 1000 : null;
  const live =
    action.status === "applied" && expiresAt !== null
      ? `<span class="mono" data-expires-at="${expiresAt}" aria-label="zbývající platnost bloku">${countdown(Math.max(0, (expiresAt - Date.now()) / 1000))}</span><span class="small muted">do ${esc(fmtDate(new Date(expiresAt).toISOString()))}</span>`
      : `<span class="mono small muted">platnost ${esc(fmtDuration(action.ttl_seconds))}</span>`;
  const denied = state.denied.approve;
  const busy = state.enfBusy === action.id;
  const lock = denied || busy;
  const own = ownStationByIp(state.report, action.ip);
  const title = findingTitle(action.finding_id);
  const buttons =
    action.status === "proposed"
      ? `<div class="actions-row"><button type="button" class="btn" data-action="enf-approve" data-key="${action.id}" aria-label="Schválit blok ${esc(action.ip)}"${lock ? ' disabled aria-describedby="deny-why"' : ""}>${busy ? "Odesílám…" : "Schválit"}</button><button type="button" class="btn btn-ghost" data-action="enf-reject" data-key="${action.id}" aria-label="Zamítnout blok ${esc(action.ip)}"${lock ? ' disabled aria-describedby="deny-why"' : ""}>Zamítnout</button>${denied ? `<span id="deny-why" class="small muted">Schvalovat a zamítat může jen operátor nebo správce. Tvoje role to nedovoluje.</span>` : ""}</div>`
      : "";
  return `<li class="action" data-action-id="${action.id}">
    <div class="action-main">
      <span class="mono big-ip">${esc(action.ip)}</span>
      ${chip(STATUS_LABEL[action.status] ?? action.status, statusTone(action.status))}
      ${live}
    </div>
    <p class="small">${esc(action.reason || "bez důvodu")}${action.finding_id ? ` · <button type="button" class="link" data-action="open-finding" data-key="${esc(action.finding_id)}">${title ? `nález: ${esc(title.slice(0, 60))}` : "nález"}</button>` : ""}</p>
    ${own ? `<p class="small hot-text">Pozor: adresa patří stanici ${esc(own.hostname ?? own.ip)} ve vaší síti. Blok ji odpojí.</p>` : ""}
    <p class="small muted">${esc(outcomeText(action, mode))}</p>
    <p class="small muted">navrženo ${esc(fmtDate(action.proposed_at))}${action.decided_by ? ` · rozhodl ${esc(action.decided_by)}` : ""}${action.applied_at ? ` · aplikováno ${esc(fmtDate(action.applied_at))}` : ""}</p>
    <details class="cmd"><summary class="small">Příkaz pro nftables</summary><code class="mono small">nft ${esc(action.nft_command.join(" "))}</code></details>
    ${buttons}
  </li>`;
}

function ipHint(ip: string): { text: string; hot: boolean } {
  const problem = obviousProblemWithIp(ip);
  if (problem) return { text: problem, hot: true };
  const own = ownStationByIp(state.report, ip);
  if (own) {
    return {
      text: `Pozor: adresa patří stanici ${own.hostname ?? own.ip} ve vaší síti. Blok ji odpojí. Blokuje se obvykle útočník zvenčí.`,
      hot: true,
    };
  }
  return { text: "", hot: false };
}

function form(): string {
  const d = state.proposeDraft;
  const findings = state.report?.findings ?? [];
  const hint = ipHint(d.ip);
  return `<form class="propose" data-submit="enf-propose" aria-label="Navrhnout zásah" novalidate>
    <h2 class="eyebrow">Navrhnout blok adresy</h2>
    <p class="small muted">Návrh nic neblokuje. Zablokuje se až po schválení v seznamu.</p>
    <div class="form-grid">
      <div class="field-group"><label class="field"><span>IP adresa k zablokování</span><input class="mono" name="ip" data-draft="ip" value="${esc(d.ip)}" inputmode="decimal" autocomplete="off" spellcheck="false" required aria-describedby="ip-hint"${hint.hot ? ' aria-invalid="true"' : ""}></label>
      <p id="ip-hint" class="small field-hint${hint.hot ? " hot-text" : ""}" role="status">${esc(hint.text)}</p></div>
      <div class="field-group"><label class="field"><span>Platnost bloku</span>
        <span class="inline"><input class="mono ttl" name="ttl" aria-label="Platnost bloku, číslo" data-draft="ttl" type="number" min="1" step="1" value="${esc(d.ttl)}" required aria-describedby="ttl-hint">
        <select name="unit" data-draft="unit" aria-label="Jednotka platnosti"><option value="m"${d.unit === "m" ? " selected" : ""}>min</option><option value="h"${d.unit === "h" ? " selected" : ""}>h</option></select></span>
      </label>
      <p id="ttl-hint" class="small field-hint muted">Nejvýš 24 hodin. Po vypršení se blok odstraní sám, trvalý blok nejde.</p></div>
      <label class="field wide"><span>Důvod (zapíše se do auditu)</span><input name="reason" data-draft="reason" value="${esc(d.reason)}" autocomplete="off" required></label>
      <label class="field wide"><span>Související nález (volitelně)</span>
        <select name="finding_id" data-draft="finding_id"><option value="">žádný</option>${findings
          .map((f) => `<option value="${esc(f.finding_id)}"${d.finding_id === f.finding_id ? " selected" : ""}>${esc(f.title.slice(0, 60))}${f.host_key ? ` · ${esc(f.host_key)}` : ""}</option>`)
          .join("")}</select></label>
    </div>
    ${state.proposeError ? `<p class="form-error" role="alert">${esc(state.proposeError)}</p>` : ""}
    <div class="actions-row"><button type="submit" class="btn"${state.proposeBusy || state.denied.propose ? " disabled" : ""}>${state.proposeBusy ? "Odesílám…" : "Navrhnout"}</button><span class="small muted">${state.denied.propose ? "Návrh může podat analytik, operátor nebo správce. Tvoje role to nedovoluje." : "Chráněné adresy (loopback, link-local, multicast, rozsahy operátora) server odmítne."}</span></div>
  </form>`;
}

function render(): string {
  if (state.enforcement === undefined) return `${paneHead("Zásahy")}${emptyState("Načítám…", "Čekám na odpověď serveru.")}`;
  if (state.enforcement === null) {
    return `${paneHead("Zásahy")}${emptyState("Zásahy nejsou dostupné", "Tento server nenabízí správu zásahů. Po aktualizaci serveru se tady objeví návrhy a schvalování.")}`;
  }
  const { mode, actions } = state.enforcement;
  // Cekajici na rozhodnuti nahore, pak nejnovejsi.
  const sorted = [...actions].sort((a, b) => Number(b.status === "proposed") - Number(a.status === "proposed") || b.id - a.id);
  const pending = actions.filter((a) => a.status === "proposed").length;
  const empty = !sorted.length
    ? `<p class="muted small">Zatím nebyl navržen žádný zásah. Blok navrhneš formulářem, nebo v detailu nálezu přes „Navrhnout zásah“.</p>`
    : "";
  return `${paneHead("Zásahy", `<span class="mono small muted">${pending} čeká · ${actions.length} celkem</span>`)}
  <div class="enf scroll" data-keep="enf">
    ${banner(mode)}
    <section class="enf-list" aria-label="Návrhy a zásahy">
      <h2 class="eyebrow">Návrhy a zásahy</h2>
      ${sorted.length ? `<ul class="actions" aria-label="Seznam zásahů">${sorted.map((a) => row(a, mode)).join("")}</ul>` : empty}
    </section>
    ${form()}
  </div>`;
}

async function decide(id: number, decision: "approve" | "reject") {
  if (state.enfBusy !== null) return;
  const mode = state.enforcement?.mode ?? "dry_run";
  const action = state.enforcement?.actions.find((a) => a.id === id);
  if (decision === "approve") {
    const enforce = mode === "enforce";
    const own = action ? ownStationByIp(state.report, action.ip) : null;
    const title = findingTitle(action?.finding_id);
    const details: Array<[string, string]> = [
      ["Adresa", action?.ip ?? ""],
      ["Platnost", action ? `${fmtDuration(action.ttl_seconds)} od schválení` : ""],
      ["Důvod", action?.reason || "bez důvodu"],
    ];
    if (title) details.push(["Nález", title]);
    const ok = await confirmDialog(
      enforce ? `Zablokovat ${action?.ip ?? "adresu"} na bráně?` : "Schválit zásah zkušebně?",
      enforce
        ? `Adresa ${action?.ip ?? ""} bude zablokována na bráně na ${action ? fmtDuration(action.ttl_seconds) : "danou dobu"}. Po vypršení se blok odstraní sám.`
        : `Adresa ${action?.ip ?? ""} se označí jako schválená. Server běží ve zkušebním režimu, nic se na bráně nezmění.`,
      enforce ? "Zablokovat" : "Schválit zkušebně",
      enforce,
      {
        details,
        warnings: own ? [`Adresa patří stanici ${own.hostname ?? own.ip} ve vaší síti. Blok ji odpojí od sítě.`] : [],
        impact: enforce
          ? "Z tohoto okna blok předčasně zrušit nejde, skončí sám po uplynutí platnosti. Rozhodnutí se zapíše do auditu pod tvým jménem."
          : "Žádný provoz se neovlivní. Rozhodnutí se zapíše do auditu.",
      },
    );
    if (!ok) return;
  }
  state.enfBusy = id;
  update({ error: null });
  try {
    const result = await api.decide(id, decision);
    const ip = result?.ip ?? action?.ip ?? "";
    if (decision === "reject") notify(`Zásah pro ${ip} zamítnut. Na bráně se nic nezměnilo.`);
    else if (result?.status === "applied") notify(`Adresa ${ip} je zablokovaná na bráně na ${fmtDuration(result.ttl_seconds)}.`);
    else notify(`Zásah pro ${ip} schválen zkušebně. Nic se neblokuje.`);
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      state.denied.approve = true;
      update({ error: "Schvalování zásahů vyžaduje roli operátor nebo správce." }, true);
    } else {
      update({ error: error instanceof Error ? error.message : String(error) }, true);
    }
  } finally {
    state.enfBusy = null;
  }
  await refreshEnforcement();
  state.audit = undefined;
  if (state.section === "audit") void refreshAudit();
}

async function submitPropose(el: HTMLElement) {
  if (state.proposeBusy) return;
  const formEl = el as HTMLFormElement;
  const data = new FormData(formEl);
  const ip = String(data.get("ip") ?? "").trim();
  const reason = String(data.get("reason") ?? "").trim();
  const ttlValue = Number(data.get("ttl"));
  const unit = String(data.get("unit") ?? "h");
  const findingId = String(data.get("finding_id") ?? "");
  if (!ip || !reason || !Number.isFinite(ttlValue) || ttlValue < 1) {
    update({ proposeError: "Vyplň adresu, důvod a platnost (alespoň 1)." });
    return;
  }
  // zjevne spatne vstupy zachytime hned, bez cesty na server
  const problem = obviousProblemWithIp(ip);
  if (problem) {
    update({ proposeError: problem });
    return;
  }
  const ttl_seconds = Math.round(ttlValue * (unit === "m" ? 60 : 3600));
  if (ttl_seconds > MAX_TTL_SECONDS) {
    update({ proposeError: REJECTION_TEXT.TtlExceedsMaximum });
    return;
  }
  update({ proposeBusy: true, proposeError: null });
  try {
    await api.propose({ ip, ttl_seconds, reason, ...(findingId ? { finding_id: findingId } : {}) });
    update({ proposeBusy: false, proposeDraft: { ip: "", finding_id: "", reason: "", ttl: "1", unit: "h" } });
    notify(`Návrh bloku ${ip} je v seznamu a čeká na schválení. Zatím se nic neblokuje.`);
    await refreshEnforcement();
  } catch (error) {
    let text = error instanceof Error ? error.message : String(error);
    if (error instanceof ApiError && error.status === 403) {
      state.denied.propose = true;
      text = "Návrh zásahu vyžaduje roli analytik, operátor nebo správce.";
    }
    if (error instanceof ApiError && (error.status === 422 || error.status === 409)) {
      const code = (error.body as { error?: string } | null)?.error ?? "";
      text = REJECTION_TEXT[code] ?? `Server zásah odmítl (${code || "422"}).`;
    }
    update({ proposeBusy: false, proposeError: text });
  }
}

export const enforcement: View = {
  id: "zasahy",
  label: "Zásahy",
  abbr: "ZA",
  render,
  actions: {
    "enf-approve": (el) => decide(Number(el.dataset.key), "approve"),
    "enf-reject": (el) => decide(Number(el.dataset.key), "reject"),
    "enf-propose": (el) => submitPropose(el),
    "open-finding": (el) => {
      update({ selectedFinding: el.dataset.key ?? null }, false);
      window.location.hash = `#/nalezy/${encodeURIComponent(el.dataset.key ?? "")}`;
    },
  },
  after() {
    // zivy popisek u pole IP bez prekresleni formulare (neprijde se o fokus ani rozepsany text)
    const input = document.querySelector<HTMLInputElement>('.propose input[name="ip"]');
    const out = document.getElementById("ip-hint");
    if (!input || !out) return;
    input.addEventListener("input", () => {
      const hint = ipHint(input.value);
      out.textContent = hint.text;
      out.classList.toggle("hot-text", hint.hot);
      if (hint.hot) input.setAttribute("aria-invalid", "true");
      else input.removeAttribute("aria-invalid");
    });
  },
};
