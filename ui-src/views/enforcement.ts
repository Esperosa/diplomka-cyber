import { api, ApiError } from "../api";
import { refreshAudit, refreshEnforcement } from "../data";
import { confirmDialog } from "../dialogs";
import { state, update, type View } from "../state";
import type { EnforcementAction, EnforcementStatus } from "../types";
import { countdown, esc, fmtDate, fmtDuration } from "../ui";
import { chip, emptyState, paneHead } from "./common";

const STATUS_LABEL: Record<EnforcementStatus, string> = {
  proposed: "navrženo",
  approved: "schváleno",
  rejected: "zamítnuto",
  applied: "aktivní",
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
    ? `<div class="mode-banner is-enforce" role="status"><strong>Ostrý režim.</strong> Schválený zásah se provede na bráně.</div>`
    : `<div class="mode-banner" role="status"><strong>Zkušební režim.</strong> Schválený zásah se jen zapíše. Do firewallu se nic neposílá.</div>`;
}

function statusTone(status: EnforcementStatus) {
  return status === "applied" ? "ink" : status === "failed" || status === "rejected" ? "hot" : "mute";
}

function row(action: EnforcementAction): string {
  const live =
    action.status === "applied" && action.applied_at
      ? `<span class="mono" data-expires-at="${Date.parse(action.applied_at) + action.ttl_seconds * 1000}" aria-label="zbývající platnost">${countdown(Math.max(0, (Date.parse(action.applied_at) + action.ttl_seconds * 1000 - Date.now()) / 1000))}</span>`
      : `<span class="mono small muted">platnost ${esc(fmtDuration(action.ttl_seconds))}</span>`;
  const canDecide = action.status === "proposed";
  return `<li class="action">
    <div class="action-main">
      <span class="mono big-ip">${esc(action.ip)}</span>
      ${chip(STATUS_LABEL[action.status] ?? action.status, statusTone(action.status))}
      ${live}
    </div>
    <p class="small">${esc(action.reason || "bez důvodu")}${action.finding_id ? ` · <button type="button" class="link" data-action="open-finding" data-key="${esc(action.finding_id)}">nález</button>` : ""}</p>
    <p class="small muted">navrženo ${esc(fmtDate(action.proposed_at))}${action.decided_by ? ` · rozhodl ${esc(action.decided_by)}` : ""}${action.applied_at ? ` · aplikováno ${esc(fmtDate(action.applied_at))}` : ""}</p>
    <details class="cmd"><summary class="small">Příkaz pro nftables</summary><code class="mono small">nft ${esc(action.nft_command.join(" "))}</code></details>
    ${
      canDecide
        ? `<div class="actions-row"><button type="button" class="btn" data-action="enf-approve" data-key="${action.id}"${state.denied.approve ? " disabled aria-describedby=\"deny-why\"" : ""}>Schválit</button><button type="button" class="btn btn-ghost" data-action="enf-reject" data-key="${action.id}"${state.denied.approve ? " disabled aria-describedby=\"deny-why\"" : ""}>Zamítnout</button>${state.denied.approve ? `<span id="deny-why" class="small muted">Schvalovat a zamítat může jen operátor nebo správce. Tvoje role to nedovoluje.</span>` : ""}</div>`
        : ""
    }
  </li>`;
}

function form(): string {
  const d = state.proposeDraft;
  const findings = state.report?.findings ?? [];
  return `<form class="propose" data-submit="enf-propose" aria-label="Navrhnout zásah" novalidate>
    <h2 class="eyebrow">Navrhnout blok adresy</h2>
    <div class="form-grid">
      <label class="field"><span>IP adresa</span><input class="mono" name="ip" data-draft="ip" value="${esc(d.ip)}" inputmode="decimal" autocomplete="off" spellcheck="false" required></label>
      <label class="field"><span>Platnost</span>
        <span class="inline"><input class="mono ttl" name="ttl" data-draft="ttl" type="number" min="1" max="1440" value="${esc(d.ttl)}" required>
        <select name="unit" data-draft="unit" aria-label="Jednotka"><option value="m"${d.unit === "m" ? " selected" : ""}>min</option><option value="h"${d.unit === "h" ? " selected" : ""}>h</option></select></span>
      </label>
      <label class="field wide"><span>Důvod</span><input name="reason" data-draft="reason" value="${esc(d.reason)}" autocomplete="off" required></label>
      <label class="field wide"><span>Související nález (volitelně)</span>
        <select name="finding_id" data-draft="finding_id"><option value="">žádný</option>${findings
          .map((f) => `<option value="${esc(f.finding_id)}"${d.finding_id === f.finding_id ? " selected" : ""}>${esc(f.title.slice(0, 70))}</option>`)
          .join("")}</select></label>
    </div>
    ${state.proposeError ? `<p class="form-error" role="alert">${esc(state.proposeError)}</p>` : ""}
    <div class="actions-row"><button type="submit" class="btn"${state.proposeBusy || state.denied.propose ? " disabled" : ""}>Navrhnout</button><span class="small muted">${state.denied.propose ? "Návrh může podat analytik, operátor nebo správce. Tvoje role to nedovoluje." : "Maximum je 24 h. Chráněné adresy server odmítne."}</span></div>
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
  return `${paneHead("Zásahy", `<span class="mono small muted">${pending} čeká · ${actions.length} celkem</span>`)}
  <div class="enf scroll" data-keep="enf">
    ${banner(mode)}
    <section class="enf-list" aria-label="Návrhy a zásahy">
      <h2 class="eyebrow">Návrhy a zásahy</h2>
      ${sorted.length ? `<ul class="actions" aria-label="Seznam zásahů">${sorted.map(row).join("")}</ul>` : `<p class="muted small">Zatím nebyl navržen žádný zásah.</p>`}
    </section>
    ${form()}
  </div>`;
}

async function decide(id: number, decision: "approve" | "reject") {
  const mode = state.enforcement?.mode ?? "dry_run";
  const action = state.enforcement?.actions.find((a) => a.id === id);
  if (decision === "approve") {
    const ok = await confirmDialog(
      "Schválit zásah?",
      mode === "enforce"
        ? `Adresa ${action?.ip ?? ""} bude zablokována na bráně na ${action ? fmtDuration(action.ttl_seconds) : "danou dobu"}. Po vypršení se blok odstraní sám.`
        : `Adresa ${action?.ip ?? ""} se označí jako schválená. Server běží ve zkušebním režimu, nic se na bráně nezmění.`,
      "Schválit",
      mode === "enforce",
    );
    if (!ok) return;
  }
  try {
    await api.decide(id, decision);
    update({ error: null }, false);
  } catch (error) {
    if (error instanceof ApiError && error.status === 403) {
      state.denied.approve = true;
      update({ error: "Schvalování zásahů vyžaduje roli operátor nebo správce." }, true);
    } else {
      update({ error: error instanceof Error ? error.message : String(error) }, true);
    }
  }
  await refreshEnforcement();
  state.audit = undefined;
  if (state.section === "audit") void refreshAudit();
}

async function submitPropose(el: HTMLElement) {
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
  const ttl_seconds = Math.round(ttlValue * (unit === "m" ? 60 : 3600));
  update({ proposeBusy: true, proposeError: null });
  try {
    await api.propose({ ip, ttl_seconds, reason, ...(findingId ? { finding_id: findingId } : {}) });
    update({ proposeBusy: false, proposeDraft: { ip: "", finding_id: "", reason: "", ttl: "1", unit: "h" } });
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
};
