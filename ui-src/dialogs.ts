import { esc } from "./ui";

function openDialog(html: string): { dialog: HTMLDialogElement; done: Promise<string | null> } {
  const dialog = document.createElement("dialog");
  dialog.className = "modal";
  dialog.innerHTML = html;
  document.body.append(dialog);
  const done = new Promise<string | null>((resolve) => {
    dialog.addEventListener("close", () => {
      const value = dialog.returnValue || null;
      dialog.remove();
      resolve(value === "cancel" ? null : value);
    });
  });
  dialog.showModal();
  return { dialog, done };
}

export type ConfirmOptions = {
  /** Dvojice popisek / hodnota: co přesně se stane. */
  details?: Array<[string, string]>;
  /** Varování zvýrazněná v dialogu (např. adresa patří vlastní stanici). */
  warnings?: string[];
  /** Poznámka o dopadu a vrácení (jedna věta až dvě). */
  impact?: string;
};

/**
 * Potvrzení nevratné nebo citlivé akce. U nebezpečných akcí (`hot`) je výchozí fokus na „Zrušit“,
 * aby náhodný Enter nic neprovedl.
 */
export async function confirmDialog(
  title: string,
  text: string,
  confirmLabel: string,
  hot = false,
  options: ConfirmOptions = {},
): Promise<boolean> {
  const details = options.details?.length
    ? `<dl class="modal-kv">${options.details.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}</dl>`
    : "";
  const warnings = (options.warnings ?? []).map((w) => `<p class="modal-warn" role="note"><strong>Pozor.</strong> ${esc(w)}</p>`).join("");
  const impact = options.impact ? `<p class="modal-impact small muted">${esc(options.impact)}</p>` : "";
  const { dialog, done } = openDialog(`<form method="dialog">
    <h2>${esc(title)}</h2>
    <p>${esc(text)}</p>
    ${details}${warnings}${impact}
    <div class="modal-actions">
      <button type="submit" value="cancel" class="btn btn-ghost"${hot ? " autofocus" : ""}>Zrušit</button>
      <button type="submit" value="yes" class="btn${hot ? " btn-hot" : ""}"${hot ? "" : " autofocus"}>${esc(confirmLabel)}</button>
    </div>
  </form>`);
  dialog.querySelector<HTMLButtonElement>("button[autofocus]")?.focus();
  return (await done) === "yes";
}

export async function tokenDialog(): Promise<string | null> {
  const { dialog, done } = openDialog(`<form method="dialog">
    <h2>API token</h2>
    <p>Server vyžaduje token. Uloží se jen pro tuto relaci prohlížeče.</p>
    <label class="field"><span>Token</span><input type="password" name="token" autocomplete="off" spellcheck="false" required></label>
    <div class="modal-actions">
      <button type="submit" value="cancel" class="btn btn-ghost" formnovalidate>Zrušit</button>
      <button type="submit" value="ok" class="btn">Použít</button>
    </div>
  </form>`);
  const input = dialog.querySelector<HTMLInputElement>("input[name=token]");
  input?.focus();
  let captured = "";
  dialog.querySelector("form")?.addEventListener("submit", (event) => {
    const submitter = (event as SubmitEvent).submitter as HTMLButtonElement | null;
    if (submitter?.value === "ok") captured = input?.value.trim() ?? "";
  });
  const result = await done;
  return result === "ok" && captured ? captured : null;
}
