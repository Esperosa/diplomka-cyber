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

export async function confirmDialog(title: string, text: string, confirmLabel: string, hot = false): Promise<boolean> {
  const { dialog, done } = openDialog(`<form method="dialog">
    <h2>${esc(title)}</h2>
    <p>${esc(text)}</p>
    <div class="modal-actions">
      <button type="submit" value="cancel" class="btn btn-ghost">Zrušit</button>
      <button type="submit" value="yes" class="btn${hot ? " btn-hot" : ""}" autofocus>${esc(confirmLabel)}</button>
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
