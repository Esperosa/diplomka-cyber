// Zpetna vazba po akci: viditelny toast + zprava pro ctecku (aria-live). Chyby jdou do #errorbar (role=alert).
let timer = 0;

function ensure(): { live: HTMLElement; toast: HTMLElement } {
  let live = document.getElementById("announcer");
  if (!live) {
    live = document.createElement("div");
    live.id = "announcer";
    live.className = "sr-only";
    live.setAttribute("role", "status");
    live.setAttribute("aria-live", "polite");
    live.setAttribute("aria-atomic", "true");
    document.body.append(live);
  }
  let toast = document.getElementById("toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "toast";
    toast.className = "toast";
    toast.hidden = true;
    toast.setAttribute("aria-hidden", "true"); // cteni zajistuje #announcer, ne duplicitni toast
    document.body.append(toast);
  }
  return { live, toast };
}

/** Potvrzeni uspechu: ukaze se na par vterin a prečte se čtečkou. */
export function notify(text: string, ms = 6000): void {
  const { live, toast } = ensure();
  live.textContent = "";
  window.setTimeout(() => {
    live.textContent = text;
  }, 30);
  toast.textContent = text;
  toast.hidden = false;
  window.clearTimeout(timer);
  timer = window.setTimeout(() => {
    toast.hidden = true;
  }, ms);
}

/** Jen pro čtečku (např. změna stavu na pozadí). */
export function announce(text: string): void {
  const { live } = ensure();
  live.textContent = "";
  window.setTimeout(() => {
    live.textContent = text;
  }, 30);
}
