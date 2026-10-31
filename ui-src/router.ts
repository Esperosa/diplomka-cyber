import type { SectionId } from "./state";

export const SECTIONS: SectionId[] = ["prehled", "hostitele", "nalezy", "overovani", "zasahy", "audit", "automat"];

export function navigate(section: SectionId, param: string | null = null) {
  const hash = `#/${section}${param ? `/${encodeURIComponent(param)}` : ""}`;
  if (window.location.hash === hash) window.dispatchEvent(new HashChangeEvent("hashchange"));
  else window.location.hash = hash;
}

/** Cast hashe za otaznikem (stav filtru mapy: `#/prehled?v=vlan:30&t=ap`). */
export function hashQuery(hash: string): URLSearchParams {
  const i = hash.indexOf("?");
  return new URLSearchParams(i >= 0 ? hash.slice(i + 1) : "");
}

export function parseHash(hash: string): { section: SectionId; param: string | null } {
  const path = hash.includes("?") ? hash.slice(0, hash.indexOf("?")) : hash;
  const [, raw = "", ...rest] = path.replace(/^#/, "").split("/");
  const section = (SECTIONS as string[]).includes(raw) ? (raw as SectionId) : "prehled";
  const param = rest.length ? decodeURIComponent(rest.join("/")) : null;
  return { section, param };
}
