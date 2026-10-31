import type { SectionId } from "./state";

export const SECTIONS: SectionId[] = ["prehled", "hostitele", "nalezy", "overovani", "zasahy", "audit", "automat"];

export function navigate(section: SectionId, param: string | null = null) {
  const hash = `#/${section}${param ? `/${encodeURIComponent(param)}` : ""}`;
  if (window.location.hash === hash) window.dispatchEvent(new HashChangeEvent("hashchange"));
  else window.location.hash = hash;
}

export function parseHash(hash: string): { section: SectionId; param: string | null } {
  const [, raw = "", ...rest] = hash.replace(/^#/, "").split("/");
  const section = (SECTIONS as string[]).includes(raw) ? (raw as SectionId) : "prehled";
  const param = rest.length ? decodeURIComponent(rest.join("/")) : null;
  return { section, param };
}
