import type {
  AuditEntry,
  AutomationLatest,
  AutomationStatus,
  ChatMessage,
  EnforcementList,
  Meta,
  PentestMode,
  Readiness,
  Report,
  RunIndexEntry,
  VerificationLatest,
} from "./types";

export type SectionId = "prehled" | "hostitele" | "nalezy" | "overovani" | "zasahy" | "audit" | "automat";

export type View = {
  id: SectionId;
  label: string;
  abbr: string;
  render: () => string;
  actions: Record<string, (el: HTMLElement, event: Event) => void | Promise<void>>;
  /** Volano po vykresleni (napr. pro naplneni dynamickych casti). */
  after?: () => void;
};

export const state = {
  section: "prehled" as SectionId,
  param: null as string | null,

  meta: null as Meta | null,
  runs: [] as RunIndexEntry[],
  activeRunId: null as string | null,
  report: null as Report | null,
  verification: null as VerificationLatest,
  automationLatest: null as AutomationLatest,
  automationStatus: null as AutomationStatus,
  readiness: null as Readiness,
  /** undefined = jeste nenacteno, null = server funkci nema. */
  enforcement: undefined as EnforcementList | null | undefined,
  audit: undefined as AuditEntry[] | null | undefined,
  auditLimit: 100,
  auditChain: undefined as { chain_ok: boolean } | null | undefined,
  /** Role se uci z odpovedi serveru: po 403 se tlacitka vypnou s vysvetlenim. */
  denied: { approve: false, propose: false },

  /** Server odpověděl 401 a token chybí nebo je špatný. */
  authNeeded: false,
  loading: true,
  error: null as string | null,
  connection: "ok" as "ok" | "error",
  lastUpdated: null as string | null,
  followLatest: true,

  selectedHost: null as string | null,
  hostsTab: "stanice" as "stanice" | "aktiva",
  selectedFinding: null as string | null,
  findingFilter: "all" as "all" | "high" | "medium" | "low",
  verifFilter: "all" as "all" | "approval" | "excluded",
  openPlans: new Set<string>(),
  openServices: new Set<string>(),

  proposeDraft: { ip: "", finding_id: "", reason: "", ttl: "1", unit: "h" } as {
    ip: string;
    finding_id: string;
    reason: string;
    ttl: string;
    unit: string;
  },
  proposeError: null as string | null,
  proposeBusy: false,
  enfBusy: null as number | null,

  pentestMode: "off" as PentestMode,
  assistantOpen: false,
  chat: [] as ChatMessage[],
  chatBusy: false,
  theme: "system" as "system" | "light" | "dark",
};

type Hook = (force: boolean) => void;
let hook: Hook = () => {};
export function onChange(fn: Hook) {
  hook = fn;
}
/** `force` = zmena z uzivatelske akce; soft = pozadi (neprepise rozepsany formular). */
export function update(patch: Partial<typeof state> = {}, force = true) {
  Object.assign(state, patch);
  hook(force);
}

export function activeHost() {
  return state.report?.hosts.find((host) => host.host_key === state.selectedHost) ?? null;
}
