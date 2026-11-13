import type {
  AuditEntry,
  AuditVerify,
  AutomationLatest,
  AutomationStatus,
  EnforcementAction,
  EnforcementList,
  Meta,
  PentestMode,
  Readiness,
  Report,
  RunIndexEntry,
  VerificationLatest,
} from "./types";

const TOKEN_KEY = "salticusApiToken";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public body: unknown = null,
  ) {
    super(message);
  }
}

// Token zije jen po dobu relace (sessionStorage). Starou hodnotu z localStorage
// jednorazove prevezmeme a smazeme.
export function getToken(): string {
  try {
    const legacy = window.localStorage.getItem(TOKEN_KEY);
    if (legacy) {
      window.sessionStorage.setItem(TOKEN_KEY, legacy);
      window.localStorage.removeItem(TOKEN_KEY);
      window.localStorage.removeItem("salticusApiTokenDismissed");
    }
    return window.sessionStorage.getItem(TOKEN_KEY)?.trim() ?? "";
  } catch {
    return "";
  }
}

export function setToken(token: string) {
  const clean = token.trim();
  if (clean) window.sessionStorage.setItem(TOKEN_KEY, clean);
  else window.sessionStorage.removeItem(TOKEN_KEY);
}

type AuthHandler = () => Promise<string | null>;
let authHandler: AuthHandler | null = null;
export function setAuthHandler(handler: AuthHandler) {
  authHandler = handler;
}

function headersFor(method: string, extra?: Record<string, string>): HeadersInit {
  const headers: Record<string, string> = { ...extra };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  // Vlastni hlavicka brani cross-site <form> POSTu (CSRF); server ji vyzaduje u mutaci.
  if (method !== "GET") headers["X-Salticus-Csrf"] = "1";
  return headers;
}

async function raw(path: string, init: RequestInit = {}, retried = false): Promise<Response> {
  const method = (init.method ?? "GET").toUpperCase();
  const response = await fetch(path, {
    ...init,
    method,
    headers: headersFor(method, init.headers as Record<string, string> | undefined),
  });
  if (response.status === 401 && !retried && authHandler) {
    const token = await authHandler();
    if (token) {
      setToken(token);
      return raw(path, init, true);
    }
  }
  return response;
}

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await raw(path, init);
  if (!response.ok) {
    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      /* odpoved bez JSON tela */
    }
    const detail = (body as { error?: string } | null)?.error;
    throw new ApiError(response.status, detail ? String(detail) : `Požadavek ${path} selhal (${response.status}).`, body);
  }
  return (await response.json()) as T;
}

// Volitelne endpointy: 404 (server funkci nema) a chyba -> null, UI ukaze poctivy prazdny stav.
async function optional<T>(path: string): Promise<T | null> {
  try {
    return await json<T>(path);
  } catch (error) {
    if (error instanceof ApiError && (error.status === 404 || error.status === 405)) return null;
    throw error;
  }
}

export const api = {
  meta: () => json<Meta>("/api/meta"),
  runs: () => json<RunIndexEntry[]>("/api/runs"),
  run: (id: string) => json<Report>(`/api/runs/${encodeURIComponent(id)}`),
  verificationLatest: () => json<VerificationLatest>("/api/verification/latest").catch(() => null),
  automationLatest: () => json<AutomationLatest>("/api/automation/latest").catch(() => null),
  automationStatus: () => json<AutomationStatus>("/api/automation/status").catch(() => null),
  readiness: () => json<Readiness>("/api/readiness").catch(() => null),
  aiStatus: () => json<Record<string, unknown>>("/api/ai/status").catch(() => null),

  enforcement: () => optional<EnforcementList>("/api/enforcement/actions"),
  propose: (body: { ip: string; ttl_seconds: number; reason: string; finding_id?: string }) =>
    json<EnforcementAction>("/api/enforcement/propose", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
  decide: (id: number, decision: "approve" | "reject") =>
    json<EnforcementAction>(`/api/enforcement/${id}/${decision}`, { method: "POST" }),
  auditVerify: () => optional<AuditVerify>("/api/audit/verify"),
  audit: (limit: number) => optional<AuditEntry[]>(`/api/audit?limit=${limit}`),

  restartAutomation: (mode: PentestMode) =>
    raw(mode === "off" ? "/api/automation/restart" : `/api/automation/restart?pentest=${encodeURIComponent(mode)}`, {
      method: "POST",
    }),
  resetAutomation: () => raw("/api/automation/reset", { method: "POST" }),

  async exportRun(id: string, format: "json" | "md" | "txt") {
    const response = await raw(`/api/runs/${encodeURIComponent(id)}/export/${format}`);
    if (!response.ok) throw new ApiError(response.status, `Export ${format} selhal (${response.status}).`);
    const blob = await response.blob();
    const disposition = response.headers.get("content-disposition");
    const name = disposition?.match(/filename="([^"]+)"/)?.[1] ?? `${id}.${format}`;
    return { blob, name };
  },
};

export type AssistantContext = {
  detail_panel: string;
  selected_node_id: string | null;
  selected_finding_id: string | null;
  selected_asset_id: string | null;
  selected_action_id: string | null;
};

type History = Array<{ role: string; text: string }>;

export async function askAssistant(runId: string, prompt: string, context: AssistantContext, history: History) {
  const response = await raw(`/api/runs/${encodeURIComponent(runId)}/assistant`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ prompt, ...context, history }),
  });
  if (!response.ok) throw new ApiError(response.status, `Asistent neodpověděl (${response.status}).`);
  const payload = (await response.json()) as {
    answer?: string;
    mode?: string;
    sources?: Array<{ label?: string; url?: string | null }>;
  };
  const sources = (payload.sources ?? []).map((item) => item.label || item.url || "").filter(Boolean);
  if (payload.mode) sources.unshift(`engine:${payload.mode}`);
  return { answer: payload.answer?.trim() ?? "", sources };
}

export async function askAssistantStream(
  runId: string,
  prompt: string,
  context: AssistantContext,
  history: History,
  onChunk: (chunk: string) => void,
) {
  const response = await raw(`/api/runs/${encodeURIComponent(runId)}/assistant/stream`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ prompt, ...context, history }),
  });
  if (!response.ok || !response.body) return askAssistant(runId, prompt, context, history);

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let answer = "";
  const sources: string[] = [];
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) {
      if (!line.trim().startsWith("data:")) continue;
      const payload = line.replace(/^data:\s*/, "");
      if (payload === "[DONE]") continue;
      const event = JSON.parse(payload) as { type: string; text?: string; mode?: string; sources?: string[]; error?: string };
      if (event.type === "chunk" && event.text) {
        answer += event.text;
        onChunk(event.text);
      }
      if (event.type === "done") {
        if (event.mode) sources.unshift(`engine:${event.mode}`);
        sources.push(...(event.sources ?? []));
      }
      if (event.type === "error") throw new Error(event.error || "Stream asistenta selhal.");
    }
  }
  if (!answer.trim()) return askAssistant(runId, prompt, context, history);
  return { answer: answer.trim(), sources };
}
