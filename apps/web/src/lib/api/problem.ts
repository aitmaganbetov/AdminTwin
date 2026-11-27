// RFC 9457 (application/problem+json): разбор ответов об ошибках ядра (pkg/problem).
import type { FieldError, Problem, ProblemCode } from "./types";

export const ERROR_TYPE_BASE = "https://errors.admintwin.io/";

const KNOWN_CODES: ProblemCode[] = [
  "policy-denied",
  "budget-exhausted",
  "kill-switch-active",
  "legal-hold",
  "separation-of-duties",
  "invalid-params",
  "not-found",
  "unauthenticated",
  "forbidden",
  "invalid-transition",
  "conflict",
  "idempotency-key-reused",
  "bad-request",
  "internal",
];

/**
 * Виды ошибок клиента:
 *  - problem — сервер вернул RFC 9457;
 *  - module-unavailable — маршрут не зарегистрирован в ядре (модуль Этапа 1 ещё не подключён);
 *  - upstream-unavailable — ядро/оркестратор недоступны (502/503/504);
 *  - network — запрос не дошёл (fetch бросил исключение);
 *  - http — прочие ответы без problem-тела.
 */
export type ApiErrorKind = "problem" | "module-unavailable" | "upstream-unavailable" | "network" | "http";

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number;
  readonly problem: Problem;
  readonly requestId?: string;

  constructor(kind: ApiErrorKind, problem: Problem, requestId?: string) {
    super(problem.detail ? `${problem.title}: ${problem.detail}` : problem.title);
    this.name = "ApiError";
    this.kind = kind;
    this.status = problem.status;
    this.problem = problem;
    this.requestId = problem.request_id || requestId;
  }

  /** Машинный код (последний сегмент type) — policy-denied, separation-of-duties, ... */
  get code(): ProblemCode | string {
    return problemCode(this.problem);
  }

  get fieldErrors(): FieldError[] {
    return Array.isArray(this.problem.errors) ? this.problem.errors : [];
  }
}

export function isApiError(e: unknown): e is ApiError {
  return e instanceof ApiError;
}

/** Код ошибки из поля type. about:blank / неизвестный домен → код по HTTP-статусу. */
export function problemCode(p: Pick<Problem, "type" | "status">): ProblemCode | string {
  const t = (p.type || "").trim();
  if (t && t !== "about:blank") {
    const seg = t.replace(/[?#].*$/, "").replace(/\/+$/, "").split("/").pop() || "";
    if (seg) return seg;
  }
  return codeForStatus(p.status);
}

export function isKnownCode(code: string): code is ProblemCode {
  return (KNOWN_CODES as string[]).includes(code);
}

export function codeForStatus(status: number): ProblemCode {
  switch (status) {
    case 400:
      return "bad-request";
    case 401:
      return "unauthenticated";
    case 403:
      return "forbidden";
    case 404:
      return "not-found";
    case 409:
      return "conflict";
    case 422:
      return "invalid-params";
    default:
      return "internal";
  }
}

export function isProblemContentType(ct: string | null | undefined): boolean {
  return !!ct && /application\/problem\+json/i.test(ct);
}

function isJsonContentType(ct: string | null | undefined): boolean {
  return !!ct && /application\/(.+\+)?json/i.test(ct);
}

function normalizeFieldErrors(v: unknown): FieldError[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: FieldError[] = [];
  for (const e of v) {
    if (e && typeof e === "object") {
      const o = e as Record<string, unknown>;
      out.push({ field: String(o.field ?? o.name ?? o.pointer ?? ""), reason: String(o.reason ?? o.detail ?? o.message ?? "") });
    }
  }
  return out;
}

/**
 * Строит Problem и вид ошибки из HTTP-ответа. Тело передаётся текстом, чтобы функция
 * была чистой и тестируемой без fetch.
 */
export function parseProblemResponse(
  status: number,
  contentType: string | null,
  bodyText: string,
  headerRequestId?: string | null,
): { kind: ApiErrorKind; problem: Problem } {
  let parsed: Record<string, unknown> | null = null;
  if (bodyText && (isProblemContentType(contentType) || isJsonContentType(contentType))) {
    try {
      const j = JSON.parse(bodyText);
      if (j && typeof j === "object" && !Array.isArray(j)) parsed = j as Record<string, unknown>;
    } catch {
      parsed = null;
    }
  }
  const looksLikeProblem = !!parsed && (isProblemContentType(contentType) || typeof parsed.title === "string" || typeof parsed.type === "string");

  if (parsed && looksLikeProblem) {
    const problem: Problem = {
      ...parsed,
      type: typeof parsed.type === "string" ? parsed.type : "about:blank",
      title: typeof parsed.title === "string" ? parsed.title : statusTitle(status),
      status: typeof parsed.status === "number" ? parsed.status : status,
      detail: typeof parsed.detail === "string" ? parsed.detail : undefined,
      request_id: typeof parsed.request_id === "string" ? parsed.request_id : headerRequestId || undefined,
      errors: normalizeFieldErrors(parsed.errors),
    };
    const kind: ApiErrorKind = status === 502 || status === 503 || status === 504 ? "upstream-unavailable" : "problem";
    return { kind, problem };
  }

  // Ответ без problem-тела: мультиплексор Go отдаёт text/plain "404 page not found" для
  // незарегистрированных маршрутов — это признак того, что модуль ещё не подключён.
  let kind: ApiErrorKind = "http";
  if (status === 404 || status === 405 || status === 501) kind = "module-unavailable";
  else if (status === 502 || status === 503 || status === 504) kind = "upstream-unavailable";
  const text = bodyText.trim().slice(0, 300);
  return {
    kind,
    problem: {
      type: "about:blank",
      title: statusTitle(status),
      status,
      detail: text || undefined,
      request_id: headerRequestId || undefined,
    },
  };
}

export function statusTitle(status: number): string {
  const titles: Record<number, string> = {
    400: "Bad request",
    401: "Unauthenticated",
    403: "Forbidden",
    404: "Not found",
    405: "Method not allowed",
    409: "Conflict",
    422: "Unprocessable content",
    429: "Too many requests",
    500: "Internal error",
    501: "Not implemented",
    502: "Bad gateway",
    503: "Service unavailable",
    504: "Gateway timeout",
  };
  return titles[status] || `HTTP ${status}`;
}

export function networkError(err: unknown, requestId?: string): ApiError {
  const detail = err instanceof Error ? err.message : String(err);
  return new ApiError("network", { type: "about:blank", title: "Network error", status: 0, detail, request_id: requestId }, requestId);
}

/** Сопоставляет ошибки полей вида "params.container_id" с именем параметра runbook. */
export function paramFieldErrors(errors: FieldError[] | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const e of errors || []) {
    const name = e.field.startsWith("params.") ? e.field.slice("params.".length) : e.field;
    out[name] = out[name] ? `${out[name]}; ${e.reason}` : e.reason;
  }
  return out;
}
