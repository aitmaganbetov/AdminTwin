// Типизированный HTTP-клиент: все вызовы — относительные /api/v1/* (Next rewrites → ADMINTWIN_CORE_URL).
import { ApiError, networkError, parseProblemResponse } from "./problem";

export type Query = Record<string, string | number | boolean | undefined | null>;

export interface RequestOptions {
  query?: Query;
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

export interface ApiResponse<T> {
  data: T;
  status: number;
  requestId?: string;
}

export interface ClientOptions {
  /** Префикс URL; по умолчанию "" (тот же origin, rewrite Next). */
  baseUrl?: string;
  /** Заголовки идентичности: Authorization: Bearer (OIDC) или X-AdminTwin-* (dev). */
  getHeaders: () => Record<string, string>;
  fetchImpl?: typeof fetch;
  /** Вызывается при 401 — сессия истекла или идентичность отклонена. */
  onUnauthenticated?: (e: ApiError) => void;
  newRequestId?: () => string;
}

export function randomId(): string {
  const c = globalThis.crypto;
  if (c && typeof c.randomUUID === "function") return c.randomUUID();
  const b = new Uint8Array(16);
  if (c && typeof c.getRandomValues === "function") c.getRandomValues(b);
  else for (let i = 0; i < 16; i++) b[i] = Math.floor(Math.random() * 256);
  b[6] = (b[6]! & 0x0f) | 0x40;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const h = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export function buildUrl(baseUrl: string, path: string, query?: Query): string {
  if (!path.startsWith("/api/v1/")) {
    throw new Error(`API path must start with /api/v1/: ${path}`);
  }
  let url = baseUrl.replace(/\/+$/, "") + path;
  if (query) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) {
      if (v === undefined || v === null || v === "") continue;
      qs.set(k, String(v));
    }
    const s = qs.toString();
    if (s) url += (url.includes("?") ? "&" : "?") + s;
  }
  return url;
}

export class ApiClient {
  private readonly opts: ClientOptions;

  constructor(opts: ClientOptions) {
    this.opts = opts;
  }

  /** Заголовки для запросов вне клиента (SSE через fetch). */
  authHeaders(): Record<string, string> {
    return { ...this.opts.getHeaders() };
  }

  url(path: string, query?: Query): string {
    return buildUrl(this.opts.baseUrl ?? "", path, query);
  }

  async request<T>(method: string, path: string, ro: RequestOptions = {}): Promise<ApiResponse<T>> {
    const f = this.opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
    const rid = (this.opts.newRequestId ?? randomId)().replace(/-/g, "");
    const headers: Record<string, string> = {
      Accept: "application/json, application/problem+json",
      "X-Request-ID": rid,
      ...this.opts.getHeaders(),
      ...(ro.headers || {}),
    };
    let body: string | undefined;
    if (ro.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(ro.body);
    }
    let res: Response;
    try {
      res = await f(this.url(path, ro.query), { method, headers, body, signal: ro.signal, cache: "no-store", credentials: "same-origin" });
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") throw e;
      throw networkError(e, rid);
    }
    const requestId = res.headers.get("X-Request-ID") || rid;
    const text = await res.text();
    if (!res.ok) {
      const { kind, problem } = parseProblemResponse(res.status, res.headers.get("Content-Type"), text, requestId);
      const err = new ApiError(kind, problem, requestId);
      if (res.status === 401 && kind === "problem") this.opts.onUnauthenticated?.(err);
      throw err;
    }
    let data: unknown = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        const { problem } = parseProblemResponse(502, "text/plain", "invalid JSON in response", requestId);
        throw new ApiError("http", problem, requestId);
      }
    }
    return { data: data as T, status: res.status, requestId };
  }

  async get<T>(path: string, query?: Query, signal?: AbortSignal): Promise<T> {
    return (await this.request<T>("GET", path, { query, signal })).data;
  }

  async post<T>(path: string, body?: unknown, headers?: Record<string, string>): Promise<T> {
    return (await this.request<T>("POST", path, { body, headers })).data;
  }
}
