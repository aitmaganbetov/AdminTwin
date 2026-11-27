// Server-Sent Events: инкрементальный парсер (WHATWG HTML §9.2) и подписка с переподключением.
// EventSource не умеет передавать заголовки (Authorization / X-AdminTwin-*), поэтому при наличии
// заголовков идентичности используется чтение потока через fetch; иначе — нативный EventSource.
import { parseProblemResponse, ApiError } from "./problem";

export interface SSEMessage {
  id?: string;
  event: string;
  data: string;
  retry?: number;
}

/** Инкрементальный парсер SSE: feed() принимает произвольные куски текста. */
export class SSEParser {
  private buf = "";
  private data: string[] = [];
  private event = "";
  private id: string | undefined;
  private retry: number | undefined;
  /** Последний полученный id (для Last-Event-ID). */
  lastEventId: string | undefined;

  feed(chunk: string): SSEMessage[] {
    this.buf += chunk;
    const out: SSEMessage[] = [];
    for (;;) {
      const m = /\r\n|\r|\n/.exec(this.buf);
      if (!m) break;
      // "\r" в конце буфера может быть началом "\r\n" — ждём следующий кусок.
      if (m[0] === "\r" && m.index === this.buf.length - 1) break;
      const line = this.buf.slice(0, m.index);
      this.buf = this.buf.slice(m.index + m[0].length);
      const msg = this.line(line);
      if (msg) out.push(msg);
    }
    return out;
  }

  /** Завершение потока: незавершённое событие без пустой строки отбрасывается (по спецификации). */
  end(): void {
    this.buf = "";
    this.data = [];
    this.event = "";
  }

  private line(line: string): SSEMessage | null {
    if (line === "") {
      if (this.id !== undefined) this.lastEventId = this.id;
      if (this.data.length === 0) {
        this.event = "";
        return null;
      }
      const msg: SSEMessage = { event: this.event || "message", data: this.data.join("\n"), id: this.lastEventId };
      if (this.retry !== undefined) msg.retry = this.retry;
      this.data = [];
      this.event = "";
      this.retry = undefined;
      return msg;
    }
    if (line.startsWith(":")) return null; // комментарий / keep-alive
    const i = line.indexOf(":");
    const field = i === -1 ? line : line.slice(0, i);
    let value = i === -1 ? "" : line.slice(i + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    switch (field) {
      case "data":
        this.data.push(value);
        break;
      case "event":
        this.event = value;
        break;
      case "id":
        if (!value.includes("\0")) this.id = value;
        break;
      case "retry":
        if (/^\d+$/.test(value)) this.retry = Number(value);
        break;
    }
    return null;
  }
}

export type StreamState = "connecting" | "open" | "reconnecting" | "closed" | "unavailable";

export interface StreamOptions {
  url: string;
  headers?: Record<string, string>;
  onMessage: (m: SSEMessage) => void;
  onState?: (s: StreamState, err?: ApiError | Error) => void;
  /** Начальная задержка переподключения, мс (сервер может переопределить полем retry). */
  retryMs?: number;
  maxRetryMs?: number;
  fetchImpl?: typeof fetch;
  /** Использовать нативный EventSource (только когда заголовки не нужны). */
  preferEventSource?: boolean;
}

export interface StreamHandle {
  close(): void;
}

/** Подписка на SSE с автоматическим переподключением и Last-Event-ID. */
export function openEventStream(opts: StreamOptions): StreamHandle {
  const hasHeaders = !!opts.headers && Object.keys(opts.headers).length > 0;
  if (!hasHeaders && opts.preferEventSource !== false && typeof EventSource !== "undefined") {
    return openNative(opts);
  }
  return openFetch(opts);
}

function openNative(opts: StreamOptions): StreamHandle {
  // Нативный EventSource сам переподключается и передаёт Last-Event-ID.
  const es = new EventSource(opts.url, { withCredentials: true });
  opts.onState?.("connecting");
  es.onopen = () => opts.onState?.("open");
  es.onerror = () => opts.onState?.(es.readyState === EventSource.CLOSED ? "closed" : "reconnecting");
  const known = new Set<string>();
  const handler = (ev: MessageEvent) => opts.onMessage({ event: ev.type, data: String(ev.data), id: ev.lastEventId || undefined });
  es.onmessage = handler;
  // Именованные события нужно регистрировать явно.
  for (const t of KNOWN_EVENT_TYPES) {
    if (!known.has(t)) {
      known.add(t);
      es.addEventListener(t, handler as EventListener);
    }
  }
  return { close: () => { es.close(); opts.onState?.("closed"); } };
}

/** Типы событий потока задач (ТЗ §7 + tool_call/fact/hypothesis/cost, stage1 §4). */
export const KNOWN_EVENT_TYPES = [
  "message",
  "tool_call",
  "fact",
  "hypothesis",
  "cost",
  "task.request",
  "task.accepted",
  "task.progress",
  "task.result",
  "task.failed",
  "task.blocked",
  "task.input_required",
  "task.cancelled",
  "evidence.added",
  "change.proposed",
  "approval.requested",
  "execution.started",
  "execution.completed",
  "execution.cancellation_pending",
  "budget.warning",
  "budget.exhausted",
];

function openFetch(opts: StreamOptions): StreamHandle {
  const f = opts.fetchImpl ?? globalThis.fetch.bind(globalThis);
  const base = opts.retryMs ?? 1000;
  const max = opts.maxRetryMs ?? 30000;
  let delay = base;
  let closed = false;
  let ctrl: AbortController | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const parser = new SSEParser();

  const schedule = (err?: Error) => {
    if (closed) return;
    opts.onState?.("reconnecting", err);
    timer = setTimeout(connect, delay);
    delay = Math.min(delay * 2, max);
  };

  const connect = async () => {
    if (closed) return;
    ctrl = new AbortController();
    opts.onState?.("connecting");
    const headers: Record<string, string> = { Accept: "text/event-stream", "Cache-Control": "no-cache", ...(opts.headers || {}) };
    if (parser.lastEventId) headers["Last-Event-ID"] = parser.lastEventId;
    let res: Response;
    try {
      res = await f(opts.url, { headers, signal: ctrl.signal, cache: "no-store" });
    } catch (e) {
      if (closed) return;
      schedule(e instanceof Error ? e : new Error(String(e)));
      return;
    }
    if (!res.ok || !res.body) {
      const text = await res.text().catch(() => "");
      const { kind, problem } = parseProblemResponse(res.status, res.headers.get("Content-Type"), text, res.headers.get("X-Request-ID"));
      const err = new ApiError(kind, problem);
      // Модуль не подключён / нет прав — переподключение бессмысленно.
      if (kind === "module-unavailable" || res.status === 401 || res.status === 403 || res.status === 404) {
        closed = true;
        opts.onState?.(kind === "module-unavailable" ? "unavailable" : "closed", err);
        return;
      }
      schedule(err);
      return;
    }
    delay = base;
    opts.onState?.("open");
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        for (const m of parser.feed(dec.decode(value, { stream: true }))) {
          if (m.retry !== undefined) delay = m.retry;
          opts.onMessage(m);
        }
      }
    } catch (e) {
      if (closed) return;
      parser.end();
      schedule(e instanceof Error ? e : new Error(String(e)));
      return;
    }
    parser.end();
    schedule(); // сервер закрыл поток — переподключаемся с Last-Event-ID
  };

  void connect();
  return {
    close() {
      closed = true;
      if (timer) clearTimeout(timer);
      ctrl?.abort();
      opts.onState?.("closed");
    },
  };
}

/** Безопасный JSON.parse для data события. */
export function parseEventData(data: string): unknown {
  try {
    return JSON.parse(data);
  } catch {
    return data;
  }
}
