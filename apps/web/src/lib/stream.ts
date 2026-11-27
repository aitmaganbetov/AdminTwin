"use client";

import { useEffect, useState } from "react";
import type { ApiError } from "./api/problem";
import { openEventStream, parseEventData, type StreamState } from "./api/sse";
import type { StreamEvent } from "./api/types";
import { useAuth } from "./auth/AuthProvider";

export type EventCategory = "message" | "tool" | "fact" | "hypothesis" | "cost" | "change";

/** Категория события потока (ТЗ §7 + tool_call/fact/hypothesis/cost). */
export function eventCategory(type: string): EventCategory {
  if (type === "tool_call" || type.startsWith("tool")) return "tool";
  if (type === "fact" || type === "evidence.added") return "fact";
  if (type === "hypothesis") return "hypothesis";
  if (type === "cost" || type.startsWith("budget.")) return "cost";
  if (type.startsWith("change.") || type.startsWith("approval.") || type.startsWith("execution.")) return "change";
  return "message";
}

/** Суммирует стоимость по провайдерам из событий cost: {provider, cost_usd} (накопительно или дельтой). */
export function costByProvider(events: StreamEvent[], base?: Record<string, number> | null): Record<string, number> {
  const out: Record<string, number> = { ...(base || {}) };
  for (const e of events) {
    if (e.event !== "cost" || !e.data || typeof e.data !== "object") continue;
    const d = e.data as Record<string, unknown>;
    const p = String(d.provider ?? d.model_profile ?? "unknown");
    if (typeof d.total_usd === "number") out[p] = d.total_usd;
    else if (typeof d.cost_usd === "number") out[p] = (out[p] || 0) + d.cost_usd;
  }
  return out;
}

const MAX_EVENTS = 500;

/** Подписка на SSE-поток с заголовками идентичности (fetch-reader) и переподключением. */
export function useEventStream(url: string | null) {
  const { client } = useAuth();
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const [state, setState] = useState<StreamState>("closed");
  const [error, setError] = useState<ApiError | Error | undefined>();

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- новый поток — новый журнал
    setEvents([]);
    setError(undefined);
    if (!url) {
      setState("closed");
      return;
    }
    const h = openEventStream({
      url,
      headers: client.authHeaders(),
      onMessage: (m) =>
        setEvents((cur) => {
          const next = [...cur, { id: m.id, event: m.event, data: parseEventData(m.data), receivedAt: Date.now() }];
          return next.length > MAX_EVENTS ? next.slice(next.length - MAX_EVENTS) : next;
        }),
      onState: (s, err) => {
        setState(s);
        if (err) setError(err);
      },
    });
    return () => h.close();
  }, [url, client]);

  return { events, state, error };
}
