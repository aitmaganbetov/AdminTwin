"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, isApiError, networkError } from "./api/problem";

export interface Resource<T> {
  data: T | undefined;
  error: ApiError | undefined;
  loading: boolean;
  reload: () => void;
}

/**
 * Загрузка данных с повторным запросом по deps и (опционально) периодическим опросом.
 * Опрос останавливается, когда poll(data) возвращает false.
 */
export function useResource<T>(
  fetcher: () => Promise<T>,
  deps: unknown[],
  opts: { intervalMs?: number; poll?: (d: T | undefined) => boolean; enabled?: boolean } = {},
): Resource<T> {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<ApiError | undefined>(undefined);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const fetcherRef = useRef(fetcher);
  const optsRef = useRef(opts);
  useEffect(() => {
    fetcherRef.current = fetcher;
    optsRef.current = opts;
  });
  const enabled = opts.enabled !== false;

  useEffect(() => {
    if (!enabled) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const run = async (first: boolean) => {
      if (first) setLoading(true);
      try {
        const d = await fetcherRef.current();
        if (!alive) return;
        setData(d);
        setError(undefined);
        const { intervalMs, poll } = optsRef.current;
        if (intervalMs && (!poll || poll(d))) timer = setTimeout(() => void run(false), intervalMs);
      } catch (e) {
        if (!alive) return;
        setError(isApiError(e) ? e : networkError(e));
        const { intervalMs } = optsRef.current;
        // Повторяем только сетевые/временные ошибки.
        if (intervalMs && isApiError(e) && (e.kind === "network" || e.kind === "upstream-unavailable")) {
          timer = setTimeout(() => void run(false), intervalMs * 2);
        }
      } finally {
        if (alive) setLoading(false);
      }
    };
    void run(true);
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- deps задаёт вызывающий
  }, [...deps, tick, enabled]);

  const reload = useCallback(() => setTick((n) => n + 1), []);
  return { data, error, loading, reload };
}
