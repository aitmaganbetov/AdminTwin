"use client";

import { useMemo } from "react";
import type { Asset } from "./api/types";
import { useApi } from "./auth/AuthProvider";
import { useResource } from "./useResource";

/** Справочник активов tenant: id → asset. */
export function useAssets() {
  const api = useApi();
  const res = useResource(() => api.assets(), [api]);
  const byId = useMemo(() => {
    const m = new Map<string, Asset>();
    for (const a of res.data?.items || []) m.set(a.id, a);
    return m;
  }, [res.data]);
  return { ...res, byId, list: res.data?.items || [] };
}

/** Классификация актива неполна: нет обязательных атрибутов (§3.2, §8.3) или актив не подтверждён. */
export function missingClassification(a: Asset): string[] {
  const miss: string[] = [];
  if (!a.environment) miss.push("environment");
  if (!a.criticality) miss.push("criticality");
  if (!a.data_class) miss.push("data_class");
  if (a.service_tier === undefined || a.service_tier === null) miss.push("service_tier");
  if (!a.owner) miss.push("owner");
  if (!a.verified) miss.push("verified");
  return miss;
}
