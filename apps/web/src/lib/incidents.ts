// Жизненный цикл инцидента (ТЗ §9, Приложение C.7; stage1-contracts §3).
import type { Hypothesis, Incident, IncidentStatus, Severity } from "./api/types";

export const INCIDENT_TRANSITIONS: Record<IncidentStatus, IncidentStatus[]> = {
  new: ["triaged"],
  triaged: ["investigating"],
  investigating: ["mitigated"],
  mitigated: ["resolved", "investigating"],
  resolved: ["closed", "reopened"],
  closed: ["reopened"],
  reopened: ["investigating"],
};

const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** Требования перехода: mitigated — evidence_ref; resolved при severity ≥ high — постмортем. */
export function transitionRequirements(inc: Pick<Incident, "severity" | "postmortem">, to: IncidentStatus) {
  return {
    evidenceRequired: to === "mitigated",
    postmortemRequired: to === "resolved" && SEV_RANK[inc.severity] >= SEV_RANK.high && !inc.postmortem,
  };
}

/** Неопределённость RCA: статус uncertain или разрыв между двумя лучшими гипотезами < gap. */
export function rcaUncertain(status: string | undefined, hyps: Hypothesis[] | null | undefined, gap = 0.15): boolean {
  if (status === "uncertain") return true;
  const sorted = [...(hyps || [])].sort((a, b) => b.confidence - a.confidence);
  if (sorted.length === 0) return false;
  if (sorted[0]!.confidence < 0.5) return true;
  return sorted.length > 1 && sorted[0]!.confidence - sorted[1]!.confidence < gap;
}

/** Разбор факта «tool.name: вывод» — инструмент отдельно, длинный вывод свёрнут. */
export function splitFact(fact: string): { tool: string | null; text: string } {
  const m = /^([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+):\s*([\s\S]*)$/.exec(fact);
  return m ? { tool: m[1] ?? null, text: m[2] ?? "" } : { tool: null, text: fact };
}

