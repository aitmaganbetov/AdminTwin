import type { AgentTask, TaskAgent } from "./api/types";

/** Описание агента из реестра (GET /api/v1/agents). */
export interface RegistryAgent {
  id: string;
  name?: string;
  model_profile?: string;
}

/**
 * Строки «Активные агенты» задачи. Оркестратор отдаёт `agents` как список идентификаторов, а статус
 * каждого агента — в подзадачах (`children`); model profile берётся из реестра агентов.
 * Объекты TaskAgent (если оркестратор пришлёт их) поддерживаются как есть.
 */
export function taskAgentRows(task: AgentTask, registry: RegistryAgent[] = []): TaskAgent[] {
  const byId = new Map(registry.map((a) => [a.id, a]));
  const children = [...(task.children || []), ...(task.subtasks || [])];
  const raw = (task.agents || []) as unknown[];
  const rows: TaskAgent[] = [];
  const seen = new Set<string>();
  const push = (row: TaskAgent) => {
    const id = row.agent_id || row.id || row.name || "";
    if (!id || seen.has(id)) return;
    seen.add(id);
    const reg = byId.get(id);
    rows.push({ ...row, agent_id: id, name: row.name || reg?.name, model_profile: row.model_profile || reg?.model_profile });
  };
  for (const a of raw) {
    if (typeof a === "string") {
      const child = children.find((c) => (c as { agent_id?: string }).agent_id === a);
      push({ agent_id: a, status: (child as { status?: string } | undefined)?.status });
    } else if (a && typeof a === "object") {
      push(a as TaskAgent);
    }
  }
  for (const c of children) {
    const id = (c as { agent_id?: string }).agent_id;
    if (id) push({ agent_id: id, status: (c as { status?: string }).status });
  }
  return rows;
}
