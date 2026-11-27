// Эндпоинты API v1. Реализованные ядром — openapi.yaml; модули Этапа 1 — stage1-contracts.md.
import type { ApiClient, ApiResponse } from "./client";
import type {
  AgentDefinition,
  AgentTask,
  AgentTaskCreate,
  AiProvider,
  AiUsage,
  Asset,
  AuditEntry,
  AuditIntegrity,
  BlastRadius,
  Capability,
  Change,
  ChangeCreate,
  Execution,
  Incident,
  IncidentCreate,
  IncidentFeedback,
  IncidentTransition,
  KillSwitchStatus,
  ListResponse,
  MetricResponse,
  ModelProfile,
  PlatformHealth,
  Postmortem,
  Runbook,
  Severity,
  StandardsResponse,
  TelemetryEvent,
  Topology,
} from "./types";

const enc = encodeURIComponent;

export function endpoints(c: ApiClient) {
  return {
    // --- core (openapi.yaml) ---
    health: () => c.get<PlatformHealth>("/api/v1/health/platform"),
    assets: () => c.get<ListResponse<Asset>>("/api/v1/assets"),
    asset: (id: string) => c.get<Asset>(`/api/v1/assets/${enc(id)}`),
    blastRadius: (id: string) => c.get<BlastRadius>(`/api/v1/assets/${enc(id)}/blast-radius`),
    topology: () => c.get<Topology>("/api/v1/topology"),
    runbooks: () => c.get<ListResponse<Runbook>>("/api/v1/runbooks"),
    capabilities: (tier?: string) => c.get<ListResponse<Capability>>("/api/v1/capabilities", { tier }),
    capabilityTests: (id: string) =>
      c.get<{ capability_id: string; tests: string[]; lifecycle_state: string }>(`/api/v1/capabilities/${enc(id)}/tests`),
    standards: () => c.get<StandardsResponse>("/api/v1/standards"),

    changes: (status?: string) => c.get<ListResponse<Change>>("/api/v1/changes", { status }),
    change: (id: string) => c.get<Change>(`/api/v1/changes/${enc(id)}`),
    /** 201 — proposed/завершён, 202 — waiting_approval/исполняется. */
    createChange: (body: ChangeCreate, idempotencyKey: string): Promise<ApiResponse<Change>> =>
      c.request<Change>("POST", "/api/v1/changes", { body, headers: { "Idempotency-Key": idempotencyKey } }),
    decide: (id: string, decision: "approve" | "reject", comment?: string) =>
      c.post<Change>(`/api/v1/changes/${enc(id)}/decisions`, comment ? { decision, comment } : { decision }),
    cancelChange: (id: string, reason?: string) =>
      c.post<Change>(`/api/v1/changes/${enc(id)}/cancel`, reason ? { reason } : {}),
    changeExecutions: (id: string) => c.get<ListResponse<Execution>>(`/api/v1/changes/${enc(id)}/executions`),
    execution: (id: string) => c.get<Execution>(`/api/v1/executions/${enc(id)}`),

    killSwitch: () => c.get<KillSwitchStatus>("/api/v1/kill-switch"),
    setKillSwitch: (active: boolean, reason: string, scope: "tenant" | "platform" = "tenant") =>
      c.post<KillSwitchStatus>("/api/v1/kill-switch", { scope, active, reason }),

    auditLogs: (objectId?: string) => c.get<ListResponse<AuditEntry>>("/api/v1/audit-logs", { object_id: objectId }),
    auditIntegrity: () => c.get<AuditIntegrity>("/api/v1/audit-logs/integrity"),
    evidence: (id: string, purpose: string) =>
      c.get<{ evidence: Record<string, unknown>; content: unknown }>(`/api/v1/evidence/${enc(id)}`, { purpose }),

    // --- stage 1: incidents ---
    incidents: (f: { status?: string; severity?: Severity | "" } = {}) =>
      c.get<ListResponse<Incident>>("/api/v1/incidents", { status: f.status, severity: f.severity }),
    incident: (id: string) => c.get<Incident>(`/api/v1/incidents/${enc(id)}`),
    createIncident: (body: IncidentCreate) => c.post<Incident>("/api/v1/incidents", body),
    incidentTransition: (id: string, body: IncidentTransition) =>
      c.post<Incident>(`/api/v1/incidents/${enc(id)}/transitions`, body),
    analyzeIncident: (id: string) => c.post<{ task_id: string }>(`/api/v1/incidents/${enc(id)}/analyze`, {}),
    incidentFeedback: (id: string, body: IncidentFeedback) => c.post<Incident>(`/api/v1/incidents/${enc(id)}/feedback`, body),
    incidentPostmortem: (id: string, body: Postmortem) => c.post<Incident>(`/api/v1/incidents/${enc(id)}/postmortem`, body),

    // --- stage 1: telemetry ---
    events: (f: { asset_id?: string; window?: string; limit?: number } = {}) =>
      c.get<{ events: TelemetryEvent[] }>("/api/v1/events", f),
    metrics: (f: { asset_id: string; metric: string; window?: string; step?: string }) =>
      c.get<MetricResponse>("/api/v1/telemetry/metrics", f),

    // --- stage 1: discovery ---
    discoveryScopes: () => c.get<ListResponse<Record<string, unknown>>>("/api/v1/discovery/scopes"),

    // --- stage 1: agents (ядро проксирует оркестратор) ---
    agents: () => c.get<ListResponse<AgentDefinition>>("/api/v1/agents"),
    agentTasks: () => c.get<ListResponse<AgentTask> | { tasks: AgentTask[] }>("/api/v1/agent-tasks"),
    agentTask: (id: string) => c.get<AgentTask>(`/api/v1/agent-tasks/${enc(id)}`),
    createAgentTask: (body: AgentTaskCreate) => c.post<{ task_id: string; status: string }>("/api/v1/agent-tasks", body),
    cancelAgentTask: (id: string) => c.post<AgentTask>(`/api/v1/agent-tasks/${enc(id)}/cancel`, {}),
    agentTaskInput: (id: string, text: string) => c.post<AgentTask>(`/api/v1/agent-tasks/${enc(id)}/input`, { text }),
    agentTaskEventsUrl: (id: string) => c.url(`/api/v1/agent-tasks/${enc(id)}/events`),
    createChatSession: (incidentId?: string) =>
      c.post<{ session_id: string }>("/api/v1/chat/sessions", incidentId ? { incident_id: incidentId } : {}),
    chatMessage: (sessionId: string, text: string) =>
      c.post<{ task_id?: string }>(`/api/v1/chat/sessions/${enc(sessionId)}/messages`, { text }),
    chatEventsUrl: (sessionId: string) => c.url(`/api/v1/chat/sessions/${enc(sessionId)}/events`),

    // --- AI providers & budgets (ТЗ §13; read-only в MVP UI) ---
    aiProviders: () => c.get<ListResponse<AiProvider>>("/api/v1/ai/providers"),
    modelProfiles: () => c.get<ListResponse<ModelProfile>>("/api/v1/ai/model-profiles"),
    aiUsage: () => c.get<AiUsage>("/api/v1/ai/usage"),
  };
}

export type Endpoints = ReturnType<typeof endpoints>;

/** Нормализация списка задач: оркестратор может вернуть {items} или {tasks}. */
export function taskList(r: ListResponse<AgentTask> | { tasks: AgentTask[] } | null | undefined): AgentTask[] {
  if (!r) return [];
  if ("items" in r && Array.isArray(r.items)) return r.items;
  if ("tasks" in r && Array.isArray(r.tasks)) return r.tasks;
  return [];
}

export function taskId(t: AgentTask): string {
  return t.task_id || t.id || "";
}

export interface TaskNode {
  task: AgentTask;
  children: TaskNode[];
}

/** Строит дерево задач из плоского списка (parent_task_id) и/или вложенных children/subtasks. */
export function buildTaskTree(tasks: AgentTask[]): TaskNode[] {
  const nodes = new Map<string, TaskNode>();
  const order: string[] = [];
  const visit = (t: AgentTask, parent?: string) => {
    const id = taskId(t);
    if (!id) return;
    const existing = nodes.get(id);
    const task = parent && !t.parent_task_id ? { ...t, parent_task_id: parent } : t;
    if (existing) existing.task = { ...existing.task, ...task };
    else {
      nodes.set(id, { task, children: [] });
      order.push(id);
    }
    for (const ch of [...(t.children || []), ...(t.subtasks || [])]) visit(ch, id);
  };
  tasks.forEach((t) => visit(t));
  const roots: TaskNode[] = [];
  for (const id of order) {
    const n = nodes.get(id)!;
    const p = n.task.parent_task_id ? nodes.get(n.task.parent_task_id) : undefined;
    if (p && p !== n) p.children.push(n);
    else roots.push(n);
  }
  return roots;
}
