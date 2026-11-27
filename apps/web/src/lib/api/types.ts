// Типы API v1 ядра AdminTwin. Написаны вручную по docs/api/openapi.yaml (реализованные эндпоинты)
// и docs/api/stage1-contracts.md (модули Этапа 1). Формы ответов сверены с services/api-gateway/server.go
// и services/change-coordinator.

// ---------- Общие ----------

export type Role =
  | "platform_super_admin"
  | "tenant_admin"
  | "it_manager"
  | "engineer"
  | "operator"
  | "compliance_manager"
  | "auditor"
  | "viewer"
  | "ai_agent";

export const ALL_ROLES: Role[] = [
  "platform_super_admin",
  "tenant_admin",
  "it_manager",
  "engineer",
  "operator",
  "compliance_manager",
  "auditor",
  "viewer",
];

/** Scope-атрибуты Engineer (§2.1) + forensic (scope, не роль). */
export const ENGINEER_SCOPES = ["sysadmin", "network", "devops", "security", "dba", "sre", "forensic"] as const;

export type ActorKind = "user" | "ai_agent" | "service";
export type Risk = "low" | "medium" | "high" | "critical";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Environment = "production" | "staging" | "dev" | "test";
export type DataClass = "public" | "internal" | "confidential" | "pii" | "secret";
export type AutonomyMode = "observer" | "advisor" | "operator" | "autonomous";

export interface ListResponse<T> {
  items: T[];
}

/** RFC 9457 + расширения AdminTwin (pkg/problem). */
export interface Problem {
  type: string;
  title: string;
  status: number;
  detail?: string;
  policy_id?: string;
  change_id?: string;
  request_id?: string;
  errors?: FieldError[];
  [ext: string]: unknown;
}

export interface FieldError {
  field: string;
  reason: string;
}

export type ProblemCode =
  | "policy-denied"
  | "budget-exhausted"
  | "kill-switch-active"
  | "legal-hold"
  | "separation-of-duties"
  | "invalid-params"
  | "not-found"
  | "unauthenticated"
  | "forbidden"
  | "invalid-transition"
  | "conflict"
  | "idempotency-key-reused"
  | "bad-request"
  | "internal";

// ---------- Inventory ----------

export interface AssetConnection {
  method: string;
  address: string;
  port?: number;
  credential_ref?: string;
  host_key?: string;
}

export interface Asset {
  id: string;
  tenant_id: string;
  name: string;
  type: string;
  environment: Environment | string;
  ring?: string;
  service_tier?: number;
  criticality: string;
  data_class: DataClass | string;
  legal_hold: boolean;
  owner: string;
  verified: boolean;
  reachability?: string;
  active_investigation?: boolean;
  health_endpoint?: string;
  objects?: Record<string, string[]>;
  protected?: string[];
  connection?: AssetConnection;
  source?: string;
}

export interface Dependency {
  tenant_id: string;
  source: string;
  target: string;
  relation_type: string;
  confidence: number;
  verified_by: "discovery" | "user" | "agent" | string;
  discovered_at?: string;
}

export interface Topology {
  nodes: Asset[];
  edges: Dependency[];
}

export interface Impacted {
  asset_id: string;
  name: string;
  depth: number;
  confidence: number;
  service_tier?: number;
  criticality: string;
}

export interface BlastRadius {
  asset_id: string;
  max_depth: number;
  items: Impacted[];
}

// ---------- Runbooks ----------

export interface RunbookParam {
  type: "string" | "integer" | "number" | "boolean" | string;
  pattern?: string;
  enum?: string[];
  max_length?: number;
  minimum?: number;
  maximum?: number;
  required?: boolean;
  default?: unknown;
  source?: string;
  kind?: string;
}

export interface RunbookCheck {
  check: string;
  args?: Record<string, unknown>;
  if_defined?: boolean;
}

export interface RunbookAction {
  action: string;
  when?: string;
  propose?: string;
}

export interface Runbook {
  id: string;
  version: string;
  title: string;
  risk: Risk;
  change_type_default: ChangeType | string;
  scope: { asset_type: string }[];
  modes_allowed: AutonomyMode[];
  parameters: Record<string, RunbookParam>;
  preflight: RunbookCheck[];
  execute: { engine: string; action: string; argv?: string[]; timeout_s: number; supports_dry_run?: boolean };
  post_check: RunbookCheck[];
  rollback: string;
  compensation: RunbookAction[];
  side_effects: string[];
  rate_limit: string;
  owner: string;
  certified_by: string[];
  tests: string[];
  digest: string;
}

// ---------- Changes ----------

export type ChangeType = "standard" | "normal" | "emergency";

export const CHANGE_STATUSES = [
  "draft",
  "impact_assessed",
  "risk_assessed",
  "waiting_approval",
  "proposed",
  "approved",
  "rejected",
  "scheduled",
  "preflight_failed",
  "executing",
  "verified",
  "rolled_back",
  "compensated",
  "failed",
  "cancellation_pending",
  "cancelled",
  "unknown",
  "manual_review",
  "closed",
  "closed_with_rollback",
  "closed_with_compensation",
] as const;

export type ChangeStatus = (typeof CHANGE_STATUSES)[number];

export interface ChangeCreate {
  runbook_id: string;
  asset_id: string;
  params: Record<string, unknown>;
  reason: string;
  incident_id?: string | null;
  type?: ChangeType;
  dry_run?: boolean;
}

export interface PolicyDecision {
  policy_id: string;
  outcome: "auto_approved" | "requires_approval" | "proposal_only" | string;
  required_approvals: number;
  approver_roles?: Role[];
  engineer_scope?: string;
  requires_maintenance_window: boolean;
  preflight_mandatory: boolean;
  break_glass: boolean;
  reasons: string[];
}

export interface ChangeImpact {
  blast_radius: Impacted[] | null;
  affected_service_tiers: number[] | null;
  max_criticality: string;
  in_maintenance_window: boolean;
}

export interface ApprovalDecision {
  actor_id: string;
  roles: string[];
  verdict: "approve" | "reject";
  comment?: string;
  at: string;
}

export interface Transition {
  from: string;
  to: string;
  actor: string;
  reason: string;
  at: string;
  correlation_id?: string;
  evidence_ref?: string;
}

export interface StepResult {
  phase: "preflight" | "execute" | "post_check" | "compensation" | string;
  name: string;
  ok: boolean;
  skipped?: boolean;
  detail?: string;
  at: string;
}

export interface ExecutionResult {
  execution_id: string;
  status: string;
  steps: StepResult[] | null;
  stdout?: string;
  stderr?: string;
  exit_code: number;
  compensation?: string[];
  proposals?: string[];
  evidence_id?: string;
  digest?: string;
  started_at: string;
  finished_at: string;
}

export interface Execution {
  id: string;
  change_id: string;
  tenant_id: string;
  runbook_id: string;
  asset_id: string;
  status: string;
  result?: ExecutionResult;
  started_at: string;
}

export interface Change {
  id: string;
  tenant_id: string;
  type: ChangeType;
  status: ChangeStatus;
  runbook_id: string;
  runbook_version: string;
  runbook_digest: string;
  risk: Risk;
  asset_id: string;
  params: Record<string, unknown>;
  dry_run: boolean;
  reason: string;
  incident_id?: string;
  author_id: string;
  author_kind: ActorKind;
  impact?: ChangeImpact;
  policy?: PolicyDecision;
  decisions: ApprovalDecision[];
  executions: Execution[];
  follow_up_proposals?: string[];
  transitions: Transition[];
  pir_required: boolean;
  pir_due_at?: string | null;
  created_at: string;
  updated_at: string;
}

// ---------- Safety ----------

export interface KillSwitchState {
  active: boolean;
  reason?: string;
  actor?: string;
  changed_at: string;
}

export interface KillSwitchStatus {
  tenant: KillSwitchState;
  platform: KillSwitchState;
}

export interface PlatformHealth {
  status: string;
  version?: string;
  uptime_s?: number;
  components?: Record<string, string>;
  [k: string]: unknown;
}

// ---------- Audit ----------

export interface AuditEntry {
  seq: number;
  tenant_id: string;
  at: string;
  actor: string;
  action: string;
  object_type: string;
  object_id: string;
  data?: Record<string, unknown>;
  pii?: string;
  prev_hash: string;
  hash: string;
}

export interface AuditCheckpoint {
  tenant_id: string;
  seq: number;
  hash: string;
  at: string;
  signature: string;
}

export interface AuditIntegrity {
  valid: boolean;
  checkpoint?: AuditCheckpoint | null;
  entries: number;
  broken_at_seq?: number;
  error?: string;
}

// ---------- Registry ----------

export interface CapabilityOperation {
  level: string;
  tool?: string;
  runbook?: string;
  runbook_step?: string;
}

export interface Capability {
  capability_id: string;
  version: string;
  domain: string;
  name: string;
  tier: "MVP" | "P1a" | "P1b" | "P2" | string;
  mode: string;
  owner_agent: string;
  supporting_agents: string[] | null;
  standards: string[] | null;
  operations: CapabilityOperation[] | null;
  asset_types: string[] | null;
  preconditions: string[] | null;
  risk: string;
  autonomy_ceiling: string;
  approval_policy: string;
  evidence_schema: string[] | null;
  tests: string[] | null;
  lifecycle_state: string;
}

export interface Standard {
  standard_id: string;
  title: string;
  edition: string;
  area: string;
  required_evidence: string;
  modules: string[] | null;
  module_refs_raw?: string;
  applicability: string[] | null;
  jurisdictions: string[] | null;
  owner: string;
  reviewed_at: string | null;
  next_review_at: string | null;
  control_mapping_version: string;
}

export interface StandardsResponse extends ListResponse<Standard> {
  notice?: string;
}

// ---------- Incidents (stage1 §3) ----------

export type IncidentStatus = "new" | "triaged" | "investigating" | "mitigated" | "resolved" | "closed" | "reopened";
export const INCIDENT_STATUSES: IncidentStatus[] = [
  "new",
  "triaged",
  "investigating",
  "mitigated",
  "resolved",
  "closed",
  "reopened",
];
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface TimelineEntry {
  at: string;
  actor: string;
  kind: string;
  text: string;
  ref?: string;
}

export interface HypothesisFact {
  fact: string;
  evidence_id?: string;
}

export interface Hypothesis {
  cause: string;
  confidence: number;
  supporting?: HypothesisFact[] | null;
  refuting?: HypothesisFact[] | null;
  next_checks?: (string | { name?: string; tool?: string; description?: string; [k: string]: unknown })[] | null;
}

export type RcaStatus = "not_started" | "running" | "completed" | "uncertain" | "failed";

export interface Rca {
  status: RcaStatus;
  task_id?: string;
  hypotheses?: Hypothesis[] | null;
  conclusion?: string;
  uncertainty_check?: string | Record<string, unknown> | null;
  agents?: string[] | null;
  cost_usd?: number;
  proposed_changes?: string[] | null;
}

export interface Postmortem {
  summary: string;
  root_cause: string;
  corrective_actions: string[];
}

export interface IncidentFeedback {
  correct: boolean;
  actual_cause?: string;
  rating: number;
  comment?: string;
}

export interface Incident {
  id: string;
  tenant_id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  owner?: string;
  description?: string;
  asset_ids: string[];
  event_ids?: string[];
  fingerprint?: string;
  created_at: string;
  updated_at?: string;
  triaged_at?: string | null;
  assigned_at?: string | null;
  timeline?: TimelineEntry[] | null;
  rca?: Rca | null;
  postmortem?: Postmortem | null;
  feedback?: IncidentFeedback | null;
  slo_impact?: unknown;
}

export interface IncidentCreate {
  title: string;
  severity: Severity;
  asset_ids: string[];
  description?: string;
}

export interface IncidentTransition {
  to: IncidentStatus;
  reason: string;
  evidence_ref?: string;
}

export interface TelemetryEvent {
  id: string;
  tenant_id: string;
  asset_id?: string;
  service_id?: string;
  kind: string;
  severity: Severity;
  title: string;
  fingerprint: string;
  labels?: Record<string, string>;
  value?: number;
  at: string;
}

export interface MetricSeries {
  labels: Record<string, string>;
  points: [number, number][];
}

export interface MetricResponse {
  asset_id: string;
  metric: string;
  window: string;
  series: MetricSeries[];
}

// ---------- Agents / ChatOps (stage1 §4, ТЗ §7, §10) ----------

export type TaskStatus =
  | "created"
  | "queued"
  | "running"
  | "waiting_approval"
  | "waiting_input"
  | "blocked"
  | "completed"
  | "failed"
  | "cancelled"
  | "timed_out";

export const TERMINAL_TASK_STATUSES: TaskStatus[] = ["completed", "failed", "cancelled", "timed_out"];

export interface TaskAgent {
  id?: string;
  agent_id?: string;
  name?: string;
  status?: string;
  model_profile?: string;
  provider?: string;
  model?: string;
}

export interface AgentTask {
  task_id?: string;
  id?: string;
  parent_task_id?: string | null;
  kind?: "rca" | "chat" | "diagnose" | string;
  status: TaskStatus | string;
  objective?: string;
  incident_id?: string | null;
  agent?: string;
  agents?: TaskAgent[] | null;
  children?: AgentTask[] | null;
  subtasks?: AgentTask[] | null;
  facts?: { evidence_id?: string; statement?: string; fact?: string }[] | null;
  cost_usd?: number;
  cost_by_provider?: Record<string, number> | null;
  waiting_input?: { question?: string; prompt?: string } | null;
  question?: string;
  created_at?: string;
  updated_at?: string;
}

export interface AgentTaskCreate {
  kind: "rca" | "chat" | "diagnose";
  objective: string;
  incident_id?: string;
  scope?: { asset_ids: string[] };
}

export interface AgentDefinition {
  id: string;
  name?: string;
  version?: string;
  model_profile?: string;
  fallback_model_profile?: string;
  allowed_capabilities?: string[];
  allowed_tools?: string[];
  status?: string;
  data_sensitivity_max?: string;
}

/** Событие SSE задачи/чата: event — тип §7 или tool_call | fact | hypothesis | cost | message. */
export interface StreamEvent {
  id?: string;
  event: string;
  data: unknown;
  receivedAt: number;
}

// ---------- AI Providers & Budgets (ТЗ §13, read-only) ----------

export interface AiProvider {
  id?: string;
  name?: string;
  kind?: string;
  mode?: string;
  status?: string;
  [k: string]: unknown;
}

export interface ModelProfile {
  id?: string;
  name?: string;
  provider?: string;
  model?: string;
  capabilities?: string[] | Record<string, unknown>;
  [k: string]: unknown;
}

export interface AiUsage {
  items?: { provider?: string; model_profile?: string; tokens?: number; cost_usd?: number; [k: string]: unknown }[];
  budgets?: { scope?: string; level?: string; utilization?: number; state?: string; [k: string]: unknown }[];
  [k: string]: unknown;
}
