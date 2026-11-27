// Матрица «роль × действие» (ТЗ §2.2) для управления видимостью элементов UI.
// Это подсказка интерфейса, а не контроль доступа: решение всегда принимает сервер (Policy Engine).
import type { Change, Role } from "./api/types";

export interface Identity {
  actorId: string;
  tenantId: string;
  roles: Role[];
  scopes: string[];
  displayName?: string;
}

const has = (id: Identity | null | undefined, ...roles: Role[]) => !!id && roles.some((r) => id.roles.includes(r));

export const can = {
  viewAssets: (id: Identity | null) =>
    has(id, "platform_super_admin", "tenant_admin", "it_manager", "engineer", "operator", "compliance_manager", "auditor", "viewer"),
  runDiscovery: (id: Identity | null) => has(id, "tenant_admin", "engineer"),
  createAiTask: (id: Identity | null) => has(id, "tenant_admin", "it_manager", "engineer", "operator"),
  proposeChange: (id: Identity | null) => has(id, "tenant_admin", "it_manager", "engineer", "operator"),
  breakGlass: (id: Identity | null) => has(id, "tenant_admin", "it_manager"),
  cancelChange: (id: Identity | null) => has(id, "tenant_admin", "it_manager", "engineer", "operator"),
  killSwitch: (id: Identity | null) => has(id, "platform_super_admin", "tenant_admin", "it_manager", "operator"),
  platformKillSwitch: (id: Identity | null) => has(id, "platform_super_admin"),
  readAudit: (id: Identity | null) => has(id, "platform_super_admin", "tenant_admin", "it_manager", "compliance_manager", "auditor"),
  auditIntegrity: (id: Identity | null) => has(id, "tenant_admin", "compliance_manager", "auditor"),
  viewEvidence: (id: Identity | null) => has(id, "tenant_admin", "it_manager", "engineer", "compliance_manager", "auditor"),
  manageIncidents: (id: Identity | null) => has(id, "tenant_admin", "it_manager", "engineer", "operator"),
};

export type ApprovalBlock =
  | "not-waiting"
  | "no-role"
  | "scope"
  | "already-decided"
  | null;

export interface ApprovalEligibility {
  /** Показать кнопки согласования. */
  canDecide: boolean;
  /** Причина, по которой кнопки скрыты/заблокированы. */
  block: ApprovalBlock;
  /** Пользователь — автор: сервер вернёт separation-of-duties (кнопки не блокируются, решение — за сервером). */
  isAuthor: boolean;
}

/**
 * Может ли пользователь принять решение по change: статус waiting_approval, роль из approver_roles
 * политики (Engineer — только своей области), ещё не голосовал. Автор видит предупреждение о
 * разделении обязанностей; окончательный ответ — от сервера (403 separation-of-duties).
 */
export function approvalEligibility(id: Identity | null, ch: Change): ApprovalEligibility {
  const isAuthor = !!id && ch.author_kind === "user" && ch.author_id === id.actorId;
  if (!id) return { canDecide: false, block: "no-role", isAuthor };
  if (ch.status !== "waiting_approval") return { canDecide: false, block: "not-waiting", isAuthor };
  const roles = ch.policy?.approver_roles && ch.policy.approver_roles.length > 0 ? ch.policy.approver_roles : (["tenant_admin", "it_manager"] as Role[]);
  let ok = false;
  let scopeOnly = false;
  for (const r of roles) {
    if (!id.roles.includes(r)) continue;
    if (r === "engineer" && ch.policy?.engineer_scope && !id.scopes.includes(ch.policy.engineer_scope)) {
      scopeOnly = true;
      continue;
    }
    ok = true;
    break;
  }
  if (!ok) return { canDecide: false, block: scopeOnly ? "scope" : "no-role", isAuthor };
  if (ch.decisions?.some((d) => d.actor_id === id.actorId)) return { canDecide: false, block: "already-decided", isAuthor };
  return { canDecide: true, block: null, isAuthor };
}

export const CANCELLABLE: string[] = ["waiting_approval", "proposed", "approved", "scheduled", "executing"];
