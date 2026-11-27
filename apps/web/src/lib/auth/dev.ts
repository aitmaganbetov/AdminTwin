// DEV-идентичность (ADMINTWIN_DEV_AUTH=true в ядре): субъект передаётся заголовками X-AdminTwin-*.
// Только для локальной разработки; в production используется OIDC.
import type { Role } from "../api/types";
import type { Identity } from "../permissions";

/** Демо-tenants из infra/dev/fixtures.yaml. */
export const DEMO_TENANTS = [
  { id: "11111111-1111-4111-8111-111111111111", label: "Tenant A", mode: "operator" },
  { id: "22222222-2222-4222-8222-222222222222", label: "Tenant B", mode: "advisor" },
] as const;

export interface DevPreset {
  key: string;
  actorId: string;
  roles: Role[];
  scopes: string[];
}

export const DEV_PRESETS: DevPreset[] = [
  { key: "tenant_admin", actorId: "alice", roles: ["tenant_admin"], scopes: [] },
  { key: "engineer", actorId: "bob", roles: ["engineer"], scopes: ["sysadmin", "devops"] },
  { key: "it_manager", actorId: "carol", roles: ["it_manager"], scopes: [] },
  { key: "operator", actorId: "dave", roles: ["operator"], scopes: [] },
  { key: "auditor", actorId: "erin", roles: ["auditor"], scopes: [] },
  { key: "viewer", actorId: "frank", roles: ["viewer"], scopes: [] },
];

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;

/** Те же правила, что DevHeaderAuth в services/api-gateway/auth.go. */
export function isValidDevId(v: string): boolean {
  return ID_RE.test(v);
}

export function devHeaders(id: Identity): Record<string, string> {
  return {
    "X-AdminTwin-Tenant": id.tenantId,
    "X-AdminTwin-Actor": id.actorId,
    // В UI — только человек; ai_agent / service — машинные идентичности.
    "X-AdminTwin-Actor-Kind": "user",
    "X-AdminTwin-Roles": id.roles.join(","),
    "X-AdminTwin-Scopes": id.scopes.join(","),
  };
}

const SESSION_KEY = "admintwin.dev-identity";

/** DEV-идентичность (не секрет и не токен) хранится в sessionStorage вкладки. */
export function saveDevIdentity(id: Identity | null): void {
  try {
    if (id) window.sessionStorage.setItem(SESSION_KEY, JSON.stringify(id));
    else window.sessionStorage.removeItem(SESSION_KEY);
  } catch {
    // без хранилища идентичность живёт только в памяти
  }
}

export function loadDevIdentity(): Identity | null {
  try {
    const raw = window.sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const v = JSON.parse(raw) as Identity;
    if (v && isValidDevId(v.actorId) && isValidDevId(v.tenantId) && Array.isArray(v.roles)) {
      return { actorId: v.actorId, tenantId: v.tenantId, roles: v.roles, scopes: Array.isArray(v.scopes) ? v.scopes : [] };
    }
  } catch {
    // повреждённые данные — игнорируем
  }
  return null;
}
