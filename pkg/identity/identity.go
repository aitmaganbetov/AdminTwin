// Package identity описывает субъекта запроса (человек, AI Agent, сервис) и роли из ТЗ §2.1.
package identity

import (
	"context"
	"slices"
	"strings"
)

// Kind — тип субъекта.
type Kind string

const (
	KindUser    Kind = "user"
	KindAIAgent Kind = "ai_agent"
	KindService Kind = "service"
)

// Role — роль платформы (§2.1). Forensic Analyst — scope, а не роль.
type Role string

const (
	RoleSuperAdmin        Role = "platform_super_admin"
	RoleTenantAdmin       Role = "tenant_admin"
	RoleITManager         Role = "it_manager"
	RoleEngineer          Role = "engineer"
	RoleOperator          Role = "operator"
	RoleComplianceManager Role = "compliance_manager"
	RoleAuditor           Role = "auditor"
	RoleViewer            Role = "viewer"
	RoleAIAgent           Role = "ai_agent"
)

// KnownRoles — все роли из §2.1.
var KnownRoles = []Role{
	RoleSuperAdmin, RoleTenantAdmin, RoleITManager, RoleEngineer, RoleOperator,
	RoleComplianceManager, RoleAuditor, RoleViewer, RoleAIAgent,
}

// Actor — аутентифицированный субъект.
type Actor struct {
	ID       string
	Kind     Kind
	TenantID string
	Roles    []Role
	// Scopes — атрибуты области Engineer (sysadmin/network/devops/security/dba/sre) и forensic.
	Scopes []string
}

// Has сообщает, есть ли у субъекта роль.
func (a Actor) Has(r Role) bool { return slices.Contains(a.Roles, r) }

// HasAny — хотя бы одна из ролей.
func (a Actor) HasAny(rs ...Role) bool {
	for _, r := range rs {
		if a.Has(r) {
			return true
		}
	}
	return false
}

// HasScope — есть ли scope-атрибут.
func (a Actor) HasScope(s string) bool { return slices.Contains(a.Scopes, s) }

// IsAI — машинная идентичность агента. AI Agent никогда не approver (§2.1).
func (a Actor) IsAI() bool { return a.Kind == KindAIAgent || a.Has(RoleAIAgent) }

// Ref — строковая ссылка на субъекта для журналов.
func (a Actor) Ref() string { return string(a.Kind) + ":" + a.ID }

// ParseRoles разбирает список ролей через запятую; неизвестные роли отбрасываются (fail closed).
func ParseRoles(s string) []Role {
	var out []Role
	for _, p := range strings.Split(s, ",") {
		r := Role(strings.TrimSpace(p))
		if slices.Contains(KnownRoles, r) {
			out = append(out, r)
		}
	}
	return out
}

type ctxKey struct{}

// WithActor кладёт субъекта в контекст.
func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, ctxKey{}, a)
}

// FromContext извлекает субъекта.
func FromContext(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(ctxKey{}).(Actor)
	return a, ok
}
