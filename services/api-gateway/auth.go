package api

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
)

var idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$`)

// DevHeaderAuth — ТОЛЬКО для разработки и тестов: субъект берётся из заголовков
// X-AdminTwin-Tenant, X-AdminTwin-Actor, X-AdminTwin-Actor-Kind, X-AdminTwin-Roles, X-AdminTwin-Scopes.
// Включается явно (ADMINTWIN_DEV_AUTH=true). Production-аутентификация — OIDC/JWT (этап 0, следующий шаг).
func DevHeaderAuth(r *http.Request) (identity.Actor, error) {
	tenant := r.Header.Get("X-AdminTwin-Tenant")
	actor := r.Header.Get("X-AdminTwin-Actor")
	if !idRe.MatchString(tenant) || !idRe.MatchString(actor) {
		return identity.Actor{}, problem.New(problem.Unauthenticated, "missing or invalid identity headers")
	}
	kind := identity.Kind(r.Header.Get("X-AdminTwin-Actor-Kind"))
	switch kind {
	case identity.KindUser, identity.KindAIAgent, identity.KindService:
	case "":
		kind = identity.KindUser
	default:
		return identity.Actor{}, problem.New(problem.Unauthenticated, "invalid actor kind")
	}
	roles := identity.ParseRoles(r.Header.Get("X-AdminTwin-Roles"))
	if kind == identity.KindAIAgent {
		// Машинная идентичность агента не может нести человеческие роли (confused deputy, §18.6).
		roles = []identity.Role{identity.RoleAIAgent}
	}
	var scopes []string
	for _, s := range strings.Split(r.Header.Get("X-AdminTwin-Scopes"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			scopes = append(scopes, s)
		}
	}
	return identity.Actor{ID: actor, Kind: kind, TenantID: tenant, Roles: roles, Scopes: scopes}, nil
}

// DenyAll — аутентификатор по умолчанию, пока не подключён OIDC (fail closed).
func DenyAll(*http.Request) (identity.Actor, error) {
	return identity.Actor{}, problem.New(problem.Unauthenticated, "authentication is not configured (OIDC/JWT pending); set ADMINTWIN_DEV_AUTH=true for local development only")
}
