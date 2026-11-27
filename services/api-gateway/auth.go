package api

import (
	"crypto/subtle"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/oidc"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
)

var idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$`)

// AuthConfig — способы аутентификации. Порядок: Bearer (OIDC) → сервисный токен → dev-заголовки.
type AuthConfig struct {
	// OIDC — верификатор токенов пользователей (nil — OIDC не настроен).
	OIDC *oidc.Verifier
	// Имена утверждений токена.
	TenantClaim string // по умолчанию "admintwin_tenant"
	RolesClaim  string // по умолчанию "admintwin_roles"
	ScopesClaim string // по умолчанию "admintwin_scopes"
	// MFAMethods — значения amr, означающие второй фактор (по умолчанию mfa, otp, hwk, swk, sc, fpt, face, pop).
	MFAMethods []string
	// ServiceToken — общий секрет сервисов (оркестратор, сборщики), ≥ 32 символов. Пусто — выключено.
	ServiceToken string
	// DevHeaders — ТОЛЬКО для разработки: субъект из заголовков X-AdminTwin-*.
	DevHeaders bool
}

// NewAuthenticator собирает цепочку. Ни один способ не настроен — каждый запрос получает 401.
func NewAuthenticator(c AuthConfig) Authenticator {
	if c.TenantClaim == "" {
		c.TenantClaim = "admintwin_tenant"
	}
	if c.RolesClaim == "" {
		c.RolesClaim = "admintwin_roles"
	}
	if c.ScopesClaim == "" {
		c.ScopesClaim = "admintwin_scopes"
	}
	if len(c.MFAMethods) == 0 {
		c.MFAMethods = []string{"mfa", "otp", "hwk", "swk", "sc", "fpt", "face", "pop"}
	}
	if len(c.ServiceToken) < 32 {
		c.ServiceToken = ""
	}
	return func(r *http.Request) (identity.Actor, error) {
		if h := r.Header.Get("Authorization"); h != "" {
			if c.OIDC == nil {
				return identity.Actor{}, problem.New(problem.Unauthenticated, "bearer tokens are not accepted: OIDC is not configured")
			}
			tok, ok := strings.CutPrefix(h, "Bearer ")
			if !ok {
				return identity.Actor{}, problem.New(problem.Unauthenticated, "unsupported authorization scheme")
			}
			return c.fromToken(r, strings.TrimSpace(tok))
		}
		if t := r.Header.Get("X-AdminTwin-Service-Token"); t != "" {
			if c.ServiceToken == "" || subtle.ConstantTimeCompare([]byte(t), []byte(c.ServiceToken)) != 1 {
				return identity.Actor{}, problem.New(problem.Unauthenticated, "invalid service token")
			}
			return serviceActor(r)
		}
		if c.DevHeaders {
			return DevHeaderAuth(r)
		}
		return identity.Actor{}, problem.New(problem.Unauthenticated, "authentication required")
	}
}

func (c AuthConfig) fromToken(r *http.Request, tok string) (identity.Actor, error) {
	claims, err := c.OIDC.Verify(r.Context(), tok)
	if err != nil {
		return identity.Actor{}, problem.New(problem.Unauthenticated, "invalid or expired token")
	}
	tenant := claims.String(c.TenantClaim)
	if !idRe.MatchString(tenant) || !idRe.MatchString(claims.Subject) {
		return identity.Actor{}, problem.New(problem.Unauthenticated, "token lacks a valid tenant or subject claim")
	}
	roles := identity.ParseRoles(strings.Join(claims.Strings(c.RolesClaim), ","))
	roles = slices.DeleteFunc(roles, func(r identity.Role) bool { return r == identity.RoleAIAgent })
	mfa := false
	for _, m := range claims.Strings("amr") {
		if slices.Contains(c.MFAMethods, m) {
			mfa = true
		}
	}
	return identity.Actor{ID: claims.Subject, Kind: identity.KindUser, TenantID: tenant, Roles: roles,
		Scopes: claims.Strings(c.ScopesClaim), MFA: mfa, Via: "oidc"}, nil
}

// serviceActor — сервис с валидным токеном действует от своего имени или от имени AI Agent.
// Выдать себя за человека сервис не может (confused deputy, §18.6).
func serviceActor(r *http.Request) (identity.Actor, error) {
	tenant := r.Header.Get("X-AdminTwin-Tenant")
	actor := r.Header.Get("X-AdminTwin-Actor")
	if !idRe.MatchString(tenant) || !idRe.MatchString(actor) {
		return identity.Actor{}, problem.New(problem.Unauthenticated, "service request lacks tenant/actor headers")
	}
	switch identity.Kind(r.Header.Get("X-AdminTwin-Actor-Kind")) {
	case identity.KindAIAgent:
		return identity.Actor{ID: actor, Kind: identity.KindAIAgent, TenantID: tenant, Roles: []identity.Role{identity.RoleAIAgent}, Via: "service_token"}, nil
	case identity.KindService:
		return identity.Actor{ID: actor, Kind: identity.KindService, TenantID: tenant, Via: "service_token"}, nil
	}
	return identity.Actor{}, problem.New(problem.Unauthenticated, "service token may act only as ai_agent or service")
}

// DevHeaderAuth — ТОЛЬКО для разработки и тестов: субъект берётся из заголовков
// X-AdminTwin-Tenant, X-AdminTwin-Actor, X-AdminTwin-Actor-Kind, X-AdminTwin-Roles, X-AdminTwin-Scopes, X-AdminTwin-MFA.
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
	if kind == identity.KindService {
		roles = nil
	}
	var scopes []string
	for _, s := range strings.Split(r.Header.Get("X-AdminTwin-Scopes"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			scopes = append(scopes, s)
		}
	}
	mfa := kind == identity.KindUser && r.Header.Get("X-AdminTwin-MFA") != "false"
	return identity.Actor{ID: actor, Kind: kind, TenantID: tenant, Roles: roles, Scopes: scopes, MFA: mfa, Via: "dev_headers"}, nil
}

// DenyAll — аутентификатор без настроенных способов (fail closed).
func DenyAll(*http.Request) (identity.Actor, error) {
	return identity.Actor{}, problem.New(problem.Unauthenticated, "authentication is not configured: set ADMINTWIN_OIDC_ISSUER (or ADMINTWIN_DEV_AUTH=true for local development only)")
}

// requireMFA — критичные действия человека требуют второго фактора (§2.1).
func requireMFA(a identity.Actor) error {
	if a.Kind == identity.KindUser && !a.MFA {
		return problem.New(problem.MFARequired, "this action requires a session authenticated with MFA")
	}
	return nil
}
