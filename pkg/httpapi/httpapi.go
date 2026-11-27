// Package httpapi — общие HTTP-примитивы API v1: аутентифицированный роутер, подключаемые модули
// сервисов, JSON/RFC 9457-хелперы. Модули (incidents, telemetry, discovery, connectors, ...)
// регистрируют свои маршруты через Module, не изменяя api-gateway.
package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
)

// Handler — обработчик аутентифицированного запроса.
type Handler func(w http.ResponseWriter, r *http.Request, a identity.Actor)

// Router регистрирует маршруты. Handle оборачивает обработчик аутентификацией и проверкой tenant.
type Router struct {
	Mux  *http.ServeMux
	Wrap func(Handler) http.HandlerFunc
	// Patterns — зарегистрированные маршруты (для контрактного теста с OpenAPI).
	Patterns []string
}

// Handle — аутентифицированный маршрут ("GET /api/v1/...").
func (r *Router) Handle(pattern string, h Handler) {
	r.Patterns = append(r.Patterns, pattern)
	r.Mux.HandleFunc(pattern, r.Wrap(h))
}

// Public — маршрут без аутентификации (health, OIDC callback). Использовать осознанно.
func (r *Router) Public(pattern string, h http.HandlerFunc) {
	r.Patterns = append(r.Patterns, pattern)
	r.Mux.HandleFunc(pattern, h)
}

// Module — сервис, публикующий маршруты API.
type Module interface {
	Routes(r *Router)
}

// ModuleFunc — адаптер функции к Module.
type ModuleFunc func(r *Router)

// Routes реализует Module.
func (f ModuleFunc) Routes(r *Router) { f(r) }

// WriteJSON пишет JSON-ответ.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Fail пишет ошибку RFC 9457; не-Problem ошибки логируются и превращаются в 500 без деталей.
func Fail(w http.ResponseWriter, r *http.Request, err error) {
	if _, ok := problem.As(err); !ok {
		slog.Error("internal error", "error", err, "request_id", r.Header.Get("X-Request-ID"), "path", r.URL.Path)
	}
	problem.Write(w, err, r.Header.Get("X-Request-ID"))
}

// Decode строго разбирает JSON-тело (неизвестные поля запрещены, числа — json.Number).
func Decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return problem.New(problem.BadRequest, "request body too large")
		}
		return problem.New(problem.BadRequest, "invalid JSON: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return problem.New(problem.BadRequest, "unexpected data after JSON body")
	}
	return nil
}

// RequireAny — у субъекта есть хотя бы одна роль.
func RequireAny(a identity.Actor, roles ...identity.Role) error {
	if a.HasAny(roles...) {
		return nil
	}
	return problem.New(problem.Forbidden, "insufficient role")
}

// RequireHuman — запрос от человека (не AI Agent и не сервис).
func RequireHuman(a identity.Actor) error {
	if a.Kind != identity.KindUser || a.IsAI() {
		return problem.New(problem.Forbidden, "this action requires a human user")
	}
	return nil
}
