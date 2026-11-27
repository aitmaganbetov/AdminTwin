package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/httpapi"
	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
)

// OrchestratorProxy публикует /api/v1/agent-tasks и /api/v1/chat/sessions (§13) поверх AI-оркестратора.
// Идентичность берётся только из проверенного субъекта: tenant_id и requested_by в теле и query
// перезаписываются, заголовки идентичности клиента не пробрасываются.
type OrchestratorProxy struct {
	BaseURL      string // http://orchestrator:8090
	ServiceToken string
	Client       *http.Client // без таймаута на тело (SSE); таймауты — через контекст
}

// Routes реализует httpapi.Module.
func (p *OrchestratorProxy) Routes(r *httpapi.Router) {
	for _, m := range []struct{ method, path, upstream string }{
		{"GET", "/api/v1/agent-tasks", "/v1/tasks"},
		{"POST", "/api/v1/agent-tasks", "/v1/tasks"},
		{"GET", "/api/v1/agent-tasks/{rest...}", "/v1/tasks/"},
		{"POST", "/api/v1/agent-tasks/{rest...}", "/v1/tasks/"},
		{"POST", "/api/v1/chat/sessions", "/v1/chat/sessions"},
		{"GET", "/api/v1/chat/sessions/{rest...}", "/v1/chat/sessions/"},
		{"POST", "/api/v1/chat/sessions/{rest...}", "/v1/chat/sessions/"},
	} {
		m := m
		r.Handle(m.method+" "+m.path, func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
			p.forward(w, req, a, m.upstream+req.PathValue("rest"))
		})
	}
}

var pathRe = regexp.MustCompile(`^/v1/[A-Za-z0-9_\-/]*$`)

func (p *OrchestratorProxy) forward(w http.ResponseWriter, r *http.Request, a identity.Actor, upstreamPath string) {
	if p.BaseURL == "" {
		httpapi.Fail(w, r, problem.New(problem.NotFound, "AI orchestrator is not configured in this deployment"))
		return
	}
	if a.Kind != identity.KindUser {
		httpapi.Fail(w, r, problem.New(problem.Forbidden, "agent tasks are created by people; agents create subtasks inside the orchestrator"))
		return
	}
	if !a.HasAny(identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleEngineer, identity.RoleOperator, identity.RoleViewer) {
		httpapi.Fail(w, r, problem.New(problem.Forbidden, "insufficient role to view AI tasks"))
		return
	}
	if r.Method != http.MethodGet && !a.HasAny(identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleEngineer, identity.RoleOperator) {
		httpapi.Fail(w, r, problem.New(problem.Forbidden, "insufficient role to manage AI tasks"))
		return
	}
	if strings.Contains(upstreamPath, "..") || strings.Contains(upstreamPath, "//") || !pathRe.MatchString(upstreamPath) {
		httpapi.Fail(w, r, problem.New(problem.BadRequest, "invalid path"))
		return
	}

	var body io.Reader
	if r.Method == http.MethodPost {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			httpapi.Fail(w, r, problem.New(problem.BadRequest, "cannot read body"))
			return
		}
		doc := map[string]any{}
		if len(bytes.TrimSpace(raw)) > 0 {
			if err := json.Unmarshal(raw, &doc); err != nil {
				httpapi.Fail(w, r, problem.New(problem.BadRequest, "invalid JSON"))
				return
			}
		}
		// Идентичность в теле — только для создания задач и сессий (их модели содержат tenant_id/requested_by);
		// в остальных телах этих полей быть не должно, tenant берётся оркестратором из заголовков ядра.
		switch upstreamPath {
		case "/v1/tasks":
			doc["tenant_id"], doc["requested_by"] = a.TenantID, a.ID
		case "/v1/chat/sessions":
			doc["tenant_id"] = a.TenantID
		default:
			delete(doc, "tenant_id")
			delete(doc, "requested_by")
		}
		b, _ := json.Marshal(doc)
		body = bytes.NewReader(b)
	}
	q := r.URL.Query()
	if r.Method == http.MethodGet && (q.Has("tenant_id") || upstreamPath == "/v1/tasks") {
		q.Set("tenant_id", a.TenantID)
	}
	target := strings.TrimRight(p.BaseURL, "/") + upstreamPath
	if enc := q.Encode(); enc != "" {
		target += "?" + enc
	}
	if _, err := url.Parse(target); err != nil {
		httpapi.Fail(w, r, problem.New(problem.BadRequest, "invalid path"))
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, body)
	if err != nil {
		httpapi.Fail(w, r, problem.New(problem.BadRequest, "invalid request"))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if v := r.Header.Get("Accept"); v != "" {
		req.Header.Set("Accept", v)
	}
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		req.Header.Set("Last-Event-ID", v)
	}
	req.Header.Set("X-Request-ID", r.Header.Get("X-Request-ID"))
	req.Header.Set("X-AdminTwin-Service-Token", p.ServiceToken)
	req.Header.Set("X-AdminTwin-Tenant", a.TenantID)
	req.Header.Set("X-AdminTwin-Actor", a.ID)
	req.Header.Set("X-AdminTwin-Actor-Kind", string(a.Kind))
	roles := make([]string, 0, len(a.Roles))
	for _, ro := range a.Roles {
		roles = append(roles, string(ro))
	}
	req.Header.Set("X-AdminTwin-Roles", strings.Join(roles, ","))
	req.Header.Set("X-AdminTwin-Scopes", strings.Join(a.Scopes, ","))

	client := p.Client
	if client == nil {
		client = &http.Client{}
	}
	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("orchestrator unreachable", "error", err)
		httpapi.Fail(w, r, &problem.Problem{Type: "https://errors.admintwin.io/orchestrator-unavailable", Title: "AI orchestrator unavailable",
			Status: http.StatusBadGateway, Detail: "AI functions are degraded; monitoring and manual changes keep working (§17.2)"})
		return
	}
	defer resp.Body.Close()
	for _, h := range []string{"Content-Type", "Cache-Control", "Last-Event-ID"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		// Поток событий живёт дольше WriteTimeout сервера; завершается закрытием клиента или оркестратора.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	}
	w.WriteHeader(resp.StatusCode)
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 16<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush() // SSE: события доходят без буферизации
			}
		}
		if err != nil {
			return
		}
	}
}

// Kill передаёт аварийную остановку оркестратору (задачи агентов отменяются < 5 с, §11.7).
func (p *OrchestratorProxy) Kill(tenantID string, platform bool) { p.SetKill(tenantID, platform, true) }

// SetKill включает или снимает остановку в оркестраторе.
func (p *OrchestratorProxy) SetKill(tenantID string, platform, active bool) {
	if p.BaseURL == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	body := map[string]any{"platform": platform, "active": active, "reason": "kill switch (core)"}
	if !platform && tenantID != "" {
		body["tenant_id"] = tenantID // для уровня платформы tenant не передаётся (оркестратор требует UUID или отсутствие)
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.BaseURL, "/")+"/v1/kill", bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AdminTwin-Service-Token", p.ServiceToken)
	if !platform && tenantID != "" {
		req.Header.Set("X-AdminTwin-Tenant", tenantID)
	}
	req.Header.Set("X-AdminTwin-Actor", "core")
	req.Header.Set("X-AdminTwin-Actor-Kind", "service")
	client := p.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("kill switch: orchestrator not reached — AI tasks may still be running", "error", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		slog.Error("kill switch: orchestrator refused", "status", resp.StatusCode)
	}
}
