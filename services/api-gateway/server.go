// Package api — API Gateway v1 (§13): REST/JSON, RFC 9457, request_id, idempotency keys.
// Единая точка любой записи в инфраструктуру — /api/v1/changes. POST /executions отсутствует.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/httpapi"
	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/killswitch"
	"github.com/aitmaganbetov/admintwin/pkg/metrics"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/approval"
	"github.com/aitmaganbetov/admintwin/services/audit"
	registry "github.com/aitmaganbetov/admintwin/services/capability-registry"
	change "github.com/aitmaganbetov/admintwin/services/change-coordinator"
	evidence "github.com/aitmaganbetov/admintwin/services/compliance-evidence"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/runbook"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	"github.com/aitmaganbetov/admintwin/services/policy"
)

// Authenticator извлекает субъекта из запроса. Ошибка — 401.
type Authenticator func(r *http.Request) (identity.Actor, error)

// Server — HTTP-слой.
type Server struct {
	Auth      Authenticator
	Changes   *change.Coordinator
	Inventory inventory.Repository
	Catalog   *runbook.Catalog
	Registry  *registry.Registry
	Audit     *audit.Log
	Evidence  evidence.Repository
	Kill      *killswitch.Switch
	Tenants   func(string) (policy.TenantPolicy, bool)
	Log       *slog.Logger
	StartedAt time.Time
	Version   string
	Simulator bool
	// Modules — сервисы, публикующие собственные маршруты (incidents, telemetry, discovery, connectors, ...).
	Modules []httpapi.Module
	// Metrics — meta-monitoring (M24); nil — без метрик.
	Metrics *metrics.Registry
	// Checks — проверки компонентов для /health/platform.
	Checks []HealthCheck
	// SaveTenant — сохранение политики tenant.
	SaveTenant func(policy.TenantPolicy) error

	patterns []string
}

// Handler строит маршруты ядра и подключённых модулей.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health/platform", s.health)

	wrap := func(h httpapi.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			a, err := s.Auth(r)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			if _, ok := s.Tenants(a.TenantID); !ok && !a.Has(identity.RoleSuperAdmin) {
				s.fail(w, r, problem.New(problem.Unauthenticated, "unknown tenant"))
				return
			}
			if a.Kind == identity.KindUser && len(a.Roles) == 0 {
				// Аутентифицирован, но без ролей AdminTwin (например, токен SSO без admintwin_roles): доступа нет.
				s.fail(w, r, problem.New(problem.Forbidden, "no AdminTwin role assigned"))
				return
			}
			h(w, r.WithContext(identity.WithActor(r.Context(), a)), a)
		}
	}
	rt := &httpapi.Router{Mux: mux, Wrap: wrap}

	rt.Handle("GET /api/v1/assets", s.listAssets)
	rt.Handle("GET /api/v1/assets/{id}", s.getAsset)
	rt.Handle("GET /api/v1/assets/{id}/blast-radius", s.blastRadius)
	rt.Handle("GET /api/v1/topology", s.topology)
	rt.Handle("GET /api/v1/runbooks", s.listRunbooks)
	rt.Handle("GET /api/v1/capabilities", s.listCapabilities)
	rt.Handle("GET /api/v1/capabilities/{id}/tests", s.capabilityTests)
	rt.Handle("GET /api/v1/capabilities/traceability", s.traceability)
	rt.Handle("GET /api/v1/standards", s.listStandards)

	rt.Handle("POST /api/v1/changes", s.createChange)
	rt.Handle("GET /api/v1/changes", s.listChanges)
	rt.Handle("GET /api/v1/changes/{id}", s.getChange)
	rt.Handle("POST /api/v1/changes/{id}/decisions", s.decide)
	rt.Handle("POST /api/v1/changes/{id}/cancel", s.cancelChange)
	rt.Handle("GET /api/v1/changes/{id}/executions", s.changeExecutions)
	rt.Handle("GET /api/v1/executions/{id}", s.getExecution)

	rt.Handle("GET /api/v1/kill-switch", s.killStatus)
	rt.Handle("POST /api/v1/kill-switch", s.killSet)
	rt.Handle("GET /api/v1/audit-logs", s.auditLogs)
	rt.Handle("GET /api/v1/audit-logs/integrity", s.auditIntegrity)
	rt.Handle("GET /api/v1/evidence/{id}", s.getEvidence)
	rt.Handle("GET /api/v1/tenant/policy", s.getTenantPolicy)
	rt.Handle("PUT /api/v1/tenant/policy", s.putTenantPolicy)
	rt.Handle("POST /api/v1/changes/{id}/pir", s.recordPIR)
	rt.Handle("POST /api/v1/audit/ai-calls", s.recordAICalls)

	for _, m := range s.Modules {
		m.Routes(rt)
	}
	s.patterns = append([]string{"GET /api/v1/health/platform"}, rt.Patterns...)
	return s.middleware(mux)
}

// RoutePatterns — маршруты, опубликованные последним вызовом Handler().
func (s *Server) RoutePatterns() []string { return append([]string(nil), s.patterns...) }

type ctxReqID struct{}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-ID")
		if rid == "" || len(rid) > 64 {
			rid = newRequestID()
		}
		w.Header().Set("X-Request-ID", rid)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		r.Header.Set("X-Request-ID", rid)
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		if s.Metrics != nil {
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			lbl := map[string]string{"route": route, "status": strconv.Itoa(sw.status)}
			s.Metrics.Inc("admintwin_http_requests_total", lbl, 1)
			s.Metrics.Observe("admintwin_http_request_duration_seconds", map[string]string{"route": route}, time.Since(start).Seconds())
		}
		if s.Log != nil {
			s.Log.Info("http", "method", r.Method, "path", r.URL.Path, "status", sw.status, "request_id", rid, "duration_ms", time.Since(start).Milliseconds())
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }

// Flush — для потоковых ответов (SSE).
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap — для http.ResponseController.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	if _, ok := problem.As(err); !ok && s.Log != nil {
		s.Log.Error("internal error", "error", err, "request_id", r.Header.Get("X-Request-ID"))
	}
	problem.Write(w, err, r.Header.Get("X-Request-ID"))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decode(r *http.Request, v any) error {
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
	if dec.More() {
		return problem.New(problem.BadRequest, "unexpected data after JSON body")
	}
	if _, err := dec.Token(); err != io.EOF {
		return problem.New(problem.BadRequest, "unexpected data after JSON body")
	}
	return nil
}

func requireAny(a identity.Actor, roles ...identity.Role) error {
	if a.HasAny(roles...) {
		return nil
	}
	return problem.New(problem.Forbidden, "insufficient role")
}

// --- handlers ---

// HealthCheck — проверка компонента. Critical — отказ делает платформу недоступной (503).
type HealthCheck struct {
	Name     string
	Critical bool
	Check    func(ctx context.Context) error
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	comps := map[string]string{
		"runbook_catalog": "ok", "capability_registry": "ok", "policy_engine": "builtin",
		"execution_backend": map[bool]string{true: "simulator", false: "connectors"}[s.Simulator],
	}
	status, code := "ok", 200
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	for _, c := range s.Checks {
		if err := c.Check(ctx); err != nil {
			comps[c.Name] = "down"
			if c.Critical {
				status, code = "down", http.StatusServiceUnavailable
			} else if status == "ok" {
				status = "degraded"
			}
			continue
		}
		comps[c.Name] = "ok"
	}
	_, plat := s.Kill.Status("")
	writeJSON(w, code, map[string]any{
		"status": status, "version": s.Version, "uptime_s": int(time.Since(s.StartedAt).Seconds()),
		"components": comps, "platform_kill_switch": plat.Active,
	})
}

func (s *Server) listAssets(w http.ResponseWriter, _ *http.Request, a identity.Actor) {
	writeJSON(w, 200, map[string]any{"items": s.Inventory.List(a.TenantID)})
}

func (s *Server) getAsset(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	as, ok := s.Inventory.Get(a.TenantID, r.PathValue("id"))
	if !ok {
		s.fail(w, r, problem.New(problem.NotFound, "asset not found"))
		return
	}
	writeJSON(w, 200, as)
}

func (s *Server) blastRadius(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	br, err := s.Inventory.BlastRadius(a.TenantID, r.PathValue("id"), 5)
	if err != nil {
		s.fail(w, r, problem.New(problem.NotFound, "asset not found"))
		return
	}
	writeJSON(w, 200, map[string]any{"asset_id": r.PathValue("id"), "max_depth": 5, "items": br})
}

func (s *Server) topology(w http.ResponseWriter, _ *http.Request, a identity.Actor) {
	writeJSON(w, 200, map[string]any{"nodes": s.Inventory.List(a.TenantID), "edges": s.Inventory.Dependencies(a.TenantID)})
}

func (s *Server) listRunbooks(w http.ResponseWriter, _ *http.Request, _ identity.Actor) {
	writeJSON(w, 200, map[string]any{"items": s.Catalog.List()})
}

func (s *Server) listCapabilities(w http.ResponseWriter, r *http.Request, _ identity.Actor) {
	tier := r.URL.Query().Get("tier")
	var items []registry.Capability
	for _, c := range s.Registry.SortedCapabilities() {
		if tier == "" || c.Tier == tier {
			items = append(items, c)
		}
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) capabilityTests(w http.ResponseWriter, r *http.Request, _ identity.Actor) {
	c, ok := s.Registry.Capabilities[r.PathValue("id")]
	if !ok {
		s.fail(w, r, problem.New(problem.NotFound, "capability not found"))
		return
	}
	writeJSON(w, 200, map[string]any{"capability_id": c.ID, "tests": c.Tests, "lifecycle_state": c.LifecycleState})
}

func (s *Server) traceability(w http.ResponseWriter, _ *http.Request, _ identity.Actor) {
	writeJSON(w, 200, map[string]any{"items": s.Registry.Traceability()})
}

func (s *Server) listStandards(w http.ResponseWriter, _ *http.Request, _ identity.Actor) {
	writeJSON(w, 200, map[string]any{"items": s.Registry.SortedStandards(), "notice": "Reference to a standard does not imply certification."})
}

type createChangeBody struct {
	RunbookID  string         `json:"runbook_id"`
	AssetID    string         `json:"asset_id"`
	Params     map[string]any `json:"params"`
	Reason     string         `json:"reason"`
	IncidentID *string        `json:"incident_id"`
	Type       string         `json:"type"`
	DryRun     bool           `json:"dry_run"`
}

func (s *Server) createChange(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	if err := requireAny(a, identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleEngineer, identity.RoleOperator, identity.RoleAIAgent); err != nil && !a.IsAI() {
		s.fail(w, r, err)
		return
	}
	var b createChangeBody
	if err := decode(r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	in := change.ProposeInput{
		RunbookID: b.RunbookID, AssetID: b.AssetID, Params: b.Params, Reason: b.Reason,
		Type: policy.ChangeType(b.Type), DryRun: b.DryRun, IdempotencyKey: r.Header.Get("Idempotency-Key"),
	}
	if b.IncidentID != nil {
		in.IncidentID = *b.IncidentID
	}
	if a.IsAI() && in.Type == policy.ChangeEmergency {
		s.fail(w, r, problem.New(problem.SeparationOfDuties, "AI agent cannot initiate break-glass emergency change"))
		return
	}
	if in.Type == policy.ChangeEmergency {
		if err := requireMFA(a); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	cr, err := s.Changes.Propose(a, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, statusForChange(cr), changeView(cr, a))
}

// statusForChange: 202 + waiting_approval — принято и ждёт согласования (§13).
func statusForChange(cr *change.ChangeRequest) int {
	switch cr.Status {
	case change.WaitingApproval, change.Scheduled, change.Executing, change.Approved:
		return http.StatusAccepted
	}
	return http.StatusCreated
}

// canSeeExecutionOutput — вывод исполнения (stdout/stderr/шаги) равнозначен содержимому evidence:
// по матрице §2.2 его видят TA, ITM, Engineer, Compliance Manager и Auditor; агенты получают ссылки.
func canSeeExecutionOutput(a identity.Actor) bool {
	return a.Kind == identity.KindUser && !a.IsAI() &&
		a.HasAny(identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleEngineer, identity.RoleComplianceManager, identity.RoleAuditor)
}

func changeView(cr *change.ChangeRequest, a identity.Actor) map[string]any {
	b, _ := json.Marshal(cr)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if !canSeeExecutionOutput(a) {
		if exs, ok := m["executions"].([]any); ok {
			for _, e := range exs {
				if em, ok := e.(map[string]any); ok {
					redactResult(em)
				}
			}
		}
	}
	if cr.Status == change.WaitingApproval {
		m["status"] = "waiting_approval"
	}
	return m
}

// redactResult оставляет в результате исполнения только статус и ссылки на evidence.
func redactResult(em map[string]any) {
	res, ok := em["result"].(map[string]any)
	if !ok {
		return
	}
	keep := map[string]any{}
	for _, k := range []string{"execution_id", "status", "evidence_id", "digest", "started_at", "finished_at", "exit_code"} {
		if v, ok := res[k]; ok {
			keep[k] = v
		}
	}
	keep["output_redacted"] = true
	em["result"] = keep
}

func (s *Server) listChanges(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	status := r.URL.Query().Get("status")
	items := []map[string]any{}
	for _, cr := range s.Changes.List(a.TenantID) {
		if status == "" || string(cr.Status) == status {
			items = append(items, changeView(cr, a))
		}
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) getChange(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	cr, ok := s.Changes.Get(a.TenantID, r.PathValue("id"))
	if !ok {
		s.fail(w, r, problem.New(problem.NotFound, "change not found"))
		return
	}
	writeJSON(w, 200, changeView(cr, a))
}

type decisionBody struct {
	Decision string `json:"decision"`
	Comment  string `json:"comment"`
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	if err := requireMFA(a); err != nil {
		s.fail(w, r, err)
		return
	}
	var b decisionBody
	if err := decode(r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	cr, err := s.Changes.Decide(a, r.PathValue("id"), approval.Verdict(b.Decision), b.Comment)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, changeView(cr, a))
}

type cancelBody struct {
	Reason string `json:"reason"`
}

func (s *Server) cancelChange(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	if a.IsAI() {
		// Агент может только отменить собственное предложение через задачу; отмена исполнения — человеком.
		s.fail(w, r, problem.New(problem.Forbidden, "AI agent cannot cancel changes"))
		return
	}
	if err := requireAny(a, identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleEngineer, identity.RoleOperator); err != nil {
		s.fail(w, r, err)
		return
	}
	var b cancelBody
	if r.ContentLength != 0 {
		if err := decode(r, &b); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	cr, err := s.Changes.Cancel(a, r.PathValue("id"), b.Reason)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 202, changeView(cr, a))
}

func (s *Server) changeExecutions(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	cr, ok := s.Changes.Get(a.TenantID, r.PathValue("id"))
	if !ok {
		s.fail(w, r, problem.New(problem.NotFound, "change not found"))
		return
	}
	writeJSON(w, 200, map[string]any{"items": changeView(cr, a)["executions"]})
}

func (s *Server) getExecution(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	ex, ok := s.Changes.Execution(a.TenantID, r.PathValue("id"))
	if !ok {
		s.fail(w, r, problem.New(problem.NotFound, "execution not found"))
		return
	}
	b, _ := json.Marshal(ex)
	var em map[string]any
	_ = json.Unmarshal(b, &em)
	if !canSeeExecutionOutput(a) {
		redactResult(em)
	}
	writeJSON(w, 200, em)
}

type killBody struct {
	Scope  string `json:"scope"` // tenant | platform
	Active *bool  `json:"active"`
	Reason string `json:"reason"`
}

func (s *Server) killStatus(w http.ResponseWriter, _ *http.Request, a identity.Actor) {
	t, p := s.Kill.Status(a.TenantID)
	writeJSON(w, 200, map[string]any{"tenant": t, "platform": p})
}

func (s *Server) killSet(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	if err := requireMFA(a); err != nil {
		s.fail(w, r, err)
		return
	}
	var b killBody
	if err := decode(r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	if b.Active == nil || b.Reason == "" {
		s.fail(w, r, problem.New(problem.BadRequest, "active and reason are required"))
		return
	}
	switch b.Scope {
	case "platform":
		if !a.Has(identity.RoleSuperAdmin) {
			s.fail(w, r, problem.New(problem.Forbidden, "platform kill switch requires Platform Super Admin"))
			return
		}
		s.Kill.Set("", true, *b.Active, a.Ref(), b.Reason)
	case "tenant", "":
		if err := requireAny(a, identity.RoleSuperAdmin, identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleOperator); err != nil || a.IsAI() {
			s.fail(w, r, problem.New(problem.Forbidden, "kill switch requires Super Admin, Tenant Admin, IT Manager or Operator"))
			return
		}
		s.Kill.Set(a.TenantID, false, *b.Active, a.Ref(), b.Reason)
	default:
		s.fail(w, r, problem.New(problem.BadRequest, "scope must be tenant or platform"))
		return
	}
	_, _ = s.Audit.Append(audit.Record{TenantID: a.TenantID, Actor: a.Ref(), Action: "kill_switch.set", ObjectType: "kill_switch", ObjectID: b.Scope,
		Data: map[string]any{"active": *b.Active, "reason": b.Reason, "scope": b.Scope}})
	t, p := s.Kill.Status(a.TenantID)
	writeJSON(w, 200, map[string]any{"tenant": t, "platform": p})
}

func (s *Server) auditLogs(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	if err := requireAny(a, identity.RoleSuperAdmin, identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleComplianceManager, identity.RoleAuditor); err != nil || a.IsAI() {
		s.fail(w, r, problem.New(problem.Forbidden, "audit read requires an audit role"))
		return
	}
	obj := r.URL.Query().Get("object_id")
	items := []audit.Entry{}
	for _, e := range s.Audit.Entries(a.TenantID) {
		if obj == "" || e.ObjectID == obj {
			items = append(items, e)
		}
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) auditIntegrity(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	if err := requireAny(a, identity.RoleTenantAdmin, identity.RoleComplianceManager, identity.RoleAuditor); err != nil || a.IsAI() {
		s.fail(w, r, problem.New(problem.Forbidden, "integrity report is available to Auditor, Compliance Manager and Tenant Admin"))
		return
	}
	ok, at, err := s.Audit.VerifyTenant(a.TenantID)
	cp, _ := s.Audit.Checkpoint(a.TenantID)
	resp := map[string]any{"valid": ok, "checkpoint": cp, "entries": len(s.Audit.Entries(a.TenantID))}
	if err != nil {
		resp["broken_at_seq"], resp["error"] = at, err.Error()
	}
	writeJSON(w, 200, resp)
}

func (s *Server) getEvidence(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	if a.IsAI() {
		s.fail(w, r, problem.New(problem.Forbidden, "AI agents receive evidence references, not content"))
		return
	}
	if err := requireAny(a, identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleEngineer, identity.RoleComplianceManager, identity.RoleAuditor); err != nil {
		s.fail(w, r, err)
		return
	}
	purpose := strings.TrimSpace(r.URL.Query().Get("purpose"))
	it, body, err := s.Evidence.Get(a.TenantID, r.PathValue("id"), a.Ref(), purpose)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_, _ = s.Audit.Append(audit.Record{TenantID: a.TenantID, Actor: a.Ref(), Action: "evidence.accessed", ObjectType: "evidence", ObjectID: it.ID, Data: map[string]any{"purpose": purpose}})
	var content any
	_ = json.Unmarshal(body, &content)
	writeJSON(w, 200, map[string]any{"evidence": it, "content": content})
}

func newRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
