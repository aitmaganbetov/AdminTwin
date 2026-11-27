// Package api — API Gateway v1 (§13): REST/JSON, RFC 9457, request_id, idempotency keys.
// Единая точка любой записи в инфраструктуру — /api/v1/changes. POST /executions отсутствует.
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/killswitch"
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
	Inventory *inventory.Store
	Catalog   *runbook.Catalog
	Registry  *registry.Registry
	Audit     *audit.Log
	Evidence  *evidence.Store
	Kill      *killswitch.Switch
	Tenants   func(string) (policy.TenantPolicy, bool)
	Log       *slog.Logger
	StartedAt time.Time
	Version   string
	Simulator bool
}

// Handler строит маршруты.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health/platform", s.health)

	auth := func(h func(http.ResponseWriter, *http.Request, identity.Actor)) http.HandlerFunc {
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
			h(w, r.WithContext(identity.WithActor(r.Context(), a)), a)
		}
	}

	mux.HandleFunc("GET /api/v1/assets", auth(s.listAssets))
	mux.HandleFunc("GET /api/v1/assets/{id}", auth(s.getAsset))
	mux.HandleFunc("GET /api/v1/assets/{id}/blast-radius", auth(s.blastRadius))
	mux.HandleFunc("GET /api/v1/topology", auth(s.topology))
	mux.HandleFunc("GET /api/v1/runbooks", auth(s.listRunbooks))
	mux.HandleFunc("GET /api/v1/capabilities", auth(s.listCapabilities))
	mux.HandleFunc("GET /api/v1/capabilities/{id}/tests", auth(s.capabilityTests))
	mux.HandleFunc("GET /api/v1/capabilities/traceability", auth(s.traceability))
	mux.HandleFunc("GET /api/v1/standards", auth(s.listStandards))

	mux.HandleFunc("POST /api/v1/changes", auth(s.createChange))
	mux.HandleFunc("GET /api/v1/changes", auth(s.listChanges))
	mux.HandleFunc("GET /api/v1/changes/{id}", auth(s.getChange))
	mux.HandleFunc("POST /api/v1/changes/{id}/decisions", auth(s.decide))
	mux.HandleFunc("POST /api/v1/changes/{id}/cancel", auth(s.cancelChange))
	mux.HandleFunc("GET /api/v1/changes/{id}/executions", auth(s.changeExecutions))
	mux.HandleFunc("GET /api/v1/executions/{id}", auth(s.getExecution))

	mux.HandleFunc("GET /api/v1/kill-switch", auth(s.killStatus))
	mux.HandleFunc("POST /api/v1/kill-switch", auth(s.killSet))
	mux.HandleFunc("GET /api/v1/audit-logs", auth(s.auditLogs))
	mux.HandleFunc("GET /api/v1/audit-logs/integrity", auth(s.auditIntegrity))
	mux.HandleFunc("GET /api/v1/evidence/{id}", auth(s.getEvidence))

	return s.middleware(mux)
}

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

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{
		"status": "ok", "version": s.Version, "uptime_s": int(time.Since(s.StartedAt).Seconds()),
		"components": map[string]string{
			"runbook_catalog": "ok", "capability_registry": "ok", "policy_engine": "builtin",
			"execution_backend": map[bool]string{true: "simulator", false: "connectors"}[s.Simulator],
		},
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
	cr, err := s.Changes.Propose(a, in)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, statusForChange(cr), changeView(cr))
}

// statusForChange: 202 + waiting_approval — принято и ждёт согласования (§13).
func statusForChange(cr *change.ChangeRequest) int {
	switch cr.Status {
	case change.WaitingApproval, change.Scheduled, change.Executing, change.Approved:
		return http.StatusAccepted
	}
	return http.StatusCreated
}

func changeView(cr *change.ChangeRequest) map[string]any {
	b, _ := json.Marshal(cr)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if cr.Status == change.WaitingApproval {
		m["status"] = "waiting_approval"
	}
	return m
}

func (s *Server) listChanges(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	status := r.URL.Query().Get("status")
	items := []map[string]any{}
	for _, cr := range s.Changes.List(a.TenantID) {
		if status == "" || string(cr.Status) == status {
			items = append(items, changeView(cr))
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
	writeJSON(w, 200, changeView(cr))
}

type decisionBody struct {
	Decision string `json:"decision"`
	Comment  string `json:"comment"`
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request, a identity.Actor) {
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
	writeJSON(w, 200, changeView(cr))
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
	writeJSON(w, 202, changeView(cr))
}

func (s *Server) changeExecutions(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	cr, ok := s.Changes.Get(a.TenantID, r.PathValue("id"))
	if !ok {
		s.fail(w, r, problem.New(problem.NotFound, "change not found"))
		return
	}
	writeJSON(w, 200, map[string]any{"items": cr.Executions})
}

func (s *Server) getExecution(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	ex, ok := s.Changes.Execution(a.TenantID, r.PathValue("id"))
	if !ok {
		s.fail(w, r, problem.New(problem.NotFound, "execution not found"))
		return
	}
	writeJSON(w, 200, ex)
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
