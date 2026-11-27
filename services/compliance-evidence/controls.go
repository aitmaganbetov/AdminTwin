package evidence

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aitmaganbetov/admintwin/pkg/db"
	"github.com/aitmaganbetov/admintwin/pkg/httpapi"
	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/audit"
)

// Статусы контроля (Приложение A.3) и verified (A.4).
var controlStatuses = []string{"not_assessed", "applicable", "implemented", "partially_implemented", "non_compliant", "not_applicable", "verified"}

// requireEvidence — статусы, недопустимые без evidence (A.4, T-COMP-001).
var requireEvidence = []string{"implemented", "verified"}

// Assessment — текущая оценка контроля tenant. История сохраняется в аудите (старые оценки не перезаписываются).
type Assessment struct {
	TenantID      string    `json:"tenant_id"`
	ControlID     string    `json:"control_id"`
	Status        string    `json:"status"`
	EvidenceIDs   []string  `json:"evidence_ids"`
	Justification string    `json:"justification,omitempty"`
	AssessedBy    string    `json:"assessed_by"`
	AssessedAt    time.Time `json:"assessed_at"`
}

// ControlRepo — хранилище оценок.
type ControlRepo interface {
	Get(ctx context.Context, tenantID string) (map[string]Assessment, error)
	Put(ctx context.Context, a Assessment) error
}

// MemControls — in-memory хранилище (dev/test).
type MemControls struct {
	mu sync.Mutex
	m  map[string]map[string]Assessment
}

// NewMemControls создаёт хранилище.
func NewMemControls() *MemControls { return &MemControls{m: map[string]map[string]Assessment{}} }

// Get — оценки tenant.
func (s *MemControls) Get(_ context.Context, t string) (map[string]Assessment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]Assessment{}
	for k, v := range s.m[t] {
		out[k] = v
	}
	return out, nil
}

// Put сохраняет оценку.
func (s *MemControls) Put(_ context.Context, a Assessment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[a.TenantID] == nil {
		s.m[a.TenantID] = map[string]Assessment{}
	}
	s.m[a.TenantID][a.ControlID] = a
	return nil
}

// PGControls — оценки в PostgreSQL (control_assessments, RLS).
type PGControls struct{ DB *db.DB }

// Get — оценки tenant.
func (s PGControls) Get(ctx context.Context, t string) (map[string]Assessment, error) {
	out := map[string]Assessment{}
	err := s.DB.WithTenant(ctx, t, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT control_id, status, evidence_ids, coalesce(justification,''), assessed_by, assessed_at FROM control_assessments`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a := Assessment{TenantID: t}
			if err := rows.Scan(&a.ControlID, &a.Status, &a.EvidenceIDs, &a.Justification, &a.AssessedBy, &a.AssessedAt); err != nil {
				return err
			}
			out[a.ControlID] = a
		}
		return rows.Err()
	})
	return out, err
}

// Put сохраняет оценку (upsert текущего статуса).
func (s PGControls) Put(ctx context.Context, a Assessment) error {
	return s.DB.WithTenant(ctx, a.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO control_assessments (tenant_id, control_id, status, evidence_ids, justification, assessed_by, assessed_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (tenant_id, control_id) DO UPDATE SET status=EXCLUDED.status, evidence_ids=EXCLUDED.evidence_ids,
			justification=EXCLUDED.justification, assessed_by=EXCLUDED.assessed_by, assessed_at=EXCLUDED.assessed_at`,
			a.TenantID, a.ControlID, a.Status, a.EvidenceIDs, a.Justification, a.AssessedBy, a.AssessedAt)
		return err
	})
}

// ControlDef — контроль каталога (в MVP — по одному на стандарт реестра; OSCAL-каталоги — P1a).
type ControlDef struct {
	ID       string `json:"id"`
	Standard string `json:"standard_id"`
	Title    string `json:"title"`
}

// Controls — модуль статусов контролей (M26 минимально; T-COMP-001).
type Controls struct {
	Catalog  func() []ControlDef
	Repo     ControlRepo
	Evidence Repository
	Audit    *audit.Log
}

var controlIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

// Assess устанавливает статус контроля с проверкой правил A.4.
func (c *Controls) Assess(ctx context.Context, a identity.Actor, controlID, status string, evidenceIDs []string, justification string) (Assessment, error) {
	if a.Kind != identity.KindUser || a.IsAI() || !a.HasAny(identity.RoleComplianceManager, identity.RoleTenantAdmin) {
		return Assessment{}, problem.New(problem.Forbidden, "control status is set by Compliance Manager or Tenant Admin")
	}
	if !a.MFA {
		return Assessment{}, problem.New(problem.MFARequired, "this action requires a session authenticated with MFA")
	}
	if !controlIDRe.MatchString(controlID) || !slices.ContainsFunc(c.Catalog(), func(d ControlDef) bool { return d.ID == controlID }) {
		return Assessment{}, problem.New(problem.NotFound, "control not found")
	}
	if !slices.Contains(controlStatuses, status) {
		return Assessment{}, problem.New(problem.InvalidParams, "status must be one of %s", strings.Join(controlStatuses, ", "))
	}
	if len(evidenceIDs) > 50 || len(justification) > 2000 {
		return Assessment{}, problem.New(problem.InvalidParams, "too many evidence ids or justification too long")
	}
	if slices.Contains(requireEvidence, status) && len(evidenceIDs) == 0 {
		// T-COMP-001: контроль без evidence не может быть implemented/verified.
		_, _ = c.Audit.Append(audit.Record{TenantID: a.TenantID, Actor: a.Ref(), Action: "control.assessment_refused", ObjectType: "control", ObjectID: controlID,
			Data: map[string]any{"status": status, "reason": "no evidence"}})
		return Assessment{}, problem.New(problem.InvalidParams, "status %q requires evidence (Appendix A.4, T-COMP-001)", status)
	}
	if status == "not_applicable" && len(strings.TrimSpace(justification)) < 10 {
		return Assessment{}, problem.New(problem.InvalidParams, "not_applicable requires a justification")
	}
	for _, id := range evidenceIDs {
		ok, err := c.Evidence.Verify(a.TenantID, id)
		if err != nil {
			return Assessment{}, problem.New(problem.InvalidParams, "evidence %s not found in tenant", id)
		}
		if !ok {
			return Assessment{}, problem.New(problem.Conflict, "evidence %s failed digest verification", id)
		}
	}
	as := Assessment{TenantID: a.TenantID, ControlID: controlID, Status: status, EvidenceIDs: evidenceIDs, Justification: justification,
		AssessedBy: a.Ref(), AssessedAt: time.Now().UTC()}
	if as.EvidenceIDs == nil {
		as.EvidenceIDs = []string{}
	}
	if err := c.Repo.Put(ctx, as); err != nil {
		return Assessment{}, err
	}
	_, _ = c.Audit.Append(audit.Record{TenantID: a.TenantID, Actor: a.Ref(), Action: "control.assessed", ObjectType: "control", ObjectID: controlID,
		Data: map[string]any{"status": status, "evidence_ids": as.EvidenceIDs}})
	return as, nil
}

// Routes — GET /api/v1/compliance/controls, POST /api/v1/compliance/controls/{id}/assessment.
func (c *Controls) Routes(r *httpapi.Router) {
	r.Handle("GET /api/v1/compliance/controls", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		if a.IsAI() || !a.HasAny(identity.RoleTenantAdmin, identity.RoleComplianceManager, identity.RoleAuditor, identity.RoleITManager) {
			httpapi.Fail(w, req, problem.New(problem.Forbidden, "insufficient role"))
			return
		}
		cur, err := c.Repo.Get(req.Context(), a.TenantID)
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		items := []map[string]any{}
		defs := c.Catalog()
		sort.Slice(defs, func(i, j int) bool { return defs[i].ID < defs[j].ID })
		for _, d := range defs {
			it := map[string]any{"id": d.ID, "standard_id": d.Standard, "title": d.Title, "status": "not_assessed"}
			if as, ok := cur[d.ID]; ok {
				b, _ := json.Marshal(as)
				var m map[string]any
				_ = json.Unmarshal(b, &m)
				for k, v := range m {
					it[k] = v
				}
			}
			items = append(items, it)
		}
		httpapi.WriteJSON(w, 200, map[string]any{"items": items, "notice": "Control statuses are not a certification; conformity is confirmed by audit."})
	})
	r.Handle("POST /api/v1/compliance/controls/{id}/assessment", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		var b struct {
			Status        string   `json:"status"`
			EvidenceIDs   []string `json:"evidence_ids"`
			Justification string   `json:"justification"`
		}
		if err := httpapi.Decode(req, &b); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		as, err := c.Assess(req.Context(), a, req.PathValue("id"), b.Status, b.EvidenceIDs, b.Justification)
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		httpapi.WriteJSON(w, 200, as)
	})
}
