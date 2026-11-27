package api

import (
	"net/http"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/audit"
	change "github.com/aitmaganbetov/admintwin/services/change-coordinator"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/runbook"
	"github.com/aitmaganbetov/admintwin/services/policy"
)

// getTenantPolicy — режим автономности и политика tenant (чтение: TA, ITM, Compliance Manager, Auditor).
func (s *Server) getTenantPolicy(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	if a.IsAI() || !a.HasAny(identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleComplianceManager, identity.RoleAuditor, identity.RoleEngineer, identity.RoleOperator) {
		s.fail(w, r, problem.New(problem.Forbidden, "insufficient role"))
		return
	}
	tp, ok := s.Tenants(a.TenantID)
	if !ok {
		s.fail(w, r, problem.New(problem.NotFound, "tenant policy not found"))
		return
	}
	writeJSON(w, 200, tp)
}

type tenantPolicyBody struct {
	Mode                        runbook.Mode        `json:"mode"`
	AutonomousMediumRunbooks    []string            `json:"autonomous_medium_runbooks"`
	DeniedRunbooksByEnvironment map[string][]string `json:"denied_runbooks_by_environment"`
	MaintenanceWindows          []policy.Window     `json:"maintenance_windows"`
}

// putTenantPolicy — изменить политику / режим автономности: только Tenant Admin, с MFA (§2.2).
func (s *Server) putTenantPolicy(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	if a.IsAI() || a.Kind != identity.KindUser || !a.Has(identity.RoleTenantAdmin) {
		s.fail(w, r, problem.New(problem.Forbidden, "only Tenant Admin can change policy or autonomy mode"))
		return
	}
	if err := requireMFA(a); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.SaveTenant == nil {
		s.fail(w, r, problem.New(problem.NotFound, "policy management is not available"))
		return
	}
	var b tenantPolicyBody
	if err := decode(r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	if !b.Mode.Valid() {
		s.fail(w, r, problem.New(problem.InvalidParams, "mode must be observer|advisor|operator|autonomous"))
		return
	}
	for _, id := range b.AutonomousMediumRunbooks {
		rb, ok := s.Catalog.Get(id)
		if !ok || rb.Risk != runbook.RiskMedium || !rb.AllowsMode(runbook.ModeAutonomous) {
			s.fail(w, r, problem.New(problem.InvalidParams, "runbook %q is not a medium-risk runbook allowed in autonomous mode", id))
			return
		}
	}
	for _, win := range b.MaintenanceWindows {
		if !win.End.After(win.Start) || win.End.Sub(win.Start) > 7*24*time.Hour {
			s.fail(w, r, problem.New(problem.InvalidParams, "maintenance window must end after it starts and last at most 7 days"))
			return
		}
	}
	old, _ := s.Tenants(a.TenantID)
	tp := policy.TenantPolicy{ID: old.ID, TenantID: a.TenantID, Mode: b.Mode, AutonomousMediumRunbooks: b.AutonomousMediumRunbooks,
		DeniedRunbooksByEnvironment: b.DeniedRunbooksByEnvironment, MaintenanceWindows: b.MaintenanceWindows}
	if tp.ID == "" {
		tp.ID = a.TenantID
	}
	if err := s.SaveTenant(tp); err != nil {
		s.fail(w, r, err)
		return
	}
	_, _ = s.Audit.Append(audit.Record{TenantID: a.TenantID, Actor: a.Ref(), Action: "tenant.policy_changed", ObjectType: "tenant_policy", ObjectID: tp.ID,
		Data: map[string]any{"mode_before": old.Mode, "mode_after": tp.Mode, "autonomous_medium_runbooks": tp.AutonomousMediumRunbooks,
			"maintenance_windows": len(tp.MaintenanceWindows)}})
	writeJSON(w, 200, tp)
}

type pirBody struct {
	Summary           string   `json:"summary"`
	Findings          string   `json:"findings"`
	CorrectiveActions []string `json:"corrective_actions"`
}

// recordPIR — post-implementation review (§11.2 п.10; break-glass — в течение 72 ч, §11.5).
func (s *Server) recordPIR(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	if a.IsAI() || a.Kind != identity.KindUser || !a.HasAny(identity.RoleTenantAdmin, identity.RoleITManager) {
		s.fail(w, r, problem.New(problem.Forbidden, "PIR is recorded by IT Manager or Tenant Admin"))
		return
	}
	var b pirBody
	if err := decode(r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(b.Summary) < 10 {
		s.fail(w, r, problem.New(problem.InvalidParams, "summary is required"))
		return
	}
	cr, err := s.Changes.RecordPIR(a, r.PathValue("id"), change.PIR{Summary: b.Summary, Findings: b.Findings, CorrectiveActions: b.CorrectiveActions})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, changeView(cr))
}
