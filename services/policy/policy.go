// Package policy — Policy Engine: единственная точка решений о допустимости изменения (§11.2 п.3).
// Реализует матрицу «риск × режим × согласование» (§11.4), separation of duties, legal hold,
// kill switch, классификацию активов. Интерфейс Engine позволяет заменить встроенную реализацию
// на OPA/Rego или Cedar (ADR-003) без изменения вызывающего кода.
package policy

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/runbook"
	"github.com/aitmaganbetov/admintwin/services/inventory"
)

// ChangeType — тип изменения (§11.1).
type ChangeType string

const (
	ChangeStandard  ChangeType = "standard"
	ChangeNormal    ChangeType = "normal"
	ChangeEmergency ChangeType = "emergency"
)

// Outcome — итог оценки политики.
type Outcome string

const (
	// OutcomeProposalOnly — режим Observer/Advisor: изменение фиксируется как предложение, исполнение невозможно.
	OutcomeProposalOnly Outcome = "proposal_only"
	// OutcomeAutoApproved — standard change / autonomous в пределах policy.
	OutcomeAutoApproved Outcome = "auto_approved"
	// OutcomeRequiresApproval — нужны решения людей по матрице.
	OutcomeRequiresApproval Outcome = "requires_approval"
)

// Window — maintenance window.
type Window struct {
	Start time.Time `json:"start" yaml:"start"`
	End   time.Time `json:"end" yaml:"end"`
}

// Contains — момент внутри окна.
func (w Window) Contains(t time.Time) bool { return !t.Before(w.Start) && t.Before(w.End) }

// TenantPolicy — настройки tenant, влияющие на решения.
type TenantPolicy struct {
	ID       string       `json:"id" yaml:"id"`
	TenantID string       `json:"tenant_id" yaml:"tenant_id"`
	Mode     runbook.Mode `json:"mode" yaml:"mode"`
	// AutonomousMediumRunbooks — runbook risk=medium, явно разрешённые для авто-исполнения
	// в режиме Autonomous внутри maintenance window (§11.4).
	AutonomousMediumRunbooks []string `json:"autonomous_medium_runbooks,omitempty" yaml:"autonomous_medium_runbooks,omitempty"`
	// DeniedRunbooksByEnvironment — запрет runbook в окружении (например, production).
	DeniedRunbooksByEnvironment map[string][]string `json:"denied_runbooks_by_environment,omitempty" yaml:"denied_runbooks_by_environment,omitempty"`
	MaintenanceWindows          []Window            `json:"maintenance_windows,omitempty" yaml:"maintenance_windows,omitempty"`
}

// InMaintenanceWindow — момент внутри любого окна tenant.
func (p TenantPolicy) InMaintenanceWindow(t time.Time) bool {
	for _, w := range p.MaintenanceWindows {
		if w.Contains(t) {
			return true
		}
	}
	return false
}

// Input — всё, что нужно для решения.
type Input struct {
	Actor            identity.Actor
	Tenant           TenantPolicy
	Asset            *inventory.Asset
	Runbook          *runbook.Spec
	ChangeType       ChangeType
	KillSwitchActive bool
	// RecentExecutions — число исполнений этого runbook по активу (или tenant) в окне rate limit.
	RecentExecutions int
	Now              time.Time
}

// Decision — результат с цепочкой причин для аудита.
type Decision struct {
	PolicyID                  string          `json:"policy_id"`
	Outcome                   Outcome         `json:"outcome"`
	RequiredApprovals         int             `json:"required_approvals"`
	ApproverRoles             []identity.Role `json:"approver_roles,omitempty"`
	EngineerScope             string          `json:"engineer_scope,omitempty"`
	RequiresMaintenanceWindow bool            `json:"requires_maintenance_window"`
	PreflightMandatory        bool            `json:"preflight_mandatory"`
	BreakGlass                bool            `json:"break_glass"`
	Reasons                   []string        `json:"reasons"`
}

// Engine — интерфейс движка политик (ADR-003: OPA-Rego / Cedar).
type Engine interface {
	Evaluate(in Input) (Decision, error)
}

// Builtin — встроенная реализация матрицы §11.4.
type Builtin struct{}

// EngineerScopeFor сопоставляет тип актива и scope-атрибут Engineer (§2.1).
func EngineerScopeFor(assetType string) string {
	switch assetType {
	case "docker_host", "kubernetes_cluster":
		return "devops"
	case "linux_host", "windows_host":
		return "sysadmin"
	case "firewall", "switch", "router", "wifi_controller":
		return "network"
	case "database":
		return "dba"
	}
	return "sysadmin"
}

func deny(code problem.Code, policyID, f string, a ...any) error {
	p := problem.New(code, f, a...)
	p.PolicyID = policyID
	return p
}

// Evaluate применяет правила в фиксированном порядке. Любая неопределённость — отказ (fail closed).
func (Builtin) Evaluate(in Input) (Decision, error) {
	pid := in.Tenant.ID
	d := Decision{PolicyID: pid}
	why := func(f string, a ...any) { d.Reasons = append(d.Reasons, fmt.Sprintf(f, a...)) }

	if in.KillSwitchActive {
		return d, deny(problem.KillSwitchActive, pid, "kill switch is active: new changes and executions are rejected")
	}
	if in.Runbook == nil || in.Asset == nil {
		return d, deny(problem.PolicyDenied, pid, "runbook and asset are required")
	}
	if in.Actor.TenantID != in.Tenant.TenantID || in.Asset.TenantID != in.Tenant.TenantID {
		return d, deny(problem.PolicyDenied, pid, "tenant scope mismatch")
	}
	if !in.Tenant.Mode.Valid() {
		return d, deny(problem.PolicyDenied, pid, "tenant autonomy mode is not configured")
	}
	rb, a := in.Runbook, in.Asset
	if !slices.Contains(rb.AssetTypes(), a.Type) {
		return d, deny(problem.PolicyDenied, pid, "runbook '%s' is not applicable to asset type '%s'", rb.ID, a.Type)
	}
	if missing := a.ClassificationComplete(); len(missing) > 0 {
		return d, deny(problem.PolicyDenied, pid, "asset classification incomplete (%s): execution requires it (§8.3)", strings.Join(missing, ", "))
	}
	if a.LegalHold {
		return d, deny(problem.LegalHold, pid, "asset '%s' is under legal hold", a.Name)
	}
	if slices.Contains(in.Tenant.DeniedRunbooksByEnvironment[a.Environment], rb.ID) {
		return d, deny(problem.PolicyDenied, pid, "runbook '%s' is not permitted for environment '%s'", rb.ID, a.Environment)
	}
	if rb.Rate.Count > 0 && in.RecentExecutions >= rb.Rate.Count {
		return d, deny(problem.PolicyDenied, pid, "rate limit %s exceeded for runbook '%s'", rb.RateLimit, rb.ID)
	}
	why("runbook %s@%s risk=%s, asset %s env=%s, mode=%s", rb.ID, rb.Version, rb.Risk, a.Name, a.Environment, in.Tenant.Mode)

	// Break-glass (§11.5): только человек Tenant Admin / IT Manager; AI не может инициировать.
	if in.ChangeType == ChangeEmergency {
		if in.Actor.IsAI() {
			return d, deny(problem.SeparationOfDuties, pid, "AI agent cannot initiate break-glass emergency change")
		}
		if !in.Actor.HasAny(identity.RoleTenantAdmin, identity.RoleITManager) {
			return d, deny(problem.Forbidden, pid, "break-glass requires Tenant Admin or IT Manager")
		}
		d.BreakGlass = true
		d.PreflightMandatory = true
		if rb.Risk == runbook.RiskCritical {
			// critical всегда dual control, включая emergency.
			d.Outcome = OutcomeRequiresApproval
			d.RequiredApprovals = 2
			d.ApproverRoles = []identity.Role{identity.RoleTenantAdmin, identity.RoleITManager}
			why("emergency critical change: dual control still required")
			return d, nil
		}
		d.Outcome = OutcomeAutoApproved
		why("break-glass by %s: approved by emergency procedure, post-review due in 72h", in.Actor.Ref())
		return d, nil
	}

	if in.ChangeType == ChangeStandard && rb.ChangeTypeDefault != "standard" {
		return d, deny(problem.PolicyDenied, pid, "runbook '%s' is not pre-approved as a standard change", rb.ID)
	}

	mode := in.Tenant.Mode
	switch mode {
	case runbook.ModeObserver:
		if rb.Risk != runbook.RiskLow {
			return d, deny(problem.PolicyDenied, pid, "Runbook '%s' is not permitted in mode 'observer' for environment '%s'", rb.ID, a.Environment)
		}
		d.Outcome = OutcomeProposalOnly
		why("observer mode: proposal only")
		return d, nil
	case runbook.ModeAdvisor:
		d.Outcome = OutcomeProposalOnly
		why("advisor mode: actions are only proposed")
		return d, nil
	}

	// Operator / Autonomous.
	scope := EngineerScopeFor(a.Type)
	needApproval := func(n int, roles []identity.Role, why2 string) {
		d.Outcome = OutcomeRequiresApproval
		d.RequiredApprovals = n
		d.ApproverRoles = roles
		why(why2)
	}
	managers := []identity.Role{identity.RoleTenantAdmin, identity.RoleITManager}
	withEngineer := []identity.Role{identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleEngineer}

	switch rb.Risk {
	case runbook.RiskLow:
		if rb.AllowsMode(mode) && (mode == runbook.ModeAutonomous || rb.ChangeTypeDefault == "standard") {
			d.Outcome = OutcomeAutoApproved
			if mode == runbook.ModeAutonomous {
				why("autonomous: low risk within policy and rate limit")
			} else {
				why("operator: standard change auto_ok")
			}
		} else {
			d.EngineerScope = scope
			needApproval(1, withEngineer, "low risk, not a standard change: 1 approver")
		}
	case runbook.RiskMedium:
		if mode == runbook.ModeAutonomous && rb.AllowsMode(mode) &&
			slices.Contains(in.Tenant.AutonomousMediumRunbooks, rb.ID) && in.Tenant.InMaintenanceWindow(in.Now) {
			d.Outcome = OutcomeAutoApproved
			why("autonomous: medium risk runbook explicitly allowed, inside maintenance window")
		} else {
			d.EngineerScope = scope
			needApproval(1, withEngineer, "medium risk: 1 approver (Engineer of scope "+scope+" or manager)")
		}
	case runbook.RiskHigh:
		d.PreflightMandatory = true
		needApproval(1, managers, "high risk: 1 approver IT Manager/Tenant Admin; preflight mandatory; auto forbidden")
	case runbook.RiskCritical:
		if !rb.Reversible() {
			return d, deny(problem.PolicyDenied, pid, "critical runbook '%s' has no rollback plan", rb.ID)
		}
		d.PreflightMandatory = true
		d.RequiresMaintenanceWindow = true
		needApproval(2, managers, "critical: dual control, maintenance window, rollback plan")
	}
	return d, nil
}
