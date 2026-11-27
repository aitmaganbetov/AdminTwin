package policy

import (
	"testing"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/runbook"
	"github.com/aitmaganbetov/admintwin/services/inventory"
)

const tenant = "t1"

func rb(risk runbook.Risk, std bool, modes ...runbook.Mode) *runbook.Spec {
	ct := "normal"
	if std {
		ct = "standard"
	}
	return &runbook.Spec{ID: "x.y." + string(risk), Version: "1.0.0", Risk: risk, ChangeTypeDefault: ct,
		Scope: []runbook.ScopeEntry{{AssetType: "linux_host"}}, ModesAllowed: modes, Rollback: "x.y.undo",
		Rate: runbook.RateLimit{Count: 5, Window: "hour", Per: "asset"}, RateLimit: "5/hour/asset"}
}

func asset() *inventory.Asset {
	return &inventory.Asset{ID: "a1", TenantID: tenant, Name: "h1", Type: "linux_host", Environment: "production",
		Criticality: "high", DataClass: "internal", Owner: "ops", Verified: true}
}

func user(roles ...identity.Role) identity.Actor {
	return identity.Actor{ID: "u1", Kind: identity.KindUser, TenantID: tenant, Roles: roles}
}

func in(mode runbook.Mode, r *runbook.Spec) Input {
	return Input{Actor: user(identity.RoleEngineer), Tenant: TenantPolicy{ID: "p1", TenantID: tenant, Mode: mode},
		Asset: asset(), Runbook: r, ChangeType: ChangeNormal, Now: time.Now()}
}

// Матрица §11.4.
func TestMatrix(t *testing.T) {
	op, auto := runbook.ModeOperator, runbook.ModeAutonomous
	cases := []struct {
		name      string
		mode      runbook.Mode
		rb        *runbook.Spec
		outcome   Outcome
		approvals int
		window    bool
		err       problem.Code
	}{
		{"observer low → proposal", runbook.ModeObserver, rb(runbook.RiskLow, true, op), OutcomeProposalOnly, 0, false, ""},
		{"observer medium → denied", runbook.ModeObserver, rb(runbook.RiskMedium, false, op), "", 0, false, problem.PolicyDenied},
		{"advisor critical → proposal", runbook.ModeAdvisor, rb(runbook.RiskCritical, false, op), OutcomeProposalOnly, 0, false, ""},
		{"operator low standard → auto", op, rb(runbook.RiskLow, true, op), OutcomeAutoApproved, 0, false, ""},
		{"operator low normal → 1", op, rb(runbook.RiskLow, false, op), OutcomeRequiresApproval, 1, false, ""},
		{"operator medium → 1", op, rb(runbook.RiskMedium, false, op), OutcomeRequiresApproval, 1, false, ""},
		{"operator high → 1 manager", op, rb(runbook.RiskHigh, false, op), OutcomeRequiresApproval, 1, false, ""},
		{"operator critical → dual + window", op, rb(runbook.RiskCritical, false, op), OutcomeRequiresApproval, 2, true, ""},
		{"autonomous low → auto", auto, rb(runbook.RiskLow, false, auto), OutcomeAutoApproved, 0, false, ""},
		{"autonomous medium not allowlisted → 1", auto, rb(runbook.RiskMedium, false, auto), OutcomeRequiresApproval, 1, false, ""},
		{"autonomous high → no auto", auto, rb(runbook.RiskHigh, false, op), OutcomeRequiresApproval, 1, false, ""},
		{"autonomous critical → dual", auto, rb(runbook.RiskCritical, false, op), OutcomeRequiresApproval, 2, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Builtin{}.Evaluate(in(tc.mode, tc.rb))
			if tc.err != "" {
				if !problem.Is(err, tc.err) {
					t.Fatalf("want %s, got %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if d.Outcome != tc.outcome || d.RequiredApprovals != tc.approvals || d.RequiresMaintenanceWindow != tc.window {
				t.Fatalf("got outcome=%s approvals=%d window=%v", d.Outcome, d.RequiredApprovals, d.RequiresMaintenanceWindow)
			}
			if tc.rb.Risk.Rank() >= runbook.RiskHigh.Rank() && tc.outcome == OutcomeRequiresApproval {
				for _, r := range d.ApproverRoles {
					if r == identity.RoleEngineer {
						t.Fatal("high/critical must not be approvable by Engineer")
					}
				}
			}
		})
	}
}

func TestAutonomousMediumInWindow(t *testing.T) {
	r := rb(runbook.RiskMedium, false, runbook.ModeAutonomous)
	x := in(runbook.ModeAutonomous, r)
	x.Tenant.AutonomousMediumRunbooks = []string{r.ID}
	if d, _ := (Builtin{}).Evaluate(x); d.Outcome != OutcomeRequiresApproval {
		t.Fatalf("outside window medium must need approval, got %s", d.Outcome)
	}
	x.Tenant.MaintenanceWindows = []Window{{Start: x.Now.Add(-time.Hour), End: x.Now.Add(time.Hour)}}
	if d, _ := (Builtin{}).Evaluate(x); d.Outcome != OutcomeAutoApproved {
		t.Fatalf("explicitly allowed medium inside window must be auto, got %s", d.Outcome)
	}
}

func TestDenials(t *testing.T) {
	op := runbook.ModeOperator
	mk := func(f func(*Input)) error {
		x := in(op, rb(runbook.RiskLow, true, op))
		f(&x)
		_, err := Builtin{}.Evaluate(x)
		return err
	}
	if err := mk(func(x *Input) { x.KillSwitchActive = true }); !problem.Is(err, problem.KillSwitchActive) {
		t.Errorf("kill switch: %v", err)
	}
	if err := mk(func(x *Input) { x.Asset.LegalHold = true }); !problem.Is(err, problem.LegalHold) {
		t.Errorf("legal hold: %v", err)
	}
	if err := mk(func(x *Input) { x.Asset.Environment = "" }); !problem.Is(err, problem.PolicyDenied) {
		t.Errorf("unclassified asset: %v", err)
	}
	if err := mk(func(x *Input) { x.Asset.Type = "firewall" }); !problem.Is(err, problem.PolicyDenied) {
		t.Errorf("scope mismatch: %v", err)
	}
	if err := mk(func(x *Input) { x.Asset.TenantID = "other" }); !problem.Is(err, problem.PolicyDenied) {
		t.Errorf("cross-tenant asset: %v", err)
	}
	if err := mk(func(x *Input) { x.RecentExecutions = 5 }); !problem.Is(err, problem.PolicyDenied) {
		t.Errorf("rate limit: %v", err)
	}
	if err := mk(func(x *Input) {
		x.Tenant.DeniedRunbooksByEnvironment = map[string][]string{"production": {x.Runbook.ID}}
	}); !problem.Is(err, problem.PolicyDenied) {
		t.Errorf("env deny: %v", err)
	}
	if err := mk(func(x *Input) { x.Tenant.Mode = "" }); !problem.Is(err, problem.PolicyDenied) {
		t.Errorf("unset mode must fail closed: %v", err)
	}
}

func TestBreakGlass(t *testing.T) {
	op := runbook.ModeOperator
	x := in(op, rb(runbook.RiskHigh, false, op))
	x.ChangeType = ChangeEmergency
	x.Actor = identity.Actor{ID: "agent", Kind: identity.KindAIAgent, TenantID: tenant, Roles: []identity.Role{identity.RoleAIAgent}}
	if _, err := (Builtin{}).Evaluate(x); !problem.Is(err, problem.SeparationOfDuties) {
		t.Fatalf("AI cannot initiate break-glass, got %v", err)
	}
	x.Actor = user(identity.RoleEngineer)
	if _, err := (Builtin{}).Evaluate(x); !problem.Is(err, problem.Forbidden) {
		t.Fatalf("engineer cannot initiate break-glass, got %v", err)
	}
	x.Actor = user(identity.RoleITManager)
	d, err := Builtin{}.Evaluate(x)
	if err != nil || !d.BreakGlass || d.Outcome != OutcomeAutoApproved {
		t.Fatalf("IT manager break-glass high: %+v %v", d, err)
	}
	x.Runbook = rb(runbook.RiskCritical, false, op)
	d, _ = Builtin{}.Evaluate(x)
	if d.RequiredApprovals != 2 {
		t.Fatalf("critical is always dual control, even emergency")
	}
}

func TestCriticalWithoutRollbackDenied(t *testing.T) {
	r := rb(runbook.RiskCritical, false, runbook.ModeOperator)
	r.Rollback = "none"
	if _, err := (Builtin{}).Evaluate(in(runbook.ModeOperator, r)); !problem.Is(err, problem.PolicyDenied) {
		t.Fatalf("critical without rollback plan must be denied, got %v", err)
	}
}
