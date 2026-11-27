package approval

import (
	"testing"

	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/policy"
)

func req(n int, roles ...identity.Role) Request {
	return Request{TenantID: "t", AuthorID: "author", Policy: policy.Decision{
		Outcome: policy.OutcomeRequiresApproval, RequiredApprovals: n, ApproverRoles: roles, EngineerScope: "sysadmin"}}
}

func human(id string, roles ...identity.Role) identity.Actor {
	return identity.Actor{ID: id, Kind: identity.KindUser, TenantID: "t", Roles: roles}
}

// T-CAP-002: AI пытается согласовать (собственный) change — отказ по separation of duties.
func TestAINeverApprover(t *testing.T) {
	ai := identity.Actor{ID: "author", Kind: identity.KindAIAgent, TenantID: "t", Roles: []identity.Role{identity.RoleAIAgent}}
	if err := CheckEligible(ai, req(1, identity.RoleTenantAdmin), Approve); !problem.Is(err, problem.SeparationOfDuties) {
		t.Fatalf("want separation-of-duties, got %v", err)
	}
	// Даже если машинной идентичности приписали человеческую роль.
	ai.Roles = append(ai.Roles, identity.RoleTenantAdmin)
	if err := CheckEligible(ai, req(1, identity.RoleTenantAdmin), Approve); !problem.Is(err, problem.SeparationOfDuties) {
		t.Fatalf("want separation-of-duties, got %v", err)
	}
}

func TestAuthorCannotApprove(t *testing.T) {
	if err := CheckEligible(human("author", identity.RoleTenantAdmin), req(1, identity.RoleTenantAdmin), Approve); !problem.Is(err, problem.SeparationOfDuties) {
		t.Fatalf("got %v", err)
	}
}

func TestDualControlNeedsIndependentApprovers(t *testing.T) {
	r := req(2, identity.RoleTenantAdmin, identity.RoleITManager)
	m := human("m1", identity.RoleITManager)
	if err := CheckEligible(m, r, Approve); err != nil {
		t.Fatal(err)
	}
	r.Decisions = append(r.Decisions, Decision{ActorID: "m1", Verdict: Approve})
	if r.Satisfied() {
		t.Fatal("one approval must not satisfy dual control")
	}
	if err := CheckEligible(m, r, Approve); !problem.Is(err, problem.SeparationOfDuties) {
		t.Fatalf("same approver twice must be refused, got %v", err)
	}
	if err := CheckEligible(human("m2", identity.RoleTenantAdmin), r, Approve); err != nil {
		t.Fatal(err)
	}
	r.Decisions = append(r.Decisions, Decision{ActorID: "m2", Verdict: Approve})
	if !r.Satisfied() {
		t.Fatal("two independent approvals must satisfy dual control")
	}
}

func TestEngineerOnlyOwnScope(t *testing.T) {
	r := req(1, identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleEngineer)
	e := human("e1", identity.RoleEngineer)
	e.Scopes = []string{"network"}
	if err := CheckEligible(e, r, Approve); !problem.Is(err, problem.Forbidden) {
		t.Fatalf("engineer outside scope must be refused, got %v", err)
	}
	e.Scopes = []string{"sysadmin"}
	if err := CheckEligible(e, r, Approve); err != nil {
		t.Fatalf("engineer in scope must be allowed: %v", err)
	}
}

func TestRolesAndTenant(t *testing.T) {
	r := req(1, identity.RoleTenantAdmin, identity.RoleITManager)
	for _, role := range []identity.Role{identity.RoleOperator, identity.RoleAuditor, identity.RoleViewer, identity.RoleComplianceManager, identity.RoleEngineer} {
		if err := CheckEligible(human("x", role), r, Approve); err == nil {
			t.Errorf("%s must not approve high-risk change", role)
		}
	}
	other := human("x", identity.RoleTenantAdmin)
	other.TenantID = "t2"
	if err := CheckEligible(other, r, Approve); !problem.Is(err, problem.NotFound) {
		t.Errorf("cross-tenant approver must see not-found, got %v", err)
	}
	notAwaiting := r
	notAwaiting.Policy.Outcome = policy.OutcomeProposalOnly
	if err := CheckEligible(human("x", identity.RoleTenantAdmin), notAwaiting, Approve); !problem.Is(err, problem.Conflict) {
		t.Errorf("proposal-only change cannot be approved, got %v", err)
	}
}
