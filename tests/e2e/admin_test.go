package e2e

import (
	"strings"
	"testing"

	"github.com/aitmaganbetov/admintwin/services/execution-gateway/sim"
)

func TestTenantPolicyAPI(t *testing.T) {
	e := newEnv(t)
	adminNoMFA := adminA
	if r := e.do(engineerA, "PUT", "/api/v1/tenant/policy", map[string]any{"mode": "autonomous"}); r.Status != 403 {
		t.Fatalf("engineer must not change policy: %d", r.Status)
	}
	if r := e.do(agentA, "PUT", "/api/v1/tenant/policy", map[string]any{"mode": "autonomous"}); r.Status != 403 {
		t.Fatalf("agent must not change policy: %d", r.Status)
	}
	r := e.do(adminNoMFA, "PUT", "/api/v1/tenant/policy", map[string]any{"mode": "advisor"}, "X-AdminTwin-MFA", "false")
	if r.Status != 403 || problemType(r) != "mfa-required" {
		t.Fatalf("policy change without MFA: %d %s", r.Status, r.Raw)
	}
	if r := e.do(adminA, "PUT", "/api/v1/tenant/policy", map[string]any{"mode": "advisor", "autonomous_medium_runbooks": []string{"docker.container.restart"}}); r.Status != 422 {
		t.Fatalf("low-risk runbook in medium allowlist must be refused: %d %s", r.Status, r.Raw)
	}
	if r := e.do(adminA, "PUT", "/api/v1/tenant/policy", map[string]any{"mode": "advisor"}); r.Status != 200 {
		t.Fatalf("switch to advisor: %d %s", r.Status, r.Raw)
	}
	// Политика действует сразу: в Advisor изменение становится предложением.
	if p := e.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": appAPI}); p.str("status") != "proposed" {
		t.Fatalf("advisor mode must produce a proposal: %s", p.Raw)
	}
	if got := e.do(auditorA, "GET", "/api/v1/tenant/policy", nil); got.str("mode") != "advisor" {
		t.Fatalf("policy read: %s", got.Raw)
	}
	found := false
	for _, it := range e.do(auditorA, "GET", "/api/v1/audit-logs", nil).Body["items"].([]any) {
		if it.(map[string]any)["action"] == "tenant.policy_changed" {
			found = true
		}
	}
	if !found {
		t.Fatal("policy change must be audited")
	}
}

func TestPIRClosesManualReview(t *testing.T) {
	e := newEnv(t)
	e.app.Sim.InjectFault(dockerWeb, sim.FaultChannelLost)
	r := e.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": appAPI})
	id := r.str("id")
	e.waitStatus(engineerA, id, "manual_review")
	body := map[string]any{"summary": "Management channel lost; container verified running manually.", "corrective_actions": []string{"add OOB access"}}
	if p := e.do(engineerA, "POST", "/api/v1/changes/"+id+"/pir", body); p.Status != 403 {
		t.Fatalf("engineer cannot record PIR: %d", p.Status)
	}
	if p := e.do(managerA, "POST", "/api/v1/changes/"+id+"/pir", body); p.Status != 200 || p.str("status") != "closed_with_compensation" {
		t.Fatalf("PIR by manager: %d %s", p.Status, p.Raw)
	}
	if p := e.do(managerA, "POST", "/api/v1/changes/"+id+"/pir", body); p.Status != 409 {
		t.Fatalf("second PIR: %d", p.Status)
	}
}

func TestMetricsAndHealth(t *testing.T) {
	e := newEnv(t)
	e.do(engineerA, "GET", "/api/v1/assets", nil)
	r := e.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": appAPI})
	e.waitStatus(engineerA, r.str("id"), "closed")
	e.app.VerifyAudit()
	var b strings.Builder
	e.app.Metrics.Write(&b)
	out := b.String()
	for _, want := range []string{
		`admintwin_http_requests_total{route="GET /api/v1/assets",status="200"} 1`,
		`admintwin_changes{status="closed"} 1`,
		`admintwin_kill_switch_active{scope="platform"} 0`,
		`admintwin_audit_chain_valid{tenant_id="` + tenantA + `"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	if strings.Contains(out, dockerWeb) {
		t.Error("object ids must not become metric labels")
	}
	h := e.do(who{}, "GET", "/api/v1/health/platform", nil)
	if h.Status != 200 || h.str("status") != "ok" {
		t.Fatalf("health: %d %s", h.Status, h.Raw)
	}
}
