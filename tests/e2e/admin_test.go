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

func TestAICallAuditIngest(t *testing.T) {
	e := newEnv(t)
	orch := who{tenantA, "orchestrator", "service", "", ""}
	rec := map[string]any{"record_type": "llm_call", "call_id": "c1", "tenant_id": tenantA, "agent_id": "devops-engineer",
		"provider": "anthropic", "model": "m", "prompt_version": "v1", "input_sha256": strings.Repeat("a", 64), "status": "ok"}
	if r := e.do(orch, "POST", "/api/v1/audit/ai-calls", map[string]any{"records": []any{rec}}); r.Status != 202 {
		t.Fatalf("orchestrator ingest: %d %s", r.Status, r.Raw)
	}
	for _, w := range []who{{tenantA, "collector", "service", "", ""}, agentA, adminA} {
		if r := e.do(w, "POST", "/api/v1/audit/ai-calls", map[string]any{"records": []any{rec}}); r.Status != 403 {
			t.Errorf("%s must not write AI audit: %d", w.id, r.Status)
		}
	}
	other := map[string]any{}
	for k, v := range rec {
		other[k] = v
	}
	other["tenant_id"] = tenantB
	if r := e.do(orch, "POST", "/api/v1/audit/ai-calls", map[string]any{"records": []any{other}}); r.Status != 403 {
		t.Errorf("cross-tenant record: %d", r.Status)
	}
	rec["input_sha256"] = "not-a-hash"
	if r := e.do(orch, "POST", "/api/v1/audit/ai-calls", map[string]any{"records": []any{rec}}); r.Status != 422 {
		t.Errorf("invalid hash: %d", r.Status)
	}
	rec["input_sha256"] = strings.Repeat("a", 64)
	rec["prompt"] = "raw prompt text"
	if r := e.do(orch, "POST", "/api/v1/audit/ai-calls", map[string]any{"records": []any{rec}}); r.Status != 400 {
		t.Errorf("raw prompt fields must be rejected: %d", r.Status)
	}
	found := false
	for _, it := range e.do(auditorA, "GET", "/api/v1/audit-logs", nil).Body["items"].([]any) {
		m := it.(map[string]any)
		if m["action"] == "ai.llm_call" && m["actor"] == "ai_agent:devops-engineer" {
			found = m["data"].(map[string]any)["provider"] == "anthropic"
		}
	}
	if !found {
		t.Fatal("LLM call must be in the tenant audit chain")
	}
}

// Ревью №6: вывод исполнений виден только ролям с правом на evidence; пользователь без ролей не читает ничего.
func TestExecutionOutputAndZeroRoleAccess(t *testing.T) {
	e := newEnv(t)
	r := e.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": appAPI})
	id := r.str("id")
	e.waitStatus(engineerA, id, "closed")
	result := func(w who) map[string]any {
		got := e.do(w, "GET", "/api/v1/changes/"+id, nil)
		if got.Status != 200 {
			t.Fatalf("%s read change: %d", w.id, got.Status)
		}
		return got.Body["executions"].([]any)[0].(map[string]any)["result"].(map[string]any)
	}
	if _, ok := result(engineerA)["stdout"]; !ok {
		t.Fatal("engineer must see execution output")
	}
	for _, w := range []who{agentA, viewerA, operatorA} {
		res := result(w)
		if _, ok := res["stdout"]; ok || res["output_redacted"] != true || res["evidence_id"] == nil {
			t.Fatalf("%s must get evidence references only: %v", w.id, res)
		}
	}
	exID := e.do(engineerA, "GET", "/api/v1/changes/"+id+"/executions", nil).Body["items"].([]any)[0].(map[string]any)["id"].(string)
	if got := e.do(agentA, "GET", "/api/v1/executions/"+exID, nil); got.Body["result"].(map[string]any)["steps"] != nil {
		t.Fatal("single execution view must be redacted for agents")
	}
	noRoles := who{tenantA, "sso-user", "user", "", ""}
	for _, p := range []string{"/api/v1/assets", "/api/v1/changes", "/api/v1/changes/" + id, "/api/v1/runbooks"} {
		if got := e.do(noRoles, "GET", p, nil); got.Status != 403 {
			t.Errorf("zero-role user %s: %d", p, got.Status)
		}
	}
	if got := e.do(agentA, "GET", "/api/v1/incidents", nil); got.Status != 403 {
		t.Errorf("agents must not read incidents via REST: %d", got.Status)
	}
}
