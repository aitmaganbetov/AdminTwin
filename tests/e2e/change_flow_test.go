// E2E: критерии приёмки §21 [MVP] для единого контура Change → Policy → Approval → Gateway → Audit.
package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/aitmaganbetov/admintwin/services/execution-gateway/sim"
	"github.com/aitmaganbetov/admintwin/services/policy"
)

func TestStandardChangeAutoExecutesWithEvidenceAndAudit(t *testing.T) {
	e := newEnv(t)
	e.app.Sim.SetRunning(dockerWeb, appAPI, false)
	r := e.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": appAPI}, "Idempotency-Key", "k-1")
	if r.Status != 202 && r.Status != 201 {
		t.Fatalf("propose: %d %s", r.Status, r.Raw)
	}
	id := r.str("id")
	done := e.waitStatus(engineerA, id, "closed", "closed_with_compensation", "preflight_failed", "failed")
	if done.str("status") != "closed" {
		t.Fatalf("standard change must close after verification: %s", done.Raw)
	}
	ex := e.do(engineerA, "GET", "/api/v1/changes/"+id+"/executions", nil)
	items := ex.Body["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("one ExecutionRequest per runbook step, got %d", len(items))
	}
	result := items[0].(map[string]any)["result"].(map[string]any)
	evID, _ := result["evidence_id"].(string)
	if evID == "" || !strings.HasPrefix(result["digest"].(string), "sha256:") {
		t.Fatalf("evidence with digest required: %v", result)
	}

	// Evidence только с purpose-of-access; агент получает ссылки, не содержимое.
	if r := e.do(auditorA, "GET", "/api/v1/evidence/"+evID, nil); r.Status != 403 {
		t.Fatalf("evidence without purpose must be refused, got %d", r.Status)
	}
	if r := e.do(auditorA, "GET", "/api/v1/evidence/"+evID+"?purpose=quarterly-audit", nil); r.Status != 200 {
		t.Fatalf("auditor with purpose: %d %s", r.Status, r.Raw)
	}
	if r := e.do(agentA, "GET", "/api/v1/evidence/"+evID+"?purpose=x", nil); r.Status != 403 {
		t.Fatalf("AI agent must not read evidence content, got %d", r.Status)
	}

	// Аудит: actor, policy, runbook, результат; hash chain верифицируется.
	logs := e.do(auditorA, "GET", "/api/v1/audit-logs?object_id="+id, nil)
	actions := map[string]bool{}
	for _, it := range logs.Body["items"].([]any) {
		m := it.(map[string]any)
		actions[m["action"].(string)] = true
		data := m["data"].(map[string]any)
		prePolicy := m["action"] == "change.created" || m["action"] == "change.impact_assessed"
		if data["runbook_id"] != "docker.container.restart" || (data["policy_id"] == nil && !prePolicy) {
			t.Fatalf("audit entry lacks runbook/policy: %v", m)
		}
	}
	for _, a := range []string{"change.created", "change.impact_assessed", "change.risk_assessed", "change.approved", "execution.requested", "change.executing", "execution.completed", "change.verified", "change.closed"} {
		if !actions[a] {
			t.Errorf("audit missing %s", a)
		}
	}
	integ := e.do(auditorA, "GET", "/api/v1/audit-logs/integrity", nil)
	if integ.Body["valid"] != true {
		t.Fatalf("hash chain must verify: %s", integ.Raw)
	}

	// Идемпотентность.
	again := e.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": appAPI}, "Idempotency-Key", "k-1")
	if again.str("id") != id {
		t.Fatalf("same Idempotency-Key must return the same change")
	}
	diff := e.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": "9b8c7d6e5f4a"}, "Idempotency-Key", "k-1")
	if diff.Status != 422 || problemType(diff) != "idempotency-key-reused" {
		t.Fatalf("reused key with different payload: %d %s", diff.Status, diff.Raw)
	}
}

func TestNormalChangeApprovalSeparationOfDuties(t *testing.T) {
	e := newEnv(t)
	tp, _ := e.app.Tenant(tenantA)
	now := time.Now()
	tp.MaintenanceWindows = []policy.Window{{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}}
	e.app.SetTenant(tp)
	e.app.Sim.SetDisk(appLinux, 96)

	// Агент предлагает medium change через propose tool.
	r := e.propose(agentA, "linux.logs.rotate_cleanup", appLinux, map[string]any{"directory": "/var/log/app"})
	if r.Status != 202 || r.str("status") != "waiting_approval" {
		t.Fatalf("medium in operator mode: want 202 waiting_approval, got %d %s", r.Status, r.Raw)
	}
	id := r.str("id")

	// T-CAP-002: AI не может согласовать (в т.ч. собственный) change.
	if d := e.do(agentA, "POST", "/api/v1/changes/"+id+"/decisions", map[string]any{"decision": "approve"}); d.Status != 403 || problemType(d) != "separation-of-duties" {
		t.Fatalf("AI approve: %d %s", d.Status, d.Raw)
	}
	// Engineer чужой области, оператор, аудитор, viewer — не согласуют.
	for _, w := range []who{engineerA, operatorA, auditorA, viewerA} {
		if d := e.do(w, "POST", "/api/v1/changes/"+id+"/decisions", map[string]any{"decision": "approve"}); d.Status != 403 {
			t.Fatalf("%s must not approve: %d %s", w.id, d.Status, d.Raw)
		}
	}
	// Engineer своей области (sysadmin для linux_host) согласует.
	if d := e.do(sysadminA, "POST", "/api/v1/changes/"+id+"/decisions", map[string]any{"decision": "approve", "comment": "ok"}); d.Status != 200 {
		t.Fatalf("sysadmin approve: %d %s", d.Status, d.Raw)
	}
	done := e.waitStatus(adminA, id, "closed", "preflight_failed", "closed_with_compensation", "failed")
	if done.str("status") != "closed" {
		t.Fatalf("approved cleanup must close: %s", done.Raw)
	}
	if done.Body["pir_required"] != true {
		t.Fatal("normal change requires PIR")
	}
}

func TestAuthorCannotApproveOwnChange(t *testing.T) {
	e := newEnv(t)
	r := e.propose(sysadminA, "linux.logs.rotate_cleanup", appLinux, map[string]any{"directory": "/var/log/app"})
	if d := e.do(sysadminA, "POST", "/api/v1/changes/"+r.str("id")+"/decisions", map[string]any{"decision": "approve"}); d.Status != 403 || problemType(d) != "separation-of-duties" {
		t.Fatalf("author approve: %d %s", d.Status, d.Raw)
	}
	if d := e.do(managerA, "POST", "/api/v1/changes/"+r.str("id")+"/decisions", map[string]any{"decision": "reject", "comment": "not now"}); d.Status != 200 || d.str("status") != "rejected" {
		t.Fatalf("reject: %d %s", d.Status, d.Raw)
	}
}

func TestMaintenanceWindowPreflight(t *testing.T) {
	e := newEnv(t) // окон нет
	r := e.propose(engineerA, "linux.logs.rotate_cleanup", appLinux, map[string]any{"directory": "/var/log/app"})
	e.do(managerA, "POST", "/api/v1/changes/"+r.str("id")+"/decisions", map[string]any{"decision": "approve"})
	done := e.waitStatus(managerA, r.str("id"), "preflight_failed", "closed")
	if done.str("status") != "preflight_failed" {
		t.Fatalf("medium outside window must fail preflight even after approval: %s", done.Raw)
	}
}

func TestLegalHoldAndAllowlist(t *testing.T) {
	e := newEnv(t)
	if r := e.propose(engineerA, "linux.logs.rotate_cleanup", logArch, map[string]any{"directory": "/var/log/app"}); r.Status != 409 || problemType(r) != "legal-hold" || r.str("change_id") == "" {
		t.Fatalf("legal hold: %d %s", r.Status, r.Raw)
	}
	if r := e.propose(engineerA, "linux.logs.rotate_cleanup", appLinux, map[string]any{"directory": "/etc"}); r.Status != 422 || problemType(r) != "invalid-params" {
		t.Fatalf("param outside allowlist: %d %s", r.Status, r.Raw)
	}
	if r := e.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": "3f2a9c1b7d4e && reboot"}); r.Status != 422 {
		t.Fatalf("injection in params: %d %s", r.Status, r.Raw)
	}
	if r := e.propose(engineerA, "firewall.policy.change", dockerWeb, map[string]any{}); r.Status != 404 {
		t.Fatalf("runbook outside catalog: %d %s", r.Status, r.Raw)
	}
}

func TestNoDirectExecutionEndpoint(t *testing.T) {
	e := newEnv(t)
	for _, m := range []string{"POST", "PUT"} {
		if r := e.do(adminA, m, "/api/v1/executions", map[string]any{"runbook_id": "docker.container.restart"}); r.Status != 404 && r.Status != 405 {
			t.Fatalf("%s /executions must not exist, got %d", m, r.Status)
		}
	}
}

func TestAdvisorModeProposalOnly(t *testing.T) {
	e := newEnv(t)
	r := e.propose(engineerB, "docker.container.restart", dockerB, map[string]any{"container_id": appAPI})
	if r.Status != 201 || r.str("status") != "proposed" {
		t.Fatalf("advisor: %d %s", r.Status, r.Raw)
	}
	if d := e.do(managerB, "POST", "/api/v1/changes/"+r.str("id")+"/decisions", map[string]any{"decision": "approve"}); d.Status != 403 || problemType(d) != "policy-denied" {
		t.Fatalf("advisor approve must be policy-denied: %d %s", d.Status, d.Raw)
	}
}

func TestGatewayFailureHasNoBypass(t *testing.T) {
	e := newEnv(t)
	e.app.Sim.SetVaultDown(true)
	r := e.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": appAPI})
	done := e.waitStatus(engineerA, r.str("id"), "failed", "closed")
	if done.str("status") != "failed" {
		t.Fatalf("vault down must fail the change: %s", done.Raw)
	}
}

func TestPostCheckFailureCompensates(t *testing.T) {
	e := newEnv(t)
	e.app.Sim.InjectFault(dockerWeb, sim.FaultPostCheckFail)
	r := e.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": appAPI})
	done := e.waitStatus(engineerA, r.str("id"), "closed_with_compensation", "closed")
	if done.str("status") != "closed_with_compensation" {
		t.Fatalf("got %s", done.Raw)
	}
	if p, _ := done.Body["follow_up_proposals"].([]any); len(p) != 1 {
		t.Fatalf("compensation must propose logs_collect: %s", done.Raw)
	}
}

func TestChannelLossGoesToManualReview(t *testing.T) {
	e := newEnv(t)
	e.app.Sim.InjectFault(dockerWeb, sim.FaultChannelLost)
	r := e.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": appAPI})
	done := e.waitStatus(engineerA, r.str("id"), "manual_review", "closed")
	if done.str("status") != "manual_review" {
		t.Fatalf("got %s", done.Raw)
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t)
	tp, _ := e.app.Tenant(tenantA)
	now := time.Now()
	tp.MaintenanceWindows = []policy.Window{{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}}
	e.app.SetTenant(tp)
	for i := 0; i < 2; i++ {
		r := e.propose(engineerA, "linux.logs.rotate_cleanup", appLinux, map[string]any{"directory": "/var/log/app"})
		e.do(managerA, "POST", "/api/v1/changes/"+r.str("id")+"/decisions", map[string]any{"decision": "approve"})
		e.waitStatus(managerA, r.str("id"), "closed", "preflight_failed")
	}
	if r := e.propose(engineerA, "linux.logs.rotate_cleanup", appLinux, map[string]any{"directory": "/var/log/app"}); r.Status != 403 || !strings.Contains(r.str("detail"), "rate limit") {
		t.Fatalf("3rd cleanup in a day must hit rate_limit 2/day/asset: %d %s", r.Status, r.Raw)
	}
}
