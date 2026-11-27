package e2e

import (
	"testing"
	"time"

	"github.com/aitmaganbetov/admintwin/internal/app"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/sim"
	"net/http/httptest"
)

// T-TENANT-001 (API-уровень): нет cross-tenant доступа к активам, changes, исполнениям, evidence, аудиту.
func TestTenantIsolation(t *testing.T) {
	e := newEnv(t)
	r := e.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": appAPI})
	idA := r.str("id")
	e.waitStatus(engineerA, idA, "closed", "failed", "preflight_failed")

	paths := []string{
		"/api/v1/assets/" + dockerWeb,
		"/api/v1/assets/" + dockerWeb + "/blast-radius",
		"/api/v1/changes/" + idA,
		"/api/v1/changes/" + idA + "/executions",
	}
	for _, p := range paths {
		if got := e.do(engineerB, "GET", p, nil); got.Status != 404 {
			t.Errorf("tenant B GET %s: want 404, got %d", p, got.Status)
		}
	}
	if got := e.do(managerB, "POST", "/api/v1/changes/"+idA+"/decisions", map[string]any{"decision": "approve"}); got.Status != 404 {
		t.Errorf("cross-tenant decision: %d", got.Status)
	}
	if got := e.do(managerB, "POST", "/api/v1/changes/"+idA+"/cancel", nil); got.Status != 404 {
		t.Errorf("cross-tenant cancel: %d", got.Status)
	}
	// Чужой asset_id в собственном запросе.
	if got := e.propose(engineerB, "docker.container.restart", dockerWeb, map[string]any{"container_id": appAPI}); got.Status != 404 {
		t.Errorf("tenant B using tenant A asset: %d %s", got.Status, got.Raw)
	}
	// Списки не содержат чужих объектов.
	for _, it := range e.do(engineerB, "GET", "/api/v1/assets", nil).Body["items"].([]any) {
		if it.(map[string]any)["tenant_id"] != tenantB {
			t.Fatal("asset list leaked another tenant")
		}
	}
	if items := e.do(engineerB, "GET", "/api/v1/changes", nil).Body["items"].([]any); len(items) != 0 {
		t.Fatal("change list leaked another tenant")
	}
	// Подмена tenant: неизвестный tenant отклоняется.
	if got := e.do(who{"33333333-3333-4333-8333-333333333333", "x", "user", "tenant_admin", ""}, "GET", "/api/v1/assets", nil); got.Status != 401 {
		t.Errorf("unknown tenant: %d", got.Status)
	}
}

func TestAuthenticationFailsClosed(t *testing.T) {
	a, err := app.New(app.Config{Root: "../..", FixturesPath: "../../infra/dev/fixtures.yaml", DevAuth: false, Simulator: true})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Server.Handler())
	defer srv.Close()
	e := &env{t: t, app: a, srv: srv}
	if r := e.do(adminA, "GET", "/api/v1/assets", nil); r.Status != 401 || problemType(r) != "unauthenticated" {
		t.Fatalf("without auth configured every request must be 401, got %d", r.Status)
	}
	if r := e.do(who{}, "GET", "/api/v1/health/platform", nil); r.Status != 200 {
		t.Fatalf("health must stay public: %d", r.Status)
	}
}

func TestRoleChecks(t *testing.T) {
	e := newEnv(t)
	for _, w := range []who{viewerA, auditorA} {
		if r := e.propose(w, "docker.container.restart", dockerWeb, map[string]any{"container_id": appAPI}); r.Status != 403 {
			t.Errorf("%s must not propose changes: %d", w.id, r.Status)
		}
	}
	for _, w := range []who{viewerA, engineerA, agentA} {
		if r := e.do(w, "GET", "/api/v1/audit-logs", nil); r.Status != 403 {
			t.Errorf("%s must not read audit: %d", w.id, r.Status)
		}
	}
	if r := e.do(agentA, "POST", "/api/v1/kill-switch", map[string]any{"active": true, "reason": "x"}); r.Status != 403 {
		t.Errorf("AI agent must not use kill switch: %d", r.Status)
	}
	if r := e.do(adminA, "POST", "/api/v1/kill-switch", map[string]any{"scope": "platform", "active": true, "reason": "x"}); r.Status != 403 {
		t.Errorf("tenant admin must not flip the platform kill switch: %d", r.Status)
	}
	if r := e.do(agentA, "POST", "/api/v1/changes", map[string]any{"runbook_id": "docker.container.restart", "asset_id": dockerWeb, "params": map[string]any{"container_id": appAPI}, "reason": "x", "type": "emergency"}); r.Status != 403 || problemType(r) != "separation-of-duties" {
		t.Errorf("AI agent cannot initiate break-glass: %d %s", r.Status, r.Raw)
	}
}

// Kill switch (§11.7, §21): новые операции отклонены немедленно, исполнения — cancelled / unknown → manual_review
// за < 5 с, открытые согласования отозваны. Успех остановки без подтверждения не утверждается.
func TestKillSwitch(t *testing.T) {
	cases := []struct {
		name  string
		fault sim.Fault
		want  string
	}{
		{"engine confirms cancellation", sim.FaultHangConfirm, "cancelled"},
		{"engine cannot confirm", sim.FaultHangNoConfirm, "manual_review"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			started := make(chan string, 1)
			e.app.Sim.Started = started
			e.app.Sim.InjectFault(dockerWeb, tc.fault)

			pending := e.propose(engineerA, "linux.logs.rotate_cleanup", appLinux, map[string]any{"directory": "/var/log/app"})
			if pending.str("status") != "waiting_approval" {
				t.Fatalf("setup: %s", pending.Raw)
			}
			running := e.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": appAPI})
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("execution did not start")
			}
			e.waitStatus(engineerA, running.str("id"), "executing")

			t0 := time.Now()
			if r := e.do(operatorA, "POST", "/api/v1/kill-switch", map[string]any{"active": true, "reason": "incident"}); r.Status != 200 {
				t.Fatalf("kill switch: %d %s", r.Status, r.Raw)
			}
			done := e.waitStatus(engineerA, running.str("id"), tc.want)
			if time.Since(t0) > 5*time.Second {
				t.Fatalf("cancellation took %v (> 5s)", time.Since(t0))
			}
			var sawPending bool
			for _, tr := range done.Body["transitions"].([]any) {
				if tr.(map[string]any)["to"] == "cancellation_pending" {
					sawPending = true
				}
			}
			if !sawPending {
				t.Fatal("cancellation must pass through cancellation_pending")
			}
			if r := e.do(engineerA, "GET", "/api/v1/changes/"+pending.str("id"), nil); r.str("status") != "rejected" {
				t.Fatalf("open approvals must be revoked: %s", r.Raw)
			}
			if r := e.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": appAPI}); r.Status != 409 || problemType(r) != "kill-switch-active" {
				t.Fatalf("new changes must be rejected: %d %s", r.Status, r.Raw)
			}
		})
	}
}
