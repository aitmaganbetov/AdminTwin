package gateway_test

import (
	"context"
	"strings"
	"testing"

	"github.com/aitmaganbetov/admintwin/pkg/killswitch"
	evidence "github.com/aitmaganbetov/admintwin/services/compliance-evidence"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/runbook"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/sim"
	"github.com/aitmaganbetov/admintwin/services/inventory"
)

const tenant = "t1"

type fixture struct {
	gw  *gateway.Gateway
	sim *sim.Infra
	ev  *evidence.Store
	ks  *killswitch.Switch
	cat *runbook.Catalog
}

func setup(t *testing.T) fixture {
	t.Helper()
	cat, err := runbook.LoadDir("../../runbooks/catalog")
	if err != nil {
		t.Fatal(err)
	}
	s := sim.New()
	ev := evidence.NewStore()
	ks := killswitch.New()
	return fixture{gw: &gateway.Gateway{Engines: s.Engines(), Broker: s, Facts: s, Evidence: ev, Kill: ks}, sim: s, ev: ev, ks: ks, cat: cat}
}

func dockerHost() inventory.Asset {
	return inventory.Asset{ID: "h1", TenantID: tenant, Name: "docker-1", Type: "docker_host", Environment: "production",
		Criticality: "high", DataClass: "internal", Owner: "ops", Verified: true, HealthEndpoint: "http://x/healthz",
		Objects: map[string][]string{"container": {"3f2a9c1b7d4e", "0a1b2c3d4e5f"}}, Protected: []string{"0a1b2c3d4e5f"}}
}

func linuxHost() inventory.Asset {
	return inventory.Asset{ID: "l1", TenantID: tenant, Name: "linux-1", Type: "linux_host", Environment: "production",
		Criticality: "high", DataClass: "internal", Owner: "ops", Verified: true,
		Objects: map[string][]string{"log_directory": {"/var/log/app"}, "systemd_unit": {"nginx.service"}}}
}

func (f fixture) req(t *testing.T, id string, a inventory.Asset, params map[string]any) gateway.Request {
	t.Helper()
	rb, _ := f.cat.Get(id)
	p, err := rb.ValidateParams(params, func(k, v string) bool { return a.HasObject(k, v) })
	if err != nil {
		t.Fatal(err)
	}
	return gateway.Request{ChangeID: "c1", ExecutionID: "e1", TenantID: tenant, Asset: a, Runbook: rb, Params: p, FencingToken: f.ks.Token(tenant), InWindow: true}
}

func TestDockerRestartVerifiedWithEvidence(t *testing.T) {
	f := setup(t)
	f.sim.SetRunning("h1", "3f2a9c1b7d4e", false)
	res := f.gw.Run(context.Background(), f.req(t, "docker.container.restart", dockerHost(), map[string]any{"container_id": "3f2a9c1b7d4e"}))
	if res.Status != gateway.StatusVerified {
		t.Fatalf("want verified, got %s: %+v", res.Status, res.Steps)
	}
	if res.EvidenceID == "" || !strings.HasPrefix(res.Digest, "sha256:") {
		t.Fatal("evidence with digest must be recorded")
	}
	if ok, _ := f.ev.Verify(tenant, res.EvidenceID); !ok {
		t.Fatal("evidence digest must match")
	}
	if f.sim.ActiveLeases() != 0 {
		t.Fatal("short-lived credentials must be revoked after execution")
	}
}

// T-LH-001: очистка логов при legal hold — отказ preflight.
func TestLegalHoldBlocksCleanup(t *testing.T) {
	f := setup(t)
	a := linuxHost()
	a.LegalHold = true
	res := f.gw.Run(context.Background(), f.req(t, "linux.logs.rotate_cleanup", a, map[string]any{"directory": "/var/log/app"}))
	if res.Status != gateway.StatusPreflightFailed {
		t.Fatalf("want preflight_failed, got %s", res.Status)
	}
	last := res.Steps[len(res.Steps)-1]
	if last.Name != "legal_hold_absent" || last.OK {
		t.Fatalf("legal_hold_absent must be the failing check, got %+v", last)
	}
	for _, s := range res.Steps {
		if s.Phase == "execute" {
			t.Fatal("nothing may execute after a failed preflight")
		}
	}
}

func TestActiveInvestigationAndWindowBlockCleanup(t *testing.T) {
	f := setup(t)
	a := linuxHost()
	a.ActiveInvestigation = true
	if res := f.gw.Run(context.Background(), f.req(t, "linux.logs.rotate_cleanup", a, map[string]any{"directory": "/var/log/app"})); res.Status != gateway.StatusPreflightFailed {
		t.Fatalf("active investigation must block cleanup, got %s", res.Status)
	}
	r := f.req(t, "linux.logs.rotate_cleanup", linuxHost(), map[string]any{"directory": "/var/log/app"})
	r.InWindow = false
	if res := f.gw.Run(context.Background(), r); res.Status != gateway.StatusPreflightFailed {
		t.Fatalf("medium risk outside maintenance window must fail preflight, got %s", res.Status)
	}
}

func TestDryRunReportsVolumeWithoutChanges(t *testing.T) {
	f := setup(t)
	f.sim.SetDisk("l1", 95)
	res := f.gw.Run(context.Background(), f.req(t, "linux.logs.rotate_cleanup", linuxHost(), map[string]any{"directory": "/var/log/app", "dry_run": true}))
	r := f.req(t, "linux.logs.rotate_cleanup", linuxHost(), map[string]any{"directory": "/var/log/app", "dry_run": true})
	r.DryRun = true
	res = f.gw.Run(context.Background(), r)
	if res.Status != gateway.StatusDryRun || !strings.Contains(res.Stdout, "would free") {
		t.Fatalf("dry run: %s %q", res.Status, res.Stdout)
	}
	if p, _ := f.sim.DiskUsagePercent(tenant, "l1"); p != 95 {
		t.Fatalf("dry run must not change state, disk=%v", p)
	}
}

func TestProtectedContainerRefused(t *testing.T) {
	f := setup(t)
	res := f.gw.Run(context.Background(), f.req(t, "docker.container.restart", dockerHost(), map[string]any{"container_id": "0a1b2c3d4e5f"}))
	if res.Status != gateway.StatusPreflightFailed {
		t.Fatalf("protected container must not be restarted, got %s", res.Status)
	}
}

func TestRestartRateFromFactsEnforced(t *testing.T) {
	f := setup(t)
	f.sim.SetRunning("h1", "3f2a9c1b7d4e", true)
	for i := 0; i < 3; i++ {
		f.gw.Run(context.Background(), f.req(t, "docker.container.restart", dockerHost(), map[string]any{"container_id": "3f2a9c1b7d4e"}))
	}
	res := f.gw.Run(context.Background(), f.req(t, "docker.container.restart", dockerHost(), map[string]any{"container_id": "3f2a9c1b7d4e"}))
	if res.Status != gateway.StatusPreflightFailed {
		t.Fatalf("4th restart within an hour must fail preflight (restart_count_last_hour < 3), got %s", res.Status)
	}
}

func TestPostCheckFailureTriggersCompensation(t *testing.T) {
	f := setup(t)
	f.sim.InjectFault("h1", sim.FaultPostCheckFail)
	res := f.gw.Run(context.Background(), f.req(t, "docker.container.restart", dockerHost(), map[string]any{"container_id": "3f2a9c1b7d4e"}))
	if res.Status != gateway.StatusPostCheckFailed {
		t.Fatalf("want post_check_failed, got %s", res.Status)
	}
	if len(res.Compensation) == 0 || len(res.Proposals) != 1 || res.Proposals[0] != "docker.container.logs_collect" {
		t.Fatalf("compensation must run and propose logs_collect as a new change: %+v %+v", res.Compensation, res.Proposals)
	}
}

func TestChannelLossIsUnknownNotRetried(t *testing.T) {
	f := setup(t)
	f.sim.InjectFault("h1", sim.FaultChannelLost)
	res := f.gw.Run(context.Background(), f.req(t, "docker.container.restart", dockerHost(), map[string]any{"container_id": "3f2a9c1b7d4e"}))
	if res.Status != gateway.StatusUnknown {
		t.Fatalf("lost management channel must yield unknown, got %s", res.Status)
	}
	n := 0
	for _, s := range res.Steps {
		if s.Phase == "execute" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("gateway must not retry blindly, execute steps=%d", n)
	}
}

func TestVaultDownMeansNoExecution(t *testing.T) {
	f := setup(t)
	f.sim.SetVaultDown(true)
	res := f.gw.Run(context.Background(), f.req(t, "docker.container.restart", dockerHost(), map[string]any{"container_id": "3f2a9c1b7d4e"}))
	if res.Status != gateway.StatusFailed {
		t.Fatalf("vault down must make executions impossible, got %s", res.Status)
	}
	for _, s := range res.Steps {
		if s.Phase == "execute" && s.Name == "restart" {
			t.Fatal("engine must not be invoked without credentials")
		}
	}
}

func TestExecutionMustBelongToChange(t *testing.T) {
	f := setup(t)
	r := f.req(t, "docker.container.restart", dockerHost(), map[string]any{"container_id": "3f2a9c1b7d4e"})
	r.ChangeID = ""
	if res := f.gw.Run(context.Background(), r); res.Status != gateway.StatusPreflightFailed {
		t.Fatalf("execution without ChangeRequest must be refused, got %s", res.Status)
	}
}

func TestStaleFencingToken(t *testing.T) {
	f := setup(t)
	r := f.req(t, "docker.container.restart", dockerHost(), map[string]any{"container_id": "3f2a9c1b7d4e"})
	f.ks.Set(tenant, false, true, "user:x", "test")
	f.ks.Set(tenant, false, false, "user:x", "test done")
	if res := f.gw.Run(context.Background(), r); res.Status != gateway.StatusCancelled {
		t.Fatalf("execution with a stale fencing token must not start, got %s", res.Status)
	}
}

func TestRedaction(t *testing.T) {
	in := "login ok password=hunter2 token: abc.def Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U AKIAABCDEFGHIJKLMNOP"
	out := gateway.Redact(in)
	for _, secret := range []string{"hunter2", "abc.def", "eyJhbGci", "AKIAABCDEFGHIJKLMNOP"} {
		if strings.Contains(out, secret) {
			t.Errorf("secret %q leaked: %s", secret, out)
		}
	}
	f := setup(t)
	f.sim.InjectFault("h1", sim.FaultExitNonZero)
	res := f.gw.Run(context.Background(), f.req(t, "docker.container.restart", dockerHost(), map[string]any{"container_id": "3f2a9c1b7d4e"}))
	if strings.Contains(res.Stderr, "abc123") {
		t.Fatalf("stderr must be redacted: %q", res.Stderr)
	}
}
