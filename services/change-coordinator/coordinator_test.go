package change

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/killswitch"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/audit"
	evidence "github.com/aitmaganbetov/admintwin/services/compliance-evidence"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/runbook"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/sim"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	"github.com/aitmaganbetov/admintwin/services/policy"
)

// slowFacts замедляет preflight, чтобы change дольше оставался в состоянии scheduled.
type slowFacts struct{ *sim.Infra }

func (s slowFacts) RestartsLastHour(t, a, o string) (int, error) {
	time.Sleep(150 * time.Millisecond)
	return s.Infra.RestartsLastHour(t, a, o)
}

// Регрессия: Tick() во время preflight не должен запускать второе исполнение того же change.
func TestTickDoesNotDuplicateExecution(t *testing.T) {
	cat, err := runbook.LoadDir("../../runbooks/catalog")
	if err != nil {
		t.Fatal(err)
	}
	inv := inventory.NewStore()
	_ = inv.Put(inventory.Asset{ID: "h1", TenantID: "t1", Name: "h1", Type: "docker_host", Environment: "production",
		Criticality: "high", DataClass: "internal", Owner: "ops", Verified: true,
		Objects: map[string][]string{"container": {"3f2a9c1b7d4e"}}})
	s := sim.New()
	s.SetRunning("h1", "3f2a9c1b7d4e", true)
	now := time.Now()
	tp := policy.TenantPolicy{ID: "p", TenantID: "t1", Mode: runbook.ModeOperator,
		MaintenanceWindows: []policy.Window{{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}}}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ks := killswitch.New()
	gw := &gateway.Gateway{Engines: s.Engines(), Broker: s, Facts: slowFacts{s}, Evidence: evidence.NewStore(), Kill: ks}
	c := New(cat, inv, policy.Builtin{}, func(string) (policy.TenantPolicy, bool) { return tp, true }, gw, audit.New(audit.NewMemoryKeys(), priv), ks)

	actor := identity.Actor{ID: "u", Kind: identity.KindUser, TenantID: "t1", Roles: []identity.Role{identity.RoleEngineer}}
	cr, err := c.Propose(actor, ProposeInput{RunbookID: "docker.container.restart", AssetID: "h1",
		Params: map[string]any{"container_id": "3f2a9c1b7d4e"}, Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		c.Tick()
		time.Sleep(5 * time.Millisecond)
	}
	c.Wait()
	got, _ := c.Get("t1", cr.ID)
	if len(got.Executions) != 1 {
		t.Fatalf("want exactly 1 execution, got %d", len(got.Executions))
	}
	if got.Status != Closed {
		t.Fatalf("want closed, got %s", got.Status)
	}
}

type rig struct {
	c   *Coordinator
	sim *sim.Infra
	ks  *killswitch.Switch
	tp  *policy.TenantPolicy
}

func newRig(t *testing.T, slow bool) rig {
	t.Helper()
	cat, err := runbook.LoadDir("../../runbooks/catalog")
	if err != nil {
		t.Fatal(err)
	}
	inv := inventory.NewStore()
	_ = inv.Put(inventory.Asset{ID: "h1", TenantID: "t1", Name: "h1", Type: "docker_host", Environment: "production",
		Criticality: "high", DataClass: "internal", Owner: "ops", Verified: true, Objects: map[string][]string{"container": {"3f2a9c1b7d4e"}}})
	_ = inv.Put(inventory.Asset{ID: "l1", TenantID: "t1", Name: "l1", Type: "linux_host", Environment: "production",
		Criticality: "high", DataClass: "internal", Owner: "ops", Verified: true, Objects: map[string][]string{"log_directory": {"/var/log/app"}}})
	s := sim.New()
	s.SetRunning("h1", "3f2a9c1b7d4e", true)
	s.SetDisk("l1", 90)
	now := time.Now()
	tp := &policy.TenantPolicy{ID: "p", TenantID: "t1", Mode: runbook.ModeOperator,
		MaintenanceWindows: []policy.Window{{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}}}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	ks := killswitch.New()
	var facts gateway.Facts = s
	if slow {
		facts = slowFacts{s}
	}
	gw := &gateway.Gateway{Engines: s.Engines(), Broker: s, Facts: facts, Evidence: evidence.NewStore(), Kill: ks}
	c := New(cat, inv, policy.Builtin{}, func(string) (policy.TenantPolicy, bool) { return *tp, true }, gw, audit.New(audit.NewMemoryKeys(), priv), ks)
	return rig{c: c, sim: s, ks: ks, tp: tp}
}

var (
	eng  = identity.Actor{ID: "u", Kind: identity.KindUser, TenantID: "t1", Roles: []identity.Role{identity.RoleEngineer}}
	mgr  = identity.Actor{ID: "m", Kind: identity.KindUser, TenantID: "t1", Roles: []identity.Role{identity.RoleITManager}, MFA: true}
	opr  = identity.Actor{ID: "o", Kind: identity.KindUser, TenantID: "t1", Roles: []identity.Role{identity.RoleOperator}}
	rest = ProposeInput{RunbookID: "docker.container.restart", AssetID: "h1", Params: map[string]any{"container_id": "3f2a9c1b7d4e"}, Reason: "test"}
)

func restartsOf(r rig) int {
	n, _ := r.sim.RestartsLastHour("t1", "h1", "3f2a9c1b7d4e")
	return n
}

// Ревью №1: отмена во время preflight не должна позволить движку выполниться.
func TestCancelDuringPreflightStopsExecution(t *testing.T) {
	r := newRig(t, true)
	cr, err := r.c.Propose(eng, rest)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond) // идёт медленный preflight
	if _, err := r.c.Cancel(opr, cr.ID, "operator stop"); err != nil {
		t.Fatal(err)
	}
	r.c.Wait()
	got, _ := r.c.Get("t1", cr.ID)
	if got.Status != Cancelled || restartsOf(r) != 0 {
		t.Fatalf("status=%s engine calls=%d: a cancelled change must not execute", got.Status, restartsOf(r))
	}
	if len(got.Executions) == 1 && got.Executions[0].Status == string(gateway.StatusVerified) {
		t.Fatal("cancelled change must not carry a verified execution")
	}
}

// Ревью №1: kill switch во время preflight.
func TestKillSwitchDuringPreflightStopsExecution(t *testing.T) {
	r := newRig(t, true)
	cr, _ := r.c.Propose(eng, rest)
	time.Sleep(30 * time.Millisecond)
	r.ks.Set("t1", false, true, "user:o", "incident")
	r.c.Wait()
	got, _ := r.c.Get("t1", cr.ID)
	if got.Status != Cancelled || restartsOf(r) != 0 {
		t.Fatalf("status=%s engine calls=%d", got.Status, restartsOf(r))
	}
}

// Ревью №3: смена режима/запретов после создания запроса действует при согласовании.
func TestPolicyReevaluatedAtApproval(t *testing.T) {
	r := newRig(t, false)
	in := ProposeInput{RunbookID: "linux.logs.rotate_cleanup", AssetID: "l1", Params: map[string]any{"directory": "/var/log/app"}, Reason: "disk"}
	cr, err := r.c.Propose(eng, in)
	if err != nil || cr.Status != WaitingApproval {
		t.Fatalf("setup: %v %v", err, cr.Status)
	}
	r.tp.Mode = runbook.ModeObserver
	if _, err := r.c.Decide(mgr, cr.ID, "approve", ""); !problem.Is(err, problem.PolicyDenied) {
		t.Fatalf("approval after switching to observer must be policy-denied, got %v", err)
	}
	r.c.Wait()
	got, _ := r.c.Get("t1", cr.ID)
	if got.Status != Rejected {
		t.Fatalf("want rejected, got %s", got.Status)
	}
	r.tp.Mode = runbook.ModeOperator
	cr2, _ := r.c.Propose(eng, in)
	r.tp.DeniedRunbooksByEnvironment = map[string][]string{"production": {"linux.logs.rotate_cleanup"}}
	if _, err := r.c.Decide(mgr, cr2.ID, "approve", ""); !problem.Is(err, problem.PolicyDenied) {
		t.Fatalf("approval of a runbook denied for the environment: %v", err)
	}
}

// Ревью №4: лимит runbook нельзя обойти пачкой согласований.
func TestRateLimitCountsApprovedQueue(t *testing.T) {
	r := newRig(t, false)
	in := ProposeInput{RunbookID: "linux.logs.rotate_cleanup", AssetID: "l1", Params: map[string]any{"directory": "/var/log/app"}, Reason: "disk"}
	var ids []string
	for i := 0; i < 4; i++ {
		cr, err := r.c.Propose(eng, in)
		if err != nil {
			t.Fatalf("propose %d: %v", i, err)
		}
		ids = append(ids, cr.ID)
	}
	approved := 0
	for _, id := range ids {
		if _, err := r.c.Decide(mgr, id, "approve", ""); err == nil {
			approved++
		}
	}
	r.c.Wait()
	executed := 0
	for _, id := range ids {
		got, _ := r.c.Get("t1", id)
		for _, e := range got.Executions {
			if e.Status == string(gateway.StatusVerified) {
				executed++
			}
		}
	}
	if executed > 2 || approved > 2 {
		t.Fatalf("rate limit 2/day/asset bypassed: approved=%d executed=%d", approved, executed)
	}
}

// Ревью №5: параллельные запросы с одним Idempotency-Key создают не более одного change.
func TestIdempotencyKeyIsAtomic(t *testing.T) {
	r := newRig(t, false)
	in := rest
	in.IdempotencyKey = "same-key"
	var wg sync.WaitGroup
	ids := make(chan string, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if cr, err := r.c.Propose(eng, in); err == nil {
				ids <- cr.ID
			}
		}()
	}
	wg.Wait()
	close(ids)
	distinct := map[string]bool{}
	for id := range ids {
		distinct[id] = true
	}
	r.c.Wait()
	if len(distinct) != 1 || restartsOf(r) != 1 {
		t.Fatalf("one key created %d changes and %d executions", len(distinct), restartsOf(r))
	}
}
