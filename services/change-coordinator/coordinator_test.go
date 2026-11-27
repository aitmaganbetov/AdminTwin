package change

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/killswitch"
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
