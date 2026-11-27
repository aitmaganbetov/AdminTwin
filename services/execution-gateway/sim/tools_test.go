package sim_test

import (
	"context"
	"testing"

	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/sim"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	toolsvc "github.com/aitmaganbetov/admintwin/services/tool-service"
)

// Ответы симулятора соответствуют контрактам ai/tools/read (Tool Service отклонил бы нарушение).
func TestSimulatorToolsMatchContracts(t *testing.T) {
	inv := inventory.NewStore()
	if err := inv.LoadFixture("../../../infra/dev/fixtures.yaml"); err != nil {
		t.Fatal(err)
	}
	ts, err := toolsvc.Load("../../../ai/tools/read", inv, func(string) []string { return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := sim.New()
	if err := s.RegisterTools(ts); err != nil {
		t.Fatal(err)
	}
	eng := identity.Actor{ID: "e", Kind: identity.KindUser, TenantID: "11111111-1111-4111-8111-111111111111", Roles: []identity.Role{identity.RoleEngineer}}
	web, linux, fw, db := "a0000000-0000-4000-8000-000000000002", "a0000000-0000-4000-8000-000000000003", "a0000000-0000-4000-8000-000000000001", "a0000000-0000-4000-8000-000000000004"
	s.SetDisk(linux, 96)
	for _, running := range []bool{true, false} {
		s.SetRunning(web, "3f2a9c1b7d4e", running)
		s.SetRunning(linux, "nginx.service", running)
		calls := map[string]map[string]any{
			"docker.container.inspect": {"asset_id": web, "container": "3f2a9c1b7d4e"},
			"linux.service.status":     {"asset_id": linux, "unit": "nginx.service"},
			"linux.disk.usage":         {"asset_id": linux},
			"postgres.activity":        {"asset_id": db},
			"fortigate.policy.status":  {"asset_id": fw},
		}
		for name, in := range calls {
			out, err := ts.Invoke(context.Background(), eng, name, in)
			if err != nil {
				t.Fatalf("%s (running=%v): %v", name, running, err)
			}
			if out["data"] == nil {
				t.Fatalf("%s: empty data", name)
			}
		}
	}
	out, _ := ts.Invoke(context.Background(), eng, "docker.container.inspect", map[string]any{"asset_id": web, "container": "3f2a9c1b7d4e"})
	if out["data"].(map[string]any)["state"].(map[string]any)["status"] != "exited" {
		t.Fatal("simulated outage must be visible to agents")
	}
}
