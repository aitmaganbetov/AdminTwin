package toolsvc_test

import (
	"context"
	"testing"

	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	toolsvc "github.com/aitmaganbetov/admintwin/services/tool-service"
)

const (
	tA     = "11111111-1111-4111-8111-111111111111"
	tB     = "22222222-2222-4222-8222-222222222222"
	assetA = "a0000000-0000-4000-8000-000000000002"
)

func svc(t *testing.T) *toolsvc.Service {
	t.Helper()
	inv := inventory.NewStore()
	if err := inv.LoadFixture("../../infra/dev/fixtures.yaml"); err != nil {
		t.Fatal(err)
	}
	scope := func(agent string) []string {
		if agent == "network-engineer" {
			return []string{"asset.get", "topology.blast_radius"}
		}
		return nil
	}
	s, err := toolsvc.Load("../../ai/tools/read", inv, scope, nil)
	if err != nil {
		t.Fatalf("all read tool contracts must compile in Go (RE2-compatible patterns): %v", err)
	}
	return s
}

func agent(id, tenant string) identity.Actor {
	return identity.Actor{ID: id, Kind: identity.KindAIAgent, TenantID: tenant, Roles: []identity.Role{identity.RoleAIAgent}}
}

func TestAgentScopeAndBuiltins(t *testing.T) {
	s := svc(t)
	ctx := context.Background()
	out, err := s.Invoke(ctx, agent("network-engineer", tA), "asset.get", map[string]any{"asset_id": assetA})
	if err != nil {
		t.Fatal(err)
	}
	if out["data_class"] != "confidential" { // актив docker-web-01 имеет data_class=confidential
		t.Fatalf("data class must be raised to the asset's class, got %v", out["data_class"])
	}
	if _, err := s.Invoke(ctx, agent("network-engineer", tA), "topology.blast_radius", map[string]any{"asset_id": assetA, "depth": 3}); err != nil {
		t.Fatal(err)
	}
	// T-CAP-001: агент без подтверждённого tool scope.
	if _, err := s.Invoke(ctx, agent("dba-engineer", tA), "asset.get", map[string]any{"asset_id": assetA}); !problem.Is(err, problem.Forbidden) {
		t.Fatalf("tool outside scope: %v", err)
	}
	// T-CAP-003: execute-инструментов не существует.
	for _, name := range []string{"docker.container.restart", "change.approve", "shell.exec"} {
		if _, err := s.Invoke(ctx, agent("network-engineer", tA), name, nil); !problem.Is(err, problem.NotFound) {
			t.Fatalf("%s must not exist: %v", name, err)
		}
	}
	// Cross-tenant: чужой актив неотличим от отсутствующего.
	if _, err := s.Invoke(ctx, agent("network-engineer", tB), "asset.get", map[string]any{"asset_id": assetA}); !problem.Is(err, problem.NotFound) {
		t.Fatalf("cross-tenant asset: %v", err)
	}
	// Вход по схеме.
	if _, err := s.Invoke(ctx, agent("network-engineer", tA), "asset.get", map[string]any{"asset_id": "../../etc"}); !problem.Is(err, problem.InvalidParams) {
		t.Fatalf("invalid input: %v", err)
	}
	if _, err := s.Invoke(ctx, agent("network-engineer", tA), "asset.get", map[string]any{"asset_id": assetA, "extra": 1}); !problem.Is(err, problem.InvalidParams) {
		t.Fatalf("unknown field: %v", err)
	}
}

func TestOutputOutsideContractIsNotReturned(t *testing.T) {
	s := svc(t)
	s.MustRegister("linux.disk.usage", func(context.Context, toolsvc.Call) (toolsvc.Result, error) {
		return toolsvc.Result{Data: map[string]any{"filesystems": "not-an-array", "secret_dump": "x"}}, nil
	})
	human := identity.Actor{ID: "eng", Kind: identity.KindUser, TenantID: tA, Roles: []identity.Role{identity.RoleEngineer}}
	if _, err := s.Invoke(context.Background(), human, "linux.disk.usage", map[string]any{"asset_id": "a0000000-0000-4000-8000-000000000003"}); !problem.Is(err, problem.Internal) {
		t.Fatalf("output violating the contract must be withheld: %v", err)
	}
	viewer := identity.Actor{ID: "v", Kind: identity.KindUser, TenantID: tA, Roles: []identity.Role{identity.RoleViewer}}
	if _, err := s.Invoke(context.Background(), viewer, "asset.get", map[string]any{"asset_id": assetA}); !problem.Is(err, problem.Forbidden) {
		t.Fatalf("viewer: %v", err)
	}
}

func TestRegisterRequiresContract(t *testing.T) {
	s := svc(t)
	if err := s.Register("docker.container.restart", nil); err == nil {
		t.Fatal("handlers can be registered only for existing read contracts")
	}
}
