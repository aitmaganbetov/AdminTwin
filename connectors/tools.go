package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"math"

	"github.com/aitmaganbetov/admintwin/connectors/db"
	"github.com/aitmaganbetov/admintwin/connectors/docker"
	"github.com/aitmaganbetov/admintwin/connectors/linux"
	"github.com/aitmaganbetov/admintwin/connectors/network"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	toolsvc "github.com/aitmaganbetov/admintwin/services/tool-service"
)

// RegisterTools подключает обработчики read tools коннекторов к Tool Service:
// docker.container.inspect, linux.service.status, linux.disk.usage, postgres.activity, fortigate.policy.status.
// Вход уже проверен по input_schema, актив — на принадлежность tenant; выход Tool Service сверяет с output_schema.
func (s *Set) RegisterTools(ts *toolsvc.Service) error {
	handlers := map[string]toolsvc.Handler{
		"docker.container.inspect": s.toolHandler(docker.Method, func(ctx context.Context, a *inventory.Asset, cred gateway.Credential, in map[string]any) (map[string]any, error) {
			out, err := s.docker.Inspect(ctx, a.Connection, cred, str(in["container"]))
			if errors.Is(err, docker.ErrNoSuchContainer) {
				return nil, problem.New(problem.NotFound, "container not found on asset")
			}
			return out, err
		}),
		"linux.service.status": s.toolHandler(linux.Method, func(ctx context.Context, a *inventory.Asset, cred gateway.Credential, in map[string]any) (map[string]any, error) {
			return s.linux.ServiceStatus(ctx, *a, cred, str(in["unit"]))
		}),
		"linux.disk.usage": s.toolHandler(linux.Method, func(ctx context.Context, a *inventory.Asset, cred gateway.Credential, in map[string]any) (map[string]any, error) {
			return s.linux.DiskUsage(ctx, *a, cred, str(in["mount"]))
		}),
		"postgres.activity": s.toolHandler(db.Method, func(ctx context.Context, a *inventory.Asset, cred gateway.Credential, in map[string]any) (map[string]any, error) {
			q := db.ActivityInput{Database: str(in["database"])}
			if v, ok := number(in["min_duration_s"]); ok {
				q.MinDuration = &v
			}
			if v, ok := number(in["limit"]); ok {
				q.Limit = int(v)
			}
			return s.pg.Activity(ctx, a.Connection, cred, q)
		}),
		"fortigate.policy.status": s.toolHandler(network.Method, func(ctx context.Context, a *inventory.Asset, cred gateway.Credential, in map[string]any) (map[string]any, error) {
			q := network.PolicyInput{VDOM: str(in["vdom"])}
			if v, ok := number(in["policy_id"]); ok {
				id := int(v)
				q.PolicyID = &id
			}
			return s.forti.PolicyStatus(ctx, a.Connection, cred, q)
		}),
	}
	for name, h := range handlers {
		if err := ts.Register(name, h); err != nil {
			return err
		}
	}
	return nil
}

type toolFunc func(ctx context.Context, a *inventory.Asset, cred gateway.Credential, in map[string]any) (map[string]any, error)

// toolHandler — общая обвязка: метод подключения актива, read-only учётка, журнал ошибок бэкенда
// (Tool Service отдаёт агенту только «tool backend error»; оператор видит причину в журнале, без секретов).
func (s *Set) toolHandler(method string, fn toolFunc) toolsvc.Handler {
	return func(ctx context.Context, c toolsvc.Call) (toolsvc.Result, error) {
		a := c.Asset
		if a == nil {
			return toolsvc.Result{}, problem.New(problem.NotFound, "asset not found")
		}
		if err := requireMethod(a, method); err != nil {
			return toolsvc.Result{}, problem.New(problem.Conflict, "asset has no %s connection configured", method)
		}
		cred, err := s.readOnly(ctx, a)
		if err != nil {
			s.log.Warn("tool credential unavailable", "tenant_id", c.TenantID, "asset_id", a.ID, "method", method, "error", err.Error())
			return toolsvc.Result{}, err
		}
		out, err := fn(ctx, a, cred, c.Input)
		if err != nil {
			if _, ok := problem.As(err); !ok {
				s.log.Warn("tool backend error", "tenant_id", c.TenantID, "asset_id", a.ID, "method", method, "error", err.Error())
			}
			return toolsvc.Result{}, err
		}
		return toolsvc.Result{Data: out}, nil
	}
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func number(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, !math.IsNaN(x) && !math.IsInf(x, 0)
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case nil:
		return 0, false
	}
	return 0, false
}
