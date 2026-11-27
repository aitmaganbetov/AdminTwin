package sim

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/httpapi"
	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	toolsvc "github.com/aitmaganbetov/admintwin/services/tool-service"
)

// RegisterTools — read tools поверх состояния симулятора (dev/демо без реальной инфраструктуры).
// Ответы строго по output_schema из ai/tools/read; Tool Service дополнительно их валидирует.
func (s *Infra) RegisterTools(ts *toolsvc.Service) error {
	reg := map[string]toolsvc.Handler{
		"docker.container.inspect": s.toolDockerInspect,
		"linux.service.status":     s.toolServiceStatus,
		"linux.disk.usage":         s.toolDiskUsage,
		"postgres.activity":        s.toolPostgres,
		"fortigate.policy.status":  s.toolFortigate,
	}
	for name, h := range reg {
		if err := ts.Register(name, h); err != nil {
			return err
		}
	}
	return nil
}

func (s *Infra) toolDockerInspect(_ context.Context, c toolsvc.Call) (toolsvc.Result, error) {
	id, _ := c.Input["container"].(string)
	if c.Asset == nil || !c.Asset.HasObject("container", id) {
		return toolsvc.Result{}, problem.New(problem.NotFound, "container not found on asset")
	}
	running, _ := s.ContainerRunning(c.TenantID, c.Asset.ID, id)
	restarts, _ := s.RestartsLastHour(c.TenantID, c.Asset.ID, id)
	state := map[string]any{"status": "running", "running": true, "exit_code": 0, "oom_killed": false, "restart_count": restarts,
		"started_at": time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339), "finished_at": nil, "health": "healthy"}
	if !running {
		state = map[string]any{"status": "exited", "running": false, "exit_code": 137, "oom_killed": true, "restart_count": restarts,
			"started_at": time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339), "finished_at": time.Now().Add(-4 * time.Minute).UTC().Format(time.RFC3339), "health": "unhealthy"}
	}
	return toolsvc.Result{Data: map[string]any{"container": id, "image": "registry.local/app/" + id[:6] + ":1.4.2", "image_digest": nil,
		"state": state, "restart_policy": "unless-stopped", "ports": []any{}, "labels": map[string]any{}}}, nil
}

func (s *Infra) toolServiceStatus(_ context.Context, c toolsvc.Call) (toolsvc.Result, error) {
	unit, _ := c.Input["unit"].(string)
	if c.Asset == nil || !c.Asset.HasObject("systemd_unit", unit) {
		return toolsvc.Result{}, problem.New(problem.NotFound, "unit not found on host")
	}
	active, _ := s.UnitActive(c.TenantID, c.Asset.ID, unit)
	out := map[string]any{"unit": unit, "load_state": "loaded", "active_state": "active", "sub_state": "running",
		"since": time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339), "main_pid": 1234, "recent_log": []any{}}
	if !active {
		out["active_state"], out["sub_state"], out["main_pid"] = "failed", "failed", nil
		out["recent_log"] = []any{time.Now().Add(-5*time.Minute).UTC().Format(time.RFC3339) + " " + unit + ": Main process exited, code=killed, status=9/KILL"}
	}
	return toolsvc.Result{Data: out}, nil
}

func (s *Infra) toolDiskUsage(_ context.Context, c toolsvc.Call) (toolsvc.Result, error) {
	pct, _ := s.DiskUsagePercent(c.TenantID, c.Asset.ID)
	const size = int64(100 << 30)
	used := int64(float64(size) * pct / 100)
	fs := []any{map[string]any{"mount": "/", "device": "/dev/sda1", "fstype": "ext4", "size_bytes": size, "used_bytes": used,
		"avail_bytes": size - used, "use_percent": pct, "inodes_use_percent": 12.0}}
	if m, ok := c.Input["mount"].(string); ok && m != "/" {
		fs = []any{}
	}
	top := []any{}
	for _, d := range c.Asset.Objects["log_directory"] {
		top = append(top, map[string]any{"path": d, "size_bytes": used / int64(2+len(top))})
	}
	return toolsvc.Result{Data: map[string]any{"filesystems": fs, "top_dirs": top}}, nil
}

func (s *Infra) toolPostgres(_ context.Context, _ toolsvc.Call) (toolsvc.Result, error) {
	sessions := []any{
		map[string]any{"pid": 4101, "usename": "app", "datname": "shop", "state": "active", "wait_event_type": nil, "wait_event": nil,
			"query_start": time.Now().Add(-2 * time.Second).UTC().Format(time.RFC3339), "duration_s": 2.1, "query": "SELECT … FROM orders WHERE …"},
		map[string]any{"pid": 4102, "usename": "app", "datname": "shop", "state": "idle", "wait_event_type": "Client", "wait_event": "ClientRead",
			"query_start": nil, "duration_s": nil, "query": nil},
	}
	return toolsvc.Result{Data: map[string]any{"max_connections": 200, "total_connections": 42, "sessions": sessions}}, nil
}

func (s *Infra) toolFortigate(_ context.Context, _ toolsvc.Call) (toolsvc.Result, error) {
	return toolsvc.Result{Data: map[string]any{"ha_status": "standalone", "policies": []any{
		map[string]any{"policy_id": 10, "name": "wan-to-web", "action": "accept", "status": "enable", "srcintf": []any{"wan1"}, "dstintf": []any{"dmz"}, "hit_count": 182734, "last_used": time.Now().UTC().Format(time.RFC3339)},
		map[string]any{"policy_id": 20, "name": "web-to-db", "action": "accept", "status": "enable", "srcintf": []any{"dmz"}, "dstintf": []any{"internal"}, "hit_count": 99120, "last_used": time.Now().UTC().Format(time.RFC3339)},
	}}}, nil
}

// Routes — DEV-эндпоинт управления симулятором (POST /api/v1/dev/simulator): уронить контейнер/службу,
// задать заполненность диска, внедрить отказ. Подключается только при симуляторе и dev-аутентификации.
func (s *Infra) Routes(r *httpapi.Router) {
	r.Handle("POST /api/v1/dev/simulator", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		if a.Kind != identity.KindUser || !a.HasAny(identity.RoleTenantAdmin, identity.RoleEngineer, identity.RoleOperator) {
			httpapi.Fail(w, req, problem.New(problem.Forbidden, "simulator control requires an engineer"))
			return
		}
		var b struct {
			AssetID     string   `json:"asset_id"`
			Object      string   `json:"object"`
			Running     *bool    `json:"running"`
			DiskPercent *float64 `json:"disk_percent"`
			Fault       string   `json:"fault"`
		}
		if err := httpapi.Decode(req, &b); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		if b.AssetID == "" {
			httpapi.Fail(w, req, problem.New(problem.InvalidParams, "asset_id is required"))
			return
		}
		if b.Running != nil {
			if b.Object == "" {
				httpapi.Fail(w, req, problem.New(problem.InvalidParams, "object is required with running"))
				return
			}
			s.SetRunning(b.AssetID, b.Object, *b.Running)
		}
		if b.DiskPercent != nil {
			if *b.DiskPercent < 0 || *b.DiskPercent > 100 {
				httpapi.Fail(w, req, problem.New(problem.InvalidParams, "disk_percent must be 0..100"))
				return
			}
			s.SetDisk(b.AssetID, *b.DiskPercent)
		}
		if b.Fault != "" {
			allowed := []Fault{FaultPostCheckFail, FaultChannelLost, FaultHangConfirm, FaultHangNoConfirm, FaultExitNonZero}
			if !slices.Contains(allowed, Fault(b.Fault)) {
				httpapi.Fail(w, req, problem.New(problem.InvalidParams, "unknown fault"))
				return
			}
			s.InjectFault(b.AssetID, Fault(b.Fault))
		}
		httpapi.WriteJSON(w, 200, map[string]any{"ok": true, "simulator": true})
	})
}
