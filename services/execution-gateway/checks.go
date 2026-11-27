package gateway

import (
	"fmt"
	"slices"

	"github.com/aitmaganbetov/admintwin/services/execution-gateway/runbook"
)

type runbookCheck = runbook.Check

// check выполняет именованную проверку. Неизвестная проверка — провал (fail closed).
// Возвращает (ok, skipped, detail).
func (g *Gateway) check(req Request, c runbookCheck) (bool, bool, string) {
	a := req.Asset
	t := req.TenantID
	param := func(name string) string { return fmt.Sprint(req.Params[name]) }
	intArg := func(name string, def int) int {
		switch v := c.Args[name].(type) {
		case int:
			return v
		case float64:
			return int(v)
		}
		return def
	}
	need := func() (bool, bool, string) { return false, false, "facts provider unavailable" }

	switch c.Check {
	case "asset_verified":
		return a.Verified, false, boolDetail(a.Verified, "asset is not verified in CMDB")
	case "environment_matches_policy":
		ok := slices.Contains([]string{"production", "staging", "dev", "test"}, a.Environment)
		return ok, false, boolDetail(ok, "asset environment is not classified")
	case "legal_hold_absent":
		return !a.LegalHold, false, boolDetail(!a.LegalHold, "asset is under legal hold")
	case "no_active_investigation":
		return !a.ActiveInvestigation, false, boolDetail(!a.ActiveInvestigation, "active investigation on asset")
	case "maintenance_window_ok":
		return req.InWindow, false, boolDetail(req.InWindow, "outside maintenance window")
	case "backup_or_snapshot_status_known":
		return false, false, "backup status integration is not available yet (P1b)"
	case "container_exists":
		ok := a.HasObject("container", param("container_id"))
		return ok, false, boolDetail(ok, "container not found in inventory")
	case "unit_exists":
		ok := a.HasObject("systemd_unit", param("unit"))
		return ok, false, boolDetail(ok, "unit not found on host")
	case "directory_in_allowlist":
		ok := a.HasObject("log_directory", param("directory")) && slices.Contains(req.Runbook.Parameters["directory"].Enum, param("directory"))
		return ok, false, boolDetail(ok, "directory not in allowlist")
	case "not_in_protected_list":
		for _, p := range []string{"container_id", "unit", "directory"} {
			if v, ok := req.Params[p]; ok && a.IsProtected(fmt.Sprint(v)) {
				return false, false, fmt.Sprintf("%v is in the protected list", v)
			}
		}
		return true, false, ""
	case "restart_count_last_hour_lt":
		if g.Facts == nil {
			return need()
		}
		obj := param("container_id")
		if _, ok := req.Params["unit"]; ok {
			obj = param("unit")
		}
		n, err := g.Facts.RestartsLastHour(t, a.ID, obj)
		if err != nil {
			return false, false, err.Error()
		}
		limit := intArg("limit", 3)
		return n < limit, false, fmt.Sprintf("restarts last hour: %d (limit %d)", n, limit)
	case "container_running":
		if g.Facts == nil {
			return need()
		}
		ok, err := g.Facts.ContainerRunning(t, a.ID, param("container_id"))
		return factResult(ok, err, "container is not running")
	case "unit_active":
		if g.Facts == nil {
			return need()
		}
		ok, err := g.Facts.UnitActive(t, a.ID, param("unit"))
		return factResult(ok, err, "unit is not active")
	case "disk_usage_below":
		if g.Facts == nil {
			return need()
		}
		p, err := g.Facts.DiskUsagePercent(t, a.ID)
		if err != nil {
			return false, false, err.Error()
		}
		limit := float64(intArg("percent", 90))
		return p < limit, false, fmt.Sprintf("disk usage %.1f%% (limit %.0f%%)", p, limit)
	case "log_writers_healthy":
		if g.Facts == nil {
			return need()
		}
		ok, err := g.Facts.LogWritersHealthy(t, a.ID)
		return factResult(ok, err, "log writers unhealthy")
	case "health_endpoint_ok":
		if a.HealthEndpoint == "" {
			if c.IfDefined {
				return true, true, "health endpoint not defined"
			}
			return false, false, "health endpoint not defined"
		}
		if g.Facts == nil {
			return need()
		}
		ok, err := g.Facts.HealthOK(t, a.ID, a.HealthEndpoint)
		return factResult(ok, err, "health endpoint failed")
	}
	return false, false, "unknown check " + c.Check
}

func boolDetail(ok bool, failure string) string {
	if ok {
		return ""
	}
	return failure
}

func factResult(ok bool, err error, failure string) (bool, bool, string) {
	if err != nil {
		return false, false, err.Error()
	}
	return ok, false, boolDetail(ok, failure)
}
