package runbook

import (
	"os"
	"strings"
	"testing"

	"github.com/aitmaganbetov/admintwin/pkg/problem"
)

func loadCatalog(t *testing.T) *Catalog {
	t.Helper()
	c, err := LoadDir("../../../runbooks/catalog")
	if err != nil {
		t.Fatalf("catalog must load: %v", err)
	}
	return c
}

func TestCatalogLoadsMVPRunbooks(t *testing.T) {
	c := loadCatalog(t)
	for _, id := range []string{"docker.container.restart", "linux.service.restart", "linux.logs.rotate_cleanup"} {
		s, ok := c.Get(id)
		if !ok {
			t.Fatalf("missing MVP runbook %s", id)
		}
		if !strings.HasPrefix(s.Digest, "sha256:") {
			t.Errorf("%s: digest not computed", id)
		}
		if !s.HasPreflight("legal_hold_absent") {
			t.Errorf("%s: legal_hold_absent preflight is mandatory", id)
		}
	}
}

const base = `id: test.object.action
version: 1.0.0
risk: low
change_type_default: standard
scope: [{asset_type: linux_host}]
modes_allowed: [operator]
parameters:
  name: {type: string, pattern: "^[a-z]+$"}
preflight:
  - check: asset_verified
  - check: environment_matches_policy
  - check: legal_hold_absent
execute: {engine: ssh_argv, action: x, argv: [echo, "{{name}}"], timeout_s: 10}
post_check: [{check: unit_active}]
rollback: none
compensation: [{action: notify_service_owner}]
side_effects: [none_known]
rate_limit: 1/hour/asset
owner: t
certified_by: [tenant_admin]
tests: [x_test.go]
`

func TestValidRunbookParses(t *testing.T) {
	if _, err := Parse([]byte(base)); err != nil {
		t.Fatalf("base runbook must be valid: %v", err)
	}
}

func TestCertificationRules(t *testing.T) {
	cases := map[string]struct{ old, new, want string }{
		"shell engine forbidden":         {"engine: ssh_argv", "engine: shell", "arbitrary shell is not allowed"},
		"rollback none needs compensate": {"compensation: [{action: notify_service_owner}]\n", "", "rollback=none requires compensation"},
		"side effects required":          {"side_effects: [none_known]\n", "", "requires side_effects"},
		"rollback required":              {"rollback: none\n", "", "rollback is required"},
		"unanchored pattern":             {`"^[a-z]+$"`, `"[a-z]+"`, "must be anchored"},
		"string needs allowlist":         {`{type: string, pattern: "^[a-z]+$"}`, `{type: string}`, "require pattern or enum"},
		"no partial interpolation":       {`"{{name}}"`, `"--name={{name}}"`, "whole argv element"},
		"shell metachar in argv":         {`[echo, "{{name}}"]`, `[echo, "a;rm -rf /", "{{name}}"]`, "shell metacharacters"},
		"legal hold preflight":           {"  - check: legal_hold_absent\n", "", "legal_hold_absent"},
		"tests required":                 {"tests: [x_test.go]", "tests: []", "tests are required"},
		"bad rate limit":                 {"1/hour/asset", "lots", "rate_limit"},
		"standard only for low":          {"risk: low", "risk: medium", "standard is allowed only for risk=low"},
		"autonomous forbidden for high":  {"risk: low\nchange_type_default: standard", "risk: high\nchange_type_default: normal", "backup_or_snapshot_status_known"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			y := strings.Replace(base, tc.old, tc.new, 1)
			if y == base {
				t.Fatalf("test case did not modify the runbook")
			}
			_, err := Parse([]byte(y))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestFrozenVersion(t *testing.T) {
	c := NewCatalog()
	a, _ := Parse([]byte(base))
	if err := c.Add(a); err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte(strings.Replace(base, "owner: t", "owner: someone-else", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Add(b); err == nil || !strings.Contains(err.Error(), "frozen") {
		t.Fatalf("changing a certified version without a bump must fail, got %v", err)
	}
}

func TestParamValidation(t *testing.T) {
	c := loadCatalog(t)
	rb, _ := c.Get("docker.container.restart")
	inv := func(kind, v string) bool { return kind == "container" && v == "3f2a9c1b7d4e" }

	if _, err := rb.ValidateParams(map[string]any{"container_id": "3f2a9c1b7d4e"}, inv); err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}
	bad := []map[string]any{
		{"container_id": "3f2a9c1b7d4e; docker rm -f $(docker ps -q)"}, // command injection
		{"container_id": "../../etc/passwd"},                           // path traversal
		{"container_id": "aaaaaaaaaaaa"},                               // not in tenant inventory
		{"container_id": 42},                                           // wrong type
		{},                                                             // missing
		{"container_id": "3f2a9c1b7d4e", "force": true},                // unknown param
	}
	for i, p := range bad {
		if _, err := rb.ValidateParams(p, inv); !problem.Is(err, problem.InvalidParams) {
			t.Errorf("case %d: want invalid-params, got %v", i, err)
		}
	}

	logs, _ := c.Get("linux.logs.rotate_cleanup")
	all := func(string, string) bool { return true }
	if _, err := logs.ValidateParams(map[string]any{"directory": "/etc"}, all); !problem.Is(err, problem.InvalidParams) {
		t.Errorf("directory outside allowlist must be rejected, got %v", err)
	}
	out, err := logs.ValidateParams(map[string]any{"directory": "/var/log/app"}, all)
	if err != nil {
		t.Fatal(err)
	}
	if out["older_than_days"] != int64(14) || out["dry_run"] != false {
		t.Errorf("defaults not applied: %v", out)
	}
	if _, err := logs.ValidateParams(map[string]any{"directory": "/var/log/app", "older_than_days": 1}, all); err == nil {
		t.Errorf("older_than_days below minimum must be rejected")
	}
}

func TestRenderArgvNoShell(t *testing.T) {
	c := loadCatalog(t)
	rb, _ := c.Get("linux.service.restart")
	argv, err := rb.RenderArgv(map[string]any{"unit": "nginx.service"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(argv, "|") != "systemctl|restart|nginx.service" {
		t.Fatalf("unexpected argv %v", argv)
	}
}

func TestCatalogRejectsInvalidFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/bad.yaml", []byte(strings.Replace(base, "engine: ssh_argv", "engine: bash", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDir(dir); err == nil {
		t.Fatal("catalog with an invalid runbook must fail to load (fail closed)")
	}
}
