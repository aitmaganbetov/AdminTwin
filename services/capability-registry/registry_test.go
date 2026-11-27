package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const root = "../.."

func noArtifacts() Artifacts {
	known := map[string]bool{"docker.container.restart": true, "linux.service.restart": true, "linux.logs.rotate_cleanup": true}
	return Artifacts{Runbooks: func(id string) bool { return known[id] }}
}

func TestRealRegistryLoads(t *testing.T) {
	r, err := Load(filepath.Join(root, "standards/registry.yaml"), filepath.Join(root, "capabilities"), noArtifacts())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Standards) != 28 {
		t.Fatalf("Appendix A lists 28 standards, got %d", len(r.Standards))
	}
	for _, c := range r.Capabilities {
		for _, o := range c.AgentOperations() {
			if o.Level.Rank() > Propose.Rank() {
				t.Fatalf("%s: agent operation above propose", c.ID)
			}
		}
	}
	if len(r.Traceability()) == 0 {
		t.Fatal("traceability matrix must be generated from registries")
	}
}

// T-CAP-001: агент без подтверждённого tool scope не получает инструментов.
func TestToolScope(t *testing.T) {
	r, err := Load(filepath.Join(root, "standards/registry.yaml"), filepath.Join(root, "capabilities"), noArtifacts())
	if err != nil {
		t.Fatal(err)
	}
	if s := r.ToolScope("unknown-agent"); len(s) != 0 {
		t.Fatalf("unknown agent must have empty tool scope, got %v", s)
	}
	scope := strings.Join(r.ToolScope("devops-engineer"), ",")
	if !strings.Contains(scope, "docker.container.inspect") || !strings.Contains(scope, "change.propose") {
		t.Fatalf("devops scope incomplete: %s", scope)
	}
	for _, tool := range r.ToolScope("devops-engineer") {
		if strings.Contains(tool, "restart") {
			t.Fatalf("runbooks must never appear as agent tools: %s", tool)
		}
	}
}

func writeCap(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "X.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

const capBase = `capability_id: TST-001
version: 1.0.0
domain: test
name: test
tier: MVP
mode: build
owner_agent: linux-admin
supporting_agents: []
standards: [STD-01]
operations:
  - {level: observe, tool: metrics.query}
asset_types: [linux_host]
preconditions: []
risk: low
autonomy_ceiling: observer
approval_policy: none
evidence_schema: []
tests: []
lifecycle_state: draft
`

func TestRegistryRules(t *testing.T) {
	cases := map[string]struct{ old, new, want string }{
		"execute via tool":       {"{level: observe, tool: metrics.query}", "{level: execute, tool: docker.restart}", "never by a tool"},
		"approve is not an op":   {"{level: observe, tool: metrics.query}", "{level: approve, tool: x}", "approve is a human action"},
		"propose must be change": {"{level: observe, tool: metrics.query}", "{level: propose, tool: shell.run}", "change.propose"},
		"unknown standard":       {"[STD-01]", "[STD-99]", "unknown standard"},
		"integration only exec":  {"mode: build\n", "mode: integration_only\n", ""},
		"prod ready needs tests": {"lifecycle_state: draft", "lifecycle_state: production_ready", "requires tests"},
		"missing runbook in MVP": {"{level: observe, tool: metrics.query}", "{level: execute, runbook: nope.not.here}", "missing runbook"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(capBase, tc.old, tc.new, 1)
			if name == "integration only exec" {
				body = strings.Replace(body, "{level: observe, tool: metrics.query}", "{level: execute, runbook: docker.container.restart}", 1)
				tc.want = "integration_only capabilities cannot execute"
			}
			_, err := Load(filepath.Join(root, "standards/registry.yaml"), writeCap(t, body), noArtifacts())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

// B.8: каждый tool, на который ссылается capability тира MVP, обязан иметь JSON Schema в ai/tools/{read|propose}/.
func TestMVPToolsHaveSchemas(t *testing.T) {
	r, err := Load(filepath.Join(root, "standards/registry.yaml"), filepath.Join(root, "capabilities"), noArtifacts())
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.SortedCapabilities() {
		if c.Tier != "MVP" {
			continue
		}
		for _, o := range c.Operations {
			if o.Tool == "" {
				continue
			}
			found := false
			for _, kind := range []string{"read", "propose"} {
				if _, err := os.Stat(filepath.Join(root, "ai", "tools", kind, o.Tool+".json")); err == nil {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: tool %s has no JSON Schema in ai/tools", c.ID, o.Tool)
			}
		}
	}
}
