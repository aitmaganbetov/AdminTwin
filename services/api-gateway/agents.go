package api

import (
	"fmt"
	"net/http"
	"os"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/aitmaganbetov/admintwin/pkg/httpapi"
	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
)

// AgentDef — запись реестра агентов (M02, §5.2) из ai/agents/*.yaml: тот же источник, что у оркестратора.
type AgentDef struct {
	ID                   string   `yaml:"id" json:"id"`
	Name                 string   `yaml:"name" json:"name"`
	Version              string   `yaml:"version" json:"version"`
	PromptVersion        string   `yaml:"prompt_version" json:"prompt_version"`
	Status               string   `yaml:"status" json:"status"`
	ModelProfile         string   `yaml:"model_profile" json:"model_profile"`
	FallbackModelProfile string   `yaml:"fallback_model_profile" json:"fallback_model_profile,omitempty"`
	AllowedCapabilities  []string `yaml:"allowed_capabilities" json:"allowed_capabilities"`
	AllowedTools         []string `yaml:"allowed_tools" json:"allowed_tools"`
	AllowedRunbooks      []string `yaml:"allowed_runbooks" json:"allowed_runbooks"`
	DataSensitivityMax   string   `yaml:"data_sensitivity_max" json:"data_sensitivity_max"`
	PolicyID             string   `yaml:"policy_id" json:"policy_id,omitempty"`
	Budget               any      `yaml:"budget" json:"budget,omitempty"`
}

// AgentRegistry — GET /api/v1/agents (§13): реестр агентов, их capabilities, tools и model profile.
type AgentRegistry struct{ Agents []AgentDef }

// LoadAgentRegistry читает реестр агентов.
func LoadAgentRegistry(path string) (*AgentRegistry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Agents []AgentDef `yaml:"agents"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("agents: %w", err)
	}
	for _, a := range doc.Agents {
		if a.ID == "" || slices.Contains(a.AllowedTools, "change.approve") {
			return nil, fmt.Errorf("agents: invalid definition %q", a.ID)
		}
	}
	return &AgentRegistry{Agents: doc.Agents}, nil
}

// Routes реализует httpapi.Module.
func (r *AgentRegistry) Routes(rt *httpapi.Router) {
	rt.Handle("GET /api/v1/agents", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		if a.Kind != identity.KindUser {
			httpapi.Fail(w, req, problem.New(problem.Forbidden, "agent registry is for people"))
			return
		}
		httpapi.WriteJSON(w, 200, map[string]any{"items": r.Agents})
	})
}
