// Package registry — Capability & Standards Registry (M25, §3.2, Приложения A и B).
// Единая модель реестров: Capability → Operation → Tool | Runbook; Standard → Capability.
// Матрицы трассируемости генерируются из данных, а не ведутся вручную (§23 п.12).
package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Level — уровень операции capability.
type Level string

const (
	Observe   Level = "observe"
	Diagnose  Level = "diagnose"
	Recommend Level = "recommend"
	Propose   Level = "propose"
	Execute   Level = "execute"
	Verify    Level = "verify"
	Rollback  Level = "rollback"
)

var levelRank = map[Level]int{Observe: 1, Diagnose: 2, Recommend: 3, Propose: 4, Execute: 5, Verify: 6, Rollback: 7}

// Rank — порядок уровня; 0 — неизвестный.
func (l Level) Rank() int { return levelRank[l] }

// AgentAllowed — уровни, которыми может владеть AI Agent (≤ propose). approve — не operation.
func (l Level) AgentAllowed() bool { return l.Rank() > 0 && l.Rank() <= Propose.Rank() }

// Operation — операция capability.
type Operation struct {
	Level       Level  `yaml:"level" json:"level"`
	Tool        string `yaml:"tool,omitempty" json:"tool,omitempty"`
	Runbook     string `yaml:"runbook,omitempty" json:"runbook,omitempty"`
	RunbookStep string `yaml:"runbook_step,omitempty" json:"runbook_step,omitempty"`
}

// Capability — запись каталога (B.1).
type Capability struct {
	ID               string      `yaml:"capability_id" json:"capability_id"`
	Version          string      `yaml:"version" json:"version"`
	Domain           string      `yaml:"domain" json:"domain"`
	Name             string      `yaml:"name" json:"name"`
	Tier             string      `yaml:"tier" json:"tier"`
	Mode             string      `yaml:"mode" json:"mode"`
	OwnerAgent       string      `yaml:"owner_agent" json:"owner_agent"`
	SupportingAgents []string    `yaml:"supporting_agents" json:"supporting_agents"`
	Standards        []string    `yaml:"standards" json:"standards"`
	Operations       []Operation `yaml:"operations" json:"operations"`
	AssetTypes       []string    `yaml:"asset_types" json:"asset_types"`
	Preconditions    []string    `yaml:"preconditions" json:"preconditions"`
	Risk             string      `yaml:"risk" json:"risk"`
	AutonomyCeiling  string      `yaml:"autonomy_ceiling" json:"autonomy_ceiling"`
	ApprovalPolicy   string      `yaml:"approval_policy" json:"approval_policy"`
	EvidenceSchema   []string    `yaml:"evidence_schema" json:"evidence_schema"`
	Tests            []string    `yaml:"tests" json:"tests"`
	LifecycleState   string      `yaml:"lifecycle_state" json:"lifecycle_state"`
}

// AgentOperations — операции, доступные агентам (≤ propose).
func (c Capability) AgentOperations() []Operation {
	var out []Operation
	for _, o := range c.Operations {
		if o.Level.AgentAllowed() {
			out = append(out, o)
		}
	}
	return out
}

// Standard — запись Приложения A.
type Standard struct {
	ID                    string   `yaml:"standard_id" json:"standard_id"`
	Title                 string   `yaml:"title" json:"title"`
	Edition               string   `yaml:"edition" json:"edition"`
	Area                  string   `yaml:"area" json:"area"`
	RequiredEvidence      string   `yaml:"required_evidence" json:"required_evidence"`
	Modules               []string `yaml:"modules" json:"modules"`
	ModuleRefsRaw         string   `yaml:"module_refs_raw" json:"module_refs_raw"`
	Applicability         []string `yaml:"applicability" json:"applicability"`
	Jurisdictions         []string `yaml:"jurisdictions" json:"jurisdictions"`
	Owner                 string   `yaml:"owner" json:"owner"`
	ReviewedAt            *string  `yaml:"reviewed_at" json:"reviewed_at"`
	NextReviewAt          *string  `yaml:"next_review_at" json:"next_review_at"`
	ControlMappingVersion string   `yaml:"control_mapping_version" json:"control_mapping_version"`
}

type standardsFile struct {
	RegistryVersion string     `yaml:"registry_version"`
	AsOf            string     `yaml:"as_of"`
	Standards       []Standard `yaml:"standards"`
}

// Artifacts — проверка существования tools и runbooks (для production_ready и B.8).
type Artifacts struct {
	Tools    func(name string) bool
	Runbooks func(id string) bool
}

// Registry — загруженные реестры.
type Registry struct {
	Capabilities map[string]Capability
	Standards    map[string]Standard
}

var (
	capIDRe   = regexp.MustCompile(`^[A-Z]{2,4}-\d{3}$`)
	tiers     = []string{"MVP", "P1a", "P1b", "P2"}
	modes     = []string{"build", "integration_only"}
	lifecycle = []string{"draft", "in_development", "tested", "production_ready", "deprecated"}
	risks     = []string{"low", "medium", "high", "critical"}
	ceilings  = []string{"observer", "advisor", "operator", "autonomous"}
)

// Load читает standards/registry.yaml и capabilities/*.yaml и проверяет согласованность.
func Load(standardsPath, capabilitiesDir string, art Artifacts) (*Registry, error) {
	r := &Registry{Capabilities: map[string]Capability{}, Standards: map[string]Standard{}}
	data, err := os.ReadFile(standardsPath)
	if err != nil {
		return nil, err
	}
	var sf standardsFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("standards: %w", err)
	}
	for _, s := range sf.Standards {
		if _, dup := r.Standards[s.ID]; dup {
			return nil, fmt.Errorf("standards: duplicate %s", s.ID)
		}
		r.Standards[s.ID] = s
	}
	files, err := filepath.Glob(filepath.Join(capabilitiesDir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	var errs []string
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var c Capability
		dec := yaml.NewDecoder(strings.NewReader(string(raw)))
		dec.KnownFields(true)
		if err := dec.Decode(&c); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", filepath.Base(f), err))
			continue
		}
		if _, dup := r.Capabilities[c.ID]; dup {
			errs = append(errs, fmt.Sprintf("%s: duplicate capability %s", filepath.Base(f), c.ID))
			continue
		}
		if problems := r.validate(c, art); len(problems) > 0 {
			errs = append(errs, fmt.Sprintf("%s: %s", c.ID, strings.Join(problems, "; ")))
			continue
		}
		r.Capabilities[c.ID] = c
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("capability registry invalid:\n  %s", strings.Join(errs, "\n  "))
	}
	return r, nil
}

func (r *Registry) validate(c Capability, art Artifacts) []string {
	var p []string
	add := func(f string, a ...any) { p = append(p, fmt.Sprintf(f, a...)) }
	if !capIDRe.MatchString(c.ID) {
		add("capability_id must look like ABC-001")
	}
	if !slices.Contains(tiers, c.Tier) {
		add("tier must be one of %v", tiers)
	}
	if !slices.Contains(modes, c.Mode) {
		add("mode must be build|integration_only")
	}
	if !slices.Contains(lifecycle, c.LifecycleState) {
		add("lifecycle_state must be one of %v", lifecycle)
	}
	if !slices.Contains(risks, c.Risk) {
		add("risk must be one of %v", risks)
	}
	if !slices.Contains(ceilings, c.AutonomyCeiling) {
		add("autonomy_ceiling must be one of %v", ceilings)
	}
	if c.OwnerAgent == "" {
		add("owner_agent is required")
	}
	if len(c.Operations) == 0 {
		add("operations must not be empty")
	}
	for _, s := range c.Standards {
		if _, ok := r.Standards[s]; !ok {
			add("unknown standard %s", s)
		}
	}
	strict := c.LifecycleState == "tested" || c.LifecycleState == "production_ready"
	for i, o := range c.Operations {
		switch {
		case o.Level.Rank() == 0:
			add("operations[%d]: unknown level %q (approve is a human action, not an operation)", i, o.Level)
		case o.Level.Rank() <= Recommend.Rank():
			if o.Tool == "" || o.Runbook != "" {
				add("operations[%d]: level %s must be implemented by a read tool", i, o.Level)
			}
		case o.Level == Propose:
			if o.Tool != "change.propose" {
				add("operations[%d]: propose must use change.propose (creates ChangeRequest)", i)
			}
		case o.Level == Verify:
			if o.RunbookStep == "" && o.Runbook == "" {
				add("operations[%d]: verify must reference a runbook step", i)
			}
		default: // execute, rollback
			if o.Runbook == "" || o.Tool != "" {
				add("operations[%d]: level %s must be implemented by a runbook via Gateway, never by a tool", i, o.Level)
			}
			if c.Mode == "integration_only" {
				add("operations[%d]: integration_only capabilities cannot execute runbooks themselves", i)
			}
		}
		if strict && art.Tools != nil && o.Tool != "" && !art.Tools(o.Tool) {
			add("operations[%d]: tool %s has no JSON Schema in ai/tools/ (blocks %s)", i, o.Tool, c.LifecycleState)
		}
		if strict && art.Runbooks != nil && o.Runbook != "" && !art.Runbooks(o.Runbook) {
			add("operations[%d]: runbook %s is not in runbooks/catalog (blocks %s)", i, o.Runbook, c.LifecycleState)
		}
		if c.Tier == "MVP" && art.Runbooks != nil && o.Runbook != "" && !art.Runbooks(o.Runbook) {
			add("operations[%d]: MVP capability references missing runbook %s", i, o.Runbook)
		}
	}
	if c.LifecycleState == "production_ready" && len(c.Tests) == 0 {
		add("production_ready requires tests (Definition of Done)")
	}
	return p
}

// AgentCanUse — может ли агент использовать capability (owner или supporting).
func (c Capability) AgentCanUse(agent string) bool {
	return c.OwnerAgent == agent || slices.Contains(c.SupportingAgents, agent)
}

// ToolScope — tools, разрешённые агенту через его capabilities. Пустой результат означает,
// что у агента нет подтверждённого tool scope (T-CAP-001).
func (r *Registry) ToolScope(agent string) []string {
	set := map[string]bool{}
	for _, c := range r.Capabilities {
		if !c.AgentCanUse(agent) {
			continue
		}
		for _, o := range c.AgentOperations() {
			if o.Tool != "" {
				set[o.Tool] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// TraceRow — строка матрицы трассируемости (B.8), генерируется из реестров.
type TraceRow struct {
	Standard   string `json:"standard"`
	Capability string `json:"capability"`
	Tier       string `json:"tier"`
	Agent      string `json:"agent"`
	Artifact   string `json:"artifact"`
	Kind       string `json:"kind"` // tool | runbook
	Tests      string `json:"tests"`
}

// Traceability строит матрицу стандарт × capability × артефакт.
func (r *Registry) Traceability() []TraceRow {
	var out []TraceRow
	for _, c := range r.SortedCapabilities() {
		for _, s := range c.Standards {
			for _, o := range c.Operations {
				row := TraceRow{Standard: s, Capability: c.ID, Tier: c.Tier, Agent: c.OwnerAgent, Tests: strings.Join(c.Tests, ",")}
				switch {
				case o.Tool != "":
					row.Artifact, row.Kind = o.Tool, "tool"
				case o.Runbook != "":
					row.Artifact, row.Kind = o.Runbook, "runbook"
				default:
					continue
				}
				out = append(out, row)
			}
		}
	}
	return out
}

// SortedCapabilities — capabilities по id.
func (r *Registry) SortedCapabilities() []Capability {
	out := make([]Capability, 0, len(r.Capabilities))
	for _, c := range r.Capabilities {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SortedStandards — стандарты по id.
func (r *Registry) SortedStandards() []Standard {
	out := make([]Standard, 0, len(r.Standards))
	for _, s := range r.Standards {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
