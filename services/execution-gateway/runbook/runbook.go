// Package runbook — спецификация сертифицированной write-операции (ТЗ §11.3), загрузка каталога,
// проверка правил сертификации и валидация параметров.
package runbook

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Risk — уровень риска операции.
type Risk string

const (
	RiskLow      Risk = "low"
	RiskMedium   Risk = "medium"
	RiskHigh     Risk = "high"
	RiskCritical Risk = "critical"
)

// Rank — порядок для сравнения рисков.
func (r Risk) Rank() int {
	switch r {
	case RiskLow:
		return 1
	case RiskMedium:
		return 2
	case RiskHigh:
		return 3
	case RiskCritical:
		return 4
	}
	return 0
}

// Valid — риск из допустимого множества.
func (r Risk) Valid() bool { return r.Rank() > 0 }

// Mode — режим автономности tenant (§11.4).
type Mode string

const (
	ModeObserver   Mode = "observer"
	ModeAdvisor    Mode = "advisor"
	ModeOperator   Mode = "operator"
	ModeAutonomous Mode = "autonomous"
)

// Valid — режим из допустимого множества.
func (m Mode) Valid() bool {
	return slices.Contains([]Mode{ModeObserver, ModeAdvisor, ModeOperator, ModeAutonomous}, m)
}

// Param — параметр runbook (подмножество JSON Schema + allowlist + источник).
type Param struct {
	Type      string   `yaml:"type" json:"type"`
	Pattern   string   `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Enum      []string `yaml:"enum,omitempty" json:"enum,omitempty"`
	MaxLength int      `yaml:"max_length,omitempty" json:"max_length,omitempty"`
	Minimum   *int     `yaml:"minimum,omitempty" json:"minimum,omitempty"`
	Maximum   *int     `yaml:"maximum,omitempty" json:"maximum,omitempty"`
	Required  *bool    `yaml:"required,omitempty" json:"required,omitempty"`
	Default   any      `yaml:"default,omitempty" json:"default,omitempty"`
	// Source = asset_inventory — значение должно существовать в CMDB tenant для целевого актива.
	Source string `yaml:"source,omitempty" json:"source,omitempty"`
	// Kind — тип объекта инвентаря для Source (container, systemd_unit, log_directory).
	Kind string `yaml:"kind,omitempty" json:"kind,omitempty"`

	re *regexp.Regexp
}

// IsRequired — параметр обязателен, если не указано иное.
func (p Param) IsRequired() bool { return p.Required == nil || *p.Required }

// Check — шаг preflight/post_check.
type Check struct {
	Check string         `yaml:"check" json:"check"`
	Args  map[string]any `yaml:"args,omitempty" json:"args,omitempty"`
	// IfDefined — шаг пропускается, если для актива нет нужных данных (например, health endpoint).
	IfDefined bool `yaml:"if_defined,omitempty" json:"if_defined,omitempty"`
}

// Execute — способ исполнения. Произвольный shell запрещён (§11.6).
type Execute struct {
	Engine   string   `yaml:"engine" json:"engine"`
	Action   string   `yaml:"action" json:"action"`
	Argv     []string `yaml:"argv,omitempty" json:"argv,omitempty"`
	TimeoutS int      `yaml:"timeout_s" json:"timeout_s"`
	DryRun   bool     `yaml:"supports_dry_run,omitempty" json:"supports_dry_run,omitempty"`
}

// Action — шаг компенсации.
type Action struct {
	Action string `yaml:"action" json:"action"`
	When   string `yaml:"when,omitempty" json:"when,omitempty"`
	// Propose — runbook, который предлагается новым ChangeRequest (не исполняется напрямую).
	Propose string `yaml:"propose,omitempty" json:"propose,omitempty"`
}

// ScopeEntry — ограничение по типу актива.
type ScopeEntry struct {
	AssetType string `yaml:"asset_type" json:"asset_type"`
}

// Spec — runbook из каталога.
type Spec struct {
	ID                string           `yaml:"id" json:"id"`
	Version           string           `yaml:"version" json:"version"`
	Title             string           `yaml:"title" json:"title"`
	Risk              Risk             `yaml:"risk" json:"risk"`
	ChangeTypeDefault string           `yaml:"change_type_default" json:"change_type_default"`
	Scope             []ScopeEntry     `yaml:"scope" json:"scope"`
	ModesAllowed      []Mode           `yaml:"modes_allowed" json:"modes_allowed"`
	Parameters        map[string]Param `yaml:"parameters" json:"parameters"`
	Preflight         []Check          `yaml:"preflight" json:"preflight"`
	Execute           Execute          `yaml:"execute" json:"execute"`
	PostCheck         []Check          `yaml:"post_check" json:"post_check"`
	Rollback          string           `yaml:"rollback" json:"rollback"`
	Compensation      []Action         `yaml:"compensation" json:"compensation"`
	SideEffects       []string         `yaml:"side_effects" json:"side_effects"`
	RateLimit         string           `yaml:"rate_limit" json:"rate_limit"`
	Owner             string           `yaml:"owner" json:"owner"`
	CertifiedBy       []string         `yaml:"certified_by" json:"certified_by"`
	Tests             []string         `yaml:"tests" json:"tests"`

	Digest string    `yaml:"-" json:"digest"`
	Rate   RateLimit `yaml:"-" json:"-"`
}

// RateLimit — разобранное ограничение вида "5/hour/asset".
type RateLimit struct {
	Count  int
	Window string // minute | hour | day
	Per    string // asset | tenant
}

// AssetTypes — допустимые типы актива.
func (s *Spec) AssetTypes() []string {
	out := make([]string, 0, len(s.Scope))
	for _, e := range s.Scope {
		out = append(out, e.AssetType)
	}
	return out
}

// AllowsMode — допускает ли runbook автоматическое исполнение в режиме.
func (s *Spec) AllowsMode(m Mode) bool { return slices.Contains(s.ModesAllowed, m) }

// HasPreflight — есть ли проверка с данным именем.
func (s *Spec) HasPreflight(name string) bool {
	for _, c := range s.Preflight {
		if c.Check == name {
			return true
		}
	}
	return false
}

// Reversible — есть ли rollback-runbook.
func (s *Spec) Reversible() bool { return s.Rollback != "" && s.Rollback != "none" }

var (
	idRe        = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+){2,}$`)
	semverRe    = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	rateRe      = regexp.MustCompile(`^(\d+)/(minute|hour|day)/(asset|tenant)$`)
	placeholder = regexp.MustCompile(`\{\{\s*([a-z_][a-z0-9_]*)\s*\}\}`)

	// Запрещённые движки исполнения: произвольный shell недопустим (§11.2 п.7, §11.6).
	forbiddenEngines = []string{"shell", "bash", "sh", "powershell_raw", "cmd", "eval"}
	knownEngines     = []string{"docker_api", "ssh_argv", "builtin"}

	// Общие preflight-проверки (Приложение C.0).
	mandatoryPreflight = []string{"legal_hold_absent", "asset_verified", "environment_matches_policy"}
)

// Validate применяет правила сертификации §11.3 и C.0. Возвращает все нарушения.
func (s *Spec) Validate() error {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }

	if !idRe.MatchString(s.ID) {
		add("id %q must look like domain.object.action", s.ID)
	}
	if !semverRe.MatchString(s.Version) {
		add("version %q must be semver", s.Version)
	}
	if !s.Risk.Valid() {
		add("risk is required (low|medium|high|critical)")
	}
	switch s.ChangeTypeDefault {
	case "standard":
		if s.Risk != RiskLow {
			add("change_type_default=standard is allowed only for risk=low")
		}
	case "normal":
	default:
		add("change_type_default must be standard|normal")
	}
	if len(s.Scope) == 0 {
		add("scope must list at least one asset_type")
	}
	for _, m := range s.ModesAllowed {
		if !m.Valid() {
			add("modes_allowed: unknown mode %q", m)
		}
		if m == ModeAutonomous && s.Risk.Rank() >= RiskHigh.Rank() {
			add("modes_allowed: autonomous is forbidden for risk %s (§11.4)", s.Risk)
		}
	}
	if s.Rollback == "" {
		add("rollback is required: a runbook id or 'none'")
	}
	if s.Rollback == "none" {
		if len(s.Compensation) == 0 {
			add("rollback=none requires compensation")
		}
		if len(s.SideEffects) == 0 {
			add("rollback=none requires side_effects")
		}
	}
	if rl, err := ParseRateLimit(s.RateLimit); err != nil {
		add("rate_limit: %v", err)
	} else {
		s.Rate = rl
	}
	if s.Owner == "" {
		add("owner is required")
	}
	if len(s.CertifiedBy) == 0 {
		add("certified_by is required")
	}
	if len(s.Tests) == 0 {
		add("tests are required (runbook is added only via PR with a sandbox test)")
	}
	for _, name := range mandatoryPreflight {
		if !s.HasPreflight(name) {
			add("preflight must include %s (Appendix C.0)", name)
		}
	}
	if s.Risk.Rank() >= RiskMedium.Rank() && !s.HasPreflight("maintenance_window_ok") {
		add("preflight must include maintenance_window_ok for risk >= medium (Appendix C.0)")
	}
	if s.Risk.Rank() >= RiskHigh.Rank() && !s.HasPreflight("backup_or_snapshot_status_known") {
		add("preflight must include backup_or_snapshot_status_known for risk >= high (Appendix C.0)")
	}
	if len(s.PostCheck) == 0 {
		add("post_check must not be empty")
	}

	// Исполнение.
	eng := strings.ToLower(s.Execute.Engine)
	if slices.Contains(forbiddenEngines, eng) {
		add("execute.engine %q is forbidden: arbitrary shell is not allowed", s.Execute.Engine)
	} else if !slices.Contains(knownEngines, eng) {
		add("execute.engine %q is unknown (allowed: %s)", s.Execute.Engine, strings.Join(knownEngines, ", "))
	}
	if s.Execute.Action == "" {
		add("execute.action is required")
	}
	if s.Execute.TimeoutS <= 0 || s.Execute.TimeoutS > 3600 {
		add("execute.timeout_s must be in 1..3600")
	}
	if eng == "ssh_argv" {
		if len(s.Execute.Argv) == 0 {
			add("execute.argv is required for ssh_argv")
		}
		for i, a := range s.Execute.Argv {
			if m := placeholder.FindAllStringSubmatchIndex(a, -1); len(m) > 0 {
				// Подстановка допускается только целым элементом argv — без строковой интерполяции.
				if len(m) != 1 || m[0][0] != 0 || m[0][1] != len(a) {
					add("execute.argv[%d] %q: placeholders must occupy the whole argv element", i, a)
				}
				name := a[m[0][2]:m[0][3]]
				if _, ok := s.Parameters[name]; !ok {
					add("execute.argv[%d] references unknown parameter %q", i, name)
				}
			}
			if strings.ContainsAny(a, "|;&$`<>\n") && !placeholder.MatchString(a) {
				add("execute.argv[%d] %q contains shell metacharacters", i, a)
			}
		}
	}

	// Параметры.
	names := make([]string, 0, len(s.Parameters))
	for n := range s.Parameters {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := s.Parameters[n]
		switch p.Type {
		case "string":
			if p.Pattern == "" && len(p.Enum) == 0 {
				add("parameters.%s: string parameters require pattern or enum (allowlist)", n)
			}
			if p.Pattern != "" {
				if !strings.HasPrefix(p.Pattern, "^") || !strings.HasSuffix(p.Pattern, "$") {
					add("parameters.%s: pattern must be anchored with ^...$", n)
				}
				re, err := regexp.Compile(p.Pattern)
				if err != nil {
					add("parameters.%s: invalid pattern: %v", n, err)
				}
				p.re = re
			}
		case "integer":
			if p.Minimum == nil || p.Maximum == nil {
				add("parameters.%s: integer parameters require minimum and maximum", n)
			}
		case "boolean":
		default:
			add("parameters.%s: unsupported type %q (string|integer|boolean)", n, p.Type)
		}
		if p.Source != "" && p.Source != "asset_inventory" {
			add("parameters.%s: unknown source %q", n, p.Source)
		}
		if p.Source == "asset_inventory" && p.Kind == "" {
			add("parameters.%s: source=asset_inventory requires kind", n)
		}
		s.Parameters[n] = p
	}

	if len(errs) > 0 {
		return &ValidationError{RunbookID: s.ID, Problems: errs}
	}
	return nil
}

// ValidationError — список нарушений правил сертификации.
type ValidationError struct {
	RunbookID string
	Problems  []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("runbook %s: %s", e.RunbookID, strings.Join(e.Problems, "; "))
}

// ParseRateLimit разбирает строку вида "5/hour/asset".
func ParseRateLimit(s string) (RateLimit, error) {
	m := rateRe.FindStringSubmatch(s)
	if m == nil {
		return RateLimit{}, fmt.Errorf("%q must look like N/(minute|hour|day)/(asset|tenant)", s)
	}
	n, _ := strconv.Atoi(m[1])
	if n <= 0 {
		return RateLimit{}, fmt.Errorf("%q: count must be positive", s)
	}
	return RateLimit{Count: n, Window: m[2], Per: m[3]}, nil
}

// Parse разбирает и валидирует runbook из YAML.
func Parse(data []byte) (*Spec, error) {
	var s Spec
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parse runbook: %w", err)
	}
	if s.Parameters == nil {
		s.Parameters = map[string]Param{}
	}
	sum := sha256.Sum256(data)
	s.Digest = "sha256:" + hex.EncodeToString(sum[:])
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Catalog — каталог сертифицированных runbook. Версия заморожена после сертификации:
// повторная регистрация id@version с другим содержимым отклоняется.
type Catalog struct {
	byID map[string]*Spec
	ver  map[string]string // id@version -> digest
}

// NewCatalog создаёт пустой каталог.
func NewCatalog() *Catalog {
	return &Catalog{byID: map[string]*Spec{}, ver: map[string]string{}}
}

// Add регистрирует runbook.
func (c *Catalog) Add(s *Spec) error {
	key := s.ID + "@" + s.Version
	if d, ok := c.ver[key]; ok && d != s.Digest {
		return fmt.Errorf("runbook %s is frozen: content changed without a version bump", key)
	}
	c.ver[key] = s.Digest
	if cur, ok := c.byID[s.ID]; !ok || versionLess(cur.Version, s.Version) {
		c.byID[s.ID] = s
	}
	return nil
}

// Get возвращает актуальную версию runbook.
func (c *Catalog) Get(id string) (*Spec, bool) {
	s, ok := c.byID[id]
	return s, ok
}

// List — все runbook, отсортированные по id.
func (c *Catalog) List() []*Spec {
	out := make([]*Spec, 0, len(c.byID))
	for _, s := range c.byID {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// LoadDir загружает все *.yaml из каталога. Любая ошибка — отказ загрузки (fail closed).
func LoadDir(dir string) (*Catalog, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	c := NewCatalog()
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		s, err := Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		if err := c.Add(s); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
	}
	return c, nil
}

func versionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3 && i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return false
}
