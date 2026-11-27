package incidents

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/problem"
)

// RCAStarter запускает задачу RCA в оркестраторе (контракт §4, kind "rca").
type RCAStarter interface {
	StartRCA(ctx context.Context, t RCATask) (taskID string, err error)
}

// RCAEventSummary — событие в контексте задачи: только ссылка и шаблонная сводка, без сырых строк журналов.
type RCAEventSummary struct {
	EventID     string `json:"event_id"`
	EvidenceRef string `json:"evidence_ref"` // event:<id> — агенты получают детали через read tools
	Kind        string `json:"kind"`
	Severity    string `json:"severity"`
	AssetID     string `json:"asset_id,omitempty"`
	At          string `json:"at"`
	Summary     string `json:"summary"`
	Fingerprint string `json:"fingerprint"`
}

// RCAContext — контекст инцидента для Commander (поля соответствуют IncidentContext в ai/).
type RCAContext struct {
	IncidentTitle string            `json:"incident_title"`
	Severity      string            `json:"severity"`
	Priority      string            `json:"priority"`
	AlertType     string            `json:"alert_type,omitempty"`
	AssetType     string            `json:"asset_type,omitempty"`
	ServiceKind   string            `json:"service_kind,omitempty"`
	Environment   string            `json:"environment,omitempty"`
	AssetIDs      []string          `json:"asset_ids"`
	Events        []RCAEventSummary `json:"events"`
	Constraints   []string          `json:"constraints"`
}

// RCATask — тело POST /v1/tasks (контракт §4) с дополнительным полем context.
type RCATask struct {
	Kind        string     `json:"kind"`
	TenantID    string     `json:"tenant_id"`
	IncidentID  string     `json:"incident_id"`
	Objective   string     `json:"objective"`
	Scope       RCAScope   `json:"scope"`
	RequestedBy string     `json:"requested_by"`
	Context     RCAContext `json:"context"`
	// requester — заголовки идентичности инициатора (не сериализуются).
	requesterID, requesterKind string
}

// RCAScope — область задачи.
type RCAScope struct {
	AssetIDs []string `json:"asset_ids"`
}

// Requester — идентичность инициатора для заголовков X-AdminTwin-Actor / Actor-Kind.
func (t RCATask) Requester() (id, kind string) { return t.requesterID, t.requesterKind }

// OrchestratorClient — HTTP-реализация RCAStarter: POST {ADMINTWIN_ORCHESTRATOR_URL}/v1/tasks
// с X-AdminTwin-Service-Token и заголовками tenant/пользователя, выставленными ядром.
type OrchestratorClient struct {
	BaseURL      string
	ServiceToken string
	HTTP         *http.Client
}

var _ RCAStarter = (*OrchestratorClient)(nil)

// NewOrchestratorClient проверяет URL (http/https) и токен.
func NewOrchestratorClient(baseURL, token string) (*OrchestratorClient, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("orchestrator url must be http(s)://host[:port]")
	}
	if token == "" {
		return nil, fmt.Errorf("orchestrator service token is required")
	}
	return &OrchestratorClient{BaseURL: strings.TrimRight(baseURL, "/"), ServiceToken: token, HTTP: &http.Client{Timeout: 10 * time.Second}}, nil
}

var taskIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// StartRCA создаёт задачу и возвращает её id.
func (c *OrchestratorClient) StartRCA(ctx context.Context, t RCATask) (string, error) {
	body, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/tasks", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AdminTwin-Service-Token", c.ServiceToken)
	req.Header.Set("X-AdminTwin-Tenant", t.TenantID)
	id, kind := t.Requester()
	if id == "" {
		id, kind = "incident-service", "service"
	}
	req.Header.Set("X-AdminTwin-Actor", id)
	req.Header.Set("X-AdminTwin-Actor-Kind", kind)
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("orchestrator: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if res.StatusCode != http.StatusAccepted && res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("orchestrator: unexpected status %d", res.StatusCode)
	}
	var out struct {
		TaskID string `json:"task_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("orchestrator: invalid response: %w", err)
	}
	if !taskIDRe.MatchString(out.TaskID) {
		return "", fmt.Errorf("orchestrator: invalid task_id in response")
	}
	return out.TaskID, nil
}

// RCAResult — тело POST /api/v1/incidents/{id}/rca от оркестратора.
type RCAResult struct {
	TaskID           string       `json:"task_id"`
	Status           string       `json:"status"`
	Hypotheses       []Hypothesis `json:"hypotheses"`
	Conclusion       string       `json:"conclusion"`
	UncertaintyCheck string       `json:"uncertainty_check"`
	Agents           []string     `json:"agents"`
	CostUSD          float64      `json:"cost_usd"`
	ProposedChanges  []string     `json:"proposed_changes"`
}

var (
	agentIDRe    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)
	refIDRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$`)
	changeIDRe   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	validRCAStat = map[string]bool{RCACompleted: true, RCAUncertain: true, RCAFailed: true, RCARunning: true}
)

func rcaInvalid(field, format string, args ...any) error {
	p := problem.New(problem.InvalidParams, "invalid RCA result")
	p.Errors = []problem.FieldError{{Field: field, Reason: fmt.Sprintf(format, args...)}}
	return p
}

func checkText(field, s string, min, max int) error {
	if len(strings.TrimSpace(s)) < min {
		return rcaInvalid(field, "is required")
	}
	if len(s) > max {
		return rcaInvalid(field, "longer than %d bytes", max)
	}
	return nil
}

func checkEvidence(field string, ev []Evidence) error {
	if len(ev) > 20 {
		return rcaInvalid(field, "too many items (max 20)")
	}
	for i, e := range ev {
		f := fmt.Sprintf("%s[%d]", field, i)
		if err := checkText(f+".fact", e.Fact, 1, 1000); err != nil {
			return err
		}
		if e.EvidenceID != "" && !refIDRe.MatchString(e.EvidenceID) {
			return rcaInvalid(f+".evidence_id", "invalid reference")
		}
	}
	return nil
}

// Validate строго проверяет результат RCA и нормализует пустые списки.
func (r *RCAResult) Validate() error {
	if !taskIDRe.MatchString(r.TaskID) {
		return rcaInvalid("task_id", "invalid task id")
	}
	if !validRCAStat[r.Status] {
		return rcaInvalid("status", "must be running|completed|uncertain|failed")
	}
	if len(r.Hypotheses) > 10 {
		return rcaInvalid("hypotheses", "too many hypotheses (max 10)")
	}
	if r.Status == RCACompleted && len(r.Hypotheses) == 0 {
		return rcaInvalid("hypotheses", "completed RCA requires at least one hypothesis")
	}
	for i := range r.Hypotheses {
		h := &r.Hypotheses[i]
		f := fmt.Sprintf("hypotheses[%d]", i)
		if err := checkText(f+".cause", h.Cause, 1, 500); err != nil {
			return err
		}
		if h.Confidence < 0 || h.Confidence > 1 || h.Confidence != h.Confidence {
			return rcaInvalid(f+".confidence", "must be within 0..1")
		}
		if err := checkEvidence(f+".supporting", h.Supporting); err != nil {
			return err
		}
		if err := checkEvidence(f+".refuting", h.Refuting); err != nil {
			return err
		}
		if len(h.NextChecks) > 20 {
			return rcaInvalid(f+".next_checks", "too many items (max 20)")
		}
		for j, c := range h.NextChecks {
			if err := checkText(fmt.Sprintf("%s.next_checks[%d]", f, j), c, 1, 500); err != nil {
				return err
			}
		}
		if h.Supporting == nil {
			h.Supporting = []Evidence{}
		}
		if h.Refuting == nil {
			h.Refuting = []Evidence{}
		}
		if h.NextChecks == nil {
			h.NextChecks = []string{}
		}
	}
	if err := checkText("conclusion", r.Conclusion, 0, 4000); err != nil {
		return err
	}
	if err := checkText("uncertainty_check", r.UncertaintyCheck, 0, 2000); err != nil {
		return err
	}
	if len(r.Agents) > 10 {
		return rcaInvalid("agents", "too many agents (max 10)")
	}
	for i, a := range r.Agents {
		if !agentIDRe.MatchString(a) {
			return rcaInvalid(fmt.Sprintf("agents[%d]", i), "invalid agent id")
		}
	}
	if r.CostUSD < 0 || r.CostUSD > 10000 || r.CostUSD != r.CostUSD {
		return rcaInvalid("cost_usd", "must be within 0..10000")
	}
	if len(r.ProposedChanges) > 20 {
		return rcaInvalid("proposed_changes", "too many items (max 20)")
	}
	for i, c := range r.ProposedChanges {
		if !changeIDRe.MatchString(c) {
			return rcaInvalid(fmt.Sprintf("proposed_changes[%d]", i), "must be a change id")
		}
	}
	if r.Hypotheses == nil {
		r.Hypotheses = []Hypothesis{}
	}
	if r.Agents == nil {
		r.Agents = []string{}
	}
	if r.ProposedChanges == nil {
		r.ProposedChanges = []string{}
	}
	return nil
}

// alertType — тип алерта для маршрутизации агентов Commander (ai/agents/mvp-agents.yaml).
func alertType(e EventRef) string {
	switch e.Kind {
	case "http_5xx":
		if e.Labels["status"] == "502" {
			return "http_502"
		}
		return "http_5xx"
	case "disk_usage":
		if e.Severity == "critical" {
			return "disk_full"
		}
		return "disk_usage_high"
	case "container_down":
		return "container_stopped"
	case "db_connections":
		return "db_connections_exhausted"
	}
	return e.Kind
}

func priorityFor(sev string) string {
	switch sev {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "normal"
	}
	return "low"
}
