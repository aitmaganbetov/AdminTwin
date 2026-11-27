package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/audit"
	change "github.com/aitmaganbetov/admintwin/services/change-coordinator"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/runbook"
	"github.com/aitmaganbetov/admintwin/services/policy"
)

// getTenantPolicy — режим автономности и политика tenant (чтение: TA, ITM, Compliance Manager, Auditor).
func (s *Server) getTenantPolicy(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	if a.IsAI() || !a.HasAny(identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleComplianceManager, identity.RoleAuditor, identity.RoleEngineer, identity.RoleOperator) {
		s.fail(w, r, problem.New(problem.Forbidden, "insufficient role"))
		return
	}
	tp, ok := s.Tenants(a.TenantID)
	if !ok {
		s.fail(w, r, problem.New(problem.NotFound, "tenant policy not found"))
		return
	}
	writeJSON(w, 200, tp)
}

type tenantPolicyBody struct {
	Mode                        runbook.Mode        `json:"mode"`
	AutonomousMediumRunbooks    []string            `json:"autonomous_medium_runbooks"`
	DeniedRunbooksByEnvironment map[string][]string `json:"denied_runbooks_by_environment"`
	MaintenanceWindows          []policy.Window     `json:"maintenance_windows"`
}

// putTenantPolicy — изменить политику / режим автономности: только Tenant Admin, с MFA (§2.2).
func (s *Server) putTenantPolicy(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	if a.IsAI() || a.Kind != identity.KindUser || !a.Has(identity.RoleTenantAdmin) {
		s.fail(w, r, problem.New(problem.Forbidden, "only Tenant Admin can change policy or autonomy mode"))
		return
	}
	if err := requireMFA(a); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.SaveTenant == nil {
		s.fail(w, r, problem.New(problem.NotFound, "policy management is not available"))
		return
	}
	var b tenantPolicyBody
	if err := decode(r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	if !b.Mode.Valid() {
		s.fail(w, r, problem.New(problem.InvalidParams, "mode must be observer|advisor|operator|autonomous"))
		return
	}
	for _, id := range b.AutonomousMediumRunbooks {
		rb, ok := s.Catalog.Get(id)
		if !ok || rb.Risk != runbook.RiskMedium || !rb.AllowsMode(runbook.ModeAutonomous) {
			s.fail(w, r, problem.New(problem.InvalidParams, "runbook %q is not a medium-risk runbook allowed in autonomous mode", id))
			return
		}
	}
	for _, win := range b.MaintenanceWindows {
		if !win.End.After(win.Start) || win.End.Sub(win.Start) > 7*24*time.Hour {
			s.fail(w, r, problem.New(problem.InvalidParams, "maintenance window must end after it starts and last at most 7 days"))
			return
		}
	}
	old, _ := s.Tenants(a.TenantID)
	tp := policy.TenantPolicy{ID: old.ID, TenantID: a.TenantID, Mode: b.Mode, AutonomousMediumRunbooks: b.AutonomousMediumRunbooks,
		DeniedRunbooksByEnvironment: b.DeniedRunbooksByEnvironment, MaintenanceWindows: b.MaintenanceWindows}
	if tp.ID == "" {
		tp.ID = a.TenantID
	}
	if err := s.SaveTenant(tp); err != nil {
		s.fail(w, r, err)
		return
	}
	_, _ = s.Audit.Append(audit.Record{TenantID: a.TenantID, Actor: a.Ref(), Action: "tenant.policy_changed", ObjectType: "tenant_policy", ObjectID: tp.ID,
		Data: map[string]any{"mode_before": old.Mode, "mode_after": tp.Mode, "autonomous_medium_runbooks": tp.AutonomousMediumRunbooks,
			"maintenance_windows": len(tp.MaintenanceWindows)}})
	writeJSON(w, 200, tp)
}

type pirBody struct {
	Summary           string   `json:"summary"`
	Findings          string   `json:"findings"`
	CorrectiveActions []string `json:"corrective_actions"`
}

// recordPIR — post-implementation review (§11.2 п.10; break-glass — в течение 72 ч, §11.5).
func (s *Server) recordPIR(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	if a.IsAI() || a.Kind != identity.KindUser || !a.HasAny(identity.RoleTenantAdmin, identity.RoleITManager) {
		s.fail(w, r, problem.New(problem.Forbidden, "PIR is recorded by IT Manager or Tenant Admin"))
		return
	}
	var b pirBody
	if err := decode(r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(b.Summary) < 10 {
		s.fail(w, r, problem.New(problem.InvalidParams, "summary is required"))
		return
	}
	cr, err := s.Changes.RecordPIR(a, r.PathValue("id"), change.PIR{Summary: b.Summary, Findings: b.Findings, CorrectiveActions: b.CorrectiveActions})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, changeView(cr))
}

// aiCallRecord — запись о вызове LLM или инструмента агентом (метаданные; сырые промпты не принимаются).
type aiCallRecord struct {
	RecordType     string   `json:"record_type"`
	CallID         string   `json:"call_id"`
	At             string   `json:"at"`
	TenantID       string   `json:"tenant_id"`
	TaskID         *string  `json:"task_id"`
	AgentID        *string  `json:"agent_id"`
	Provider       string   `json:"provider"`
	Model          string   `json:"model"`
	RequestedModel string   `json:"requested_model"`
	Mode           string   `json:"mode"`
	ProfileID      string   `json:"profile_id"`
	PromptVersion  string   `json:"prompt_version"`
	InputSHA256    string   `json:"input_sha256"`
	InputTokens    int      `json:"input_tokens"`
	OutputTokens   int      `json:"output_tokens"`
	CostUSD        float64  `json:"cost_usd"`
	LatencyMS      float64  `json:"latency_ms"`
	Status         string   `json:"status"`
	ErrorType      *string  `json:"error_type"`
	FinishReason   *string  `json:"finish_reason"`
	DataClass      *string  `json:"data_class"`
	Masked         bool     `json:"masked"`
	External       bool     `json:"external"`
	Attempt        int      `json:"attempt"`
	RoutingReasons []string `json:"routing_reasons"`
	// tool_call
	Tool               string  `json:"tool"`
	Kind               *string `json:"kind"`
	Reason             *string `json:"reason"`
	ParamsSHA256       string  `json:"params_sha256"`
	ResponseBytes      int     `json:"response_bytes"`
	Truncated          bool    `json:"truncated"`
	SuspectedInjection bool    `json:"suspected_injection"`
}

var shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// recordAICalls — POST /api/v1/audit/ai-calls: оркестратор передаёт записи о вызовах LLM и инструментов,
// ядро вписывает их в hash chain tenant (§6.3: провайдер, модель, режим, prompt_version, хэш входа, токены, стоимость).
func (s *Server) recordAICalls(w http.ResponseWriter, r *http.Request, a identity.Actor) {
	if a.Kind != identity.KindService || a.ID != "orchestrator" {
		s.fail(w, r, problem.New(problem.Forbidden, "only the AI orchestrator service records AI calls"))
		return
	}
	var b struct {
		Records []aiCallRecord `json:"records"`
	}
	if err := decode(r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(b.Records) == 0 || len(b.Records) > 200 {
		s.fail(w, r, problem.New(problem.InvalidParams, "records: 1..200 per request"))
		return
	}
	for i, rec := range b.Records {
		if rec.TenantID != a.TenantID {
			s.fail(w, r, problem.New(problem.Forbidden, "records[%d]: tenant does not match the caller", i))
			return
		}
		switch rec.RecordType {
		case "llm_call":
			if !shaRe.MatchString(rec.InputSHA256) || rec.Provider == "" || rec.Model == "" {
				s.fail(w, r, problem.New(problem.InvalidParams, "records[%d]: llm_call requires provider, model, input_sha256", i))
				return
			}
		case "tool_call":
			if !shaRe.MatchString(rec.ParamsSHA256) || rec.Tool == "" {
				s.fail(w, r, problem.New(problem.InvalidParams, "records[%d]: tool_call requires tool and params_sha256", i))
				return
			}
		default:
			s.fail(w, r, problem.New(problem.InvalidParams, "records[%d]: record_type must be llm_call or tool_call", i))
			return
		}
	}
	for _, rec := range b.Records {
		raw, _ := json.Marshal(rec)
		var data map[string]any
		_ = json.Unmarshal(raw, &data)
		for k, v := range data { // компактная запись: без пустых значений
			if v == nil || v == "" || v == false || v == float64(0) {
				delete(data, k)
			}
		}
		delete(data, "tenant_id")
		actor := "service:orchestrator"
		if rec.AgentID != nil && *rec.AgentID != "" {
			actor = "ai_agent:" + *rec.AgentID
		}
		action, obj := "ai.llm_call", "llm_call"
		if rec.RecordType == "tool_call" {
			action, obj = "ai.tool_call", "tool_call"
		}
		if _, err := s.Audit.Append(audit.Record{TenantID: a.TenantID, Actor: actor, Action: action, ObjectType: obj, ObjectID: rec.CallID, Data: data}); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": len(b.Records)})
}
