// Package incidents — Incident Management (M06, Приложение C.7) и инцидентная сторона RCA (M07):
// корреляция и дедупликация событий телеметрии, owner = owner актива, timeline, запуск RCA через
// оркестратор, приём результатов RCA (только гипотезы — инцидент автоматически не закрывается),
// постмортем, оценка оператора → кандидат в golden dataset (M22).
package incidents

import (
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/fsm"
	"github.com/aitmaganbetov/admintwin/services/telemetry"
)

// Состояния инцидента (C.7).
const (
	StatusNew           fsm.State = "new"
	StatusTriaged       fsm.State = "triaged"
	StatusInvestigating fsm.State = "investigating"
	StatusMitigated     fsm.State = "mitigated"
	StatusResolved      fsm.State = "resolved"
	StatusClosed        fsm.State = "closed"
	StatusReopened      fsm.State = "reopened"
)

// Lifecycle — автомат C.7 как данные (C.10). reopened — из resolved/closed, далее → investigating.
var Lifecycle = fsm.Definition{
	Name:    "incident",
	Initial: StatusNew,
	Transitions: map[fsm.State][]fsm.State{
		StatusNew:           {StatusTriaged},
		StatusTriaged:       {StatusInvestigating},
		StatusInvestigating: {StatusMitigated},
		StatusMitigated:     {StatusResolved},
		StatusResolved:      {StatusClosed, StatusReopened},
		StatusClosed:        {StatusReopened},
		StatusReopened:      {StatusInvestigating},
	},
}

// IsOpen — инцидент принимает новые события (корреляция/дедупликация).
func IsOpen(s fsm.State) bool { return s != StatusResolved && s != StatusClosed }

// Статусы RCA (контракт §3).
const (
	RCANotStarted = "not_started"
	RCARunning    = "running"
	RCACompleted  = "completed"
	RCAUncertain  = "uncertain"
	RCAFailed     = "failed"
)

// TimelineEntry — запись хронологии.
type TimelineEntry struct {
	At    time.Time `json:"at"`
	Actor string    `json:"actor"`
	Kind  string    `json:"kind"` // created | event | transition | rca_requested | rca_update | change_linked | postmortem | feedback | owner_assigned | severity_changed
	Text  string    `json:"text"`
	Ref   string    `json:"ref,omitempty"`
}

// Evidence — факт гипотезы со ссылкой на evidence.
type Evidence struct {
	Fact       string `json:"fact"`
	EvidenceID string `json:"evidence_id"`
}

// Hypothesis — гипотеза RCA (§9: confidence, evidence, исключённые причины, следующие безопасные проверки).
type Hypothesis struct {
	Cause      string     `json:"cause"`
	Confidence float64    `json:"confidence"`
	Supporting []Evidence `json:"supporting"`
	Refuting   []Evidence `json:"refuting"`
	NextChecks []string   `json:"next_checks"`
}

// RCA — состояние анализа первопричины. Выводы — гипотезы, а не утверждённая первопричина.
type RCA struct {
	Status           string       `json:"status"`
	TaskID           string       `json:"task_id"`
	Hypotheses       []Hypothesis `json:"hypotheses"`
	Conclusion       string       `json:"conclusion"`
	UncertaintyCheck string       `json:"uncertainty_check"`
	Agents           []string     `json:"agents"`
	CostUSD          float64      `json:"cost_usd"`
	ProposedChanges  []string     `json:"proposed_changes"`
	RequestedAt      *time.Time   `json:"requested_at,omitempty"`
	UpdatedAt        *time.Time   `json:"updated_at,omitempty"`
	Note             string       `json:"note,omitempty"`
}

// Postmortem — обязателен перед resolved для severity ≥ high (C.7).
type Postmortem struct {
	Summary           string    `json:"summary"`
	RootCause         string    `json:"root_cause"`
	CorrectiveActions []string  `json:"corrective_actions"`
	Author            string    `json:"author"`
	At                time.Time `json:"at"`
}

// Feedback — оценка оператора результата RCA.
type Feedback struct {
	Correct     bool      `json:"correct"`
	ActualCause string    `json:"actual_cause,omitempty"`
	Rating      int       `json:"rating"`
	Comment     string    `json:"comment,omitempty"`
	Author      string    `json:"author"`
	At          time.Time `json:"at"`
	CandidateID string    `json:"candidate_id,omitempty"`
}

// EventRef — сводка связанного события (без сырых строк журналов: только ссылка и шаблонный заголовок).
type EventRef struct {
	ID          string             `json:"id"`
	AssetID     string             `json:"asset_id,omitempty"`
	Kind        string             `json:"kind"`
	Severity    telemetry.Severity `json:"severity"`
	Title       string             `json:"title"`
	Fingerprint string             `json:"fingerprint"`
	Labels      map[string]string  `json:"labels,omitempty"`
	At          time.Time          `json:"at"`
}

// Latency — задержки от первого события (критерий §21 «создаётся и назначается за < 30 с»).
type Latency struct {
	EventToCreatedMS  int64  `json:"event_to_created_ms"`
	EventToAssignedMS *int64 `json:"event_to_assigned_ms"`
}

// Incident — инцидент (контракт Этапа 1, §3).
type Incident struct {
	ID          string             `json:"id"`
	TenantID    string             `json:"tenant_id"`
	Title       string             `json:"title"`
	Description string             `json:"description,omitempty"`
	Severity    telemetry.Severity `json:"severity"`
	Status      fsm.State          `json:"status"`
	Owner       string             `json:"owner"`
	AssetIDs    []string           `json:"asset_ids"`
	EventIDs    []string           `json:"event_ids"`
	Fingerprint string             `json:"fingerprint"`
	// Fingerprints — все fingerprint, дедуплицируемые этим инцидентом, с временем последнего события.
	Fingerprints map[string]time.Time `json:"fingerprints,omitempty"`
	Events       []EventRef           `json:"events"`
	CreatedAt    time.Time            `json:"created_at"`
	UpdatedAt    time.Time            `json:"updated_at"`
	TriagedAt    *time.Time           `json:"triaged_at"`
	AssignedAt   *time.Time           `json:"assigned_at"`
	FirstEventAt *time.Time           `json:"first_event_at,omitempty"`
	// LastSignalAt — время последнего события severity ≥ high (окно корреляции 10 мин).
	LastSignalAt *time.Time       `json:"last_signal_at,omitempty"`
	Latency      *Latency         `json:"latency,omitempty"`
	CreatedBy    string           `json:"created_by"`
	Timeline     []TimelineEntry  `json:"timeline"`
	Transitions  []fsm.Transition `json:"transitions"`
	RCA          RCA              `json:"rca"`
	Postmortem   *Postmortem      `json:"postmortem"`
	Feedback     *Feedback        `json:"feedback"`
	SLOImpact    any              `json:"slo_impact"`
	Version      int              `json:"version"`
	// TimelineBase — число более ранних записей timeline, не загруженных в память (seq первой = base+1).
	TimelineBase int `json:"-"`
}

// Clone — глубокая копия (репозиторий не отдаёт внутренние указатели).
func (i *Incident) Clone() *Incident {
	cp := *i
	cp.AssetIDs = append([]string(nil), i.AssetIDs...)
	cp.EventIDs = append([]string(nil), i.EventIDs...)
	cp.Events = append([]EventRef(nil), i.Events...)
	cp.Timeline = append([]TimelineEntry(nil), i.Timeline...)
	cp.Transitions = append([]fsm.Transition(nil), i.Transitions...)
	if i.Fingerprints != nil {
		cp.Fingerprints = make(map[string]time.Time, len(i.Fingerprints))
		for k, v := range i.Fingerprints {
			cp.Fingerprints[k] = v
		}
	}
	cp.RCA.Hypotheses = append([]Hypothesis(nil), i.RCA.Hypotheses...)
	cp.RCA.Agents = append([]string(nil), i.RCA.Agents...)
	cp.RCA.ProposedChanges = append([]string(nil), i.RCA.ProposedChanges...)
	if i.Postmortem != nil {
		pm := *i.Postmortem
		pm.CorrectiveActions = append([]string(nil), i.Postmortem.CorrectiveActions...)
		cp.Postmortem = &pm
	}
	if i.Feedback != nil {
		fb := *i.Feedback
		cp.Feedback = &fb
	}
	if i.Latency != nil {
		l := *i.Latency
		cp.Latency = &l
	}
	return &cp
}

// GoldenCandidate — кандидат в golden dataset (M22) из оценки оператора; требует ревью перед включением.
type GoldenCandidate struct {
	ID         string         `json:"id"`
	TenantID   string         `json:"tenant_id"`
	IncidentID string         `json:"incident_id"`
	CreatedAt  time.Time      `json:"created_at"`
	CreatedBy  string         `json:"created_by"`
	Status     string         `json:"status"` // candidate
	Exportable bool           `json:"exportable"`
	Reason     string         `json:"reason,omitempty"`
	Case       map[string]any `json:"case"`
}
