package incidents

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/fsm"
	"github.com/aitmaganbetov/admintwin/pkg/httpapi"
	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/audit"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	"github.com/aitmaganbetov/admintwin/services/telemetry"
)

// Параметры корреляции (контракт §3).
const (
	DedupWindow       = 30 * time.Minute // одинаковый fingerprint → дедупликация
	CorrelationWindow = 10 * time.Minute // severity ≥ high на том же активе или в blast radius ≤ 2
	CorrelationDepth  = 2
	maxEventsPerInc   = 1000
	maxTimeline       = 5000
)

// CorrelatorActor — субъект автоматических записей.
const CorrelatorActor = "service:incident-correlator"

// Роли, которым разрешены изменения инцидентов (§2.2: Operator — инциденты).
var (
	mutatorRoles = []identity.Role{identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleEngineer, identity.RoleOperator}
	readerRoles  = []identity.Role{identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleEngineer, identity.RoleOperator, identity.RoleViewer, identity.RoleAuditor, identity.RoleComplianceManager}
	exportRoles  = []identity.Role{identity.RoleTenantAdmin, identity.RoleITManager}
)

// Config — параметры сервиса.
type Config struct {
	// AutoTriage — автоматически переводить созданный инцидент severity ≥ high в triaged (и запускать RCA),
	// чтобы уложиться в «алерт → старт RCA < 30 с» (§17.1). По умолчанию выключено: triage делает человек.
	AutoTriage bool
	// RCATimeout — таймаут вызова оркестратора.
	RCATimeout time.Duration
}

// Service — управление инцидентами.
type Service struct {
	repo  Repository
	inv   inventory.Repository
	audit *audit.Log
	rca   RCAStarter
	cfg   Config
	// ServiceToken — если задан, POST /rca обязан нести X-AdminTwin-Service-Token (защита в глубину).
	ServiceToken string
	// OnFeedback вызывается (асинхронно) после оценки оператора: подтверждённые RCA становятся кейсами
	// для поиска похожих инцидентов в оркестраторе (§5.3). cause/actualCause — машинные коды или пусто.
	OnFeedback func(tenantID, incidentID string, correct bool, cause, actualCause, summary string)

	mu  sync.Mutex // сериализует корреляцию и изменения (MVP: один экземпляр ядра)
	now func() time.Time
}

var _ telemetry.EventSubscriber = (*Service)(nil)

// New создаёт сервис. rca может быть nil (оркестратор не настроен: RCA → failed с пометкой).
func New(repo Repository, inv inventory.Repository, al *audit.Log, rca RCAStarter, cfg Config) *Service {
	if cfg.RCATimeout <= 0 {
		cfg.RCATimeout = 10 * time.Second
	}
	return &Service{repo: repo, inv: inv, audit: al, rca: rca, cfg: cfg, now: time.Now}
}

// SetClock подменяет часы (тесты).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// SetRCAStarter подключает оркестратор после сборки.
func (s *Service) SetRCAStarter(r RCAStarter) { s.mu.Lock(); s.rca = r; s.mu.Unlock() }

func (s *Service) auditLog(tenantID, actor, action, id string, data map[string]any) {
	if s.audit == nil {
		return
	}
	if _, err := s.audit.Append(audit.Record{TenantID: tenantID, Actor: actor, Action: action, ObjectType: "incident", ObjectID: id, Data: data}); err != nil {
		slog.Error("incidents: audit append failed", "error", err, "incident_id", id)
	}
}

func notFound() error { return problem.New(problem.NotFound, "incident not found") }

func (s *Service) get(ctx context.Context, tenantID, id string) (*Incident, error) {
	inc, err := s.repo.Get(ctx, tenantID, id)
	if errors.Is(err, ErrNotFound) {
		return nil, notFound()
	}
	return inc, err
}

func (s *Service) save(ctx context.Context, inc *Incident) error {
	inc.Version++
	inc.UpdatedAt = s.now().UTC()
	if n := len(inc.Timeline) - maxTimeline; n > 0 {
		inc.Timeline = inc.Timeline[n:]
		inc.TimelineBase += n
	}
	err := s.repo.Update(ctx, inc)
	if errors.Is(err, ErrConflict) {
		return problem.New(problem.Conflict, "incident was modified concurrently, retry")
	}
	return err
}

func (inc *Incident) addTimeline(at time.Time, actor, kind, text, ref string) {
	inc.Timeline = append(inc.Timeline, TimelineEntry{At: at.UTC(), Actor: actor, Kind: kind, Text: text, Ref: ref})
}

// ------------------------------------------------------------------ корреляция

// HandleEvents реализует telemetry.EventSubscriber: дедупликация, корреляция, автосоздание (severity ≥ high).
func (s *Service) HandleEvents(ctx context.Context, tenantID string, evs []telemetry.Event) ([]string, error) {
	s.mu.Lock()
	var ids []string
	var autoTriage []string
	for _, e := range evs {
		if e.TenantID != tenantID {
			continue // защита: событие другого tenant не коррелируется
		}
		id, created, err := s.correlate(ctx, e)
		if err != nil {
			s.mu.Unlock()
			return ids, err
		}
		if id != "" && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
		if created && s.cfg.AutoTriage {
			autoTriage = append(autoTriage, id)
		}
	}
	s.mu.Unlock()
	for _, id := range autoTriage {
		sys := identity.Actor{ID: "incident-correlator", Kind: identity.KindService, TenantID: tenantID}
		if _, err := s.transition(ctx, sys, id, StatusTriaged, "auto-triage: severity >= high", ""); err != nil {
			slog.Warn("incidents: auto-triage failed", "incident_id", id, "error", err)
		}
	}
	return ids, nil
}

func eventRef(e telemetry.Event) EventRef {
	return EventRef{ID: e.ID, AssetID: e.AssetID, Kind: e.Kind, Severity: e.Severity, Title: telemetry.Truncate(e.Title, 300), Fingerprint: e.Fingerprint, Labels: e.Labels, At: e.At.UTC()}
}

func eventTime(e telemetry.Event, now time.Time) time.Time {
	if e.At.IsZero() {
		return now
	}
	return e.At.UTC()
}

// correlate возвращает id инцидента (пусто — событие не привело к инциденту) и признак создания.
func (s *Service) correlate(ctx context.Context, e telemetry.Event) (string, bool, error) {
	now := s.now().UTC()
	at := eventTime(e, now)
	open, err := s.repo.Open(ctx, e.TenantID, at.Add(-DedupWindow))
	if err != nil {
		return "", false, err
	}
	// 1. Дедупликация по fingerprint (30 мин).
	for i := range open {
		inc := &open[i]
		if last, ok := inc.Fingerprints[e.Fingerprint]; ok && at.Sub(last) <= DedupWindow {
			return inc.ID, false, s.attach(ctx, inc, e, at, "deduplicated by fingerprint")
		}
	}
	high := e.Severity.AtLeast(telemetry.SevHigh)
	// 2. Корреляция severity ≥ high: тот же актив или связь в графе (blast radius ≤ 2), окно 10 мин.
	if high && e.AssetID != "" {
		related := s.relatedAssets(e.TenantID, e.AssetID)
		for i := range open {
			inc := &open[i]
			if inc.LastSignalAt == nil || at.Sub(*inc.LastSignalAt) > CorrelationWindow || at.Before(inc.LastSignalAt.Add(-CorrelationWindow)) {
				continue
			}
			for _, a := range inc.AssetIDs {
				if related[a] || s.inBlastRadius(e.TenantID, a, e.AssetID) {
					return inc.ID, false, s.attach(ctx, inc, e, at, "correlated: same asset or blast radius <= 2 within 10m")
				}
			}
		}
	}
	if !high {
		return "", false, nil // событие сохранено в телеметрии; инцидент не создаётся
	}
	// 3. Новый инцидент.
	inc, err := s.createFromEvent(ctx, e, at, now)
	if err != nil {
		return "", false, err
	}
	return inc.ID, true, nil
}

// relatedAssets — актив и зависящие от него в пределах CorrelationDepth.
func (s *Service) relatedAssets(tenantID, assetID string) map[string]bool {
	out := map[string]bool{assetID: true}
	if s.inv == nil {
		return out
	}
	items, err := s.inv.BlastRadius(tenantID, assetID, CorrelationDepth)
	if err != nil {
		return out
	}
	for _, it := range items {
		out[it.AssetID] = true
	}
	return out
}

// inBlastRadius — target зависит (в пределах глубины) от source.
func (s *Service) inBlastRadius(tenantID, source, target string) bool {
	if s.inv == nil {
		return false
	}
	items, err := s.inv.BlastRadius(tenantID, source, CorrelationDepth)
	if err != nil {
		return false
	}
	for _, it := range items {
		if it.AssetID == target {
			return true
		}
	}
	return false
}

func (s *Service) attach(ctx context.Context, inc *Incident, e telemetry.Event, at time.Time, why string) error {
	if slices.Contains(inc.EventIDs, e.ID) {
		return nil
	}
	if len(inc.EventIDs) < maxEventsPerInc {
		inc.EventIDs = append(inc.EventIDs, e.ID)
		inc.Events = append(inc.Events, eventRef(e))
	}
	if inc.Fingerprints == nil {
		inc.Fingerprints = map[string]time.Time{}
	}
	if prev, ok := inc.Fingerprints[e.Fingerprint]; !ok || at.After(prev) {
		inc.Fingerprints[e.Fingerprint] = at
	}
	if e.AssetID != "" && !slices.Contains(inc.AssetIDs, e.AssetID) {
		inc.AssetIDs = append(inc.AssetIDs, e.AssetID)
	}
	if e.Severity.AtLeast(telemetry.SevHigh) && (inc.LastSignalAt == nil || at.After(*inc.LastSignalAt)) {
		t := at
		inc.LastSignalAt = &t
	}
	inc.addTimeline(s.now(), CorrelatorActor, "event", fmt.Sprintf("%s event %s (%s): %s", e.Severity, e.Kind, why, telemetry.Truncate(e.Title, 300)), "event:"+e.ID)
	if e.Severity.Rank() > inc.Severity.Rank() {
		inc.addTimeline(s.now(), CorrelatorActor, "severity_changed", fmt.Sprintf("severity %s -> %s", inc.Severity, e.Severity), "event:"+e.ID)
		inc.Severity = e.Severity
	}
	if inc.Owner == "" && e.AssetID != "" {
		s.assignOwner(inc, e.AssetID)
	}
	if err := s.save(ctx, inc); err != nil {
		return err
	}
	s.auditLog(inc.TenantID, CorrelatorActor, "incident.event_linked", inc.ID, map[string]any{"event_id": e.ID, "fingerprint": e.Fingerprint, "reason": why})
	return nil
}

func (s *Service) assignOwner(inc *Incident, assetID string) {
	if s.inv == nil {
		return
	}
	a, ok := s.inv.Get(inc.TenantID, assetID)
	if !ok || a.Owner == "" {
		return
	}
	now := s.now().UTC()
	inc.Owner = a.Owner
	inc.AssignedAt = &now
	inc.addTimeline(now, CorrelatorActor, "owner_assigned", "owner assigned from asset "+a.Name+": "+a.Owner, "asset:"+a.ID)
	if inc.Latency != nil && inc.FirstEventAt != nil {
		ms := now.Sub(*inc.FirstEventAt).Milliseconds()
		inc.Latency.EventToAssignedMS = &ms
	}
}

func (s *Service) createFromEvent(ctx context.Context, e telemetry.Event, at, now time.Time) (*Incident, error) {
	first := at
	inc := &Incident{
		ID: telemetry.NewID(), TenantID: e.TenantID, Title: telemetry.Truncate(e.Title, 300), Severity: e.Severity,
		Status: Lifecycle.Initial, Fingerprint: e.Fingerprint, Fingerprints: map[string]time.Time{e.Fingerprint: at},
		EventIDs: []string{e.ID}, Events: []EventRef{eventRef(e)}, AssetIDs: []string{},
		CreatedAt: now, UpdatedAt: now, FirstEventAt: &first, LastSignalAt: &first, CreatedBy: CorrelatorActor,
		RCA:      RCA{Status: RCANotStarted, Hypotheses: []Hypothesis{}, Agents: []string{}, ProposedChanges: []string{}},
		Timeline: []TimelineEntry{}, Transitions: []fsm.Transition{}, Version: 1,
	}
	inc.Latency = &Latency{EventToCreatedMS: now.Sub(first).Milliseconds()}
	inc.addTimeline(now, CorrelatorActor, "created", fmt.Sprintf("incident created from %s event %s", e.Severity, e.Kind), "event:"+e.ID)
	inc.addTimeline(now, CorrelatorActor, "event", fmt.Sprintf("%s event %s: %s", e.Severity, e.Kind, inc.Title), "event:"+e.ID)
	if e.AssetID != "" {
		inc.AssetIDs = append(inc.AssetIDs, e.AssetID)
		s.assignOwner(inc, e.AssetID)
	}
	if inc.Owner == "" {
		inc.addTimeline(now, CorrelatorActor, "owner_assigned", "owner unknown: asset classification incomplete", "")
	}
	if err := s.repo.Create(ctx, inc); err != nil {
		return nil, err
	}
	data := map[string]any{"event_id": e.ID, "severity": string(e.Severity), "owner": inc.Owner, "event_to_created_ms": inc.Latency.EventToCreatedMS}
	if inc.Latency.EventToAssignedMS != nil {
		data["event_to_assigned_ms"] = *inc.Latency.EventToAssignedMS
	}
	s.auditLog(inc.TenantID, CorrelatorActor, "incident.created", inc.ID, data)
	return inc, nil
}

// ------------------------------------------------------------------ чтение

func canRead(a identity.Actor) error {
	if a.IsAI() {
		return nil
	}
	if a.Kind != identity.KindUser {
		return problem.New(problem.Forbidden, "insufficient identity")
	}
	return httpapi.RequireAny(a, readerRoles...)
}

func canMutate(a identity.Actor) error {
	if a.IsAI() {
		return problem.New(problem.Forbidden, "AI agents cannot modify incidents")
	}
	if a.Kind != identity.KindUser {
		return problem.New(problem.Forbidden, "this action requires a human user")
	}
	return httpapi.RequireAny(a, mutatorRoles...)
}

// Get возвращает инцидент.
func (s *Service) Get(ctx context.Context, a identity.Actor, id string) (*Incident, error) {
	if err := canRead(a); err != nil {
		return nil, err
	}
	return s.get(ctx, a.TenantID, id)
}

// List возвращает инциденты tenant.
func (s *Service) List(ctx context.Context, a identity.Actor, f Filter) ([]Incident, error) {
	if err := canRead(a); err != nil {
		return nil, err
	}
	if f.Status != "" && !slices.Contains(Lifecycle.States(), f.Status) {
		return nil, problem.New(problem.InvalidParams, "unknown status")
	}
	if f.Severity != "" && !f.Severity.Valid() {
		return nil, problem.New(problem.InvalidParams, "unknown severity")
	}
	return s.repo.List(ctx, a.TenantID, f)
}

// ------------------------------------------------------------------ ручное создание

// CreateInput — ручное создание.
type CreateInput struct {
	Title       string             `json:"title"`
	Severity    telemetry.Severity `json:"severity"`
	AssetIDs    []string           `json:"asset_ids"`
	Description string             `json:"description"`
}

// Create — ручное создание инцидента человеком.
func (s *Service) Create(ctx context.Context, a identity.Actor, in CreateInput) (*Incident, error) {
	if err := canMutate(a); err != nil {
		return nil, err
	}
	if err := checkText("title", in.Title, 3, 300); err != nil {
		return nil, err
	}
	if err := checkText("description", in.Description, 0, 10000); err != nil {
		return nil, err
	}
	if !in.Severity.Valid() {
		return nil, rcaInvalid("severity", "must be critical|high|medium|low|info")
	}
	if len(in.AssetIDs) > 50 {
		return nil, rcaInvalid("asset_ids", "too many assets (max 50)")
	}
	assets := []string{}
	for _, id := range in.AssetIDs {
		if s.inv != nil {
			if _, ok := s.inv.Get(a.TenantID, id); !ok {
				return nil, problem.New(problem.NotFound, "asset not found")
			}
		}
		if !slices.Contains(assets, id) {
			assets = append(assets, id)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	inc := &Incident{
		ID: telemetry.NewID(), TenantID: a.TenantID, Title: in.Title, Description: in.Description, Severity: in.Severity,
		Status: Lifecycle.Initial, AssetIDs: assets, EventIDs: []string{}, Events: []EventRef{}, CreatedAt: now, UpdatedAt: now,
		CreatedBy: a.Ref(), Timeline: []TimelineEntry{}, Transitions: []fsm.Transition{}, Version: 1,
		RCA: RCA{Status: RCANotStarted, Hypotheses: []Hypothesis{}, Agents: []string{}, ProposedChanges: []string{}},
	}
	inc.Fingerprint = "manual:" + inc.ID
	inc.addTimeline(now, a.Ref(), "created", "incident created manually", "")
	for _, id := range assets {
		if inc.Owner == "" {
			s.assignOwner(inc, id)
		}
	}
	if err := s.repo.Create(ctx, inc); err != nil {
		return nil, err
	}
	s.auditLog(a.TenantID, a.Ref(), "incident.created", inc.ID, map[string]any{"severity": string(in.Severity), "manual": true, "owner": inc.Owner})
	return inc, nil
}

// ------------------------------------------------------------------ переходы

// TransitionInput — тело POST /transitions.
type TransitionInput struct {
	To          fsm.State `json:"to"`
	Reason      string    `json:"reason"`
	EvidenceRef string    `json:"evidence_ref"`
}

// Transition — переход состояния человеком. AI-агенты не меняют состояние и не закрывают инциденты.
func (s *Service) Transition(ctx context.Context, a identity.Actor, id string, in TransitionInput) (*Incident, error) {
	if err := canMutate(a); err != nil {
		return nil, err
	}
	if err := checkText("reason", in.Reason, 1, 2000); err != nil {
		return nil, err
	}
	if in.EvidenceRef != "" && !refIDRe.MatchString(in.EvidenceRef) {
		return nil, rcaInvalid("evidence_ref", "invalid reference")
	}
	return s.transition(ctx, a, id, in.To, in.Reason, in.EvidenceRef)
}

func (s *Service) transition(ctx context.Context, a identity.Actor, id string, to fsm.State, reason, evidenceRef string) (*Incident, error) {
	s.mu.Lock()
	inc, err := s.get(ctx, a.TenantID, id)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	now := s.now().UTC()
	tr, err := Lifecycle.Check(inc.Status, to, a.Ref(), reason, now)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if to == StatusMitigated && evidenceRef == "" {
		s.mu.Unlock()
		return nil, problem.New(problem.InvalidTransition, "mitigated requires evidence_ref (C.7)")
	}
	if to == StatusResolved && inc.Severity.AtLeast(telemetry.SevHigh) && inc.Postmortem == nil {
		s.mu.Unlock()
		return nil, problem.New(problem.InvalidTransition, "resolved requires a postmortem for severity >= high (C.7)")
	}
	tr.EvidenceRef = evidenceRef
	tr.CorrelationID = inc.ID
	from := inc.Status
	inc.Status = to
	inc.Transitions = append(inc.Transitions, tr)
	inc.addTimeline(now, a.Ref(), "transition", fmt.Sprintf("%s -> %s: %s", from, to, reason), evidenceRef)
	startRCA := false
	if to == StatusTriaged {
		inc.TriagedAt = &now
		startRCA = true
	}
	if startRCA {
		s.markRCARequested(inc, a, now)
	}
	if err := s.save(ctx, inc); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	s.auditLog(a.TenantID, a.Ref(), "incident.transitioned", inc.ID, map[string]any{"from": string(from), "to": string(to), "reason": reason, "evidence_ref": evidenceRef})
	s.mu.Unlock()
	if startRCA {
		return s.startRCA(ctx, a, inc.ID)
	}
	return inc, nil
}

// ------------------------------------------------------------------ RCA

func (s *Service) markRCARequested(inc *Incident, a identity.Actor, now time.Time) {
	inc.RCA = RCA{Status: RCARunning, Hypotheses: []Hypothesis{}, Agents: []string{}, ProposedChanges: []string{}, RequestedAt: &now}
	inc.addTimeline(now, a.Ref(), "rca_requested", "RCA requested", "")
}

// Analyze — ручной запуск RCA (POST /analyze).
func (s *Service) Analyze(ctx context.Context, a identity.Actor, id string) (*Incident, error) {
	if err := canMutate(a); err != nil {
		return nil, err
	}
	s.mu.Lock()
	inc, err := s.get(ctx, a.TenantID, id)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if inc.Status == StatusClosed {
		s.mu.Unlock()
		return nil, problem.New(problem.InvalidTransition, "closed incident cannot be analyzed; reopen it first")
	}
	if inc.RCA.Status == RCARunning && inc.RCA.TaskID == "" {
		s.mu.Unlock()
		return nil, problem.New(problem.Conflict, "RCA start is already in progress")
	}
	s.markRCARequested(inc, a, s.now().UTC())
	if err := s.save(ctx, inc); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	s.mu.Unlock()
	return s.startRCA(ctx, a, id)
}

func (s *Service) buildTask(inc *Incident, a identity.Actor) RCATask {
	t := RCATask{
		Kind: "rca", TenantID: inc.TenantID, IncidentID: inc.ID,
		Objective:   "Determine probable root cause of incident " + inc.ID + " using read-only tools; propose fixes only as ChangeRequests",
		Scope:       RCAScope{AssetIDs: append([]string{}, inc.AssetIDs...)},
		RequestedBy: a.Ref(), requesterID: a.ID, requesterKind: string(a.Kind),
		Context: RCAContext{
			IncidentTitle: inc.Title, Severity: string(inc.Severity), Priority: priorityFor(string(inc.Severity)),
			AssetIDs: append([]string{}, inc.AssetIDs...), Events: []RCAEventSummary{}, Constraints: []string{"read_only"},
		},
	}
	// Последние 50 событий: ссылки и шаблонные сводки (сырые строки журналов не передаются).
	evs := inc.Events
	if len(evs) > 50 {
		evs = evs[len(evs)-50:]
	}
	for _, e := range evs {
		t.Context.Events = append(t.Context.Events, RCAEventSummary{
			EventID: e.ID, EvidenceRef: "event:" + e.ID, Kind: e.Kind, Severity: string(e.Severity), AssetID: e.AssetID,
			At: e.At.UTC().Format(time.RFC3339Nano), Summary: e.Title, Fingerprint: e.Fingerprint,
		})
	}
	if len(inc.Events) > 0 {
		// Тип алерта — по самому серьёзному событию.
		top := inc.Events[0]
		for _, e := range inc.Events {
			if e.Severity.Rank() > top.Severity.Rank() {
				top = e
			}
		}
		t.Context.AlertType = alertType(top)
		t.Context.ServiceKind = top.Labels["service_kind"]
	}
	if len(inc.AssetIDs) > 0 && s.inv != nil {
		if as, ok := s.inv.Get(inc.TenantID, inc.AssetIDs[0]); ok {
			t.Context.AssetType, t.Context.Environment = as.Type, as.Environment
		}
	}
	return t
}

// startRCA вызывает оркестратор вне блокировки и записывает task_id или ошибку.
func (s *Service) startRCA(ctx context.Context, a identity.Actor, id string) (*Incident, error) {
	s.mu.Lock()
	inc, err := s.get(ctx, a.TenantID, id)
	starter := s.rca
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	task := s.buildTask(inc, a)
	var taskID string
	var startErr error
	if starter == nil {
		startErr = errors.New("orchestrator is not configured")
	} else {
		cctx, cancel := context.WithTimeout(ctx, s.cfg.RCATimeout)
		taskID, startErr = starter.StartRCA(cctx, task)
		cancel()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	inc, err = s.get(ctx, a.TenantID, id)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if startErr != nil {
		inc.RCA.Status = RCAFailed
		inc.RCA.Note = "RCA could not be started: " + telemetry.Truncate(startErr.Error(), 300)
		inc.addTimeline(now, CorrelatorActor, "rca_update", inc.RCA.Note, "")
		slog.Warn("incidents: RCA start failed", "incident_id", id, "error", startErr)
	} else {
		inc.RCA.TaskID = taskID
		inc.RCA.UpdatedAt = &now
		inc.addTimeline(now, CorrelatorActor, "rca_update", "RCA task started", "task:"+taskID)
	}
	if err := s.save(ctx, inc); err != nil {
		return nil, err
	}
	s.auditLog(inc.TenantID, a.Ref(), "incident.rca_requested", inc.ID, map[string]any{"task_id": taskID, "ok": startErr == nil})
	return inc, nil
}

// RecordRCA — результат RCA от оркестратора. Только Actor-Kind service с Actor "orchestrator".
// Выводы — гипотезы: статус инцидента не меняется; первопричина без evidence понижается до uncertain.
func (s *Service) RecordRCA(ctx context.Context, a identity.Actor, id string, r RCAResult) (*Incident, error) {
	if a.Kind != identity.KindService || a.ID != "orchestrator" || a.IsAI() {
		return nil, problem.New(problem.Forbidden, "only the orchestrator service may record RCA results")
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	inc, err := s.get(ctx, a.TenantID, id)
	if err != nil {
		return nil, err
	}
	if inc.RCA.TaskID == "" {
		return nil, problem.New(problem.Conflict, "no RCA task is registered for this incident (retry if it was just started)")
	}
	if inc.RCA.TaskID != r.TaskID {
		return nil, problem.New(problem.Conflict, "task_id does not match the active RCA task")
	}
	now := s.now().UTC()
	sort.SliceStable(r.Hypotheses, func(i, j int) bool { return r.Hypotheses[i].Confidence > r.Hypotheses[j].Confidence })
	status, note := r.Status, ""
	if status == RCACompleted && !hasEvidence(r.Hypotheses[0]) {
		// §9: первопричина не утверждается без доказательств.
		status, note = RCAUncertain, "top hypothesis has no supporting evidence; downgraded to uncertain"
	}
	inc.RCA = RCA{
		Status: status, TaskID: r.TaskID, Hypotheses: r.Hypotheses, Conclusion: r.Conclusion, UncertaintyCheck: r.UncertaintyCheck,
		Agents: r.Agents, CostUSD: r.CostUSD, ProposedChanges: r.ProposedChanges, RequestedAt: inc.RCA.RequestedAt, UpdatedAt: &now, Note: note,
	}
	text := fmt.Sprintf("RCA %s: %d hypotheses", status, len(r.Hypotheses))
	if len(r.Hypotheses) > 0 {
		text += fmt.Sprintf("; top: %s (confidence %.2f)", telemetry.Truncate(r.Hypotheses[0].Cause, 200), r.Hypotheses[0].Confidence)
	}
	inc.addTimeline(now, a.Ref(), "rca_update", text, "task:"+r.TaskID)
	for _, c := range r.ProposedChanges {
		inc.addTimeline(now, a.Ref(), "change_linked", "change proposed by RCA (requires approval)", "change:"+c)
	}
	if err := s.save(ctx, inc); err != nil {
		return nil, err
	}
	s.auditLog(inc.TenantID, a.Ref(), "incident.rca_recorded", inc.ID, map[string]any{"task_id": r.TaskID, "status": status, "hypotheses": len(r.Hypotheses), "cost_usd": r.CostUSD, "proposed_changes": r.ProposedChanges})
	return inc, nil
}

func hasEvidence(h Hypothesis) bool {
	for _, e := range h.Supporting {
		if e.EvidenceID != "" {
			return true
		}
	}
	return false
}

// LinkChange — связь инцидента с ChangeRequest (вызывается Change Coordinator / интегратором).
func (s *Service) LinkChange(ctx context.Context, tenantID, incidentID, changeID, actor string) error {
	if !changeIDRe.MatchString(changeID) {
		return rcaInvalid("change_id", "must be a change id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	inc, err := s.get(ctx, tenantID, incidentID)
	if err != nil {
		return err
	}
	inc.addTimeline(s.now(), actor, "change_linked", "change linked", "change:"+changeID)
	if err := s.save(ctx, inc); err != nil {
		return err
	}
	s.auditLog(tenantID, actor, "incident.change_linked", incidentID, map[string]any{"change_id": changeID})
	return nil
}

// ------------------------------------------------------------------ постмортем и оценка

// PostmortemInput — тело POST /postmortem.
type PostmortemInput struct {
	Summary           string   `json:"summary"`
	RootCause         string   `json:"root_cause"`
	CorrectiveActions []string `json:"corrective_actions"`
}

// SetPostmortem сохраняет постмортем.
func (s *Service) SetPostmortem(ctx context.Context, a identity.Actor, id string, in PostmortemInput) (*Incident, error) {
	if err := canMutate(a); err != nil {
		return nil, err
	}
	if err := checkText("summary", in.Summary, 1, 10000); err != nil {
		return nil, err
	}
	if err := checkText("root_cause", in.RootCause, 1, 2000); err != nil {
		return nil, err
	}
	if len(in.CorrectiveActions) == 0 || len(in.CorrectiveActions) > 50 {
		return nil, rcaInvalid("corrective_actions", "1..50 items required")
	}
	for i, c := range in.CorrectiveActions {
		if err := checkText(fmt.Sprintf("corrective_actions[%d]", i), c, 1, 1000); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	inc, err := s.get(ctx, a.TenantID, id)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	inc.Postmortem = &Postmortem{Summary: in.Summary, RootCause: in.RootCause, CorrectiveActions: append([]string(nil), in.CorrectiveActions...), Author: a.Ref(), At: now}
	inc.addTimeline(now, a.Ref(), "postmortem", "postmortem recorded", "")
	if err := s.save(ctx, inc); err != nil {
		return nil, err
	}
	s.auditLog(a.TenantID, a.Ref(), "incident.postmortem", inc.ID, map[string]any{"corrective_actions": len(in.CorrectiveActions)})
	return inc, nil
}

// FeedbackInput — тело POST /feedback.
type FeedbackInput struct {
	Correct     *bool  `json:"correct"`
	ActualCause string `json:"actual_cause"`
	Rating      int    `json:"rating"`
	Comment     string `json:"comment"`
}

// SetFeedback сохраняет оценку оператора и формирует кандидата golden dataset.
func (s *Service) SetFeedback(ctx context.Context, a identity.Actor, id string, in FeedbackInput) (*Incident, *GoldenCandidate, error) {
	if err := canMutate(a); err != nil {
		return nil, nil, err
	}
	if in.Correct == nil {
		return nil, nil, rcaInvalid("correct", "is required")
	}
	if in.Rating < 1 || in.Rating > 5 {
		return nil, nil, rcaInvalid("rating", "must be 1..5")
	}
	if err := checkText("actual_cause", in.ActualCause, 0, 500); err != nil {
		return nil, nil, err
	}
	if err := checkText("comment", in.Comment, 0, 2000); err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	inc, err := s.get(ctx, a.TenantID, id)
	if err != nil {
		return nil, nil, err
	}
	if inc.RCA.Status == RCANotStarted {
		return nil, nil, problem.New(problem.Conflict, "feedback requires an RCA result")
	}
	now := s.now().UTC()
	fb := &Feedback{Correct: *in.Correct, ActualCause: strings.TrimSpace(in.ActualCause), Rating: in.Rating, Comment: in.Comment, Author: a.Ref(), At: now}
	cand := buildCandidate(inc, fb, s.inv)
	cand.ID, cand.TenantID, cand.IncidentID, cand.CreatedAt, cand.CreatedBy, cand.Status = telemetry.NewID(), inc.TenantID, inc.ID, now, a.Ref(), "candidate"
	fb.CandidateID = cand.ID
	inc.Feedback = fb
	inc.addTimeline(now, a.Ref(), "feedback", fmt.Sprintf("operator feedback: correct=%t rating=%d", fb.Correct, fb.Rating), "golden_candidate:"+cand.ID)
	if err := s.save(ctx, inc); err != nil {
		return nil, nil, err
	}
	if err := s.repo.AddCandidate(ctx, cand); err != nil {
		return nil, nil, err
	}
	s.auditLog(a.TenantID, a.Ref(), "incident.feedback", inc.ID, map[string]any{"correct": fb.Correct, "rating": fb.Rating, "candidate_id": cand.ID, "exportable": cand.Exportable})
	if s.OnFeedback != nil {
		cause := ""
		if len(inc.RCA.Hypotheses) > 0 {
			cause = inc.RCA.Hypotheses[0].Cause
		}
		go s.OnFeedback(inc.TenantID, inc.ID, fb.Correct, causeCode(cause), causeCode(fb.ActualCause), inc.RCA.Conclusion)
	}
	return inc, &cand, nil
}

// ExportCandidates — JSONL-совместимые eval cases tenant (только пригодные к экспорту).
func (s *Service) ExportCandidates(ctx context.Context, a identity.Actor) ([]map[string]any, error) {
	if a.IsAI() || a.Kind != identity.KindUser {
		return nil, problem.New(problem.Forbidden, "this action requires a human user")
	}
	if err := httpapi.RequireAny(a, exportRoles...); err != nil {
		return nil, err
	}
	cs, err := s.repo.Candidates(ctx, a.TenantID)
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for _, c := range cs {
		if c.Exportable {
			out = append(out, c.Case)
		}
	}
	return out, nil
}

var causeCodeRe = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)

// causeCode — только машинный код причины; свободный текст оператора наружу не передаётся.
func causeCode(s string) string {
	s = strings.TrimSpace(s)
	if causeCodeRe.MatchString(s) {
		return s
	}
	return ""
}
