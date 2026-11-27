package discovery

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/httpapi"
	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/audit"
	"github.com/aitmaganbetov/admintwin/services/inventory"
)

// EvidenceSink — хранилище evidence (services/compliance-evidence.Store реализует этот интерфейс).
type EvidenceSink interface {
	Store(tenantID, kind, ref string, body []byte, legalHold bool) (id, digest string, err error)
}

// KnownMethods — методы сбора (§8.1); выполнимы только методы с зарегистрированным Collector.
var KnownMethods = []string{"ssh", "docker_api", "postgres", "fortigate_api", "snmpv3", "winrm"}

// Ограничения Scope Document и заданий.
const (
	MaxScopeValidity  = 366 * 24 * time.Hour
	MinIPv4PrefixBits = 16 // шире /16 — только несколькими scope (защита от «сканировать всё»)
	MinIPv6PrefixBits = 48
	MaxTargetsPerJob  = 256
	MaxSessionsLimit  = 64
	MaxPPSLimit       = 10000
	// ConfirmThreshold — объекты с confidence ниже порога попадают в CMDB только после подтверждения.
	ConfirmThreshold = 0.8
	targetTimeout    = 60 * time.Second
)

var (
	nameRe    = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._:-]{0,127}$`)
	credRefRe = regexp.MustCompile(`^[a-z0-9][a-z0-9/_.-]{0,255}$`)
)

// Config — параметры сервиса.
type Config struct {
	// ConfirmThreshold — порог confidence (по умолчанию 0.8).
	ConfirmThreshold float64
}

// Service — Discovery (M03, C.9).
type Service struct {
	repo       Repository
	inv        inventory.Repository
	audit      *audit.Log
	evidence   EvidenceSink
	creds      CredentialSource
	collectors map[string]Collector
	cfg        Config

	mu       sync.Mutex
	sessions map[string]chan struct{} // tenant|scope → семафор max_sessions
	wg       sync.WaitGroup
	now      func() time.Time
	// OnCMDBChange вызывается после изменения CMDB (например, InventoryResolver.Invalidate).
	OnCMDBChange func()
}

// New создаёт сервис. creds — источник read-only учёток (Vault); collectors — реализации connectors/*.
func New(repo Repository, inv inventory.Repository, al *audit.Log, ev EvidenceSink, creds CredentialSource, cfg Config, collectors ...Collector) *Service {
	if cfg.ConfirmThreshold <= 0 || cfg.ConfirmThreshold > 1 {
		cfg.ConfirmThreshold = ConfirmThreshold
	}
	s := &Service{repo: repo, inv: inv, audit: al, evidence: ev, creds: creds, cfg: cfg, collectors: map[string]Collector{}, sessions: map[string]chan struct{}{}, now: time.Now}
	for _, c := range collectors {
		s.collectors[c.Method()] = c
	}
	return s
}

// Register добавляет сборщик метода.
func (s *Service) Register(c Collector) { s.mu.Lock(); s.collectors[c.Method()] = c; s.mu.Unlock() }

// SetClock подменяет часы (тесты).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Wait дожидается завершения запущенных заданий (тесты, остановка).
func (s *Service) Wait() { s.wg.Wait() }

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func (s *Service) auditLog(tenantID, actor, action, typ, id string, data map[string]any) {
	if s.audit == nil {
		return
	}
	if _, err := s.audit.Append(audit.Record{TenantID: tenantID, Actor: actor, Action: action, ObjectType: typ, ObjectID: id, Data: data}); err != nil {
		slog.Error("discovery: audit append failed", "error", err)
	}
}

func invalid(field, format string, args ...any) error {
	p := problem.New(problem.InvalidParams, "invalid discovery request")
	p.Errors = []problem.FieldError{{Field: field, Reason: fmt.Sprintf(format, args...)}}
	return p
}

func requireTenantAdmin(a identity.Actor) error {
	if err := httpapi.RequireHuman(a); err != nil {
		return err
	}
	return httpapi.RequireAny(a, identity.RoleTenantAdmin)
}

// ------------------------------------------------------------------ Scope Document

// ScopeInput — тело POST /scopes.
type ScopeInput struct {
	Name        string    `json:"name"`
	Ranges      []string  `json:"ranges"`
	Methods     []string  `json:"methods"`
	Limits      Limits    `json:"limits"`
	Responsible string    `json:"responsible"`
	ValidUntil  time.Time `json:"valid_until"`
}

func parseRanges(rs []string) ([]netip.Prefix, []string, error) {
	if len(rs) == 0 || len(rs) > 64 {
		return nil, nil, invalid("ranges", "1..64 CIDR ranges required")
	}
	var out []netip.Prefix
	var norm []string
	for i, r := range rs {
		p, err := netip.ParsePrefix(strings.TrimSpace(r))
		if err != nil {
			return nil, nil, invalid(fmt.Sprintf("ranges[%d]", i), "invalid CIDR")
		}
		p = p.Masked()
		min := MinIPv4PrefixBits
		if p.Addr().Is6() && !p.Addr().Is4In6() {
			min = MinIPv6PrefixBits
		}
		if p.Bits() < min {
			return nil, nil, invalid(fmt.Sprintf("ranges[%d]", i), "range too broad (minimum /%d)", min)
		}
		out = append(out, p)
		norm = append(norm, p.String())
	}
	return out, norm, nil
}

// CreateScope — Tenant Admin создаёт Scope Document (черновик; действует только после утверждения).
func (s *Service) CreateScope(a identity.Actor, in ScopeInput) (*Scope, error) {
	if err := requireTenantAdmin(a); err != nil {
		return nil, err
	}
	if !nameRe.MatchString(in.Name) {
		return nil, invalid("name", "1..128 characters, letters/digits/space/._:-")
	}
	prefixes, ranges, err := parseRanges(in.Ranges)
	if err != nil {
		return nil, err
	}
	if len(in.Methods) == 0 {
		return nil, invalid("methods", "at least one method is required")
	}
	var methods []string
	for i, m := range in.Methods {
		if !slices.Contains(KnownMethods, m) {
			return nil, invalid(fmt.Sprintf("methods[%d]", i), "unknown method")
		}
		if !slices.Contains(methods, m) {
			methods = append(methods, m)
		}
	}
	if in.Limits.MaxSessions < 1 || in.Limits.MaxSessions > MaxSessionsLimit {
		return nil, invalid("limits.max_sessions", "must be 1..%d", MaxSessionsLimit)
	}
	if in.Limits.PPS < 1 || in.Limits.PPS > MaxPPSLimit {
		return nil, invalid("limits.pps", "must be 1..%d", MaxPPSLimit)
	}
	if !nameRe.MatchString(in.Responsible) {
		return nil, invalid("responsible", "is required")
	}
	now := s.now().UTC()
	if !in.ValidUntil.After(now) || in.ValidUntil.Sub(now) > MaxScopeValidity {
		return nil, invalid("valid_until", "must be in the future and within 366 days")
	}
	sc := Scope{
		ID: newID(), TenantID: a.TenantID, Name: in.Name, Ranges: ranges, Methods: methods, Limits: in.Limits,
		Responsible: in.Responsible, ValidUntil: in.ValidUntil.UTC(), CreatedBy: a.Ref(), CreatedAt: now, prefixes: prefixes,
	}
	sc.computeStatus(now)
	if err := s.repo.PutScope(sc); err != nil {
		return nil, err
	}
	s.auditLog(a.TenantID, a.Ref(), "discovery.scope_created", "discovery_scope", sc.ID, map[string]any{"ranges": ranges, "methods": methods, "valid_until": sc.ValidUntil})
	return &sc, nil
}

// ListScopes — Tenant Admin и Engineer (запуск discovery, §2.2) видят Scope Documents; Auditor — чтение.
func (s *Service) ListScopes(a identity.Actor) ([]Scope, error) {
	if err := httpapi.RequireHuman(a); err != nil {
		return nil, err
	}
	if err := httpapi.RequireAny(a, identity.RoleTenantAdmin, identity.RoleEngineer, identity.RoleAuditor); err != nil {
		return nil, err
	}
	now := s.now()
	out := s.repo.ListScopes(a.TenantID)
	for i := range out {
		out[i].computeStatus(now)
	}
	if out == nil {
		out = []Scope{}
	}
	return out, nil
}

// ApproveScope — утверждение Tenant Admin; согласующий не может быть автором (§2.1).
func (s *Service) ApproveScope(a identity.Actor, id string) (*Scope, error) {
	if err := requireTenantAdmin(a); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sc, ok := s.repo.GetScope(a.TenantID, id)
	if !ok {
		return nil, problem.New(problem.NotFound, "scope not found")
	}
	if sc.ApprovedAt != nil {
		return nil, problem.New(problem.Conflict, "scope is already approved")
	}
	if sc.CreatedBy == a.Ref() {
		s.auditLog(a.TenantID, a.Ref(), "discovery.scope_approval_denied", "discovery_scope", id, map[string]any{"reason": "separation of duties"})
		return nil, problem.New(problem.SeparationOfDuties, "the author of a scope document cannot approve it")
	}
	now := s.now().UTC()
	if !now.Before(sc.ValidUntil) {
		return nil, problem.New(problem.Conflict, "scope document has expired")
	}
	sc.ApprovedAt, sc.ApprovedBy = &now, a.Ref()
	sc.computeStatus(now)
	if err := s.repo.PutScope(*sc); err != nil {
		return nil, err
	}
	s.auditLog(a.TenantID, a.Ref(), "discovery.scope_approved", "discovery_scope", id, map[string]any{"valid_until": sc.ValidUntil})
	return sc, nil
}

// ------------------------------------------------------------------ задания

// JobInput — тело POST /jobs.
type JobInput struct {
	ScopeID string        `json:"scope_id"`
	Targets []TargetInput `json:"targets"`
}

func (s *Service) deny(a identity.Actor, scopeID, reason string, extra map[string]any) error {
	data := map[string]any{"scope_id": scopeID, "reason": reason}
	for k, v := range extra {
		data[k] = v
	}
	s.auditLog(a.TenantID, a.Ref(), "discovery.job_rejected", "discovery_job", "", data)
	p := problem.New(problem.PolicyDenied, "discovery denied: %s", reason)
	p.PolicyID = "discovery-scope"
	return p
}

// CreateJob — запуск discovery (Tenant Admin, Engineer). Без активного утверждённого scope или с целями
// вне диапазонов/методов — 403 policy-denied (журналируется). AI-агенты discovery не запускают (fail closed:
// политика «read-only по policy» §2.2 для агентов в MVP не определена).
func (s *Service) CreateJob(ctx context.Context, a identity.Actor, in JobInput) (*Job, error) {
	if err := httpapi.RequireHuman(a); err != nil {
		return nil, err
	}
	if err := httpapi.RequireAny(a, identity.RoleTenantAdmin, identity.RoleEngineer); err != nil {
		return nil, err
	}
	if len(in.Targets) == 0 || len(in.Targets) > MaxTargetsPerJob {
		return nil, invalid("targets", "1..%d targets required", MaxTargetsPerJob)
	}
	now := s.now().UTC()
	sc, ok := s.repo.GetScope(a.TenantID, in.ScopeID)
	if !ok || !sc.Active(now) {
		return nil, s.deny(a, in.ScopeID, "no active approved scope document", nil)
	}
	if len(sc.prefixes) == 0 {
		sc.prefixes, _, _ = parseRanges(sc.Ranges)
	}
	targets := make([]TargetInput, 0, len(in.Targets))
	for i, t := range in.Targets {
		f := fmt.Sprintf("targets[%d]", i)
		ip, err := netip.ParseAddr(strings.TrimSpace(t.Address))
		if err != nil {
			// hostname не проверяется на принадлежность диапазону без DNS — отклоняем.
			return nil, invalid(f+".address", "must be an IP address")
		}
		if !sc.Contains(ip) {
			return nil, s.deny(a, sc.ID, "target outside scope ranges", map[string]any{"target": ip.String()})
		}
		if !sc.AllowsMethod(t.Method) {
			return nil, s.deny(a, sc.ID, "method not allowed by scope", map[string]any{"target": ip.String(), "method": t.Method})
		}
		s.mu.Lock()
		_, hasCollector := s.collectors[t.Method]
		s.mu.Unlock()
		if !hasCollector {
			return nil, invalid(f+".method", "no collector registered for method %q", t.Method)
		}
		if t.Port < 0 || t.Port > 65535 {
			return nil, invalid(f+".port", "must be 1..65535")
		}
		if !credRefRe.MatchString(t.CredentialRef) {
			return nil, invalid(f+".credential_ref", "Vault reference is required")
		}
		if len(t.HostKey) > 4096 || len(t.TLSServerName) > 255 {
			return nil, invalid(f, "host_key/tls_server_name too long")
		}
		t.Address = ip.Unmap().String()
		targets = append(targets, t)
	}
	job := &Job{ID: newID(), TenantID: a.TenantID, ScopeID: sc.ID, Status: JobQueued, Targets: targets, Results: []TargetResult{}, Findings: []Finding{}, CreatedBy: a.Ref(), CreatedAt: now}
	if err := s.repo.PutJob(job); err != nil {
		return nil, err
	}
	s.auditLog(a.TenantID, a.Ref(), "discovery.job_created", "discovery_job", job.ID, map[string]any{"scope_id": sc.ID, "targets": len(targets)})
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.run(context.WithoutCancel(ctx), *sc, job.ID, a)
	}()
	return job, nil
}

// GetJob — статус задания.
func (s *Service) GetJob(a identity.Actor, id string) (*Job, error) {
	if a.Kind != identity.KindUser && !a.IsAI() {
		return nil, problem.New(problem.Forbidden, "insufficient identity")
	}
	if !a.IsAI() {
		if err := httpapi.RequireAny(a, identity.RoleTenantAdmin, identity.RoleEngineer, identity.RoleITManager, identity.RoleAuditor); err != nil {
			return nil, err
		}
	}
	j, ok := s.repo.GetJob(a.TenantID, id)
	if !ok {
		return nil, problem.New(problem.NotFound, "job not found")
	}
	return j, nil
}

func (s *Service) semaphore(sc Scope) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sc.TenantID + "|" + sc.ID
	ch, ok := s.sessions[key]
	if !ok || cap(ch) != sc.Limits.MaxSessions {
		ch = make(chan struct{}, sc.Limits.MaxSessions)
		s.sessions[key] = ch
	}
	return ch
}

type collected struct {
	target TargetInput
	obs    Observation
	err    error
}

// run выполняет C.9: лимиты → сбор (read-only) → нормализация → reconciliation → confidence → CMDB → evidence.
func (s *Service) run(ctx context.Context, sc Scope, jobID string, a identity.Actor) {
	job, ok := s.repo.GetJob(sc.TenantID, jobID)
	if !ok {
		return
	}
	started := s.now().UTC()
	job.Status, job.StartedAt = JobRunning, &started
	_ = s.repo.PutJob(job)

	sem := s.semaphore(sc)
	interval := time.Second / time.Duration(sc.Limits.PPS)
	results := make([]collected, len(job.Targets))
	var wg sync.WaitGroup
	for i, t := range job.Targets {
		if i > 0 && interval > 0 {
			time.Sleep(interval) // темп запусков не выше pps
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int, t TargetInput) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = collected{target: t}
			results[i].obs, results[i].err = s.collect(ctx, sc.TenantID, t)
		}(i, t)
	}
	wg.Wait()

	for _, r := range results {
		tr := TargetResult{Address: r.target.Address, Method: r.target.Method, Status: "ok", Confidence: r.obs.Confidence, Objects: len(r.obs.Assets)}
		if r.err != nil {
			tr.Status, tr.Error, tr.Confidence, tr.Objects = "error", truncate(r.err.Error(), 300), 0, 0
		}
		job.Results = append(job.Results, tr)
	}
	job.Findings = s.reconcile(&sc, results)
	s.applyConfident(job)
	job.Summary = summarize(job.Findings)
	finished := s.now().UTC()
	job.FinishedAt = &finished
	job.Status = JobCompleted
	if allFailed(job.Results) {
		job.Status, job.Error = JobFailed, "all targets failed"
	}
	s.storeEvidence(job, sc)
	_ = s.repo.PutJob(job)
	s.auditLog(sc.TenantID, a.Ref(), "discovery.job_completed", "discovery_job", job.ID, map[string]any{
		"status": job.Status, "new": job.Summary.New, "changed": job.Summary.Changed, "missing": job.Summary.Missing,
		"pending_confirmation": job.Summary.PendingConfirmation, "evidence_id": job.EvidenceID,
	})
}

func (s *Service) collect(ctx context.Context, tenantID string, t TargetInput) (Observation, error) {
	s.mu.Lock()
	c, ok := s.collectors[t.Method]
	s.mu.Unlock()
	if !ok {
		return Observation{}, fmt.Errorf("no collector for method %s", t.Method)
	}
	if s.creds == nil {
		return Observation{}, fmt.Errorf("credential source (Vault) is not configured")
	}
	cctx, cancel := context.WithTimeout(ctx, targetTimeout)
	defer cancel()
	cred, err := s.creds.ReadOnly(cctx, tenantID, t.CredentialRef)
	if err != nil {
		return Observation{}, fmt.Errorf("credential unavailable")
	}
	obs, err := c.Collect(cctx, Target{TenantID: tenantID, Address: t.Address, Port: t.Port, Method: t.Method, CredentialRef: t.CredentialRef, HostKey: t.HostKey, TLSServerName: t.TLSServerName}, cred)
	if err != nil {
		return Observation{}, err
	}
	if obs.Confidence < 0 || obs.Confidence > 1 || obs.Confidence != obs.Confidence {
		obs.Confidence = 0
	}
	return obs, nil
}

func allFailed(rs []TargetResult) bool {
	for _, r := range rs {
		if r.Status == "ok" {
			return false
		}
	}
	return len(rs) > 0
}

func summarize(fs []Finding) Summary {
	var sm Summary
	for _, f := range fs {
		switch f.Change {
		case FindingNew:
			sm.New++
		case FindingChanged:
			sm.Changed++
		case FindingMissing:
			sm.Missing++
		case FindingUnchanged:
			sm.Unchanged++
		}
		if f.NeedsConfirmation && !f.Applied {
			sm.PendingConfirmation++
		}
		if f.Applied {
			sm.Applied++
		}
	}
	return sm
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *Service) storeEvidence(job *Job, sc Scope) {
	if s.evidence == nil {
		return
	}
	type fRef struct {
		Key        string  `json:"key"`
		Change     string  `json:"change"`
		Confidence float64 `json:"confidence"`
		Applied    bool    `json:"applied"`
	}
	refs := make([]fRef, 0, len(job.Findings))
	for _, f := range job.Findings {
		refs = append(refs, fRef{f.Key, f.Change, f.Confidence, f.Applied})
	}
	body, _ := json.Marshal(map[string]any{
		"job_id": job.ID, "tenant_id": job.TenantID, "created_by": job.CreatedBy, "created_at": job.CreatedAt,
		"started_at": job.StartedAt, "finished_at": job.FinishedAt, "status": job.Status,
		"scope":   map[string]any{"id": sc.ID, "name": sc.Name, "ranges": sc.Ranges, "methods": sc.Methods, "limits": sc.Limits, "approved_by": sc.ApprovedBy, "approved_at": sc.ApprovedAt, "valid_until": sc.ValidUntil},
		"targets": job.Targets, "results": job.Results, "findings": refs, "summary": summarize(job.Findings),
	})
	id, digest, err := s.evidence.Store(job.TenantID, "compliance", "discovery_job:"+job.ID, body, false)
	if err != nil {
		slog.Error("discovery: evidence store failed", "job_id", job.ID, "error", err)
		return
	}
	job.EvidenceID, job.Digest = id, digest
}

// ------------------------------------------------------------------ подтверждение

// ConfirmInput — тело POST /jobs/{id}/confirm.
type ConfirmInput struct {
	Keys []string `json:"keys"`
}

// Confirm — человек подтверждает объекты с низким confidence → CMDB.
func (s *Service) Confirm(a identity.Actor, jobID string, in ConfirmInput) (*Job, error) {
	if err := httpapi.RequireHuman(a); err != nil {
		return nil, err
	}
	if err := httpapi.RequireAny(a, identity.RoleTenantAdmin, identity.RoleEngineer); err != nil {
		return nil, err
	}
	if len(in.Keys) == 0 || len(in.Keys) > 1000 {
		return nil, invalid("keys", "1..1000 keys required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.repo.GetJob(a.TenantID, jobID)
	if !ok {
		return nil, problem.New(problem.NotFound, "job not found")
	}
	if job.Status != JobCompleted {
		return nil, problem.New(problem.Conflict, "job is not completed")
	}
	idx := map[string]int{}
	for i, f := range job.Findings {
		idx[f.Key] = i
	}
	var confirmed []string
	for _, k := range in.Keys {
		i, ok := idx[k]
		if !ok {
			return nil, invalid("keys", "unknown key %q", truncate(k, 200))
		}
		f := &job.Findings[i]
		if !f.NeedsConfirmation || f.Applied || (f.Change != FindingNew && f.Change != FindingChanged) {
			continue
		}
		if err := s.apply(job.TenantID, f); err != nil {
			return nil, err
		}
		f.ConfirmedBy = a.Ref()
		confirmed = append(confirmed, k)
	}
	s.applyAllDeps(job)
	job.Summary = summarize(job.Findings)
	if err := s.repo.PutJob(job); err != nil {
		return nil, err
	}
	s.auditLog(a.TenantID, a.Ref(), "discovery.confirmed", "discovery_job", jobID, map[string]any{"keys": confirmed})
	if len(confirmed) > 0 && s.OnCMDBChange != nil {
		s.OnCMDBChange()
	}
	return job, nil
}

// sortFindings — детерминированный порядок.
func sortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool { return fs[i].Key < fs[j].Key })
}
