package change

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/fsm"
	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/killswitch"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/approval"
	"github.com/aitmaganbetov/admintwin/services/audit"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/runbook"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	"github.com/aitmaganbetov/admintwin/services/policy"
)

// Impact — оценка влияния (§11.2 п.2).
type Impact struct {
	BlastRadius         []inventory.Impacted `json:"blast_radius"`
	AffectedTiers       []int                `json:"affected_service_tiers"`
	MaxCriticality      string               `json:"max_criticality"`
	InMaintenanceWindow bool                 `json:"in_maintenance_window"`
}

// Execution — ExecutionRequest: дочерний объект ChangeRequest, один на runbook-шаг.
type Execution struct {
	ID        string          `json:"id"`
	ChangeID  string          `json:"change_id"`
	TenantID  string          `json:"tenant_id"`
	RunbookID string          `json:"runbook_id"`
	AssetID   string          `json:"asset_id"`
	Status    string          `json:"status"`
	Result    *gateway.Result `json:"result,omitempty"`
	StartedAt time.Time       `json:"started_at"`
}

// ChangeRequest — единая сущность изменения.
type ChangeRequest struct {
	ID             string              `json:"id"`
	TenantID       string              `json:"tenant_id"`
	Type           policy.ChangeType   `json:"type"`
	Status         fsm.State           `json:"status"`
	RunbookID      string              `json:"runbook_id"`
	RunbookVersion string              `json:"runbook_version"`
	RunbookDigest  string              `json:"runbook_digest"`
	Risk           runbook.Risk        `json:"risk"`
	AssetID        string              `json:"asset_id"`
	Params         map[string]any      `json:"params"`
	DryRun         bool                `json:"dry_run"`
	Reason         string              `json:"reason"`
	IncidentID     string              `json:"incident_id,omitempty"`
	AuthorID       string              `json:"author_id"`
	AuthorKind     identity.Kind       `json:"author_kind"`
	Impact         *Impact             `json:"impact,omitempty"`
	Policy         *policy.Decision    `json:"policy,omitempty"`
	Decisions      []approval.Decision `json:"decisions"`
	Executions     []Execution         `json:"executions"`
	Proposals      []string            `json:"follow_up_proposals,omitempty"`
	Transitions    []fsm.Transition    `json:"transitions"`
	PIRRequired    bool                `json:"pir_required"`
	PIRDueAt       *time.Time          `json:"pir_due_at,omitempty"`
	PIR            *PIR                `json:"pir,omitempty"`
	CreatedAt      time.Time           `json:"created_at"`
	UpdatedAt      time.Time           `json:"updated_at"`

	idemKey  string
	idemHash string
	// awaitingWindow — отложено до maintenance window; только такие change запускает Tick.
	awaitingWindow bool
	// Учёт уже сохранённых переходов/решений и последняя ошибка сохранения.
	savedTransitions int
	savedDecisions   int
	persistErr       error
	fence            uint64
	cancel           context.CancelFunc
}

// ProposeInput — запрос на изменение (человек или propose-tool агента).
type ProposeInput struct {
	RunbookID      string            `json:"runbook_id"`
	AssetID        string            `json:"asset_id"`
	Params         map[string]any    `json:"params"`
	Reason         string            `json:"reason"`
	IncidentID     string            `json:"incident_id,omitempty"`
	Type           policy.ChangeType `json:"type,omitempty"`
	DryRun         bool              `json:"dry_run,omitempty"`
	IdempotencyKey string            `json:"-"`
}

// Coordinator связывает Policy → Approval → Gateway → Audit.
type Coordinator struct {
	mu        sync.Mutex
	changes   map[string]*ChangeRequest
	idem      map[string]string // tenant|actor|key -> change id
	wg        sync.WaitGroup
	Catalog   *runbook.Catalog
	Inventory inventory.Repository
	Policy    policy.Engine
	Tenants   func(tenantID string) (policy.TenantPolicy, bool)
	Gateway   *gateway.Gateway
	Audit     *audit.Log
	Kill      *killswitch.Switch
	Now       func() time.Time
	// Persist — постоянное хранилище (PostgreSQL); nil — только память (dev/test).
	Persist Persister
}

// New создаёт координатор и подписывает его на kill switch.
func New(cat *runbook.Catalog, inv inventory.Repository, pe policy.Engine, tenants func(string) (policy.TenantPolicy, bool),
	gw *gateway.Gateway, al *audit.Log, ks *killswitch.Switch) *Coordinator {
	c := &Coordinator{changes: map[string]*ChangeRequest{}, idem: map[string]string{}, Catalog: cat, Inventory: inv,
		Policy: pe, Tenants: tenants, Gateway: gw, Audit: al, Kill: ks}
	if ks != nil {
		ks.OnActivate(c.onKill)
	}
	return c
}

func (c *Coordinator) now() time.Time {
	if c.Now != nil {
		return c.Now().UTC()
	}
	return time.Now().UTC()
}

// Propose создаёт ChangeRequest и проводит его через impact → risk/policy → (approval | auto | proposal).
// Отклонённые политикой запросы сохраняются со статусом rejected (для аудита) и возвращаются вместе с ошибкой.
func (c *Coordinator) Propose(actor identity.Actor, in ProposeInput) (*ChangeRequest, error) {
	if in.Reason == "" {
		return nil, problem.New(problem.BadRequest, "reason is required")
	}
	if in.Type == "" {
		in.Type = policy.ChangeNormal
	}
	if in.Type != policy.ChangeNormal && in.Type != policy.ChangeStandard && in.Type != policy.ChangeEmergency {
		return nil, problem.New(problem.BadRequest, "type must be standard|normal|emergency")
	}
	if actor.Has(identity.RoleViewer) && !actor.HasAny(identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleEngineer, identity.RoleOperator) {
		return nil, problem.New(problem.Forbidden, "viewer cannot propose changes")
	}
	if actor.HasAny(identity.RoleAuditor, identity.RoleComplianceManager) && !actor.HasAny(identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleEngineer, identity.RoleOperator) && !actor.IsAI() {
		return nil, problem.New(problem.Forbidden, "role has no right to propose changes")
	}

	payloadHash := hashPayload(in)
	idemScope := actor.TenantID + "|" + actor.Ref() + "|" + in.IdempotencyKey
	c.mu.Lock()
	if in.IdempotencyKey != "" {
		if id, ok := c.idem[idemScope]; ok {
			cr := c.changes[id]
			defer c.mu.Unlock()
			if cr.idemHash != payloadHash {
				return nil, problem.New(problem.IdempotencyMismatch, "Idempotency-Key already used with a different payload")
			}
			return cr.snapshot(), nil
		}
	}
	c.mu.Unlock()

	tp, ok := c.Tenants(actor.TenantID)
	if !ok {
		return nil, problem.New(problem.PolicyDenied, "tenant policy is not configured")
	}
	if c.Kill != nil && c.Kill.Active(actor.TenantID) {
		return nil, problem.New(problem.KillSwitchActive, "kill switch is active: new changes are rejected")
	}
	rb, ok := c.Catalog.Get(in.RunbookID)
	if !ok {
		return nil, problem.New(problem.NotFound, "runbook %q is not in the catalog", in.RunbookID)
	}
	asset, ok := c.Inventory.Get(actor.TenantID, in.AssetID)
	if !ok {
		return nil, problem.New(problem.NotFound, "asset not found")
	}
	params, err := rb.ValidateParams(in.Params, func(kind, v string) bool { return asset.HasObject(kind, v) })
	if err != nil {
		return nil, err
	}

	now := c.now()
	cr := &ChangeRequest{
		ID: newID(), TenantID: actor.TenantID, Type: in.Type, Status: Draft,
		RunbookID: rb.ID, RunbookVersion: rb.Version, RunbookDigest: rb.Digest, Risk: rb.Risk,
		AssetID: asset.ID, Params: params, DryRun: in.DryRun, Reason: in.Reason, IncidentID: in.IncidentID,
		AuthorID: actor.ID, AuthorKind: actor.Kind, Decisions: []approval.Decision{}, Executions: []Execution{},
		CreatedAt: now, UpdatedAt: now, idemKey: in.IdempotencyKey, idemHash: payloadHash,
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.changes[cr.ID] = cr
	if c.Persist != nil {
		if err := c.persistLocked(cr); err != nil {
			delete(c.changes, cr.ID)
			return nil, fmt.Errorf("persist change: %w", err)
		}
	}
	if in.IdempotencyKey != "" {
		c.idem[idemScope] = cr.ID
	}
	c.audit(cr, actor.Ref(), "change.created", map[string]any{"runbook": rb.ID + "@" + rb.Version, "asset_id": asset.ID, "type": in.Type, "risk": rb.Risk})

	// Impact: blast radius по графу, затронутые service_tier, maintenance window.
	br, _ := c.Inventory.BlastRadius(actor.TenantID, asset.ID, 5)
	imp := &Impact{BlastRadius: br, MaxCriticality: asset.Criticality, InMaintenanceWindow: tp.InMaintenanceWindow(now)}
	tiers := map[int]bool{}
	if asset.ServiceTier != nil {
		tiers[*asset.ServiceTier] = true
	}
	for _, b := range br {
		if b.ServiceTier != nil {
			tiers[*b.ServiceTier] = true
		}
	}
	for t := range tiers {
		imp.AffectedTiers = append(imp.AffectedTiers, t)
	}
	sort.Ints(imp.AffectedTiers)
	cr.Impact = imp
	c.transition(cr, ImpactAssessed, "system:change-coordinator", fmt.Sprintf("blast radius: %d dependent asset(s)", len(br)))

	// Policy.
	dec, perr := c.Policy.Evaluate(policy.Input{
		Actor: actor, Tenant: tp, Asset: asset, Runbook: rb, ChangeType: in.Type,
		KillSwitchActive: c.Kill != nil && c.Kill.Active(actor.TenantID),
		RecentExecutions: c.recentExecutionsLocked(actor.TenantID, rb, asset.ID, now), Now: now,
	})
	cr.Policy = &dec
	if perr != nil {
		c.transition(cr, Rejected, "policy:"+tp.ID, "policy denied: "+perr.Error())
		if p, ok := problem.As(perr); ok {
			p.ChangeID = cr.ID
		}
		return cr.snapshot(), perr
	}
	c.transition(cr, RiskAssessed, "policy:"+tp.ID, fmt.Sprintf("risk=%s outcome=%s", rb.Risk, dec.Outcome))

	if dec.BreakGlass {
		due := now.Add(72 * time.Hour)
		cr.PIRRequired, cr.PIRDueAt = true, &due
	}
	if cr.Type == policy.ChangeNormal {
		cr.PIRRequired = true
	}

	switch dec.Outcome {
	case policy.OutcomeProposalOnly:
		c.transition(cr, Proposed, "policy:"+tp.ID, "mode "+string(tp.Mode)+": proposal only, execution is not permitted")
	case policy.OutcomeRequiresApproval:
		c.transition(cr, WaitingApproval, "policy:"+tp.ID, fmt.Sprintf("%d approval(s) required", dec.RequiredApprovals))
	case policy.OutcomeAutoApproved:
		reason := "standard change auto_ok"
		if dec.BreakGlass {
			reason = "break-glass emergency change by " + actor.Ref()
		} else if tp.Mode == runbook.ModeAutonomous {
			reason = "autonomous mode within policy"
		}
		c.transition(cr, Approved, "policy:"+tp.ID, reason)
		c.scheduleLocked(cr, rb, asset, tp)
	}
	return cr.snapshot(), nil
}

// Decide — решение человека по change (approve/reject).
func (c *Coordinator) Decide(actor identity.Actor, changeID string, v approval.Verdict, comment string) (*ChangeRequest, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cr, ok := c.changes[changeID]
	if !ok || cr.TenantID != actor.TenantID {
		return nil, problem.New(problem.NotFound, "change not found")
	}
	if c.Kill != nil && c.Kill.Active(cr.TenantID) && v == approval.Approve {
		return nil, problem.New(problem.KillSwitchActive, "kill switch is active: approvals are revoked")
	}
	if cr.Status != WaitingApproval {
		if cr.Status == Proposed {
			p := problem.New(problem.PolicyDenied, "change %s is a proposal only (autonomy mode does not permit execution)", cr.ID)
			p.ChangeID = cr.ID
			return nil, p
		}
		return nil, problem.New(problem.Conflict, "change is in state %s, not waiting_approval", cr.Status)
	}
	req := approval.Request{TenantID: cr.TenantID, AuthorID: cr.AuthorID, Policy: *cr.Policy, Decisions: cr.Decisions}
	if err := approval.CheckEligible(actor, req, v); err != nil {
		c.audit(cr, actor.Ref(), "change.decision_refused", map[string]any{"verdict": v, "error": err.Error()})
		if p, ok := problem.As(err); ok {
			p.ChangeID = cr.ID
		}
		return nil, err
	}
	roles := make([]string, 0, len(actor.Roles))
	for _, r := range actor.Roles {
		roles = append(roles, string(r))
	}
	cr.Decisions = append(cr.Decisions, approval.Decision{ActorID: actor.ID, Roles: roles, Verdict: v, Comment: comment, At: c.now()})
	c.audit(cr, actor.Ref(), "approval.decision", map[string]any{"verdict": v})

	if v == approval.Reject {
		c.transition(cr, Rejected, actor.Ref(), "rejected by approver")
		return cr.snapshot(), nil
	}
	req.Decisions = cr.Decisions
	if !req.Satisfied() {
		c.touch(cr)
		return cr.snapshot(), nil
	}
	c.transition(cr, Approved, actor.Ref(), fmt.Sprintf("%d/%d approvals", req.Approvals(), cr.Policy.RequiredApprovals))
	rb, _ := c.Catalog.Get(cr.RunbookID)
	asset, ok := c.Inventory.Get(cr.TenantID, cr.AssetID)
	tp, _ := c.Tenants(cr.TenantID)
	if !ok || rb == nil || rb.Digest != cr.RunbookDigest {
		c.transition(cr, Cancelled, "system:change-coordinator", "runbook or asset changed after approval")
		return cr.snapshot(), nil
	}
	c.scheduleLocked(cr, rb, asset, tp)
	return cr.snapshot(), nil
}

// Cancel — отмена change пользователем (cooperative cancellation для исполняемых).
func (c *Coordinator) Cancel(actor identity.Actor, changeID, reason string) (*ChangeRequest, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cr, ok := c.changes[changeID]
	if !ok || cr.TenantID != actor.TenantID {
		return nil, problem.New(problem.NotFound, "change not found")
	}
	if reason == "" {
		reason = "cancelled by " + actor.Ref()
	}
	if err := c.cancelLocked(cr, actor.Ref(), reason); err != nil {
		return nil, err
	}
	return cr.snapshot(), nil
}

func (c *Coordinator) cancelLocked(cr *ChangeRequest, actor, reason string) error {
	switch cr.Status {
	case WaitingApproval:
		c.transition(cr, Rejected, actor, "approval revoked: "+reason)
	case Proposed:
		c.transition(cr, Closed, actor, "proposal dismissed: "+reason)
	case Approved, Scheduled:
		c.transition(cr, Cancelled, actor, reason)
	case Executing:
		c.transition(cr, CancellationPending, actor, reason)
		if cr.cancel != nil {
			cr.cancel()
		}
	default:
		return problem.New(problem.Conflict, "change in state %s cannot be cancelled", cr.Status)
	}
	return nil
}

// onKill — реакция на kill switch: открытые согласования отзываются, исполнения получают
// cooperative cancellation. Успех остановки не утверждается без подтверждения.
func (c *Coordinator) onKill(tenantID string, platform bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cr := range c.changes {
		if !platform && cr.TenantID != tenantID {
			continue
		}
		switch cr.Status {
		case WaitingApproval, Proposed, Approved, Scheduled, Executing:
			_ = c.cancelLocked(cr, "system:kill-switch", "kill switch activated")
		}
	}
}

// Tick запускает отложенные изменения, когда наступило maintenance window.
func (c *Coordinator) Tick() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cr := range c.changes {
		if cr.Status != Scheduled || !cr.awaitingWindow {
			continue // уже исполняется (идёт preflight) или не ждёт окна
		}
		tp, _ := c.Tenants(cr.TenantID)
		if tp.InMaintenanceWindow(c.now()) {
			rb, _ := c.Catalog.Get(cr.RunbookID)
			asset, ok := c.Inventory.Get(cr.TenantID, cr.AssetID)
			if ok && rb != nil {
				cr.awaitingWindow = false
				c.startLocked(cr, rb, asset, tp)
			}
		}
	}
}

func (c *Coordinator) scheduleLocked(cr *ChangeRequest, rb *runbook.Spec, asset *inventory.Asset, tp policy.TenantPolicy) {
	c.transition(cr, Scheduled, "system:change-coordinator", "scheduled")
	if cr.Policy.RequiresMaintenanceWindow && !tp.InMaintenanceWindow(c.now()) {
		cr.awaitingWindow = true
		return // ждёт окна; Tick() запустит
	}
	c.startLocked(cr, rb, asset, tp)
}

// startLocked создаёт ExecutionRequest и запускает Gateway асинхронно.
func (c *Coordinator) startLocked(cr *ChangeRequest, rb *runbook.Spec, asset *inventory.Asset, tp policy.TenantPolicy) {
	if c.Kill != nil && c.Kill.Active(cr.TenantID) {
		c.transition(cr, Cancelled, "system:kill-switch", "kill switch active")
		return
	}
	if cr.persistErr != nil {
		// Не исполняем то, что не смогли надёжно зафиксировать (fail closed).
		c.transition(cr, Failed, "system:change-coordinator", "change state could not be persisted: execution refused")
		return
	}
	ex := Execution{ID: newID(), ChangeID: cr.ID, TenantID: cr.TenantID, RunbookID: rb.ID, AssetID: asset.ID, Status: "preflight", StartedAt: c.now()}
	cr.Executions = append(cr.Executions, ex)
	idx := len(cr.Executions) - 1
	var fence uint64
	if c.Kill != nil {
		fence = c.Kill.Token(cr.TenantID)
	}
	cr.fence = fence
	ctx, cancel := context.WithCancel(context.Background())
	cr.cancel = cancel
	approvers := make([]string, 0, len(cr.Decisions))
	for _, d := range cr.Decisions {
		if d.Verdict == approval.Approve {
			approvers = append(approvers, d.ActorID)
		}
	}
	if len(approvers) == 0 {
		approvers = append(approvers, "policy:"+cr.Policy.PolicyID)
	}
	req := gateway.Request{
		ChangeID: cr.ID, ExecutionID: ex.ID, TenantID: cr.TenantID, Asset: *asset, Runbook: rb,
		Params: cr.Params, FencingToken: fence, DryRun: cr.DryRun, InWindow: tp.InMaintenanceWindow(c.now()),
		ApprovedBy: approvers, OnExecuteStart: func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if cr.Status == Scheduled {
				c.transition(cr, Executing, "service:execution-gateway", "preflight passed, executing "+rb.Execute.Action)
				cr.Executions[idx].Status = "executing"
			}
		},
	}
	c.audit(cr, "system:change-coordinator", "execution.requested", map[string]any{"execution_id": ex.ID, "runbook": rb.ID + "@" + rb.Version, "approved_by": approvers})
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer cancel()
		res := c.Gateway.Run(ctx, req)
		c.complete(cr, idx, rb, res)
	}()
}

func (c *Coordinator) complete(cr *ChangeRequest, idx int, rb *runbook.Spec, res gateway.Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cr.Executions[idx].Status = string(res.Status)
	r := res
	cr.Executions[idx].Result = &r
	cr.Proposals = append(cr.Proposals, res.Proposals...)
	gw := "service:execution-gateway"
	c.audit(cr, gw, "execution.completed", map[string]any{"execution_id": res.ExecutionID, "status": res.Status, "evidence_id": res.EvidenceID, "digest": res.Digest})

	switch cr.Status {
	case Cancelled:
		return // отменено до запуска движка
	case CancellationPending:
		if res.Status == gateway.StatusCancelled {
			c.transition(cr, Cancelled, gw, "cancellation confirmed")
			return
		}
		// Отмена не подтверждена: успех остановки не утверждаем.
		c.transition(cr, Unknown, gw, fmt.Sprintf("cancellation not confirmed (engine result: %s)", res.Status))
		c.transition(cr, ManualReview, "system:change-coordinator", "unknown outcome always goes to manual review; operators notified")
		cr.PIRRequired = true
		return
	}

	switch res.Status {
	case gateway.StatusPreflightFailed:
		if cr.Status == Scheduled {
			c.transition(cr, PreflightFailed, gw, "preflight failed: "+lastFailure(res))
		}
	case gateway.StatusVerified, gateway.StatusDryRun:
		c.transition(cr, Verified, gw, "post-check passed")
		c.transition(cr, Closed, "system:change-coordinator", "verified")
	case gateway.StatusPostCheckFailed:
		c.finishFailure(cr, rb, gw, "post-check failed: "+lastFailure(res))
	case gateway.StatusFailed:
		if cr.Status == Scheduled {
			c.transition(cr, Failed, gw, "execution not started: "+lastFailure(res))
		} else {
			c.finishFailure(cr, rb, gw, "execution failed: "+lastFailure(res))
		}
	case gateway.StatusCancelled:
		switch cr.Status {
		case Executing:
			c.transition(cr, CancellationPending, gw, "cancellation requested")
			c.transition(cr, Cancelled, gw, "cancellation confirmed")
		case Scheduled:
			c.transition(cr, Cancelled, gw, "cancelled before execution")
		}
	case gateway.StatusUnknown:
		if cr.Status == Scheduled {
			c.transition(cr, Executing, gw, "engine invoked")
		}
		c.transition(cr, Unknown, gw, "outcome unknown: "+lastFailure(res))
		c.transition(cr, ManualReview, "system:change-coordinator", "unknown outcome always goes to manual review; operators notified")
		cr.PIRRequired = true
	}
}

func (c *Coordinator) finishFailure(cr *ChangeRequest, rb *runbook.Spec, actor, reason string) {
	cr.PIRRequired = true
	if rb.Reversible() {
		c.transition(cr, RolledBack, actor, reason+"; rollback via "+rb.Rollback)
		c.transition(cr, ClosedWithRollback, "system:change-coordinator", "closed with rollback; PIR required")
		return
	}
	c.transition(cr, Compensated, actor, reason+"; compensation executed")
	c.transition(cr, ClosedWithCompensation, "system:change-coordinator", "closed with compensation; PIR required")
}

func lastFailure(r gateway.Result) string {
	for i := len(r.Steps) - 1; i >= 0; i-- {
		if !r.Steps[i].OK && !r.Steps[i].Skipped {
			return r.Steps[i].Phase + "/" + r.Steps[i].Name + ": " + r.Steps[i].Detail
		}
	}
	return string(r.Status)
}

// PIR — post-implementation review.
type PIR struct {
	Summary           string    `json:"summary"`
	Findings          string    `json:"findings,omitempty"`
	CorrectiveActions []string  `json:"corrective_actions,omitempty"`
	ReviewedBy        string    `json:"reviewed_by"`
	ReviewedAt        time.Time `json:"reviewed_at"`
	Overdue           bool      `json:"overdue"`
}

// RecordPIR фиксирует PIR для завершённого изменения. Ревьюер не может быть автором.
func (c *Coordinator) RecordPIR(actor identity.Actor, changeID string, p PIR) (*ChangeRequest, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cr, ok := c.changes[changeID]
	if !ok || cr.TenantID != actor.TenantID {
		return nil, problem.New(problem.NotFound, "change not found")
	}
	if !Terminal(cr.Status) && cr.Status != ManualReview {
		return nil, problem.New(problem.Conflict, "PIR is recorded after the change has finished (state %s)", cr.Status)
	}
	if cr.AuthorID == actor.ID {
		return nil, problem.New(problem.SeparationOfDuties, "the author of a change cannot review it")
	}
	if cr.PIR != nil {
		return nil, problem.New(problem.Conflict, "PIR already recorded")
	}
	now := c.now()
	p.ReviewedBy, p.ReviewedAt = actor.Ref(), now
	p.Overdue = cr.PIRDueAt != nil && now.After(*cr.PIRDueAt)
	cr.PIR = &p
	c.touch(cr)
	c.audit(cr, actor.Ref(), "change.pir_recorded", map[string]any{"overdue": p.Overdue, "corrective_actions": len(p.CorrectiveActions)})
	if cr.Status == ManualReview {
		next := Closed
		if len(cr.Executions) > 0 {
			next = ClosedWithCompensation
		}
		c.transition(cr, next, actor.Ref(), "manual review completed with PIR")
	}
	return cr.snapshot(), nil
}

// StatusCounts — число изменений по статусам (meta-monitoring, без разбивки по tenant).
func (c *Coordinator) StatusCounts() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]int{}
	for _, cr := range c.changes {
		out[string(cr.Status)]++
	}
	return out
}

// Wait ожидает завершения всех асинхронных исполнений (тесты, graceful shutdown).
func (c *Coordinator) Wait() { c.wg.Wait() }

// Get возвращает снимок change tenant.
func (c *Coordinator) Get(tenantID, id string) (*ChangeRequest, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cr, ok := c.changes[id]
	if !ok && c.Persist != nil {
		if p, found, err := c.Persist.Get(tenantID, id); err == nil && found {
			return p, true
		}
	}
	if !ok || cr.TenantID != tenantID {
		return nil, false
	}
	return cr.snapshot(), true
}

// List — изменения tenant (новые первыми).
func (c *Coordinator) List(tenantID string) []*ChangeRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*ChangeRequest
	seen := map[string]bool{}
	for _, cr := range c.changes {
		if cr.TenantID == tenantID {
			out = append(out, cr.snapshot())
			seen[cr.ID] = true
		}
	}
	if c.Persist != nil {
		if older, err := c.Persist.List(tenantID, 500); err == nil {
			for _, cr := range older {
				if !seen[cr.ID] {
					out = append(out, cr)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Execution возвращает исполнение по id (read-only).
func (c *Coordinator) Execution(tenantID, id string) (*Execution, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cr := range c.changes {
		if cr.TenantID != tenantID {
			continue
		}
		for _, e := range cr.Executions {
			if e.ID == id {
				cp := e
				return &cp, true
			}
		}
	}
	return nil, false
}

func (c *Coordinator) recentExecutionsLocked(tenantID string, rb *runbook.Spec, assetID string, now time.Time) int {
	window := map[string]time.Duration{"minute": time.Minute, "hour": time.Hour, "day": 24 * time.Hour}[rb.Rate.Window]
	n := 0
	for _, cr := range c.changes {
		if cr.TenantID != tenantID || cr.RunbookID != rb.ID {
			continue
		}
		if rb.Rate.Per == "asset" && cr.AssetID != assetID {
			continue
		}
		for _, e := range cr.Executions {
			if e.Status != string(gateway.StatusPreflightFailed) && now.Sub(e.StartedAt) < window {
				n++
			}
		}
	}
	return n
}

func (c *Coordinator) transition(cr *ChangeRequest, to fsm.State, actor, reason string) {
	t, err := Machine.Check(cr.Status, to, actor, reason, c.now())
	if err != nil {
		// Нарушение автомата — ошибка программирования; фиксируем в аудите, состояние не меняем.
		c.audit(cr, actor, "change.invalid_transition", map[string]any{"from": cr.Status, "to": to, "error": err.Error()})
		return
	}
	t.CorrelationID = cr.ID
	cr.Transitions = append(cr.Transitions, t)
	cr.Status = to
	c.touch(cr)
	c.audit(cr, actor, "change."+string(to), map[string]any{"from": t.From, "to": t.To, "reason": reason})
}

func (c *Coordinator) touch(cr *ChangeRequest) {
	cr.UpdatedAt = c.now()
	if c.Persist != nil {
		if err := c.persistLocked(cr); err != nil {
			cr.persistErr = err
			slog.Error("change: persist failed", "change_id", cr.ID, "error", err)
		} else {
			cr.persistErr = nil
		}
	}
}

func (c *Coordinator) persistLocked(cr *ChangeRequest) error {
	nt := cr.Transitions[cr.savedTransitions:]
	nd := cr.Decisions[cr.savedDecisions:]
	if err := c.Persist.Save(cr, nt, cr.savedTransitions, nd); err != nil {
		return err
	}
	cr.savedTransitions = len(cr.Transitions)
	cr.savedDecisions = len(cr.Decisions)
	return nil
}

func (c *Coordinator) audit(cr *ChangeRequest, actor, action string, data map[string]any) {
	if c.Audit == nil {
		return
	}
	if data == nil {
		data = map[string]any{}
	}
	data["runbook_id"] = cr.RunbookID
	data["asset_id"] = cr.AssetID
	if cr.Policy != nil {
		data["policy_id"] = cr.Policy.PolicyID
	}
	_, _ = c.Audit.Append(audit.Record{TenantID: cr.TenantID, Actor: actor, Action: action, ObjectType: "change_request", ObjectID: cr.ID, Data: data})
}

func (cr *ChangeRequest) snapshot() *ChangeRequest {
	b, _ := json.Marshal(cr)
	var out ChangeRequest
	_ = json.Unmarshal(b, &out)
	return &out
}

func hashPayload(in ProposeInput) string {
	b, _ := json.Marshal(in)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
