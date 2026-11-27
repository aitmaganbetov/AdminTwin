// Package approval — единый сервис согласований (§11.1): решения привязаны к ChangeRequest.
// Правила: AI Agent никогда не approver; согласующий не может быть автором; для critical —
// два независимых согласующих (dual control); роли согласующих — по матрице §2.2 / §11.4.
package approval

import (
	"slices"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/policy"
)

// Verdict — решение человека.
type Verdict string

const (
	Approve Verdict = "approve"
	Reject  Verdict = "reject"
)

// Decision — запись решения.
type Decision struct {
	ActorID string    `json:"actor_id"`
	Roles   []string  `json:"roles"`
	Verdict Verdict   `json:"verdict"`
	Comment string    `json:"comment,omitempty"`
	At      time.Time `json:"at"`
}

// Request — то, что нужно знать о change для проверки решения.
type Request struct {
	TenantID  string
	AuthorID  string
	Policy    policy.Decision
	Decisions []Decision
}

// Approvals — число положительных решений.
func (r Request) Approvals() int {
	n := 0
	for _, d := range r.Decisions {
		if d.Verdict == Approve {
			n++
		}
	}
	return n
}

// Satisfied — набрано требуемое число независимых согласований.
func (r Request) Satisfied() bool {
	return r.Policy.RequiredApprovals > 0 && r.Approvals() >= r.Policy.RequiredApprovals
}

// CheckEligible проверяет, может ли субъект принять решение по change.
func CheckEligible(actor identity.Actor, r Request, v Verdict) error {
	if v != Approve && v != Reject {
		return problem.New(problem.BadRequest, "decision must be approve or reject")
	}
	if actor.IsAI() {
		// T-CAP-002: AI не может согласовать (в т.ч. собственный) change.
		return problem.New(problem.SeparationOfDuties, "AI agent is never an approver")
	}
	if actor.Kind != identity.KindUser {
		return problem.New(problem.SeparationOfDuties, "only humans can decide on changes")
	}
	if actor.TenantID != r.TenantID {
		return problem.New(problem.NotFound, "change not found")
	}
	if r.Policy.Outcome != policy.OutcomeRequiresApproval {
		return problem.New(problem.Conflict, "change does not await approval (policy outcome: %s)", r.Policy.Outcome)
	}
	if actor.ID == r.AuthorID {
		return problem.New(problem.SeparationOfDuties, "approver cannot be the author of the request")
	}
	for _, d := range r.Decisions {
		if d.ActorID == actor.ID {
			return problem.New(problem.SeparationOfDuties, "actor has already decided on this change; dual control requires independent approvers")
		}
	}
	allowed := false
	for _, role := range r.Policy.ApproverRoles {
		if !actor.Has(role) {
			continue
		}
		if role == identity.RoleEngineer && r.Policy.EngineerScope != "" && !actor.HasScope(r.Policy.EngineerScope) {
			continue // Engineer согласует только в своей области
		}
		allowed = true
		break
	}
	if !allowed {
		return problem.New(problem.Forbidden, "actor roles are not sufficient to decide on this change (allowed: %v)", roleNames(r.Policy.ApproverRoles))
	}
	return nil
}

func roleNames(rs []identity.Role) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, string(r))
	}
	slices.Sort(out)
	return out
}
