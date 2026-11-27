// Package change — Change & Release Coordinator (M27): ChangeRequest — единственная сущность,
// через которую возможна запись в инфраструктуру (§11.1). ExecutionRequest — дочерний объект,
// не существующий без родителя. Создать исполнение в обход Coordinator невозможно.
package change

import "github.com/aitmaganbetov/admintwin/pkg/fsm"

// Состояния ChangeRequest. Базовый автомат — §11.1 / Приложение C.8; расширения
// (waiting_approval, proposed, preflight_failed, compensated, failed) описаны в
// docs/architecture/spec-interpretations.md.
const (
	Draft                  fsm.State = "draft"
	ImpactAssessed         fsm.State = "impact_assessed"
	RiskAssessed           fsm.State = "risk_assessed"
	WaitingApproval        fsm.State = "waiting_approval"
	Proposed               fsm.State = "proposed"
	Approved               fsm.State = "approved"
	Rejected               fsm.State = "rejected"
	Scheduled              fsm.State = "scheduled"
	PreflightFailed        fsm.State = "preflight_failed"
	Executing              fsm.State = "executing"
	Verified               fsm.State = "verified"
	RolledBack             fsm.State = "rolled_back"
	Compensated            fsm.State = "compensated"
	Failed                 fsm.State = "failed"
	CancellationPending    fsm.State = "cancellation_pending"
	Cancelled              fsm.State = "cancelled"
	Unknown                fsm.State = "unknown"
	ManualReview           fsm.State = "manual_review"
	Closed                 fsm.State = "closed"
	ClosedWithRollback     fsm.State = "closed_with_rollback"
	ClosedWithCompensation fsm.State = "closed_with_compensation"
)

// Machine — автомат ChangeRequest.
var Machine = fsm.Definition{
	Name:    "change_request",
	Initial: Draft,
	Transitions: map[fsm.State][]fsm.State{
		Draft:               {ImpactAssessed, Rejected},
		ImpactAssessed:      {RiskAssessed, Rejected},
		RiskAssessed:        {WaitingApproval, Approved, Proposed, Rejected},
		WaitingApproval:     {Approved, Rejected},
		Proposed:            {Closed},
		Approved:            {Scheduled, Cancelled},
		Scheduled:           {Executing, PreflightFailed, Failed, Cancelled},
		Executing:           {Verified, RolledBack, Compensated, Failed, CancellationPending, Unknown},
		CancellationPending: {Cancelled, Unknown},
		Unknown:             {ManualReview},
		ManualReview:        {Closed, ClosedWithCompensation},
		Verified:            {Closed},
		RolledBack:          {ClosedWithRollback},
		Compensated:         {ClosedWithCompensation},
	},
}

// Open — состояния, в которых решение ещё не принято (отзываются kill switch).
func Open(s fsm.State) bool { return s == WaitingApproval || s == Proposed }
