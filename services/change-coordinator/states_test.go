package change

import (
	"testing"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/fsm"
)

func TestMachineMatchesSpec(t *testing.T) {
	// Переходы из §11.1 / Приложения C.8 должны быть разрешены.
	allowed := [][2]fsm.State{
		{Draft, ImpactAssessed}, {ImpactAssessed, RiskAssessed}, {RiskAssessed, Approved}, {RiskAssessed, Rejected},
		{Approved, Scheduled}, {Scheduled, Executing}, {Executing, Verified}, {Verified, Closed},
		{Executing, RolledBack}, {RolledBack, ClosedWithRollback},
		{Executing, CancellationPending}, {CancellationPending, Cancelled}, {CancellationPending, Unknown}, {Unknown, ManualReview},
	}
	for _, p := range allowed {
		if !Machine.Can(p[0], p[1]) {
			t.Errorf("%s -> %s must be allowed", p[0], p[1])
		}
	}
	forbidden := [][2]fsm.State{
		{Draft, Executing}, {WaitingApproval, Executing}, {Proposed, Approved}, {Rejected, Approved},
		{Unknown, Closed}, {Unknown, Verified}, {Cancelled, Executing}, {Executing, Closed},
	}
	for _, p := range forbidden {
		if Machine.Can(p[0], p[1]) {
			t.Errorf("%s -> %s must be forbidden", p[0], p[1])
		}
	}
}

func TestTransitionRequiresReasonAndActor(t *testing.T) {
	if _, err := Machine.Check(Draft, ImpactAssessed, "x", "", time.Now()); err == nil {
		t.Fatal("reason is mandatory")
	}
	if _, err := Machine.Check(Draft, ImpactAssessed, "", "r", time.Now()); err == nil {
		t.Fatal("actor is mandatory")
	}
}

func TestEveryStateReachable(t *testing.T) {
	reached := map[fsm.State]bool{Machine.Initial: true}
	queue := []fsm.State{Machine.Initial}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		for _, n := range Machine.Next(s) {
			if !reached[n] {
				reached[n] = true
				queue = append(queue, n)
			}
		}
	}
	for _, s := range Machine.States() {
		if !reached[s] {
			t.Errorf("state %s is unreachable", s)
		}
	}
}
