package change

import (
	"encoding/json"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/fsm"
	"github.com/aitmaganbetov/admintwin/services/approval"
)

// Persister — постоянное хранилище ChangeRequest.
type Persister interface {
	// Save сохраняет снимок и дописывает новые переходы (с порядковым номером firstSeq) и решения.
	Save(cr *ChangeRequest, newTransitions []fsm.Transition, firstSeq int, newDecisions []approval.Decision) error
	// Recent — платформенная выборка для восстановления: незавершённые и изменённые после since.
	Recent(since time.Time) ([]*ChangeRequest, error)
	Get(tenantID, id string) (*ChangeRequest, bool, error)
	List(tenantID string, limit int) ([]*ChangeRequest, error)
}

// Record — сериализуемая форма ChangeRequest вместе со служебными полями.
type Record struct {
	Change         *ChangeRequest `json:"change"`
	IdemKey        string         `json:"idem_key,omitempty"`
	IdemHash       string         `json:"idem_hash,omitempty"`
	AwaitingWindow bool           `json:"awaiting_window,omitempty"`
}

// ToRecord упаковывает change для хранения.
func ToRecord(cr *ChangeRequest) Record {
	return Record{Change: cr.snapshot(), IdemKey: cr.idemKey, IdemHash: cr.idemHash, AwaitingWindow: cr.awaitingWindow}
}

// FromRecord восстанавливает change.
func FromRecord(r Record) *ChangeRequest {
	cr := r.Change
	cr.idemKey, cr.idemHash, cr.awaitingWindow = r.IdemKey, r.IdemHash, r.AwaitingWindow
	cr.savedTransitions, cr.savedDecisions = len(cr.Transitions), len(cr.Decisions)
	if cr.Decisions == nil {
		cr.Decisions = []approval.Decision{}
	}
	if cr.Executions == nil {
		cr.Executions = []Execution{}
	}
	return cr
}

// MarshalRecord — JSON записи.
func MarshalRecord(cr *ChangeRequest) ([]byte, error) { return json.Marshal(ToRecord(cr)) }

// Terminal — состояние без дальнейших переходов.
func Terminal(s fsm.State) bool { return Machine.Terminal(s) }

// Recover загружает изменения после рестарта. Исполнения, прерванные рестартом, не считаются
// ни успешными, ни отменёнными: unknown → manual_review (§11.7, §17.2). Запланированные, но не
// начатые — отменяются (их нужно предложить заново); ожидающие окна — продолжают ждать.
func (c *Coordinator) Recover() (int, error) {
	if c.Persist == nil {
		return 0, nil
	}
	items, err := c.Persist.Recent(c.now().Add(-25 * time.Hour))
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cr := range items {
		c.changes[cr.ID] = cr
		if cr.idemKey != "" {
			c.idem[cr.TenantID+"|"+string(cr.AuthorKind)+":"+cr.AuthorID+"|"+cr.idemKey] = cr.ID
		}
		const who = "system:change-coordinator"
		switch cr.Status {
		case Executing:
			c.transition(cr, Unknown, who, "core restarted during execution: outcome unknown")
			c.transition(cr, ManualReview, who, "unknown outcome always goes to manual review; operators notified")
			cr.PIRRequired = true
		case CancellationPending:
			c.transition(cr, Unknown, who, "core restarted while cancellation was pending: outcome unknown")
			c.transition(cr, ManualReview, who, "unknown outcome always goes to manual review; operators notified")
			cr.PIRRequired = true
		case Approved:
			c.transition(cr, Cancelled, who, "core restarted before execution was scheduled; propose again")
		case Scheduled:
			if !cr.awaitingWindow {
				c.transition(cr, Cancelled, who, "core restarted before execution started; propose again")
			}
		}
	}
	return len(items), nil
}
