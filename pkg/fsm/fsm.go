// Package fsm — конечный автомат, заданный данными (Приложение C.10: state machine как данные,
// а не захардкоженный код). Каждый переход фиксируется с actor, причиной и временем.
package fsm

import (
	"fmt"
	"sort"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/problem"
)

// State — состояние автомата.
type State string

// Definition — набор допустимых переходов и терминальных состояний.
type Definition struct {
	Name        string
	Initial     State
	Transitions map[State][]State
}

// Transition — запись журнала переходов.
type Transition struct {
	From          State     `json:"from"`
	To            State     `json:"to"`
	Actor         string    `json:"actor"`
	Reason        string    `json:"reason"`
	At            time.Time `json:"at"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	EvidenceRef   string    `json:"evidence_ref,omitempty"`
}

// Can сообщает, допустим ли переход from → to.
func (d Definition) Can(from, to State) bool {
	for _, s := range d.Transitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Terminal — состояние без исходящих переходов.
func (d Definition) Terminal(s State) bool {
	return len(d.Transitions[s]) == 0
}

// Next возвращает допустимые следующие состояния (отсортированы для детерминизма).
func (d Definition) Next(s State) []State {
	out := append([]State(nil), d.Transitions[s]...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// States возвращает все состояния, упомянутые в определении.
func (d Definition) States() []State {
	seen := map[State]bool{d.Initial: true}
	for from, tos := range d.Transitions {
		seen[from] = true
		for _, t := range tos {
			seen[t] = true
		}
	}
	out := make([]State, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Check проверяет переход и строит запись журнала. Причина обязательна.
func (d Definition) Check(from, to State, actor, reason string, now time.Time) (Transition, error) {
	if reason == "" {
		return Transition{}, problem.New(problem.InvalidTransition, "%s: transition %s -> %s requires a reason", d.Name, from, to)
	}
	if actor == "" {
		return Transition{}, problem.New(problem.InvalidTransition, "%s: transition %s -> %s requires an actor", d.Name, from, to)
	}
	if !d.Can(from, to) {
		return Transition{}, problem.New(problem.InvalidTransition, "%s: transition %s -> %s is not allowed", d.Name, from, to)
	}
	return Transition{From: from, To: to, Actor: actor, Reason: reason, At: now.UTC()}, nil
}

// String — для отладки.
func (t Transition) String() string {
	return fmt.Sprintf("%s -> %s by %s (%s)", t.From, t.To, t.Actor, t.Reason)
}
