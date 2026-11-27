// Package killswitch — аварийная остановка уровня tenant и платформы (§11.7).
// Каждое включение увеличивает поколение (fencing token): исполнение, начатое со старым
// токеном, не может начать новые шаги.
package killswitch

import (
	"sync"
	"time"
)

// State — состояние переключателя.
type State struct {
	Active    bool      `json:"active"`
	Reason    string    `json:"reason,omitempty"`
	Actor     string    `json:"actor,omitempty"`
	ChangedAt time.Time `json:"changed_at"`
}

// Switch хранит состояния и поколения.
type Switch struct {
	mu        sync.RWMutex
	platform  State
	tenants   map[string]State
	gen       map[string]uint64 // tenant -> generation
	platGen   uint64
	listeners []func(tenantID string, platform bool)
}

// New создаёт переключатель.
func New() *Switch { return &Switch{tenants: map[string]State{}, gen: map[string]uint64{}} }

// OnActivate регистрирует обработчик (отмена задач, отзыв согласований, cooperative cancellation).
func (s *Switch) OnActivate(f func(tenantID string, platform bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listeners = append(s.listeners, f)
}

// Set включает/выключает переключатель tenant ("" и platform=true — уровень платформы).
func (s *Switch) Set(tenantID string, platform, active bool, actor, reason string) {
	st := State{Active: active, Reason: reason, Actor: actor, ChangedAt: time.Now().UTC()}
	s.mu.Lock()
	if platform {
		s.platform = st
		if active {
			s.platGen++
		}
	} else {
		s.tenants[tenantID] = st
		if active {
			s.gen[tenantID]++
		}
	}
	ls := append([]func(string, bool){}, s.listeners...)
	s.mu.Unlock()
	if active {
		for _, f := range ls {
			f(tenantID, platform)
		}
	}
}

// Active — действует ли остановка для tenant (с учётом уровня платформы).
func (s *Switch) Active(tenantID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.platform.Active || s.tenants[tenantID].Active
}

// Status возвращает состояния tenant и платформы.
func (s *Switch) Status(tenantID string) (tenant, platform State) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tenants[tenantID], s.platform
}

// Token — текущий fencing token tenant.
func (s *Switch) Token(tenantID string) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.gen[tenantID]<<32 | s.platGen
}

// Valid — токен ещё действителен и остановка не активна.
func (s *Switch) Valid(tenantID string, token uint64) bool {
	return !s.Active(tenantID) && s.Token(tenantID) == token
}
