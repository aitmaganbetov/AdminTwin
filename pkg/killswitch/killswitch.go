// Package killswitch — аварийная остановка уровня tenant и платформы (§11.7).
// Каждое включение увеличивает поколение (fencing token): исполнение, начатое со старым
// токеном, не может начать новые шаги.
package killswitch

import (
	"log/slog"
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
	releases  []func(tenantID string, platform bool)
	// Persist сохраняет изменение (БД). Ошибка не отменяет остановку: она действует локально всегда.
	Persist func(tenantID string, platform bool, st State, generation uint64) error
}

// Record — сохранённое состояние для загрузки и синхронизации реплик.
type Record struct {
	TenantID   string
	Platform   bool
	State      State
	Generation uint64
}

// New создаёт переключатель.
func New() *Switch { return &Switch{tenants: map[string]State{}, gen: map[string]uint64{}} }

// OnActivate регистрирует обработчик (отмена задач, отзыв согласований, cooperative cancellation).
func (s *Switch) OnActivate(f func(tenantID string, platform bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listeners = append(s.listeners, f)
}

// OnRelease регистрирует обработчик снятия остановки (например, разблокировать приём задач в оркестраторе).
func (s *Switch) OnRelease(f func(tenantID string, platform bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releases = append(s.releases, f)
}

// Set включает/выключает переключатель tenant ("" и platform=true — уровень платформы).
func (s *Switch) Set(tenantID string, platform, active bool, actor, reason string) {
	s.set(tenantID, platform, active, actor, reason, true)
}

func (s *Switch) set(tenantID string, platform, active bool, actor, reason string, store bool) {
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
	gen := s.gen[tenantID]
	if platform {
		gen = s.platGen
	}
	persist := s.Persist
	if !store {
		persist = nil
	}
	ls := append([]func(string, bool){}, s.listeners...)
	rs := append([]func(string, bool){}, s.releases...)
	s.mu.Unlock()
	if persist != nil {
		if err := persist(tenantID, platform, st, gen); err != nil {
			slog.Error("kill switch state not persisted (active locally only)", "tenant", tenantID, "platform", platform, "error", err)
		}
	}
	if active {
		for _, f := range ls {
			f(tenantID, platform)
		}
		return
	}
	for _, f := range rs {
		f(tenantID, platform)
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

// Restore применяет сохранённые состояния при старте (до приёма запросов) без вызова обработчиков.
func (s *Switch) Restore(recs []Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range recs {
		if r.Platform {
			s.platform, s.platGen = r.State, max(s.platGen, r.Generation)
		} else {
			s.tenants[r.TenantID] = r.State
			s.gen[r.TenantID] = max(s.gen[r.TenantID], r.Generation)
		}
	}
}

// Sync сверяет локальное состояние с общим хранилищем (другая реплика включила/сняла остановку):
// расхождения применяются локально с вызовом обработчиков, но без повторной записи в хранилище.
func (s *Switch) Sync(recs []Record) {
	for _, r := range recs {
		s.mu.RLock()
		cur := s.tenants[r.TenantID]
		if r.Platform {
			cur = s.platform
		}
		s.mu.RUnlock()
		if cur.Active == r.State.Active {
			continue
		}
		s.set(r.TenantID, r.Platform, r.State.Active, r.State.Actor, r.State.Reason, false)
	}
}
