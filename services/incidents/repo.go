package incidents

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/fsm"
	"github.com/aitmaganbetov/admintwin/services/telemetry"
)

// Ошибки репозитория.
var (
	ErrNotFound = errors.New("incident not found")
	ErrConflict = errors.New("incident version conflict")
)

// Filter — фильтр списка.
type Filter struct {
	Status   fsm.State
	Severity telemetry.Severity
	Limit    int
}

// Repository — хранилище инцидентов (in-memory или PostgreSQL). Все методы tenant-scoped:
// инцидент другого tenant неотличим от отсутствующего.
type Repository interface {
	Create(ctx context.Context, inc *Incident) error
	Get(ctx context.Context, tenantID, id string) (*Incident, error)
	// Update сохраняет инцидент, если его версия в хранилище равна inc.Version-1 (оптимистическая блокировка).
	Update(ctx context.Context, inc *Incident) error
	List(ctx context.Context, tenantID string, f Filter) ([]Incident, error)
	// Open — открытые (не resolved/closed) инциденты с активностью не раньше since.
	Open(ctx context.Context, tenantID string, since time.Time) ([]Incident, error)
	AddCandidate(ctx context.Context, c GoldenCandidate) error
	Candidates(ctx context.Context, tenantID string) ([]GoldenCandidate, error)
}

// MemoryRepo — in-memory репозиторий (dev/test).
type MemoryRepo struct {
	mu         sync.RWMutex
	items      map[string]*Incident
	candidates []GoldenCandidate
}

var _ Repository = (*MemoryRepo)(nil)

// NewMemoryRepo создаёт пустой репозиторий.
func NewMemoryRepo() *MemoryRepo { return &MemoryRepo{items: map[string]*Incident{}} }

// Create сохраняет новый инцидент.
func (m *MemoryRepo) Create(_ context.Context, inc *Incident) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.items[inc.ID]; ok {
		return ErrConflict
	}
	m.items[inc.ID] = inc.Clone()
	return nil
}

// Get возвращает копию инцидента tenant.
func (m *MemoryRepo) Get(_ context.Context, tenantID, id string) (*Incident, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	inc, ok := m.items[id]
	if !ok || inc.TenantID != tenantID {
		return nil, ErrNotFound
	}
	return inc.Clone(), nil
}

// Update — с проверкой версии.
func (m *MemoryRepo) Update(_ context.Context, inc *Incident) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.items[inc.ID]
	if !ok || cur.TenantID != inc.TenantID {
		return ErrNotFound
	}
	if cur.Version != inc.Version-1 {
		return ErrConflict
	}
	m.items[inc.ID] = inc.Clone()
	return nil
}

// List — инциденты tenant, новые сначала.
func (m *MemoryRepo) List(_ context.Context, tenantID string, f Filter) ([]Incident, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Incident
	for _, inc := range m.items {
		if inc.TenantID != tenantID {
			continue
		}
		if f.Status != "" && inc.Status != f.Status {
			continue
		}
		if f.Severity != "" && inc.Severity != f.Severity {
			continue
		}
		out = append(out, *inc.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

// Open — открытые инциденты tenant, обновлённые не раньше since.
func (m *MemoryRepo) Open(_ context.Context, tenantID string, since time.Time) ([]Incident, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Incident
	for _, inc := range m.items {
		if inc.TenantID == tenantID && IsOpen(inc.Status) && !inc.UpdatedAt.Before(since) {
			out = append(out, *inc.Clone())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// AddCandidate сохраняет кандидата golden dataset (последний по инциденту замещает предыдущий).
func (m *MemoryRepo) AddCandidate(_ context.Context, c GoldenCandidate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, cur := range m.candidates {
		if cur.TenantID == c.TenantID && cur.IncidentID == c.IncidentID {
			m.candidates[i] = c
			return nil
		}
	}
	m.candidates = append(m.candidates, c)
	return nil
}

// Candidates — кандидаты tenant.
func (m *MemoryRepo) Candidates(_ context.Context, tenantID string) ([]GoldenCandidate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []GoldenCandidate
	for _, c := range m.candidates {
		if c.TenantID == tenantID {
			out = append(out, c)
		}
	}
	return out, nil
}
