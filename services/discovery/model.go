package discovery

import (
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/aitmaganbetov/admintwin/services/inventory"
)

// Limits — лимиты нагрузки Scope Document (§8.1).
type Limits struct {
	MaxSessions int `json:"max_sessions"` // одновременных сессий сбора
	PPS         int `json:"pps"`          // начал сбора в секунду (верхняя граница темпа)
}

// Scope — Scope Document tenant: разрешённые диапазоны, методы, лимиты, ответственный, срок действия.
type Scope struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Name        string     `json:"name"`
	Ranges      []string   `json:"ranges"`
	Methods     []string   `json:"methods"`
	Limits      Limits     `json:"limits"`
	Responsible string     `json:"responsible"`
	ValidUntil  time.Time  `json:"valid_until"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	ApprovedBy  string     `json:"approved_by,omitempty"`
	ApprovedAt  *time.Time `json:"approved_at"`
	Status      string     `json:"status"` // draft | active | expired (вычисляется)
	prefixes    []netip.Prefix
}

// Active — утверждён и в пределах срока действия.
func (s *Scope) Active(now time.Time) bool {
	return s.ApprovedAt != nil && now.Before(s.ValidUntil)
}

func (s *Scope) computeStatus(now time.Time) {
	switch {
	case s.ApprovedAt == nil:
		s.Status = "draft"
	case !now.Before(s.ValidUntil):
		s.Status = "expired"
	default:
		s.Status = "active"
	}
}

// Contains — адрес входит в один из диапазонов scope.
func (s *Scope) Contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range s.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// AllowsMethod — метод разрешён scope.
func (s *Scope) AllowsMethod(m string) bool { return slices.Contains(s.Methods, m) }

// TargetInput — цель задания (тело POST /jobs).
type TargetInput struct {
	Address       string `json:"address"`
	Method        string `json:"method"`
	Port          int    `json:"port,omitempty"`
	CredentialRef string `json:"credential_ref"`
	HostKey       string `json:"host_key,omitempty"`
	TLSServerName string `json:"tls_server_name,omitempty"`
}

// Статусы задания (C.9).
const (
	JobQueued    = "queued"
	JobRunning   = "running"
	JobCompleted = "completed"
	JobFailed    = "failed"
)

// Состояния находки.
const (
	FindingNew       = "new"
	FindingChanged   = "changed"
	FindingMissing   = "missing"
	FindingUnchanged = "unchanged"
)

// Finding — результат reconciliation одного объекта.
type Finding struct {
	Key        string   `json:"key"`    // type|name — стабильный ключ для подтверждения
	Change     string   `json:"change"` // new | changed | missing | unchanged
	AssetID    string   `json:"asset_id,omitempty"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Address    string   `json:"address,omitempty"`
	Method     string   `json:"method,omitempty"`
	Confidence float64  `json:"confidence"`
	Diff       []string `json:"diff,omitempty"`
	// NeedsConfirmation — confidence ниже порога: в CMDB только после подтверждения человеком.
	NeedsConfirmation bool   `json:"needs_confirmation"`
	Applied           bool   `json:"applied"`
	ConfirmedBy       string `json:"confirmed_by,omitempty"`
	// ClassificationIncomplete — environment/criticality/owner/data_class не заданы: execution заблокировано
	// до классификации человеком (§8.3). Discovery эти атрибуты никогда не выставляет.
	ClassificationIncomplete bool     `json:"classification_incomplete"`
	Warnings                 []string `json:"warnings,omitempty"`

	observed inventory.Asset
	deps     []ObservedDependency
}

// TargetResult — итог по цели.
type TargetResult struct {
	Address    string  `json:"address"`
	Method     string  `json:"method"`
	Status     string  `json:"status"` // ok | error
	Error      string  `json:"error,omitempty"`
	Confidence float64 `json:"confidence"`
	Objects    int     `json:"objects"`
}

// Summary — сводка задания.
type Summary struct {
	New                 int `json:"new"`
	Changed             int `json:"changed"`
	Missing             int `json:"missing"`
	Unchanged           int `json:"unchanged"`
	PendingConfirmation int `json:"pending_confirmation"`
	Applied             int `json:"applied"`
}

// Job — discovery job (C.9).
type Job struct {
	ID         string         `json:"id"`
	TenantID   string         `json:"tenant_id"`
	ScopeID    string         `json:"scope_id"`
	Status     string         `json:"status"`
	Targets    []TargetInput  `json:"targets"`
	Results    []TargetResult `json:"results"`
	Findings   []Finding      `json:"findings"`
	Summary    Summary        `json:"summary"`
	CreatedBy  string         `json:"created_by"`
	CreatedAt  time.Time      `json:"created_at"`
	StartedAt  *time.Time     `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at"`
	EvidenceID string         `json:"evidence_id,omitempty"`
	Digest     string         `json:"evidence_digest,omitempty"`
	Error      string         `json:"error,omitempty"`
}

func (j *Job) clone() *Job {
	cp := *j
	cp.Targets = append([]TargetInput(nil), j.Targets...)
	cp.Results = append([]TargetResult(nil), j.Results...)
	cp.Findings = append([]Finding(nil), j.Findings...)
	return &cp
}

// Repository — хранилище scope и заданий (in-memory; PostgreSQL — таблицы discovery_scopes/jobs/findings 0003).
type Repository interface {
	PutScope(s Scope) error
	GetScope(tenantID, id string) (*Scope, bool)
	ListScopes(tenantID string) []Scope
	PutJob(j *Job) error
	GetJob(tenantID, id string) (*Job, bool)
}

// MemoryRepo — in-memory Repository.
type MemoryRepo struct {
	mu     sync.RWMutex
	scopes map[string]Scope
	jobs   map[string]*Job
}

// NewMemoryRepo создаёт хранилище.
func NewMemoryRepo() *MemoryRepo {
	return &MemoryRepo{scopes: map[string]Scope{}, jobs: map[string]*Job{}}
}

// PutScope сохраняет scope.
func (m *MemoryRepo) PutScope(s Scope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scopes[s.ID] = s
	return nil
}

// GetScope — scope tenant.
func (m *MemoryRepo) GetScope(tenantID, id string) (*Scope, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.scopes[id]
	if !ok || s.TenantID != tenantID {
		return nil, false
	}
	return &s, true
}

// ListScopes — scope tenant.
func (m *MemoryRepo) ListScopes(tenantID string) []Scope {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Scope
	for _, s := range m.scopes {
		if s.TenantID == tenantID {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b Scope) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out
}

// PutJob сохраняет задание.
func (m *MemoryRepo) PutJob(j *Job) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs[j.ID] = j.clone()
	return nil
}

// GetJob — задание tenant.
func (m *MemoryRepo) GetJob(tenantID, id string) (*Job, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	if !ok || j.TenantID != tenantID {
		return nil, false
	}
	return j.clone(), true
}
