// Package inventory — минимальный CMDB (M04): активы с обязательными атрибутами
// классификации (§8.3), связи с confidence и blast radius (§8.4). Хранилище tenant-scoped.
package inventory

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Asset — объект инфраструктуры.
type Asset struct {
	ID           string `yaml:"id" json:"id"`
	TenantID     string `yaml:"tenant_id" json:"tenant_id"`
	Name         string `yaml:"name" json:"name"`
	Type         string `yaml:"type" json:"type"` // docker_host, linux_host, firewall, database ...
	Environment  string `yaml:"environment" json:"environment"`
	Ring         string `yaml:"ring,omitempty" json:"ring,omitempty"`
	ServiceTier  *int   `yaml:"service_tier,omitempty" json:"service_tier,omitempty"`
	Criticality  string `yaml:"criticality" json:"criticality"`
	DataClass    string `yaml:"data_class" json:"data_class"`
	LegalHold    bool   `yaml:"legal_hold" json:"legal_hold"`
	Owner        string `yaml:"owner" json:"owner"`
	Verified     bool   `yaml:"verified" json:"verified"`
	Reachability string `yaml:"reachability,omitempty" json:"reachability,omitempty"` // reachable | unreachable
	// ActiveInvestigation — открыт forensic/security case по активу (блокирует очистки).
	ActiveInvestigation bool `yaml:"active_investigation" json:"active_investigation"`
	// HealthEndpoint — опциональная проверка здоровья для post_check.
	HealthEndpoint string `yaml:"health_endpoint,omitempty" json:"health_endpoint,omitempty"`
	// Objects — дочерние объекты по видам: container, systemd_unit, log_directory.
	Objects map[string][]string `yaml:"objects,omitempty" json:"objects,omitempty"`
	// Protected — объекты, которые нельзя трогать автоматикой.
	Protected []string `yaml:"protected,omitempty" json:"protected,omitempty"`
}

// HasObject — существует ли дочерний объект данного вида.
func (a *Asset) HasObject(kind, value string) bool {
	return slices.Contains(a.Objects[kind], value)
}

// IsProtected — объект в защищённом списке.
func (a *Asset) IsProtected(value string) bool { return slices.Contains(a.Protected, value) }

// ClassificationComplete — есть ли атрибуты, обязательные для execution (§8.3).
func (a *Asset) ClassificationComplete() []string {
	var missing []string
	if a.Environment == "" {
		missing = append(missing, "environment")
	}
	if a.Criticality == "" {
		missing = append(missing, "criticality")
	}
	if a.DataClass == "" {
		missing = append(missing, "data_class")
	}
	if a.Owner == "" {
		missing = append(missing, "owner")
	}
	return missing
}

// Dependency — ребро графа: Source зависит от Target.
type Dependency struct {
	TenantID     string    `yaml:"tenant_id" json:"tenant_id"`
	Source       string    `yaml:"source" json:"source"`
	Target       string    `yaml:"target" json:"target"`
	RelationType string    `yaml:"relation_type" json:"relation_type"`
	Confidence   float64   `yaml:"confidence" json:"confidence"`
	VerifiedBy   string    `yaml:"verified_by" json:"verified_by"` // discovery | user | agent
	DiscoveredAt time.Time `yaml:"discovered_at" json:"discovered_at"`
}

// Impacted — элемент blast radius.
type Impacted struct {
	AssetID     string  `json:"asset_id"`
	Name        string  `json:"name"`
	Depth       int     `json:"depth"`
	Confidence  float64 `json:"confidence"`
	ServiceTier *int    `json:"service_tier,omitempty"`
	Criticality string  `json:"criticality"`
}

// Store — in-memory CMDB. Все операции требуют tenant_id.
type Store struct {
	mu     sync.RWMutex
	assets map[string]*Asset // id -> asset
	deps   []Dependency
}

// NewStore создаёт пустое хранилище.
func NewStore() *Store { return &Store{assets: map[string]*Asset{}} }

// Put добавляет или заменяет актив.
func (s *Store) Put(a Asset) error {
	if a.TenantID == "" || a.ID == "" {
		return fmt.Errorf("asset requires id and tenant_id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.assets[a.ID]; ok && cur.TenantID != a.TenantID {
		return fmt.Errorf("asset %s belongs to another tenant", a.ID)
	}
	cp := a
	s.assets[a.ID] = &cp
	return nil
}

// AddDependency добавляет ребро (оба конца — в том же tenant).
func (s *Store) AddDependency(d Dependency) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range []string{d.Source, d.Target} {
		a, ok := s.assets[id]
		if !ok || a.TenantID != d.TenantID {
			return fmt.Errorf("dependency endpoint %s not found in tenant", id)
		}
	}
	s.deps = append(s.deps, d)
	return nil
}

// Get возвращает копию актива tenant; актив другого tenant неотличим от отсутствующего.
func (s *Store) Get(tenantID, id string) (*Asset, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.assets[id]
	if !ok || a.TenantID != tenantID {
		return nil, false
	}
	cp := *a
	return &cp, true
}

// SetLegalHold меняет флаг legal hold.
func (s *Store) SetLegalHold(tenantID, id string, hold bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.assets[id]
	if !ok || a.TenantID != tenantID {
		return false
	}
	a.LegalHold = hold
	return true
}

// List — активы tenant, по имени.
func (s *Store) List(tenantID string) []Asset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Asset
	for _, a := range s.assets {
		if a.TenantID == tenantID {
			out = append(out, *a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Dependencies — рёбра tenant.
func (s *Store) Dependencies(tenantID string) []Dependency {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Dependency
	for _, d := range s.deps {
		if d.TenantID == tenantID {
			out = append(out, d)
		}
	}
	return out
}

// BlastRadius — транзитивно зависимые от актива объекты с весами confidence (§8.4).
// Confidence пути — произведение confidence рёбер; для узла берётся максимум по путям.
func (s *Store) BlastRadius(tenantID, assetID string, maxDepth int) ([]Impacted, error) {
	if maxDepth <= 0 || maxDepth > 5 {
		maxDepth = 5
	}
	if _, ok := s.Get(tenantID, assetID); !ok {
		return nil, fmt.Errorf("asset not found")
	}
	dependents := map[string][]Dependency{} // target -> edges pointing to it
	for _, d := range s.Dependencies(tenantID) {
		dependents[d.Target] = append(dependents[d.Target], d)
	}
	type node struct {
		id    string
		depth int
		conf  float64
	}
	best := map[string]node{}
	queue := []node{{assetID, 0, 1}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.depth >= maxDepth {
			continue
		}
		for _, e := range dependents[cur.id] {
			n := node{e.Source, cur.depth + 1, cur.conf * e.Confidence}
			if n.id == assetID {
				continue
			}
			if prev, ok := best[n.id]; ok && prev.conf >= n.conf {
				continue
			}
			best[n.id] = n
			queue = append(queue, n)
		}
	}
	out := make([]Impacted, 0, len(best))
	for id, n := range best {
		a, _ := s.Get(tenantID, id)
		out = append(out, Impacted{AssetID: id, Name: a.Name, Depth: n.depth, Confidence: round(n.conf), ServiceTier: a.ServiceTier, Criticality: a.Criticality})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Depth != out[j].Depth {
			return out[i].Depth < out[j].Depth
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func round(f float64) float64 { return float64(int(f*1000+0.5)) / 1000 }

// Fixture — формат файла демо-данных.
type Fixture struct {
	Assets       []Asset      `yaml:"assets"`
	Dependencies []Dependency `yaml:"dependencies"`
}

// LoadFixture загружает демо-инвентарь (dev/test). В production данные приходят из discovery.
func (s *Store) LoadFixture(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var f Fixture
	if err := yaml.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parse fixture: %w", err)
	}
	for _, a := range f.Assets {
		if err := s.Put(a); err != nil {
			return err
		}
	}
	for _, d := range f.Dependencies {
		if d.DiscoveredAt.IsZero() {
			d.DiscoveredAt = time.Now().UTC()
		}
		if err := s.AddDependency(d); err != nil {
			return err
		}
	}
	return nil
}
