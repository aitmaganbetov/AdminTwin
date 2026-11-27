// Package app собирает ядро AdminTwin из сервисов (используется cmd/admintwin-core и e2e-тестами).
package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/aitmaganbetov/admintwin/pkg/killswitch"
	api "github.com/aitmaganbetov/admintwin/services/api-gateway"
	"github.com/aitmaganbetov/admintwin/services/audit"
	registry "github.com/aitmaganbetov/admintwin/services/capability-registry"
	change "github.com/aitmaganbetov/admintwin/services/change-coordinator"
	evidence "github.com/aitmaganbetov/admintwin/services/compliance-evidence"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/runbook"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/sim"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	"github.com/aitmaganbetov/admintwin/services/policy"
)

// Config — параметры сборки.
type Config struct {
	Root         string // корень репозитория (каталоги runbooks/, capabilities/, standards/, ai/tools/)
	FixturesPath string // демо-данные; пусто — без данных
	DevAuth      bool
	Simulator    bool
	Version      string
	Logger       *slog.Logger
}

// App — собранное ядро.
type App struct {
	Server      *api.Server
	Coordinator *change.Coordinator
	Inventory   *inventory.Store
	Audit       *audit.Log
	AuditPub    ed25519.PublicKey
	Kill        *killswitch.Switch
	Sim         *sim.Infra
	Evidence    *evidence.Store
	tenantsMu   sync.RWMutex
	tenants     map[string]policy.TenantPolicy
}

// Tenant возвращает политику tenant.
func (a *App) Tenant(id string) (policy.TenantPolicy, bool) {
	a.tenantsMu.RLock()
	defer a.tenantsMu.RUnlock()
	t, ok := a.tenants[id]
	return t, ok
}

// SetTenant задаёт политику tenant (используется тестами и будущим API настроек).
func (a *App) SetTenant(p policy.TenantPolicy) {
	a.tenantsMu.Lock()
	defer a.tenantsMu.Unlock()
	a.tenants[p.TenantID] = p
}

type tenantFixture struct {
	Tenants []policy.TenantPolicy `yaml:"tenants"`
}

// New собирает приложение. Любая ошибка реестров — отказ старта (fail closed).
func New(cfg Config) (*App, error) {
	cat, err := runbook.LoadDir(filepath.Join(cfg.Root, "runbooks", "catalog"))
	if err != nil {
		return nil, fmt.Errorf("runbook catalog: %w", err)
	}
	toolExists := func(name string) bool {
		for _, kind := range []string{"read", "propose"} {
			if _, err := os.Stat(filepath.Join(cfg.Root, "ai", "tools", kind, name+".json")); err == nil {
				return true
			}
		}
		return false
	}
	reg, err := registry.Load(filepath.Join(cfg.Root, "standards", "registry.yaml"), filepath.Join(cfg.Root, "capabilities"),
		registry.Artifacts{Tools: toolExists, Runbooks: func(id string) bool { _, ok := cat.Get(id); return ok }})
	if err != nil {
		return nil, err
	}

	a := &App{Inventory: inventory.NewStore(), Kill: killswitch.New(), Evidence: evidence.NewStore(), tenants: map[string]policy.TenantPolicy{}}
	if cfg.FixturesPath != "" {
		if err := a.Inventory.LoadFixture(cfg.FixturesPath); err != nil {
			return nil, fmt.Errorf("fixtures: %w", err)
		}
		raw, err := os.ReadFile(cfg.FixturesPath)
		if err != nil {
			return nil, err
		}
		var tf tenantFixture
		if err := yaml.Unmarshal(raw, &tf); err != nil {
			return nil, err
		}
		for _, t := range tf.Tenants {
			a.SetTenant(t)
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	a.AuditPub = pub
	a.Audit = audit.New(audit.NewMemoryKeys(), priv)

	gw := &gateway.Gateway{Evidence: a.Evidence, Kill: a.Kill}
	if cfg.Simulator {
		a.Sim = sim.New()
		gw.Engines, gw.Facts, gw.Broker = a.Sim.Engines(), a.Sim, a.Sim
		// Начальное состояние симулятора: все известные объекты запущены, диск заполнен на 50%.
		for tid := range a.tenants {
			for _, as := range a.Inventory.List(tid) {
				a.Sim.SetDisk(as.ID, 50)
				for _, kind := range []string{"container", "systemd_unit"} {
					for _, obj := range as.Objects[kind] {
						a.Sim.SetRunning(as.ID, obj, true)
					}
				}
			}
		}
	}
	// Без симулятора и без коннекторов движков нет: исполнения завершаются отказом (fail closed).
	a.Coordinator = change.New(cat, a.Inventory, policy.Builtin{}, a.Tenant, gw, a.Audit, a.Kill)

	auth := api.DenyAll
	if cfg.DevAuth {
		auth = api.DevHeaderAuth
	}
	a.Server = &api.Server{
		Auth: auth, Changes: a.Coordinator, Inventory: a.Inventory, Catalog: cat, Registry: reg, Audit: a.Audit,
		Evidence: a.Evidence, Kill: a.Kill, Tenants: a.Tenant, Log: cfg.Logger, StartedAt: time.Now(),
		Version: cfg.Version, Simulator: cfg.Simulator,
	}
	return a, nil
}
