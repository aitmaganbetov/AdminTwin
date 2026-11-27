// Package app собирает ядро AdminTwin из сервисов (используется cmd/admintwin-core и e2e-тестами).
package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"

	"github.com/aitmaganbetov/admintwin/pkg/db"
	"github.com/aitmaganbetov/admintwin/pkg/httpapi"
	"github.com/aitmaganbetov/admintwin/pkg/killswitch"
	"github.com/aitmaganbetov/admintwin/pkg/oidc"
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
	toolsvc "github.com/aitmaganbetov/admintwin/services/tool-service"
)

// Config — параметры сборки.
type Config struct {
	Root         string // корень репозитория (каталоги runbooks/, capabilities/, standards/, ai/tools/)
	FixturesPath string // демо-данные; пусто — без данных
	DevAuth      bool
	// OIDC (пользователи): issuer и audience обязательны вместе.
	OIDCIssuer   string
	OIDCAudience string
	OIDCJWKSURL  string
	// ServiceToken — общий секрет сервисов (оркестратор, сборщики), ≥ 32 символов.
	ServiceToken string
	// DatabaseURL — PostgreSQL; пусто — in-memory (dev/test). Migrate — применить db/migrations при старте.
	DatabaseURL string
	Migrate     bool
	// AuditSigningKey — base64 seed Ed25519 (32 байта) для подписи checkpoint'ов аудита.
	AuditSigningKey string
	// PIIMasterKey — base64 KEK (32 байта) для обёртки ключей ПДн tenant (crypto-shredding).
	PIIMasterKey string
	Simulator    bool
	Version      string
	Logger       *slog.Logger
}

// App — собранное ядро.
type App struct {
	Server      *api.Server
	Coordinator *change.Coordinator
	Inventory   inventory.Repository
	DB          *db.DB
	Tools       *toolsvc.Service
	Registry    *registry.Registry
	Audit       *audit.Log
	AuditPub    ed25519.PublicKey
	Kill        *killswitch.Switch
	Sim         *sim.Infra
	Evidence    evidence.Repository
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

// SetTenant задаёт политику tenant (в режиме БД — сохраняет её).
func (a *App) SetTenant(p policy.TenantPolicy) {
	if err := a.SaveTenant(p); err != nil {
		slog.Error("tenant policy not saved", "tenant", p.TenantID, "error", err)
	}
}

// SaveTenant сохраняет политику tenant (БД — платформенная операция) и обновляет кэш.
func (a *App) SaveTenant(p policy.TenantPolicy) error {
	if !p.Mode.Valid() {
		return fmt.Errorf("invalid autonomy mode %q", p.Mode)
	}
	if a.DB != nil {
		doc, _ := json.Marshal(p)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := a.DB.Platform(ctx, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO tenants (id, name, edition, autonomy_mode, policy) VALUES ($1::uuid, $1::text, 'enterprise', $2, $3)
				ON CONFLICT (id) DO UPDATE SET autonomy_mode = EXCLUDED.autonomy_mode, policy = EXCLUDED.policy`, p.TenantID, string(p.Mode), doc)
			return err
		})
		if err != nil {
			return err
		}
	}
	a.tenantsMu.Lock()
	defer a.tenantsMu.Unlock()
	a.tenants[p.TenantID] = p
	return nil
}

func (a *App) loadTenantsFromDB(ctx context.Context) error {
	return a.DB.Platform(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT id::text, autonomy_mode, policy FROM tenants")
		if err != nil {
			return err
		}
		defer rows.Close()
		a.tenantsMu.Lock()
		defer a.tenantsMu.Unlock()
		for rows.Next() {
			var id, mode string
			var doc []byte
			if err := rows.Scan(&id, &mode, &doc); err != nil {
				return err
			}
			var p policy.TenantPolicy
			_ = json.Unmarshal(doc, &p)
			p.TenantID, p.Mode = id, runbook.Mode(mode)
			if p.ID == "" {
				p.ID = id
			}
			a.tenants[id] = p
		}
		return rows.Err()
	})
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

	a := &App{Kill: killswitch.New(), tenants: map[string]policy.TenantPolicy{}}

	signer, err := signingKey(cfg)
	if err != nil {
		return nil, err
	}
	a.AuditPub = signer.Public().(ed25519.PublicKey)

	if cfg.DatabaseURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		a.DB, err = db.Open(ctx, cfg.DatabaseURL)
		if err != nil {
			return nil, err
		}
		if cfg.Migrate {
			applied, err := a.DB.Migrate(ctx, filepath.Join(cfg.Root, "db", "migrations"))
			if err != nil {
				return nil, err
			}
			if len(applied) > 0 {
				slog.Info("migrations applied", "versions", applied)
			}
		}
		kek, err := decodeKey(cfg.PIIMasterKey, "ADMINTWIN_PII_MASTER_KEY")
		if err != nil {
			if !cfg.DevAuth {
				return nil, err
			}
			slog.Warn("PII master key not set: using an ephemeral key (dev only) — PII in audit becomes unreadable after restart")
			kek = make([]byte, 32)
			_, _ = rand.Read(kek)
		}
		a.Inventory = inventory.NewPGStore(a.DB)
		a.Evidence = evidence.PGStore{DB: a.DB}
		a.Audit = audit.New(audit.PGKeys{DB: a.DB, KEK: kek}, signer).WithStore(audit.PGStore{DB: a.DB})
		if err := a.loadTenantsFromDB(ctx); err != nil {
			return nil, fmt.Errorf("load tenants: %w", err)
		}
	} else {
		a.Inventory = inventory.NewStore()
		a.Evidence = evidence.NewStore()
		a.Audit = audit.New(audit.NewMemoryKeys(), signer)
	}

	if cfg.FixturesPath != "" {
		if err := a.loadFixtures(cfg.FixturesPath); err != nil {
			return nil, fmt.Errorf("fixtures: %w", err)
		}
	}

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
	if a.DB != nil {
		a.Coordinator.Persist = change.PGStore{DB: a.DB}
		n, err := a.Coordinator.Recover()
		if err != nil {
			return nil, fmt.Errorf("recover changes: %w", err)
		}
		if n > 0 {
			slog.Info("changes recovered", "count", n)
		}
	}

	a.Registry = reg
	a.Tools, err = toolsvc.Load(filepath.Join(cfg.Root, "ai", "tools", "read"), a.Inventory, reg.ToolScope, a.Audit)
	if err != nil {
		return nil, fmt.Errorf("tool service: %w", err)
	}

	ac := api.AuthConfig{DevHeaders: cfg.DevAuth, ServiceToken: cfg.ServiceToken}
	if cfg.ServiceToken != "" && len(cfg.ServiceToken) < 32 {
		return nil, fmt.Errorf("ADMINTWIN_SERVICE_TOKEN must be at least 32 characters")
	}
	if cfg.OIDCIssuer != "" {
		v, err := oidc.New(oidc.Config{Issuer: cfg.OIDCIssuer, Audience: cfg.OIDCAudience, JWKSURL: cfg.OIDCJWKSURL})
		if err != nil {
			return nil, err
		}
		ac.OIDC = v
	}
	auth := api.Authenticator(api.DenyAll)
	if ac.OIDC != nil || ac.ServiceToken != "" || ac.DevHeaders {
		auth = api.NewAuthenticator(ac)
	}
	a.Server = &api.Server{
		Auth: auth, Changes: a.Coordinator, Inventory: a.Inventory, Catalog: cat, Registry: reg, Audit: a.Audit,
		Evidence: a.Evidence, Kill: a.Kill, Tenants: a.Tenant, Log: cfg.Logger, StartedAt: time.Now(),
		Version: cfg.Version, Simulator: cfg.Simulator,
		Modules: []httpapi.Module{a.Tools},
	}
	return a, nil
}

// loadFixtures загружает демо-данные (tenants, активы, связи) в выбранное хранилище. Только dev/test.
func (a *App) loadFixtures(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var f struct {
		Tenants      []policy.TenantPolicy  `yaml:"tenants"`
		Assets       []inventory.Asset      `yaml:"assets"`
		Dependencies []inventory.Dependency `yaml:"dependencies"`
	}
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return err
	}
	for _, t := range f.Tenants {
		if _, exists := a.Tenant(t.TenantID); exists && a.DB != nil {
			continue // политика в БД главнее фикстуры
		}
		if err := a.SaveTenant(t); err != nil {
			return err
		}
	}
	for _, as := range f.Assets {
		if err := a.Inventory.Put(as); err != nil {
			return err
		}
	}
	existing := map[string]bool{}
	for t := range a.tenants {
		for _, d := range a.Inventory.Dependencies(t) {
			existing[d.Source+">"+d.Target+">"+d.RelationType] = true
		}
	}
	for _, d := range f.Dependencies {
		if existing[d.Source+">"+d.Target+">"+d.RelationType] {
			continue
		}
		if d.DiscoveredAt.IsZero() {
			d.DiscoveredAt = time.Now().UTC()
		}
		if err := a.Inventory.AddDependency(d); err != nil {
			return err
		}
	}
	return nil
}

func decodeKey(b64, name string) ([]byte, error) {
	if b64 == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	k, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(k) != 32 {
		return nil, fmt.Errorf("%s must be base64 of 32 bytes", name)
	}
	return k, nil
}

// signingKey — ключ подписи checkpoint'ов аудита. Без БД допускается эфемерный (dev/test).
func signingKey(cfg Config) (ed25519.PrivateKey, error) {
	seed, err := decodeKey(cfg.AuditSigningKey, "ADMINTWIN_AUDIT_SIGNING_KEY")
	if err == nil {
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if cfg.DatabaseURL != "" && !cfg.DevAuth {
		return nil, err
	}
	_, priv, gerr := ed25519.GenerateKey(rand.Reader)
	return priv, gerr
}
