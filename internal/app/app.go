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
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"

	"github.com/aitmaganbetov/admintwin/connectors"
	"github.com/aitmaganbetov/admintwin/connectors/linux"
	"github.com/aitmaganbetov/admintwin/pkg/db"
	"github.com/aitmaganbetov/admintwin/pkg/httpapi"
	"github.com/aitmaganbetov/admintwin/pkg/killswitch"
	"github.com/aitmaganbetov/admintwin/pkg/metrics"
	"github.com/aitmaganbetov/admintwin/pkg/oidc"
	api "github.com/aitmaganbetov/admintwin/services/api-gateway"
	"github.com/aitmaganbetov/admintwin/services/audit"
	registry "github.com/aitmaganbetov/admintwin/services/capability-registry"
	change "github.com/aitmaganbetov/admintwin/services/change-coordinator"
	evidence "github.com/aitmaganbetov/admintwin/services/compliance-evidence"
	"github.com/aitmaganbetov/admintwin/services/discovery"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/runbook"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/sim"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/vault"
	"github.com/aitmaganbetov/admintwin/services/incidents"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	"github.com/aitmaganbetov/admintwin/services/policy"
	"github.com/aitmaganbetov/admintwin/services/telemetry"
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
	// OrchestratorURL — AI-оркестратор (admintwin-orchestrator); пусто — AI-задачи недоступны.
	OrchestratorURL string
	// Телеметрия: VictoriaMetrics + Loki (оба или ни одного — тогда in-memory, §3.5); syslog-приёмник (пусто — выключен).
	VictoriaMetricsURL string
	LokiURL            string
	SyslogAddr         string
	// IncidentAutoTriage — инцидент severity ≥ high сразу triaged и запускает RCA (§17.1 «алерт → RCA < 30 с»).
	IncidentAutoTriage bool
	// Getenv — источник прочих переменных (ретенция, Vault); по умолчанию os.Getenv.
	Getenv    func(string) string
	Simulator bool
	Version   string
	Logger    *slog.Logger
}

// App — собранное ядро.
type App struct {
	Server      *api.Server
	Coordinator *change.Coordinator
	Inventory   inventory.Repository
	DB          *db.DB
	Tools       *toolsvc.Service
	Metrics     *metrics.Registry
	// auditState — результат последней фоновой верификации цепочек.
	auditMu    sync.Mutex
	auditValid map[string]bool
	Telemetry  *telemetry.Service
	Incidents  *incidents.Service
	Discovery  *discovery.Service
	Connectors *connectors.Set
	resolver   *telemetry.InventoryResolver
	syslogAddr string
	// Orchestrator — прокси к AI-оркестратору (nil, если не настроен).
	Orchestrator *api.OrchestratorProxy
	Registry     *registry.Registry
	Audit        *audit.Log
	AuditPub     ed25519.PublicKey
	Kill         *killswitch.Switch
	Sim          *sim.Infra
	Evidence     evidence.Repository
	tenantsMu    sync.RWMutex
	tenants      map[string]policy.TenantPolicy
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

	getenv := cfg.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	gw := &gateway.Gateway{Evidence: a.Evidence, Kill: a.Kill}

	// Vault и коннекторы. Без VAULT_ADDR исполнения невозможны (fail closed), чтение и мониторинг работают (§17.2).
	var creds discovery.CredentialSource = noCredentials{}
	var broker *vault.Broker
	if getenv("VAULT_ADDR") != "" {
		vcfg, err := vault.ConfigFromEnv()
		if err != nil {
			return nil, fmt.Errorf("vault: %w", err)
		}
		vcfg.Logger = cfg.Logger
		if broker, err = vault.New(vcfg); err != nil {
			return nil, fmt.Errorf("vault: %w", err)
		}
		creds = broker
	} else if !cfg.Simulator {
		slog.Warn("VAULT_ADDR is not set: executions are impossible until Vault is configured (read-only mode)")
	}
	var dirs, units []string
	if rb, ok := cat.Get("linux.logs.rotate_cleanup"); ok {
		dirs = rb.Parameters["directory"].Enum
	}
	if rb, ok := cat.Get("linux.service.restart"); ok {
		units = rb.Parameters["unit"].Enum
	}
	a.Connectors = connectors.New(connectors.Config{Inventory: a.Inventory, Credentials: creds, Logger: cfg.Logger,
		Linux: linux.Options{Sudo: getenv("ADMINTWIN_SSH_SUDO") == "true", LogDirectories: dirs, RestartUnits: units}})
	if !cfg.Simulator {
		gw.Engines, gw.Facts = a.Connectors.Engines(), a.Connectors.Facts()
		if broker != nil {
			gw.Broker = broker
		}
	}
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

	if !cfg.Simulator {
		if err := a.Connectors.RegisterTools(a.Tools); err != nil {
			return nil, fmt.Errorf("connector tools: %w", err)
		}
	} else if err := a.Sim.RegisterTools(a.Tools); err != nil {
		return nil, fmt.Errorf("simulator tools: %w", err)
	}

	// Телеметрия (M05).
	retention, err := telemetry.RetentionFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	var store telemetry.Store = telemetry.NewMemoryStore(telemetry.Limits{}, retention)
	if cfg.VictoriaMetricsURL != "" && cfg.LokiURL != "" {
		store = telemetry.Composite{Metrics: &telemetry.VictoriaMetrics{URL: cfg.VictoriaMetricsURL}, Logs: &telemetry.Loki{URL: cfg.LokiURL},
			Events: telemetry.NewMemoryStore(telemetry.Limits{}, retention)}
	} else if cfg.VictoriaMetricsURL != "" || cfg.LokiURL != "" {
		return nil, fmt.Errorf("ADMINTWIN_VICTORIAMETRICS_URL and ADMINTWIN_LOKI_URL must be set together")
	}
	a.Telemetry = telemetry.NewService(store, a.Inventory)
	a.Telemetry.ServiceToken = cfg.ServiceToken
	if err := a.Telemetry.RegisterTools(a.Tools); err != nil {
		return nil, fmt.Errorf("telemetry tools: %w", err)
	}

	// Инциденты (M06/M07).
	var starter incidents.RCAStarter
	var orch *incidents.OrchestratorClient
	if cfg.OrchestratorURL != "" {
		oc, err := incidents.NewOrchestratorClient(cfg.OrchestratorURL, cfg.ServiceToken)
		if err != nil {
			return nil, err
		}
		starter = oc
		orch = oc
	}
	var incRepo incidents.Repository = incidents.NewMemoryRepo()
	if a.DB != nil {
		incRepo = incidents.NewPGRepo(db.AppRole{DB: a.DB})
	}
	a.Incidents = incidents.New(incRepo, a.Inventory, a.Audit, starter, incidents.Config{AutoTriage: cfg.IncidentAutoTriage})
	a.Incidents.ServiceToken = cfg.ServiceToken
	if orch != nil {
		a.Incidents.OnFeedback = func(tenantID, incidentID string, correct bool, cause, actual, summary string) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := orch.PostCase(ctx, tenantID, incidentID, correct, cause, actual, summary); err != nil {
				slog.Warn("RCA case not forwarded to orchestrator", "incident_id", incidentID, "error", err)
			}
		}
	}
	a.Telemetry.Subscriber = a.Incidents
	a.Coordinator.OnLinked = func(tenantID, incidentID, changeID, actor string) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := a.Incidents.LinkChange(ctx, tenantID, incidentID, changeID, actor); err != nil {
			slog.Warn("change not linked to incident", "incident_id", incidentID, "change_id", changeID, "error", err)
		}
	}

	// Discovery (M03).
	a.resolver = telemetry.NewInventoryResolver(a.Inventory, a.TenantIDs)
	a.Discovery = discovery.New(discovery.NewMemoryRepo(), a.Inventory, a.Audit, a.Evidence, creds, discovery.Config{}, a.Connectors.Collectors()...)
	a.Discovery.OnCMDBChange = a.resolver.Invalidate
	a.syslogAddr = cfg.SyslogAddr

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
		Modules: []httpapi.Module{a.Tools, a.Telemetry, a.Incidents, a.Discovery},
	}
	if cfg.Simulator && cfg.DevAuth {
		a.Server.Modules = append(a.Server.Modules, a.Sim) // POST /api/v1/dev/simulator — только dev
	}
	a.Metrics = metrics.New()
	a.Metrics.Help("admintwin_http_requests_total", "HTTP requests by route template and status")
	a.Metrics.Help("admintwin_changes", "Change requests in memory by status")
	a.Metrics.Help("admintwin_audit_chain_valid", "1 if the last verification of the tenant audit hash chain succeeded")
	a.Metrics.GaugeFunc(a.gauges)
	a.Server.Metrics = a.Metrics
	a.Server.SaveTenant = a.SaveTenant
	if a.DB != nil {
		a.Server.Checks = append(a.Server.Checks, api.HealthCheck{Name: "postgresql", Critical: true, Check: func(ctx context.Context) error { return a.DB.Pool.Ping(ctx) }})
	}
	if cfg.OrchestratorURL != "" {
		url := strings.TrimRight(cfg.OrchestratorURL, "/") + "/healthz"
		a.Server.Checks = append(a.Server.Checks, api.HealthCheck{Name: "ai_orchestrator", Check: func(ctx context.Context) error {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			req.Header.Set("X-AdminTwin-Service-Token", cfg.ServiceToken)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				return fmt.Errorf("status %d", resp.StatusCode)
			}
			return nil
		}})
	}
	if cfg.OrchestratorURL != "" {
		a.Orchestrator = &api.OrchestratorProxy{BaseURL: cfg.OrchestratorURL, ServiceToken: cfg.ServiceToken}
		a.Server.Modules = append(a.Server.Modules, a.Orchestrator)
		a.Kill.OnActivate(func(tenantID string, platform bool) { go a.Orchestrator.SetKill(tenantID, platform, true) })
		a.Kill.OnRelease(func(tenantID string, platform bool) { go a.Orchestrator.SetKill(tenantID, platform, false) })
	} else {
		a.Server.Modules = append(a.Server.Modules, &api.OrchestratorProxy{}) // 404 «не настроен», а не 404 маршрута
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

func (a *App) gauges() []metrics.Gauge {
	var out []metrics.Gauge
	for st, n := range a.Coordinator.StatusCounts() {
		out = append(out, metrics.Gauge{Name: "admintwin_changes", Labels: map[string]string{"status": st}, Value: float64(n)})
	}
	_, plat := a.Kill.Status("")
	out = append(out, metrics.Gauge{Name: "admintwin_kill_switch_active", Labels: map[string]string{"scope": "platform"}, Value: b2f(plat.Active)})
	a.tenantsMu.RLock()
	tenants := make([]string, 0, len(a.tenants))
	for t := range a.tenants {
		tenants = append(tenants, t)
	}
	a.tenantsMu.RUnlock()
	active := 0
	for _, t := range tenants {
		if a.Kill.Active(t) {
			active++
		}
	}
	out = append(out, metrics.Gauge{Name: "admintwin_kill_switch_active", Labels: map[string]string{"scope": "tenant"}, Value: float64(active)})
	a.auditMu.Lock()
	for t, ok := range a.auditValid {
		// tenant_id — ограниченное число tenant; для SaaS с тысячами tenant метка заменяется агрегатом.
		out = append(out, metrics.Gauge{Name: "admintwin_audit_chain_valid", Labels: map[string]string{"tenant_id": t}, Value: b2f(ok)})
	}
	a.auditMu.Unlock()
	return out
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// RunBackground — периодические задачи ядра до отмены ctx:
// запуск изменений, дождавшихся maintenance window; верификация hash chain и подписанный checkpoint.
func (a *App) RunBackground(ctx context.Context, tick, auditEvery time.Duration) {
	t := time.NewTicker(tick)
	defer t.Stop()
	au := time.NewTicker(auditEvery)
	defer au.Stop()
	a.VerifyAudit()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.Coordinator.Tick()
		case <-au.C:
			a.VerifyAudit()
		}
	}
}

// VerifyAudit проверяет цепочки всех tenant и сохраняет подписанные checkpoint'ы.
func (a *App) VerifyAudit() {
	a.tenantsMu.RLock()
	tenants := make([]string, 0, len(a.tenants))
	for t := range a.tenants {
		tenants = append(tenants, t)
	}
	a.tenantsMu.RUnlock()
	for _, t := range tenants {
		ok, at, err := a.Audit.VerifyTenant(t)
		if !ok {
			slog.Error("AUDIT CHAIN INTEGRITY FAILURE", "tenant", t, "broken_at_seq", at, "error", err)
		}
		a.auditMu.Lock()
		if a.auditValid == nil {
			a.auditValid = map[string]bool{}
		}
		a.auditValid[t] = ok
		a.auditMu.Unlock()
		if ok && a.DB != nil {
			if cp, err := a.Audit.Checkpoint(t); err == nil && cp.Seq > 0 {
				if err := (audit.PGStore{DB: a.DB}).SaveCheckpoint(cp); err != nil {
					slog.Error("audit checkpoint not saved", "tenant", t, "error", err)
				}
			}
		}
	}
}

// TenantIDs — известные tenant.
func (a *App) TenantIDs() []string {
	a.tenantsMu.RLock()
	defer a.tenantsMu.RUnlock()
	out := make([]string, 0, len(a.tenants))
	for t := range a.tenants {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// StartListeners запускает сетевые приёмники и сборщики: syslog (если задан адрес) и опрос метрик коннекторов.
func (a *App) StartListeners(ctx context.Context, simulator bool) error {
	if a.syslogAddr != "" {
		sys := &telemetry.SyslogReceiver{Addr: a.syslogAddr, Resolver: a.resolver, Ingest: a.Telemetry}
		if err := sys.Start(ctx); err != nil {
			return fmt.Errorf("syslog: %w", err)
		}
	}
	if !simulator {
		go a.Connectors.Poller(a.Telemetry.AsSink(), a.TenantIDs).Run(ctx)
	}
	return nil
}

// noCredentials — источник учёток, когда Vault не настроен: любые запросы отклоняются (fail closed).
type noCredentials struct{}

func (noCredentials) ReadOnly(context.Context, string, string) (discovery.Credential, error) {
	return discovery.Credential{}, fmt.Errorf("vault is not configured")
}
