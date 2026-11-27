// Package connectors — композит инфраструктурных коннекторов MVP (§1.4, §14 п.1–4): выбирает коннектор
// по Asset.Connection.Method и предоставляет Gateway движки исполнения и факты, Discovery — сборщики,
// Tool Service — read tools, телеметрии — опрос метрик.
//
// Fail closed: актив без Connection или с неподдерживаемым методом — ошибка; симулятор никогда не
// используется как запасной вариант. Секреты берутся из Vault (Lease для исполнения, read-only учётка
// через discovery.CredentialSource для фактов, инструментов и метрик) и не журналируются.
package connectors

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/aitmaganbetov/admintwin/connectors/db"
	"github.com/aitmaganbetov/admintwin/connectors/docker"
	"github.com/aitmaganbetov/admintwin/connectors/internal/common"
	"github.com/aitmaganbetov/admintwin/connectors/linux"
	"github.com/aitmaganbetov/admintwin/connectors/network"
	"github.com/aitmaganbetov/admintwin/services/discovery"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/inventory"
)

// Ошибки композита.
var (
	ErrNoConnection      = errors.New("asset has no connection descriptor: connectors fail closed")
	ErrUnsupportedMethod = errors.New("operation is not supported for the asset connection method")
	ErrAssetNotFound     = errors.New("asset not found in tenant inventory")
)

// Config — параметры композита.
type Config struct {
	// Inventory — CMDB: Facts получают только tenant_id/asset_id и находят актив здесь. Обязателен.
	Inventory inventory.Repository
	// Credentials — read-only учётки (обычно *vault.Broker). Обязателен.
	Credentials discovery.CredentialSource
	Logger      *slog.Logger
	// FactTimeout — предел одного факта (интерфейс gateway.Facts без контекста). По умолчанию 20 с.
	FactTimeout time.Duration
	// HealthTimeout — HTTP-проверка Asset.HealthEndpoint. По умолчанию 5 с.
	HealthTimeout time.Duration
	// CredentialCacheTTL — кэш read-only учёток в памяти процесса (60 с); отрицательное — без кэша.
	CredentialCacheTTL time.Duration
	// HealthClient — HTTP-клиент проверки здоровья (тесты); по умолчанию — с проверкой TLS и без редиректов.
	HealthClient *http.Client

	Docker   docker.Options
	Linux    linux.Options
	Postgres db.Options
	Forti    network.Options
}

// Set — набор коннекторов.
type Set struct {
	cfg    Config
	log    *slog.Logger
	docker *docker.Connector
	linux  *linux.Connector
	pg     *db.Connector
	forti  *network.Connector
	health *http.Client

	mu    sync.Mutex
	cache map[string]cachedCred
}

type cachedCred struct {
	cred  gateway.Credential
	until time.Time
}

// New создаёт композит.
func New(cfg Config) *Set {
	log := common.Logger(cfg.Logger)
	if cfg.FactTimeout <= 0 {
		cfg.FactTimeout = 20 * time.Second
	}
	if cfg.HealthTimeout <= 0 {
		cfg.HealthTimeout = 5 * time.Second
	}
	if cfg.CredentialCacheTTL == 0 {
		cfg.CredentialCacheTTL = time.Minute
	}
	for _, l := range []**slog.Logger{&cfg.Docker.Logger, &cfg.Linux.Logger, &cfg.Postgres.Logger, &cfg.Forti.Logger} {
		if *l == nil {
			*l = log
		}
	}
	hc := cfg.HealthClient
	if hc == nil {
		hc = &http.Client{
			Timeout:       cfg.HealthTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &Set{cfg: cfg, log: log, docker: docker.New(cfg.Docker), linux: linux.New(cfg.Linux), pg: db.New(cfg.Postgres),
		forti: network.New(cfg.Forti), health: hc, cache: map[string]cachedCred{}}
}

// Methods — поддерживаемые значения Connection.Method.
func (s *Set) Methods() []string {
	return []string{docker.Method, linux.Method, db.Method, network.Method}
}

// --- движки исполнения ---

// Engines — движки для gateway.Gateway.Engines: docker_api, ssh_argv, builtin.
func (s *Set) Engines() map[string]gateway.Engine {
	return map[string]gateway.Engine{
		"docker_api": methodEngine{method: docker.Method, eng: s.docker},
		"ssh_argv":   methodEngine{method: linux.Method, eng: s.linux.ArgvEngine()},
		"builtin":    builtinEngine{s: s},
	}
}

// methodEngine — движок, допускающий только активы с заданным методом подключения.
type methodEngine struct {
	method string
	eng    gateway.Engine
}

func (m methodEngine) Execute(ctx context.Context, req gateway.EngineRequest) (gateway.EngineResult, error) {
	if err := requireMethod(&req.Asset, m.method); err != nil {
		return gateway.EngineResult{}, err
	}
	return m.eng.Execute(ctx, req)
}

// builtinEngine — встроенные действия; MVP: logs_rotate_cleanup поверх SSH.
type builtinEngine struct{ s *Set }

func (b builtinEngine) Execute(ctx context.Context, req gateway.EngineRequest) (gateway.EngineResult, error) {
	switch req.Action {
	case "logs_rotate_cleanup":
		return methodEngine{method: linux.Method, eng: b.s.linux.BuiltinEngine()}.Execute(ctx, req)
	}
	return gateway.EngineResult{}, fmt.Errorf("builtin: unsupported action %q", req.Action)
}

func requireMethod(a *inventory.Asset, method string) error {
	if a == nil || a.Connection == nil || a.Connection.Method == "" {
		return ErrNoConnection
	}
	if a.Connection.Method != method {
		return fmt.Errorf("%w: need %s, asset uses %s", ErrUnsupportedMethod, method, a.Connection.Method)
	}
	return nil
}

// --- учётки ---

// readOnly — read-only учётка актива из Vault (с кратким кэшем). Пустой CredentialRef допустим только
// для Docker через локальный unix-сокет (доступ определяется правами на сокет).
func (s *Set) readOnly(ctx context.Context, a *inventory.Asset) (gateway.Credential, error) {
	ref := a.Connection.CredentialRef
	if ref == "" {
		if a.Connection.Method == docker.Method && isUnixSocket(a.Connection.Address) {
			return gateway.Credential{}, nil
		}
		return gateway.Credential{}, errors.New("asset connection has no credential_ref")
	}
	if s.cfg.Credentials == nil {
		return gateway.Credential{}, errors.New("credential source is not configured: connectors fail closed")
	}
	k := a.TenantID + "|" + ref
	now := time.Now()
	s.mu.Lock()
	if c, ok := s.cache[k]; ok && now.Before(c.until) {
		s.mu.Unlock()
		return c.cred, nil
	}
	s.mu.Unlock()
	dc, err := s.cfg.Credentials.ReadOnly(ctx, a.TenantID, ref)
	if err != nil {
		return gateway.Credential{}, fmt.Errorf("read-only credential unavailable: %w", err)
	}
	cred := common.FromDiscovery(dc)
	if s.cfg.CredentialCacheTTL > 0 {
		s.mu.Lock()
		for key, c := range s.cache {
			if !now.Before(c.until) {
				delete(s.cache, key)
			}
		}
		s.cache[k] = cachedCred{cred: cred, until: now.Add(s.cfg.CredentialCacheTTL)}
		s.mu.Unlock()
	}
	return cred, nil
}

func isUnixSocket(addr string) bool {
	return len(addr) > 0 && (addr[0] == '/' || len(addr) > 7 && addr[:7] == "unix://")
}

// --- Facts ---

// Facts — реализация gateway.Facts поверх CMDB и коннекторов.
func (s *Set) Facts() gateway.Facts { return facts{s} }

type facts struct{ s *Set }

var _ gateway.Facts = facts{}

// resolve — актив tenant с подключением и read-only учёткой.
func (f facts) resolve(ctx context.Context, tenantID, assetID string) (*inventory.Asset, gateway.Credential, error) {
	if f.s.cfg.Inventory == nil {
		return nil, gateway.Credential{}, errors.New("inventory is not configured: connectors fail closed")
	}
	a, ok := f.s.cfg.Inventory.Get(tenantID, assetID)
	if !ok {
		return nil, gateway.Credential{}, ErrAssetNotFound
	}
	if a.Connection == nil || a.Connection.Method == "" {
		return nil, gateway.Credential{}, ErrNoConnection
	}
	cred, err := f.s.readOnly(ctx, a)
	return a, cred, err
}

func (f facts) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), f.s.cfg.FactTimeout)
}

func (f facts) ContainerRunning(tenantID, assetID, containerID string) (bool, error) {
	ctx, cancel := f.ctx()
	defer cancel()
	a, cred, err := f.resolve(ctx, tenantID, assetID)
	if err != nil {
		return false, err
	}
	if err := requireMethod(a, docker.Method); err != nil {
		return false, err
	}
	return f.s.docker.ContainerRunning(ctx, a.Connection, cred, containerID)
}

func (f facts) RestartsLastHour(tenantID, assetID, object string) (int, error) {
	ctx, cancel := f.ctx()
	defer cancel()
	a, cred, err := f.resolve(ctx, tenantID, assetID)
	if err != nil {
		return 0, err
	}
	switch a.Connection.Method {
	case docker.Method:
		return f.s.docker.RestartsLastHour(ctx, a.Connection, cred, object)
	case linux.Method:
		return f.s.linux.RestartsLastHour(ctx, *a, cred, object)
	}
	return 0, ErrUnsupportedMethod
}

func (f facts) UnitActive(tenantID, assetID, unit string) (bool, error) {
	ctx, cancel := f.ctx()
	defer cancel()
	a, cred, err := f.resolve(ctx, tenantID, assetID)
	if err != nil {
		return false, err
	}
	if err := requireMethod(a, linux.Method); err != nil {
		return false, err
	}
	return f.s.linux.UnitActive(ctx, *a, cred, unit)
}

func (f facts) DiskUsagePercent(tenantID, assetID string) (float64, error) {
	ctx, cancel := f.ctx()
	defer cancel()
	a, cred, err := f.resolve(ctx, tenantID, assetID)
	if err != nil {
		return 0, err
	}
	if err := requireMethod(a, linux.Method); err != nil {
		return 0, err
	}
	return f.s.linux.DiskUsagePercent(ctx, *a, cred)
}

func (f facts) LogWritersHealthy(tenantID, assetID string) (bool, error) {
	ctx, cancel := f.ctx()
	defer cancel()
	a, cred, err := f.resolve(ctx, tenantID, assetID)
	if err != nil {
		return false, err
	}
	if err := requireMethod(a, linux.Method); err != nil {
		return false, err
	}
	return f.s.linux.LogWritersHealthy(ctx, *a, cred)
}

// HealthOK — HTTP GET Asset.HealthEndpoint: только 2xx — здоров; редиректы не выполняются;
// http/https; короткий таймаут; тело не читается сверх 64 КиБ. Актив обязан существовать и иметь Connection.
func (f facts) HealthOK(tenantID, assetID, endpoint string) (bool, error) {
	if f.s.cfg.Inventory == nil {
		return false, errors.New("inventory is not configured: connectors fail closed")
	}
	a, ok := f.s.cfg.Inventory.Get(tenantID, assetID)
	if !ok {
		return false, ErrAssetNotFound
	}
	if a.Connection == nil {
		return false, ErrNoConnection
	}
	if endpoint == "" || endpoint != a.HealthEndpoint {
		return false, errors.New("health endpoint does not match the asset inventory record")
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return false, errors.New("health endpoint must be an http(s) URL without credentials")
	}
	ctx, cancel := context.WithTimeout(context.Background(), f.s.cfg.HealthTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", "admintwin-healthcheck")
	resp, err := f.s.health.Do(req)
	if err != nil {
		return false, errors.New("health endpoint unreachable")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

// --- discovery ---

// Collectors — read-only сборщики для ssh, docker_api, postgres, fortigate_api.
func (s *Set) Collectors() []discovery.Collector {
	return []discovery.Collector{s.linux.Collector(), s.docker.Collector(), s.pg.Collector(), s.forti.Collector()}
}
