package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aitmaganbetov/admintwin/connectors/docker"
	"github.com/aitmaganbetov/admintwin/connectors/internal/testutil"
	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/discovery"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/runbook"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	"github.com/aitmaganbetov/admintwin/services/telemetry"
	toolsvc "github.com/aitmaganbetov/admintwin/services/tool-service"
)

const (
	tenantA   = "11111111-1111-4111-8111-111111111111"
	dockerID  = "a0000000-0000-4000-8000-000000000002"
	linuxID   = "a0000000-0000-4000-8000-000000000003"
	bareID    = "a0000000-0000-4000-8000-000000000009"
	appFullID = "3f2a9c1b7d4e0000000000000000000000000000000000000000000000000001"
)

// miniDocker — минимальный Engine API на unix-сокете.
type miniDocker struct {
	mu       sync.Mutex
	running  bool
	restarts int
}

func (d *miniDocker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch p := strings.TrimPrefix(r.URL.Path, "/v1.41"); {
	case r.Method == http.MethodPost && p == "/containers/3f2a9c1b7d4e/restart":
		d.restarts++
		d.running = true
		w.WriteHeader(204)
	case r.Method == http.MethodGet && p == "/containers/json":
		_ = json.NewEncoder(w).Encode([]map[string]any{{"Id": appFullID, "Names": []string{"/app"}, "State": "running"}})
	case r.Method == http.MethodGet && (p == "/containers/3f2a9c1b7d4e/json" || p == "/containers/"+appFullID+"/json" || p == "/containers/app/json"):
		st := "exited"
		if d.running {
			st = "running"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": appFullID, "Name": "/app", "RestartCount": 1,
			"State":  map[string]any{"Status": st, "Running": d.running, "StartedAt": "2026-11-27T07:00:00Z"},
			"Config": map[string]any{"Image": "app:1"}, "HostConfig": map[string]any{"RestartPolicy": map[string]any{"Name": "always"}}})
	case r.Method == http.MethodGet && p == "/events":
		_, _ = w.Write([]byte(`{"Type":"container","Action":"start","Actor":{"ID":"` + appFullID + `"}}` + "\n"))
	default:
		http.Error(w, "not emulated", 404)
	}
}

func startDocker(t *testing.T) (*miniDocker, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ct")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	d := &miniDocker{}
	srv := &http.Server{Handler: d, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return d, "unix://" + sock
}

type fakeCreds struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (f *fakeCreds) ReadOnly(_ context.Context, _, ref string) (discovery.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return discovery.Credential{}, f.err
	}
	return discovery.Credential{Username: "ro", Password: "ro-pass-" + ref}, nil
}

type fakeBroker struct{ revoked int }

func (b *fakeBroker) Lease(_ context.Context, _, _, ref string, ttl time.Duration) (gateway.Lease, error) {
	if ref == "" {
		return gateway.Lease{}, errors.New("empty ref")
	}
	return gateway.Lease{Handle: "lease-1", ExpiresAt: time.Now().Add(ttl)}, nil
}
func (b *fakeBroker) Revoke(context.Context, gateway.Lease) error { b.revoked++; return nil }

type sink struct {
	mu      sync.Mutex
	samples []telemetry.Sample
}

func (s *sink) WriteSamples(_ context.Context, x []telemetry.Sample) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.samples = append(s.samples, x...)
	return nil
}
func (s *sink) WriteLogs(context.Context, []telemetry.LogRecord) error { return nil }
func (s *sink) WriteEvents(context.Context, []telemetry.Event) error   { return nil }

type fixture struct {
	inv    *inventory.Store
	set    *Set
	docker *miniDocker
	creds  *fakeCreds
	health *httptest.Server
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	d, addr := startDocker(t)
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(200)
			return
		}
		http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
	}))
	t.Cleanup(health.Close)
	inv := inventory.NewStore()
	put := func(a inventory.Asset) {
		if err := inv.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	put(inventory.Asset{ID: dockerID, TenantID: tenantA, Name: "docker-web-01", Type: "docker_host", Environment: "production",
		Criticality: "high", DataClass: "confidential", Owner: "web", Verified: true, HealthEndpoint: health.URL + "/healthz",
		Objects:    map[string][]string{"container": {"3f2a9c1b7d4e"}},
		Connection: &inventory.Connection{Method: "docker_api", Address: addr, CredentialRef: "kv/data/tenants/" + tenantA + "/assets/docker"}})
	put(inventory.Asset{ID: bareID, TenantID: tenantA, Name: "bare", Type: "docker_host", Environment: "production", Verified: true,
		Objects: map[string][]string{"container": {"3f2a9c1b7d4e"}, "systemd_unit": {"nginx.service"}}})
	put(inventory.Asset{ID: linuxID, TenantID: tenantA, Name: "app-linux-01", Type: "linux_host", Environment: "production", Verified: true,
		Connection: &inventory.Connection{Method: "ssh", Address: "127.0.0.1", Port: 1}})
	creds := &fakeCreds{}
	return &fixture{inv: inv, docker: d, creds: creds, health: health,
		set: New(Config{Inventory: inv, Credentials: creds, Docker: dockerOpts(), FactTimeout: 3 * time.Second})}
}

func dockerOpts() docker.Options { return docker.Options{Timeout: 2 * time.Second} }

func catalog(t *testing.T) *runbook.Catalog {
	t.Helper()
	cat, err := runbook.LoadDir(filepath.Join(testutil.RepoRoot(), "runbooks", "catalog"))
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

func TestGatewayRunsDockerRestartRunbook(t *testing.T) {
	f := newFixture(t)
	broker := &fakeBroker{}
	gw := &gateway.Gateway{Engines: f.set.Engines(), Facts: f.set.Facts(), Broker: broker}
	rb, _ := catalog(t).Get("docker.container.restart")
	a, _ := f.inv.Get(tenantA, dockerID)
	params, err := rb.ValidateParams(map[string]any{"container_id": "3f2a9c1b7d4e"}, func(k, v string) bool { return a.HasObject(k, v) })
	if err != nil {
		t.Fatal(err)
	}
	res := gw.Run(context.Background(), gateway.Request{ChangeID: "c1", ExecutionID: "e1", TenantID: tenantA, Asset: *a, Runbook: rb, Params: params, InWindow: true})
	if res.Status != gateway.StatusVerified {
		t.Fatalf("status %s, steps %+v", res.Status, res.Steps)
	}
	if f.docker.restarts != 1 || broker.revoked != 1 {
		t.Fatalf("restarts=%d revoked=%d", f.docker.restarts, broker.revoked)
	}
	var sawHealth bool
	for _, s := range res.Steps {
		if s.Name == "health_endpoint_ok" && s.OK && !s.Skipped {
			sawHealth = true
		}
	}
	if !sawHealth {
		t.Fatalf("health endpoint must be checked for real: %+v", res.Steps)
	}

	// Актив без Connection: preflight не проходит (факт недоступен), движок не вызывается; симулятора нет.
	bare, _ := f.inv.Get(tenantA, bareID)
	res = gw.Run(context.Background(), gateway.Request{ChangeID: "c2", ExecutionID: "e2", TenantID: tenantA, Asset: *bare, Runbook: rb, Params: params, InWindow: true})
	if res.Status != gateway.StatusPreflightFailed || f.docker.restarts != 1 {
		t.Fatalf("asset without connection: %s %+v", res.Status, res.Steps)
	}
}

func TestEnginesFailClosed(t *testing.T) {
	f := newFixture(t)
	eng := f.set.Engines()
	bare, _ := f.inv.Get(tenantA, bareID)
	lin, _ := f.inv.Get(tenantA, linuxID)
	lease := gateway.Lease{Handle: "l", ExpiresAt: time.Now().Add(time.Minute)}
	cases := []struct {
		engine string
		req    gateway.EngineRequest
		want   error
	}{
		{"docker_api", gateway.EngineRequest{Asset: *bare, Action: "restart", Params: map[string]any{"container_id": "3f2a9c1b7d4e"}, Lease: lease}, ErrNoConnection},
		{"docker_api", gateway.EngineRequest{Asset: *lin, Action: "restart", Params: map[string]any{"container_id": "3f2a9c1b7d4e"}, Lease: lease}, ErrUnsupportedMethod},
		{"ssh_argv", gateway.EngineRequest{Asset: *bare, Action: "systemctl_restart", Argv: []string{"systemctl", "restart", "nginx.service"}, Lease: lease}, ErrNoConnection},
		{"builtin", gateway.EngineRequest{Asset: *bare, Action: "logs_rotate_cleanup", Lease: lease}, ErrNoConnection},
	}
	for i, c := range cases {
		if _, err := eng[c.engine].Execute(context.Background(), c.req); !errors.Is(err, c.want) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	if _, err := eng["builtin"].Execute(context.Background(), gateway.EngineRequest{Asset: *lin, Action: "shell"}); err == nil {
		t.Fatal("unknown builtin action must fail")
	}
	if _, ok := eng["shell"]; ok {
		t.Fatal("no shell engine may exist")
	}
}

func TestFactsDispatch(t *testing.T) {
	f := newFixture(t)
	fx := f.set.Facts()
	if ok, err := fx.ContainerRunning(tenantA, dockerID, "3f2a9c1b7d4e"); err != nil || ok {
		t.Fatalf("container stopped: %v %v", ok, err)
	}
	if n, err := fx.RestartsLastHour(tenantA, dockerID, "3f2a9c1b7d4e"); err != nil || n != 1 {
		t.Fatalf("restarts: %d %v", n, err)
	}
	if _, err := fx.ContainerRunning(tenantA, bareID, "3f2a9c1b7d4e"); !errors.Is(err, ErrNoConnection) {
		t.Fatalf("no connection: %v", err)
	}
	if _, err := fx.ContainerRunning("22222222-2222-4222-8222-222222222222", dockerID, "3f2a9c1b7d4e"); !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("foreign tenant: %v", err)
	}
	if _, err := fx.UnitActive(tenantA, dockerID, "nginx.service"); !errors.Is(err, ErrUnsupportedMethod) {
		t.Fatalf("unit on docker host: %v", err)
	}
	// ssh-актив без credential_ref — отказ до подключения.
	if _, err := fx.DiskUsagePercent(tenantA, linuxID); err == nil || !strings.Contains(err.Error(), "credential_ref") {
		t.Fatalf("missing credential ref: %v", err)
	}
	// HealthOK: 2xx — да; редирект — нет; endpoint не из CMDB — отказ.
	if ok, err := fx.HealthOK(tenantA, dockerID, f.health.URL+"/healthz"); err != nil || !ok {
		t.Fatalf("health: %v %v", ok, err)
	}
	if _, err := fx.HealthOK(tenantA, dockerID, "http://169.254.169.254/latest/meta-data"); err == nil {
		t.Fatal("endpoint not matching the CMDB record must be refused")
	}
	a, _ := f.inv.Get(tenantA, dockerID)
	a.HealthEndpoint = f.health.URL + "/redirect"
	_ = f.inv.Put(*a)
	if ok, err := fx.HealthOK(tenantA, dockerID, a.HealthEndpoint); err != nil || ok {
		t.Fatalf("redirect must not count as healthy: %v %v", ok, err)
	}
	// Vault недоступен — факты недоступны (fail closed).
	nosrc := New(Config{Inventory: f.inv})
	if _, err := nosrc.Facts().ContainerRunning(tenantA, linuxID, "x"); err == nil {
		t.Fatal("no credential source must fail")
	}
}

func TestCredentialCache(t *testing.T) {
	f := newFixture(t)
	a, _ := f.inv.Get(tenantA, dockerID)
	for i := 0; i < 3; i++ {
		if _, err := f.set.readOnly(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	}
	if f.creds.calls != 1 {
		t.Fatalf("read-only credential must be cached briefly: %d calls", f.creds.calls)
	}
	f.creds.err = errors.New("vault sealed")
	nc := New(Config{Inventory: f.inv, Credentials: f.creds, CredentialCacheTTL: -1})
	if _, err := nc.readOnly(context.Background(), a); err == nil {
		t.Fatal("vault error must propagate")
	}
}

func TestToolsThroughToolService(t *testing.T) {
	f := newFixture(t)
	ts, err := toolsvc.Load(filepath.Join(testutil.RepoRoot(), "ai", "tools", "read"), f.inv, func(string) []string { return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.set.RegisterTools(ts); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"docker.container.inspect", "linux.service.status", "linux.disk.usage", "postgres.activity", "fortigate.policy.status"} {
		found := false
		for _, a := range ts.Available() {
			found = found || a == n
		}
		if !found {
			t.Fatalf("tool %s not registered", n)
		}
	}
	eng := identity.Actor{ID: "eng", Kind: identity.KindUser, TenantID: tenantA, Roles: []identity.Role{identity.RoleEngineer}}
	out, err := ts.Invoke(context.Background(), eng, "docker.container.inspect", map[string]any{"asset_id": dockerID, "container": "app"})
	if err != nil {
		t.Fatal(err)
	}
	if out["data"].(map[string]any)["container"] != "app" {
		t.Fatalf("inspect: %v", out)
	}
	if _, err := ts.Invoke(context.Background(), eng, "docker.container.inspect", map[string]any{"asset_id": dockerID, "container": "missing"}); !problem.Is(err, problem.NotFound) {
		t.Fatalf("missing container: %v", err)
	}
	for _, c := range []struct {
		tool  string
		input map[string]any
	}{
		{"linux.service.status", map[string]any{"asset_id": dockerID, "unit": "nginx.service"}},
		{"docker.container.inspect", map[string]any{"asset_id": bareID, "container": "app"}},
		{"postgres.activity", map[string]any{"asset_id": bareID}},
		{"fortigate.policy.status", map[string]any{"asset_id": linuxID}},
	} {
		if _, err := ts.Invoke(context.Background(), eng, c.tool, c.input); !problem.Is(err, problem.Conflict) {
			t.Fatalf("%s on wrong asset must be refused: %v", c.tool, err)
		}
	}
}

func TestPoller(t *testing.T) {
	f := newFixture(t)
	f.docker.running = true
	sk := &sink{}
	p := f.set.Poller(sk, func() []string { return []string{tenantA} })
	err := p.PollOnce(context.Background())
	// ssh-актив без credential_ref даёт ошибку, docker опрашивается.
	if err == nil {
		t.Fatal("expected error for the ssh asset without credential_ref")
	}
	got := map[string]float64{}
	for _, s := range sk.samples {
		got[s.Metric] = s.Value
		if s.TenantID != tenantA || s.AssetID != dockerID {
			t.Fatalf("sample: %+v", s)
		}
	}
	if got["container_up"] != 1 || got["container_restarts_total"] != 1 {
		t.Fatalf("samples: %+v", sk.samples)
	}
	if len(f.set.Collectors()) != 4 {
		t.Fatal("collectors for ssh, docker_api, postgres, fortigate_api expected")
	}
	methods := map[string]bool{}
	for _, c := range f.set.Collectors() {
		methods[c.Method()] = true
	}
	for _, m := range []string{"ssh", "docker_api", "postgres", "fortigate_api"} {
		if !methods[m] {
			t.Fatalf("collector %s missing", m)
		}
	}
}
