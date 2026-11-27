package docker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aitmaganbetov/admintwin/connectors/internal/testutil"
	"github.com/aitmaganbetov/admintwin/services/discovery"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/inventory"
)

const (
	appID    = "3f2a9c1b7d4e0000000000000000000000000000000000000000000000000001"
	nginxID  = "9b8c7d6e5f4a0000000000000000000000000000000000000000000000000002"
	vaultID  = "0a1b2c3d4e5f0000000000000000000000000000000000000000000000000003"
	tenantID = "11111111-1111-4111-8111-111111111111"
)

// fakeEngine эмулирует Docker Engine API v1.41.
type fakeEngine struct {
	mu        sync.Mutex
	running   map[string]bool
	restarts  []string // пути POST restart
	eventsQ   []url.Values
	events    []map[string]any
	hang      chan struct{} // restart блокируется до закрытия (или отмены запроса)
	dropConn  bool          // restart: соединение рвётся после получения запроса
	statusOut int
}

func newFakeEngine() *fakeEngine {
	return &fakeEngine{running: map[string]bool{appID: true, nginxID: false, vaultID: true}}
}

func (f *fakeEngine) find(ref string) (string, bool) {
	for _, id := range []string{appID, nginxID, vaultID} {
		if ref == id || (len(ref) >= 12 && strings.HasPrefix(id, ref)) || ref == nameOf(id) {
			return id, true
		}
	}
	return "", false
}

func nameOf(id string) string {
	switch id {
	case appID:
		return "app-api"
	case nginxID:
		return "nginx"
	}
	return "vault-agent"
}

func (f *fakeEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/v1.41")
	if p == r.URL.Path {
		http.Error(w, "api version prefix required", 400)
		return
	}
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/restart"):
		id, ok := f.find(strings.TrimSuffix(strings.TrimPrefix(p, "/containers/"), "/restart"))
		f.mu.Lock()
		f.restarts = append(f.restarts, r.URL.Path+"?"+r.URL.RawQuery)
		hang, drop, st := f.hang, f.dropConn, f.statusOut
		f.mu.Unlock()
		if drop {
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			_ = c.Close()
			return
		}
		if hang != nil {
			select {
			case <-hang:
			case <-r.Context().Done():
				return
			}
		}
		if !ok {
			http.Error(w, `{"message":"No such container"}`, 404)
			return
		}
		if st != 0 {
			w.WriteHeader(st)
			return
		}
		f.mu.Lock()
		f.running[id] = true
		f.mu.Unlock()
		w.WriteHeader(204)
	case r.Method == http.MethodGet && p != "/containers/json" && strings.HasPrefix(p, "/containers/") && strings.HasSuffix(p, "/json"):
		id, ok := f.find(strings.TrimSuffix(strings.TrimPrefix(p, "/containers/"), "/json"))
		if !ok {
			http.Error(w, `{"message":"No such container"}`, 404)
			return
		}
		f.mu.Lock()
		run := f.running[id]
		f.mu.Unlock()
		status := "exited"
		if run {
			status = "running"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Id": id, "Name": "/" + nameOf(id), "Image": "sha256:abcdef", "RestartCount": 2,
			"State": map[string]any{"Status": status, "Running": run, "ExitCode": 0, "OOMKilled": false,
				"StartedAt": "2026-11-27T09:00:00.123Z", "FinishedAt": "0001-01-01T00:00:00Z", "Health": map[string]any{"Status": "healthy"}},
			"Config": map[string]any{"Image": "registry.local/app:1.2", "Env": []string{"DB_PASSWORD=supersecret"},
				"Labels": map[string]string{"com.example.team": "web", "auth": "password=hunter2"}},
			"HostConfig":      map[string]any{"RestartPolicy": map[string]any{"Name": "unless-stopped"}},
			"NetworkSettings": map[string]any{"Ports": map[string]any{"80/tcp": []map[string]string{{"HostIp": "0.0.0.0", "HostPort": "8080"}}, "443/tcp": nil}},
		})
	case r.Method == http.MethodGet && p == "/containers/json":
		if r.URL.Query().Get("all") != "1" {
			http.Error(w, "all=1 expected", 400)
			return
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"Id": appID, "Names": []string{"/app-api"}, "State": "running"},
			{"Id": nginxID, "Names": []string{"/nginx"}, "State": "restarting"},
			{"Id": vaultID, "Names": []string{"/vault-agent"}, "State": "running"},
		})
	case r.Method == http.MethodGet && p == "/info":
		_ = json.NewEncoder(w).Encode(map[string]any{"Name": "docker-web-01\n", "ServerVersion": "24.0.7", "OperatingSystem": "Ubuntu 22.04.3 LTS"})
	case r.Method == http.MethodGet && p == "/events":
		f.mu.Lock()
		f.eventsQ = append(f.eventsQ, r.URL.Query())
		evs := f.events
		f.mu.Unlock()
		enc := json.NewEncoder(w)
		for _, e := range evs {
			_ = enc.Encode(e)
		}
	default:
		http.Error(w, "not emulated: "+r.Method+" "+p, 404)
	}
}

type env struct {
	f    *fakeEngine
	srv  *httptest.Server
	conn *inventory.Connection
	cred gateway.Credential
	c    *Connector
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pki := testutil.NewPKI(t)
	f := newFakeEngine()
	srv := httptest.NewUnstartedServer(f)
	srv.TLS = pki.ServerTLS(t, true)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // ожидаемые ошибки рукопожатия в негативных тестах
	srv.StartTLS()
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	cert, key := pki.Client(t)
	pn := 0
	for _, ch := range port {
		pn = pn*10 + int(ch-'0')
	}
	return &env{
		f: f, srv: srv,
		conn: &inventory.Connection{Method: Method, Address: host, Port: pn, TLSServerName: "localhost"},
		cred: gateway.Credential{ClientCert: cert, ClientKey: key, CACert: pki.CAPEM},
		c:    New(Options{Timeout: 2 * time.Second}),
	}
}

func (e *env) asset() inventory.Asset {
	return inventory.Asset{ID: "a0000000-0000-4000-8000-000000000002", TenantID: tenantID, Type: "docker_host", Connection: e.conn,
		Objects: map[string][]string{"container": {"3f2a9c1b7d4e", "9b8c7d6e5f4a", "0a1b2c3d4e5f"}}, Protected: []string{"0a1b2c3d4e5f"}}
}

func (e *env) req(id string) gateway.EngineRequest {
	return gateway.EngineRequest{TenantID: tenantID, AssetID: "a", Asset: e.asset(), Action: "restart",
		Params: map[string]any{"container_id": id}, Lease: gateway.Lease{Handle: "l", ExpiresAt: time.Now().Add(time.Minute), Credential: e.cred}}
}

func TestRestartOverMTLS(t *testing.T) {
	e := newEnv(t)
	out, err := e.c.Execute(context.Background(), e.req("9b8c7d6e5f4a"))
	if err != nil || out.ExitCode != 0 {
		t.Fatalf("restart: %v %+v", err, out)
	}
	if len(e.f.restarts) != 1 || e.f.restarts[0] != "/v1.41/containers/9b8c7d6e5f4a/restart?t=10" {
		t.Fatalf("unexpected engine calls: %v", e.f.restarts)
	}
	ok, err := e.c.ContainerRunning(context.Background(), e.conn, e.cred, "9b8c7d6e5f4a")
	if err != nil || !ok {
		t.Fatalf("post-check running: %v %v", ok, err)
	}
}

func TestRestartRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cases := map[string]gateway.EngineRequest{}
	cases["protected"] = e.req("0a1b2c3d4e5f")
	cases["not in inventory"] = e.req("ffffffffffff")
	cases["bad format"] = e.req("../../info")
	r := e.req("3f2a9c1b7d4e")
	r.Lease.ExpiresAt = time.Now().Add(-time.Second)
	cases["expired lease"] = r
	r = e.req("3f2a9c1b7d4e")
	r.Action = "exec"
	cases["unknown action"] = r
	r = e.req("3f2a9c1b7d4e")
	r.Lease.Credential.ClientCert, r.Lease.Credential.ClientKey = nil, nil
	cases["no client cert"] = r
	r = e.req("3f2a9c1b7d4e")
	r.Lease.Credential.CACert = nil
	cases["untrusted server"] = r
	r = e.req("3f2a9c1b7d4e")
	r.Asset.Connection = &inventory.Connection{Method: Method, Address: "http://127.0.0.1", Port: 2375}
	cases["plain tcp"] = r
	for name, rq := range cases {
		if _, err := e.c.Execute(ctx, rq); err == nil {
			t.Fatalf("%s: expected refusal", name)
		}
	}
	if len(e.f.restarts) != 0 {
		t.Fatalf("no request may reach the engine: %v", e.f.restarts)
	}
	// 404 и 500 демона — провал исполнения (exit code), а не unknown.
	e.f.statusOut = 500
	out, err := e.c.Execute(ctx, e.req("3f2a9c1b7d4e"))
	if err != nil || out.ExitCode != 1 {
		t.Fatalf("engine 500: %v %+v", err, out)
	}
}

func TestRestartCancellationSemantics(t *testing.T) {
	e := newEnv(t)
	// 1. Контекст отменён до отправки — подтверждённая отмена, запрос не ушёл.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.c.Execute(ctx, e.req("3f2a9c1b7d4e")); !errors.Is(err, gateway.ErrCancelConfirmed) {
		t.Fatalf("cancel before send: %v", err)
	}
	if len(e.f.restarts) != 0 {
		t.Fatal("request must not be sent")
	}
	// 2. Запрос принят демоном, ответа нет — отмена НЕ подтверждается (Gateway → unknown).
	e.f.hang = make(chan struct{})
	defer close(e.f.hang)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	_, err := e.c.Execute(ctx2, e.req("3f2a9c1b7d4e"))
	if errors.Is(err, gateway.ErrCancelConfirmed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hang after send must be unknown (ctx error), got %v", err)
	}
	// 3. Канал потерян после отправки — ErrChannelLost.
	e.f.mu.Lock()
	e.f.dropConn = true
	e.f.mu.Unlock()
	if _, err := e.c.Execute(context.Background(), e.req("3f2a9c1b7d4e")); !errors.Is(err, gateway.ErrChannelLost) {
		t.Fatalf("dropped connection: %v", err)
	}
	// 4. Демон недоступен (соединение не установлено) — обычная ошибка: ничего не отправлено.
	e.srv.Close()
	_, err = e.c.Execute(context.Background(), e.req("3f2a9c1b7d4e"))
	if err == nil || errors.Is(err, gateway.ErrChannelLost) || errors.Is(err, gateway.ErrCancelConfirmed) {
		t.Fatalf("connect failure: %v", err)
	}
}

func TestFactsAndInspectTool(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if ok, err := e.c.ContainerRunning(ctx, e.conn, e.cred, "9b8c7d6e5f4a"); err != nil || ok {
		t.Fatalf("stopped container: %v %v", ok, err)
	}
	if ok, err := e.c.ContainerRunning(ctx, e.conn, e.cred, "ffffffffffff"); err != nil || ok {
		t.Fatalf("missing container: %v %v", ok, err)
	}
	now := time.Now()
	e.f.events = []map[string]any{
		{"Type": "container", "Action": "start", "Actor": map[string]any{"ID": appID}},
		{"Type": "container", "Action": "start", "Actor": map[string]any{"ID": appID}},
		{"Type": "container", "Action": "start", "Actor": map[string]any{"ID": nginxID}}, // чужой — отфильтрован клиентом
		{"Type": "container", "Action": "die", "Actor": map[string]any{"ID": appID}},
	}
	n, err := e.c.RestartsLastHour(ctx, e.conn, e.cred, "3f2a9c1b7d4e")
	if err != nil || n != 2 {
		t.Fatalf("restarts: %d %v", n, err)
	}
	q := e.f.eventsQ[0]
	var filters map[string][]string
	_ = json.Unmarshal([]byte(q.Get("filters")), &filters)
	if filters["container"][0] != appID || filters["event"][0] != "start" || q.Get("until") == "" {
		t.Fatalf("events query: %v", q)
	}
	if since := q.Get("since"); since == "" || since > q.Get("until") || since < "1" || now.Unix()-3601 > atoi(since) {
		t.Fatalf("since: %v", q)
	}

	out, err := e.c.Inspect(ctx, e.conn, e.cred, "app-api")
	if err != nil {
		t.Fatal(err)
	}
	testutil.ValidateToolOutput(t, "docker.container.inspect", out)
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "supersecret") || strings.Contains(string(raw), "hunter2") {
		t.Fatalf("env/secrets must not be returned: %s", raw)
	}
	st := out["state"].(map[string]any)
	if out["container"] != "app-api" || st["finished_at"] != nil || st["health"] != "healthy" || st["restart_count"] != 2 {
		t.Fatalf("inspect mapping: %s", raw)
	}
	if _, err := e.c.Inspect(ctx, e.conn, e.cred, "nope"); !errors.Is(err, ErrNoSuchContainer) {
		t.Fatalf("missing: %v", err)
	}
}

func atoi(s string) int64 {
	var n int64
	for _, c := range s {
		n = n*10 + int64(c-'0')
	}
	return n
}

func TestCollectorAndMetrics(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	obs, err := e.c.Collector().Collect(ctx, discovery.Target{TenantID: tenantID, Address: e.conn.Address, Port: e.conn.Port, Method: Method,
		CredentialRef: "kv/data/tenants/x/docker", TLSServerName: "localhost"},
		discovery.Credential{ClientCert: e.cred.ClientCert, ClientKey: e.cred.ClientKey, CACert: e.cred.CACert})
	if err != nil {
		t.Fatal(err)
	}
	a := obs.Assets[0]
	if a.Type != "docker_host" || a.Name != "docker-web-01" || strings.Join(a.Objects["container"], ",") != "0a1b2c3d4e5f,3f2a9c1b7d4e,9b8c7d6e5f4a" {
		t.Fatalf("asset: %+v", a)
	}
	if a.Connection == nil || a.Connection.CredentialRef != "kv/data/tenants/x/docker" || len(obs.Warnings) != 1 {
		t.Fatalf("connection/warnings: %+v %v", a.Connection, obs.Warnings)
	}
	samples, err := e.c.Metrics(ctx, e.asset(), e.cred)
	if err != nil || len(samples) != 6 {
		t.Fatalf("metrics: %v %d", err, len(samples))
	}
	for _, s := range samples {
		if s.TenantID != tenantID || s.Labels["container"] == "" {
			t.Fatalf("sample: %+v", s)
		}
		if s.Metric == "container_up" && s.Labels["container"] == "9b8c7d6e5f4a" && s.Value != 0 {
			t.Fatalf("stopped container must be down: %+v", s)
		}
	}
}

func TestUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "dk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	f := newFakeEngine()
	srv := &http.Server{Handler: f, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	c := New(Options{Timeout: 2 * time.Second})
	for _, addr := range []string{"unix://" + sock, sock} {
		conn := &inventory.Connection{Method: Method, Address: addr}
		ok, err := c.ContainerRunning(context.Background(), conn, gateway.Credential{}, "3f2a9c1b7d4e")
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", addr, ok, err)
		}
	}
	if _, err := c.ContainerRunning(context.Background(), &inventory.Connection{Method: Method, Address: "unix://relative.sock"}, gateway.Credential{}, "x"); err == nil {
		t.Fatal("relative socket path must be rejected")
	}
}
