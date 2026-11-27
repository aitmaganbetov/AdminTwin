package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
)

const (
	tenant = "11111111-1111-4111-8111-111111111111"
	other  = "22222222-2222-4222-8222-222222222222"
	token  = "hvs.TESTTOKENTESTTOKENTESTTOKEN"
)

// fakeVault — минимальная эмуляция HTTP API Vault/OpenBao.
type fakeVault struct {
	mu       sync.Mutex
	sealed   bool
	secrets  map[string]map[string]any // KV v2: путь без mount/data → data
	dynamic  map[string]map[string]any // database/creds/<role>
	revoked  []string
	logins   int
	requests []string
	tokens   map[string]bool
}

func newFake() *fakeVault {
	return &fakeVault{secrets: map[string]map[string]any{}, dynamic: map[string]map[string]any{}, tokens: map[string]bool{token: true}}
}

func (f *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	if f.sealed {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"errors":["Vault is sealed"]}`))
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	if path == "sys/health" {
		_, _ = w.Write([]byte(`{"initialized":true,"sealed":false}`))
		return
	}
	if path == "auth/approle/login" && r.Method == http.MethodPost {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["role_id"] != "role-1" || body["secret_id"] != "secret-1" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.logins++
		tok := fmt.Sprintf("hvs.approle%d", f.logins)
		f.tokens[tok] = true
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": tok, "lease_duration": 3600}})
		return
	}
	if !f.tokens[r.Header.Get("X-Vault-Token")] {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
		return
	}
	switch {
	case path == "sys/leases/revoke" && r.Method == http.MethodPut:
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.revoked = append(f.revoked, body["lease_id"])
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(path, "kv/data/") && r.Method == http.MethodGet:
		d, ok := f.secrets[strings.TrimPrefix(path, "kv/data/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"lease_id": "", "lease_duration": 0,
			"data": map[string]any{"data": d, "metadata": map[string]any{"version": 3}}})
	case strings.HasPrefix(path, "database/creds/") && r.Method == http.MethodGet:
		role := strings.TrimPrefix(path, "database/creds/")
		d, ok := f.dynamic[role]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"lease_id": "database/creds/" + role + "/abc123", "lease_duration": 30, "renewable": true, "data": d})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func newBroker(t *testing.T, f *fakeVault, mut func(*Config)) (*Broker, *httptest.Server, *bytes.Buffer) {
	t.Helper()
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	logs := &bytes.Buffer{}
	cfg := Config{Addr: srv.URL, Token: token, TenantScoped: true, HTTPClient: srv.Client(), Timeout: 2 * time.Second,
		Logger: slog.New(slog.NewTextHandler(logs, nil))}
	if mut != nil {
		mut(&cfg)
	}
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return b, srv, logs
}

const sshKey = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAsecretkeymaterial\n-----END OPENSSH PRIVATE KEY-----"

func TestLeaseKV2(t *testing.T) {
	f := newFake()
	f.secrets["tenants/"+tenant+"/assets/a1/ssh"] = map[string]any{"username": "admintwin", "private_key": sshKey, "password": "pw-secret"}
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	b, _, logs := newBroker(t, f, func(c *Config) { c.Now = func() time.Time { return now } })

	l, err := b.Lease(context.Background(), tenant, "a1", "kv/data/tenants/"+tenant+"/assets/a1/ssh", 150*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if l.Credential.Username != "admintwin" || string(l.Credential.PrivateKey) != sshKey || l.Credential.Password != "pw-secret" {
		t.Fatalf("credential not mapped: user=%q", l.Credential.Username)
	}
	if !l.ExpiresAt.Equal(now.Add(150*time.Second)) || !strings.HasPrefix(l.Handle, "lease-") {
		t.Fatalf("lease: %v %q", l.ExpiresAt, l.Handle)
	}
	if b.ActiveLeases() != 1 {
		t.Fatal("lease must be tracked")
	}
	if err := b.Revoke(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	if b.ActiveLeases() != 0 || len(f.revoked) != 0 {
		t.Fatalf("KV revoke is local bookkeeping only: %v", f.revoked)
	}
	// Секреты не журналируются и не печатаются.
	out := logs.String() + fmt.Sprintf("%v %+v %#v", l, l, l.Credential)
	for _, s := range []string{"pw-secret", "secretkeymaterial", token} {
		if strings.Contains(out, s) {
			t.Fatalf("secret %q leaked into logs/print: %s", s, out)
		}
	}
	raw, _ := json.Marshal(l)
	if strings.Contains(string(raw), "pw-secret") {
		t.Fatal("secret leaked into JSON")
	}
}

func TestDynamicLeaseIsRevoked(t *testing.T) {
	f := newFake()
	f.dynamic[tenant+"-readwrite"] = map[string]any{"username": "v-token-rw-1", "password": "dyn-pass"}
	now := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	b, _, _ := newBroker(t, f, func(c *Config) { c.Now = func() time.Time { return now } })
	l, err := b.Lease(context.Background(), tenant, "pg1", "database/creds/"+tenant+"-readwrite", 150*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Срок аренды Vault (30 с) короче запрошенного TTL — берётся меньший.
	if !l.ExpiresAt.Equal(now.Add(30 * time.Second)) {
		t.Fatalf("expires: %v", l.ExpiresAt)
	}
	if err := b.Revoke(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	if len(f.revoked) != 1 || f.revoked[0] != "database/creds/"+tenant+"-readwrite/abc123" {
		t.Fatalf("dynamic lease must be revoked in vault: %v", f.revoked)
	}
	// Повторный отзыв — идемпотентен.
	if err := b.Revoke(context.Background(), l); err != nil || len(f.revoked) != 1 {
		t.Fatal("second revoke must be a no-op")
	}
}

func TestFailClosed(t *testing.T) {
	f := newFake()
	ref := "kv/data/tenants/" + tenant + "/assets/a1/ssh"
	f.secrets["tenants/"+tenant+"/assets/a1/ssh"] = map[string]any{"username": "u", "password": "p"}
	b, srv, _ := newBroker(t, f, nil)
	ctx := context.Background()

	f.mu.Lock()
	f.sealed = true
	f.mu.Unlock()
	if _, err := b.Lease(ctx, tenant, "a1", ref, time.Minute); !errors.Is(err, ErrSealed) {
		t.Fatalf("sealed vault: %v", err)
	}
	if err := b.Health(ctx); !errors.Is(err, ErrSealed) {
		t.Fatalf("health on sealed vault: %v", err)
	}
	f.mu.Lock()
	f.sealed = false
	f.mu.Unlock()
	if err := b.Health(ctx); err != nil {
		t.Fatal(err)
	}

	// Пустая ссылка, traversal, чужой tenant, служебные пути — отказ без запроса к Vault.
	for _, r := range []string{"", "kv/data/tenants/" + tenant + "/../x", "kv/data/tenants/" + other + "/assets/a1/ssh",
		"sys/leases/lookup", "kv/metadata/tenants/" + tenant + "/a", "/etc/passwd", "kv/data/tenants/" + tenant + "/a b"} {
		if _, err := b.Lease(ctx, tenant, "a1", r, time.Minute); !errors.Is(err, ErrBadRef) {
			t.Fatalf("ref %q must be rejected: %v", r, err)
		}
	}
	if _, err := b.Lease(ctx, tenant, "a1", "kv/data/tenants/"+tenant+"/assets/missing", time.Minute); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing secret: %v", err)
	}
	if _, err := b.Lease(ctx, tenant, "a1", ref, 0); err == nil {
		t.Fatal("non-positive ttl must be rejected")
	}

	// Неверный токен.
	bad, _, _ := newBroker(t, f, func(c *Config) { c.Token = "hvs.wrong" })
	if _, err := bad.Lease(ctx, tenant, "a1", ref, time.Minute); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bad token: %v", err)
	}

	// Vault недоступен.
	srv.Close()
	_, err := b.Lease(ctx, tenant, "a1", ref, time.Minute)
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("unreachable: %v", err)
	}
	if strings.Contains(err.Error(), "tenants/") {
		t.Fatalf("error must not include the vault path: %v", err)
	}

	// TLS-проверка включена: клиент без CA тестового сервера не доверяет ему.
	srv2 := httptest.NewTLSServer(f)
	defer srv2.Close()
	strict, err := New(Config{Addr: srv2.URL, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.Lease(ctx, tenant, "a1", ref, time.Minute); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("untrusted certificate must fail: %v", err)
	}
	// Plain http запрещён.
	if _, err := New(Config{Addr: "http://vault:8200", Token: token}); err == nil {
		t.Fatal("http must be rejected")
	}
	if _, err := New(Config{Addr: "https://vault:8200"}); err == nil {
		t.Fatal("missing auth must be rejected")
	}
}

func TestAppRoleLogin(t *testing.T) {
	f := newFake()
	f.secrets["tenants/"+tenant+"/fw"] = map[string]any{"token": "forti-api-token"}
	b, _, _ := newBroker(t, f, func(c *Config) { c.Token, c.RoleID, c.SecretID = "", "role-1", "secret-1" })
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		l, err := b.Lease(ctx, tenant, "fw", "kv/data/tenants/"+tenant+"/fw", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if l.Credential.Token != "forti-api-token" {
			t.Fatal("token not mapped")
		}
	}
	if f.logins != 1 {
		t.Fatalf("approle token must be cached, logins=%d", f.logins)
	}
	// Токен отозван в Vault → повторный вход один раз.
	f.mu.Lock()
	f.tokens = map[string]bool{}
	f.mu.Unlock()
	if _, err := b.Lease(ctx, tenant, "fw", "kv/data/tenants/"+tenant+"/fw", time.Minute); err != nil {
		t.Fatal(err)
	}
	if f.logins != 2 {
		t.Fatalf("expected re-login, logins=%d", f.logins)
	}
	wrong, _, _ := newBroker(t, f, func(c *Config) { c.Token, c.RoleID, c.SecretID = "", "role-1", "nope" })
	if _, err := wrong.Lease(ctx, tenant, "fw", "kv/data/tenants/"+tenant+"/fw", time.Minute); err == nil || strings.Contains(err.Error(), "nope") {
		t.Fatalf("approle failure must not echo secret_id: %v", err)
	}
}

func TestReadOnlyConvention(t *testing.T) {
	f := newFake()
	base := "tenants/" + tenant + "/assets/"
	f.secrets[base+"a1/ssh"] = map[string]any{"username": "root", "password": "write"}
	f.secrets[base+"a1/ssh-readonly"] = map[string]any{"username": "ro", "password": "read"}
	f.secrets[base+"a2/ssh"] = map[string]any{"username": "root", "password": "write",
		"readonly": map[string]any{"username": "ro2", "private_key": sshKey}}
	f.secrets[base+"a3/ssh"] = map[string]any{"username": "root", "password": "write"}
	b, _, _ := newBroker(t, f, nil)
	ctx := context.Background()

	c, err := b.ReadOnly(ctx, tenant, "kv/data/"+base+"a1/ssh")
	if err != nil || c.Username != "ro" || c.Password != "read" {
		t.Fatalf("suffix convention: %v %q", err, c.Username)
	}
	c, err = b.ReadOnly(ctx, tenant, "kv/data/"+base+"a2/ssh")
	if err != nil || c.Username != "ro2" || string(c.PrivateKey) != sshKey {
		t.Fatalf("sub-key convention: %v %q", err, c.Username)
	}
	// Без read-only учётки — отказ; учётка исполнения не выдаётся вместо неё.
	if c, err := b.ReadOnly(ctx, tenant, "kv/data/"+base+"a3/ssh"); !errors.Is(err, ErrNoReadOnly) || c.Password != "" {
		t.Fatalf("missing readonly must fail closed: %v", err)
	}
	if _, err := b.ReadOnly(ctx, other, "kv/data/"+base+"a1/ssh"); !errors.Is(err, ErrBadRef) {
		t.Fatalf("foreign tenant: %v", err)
	}
}

func TestEmptySecretRejected(t *testing.T) {
	f := newFake()
	f.secrets["tenants/"+tenant+"/x"] = map[string]any{"note": "nothing"}
	b, _, _ := newBroker(t, f, nil)
	if _, err := b.Lease(context.Background(), tenant, "x", "kv/data/tenants/"+tenant+"/x", time.Minute); !errors.Is(err, ErrEmptySecret) {
		t.Fatalf("empty secret: %v", err)
	}
}

// Брокер удовлетворяет интерфейсу Gateway.
var _ gateway.CredentialBroker = (*Broker)(nil)
