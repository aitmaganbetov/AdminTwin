package e2e

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aitmaganbetov/admintwin/internal/app"
)

const serviceToken = "test-service-token-0123456789abcdef0123"

type idp struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	i := &idp{key: k}
	mux := http.NewServeMux()
	i.srv = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": i.srv.URL, "jwks_uri": i.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		b := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "RSA", "kid": "k1", "use": "sig", "n": b(k.N.Bytes()), "e": b(big.NewInt(int64(k.E)).Bytes())}}})
	})
	t.Cleanup(i.srv.Close)
	return i
}

func (i *idp) token(sub, tenant string, roles, scopes, amr []string) string {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	in := enc(map[string]string{"alg": "RS256", "kid": "k1"}) + "." + enc(map[string]any{
		"iss": i.srv.URL, "aud": "admintwin", "sub": sub, "exp": time.Now().Add(time.Hour).Unix(),
		"admintwin_tenant": tenant, "admintwin_roles": roles, "admintwin_scopes": scopes, "amr": amr})
	d := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, d[:])
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func call(t *testing.T, srv *httptest.Server, method, path string, body any, hdr map[string]string) resp {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, srv.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := resp{Status: res.StatusCode, Raw: string(raw)}
	_ = json.Unmarshal(raw, &out.Body)
	return out
}

func TestOIDCAndServiceTokenAuth(t *testing.T) {
	i := newIDP(t)
	a, err := app.New(app.Config{Root: "../..", FixturesPath: "../../infra/dev/fixtures.yaml", Simulator: true,
		OIDCIssuer: i.srv.URL, OIDCAudience: "admintwin", ServiceToken: serviceToken})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Server.Handler())
	t.Cleanup(func() { srv.Close(); a.Coordinator.Wait() })
	bearer := func(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

	eng := i.token("eng-1", tenantA, []string{"engineer"}, []string{"sysadmin"}, []string{"pwd", "otp"})
	if r := call(t, srv, "GET", "/api/v1/assets", nil, bearer(eng)); r.Status != 200 {
		t.Fatalf("OIDC user: %d %s", r.Status, r.Raw)
	}
	// Dev-заголовки при выключенном dev-режиме не работают.
	if r := call(t, srv, "GET", "/api/v1/assets", nil, map[string]string{"X-AdminTwin-Tenant": tenantA, "X-AdminTwin-Actor": "x", "X-AdminTwin-Roles": "tenant_admin"}); r.Status != 401 {
		t.Fatalf("dev headers must be ignored: %d", r.Status)
	}
	// Агент через сервисный токен предлагает изменение.
	agentHdr := map[string]string{"X-AdminTwin-Service-Token": serviceToken, "X-AdminTwin-Tenant": tenantA,
		"X-AdminTwin-Actor": "linux-admin", "X-AdminTwin-Actor-Kind": "ai_agent"}
	r := call(t, srv, "POST", "/api/v1/changes", map[string]any{"runbook_id": "linux.logs.rotate_cleanup", "asset_id": appLinux,
		"params": map[string]any{"directory": "/var/log/app"}, "reason": "disk 96%"}, agentHdr)
	if r.Status != 202 {
		t.Fatalf("agent propose via service token: %d %s", r.Status, r.Raw)
	}
	id := r.str("id")

	// Согласование без MFA отклоняется; с MFA — проходит.
	noMFA := i.token("eng-2", tenantA, []string{"engineer"}, []string{"sysadmin"}, []string{"pwd"})
	if d := call(t, srv, "POST", "/api/v1/changes/"+id+"/decisions", map[string]any{"decision": "approve"}, bearer(noMFA)); d.Status != 403 || problemType(d) != "mfa-required" {
		t.Fatalf("approval without MFA: %d %s", d.Status, d.Raw)
	}
	if d := call(t, srv, "POST", "/api/v1/kill-switch", map[string]any{"active": true, "reason": "x"}, bearer(i.token("op", tenantA, []string{"operator"}, nil, []string{"pwd"}))); d.Status != 403 {
		t.Fatalf("kill switch without MFA: %d", d.Status)
	}
	if d := call(t, srv, "POST", "/api/v1/changes/"+id+"/decisions", map[string]any{"decision": "reject"}, bearer(eng)); d.Status != 200 {
		t.Fatalf("decision with MFA: %d %s", d.Status, d.Raw)
	}

	bad := []map[string]string{
		{"X-AdminTwin-Service-Token": "wrong-token-wrong-token-wrong-token", "X-AdminTwin-Tenant": tenantA, "X-AdminTwin-Actor": "x", "X-AdminTwin-Actor-Kind": "ai_agent"},
		// сервис не может выдать себя за человека
		{"X-AdminTwin-Service-Token": serviceToken, "X-AdminTwin-Tenant": tenantA, "X-AdminTwin-Actor": "adm-1", "X-AdminTwin-Actor-Kind": "user", "X-AdminTwin-Roles": "tenant_admin"},
		{"Authorization": "Basic YWRtaW46YWRtaW4="},
		{"Authorization": "Bearer " + eng[:len(eng)-4] + "AAAA"},
	}
	for n, h := range bad {
		if r := call(t, srv, "GET", "/api/v1/assets", nil, h); r.Status != 401 {
			t.Errorf("case %d: want 401, got %d", n, r.Status)
		}
	}
	// Роль ai_agent в токене пользователя отбрасывается; роль из чужого tenant не даёт доступа.
	other := i.token("eng-b", tenantB, []string{"tenant_admin"}, nil, []string{"otp"})
	if r := call(t, srv, "GET", "/api/v1/changes/"+id, nil, bearer(other)); r.Status != 404 {
		t.Fatalf("cross-tenant via OIDC: %d", r.Status)
	}
}
