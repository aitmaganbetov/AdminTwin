package network

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/aitmaganbetov/admintwin/connectors/internal/testutil"
	"github.com/aitmaganbetov/admintwin/services/discovery"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/inventory"
)

const apiToken = "fgt-ro-token-0123456789"

// fakeFortiOS — эмуляция FortiOS 7.x REST API (только GET).
type fakeFortiOS struct {
	t      *testing.T
	mu     sync.Mutex
	paths  []string
	haMode string
}

func (f *fakeFortiOS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		f.t.Errorf("non-GET request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(405)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+apiToken || r.URL.Query().Get("access_token") != "" {
		w.WriteHeader(401)
		return
	}
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path+"?"+r.URL.RawQuery)
	mode := f.haMode
	f.mu.Unlock()
	ok := func(results any, extra map[string]any) {
		body := map[string]any{"http_method": "GET", "status": "success", "http_status": 200, "vdom": "root", "results": results}
		for k, v := range extra {
			body[k] = v
		}
		_ = json.NewEncoder(w).Encode(body)
	}
	policies := []map[string]any{
		{"policyid": 1, "name": "lan-to-wan", "action": "accept", "status": "enable", "srcintf": []map[string]string{{"name": "lan"}}, "dstintf": []map[string]string{{"name": "wan1"}}},
		{"policyid": 7, "name": "block\nbad", "action": "deny", "status": "disable", "srcintf": []map[string]string{{"name": "any"}}, "dstintf": []map[string]string{{"name": "any"}}},
		{"policyid": 9, "name": "weird", "action": "redirect", "status": "enable"},
	}
	switch p := r.URL.Path; {
	case p == pathPolicyCMDB:
		ok(policies, nil)
	case p == pathPolicyCMDB+"/7":
		ok(policies[1:2], nil)
	case strings.HasPrefix(p, pathPolicyCMDB+"/"):
		w.WriteHeader(404)
	case p == pathPolicyMonitor:
		ok([]map[string]any{{"policyid": 1, "hit_count": 1234, "last_used": 1795000000, "bytes": 99}, {"policyid": 7, "hit_count": 0, "last_used": 0}}, nil)
	case p == pathHAConfig:
		ok(map[string]any{"mode": mode}, nil)
	case p == pathHAChecksums:
		ok([]map[string]any{{"serial_no": "FGT1", "checksum": map[string]string{"all": "abc"}}, {"serial_no": "FGT2", "checksum": map[string]string{"all": "abc"}}}, nil)
	case p == pathStatus:
		ok(map[string]any{"model_name": "FortiGate", "model_number": "60F", "model": "FGT60F", "hostname": "fw-edge-01"},
			map[string]any{"serial": "FGT60FTK1234", "version": "v7.2.5", "build": 1517})
	case p == pathInterfaces:
		ok([]map[string]any{{"name": "wan1", "status": "up"}, {"name": "lan", "status": "up"}}, nil)
	case p == pathIPsec:
		ok([]map[string]any{{"name": "to-dc", "proxyid": []map[string]string{{"status": "up"}}}, {"name": "to-branch", "proxyid": []map[string]string{{"status": "down"}}}}, nil)
	default:
		w.WriteHeader(404)
	}
}

func newFake(t *testing.T) (*fakeFortiOS, *inventory.Connection, gateway.Credential) {
	t.Helper()
	f := &fakeFortiOS{t: t, haMode: "a-p"}
	srv := httptest.NewTLSServer(f)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(srv.Close)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	pn, _ := strconv.Atoi(port)
	return f, &inventory.Connection{Method: Method, Address: host, Port: pn, TLSServerName: "example.com"},
		gateway.Credential{Token: apiToken, CACert: testutil.CertPEM(srv.Certificate())}
}

func TestPolicyStatus(t *testing.T) {
	f, conn, cred := newFake(t)
	c := New(Options{})
	ctx := context.Background()
	out, err := c.PolicyStatus(ctx, conn, cred, PolicyInput{VDOM: "root"})
	if err != nil {
		t.Fatal(err)
	}
	testutil.ValidateToolOutput(t, "fortigate.policy.status", out)
	pols := out["policies"].([]map[string]any)
	if len(pols) != 2 || pols[0]["hit_count"] != int64(1234) || pols[0]["last_used"] != "2026-11-18T11:06:40Z" || pols[1]["last_used"] != nil {
		t.Fatalf("policies: %v", pols)
	}
	if pols[1]["name"] != "blockbad" || out["ha_status"] != "a-p: 2 members, in sync" {
		t.Fatalf("sanitize/ha: %v %v", pols[1]["name"], out["ha_status"])
	}
	if !strings.Contains(f.paths[0], "vdom=root") || !strings.Contains(f.paths[0], "format=policyid") {
		t.Fatalf("query: %v", f.paths)
	}
	id := 7
	out, err = c.PolicyStatus(ctx, conn, cred, PolicyInput{PolicyID: &id})
	if err != nil || len(out["policies"].([]map[string]any)) != 1 {
		t.Fatalf("single policy: %v %v", out, err)
	}
	missing := 42
	out, err = c.PolicyStatus(ctx, conn, cred, PolicyInput{PolicyID: &missing})
	if err != nil || len(out["policies"].([]any)) != 0 {
		t.Fatalf("missing policy: %v %v", out, err)
	}
	testutil.ValidateToolOutput(t, "fortigate.policy.status", out)
	f.mu.Lock()
	f.haMode = "standalone"
	f.mu.Unlock()
	if out, _ := c.PolicyStatus(ctx, conn, cred, PolicyInput{}); out["ha_status"] != "standalone" {
		t.Fatalf("standalone: %v", out["ha_status"])
	}
}

func TestFailClosed(t *testing.T) {
	_, conn, cred := newFake(t)
	c := New(Options{})
	ctx := context.Background()
	if _, err := c.PolicyStatus(ctx, conn, gateway.Credential{CACert: cred.CACert}, PolicyInput{}); err == nil {
		t.Fatal("missing token must be rejected")
	}
	_, err := c.PolicyStatus(ctx, conn, gateway.Credential{Token: "wrong-token-value", CACert: cred.CACert}, PolicyInput{})
	if !errors.Is(err, ErrAccessDenied) || strings.Contains(err.Error(), "wrong-token") {
		t.Fatalf("bad token: %v", err)
	}
	// Без CA устройства сертификат не доверен.
	if _, err := c.PolicyStatus(ctx, conn, gateway.Credential{Token: apiToken}, PolicyInput{}); err == nil {
		t.Fatal("untrusted certificate must fail")
	}
	// Явный tls_skip_verify — работает (с предупреждением в журнале).
	skip := *conn
	skip.TLSSkipVerify = true
	if _, err := c.PolicyStatus(ctx, &skip, gateway.Credential{Token: apiToken}, PolicyInput{}); err != nil {
		t.Fatalf("explicit skip verify: %v", err)
	}
	for _, addr := range []string{"http://fw", "fw/../x", "user@fw", ""} {
		if _, err := c.PolicyStatus(ctx, &inventory.Connection{Method: Method, Address: addr}, cred, PolicyInput{}); err == nil {
			t.Fatalf("address %q must be rejected", addr)
		}
	}
	if _, err := c.PolicyStatus(ctx, conn, cred, PolicyInput{VDOM: "root&x=1"}); err == nil {
		t.Fatal("invalid vdom must be rejected")
	}
}

func TestCollector(t *testing.T) {
	_, conn, cred := newFake(t)
	obs, err := New(Options{}).Collector().Collect(context.Background(),
		discovery.Target{TenantID: "t", Address: conn.Address, Port: conn.Port, Method: Method, TLSServerName: "example.com", CredentialRef: "kv/data/tenants/t/fw"},
		discovery.Credential{Token: apiToken, CACert: cred.CACert})
	if err != nil {
		t.Fatal(err)
	}
	a := obs.Assets[0]
	if a.Name != "fw-edge-01" || a.Type != "firewall" || a.Objects["model"][0] != "FortiGate 60F" || a.Objects["firmware"][0] != "v7.2.5 build1517" ||
		strings.Join(a.Objects["interface"], ",") != "lan,wan1" || strings.Join(a.Objects["ipsec_tunnel"], ",") != "to-dc,to-branch" {
		t.Fatalf("asset: %+v", a)
	}
	if len(obs.Warnings) != 1 || !strings.Contains(obs.Warnings[0], "to-branch") {
		t.Fatalf("warnings: %v", obs.Warnings)
	}
}

// TestNoWriteMethods — в коде коннектора нет ни одного метода изменения (только GET).
func TestNoWriteMethods(t *testing.T) {
	src, err := os.ReadFile("fortigate.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`Method(Post|Put|Patch|Delete)|"(POST|PUT|PATCH|DELETE)"`)
	if m := re.Find(src); m != nil {
		t.Fatalf("write method found in read-only connector: %s", m)
	}
}
