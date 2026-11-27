package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aitmaganbetov/admintwin/internal/app"
)

const (
	tenantA   = "11111111-1111-4111-8111-111111111111"
	tenantB   = "22222222-2222-4222-8222-222222222222"
	dockerWeb = "a0000000-0000-4000-8000-000000000002"
	appLinux  = "a0000000-0000-4000-8000-000000000003"
	logArch   = "a0000000-0000-4000-8000-000000000005"
	dockerB   = "b0000000-0000-4000-8000-000000000001"
	appAPI    = "3f2a9c1b7d4e"
)

type env struct {
	t   *testing.T
	app *app.App
	srv *httptest.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	a, err := app.New(app.Config{Root: "../..", FixturesPath: "../../infra/dev/fixtures.yaml", DevAuth: true, Simulator: true, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Server.Handler())
	t.Cleanup(func() { srv.Close(); a.Coordinator.Wait() })
	return &env{t: t, app: a, srv: srv}
}

type who struct {
	tenant, id, kind, roles, scopes string
}

var (
	engineerA = who{tenantA, "eng-1", "user", "engineer", "devops"}
	sysadminA = who{tenantA, "eng-2", "user", "engineer", "sysadmin"}
	managerA  = who{tenantA, "mgr-1", "user", "it_manager", ""}
	adminA    = who{tenantA, "adm-1", "user", "tenant_admin", ""}
	operatorA = who{tenantA, "op-1", "user", "operator", ""}
	auditorA  = who{tenantA, "aud-1", "user", "auditor", ""}
	viewerA   = who{tenantA, "view-1", "user", "viewer", ""}
	agentA    = who{tenantA, "devops-engineer", "ai_agent", "tenant_admin", ""} // попытка приписать агенту роль
	engineerB = who{tenantB, "eng-b", "user", "engineer", "devops"}
	managerB  = who{tenantB, "mgr-b", "user", "it_manager", ""}
)

type resp struct {
	Status int
	Body   map[string]any
	Raw    string
}

func (r resp) str(k string) string { s, _ := r.Body[k].(string); return s }

func (e *env) do(w who, method, path string, body any, hdr ...string) resp {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if w.id != "" {
		req.Header.Set("X-AdminTwin-Tenant", w.tenant)
		req.Header.Set("X-AdminTwin-Actor", w.id)
		req.Header.Set("X-AdminTwin-Actor-Kind", w.kind)
		req.Header.Set("X-AdminTwin-Roles", w.roles)
		req.Header.Set("X-AdminTwin-Scopes", w.scopes)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := resp{Status: res.StatusCode, Raw: string(raw)}
	_ = json.Unmarshal(raw, &out.Body)
	return out
}

func (e *env) propose(w who, runbookID, asset string, params map[string]any, extra ...string) resp {
	e.t.Helper()
	return e.do(w, "POST", "/api/v1/changes", map[string]any{"runbook_id": runbookID, "asset_id": asset, "params": params, "reason": "e2e"}, extra...)
}

// waitStatus ждёт, пока change не придёт в одно из состояний.
func (e *env) waitStatus(w who, id string, want ...string) resp {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var r resp
	for time.Now().Before(deadline) {
		r = e.do(w, "GET", "/api/v1/changes/"+id, nil)
		for _, s := range want {
			if r.str("status") == s {
				return r
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.t.Fatalf("change %s: want status %v, got %s (%s)", id, want, r.str("status"), r.Raw)
	return r
}

func problemType(r resp) string {
	t := r.str("type")
	return strings.TrimPrefix(t, "https://errors.admintwin.io/")
}
