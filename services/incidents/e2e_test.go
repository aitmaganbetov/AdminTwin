package incidents_test

// Сквозной MVP-сценарий «HTTP 502» (§1.4, §21): syslog nginx 502 + http_5xx_rate → событие → инцидент
// (owner назначен < 30 с) → triaged → задача RCA в оркестраторе → результат RCA → гипотезы в инциденте.
// Плюс изоляция tenant для событий, инцидентов и discovery. Модули подключаются как у интегратора:
// a, _ := app.New(cfg); a.Server.Modules = append(a.Server.Modules, m).

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aitmaganbetov/admintwin/internal/app"
	"github.com/aitmaganbetov/admintwin/pkg/httpapi"
	"github.com/aitmaganbetov/admintwin/services/discovery"
	"github.com/aitmaganbetov/admintwin/services/incidents"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	"github.com/aitmaganbetov/admintwin/services/telemetry"
)

const e2eToken = "e2e-service-token-0123456789abcdef"

type e2eWho struct{ tenant, id, kind, roles string }

var (
	opA       = e2eWho{tA, "op-1", "user", "operator"}
	viewA     = e2eWho{tA, "view-1", "user", "viewer"}
	admA      = e2eWho{tA, "adm-1", "user", "tenant_admin"}
	adm2A     = e2eWho{tA, "adm-2", "user", "tenant_admin"}
	engA      = e2eWho{tA, "eng-1", "user", "engineer"}
	agentE2E  = e2eWho{tA, "devops-engineer", "ai_agent", ""}
	collector = e2eWho{tA, "collector-nginx", "service", ""}
	orchA     = e2eWho{tA, "orchestrator", "service", ""}
	opB       = e2eWho{tB, "op-b", "user", "operator,engineer,tenant_admin"}
)

type orchestratorFake struct {
	mu    sync.Mutex
	calls []struct {
		hdr  http.Header
		body map[string]any
	}
}

func (o *orchestratorFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/tasks" {
		http.NotFound(w, r)
		return
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	o.mu.Lock()
	o.calls = append(o.calls, struct {
		hdr  http.Header
		body map[string]any
	}{r.Header.Clone(), body})
	o.mu.Unlock()
	w.WriteHeader(http.StatusAccepted)
	_, _ = io.WriteString(w, `{"task_id":"task-e2e-1","status":"queued"}`)
}

type e2e struct {
	t    *testing.T
	srv  *httptest.Server
	app  *app.App
	orch *orchestratorFake
	disc *discovery.Service
	sys  *telemetry.SyslogReceiver
}

func newE2E(t *testing.T) *e2e {
	t.Helper()
	a, err := app.New(app.Config{Root: "../..", FixturesPath: "../../infra/dev/fixtures.yaml", DevAuth: true, Version: "test", ServiceToken: e2eToken})
	if err != nil {
		t.Fatal(err)
	}
	// nginx-хост app-linux-01: адрес подключения — источник syslog.
	host, _ := a.Inventory.Get(tA, appLinux)
	host.Connection = &inventory.Connection{Method: "ssh", Address: "127.0.0.1", CredentialRef: "kv/tenants/a/app-linux-01/ssh", HostKey: "ssh-ed25519 AAAA"}
	if err := a.Inventory.Put(*host); err != nil {
		t.Fatal(err)
	}

	orch := &orchestratorFake{}
	orchSrv := httptest.NewServer(orch)
	t.Cleanup(orchSrv.Close)
	client, err := incidents.NewOrchestratorClient(orchSrv.URL, e2eToken)
	if err != nil {
		t.Fatal(err)
	}

	inc := incidents.New(incidents.NewMemoryRepo(), a.Inventory, a.Audit, client, incidents.Config{})
	inc.ServiceToken = e2eToken
	tel := telemetry.NewService(telemetry.NewMemoryStore(telemetry.Limits{}, telemetry.Retention{}), a.Inventory)
	tel.Subscriber, tel.ServiceToken = inc, e2eToken
	if err := tel.RegisterTools(a.Tools); err != nil {
		t.Fatal(err)
	}
	resolver := telemetry.NewInventoryResolver(a.Inventory, func() []string { return []string{tA, tB} })
	sys := &telemetry.SyslogReceiver{Addr: "127.0.0.1:0", Resolver: resolver, Ingest: tel}
	if err := sys.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sys.Close() })

	coll := &fakeSSH{}
	disc := discovery.New(discovery.NewMemoryRepo(), a.Inventory, a.Audit, a.Evidence, staticCreds{}, discovery.Config{}, coll)
	disc.OnCMDBChange = resolver.Invalidate

	// Штатные модули приложения заменяются тестовыми экземплярами (свой starter, фейковые сборщики).
	a.Server.Modules = []httpapi.Module{a.Tools, tel, inc, disc}
	srv := httptest.NewServer(a.Server.Handler())
	t.Cleanup(func() { srv.Close(); disc.Wait() })
	return &e2e{t: t, srv: srv, app: a, orch: orch, disc: disc, sys: sys}
}

type fakeSSH struct{}

func (fakeSSH) Method() string { return "ssh" }

func (fakeSSH) Collect(_ context.Context, t discovery.Target, _ discovery.Credential) (discovery.Observation, error) {
	return discovery.Observation{Confidence: 0.9, Assets: []inventory.Asset{{Name: "edge-" + strings.ReplaceAll(t.Address, ".", "-"), Type: "linux_host"}}}, nil
}

type staticCreds struct{}

func (staticCreds) ReadOnly(context.Context, string, string) (discovery.Credential, error) {
	return discovery.Credential{Username: "ro"}, nil
}

func (e *e2e) do(w e2eWho, method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AdminTwin-Tenant", w.tenant)
	req.Header.Set("X-AdminTwin-Actor", w.id)
	req.Header.Set("X-AdminTwin-Actor-Kind", w.kind)
	req.Header.Set("X-AdminTwin-Roles", w.roles)
	if w.kind == "service" {
		req.Header.Set("X-AdminTwin-Service-Token", e2eToken)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func TestE2EHTTP502IncidentFlow(t *testing.T) {
	e := newE2E(t)
	start := time.Now()

	// 1. nginx пишет в syslog строку 502 (UDP) — hostname в сообщении поддельный, tenant/актив берутся по IP.
	conn, err := net.Dial("udp", e.sys.UDPAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	line := `<27>` + time.Now().Format(time.Stamp) + ` docker-b-01 nginx[812]: 2026/11/27 10:15:02 [error] 812#812: *4411 connect() failed (111: Connection refused) while connecting to upstream, client: 10.0.0.7, server: shop, request: "GET /api/cart HTTP/1.1", upstream: "http://10.20.0.15:8080/api/cart"`
	if _, err := conn.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	conn.Close()

	var incID string
	deadline := time.Now().Add(5 * time.Second)
	for incID == "" && time.Now().Before(deadline) {
		if _, body := e.do(opA, "GET", "/api/v1/incidents", nil); body != nil {
			if items, _ := body["items"].([]any); len(items) == 1 {
				incID = items[0].(map[string]any)["id"].(string)
			}
		}
		if incID == "" {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if incID == "" {
		t.Fatalf("incident was not created from syslog; syslog stats %+v", e.sys.Stats())
	}
	createdIn := time.Since(start)

	// 2. Сборщик присылает http_5xx_rate = 38% по тому же активу → корреляция в тот же инцидент.
	code, body := e.do(collector, "POST", "/api/v1/telemetry/samples", map[string]any{"samples": []map[string]any{
		{"asset_id": appLinux, "metric": "http_5xx_rate", "value": 38.0, "labels": map[string]string{"vhost": "shop"}},
	}})
	if code != 202 || len(body["incidents"].([]any)) != 1 || body["incidents"].([]any)[0] != incID {
		t.Fatalf("sample must correlate into the same incident: %d %v", code, body)
	}

	code, inc := e.do(viewA, "GET", "/api/v1/incidents/"+incID, nil)
	if code != 200 {
		t.Fatalf("get: %d", code)
	}
	if inc["owner"] != "web-team" || inc["assigned_at"] == nil || inc["status"] != "new" || len(inc["event_ids"].([]any)) != 2 {
		t.Fatalf("incident: %v", inc)
	}
	lat := inc["latency"].(map[string]any)
	if ms := lat["event_to_assigned_ms"].(float64); ms >= 30_000 || createdIn >= 30*time.Second {
		t.Fatalf("[MVP] incident 502 must be created and assigned < 30s: %v ms, observed %v", ms, createdIn)
	}
	t.Logf("syslog 502 -> incident assigned to %s in %v (recorded %v ms)", inc["owner"], createdIn, lat["event_to_assigned_ms"])

	// 3. Агент не может менять состояние; оператор переводит в triaged → RCA запускается.
	if code, _ := e.do(agentE2E, "POST", "/api/v1/incidents/"+incID+"/transitions", map[string]any{"to": "triaged", "reason": "agent"}); code != 403 {
		t.Fatalf("AI agent transition: %d", code)
	}
	code, inc = e.do(opA, "POST", "/api/v1/incidents/"+incID+"/transitions", map[string]any{"to": "triaged", "reason": "confirmed 502 on shop"})
	if code != 200 || inc["status"] != "triaged" {
		t.Fatalf("triage: %d %v", code, inc)
	}
	rca := inc["rca"].(map[string]any)
	if rca["status"] != "running" || rca["task_id"] != "task-e2e-1" {
		t.Fatalf("rca after triage: %v", rca)
	}
	if len(e.orch.calls) != 1 {
		t.Fatalf("orchestrator must be called once, got %d", len(e.orch.calls))
	}
	call := e.orch.calls[0]
	if call.hdr.Get("X-AdminTwin-Service-Token") != e2eToken || call.hdr.Get("X-AdminTwin-Tenant") != tA || call.hdr.Get("X-AdminTwin-Actor") != "op-1" || call.hdr.Get("X-AdminTwin-Actor-Kind") != "user" {
		t.Fatalf("orchestrator headers: %v", call.hdr)
	}
	b := call.body
	if b["kind"] != "rca" || b["tenant_id"] != tA || b["incident_id"] != incID || b["requested_by"] != "user:op-1" || b["objective"] == "" {
		t.Fatalf("task body: %v", b)
	}
	if ids := b["scope"].(map[string]any)["asset_ids"].([]any); len(ids) != 1 || ids[0] != appLinux {
		t.Fatalf("scope: %v", b["scope"])
	}
	ctxb := b["context"].(map[string]any)
	if ctxb["alert_type"] != "http_502" || ctxb["asset_type"] != "linux_host" || len(ctxb["events"].([]any)) != 2 {
		t.Fatalf("context: %v", ctxb)
	}
	rawBody, _ := json.Marshal(b)
	if strings.Contains(string(rawBody), "connect() failed") || strings.Contains(string(rawBody), "10.20.0.15") {
		t.Fatalf("task must carry references, not raw log lines: %s", rawBody)
	}

	// 4. Оркестратор публикует результат RCA (только service "orchestrator").
	result := map[string]any{
		"task_id": "task-e2e-1", "status": "completed",
		"hypotheses": []map[string]any{
			{"cause": "upstream_container_stopped", "confidence": 0.82,
				"supporting":  []map[string]any{{"fact": "nginx: connection refused to upstream 10.20.0.15:8080", "evidence_id": "tool:logs.search:1"}, {"fact": "container app-api exited 137 (OOM)", "evidence_id": "tool:docker.container.inspect:1"}},
				"refuting":    []map[string]any{{"fact": "pg connections 42/200", "evidence_id": "tool:postgres.activity:1"}},
				"next_checks": []string{"docker.container.inspect app-api"}},
			{"cause": "db_connections_exhausted", "confidence": 0.08, "supporting": []any{}, "refuting": []any{}, "next_checks": []any{}},
		},
		"conclusion": "Probable cause: upstream container stopped (OOM).", "uncertainty_check": "db excluded by postgres.activity",
		"agents": []string{"network-engineer", "devops-engineer", "dba-engineer"}, "cost_usd": 0.12, "proposed_changes": []string{},
	}
	if code, _ := e.do(e2eWho{tA, "devops-engineer", "ai_agent", ""}, "POST", "/api/v1/incidents/"+incID+"/rca", result); code != 403 {
		t.Fatalf("agent must not post RCA: %d", code)
	}
	if code, _ := e.do(e2eWho{tA, "collector-nginx", "service", ""}, "POST", "/api/v1/incidents/"+incID+"/rca", result); code != 403 {
		t.Fatalf("non-orchestrator service must not post RCA: %d", code)
	}
	extra := map[string]any{}
	for k, v := range result {
		extra[k] = v
	}
	extra["status_override"] = "closed"
	if code, _ := e.do(orchA, "POST", "/api/v1/incidents/"+incID+"/rca", extra); code != 400 {
		t.Fatalf("unknown fields must be rejected: %d", code)
	}
	code, out := e.do(orchA, "POST", "/api/v1/incidents/"+incID+"/rca", result)
	if code != 200 {
		t.Fatalf("rca: %d %v", code, out)
	}
	// Tenant B не может записать RCA в инцидент tenant A.
	if code, _ := e.do(e2eWho{tB, "orchestrator", "service", ""}, "POST", "/api/v1/incidents/"+incID+"/rca", result); code != 404 {
		t.Fatalf("cross-tenant RCA: %d", code)
	}

	code, inc = e.do(viewA, "GET", "/api/v1/incidents/"+incID, nil)
	if code != 200 || inc["status"] != "triaged" {
		t.Fatalf("RCA must never change the incident status: %v", inc["status"])
	}
	rca = inc["rca"].(map[string]any)
	hyps := rca["hypotheses"].([]any)
	if rca["status"] != "completed" || len(hyps) != 2 || hyps[0].(map[string]any)["cause"] != "upstream_container_stopped" || rca["cost_usd"].(float64) != 0.12 {
		t.Fatalf("hypotheses: %v", rca)
	}
	kinds := map[string]bool{}
	for _, te := range inc["timeline"].([]any) {
		kinds[te.(map[string]any)["kind"].(string)] = true
	}
	for _, k := range []string{"created", "event", "owner_assigned", "transition", "rca_requested", "rca_update"} {
		if !kinds[k] {
			t.Fatalf("timeline lacks %s: %v", k, kinds)
		}
	}

	// 5. Оценка оператора → кандидат golden dataset.
	code, fb := e.do(opA, "POST", "/api/v1/incidents/"+incID+"/feedback", map[string]any{"correct": true, "rating": 5})
	if code != 200 || fb["candidate"].(map[string]any)["exportable"] != true {
		t.Fatalf("feedback: %d %v", code, fb)
	}
	// 6. Аудит: создание, переход, RCA, оценка.
	actions := map[string]bool{}
	for _, en := range e.app.Audit.Entries(tA) {
		actions[en.Action] = true
	}
	for _, act := range []string{"incident.created", "incident.event_linked", "incident.transitioned", "incident.rca_requested", "incident.rca_recorded", "incident.feedback"} {
		if !actions[act] {
			t.Fatalf("audit lacks %s", act)
		}
	}

	// 7. Изоляция tenant B: инцидент — 404, списки событий/инцидентов пусты.
	if code, _ := e.do(opB, "GET", "/api/v1/incidents/"+incID, nil); code != 404 {
		t.Fatalf("cross-tenant incident: %d", code)
	}
	if code, _ := e.do(opB, "POST", "/api/v1/incidents/"+incID+"/transitions", map[string]any{"to": "investigating", "reason": "x"}); code != 404 {
		t.Fatalf("cross-tenant transition: %d", code)
	}
	if _, body := e.do(opB, "GET", "/api/v1/incidents", nil); len(body["items"].([]any)) != 0 {
		t.Fatalf("cross-tenant incident list: %v", body)
	}
	if _, body := e.do(opB, "GET", "/api/v1/events?window=1h", nil); len(body["events"].([]any)) != 0 {
		t.Fatalf("cross-tenant events: %v", body)
	}
	if _, body := e.do(opA, "GET", "/api/v1/events?window=1h", nil); len(body["events"].([]any)) != 2 {
		t.Fatalf("tenant A events: %v", body)
	}
}

func TestE2EDiscoveryIsolation(t *testing.T) {
	e := newE2E(t)
	scope := map[string]any{"name": "dc-1", "ranges": []string{"10.30.0.0/24"}, "methods": []string{"ssh"}, "credential_refs": []string{"kv/discovery/ssh"}, "limits": map[string]any{"max_sessions": 2, "pps": 50}, "responsible": "infra lead", "valid_until": time.Now().Add(24 * time.Hour)}
	if code, _ := e.do(engA, "POST", "/api/v1/discovery/scopes", scope); code != 403 {
		t.Fatalf("engineer cannot create scope: %d", code)
	}
	code, sc := e.do(admA, "POST", "/api/v1/discovery/scopes", scope)
	if code != 201 {
		t.Fatalf("scope: %d %v", code, sc)
	}
	scopeID := sc["id"].(string)
	job := map[string]any{"scope_id": scopeID, "targets": []map[string]any{{"address": "10.30.0.5", "method": "ssh", "port": 22, "credential_ref": "kv/discovery/ssh"}}}
	code, body := e.do(engA, "POST", "/api/v1/discovery/jobs", job)
	if code != 403 || !strings.HasSuffix(body["type"].(string), "policy-denied") {
		t.Fatalf("job without approved scope must be policy-denied: %d %v", code, body)
	}
	if code, _ := e.do(admA, "POST", "/api/v1/discovery/scopes/"+scopeID+"/approve", nil); code != 403 {
		t.Fatalf("author approval must be rejected: %d", code)
	}
	if code, _ := e.do(adm2A, "POST", "/api/v1/discovery/scopes/"+scopeID+"/approve", nil); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	outside := map[string]any{"scope_id": scopeID, "targets": []map[string]any{{"address": "10.31.0.5", "method": "ssh", "credential_ref": "kv/discovery/ssh"}}}
	if code, _ := e.do(engA, "POST", "/api/v1/discovery/jobs", outside); code != 403 {
		t.Fatalf("target outside scope: %d", code)
	}
	code, j := e.do(engA, "POST", "/api/v1/discovery/jobs", job)
	if code != 202 {
		t.Fatalf("job: %d %v", code, j)
	}
	jobID := j["id"].(string)
	e.disc.Wait()
	code, j = e.do(engA, "GET", "/api/v1/discovery/jobs/"+jobID, nil)
	if code != 200 || j["status"] != "completed" || j["summary"].(map[string]any)["new"].(float64) != 1 || j["evidence_id"] == "" {
		t.Fatalf("job result: %d %v", code, j)
	}
	// Tenant B: ни scope, ни задания tenant A.
	if code, _ := e.do(opB, "GET", "/api/v1/discovery/jobs/"+jobID, nil); code != 404 {
		t.Fatalf("cross-tenant job: %d", code)
	}
	if _, body := e.do(opB, "GET", "/api/v1/discovery/scopes", nil); len(body["items"].([]any)) != 0 {
		t.Fatalf("cross-tenant scopes: %v", body)
	}
	if code, _ := e.do(opB, "POST", "/api/v1/discovery/jobs", job); code != 403 {
		t.Fatalf("tenant B cannot use tenant A scope: %d", code)
	}
	if code, _ := e.do(opB, "POST", "/api/v1/discovery/jobs/"+jobID+"/confirm", map[string]any{"keys": []string{"linux_host|edge-10-30-0-5"}}); code != 404 {
		t.Fatalf("cross-tenant confirm: %d", code)
	}
}
