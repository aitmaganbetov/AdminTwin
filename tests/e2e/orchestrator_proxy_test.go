package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aitmaganbetov/admintwin/internal/app"
)

type fakeOrch struct {
	mu      sync.Mutex
	last    map[string]any
	headers http.Header
	kills   []map[string]any
	release chan struct{}
}

func (f *fakeOrch) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/tasks", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.mu.Lock()
		f.last, f.headers = b, r.Header.Clone()
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(202)
		_, _ = w.Write([]byte(`{"task_id":"task-1","status":"queued"}`))
	})
	mux.HandleFunc("GET /v1/tasks/{id}/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		fmt.Fprint(w, "id: 1\nevent: task.progress\ndata: {\"n\":1}\n\n")
		fl.Flush()
		<-f.release // второе событие — только после того, как клиент получил первое
		fmt.Fprint(w, "id: 2\nevent: task.result\ndata: {\"n\":2}\n\n")
		fl.Flush()
	})
	mux.HandleFunc("POST /v1/kill", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-AdminTwin-Service-Token") != serviceToken {
			w.WriteHeader(401)
			return
		}
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.mu.Lock()
		f.kills = append(f.kills, b)
		f.mu.Unlock()
	})
	return mux
}

func TestOrchestratorProxy(t *testing.T) {
	fo := &fakeOrch{release: make(chan struct{})}
	orch := httptest.NewServer(fo.handler(t))
	defer orch.Close()
	a, err := app.New(app.Config{Root: "../..", FixturesPath: "../../infra/dev/fixtures.yaml", DevAuth: true, Simulator: true,
		ServiceToken: serviceToken, OrchestratorURL: orch.URL})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.Server.Handler())
	defer srv.Close()
	e := &env{t: t, app: a, srv: srv}

	// Клиент пытается подставить чужой tenant — прокси перезаписывает его проверенной идентичностью.
	r := e.do(engineerA, "POST", "/api/v1/agent-tasks", map[string]any{"kind": "diagnose", "objective": "check web",
		"tenant_id": tenantB, "requested_by": "someone-else"})
	if r.Status != 202 || r.str("task_id") != "task-1" {
		t.Fatalf("create task: %d %s", r.Status, r.Raw)
	}
	fo.mu.Lock()
	if fo.last["tenant_id"] != tenantA || fo.last["requested_by"] != engineerA.id {
		t.Fatalf("identity must come from the verified actor: %v", fo.last)
	}
	if fo.headers.Get("X-AdminTwin-Service-Token") != serviceToken || fo.headers.Get("X-AdminTwin-Tenant") != tenantA || fo.headers.Get("X-AdminTwin-Actor-Kind") != "user" {
		t.Fatalf("service headers: %v", fo.headers)
	}
	fo.mu.Unlock()

	// SSE проходит потоково.
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/agent-tasks/task-1/events", nil)
	for k, v := range map[string]string{"X-AdminTwin-Tenant": tenantA, "X-AdminTwin-Actor": "eng-1", "X-AdminTwin-Roles": "engineer", "Accept": "text/event-stream"} {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	rd := bufio.NewReader(res.Body)
	got := make(chan string, 10)
	go func() {
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				close(got)
				return
			}
			if strings.HasPrefix(line, "event:") {
				got <- strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			}
		}
	}()
	select {
	case ev := <-got:
		if ev != "task.progress" {
			t.Fatalf("first event: %s", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SSE event was buffered by the proxy")
	}
	close(fo.release)
	if ev := <-got; ev != "task.result" {
		t.Fatalf("second event: %s", ev)
	}
	res.Body.Close()

	// Права и пути.
	if r := e.do(viewerA, "POST", "/api/v1/agent-tasks", map[string]any{"kind": "diagnose"}); r.Status != 403 {
		t.Fatalf("viewer creating tasks: %d", r.Status)
	}
	if r := e.do(agentA, "GET", "/api/v1/agent-tasks", nil); r.Status != 403 {
		t.Fatalf("agent via user proxy: %d", r.Status)
	}
	if r := e.do(engineerA, "GET", "/api/v1/agent-tasks/..%2f..%2fadmin", nil); r.Status != 400 && r.Status != 404 {
		t.Fatalf("path traversal: %d", r.Status)
	}

	// Kill switch ядра останавливает задачи оркестратора.
	e.do(operatorA, "POST", "/api/v1/kill-switch", map[string]any{"active": true, "reason": "incident"})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		fo.mu.Lock()
		n := len(fo.kills)
		fo.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	fo.mu.Lock()
	if len(fo.kills) != 1 || fo.kills[0]["tenant_id"] != tenantA {
		t.Fatalf("orchestrator kill not delivered: %v", fo.kills)
	}
	fo.mu.Unlock()

	// Оркестратор недоступен → деградация 502, ядро работает.
	orch.Close()
	if r := e.do(engineerA, "POST", "/api/v1/agent-tasks", map[string]any{"kind": "diagnose"}); r.Status != 502 {
		t.Fatalf("orchestrator down: %d %s", r.Status, r.Raw)
	}
	if r := e.do(engineerA, "GET", "/api/v1/assets", nil); r.Status != 200 {
		t.Fatal("core must keep working without the orchestrator")
	}
}
