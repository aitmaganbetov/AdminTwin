package incidents_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/aitmaganbetov/admintwin/pkg/fsm"
	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/audit"
	"github.com/aitmaganbetov/admintwin/services/incidents"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	"github.com/aitmaganbetov/admintwin/services/telemetry"
)

const (
	tA       = "11111111-1111-4111-8111-111111111111"
	tB       = "22222222-2222-4222-8222-222222222222"
	fwEdge   = "a0000000-0000-4000-8000-000000000001"
	dockerWb = "a0000000-0000-4000-8000-000000000002"
	appLinux = "a0000000-0000-4000-8000-000000000003"
	pgMain   = "a0000000-0000-4000-8000-000000000004"
	changeID = "c0000000-0000-4000-8000-000000000001"
)

var (
	operator = identity.Actor{ID: "op-1", Kind: identity.KindUser, TenantID: tA, Roles: []identity.Role{identity.RoleOperator}}
	viewer   = identity.Actor{ID: "view-1", Kind: identity.KindUser, TenantID: tA, Roles: []identity.Role{identity.RoleViewer}}
	agent    = identity.Actor{ID: "devops-engineer", Kind: identity.KindAIAgent, TenantID: tA, Roles: []identity.Role{identity.RoleAIAgent}}
	orch     = identity.Actor{ID: "orchestrator", Kind: identity.KindService, TenantID: tA}
	operB    = identity.Actor{ID: "op-b", Kind: identity.KindUser, TenantID: tB, Roles: []identity.Role{identity.RoleOperator}}
)

// fakeStarter — RCAStarter для unit-тестов.
type fakeStarter struct {
	mu    sync.Mutex
	tasks []incidents.RCATask
	err   error
}

func (f *fakeStarter) StartRCA(_ context.Context, t incidents.RCATask) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return "", f.err
	}
	f.tasks = append(f.tasks, t)
	return fmt.Sprintf("task-%d", len(f.tasks)), nil
}

type fixture struct {
	svc   *incidents.Service
	inv   *inventory.Store
	audit *audit.Log
	rca   *fakeStarter
	now   time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inv := inventory.NewStore()
	if err := inv.LoadFixture("../../infra/dev/fixtures.yaml"); err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	al := audit.New(audit.NewMemoryKeys(), priv)
	f := &fixture{inv: inv, audit: al, rca: &fakeStarter{}, now: time.Now().UTC()}
	f.svc = incidents.New(incidents.NewMemoryRepo(), inv, al, f.rca, incidents.Config{})
	f.svc.SetClock(func() time.Time { return f.now })
	return f
}

func ev(asset, kind string, sev telemetry.Severity, at time.Time) telemetry.Event {
	return telemetry.Event{ID: telemetry.NewID(), TenantID: tA, AssetID: asset, Kind: kind, Severity: sev, Title: kind + " on " + asset, Fingerprint: kind + ":" + asset, At: at}
}

func (f *fixture) handle(t *testing.T, e telemetry.Event) []string {
	t.Helper()
	ids, err := f.svc.HandleEvents(context.Background(), e.TenantID, []telemetry.Event{e})
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func TestLifecycleDefinition(t *testing.T) {
	d := incidents.Lifecycle
	path := []fsm.State{incidents.StatusNew, incidents.StatusTriaged, incidents.StatusInvestigating, incidents.StatusMitigated, incidents.StatusResolved, incidents.StatusClosed}
	for i := 0; i+1 < len(path); i++ {
		if !d.Can(path[i], path[i+1]) {
			t.Fatalf("%s -> %s must be allowed", path[i], path[i+1])
		}
	}
	for _, from := range []fsm.State{incidents.StatusResolved, incidents.StatusClosed} {
		if !d.Can(from, incidents.StatusReopened) {
			t.Fatalf("%s -> reopened must be allowed", from)
		}
	}
	if !d.Can(incidents.StatusReopened, incidents.StatusInvestigating) || d.Can(incidents.StatusNew, incidents.StatusClosed) || d.Can(incidents.StatusInvestigating, incidents.StatusClosed) {
		t.Fatal("unexpected transitions")
	}
	if len(d.States()) != 7 {
		t.Fatalf("states: %v", d.States())
	}
}

func TestCorrelationAndDedup(t *testing.T) {
	f := newFixture(t)
	t0 := f.now

	// low/medium без инцидента не создают инцидент.
	if ids := f.handle(t, ev(pgMain, "slow_queries", telemetry.SevMedium, t0)); len(ids) != 0 {
		t.Fatalf("medium event must not create an incident: %v", ids)
	}
	first := f.handle(t, ev(pgMain, "db_connections", telemetry.SevHigh, t0))
	if len(first) != 1 {
		t.Fatal("high event must create an incident")
	}
	// Дедупликация по fingerprint в окне 30 мин.
	f.now = t0.Add(20 * time.Minute)
	if ids := f.handle(t, ev(pgMain, "db_connections", telemetry.SevHigh, f.now)); len(ids) != 1 || ids[0] != first[0] {
		t.Fatalf("same fingerprint within 30m must dedup: %v", ids)
	}
	// Связанный актив (app-linux-01 → docker-web-01 → pg-main: глубина 2) в окне 10 мин → тот же инцидент.
	f.now = t0.Add(25 * time.Minute)
	if ids := f.handle(t, ev(appLinux, "http_5xx", telemetry.SevHigh, f.now)); len(ids) != 1 || ids[0] != first[0] {
		t.Fatalf("blast radius <= 2 within 10m must correlate: %v", ids)
	}
	inc, err := f.svc.Get(context.Background(), operator, first[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(inc.EventIDs) != 3 || len(inc.AssetIDs) != 2 || inc.Owner != "dba-team" {
		t.Fatalf("incident: events=%d assets=%v owner=%s", len(inc.EventIDs), inc.AssetIDs, inc.Owner)
	}
	// Вне окна 10 мин — новый инцидент даже для связанного актива.
	f.now = t0.Add(40 * time.Minute)
	if ids := f.handle(t, ev(dockerWb, "container_down", telemetry.SevHigh, f.now)); len(ids) != 1 || ids[0] == first[0] {
		t.Fatalf("outside correlation window must create a new incident: %v", ids)
	}
	// Глубина 3 (fw-edge-01 → app-linux-01 → docker-web-01 → pg-main) не коррелирует с инцидентом только по pg-main.
	g := newFixture(t)
	a := g.handle(t, ev(pgMain, "db_connections", telemetry.SevCritical, g.now))
	b := g.handle(t, ev(fwEdge, "packet_loss", telemetry.SevHigh, g.now.Add(time.Minute)))
	if a[0] == b[0] {
		t.Fatal("blast radius depth 3 must not correlate")
	}
	// Событие другого tenant не коррелирует с инцидентом tenant A.
	other := ev(pgMain, "db_connections", telemetry.SevHigh, g.now)
	other.TenantID = tB
	ids, _ := g.svc.HandleEvents(context.Background(), tB, []telemetry.Event{other})
	if len(ids) != 1 || ids[0] == a[0] {
		t.Fatalf("cross-tenant event must not join tenant A incident: %v", ids)
	}
	if _, err := g.svc.Get(context.Background(), operB, a[0]); !problem.Is(err, problem.NotFound) {
		t.Fatalf("tenant B must not see tenant A incident: %v", err)
	}
	list, _ := g.svc.List(context.Background(), operB, incidents.Filter{})
	for _, inc := range list {
		if inc.TenantID != tB {
			t.Fatal("list leaked another tenant")
		}
	}
}

// [MVP] Инцидент 502 создаётся и назначается за < 30 с.
func TestIncidentCreatedAndAssignedUnder30s(t *testing.T) {
	f := newFixture(t)
	f.svc.SetClock(time.Now)
	e := ev(appLinux, "http_5xx", telemetry.SevHigh, time.Now().UTC())
	e.Labels = map[string]string{"status": "502"}
	start := time.Now()
	ids := f.handle(t, e)
	elapsed := time.Since(start)
	inc, err := f.svc.Get(context.Background(), operator, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if inc.Owner != "web-team" || inc.AssignedAt == nil {
		t.Fatalf("owner must be the asset owner: %+v", inc)
	}
	if elapsed >= 30*time.Second || inc.Latency == nil || inc.Latency.EventToAssignedMS == nil || *inc.Latency.EventToAssignedMS >= 30_000 {
		t.Fatalf("created+assigned must take < 30s: elapsed=%v latency=%+v", elapsed, inc.Latency)
	}
	t.Logf("event -> incident+owner: %v (recorded %d ms)", elapsed, *inc.Latency.EventToAssignedMS)
}

func TestTransitionsRulesAndRoles(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id := f.handle(t, ev(dockerWb, "container_down", telemetry.SevHigh, f.now))[0]
	tr := func(a identity.Actor, to fsm.State, evRef string) error {
		_, err := f.svc.Transition(ctx, a, id, incidents.TransitionInput{To: to, Reason: "test", EvidenceRef: evRef})
		return err
	}
	if err := tr(agent, incidents.StatusTriaged, ""); !problem.Is(err, problem.Forbidden) {
		t.Fatalf("AI agent cannot transition: %v", err)
	}
	if err := tr(viewer, incidents.StatusTriaged, ""); !problem.Is(err, problem.Forbidden) {
		t.Fatalf("viewer cannot transition: %v", err)
	}
	if err := tr(orch, incidents.StatusTriaged, ""); !problem.Is(err, problem.Forbidden) {
		t.Fatalf("service cannot transition: %v", err)
	}
	if err := tr(operator, incidents.StatusClosed, ""); !problem.Is(err, problem.InvalidTransition) {
		t.Fatalf("new -> closed must be rejected: %v", err)
	}
	if _, err := f.svc.Transition(ctx, operator, id, incidents.TransitionInput{To: incidents.StatusTriaged}); !problem.Is(err, problem.InvalidParams) {
		t.Fatalf("reason is required: %v", err)
	}
	if err := tr(operator, incidents.StatusTriaged, ""); err != nil {
		t.Fatal(err)
	}
	if len(f.rca.tasks) != 1 {
		t.Fatal("triaged must start RCA")
	}
	task := f.rca.tasks[0]
	if task.Kind != "rca" || task.IncidentID != id || task.TenantID != tA || task.Scope.AssetIDs[0] != dockerWb || task.Context.AlertType != "container_stopped" {
		t.Fatalf("task: %+v", task)
	}
	if err := tr(operator, incidents.StatusInvestigating, ""); err != nil {
		t.Fatal(err)
	}
	if err := tr(operator, incidents.StatusMitigated, ""); !problem.Is(err, problem.InvalidTransition) {
		t.Fatalf("mitigated requires evidence_ref: %v", err)
	}
	if err := tr(operator, incidents.StatusMitigated, "change:"+changeID); err != nil {
		t.Fatal(err)
	}
	if err := tr(operator, incidents.StatusResolved, ""); !problem.Is(err, problem.InvalidTransition) {
		t.Fatalf("resolved requires postmortem for high: %v", err)
	}
	if _, err := f.svc.SetPostmortem(ctx, agent, id, incidents.PostmortemInput{Summary: "s", RootCause: "r", CorrectiveActions: []string{"a"}}); !problem.Is(err, problem.Forbidden) {
		t.Fatalf("AI cannot write postmortem: %v", err)
	}
	if _, err := f.svc.SetPostmortem(ctx, operator, id, incidents.PostmortemInput{Summary: "container OOM", RootCause: "memory limit", CorrectiveActions: []string{"raise limit via change"}}); err != nil {
		t.Fatal(err)
	}
	for _, to := range []fsm.State{incidents.StatusResolved, incidents.StatusClosed, incidents.StatusReopened, incidents.StatusInvestigating} {
		if err := tr(operator, to, ""); err != nil {
			t.Fatalf("%s: %v", to, err)
		}
	}
	inc, _ := f.svc.Get(ctx, viewer, id)
	kinds := map[string]int{}
	for _, e := range inc.Timeline {
		kinds[e.Kind]++
	}
	if kinds["transition"] != 7 || kinds["created"] != 1 || kinds["event"] < 1 || kinds["rca_requested"] < 1 || kinds["postmortem"] != 1 {
		t.Fatalf("timeline: %v", kinds)
	}
	if len(inc.Transitions) != 7 || inc.Transitions[0].Actor != "user:op-1" {
		t.Fatalf("transitions journal: %+v", inc.Transitions)
	}
	// Аудит каждой мутации.
	actions := map[string]int{}
	for _, e := range f.audit.Entries(tA) {
		actions[e.Action]++
	}
	if actions["incident.created"] != 1 || actions["incident.transitioned"] != 7 || actions["incident.postmortem"] != 1 || actions["incident.rca_requested"] < 1 {
		t.Fatalf("audit: %v", actions)
	}
	if ok, _, err := f.audit.VerifyTenant(tA); !ok || err != nil {
		t.Fatal("audit chain must verify")
	}
}

func TestRCAResultStrictAndNeverCloses(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id := f.handle(t, ev(appLinux, "http_5xx", telemetry.SevHigh, f.now))[0]
	res := incidents.RCAResult{TaskID: "task-1", Status: "completed", Hypotheses: []incidents.Hypothesis{{Cause: "upstream_container_stopped", Confidence: 0.8, Supporting: []incidents.Evidence{{Fact: "container exited 137", EvidenceID: "tool:docker.container.inspect:1"}}}}, Agents: []string{"devops-engineer"}, CostUSD: 0.1}
	if _, err := f.svc.RecordRCA(ctx, orch, id, res); !problem.Is(err, problem.Conflict) {
		t.Fatalf("RCA without a registered task must conflict: %v", err)
	}
	if _, err := f.svc.Transition(ctx, operator, id, incidents.TransitionInput{To: incidents.StatusTriaged, Reason: "triage"}); err != nil {
		t.Fatal(err)
	}
	for _, a := range []identity.Actor{operator, agent, {ID: "collector", Kind: identity.KindService, TenantID: tA}} {
		if _, err := f.svc.RecordRCA(ctx, a, id, res); !problem.Is(err, problem.Forbidden) {
			t.Fatalf("%s must not record RCA: %v", a.Ref(), err)
		}
	}
	bad := res
	bad.TaskID = "task-999"
	if _, err := f.svc.RecordRCA(ctx, orch, id, bad); !problem.Is(err, problem.Conflict) {
		t.Fatalf("foreign task id: %v", err)
	}
	for name, mut := range map[string]func(r *incidents.RCAResult){
		"confidence>1": func(r *incidents.RCAResult) { r.Hypotheses = []incidents.Hypothesis{{Cause: "x", Confidence: 1.5}} },
		"status":       func(r *incidents.RCAResult) { r.Status = "closed" },
		"agent id":     func(r *incidents.RCAResult) { r.Agents = []string{"Robert'); DROP"} },
		"change id":    func(r *incidents.RCAResult) { r.ProposedChanges = []string{"rm -rf /"} },
		"no hyp":       func(r *incidents.RCAResult) { r.Hypotheses = nil },
		"cost":         func(r *incidents.RCAResult) { r.CostUSD = -1 },
	} {
		r := res
		r.Hypotheses = append([]incidents.Hypothesis(nil), res.Hypotheses...)
		mut(&r)
		if _, err := f.svc.RecordRCA(ctx, orch, id, r); !problem.Is(err, problem.InvalidParams) {
			t.Fatalf("%s must be rejected: %v", name, err)
		}
	}
	// Первопричина без evidence → uncertain.
	noEv := res
	noEv.Hypotheses = []incidents.Hypothesis{{Cause: "guess", Confidence: 0.9}}
	inc, err := f.svc.RecordRCA(ctx, orch, id, noEv)
	if err != nil || inc.RCA.Status != incidents.RCAUncertain {
		t.Fatalf("completed without evidence must be downgraded: %v %+v", err, inc.RCA)
	}
	res.ProposedChanges = []string{changeID}
	inc, err = f.svc.RecordRCA(ctx, orch, id, res)
	if err != nil {
		t.Fatal(err)
	}
	if inc.Status != incidents.StatusTriaged || inc.RCA.Status != incidents.RCACompleted || inc.RCA.Hypotheses[0].Cause != "upstream_container_stopped" {
		t.Fatalf("RCA must not change incident status: %s %+v", inc.Status, inc.RCA)
	}
	linked := false
	for _, e := range inc.Timeline {
		if e.Kind == "change_linked" && e.Ref == "change:"+changeID {
			linked = true
		}
	}
	if !linked {
		t.Fatal("proposed change must be linked in the timeline")
	}
}

func TestFeedbackGoldenCandidateMatchesSchema(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	e := ev(appLinux, "http_5xx", telemetry.SevHigh, f.now)
	e.Labels = map[string]string{"status": "502", "service_kind": "reverse_proxy"}
	id := f.handle(t, e)[0]
	yes := true
	if _, _, err := f.svc.SetFeedback(ctx, operator, id, incidents.FeedbackInput{Correct: &yes, Rating: 5}); !problem.Is(err, problem.Conflict) {
		t.Fatalf("feedback before RCA: %v", err)
	}
	_, _ = f.svc.Transition(ctx, operator, id, incidents.TransitionInput{To: incidents.StatusTriaged, Reason: "t"})
	_, err := f.svc.RecordRCA(ctx, orch, id, incidents.RCAResult{TaskID: "task-1", Status: "completed", Hypotheses: []incidents.Hypothesis{
		{Cause: "Upstream container stopped", Confidence: 0.82, Supporting: []incidents.Evidence{{Fact: "nginx upstream connection refused", EvidenceID: "event:1"}}, NextChecks: []string{"docker.container.inspect"}},
		{Cause: "db_connections_exhausted", Confidence: 0.1},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.SetFeedback(ctx, agent, id, incidents.FeedbackInput{Correct: &yes, Rating: 5}); !problem.Is(err, problem.Forbidden) {
		t.Fatalf("AI feedback: %v", err)
	}
	if _, _, err := f.svc.SetFeedback(ctx, operator, id, incidents.FeedbackInput{Correct: &yes, Rating: 9}); !problem.Is(err, problem.InvalidParams) {
		t.Fatalf("rating: %v", err)
	}
	_, cand, err := f.svc.SetFeedback(ctx, operator, id, incidents.FeedbackInput{Correct: &yes, Rating: 5, Comment: "точно"})
	if err != nil {
		t.Fatal(err)
	}
	if !cand.Exportable {
		t.Fatalf("candidate must be exportable: %s", cand.Reason)
	}
	manager := identity.Actor{ID: "mgr", Kind: identity.KindUser, TenantID: tA, Roles: []identity.Role{identity.RoleITManager}}
	cases, err := f.svc.ExportCandidates(ctx, manager)
	if err != nil || len(cases) != 1 {
		t.Fatalf("export: %v %v", cases, err)
	}
	validateEvalCase(t, cases[0])
	exp := cases[0]["expected"].(map[string]any)
	if exp["root_cause"] != "upstream_container_stopped" || cases[0]["scenario"] != "http_502" {
		t.Fatalf("case: %v", cases[0])
	}
	raw, _ := json.Marshal(cases[0])
	if strings.Contains(string(raw), "connect() failed") {
		t.Fatal("eval case must not contain raw log lines")
	}
	if _, err := f.svc.ExportCandidates(ctx, operator); !problem.Is(err, problem.Forbidden) {
		t.Fatalf("operator export: %v", err)
	}
	if cs, _ := f.svc.ExportCandidates(ctx, identity.Actor{ID: "m", Kind: identity.KindUser, TenantID: tB, Roles: []identity.Role{identity.RoleITManager}}); len(cs) != 0 {
		t.Fatal("cross-tenant export")
	}
	// RCA неверна, указана фактическая причина.
	no := false
	_, cand, err = f.svc.SetFeedback(ctx, operator, id, incidents.FeedbackInput{Correct: &no, ActualCause: "firewall policy block", Rating: 2})
	if err != nil || !cand.Exportable || cand.Case["expected"].(map[string]any)["root_cause"] != "firewall_policy_block" {
		t.Fatalf("incorrect RCA candidate: %+v %v", cand, err)
	}
	validateEvalCase(t, cand.Case)
}

func validateEvalCase(t *testing.T, c map[string]any) {
	t.Helper()
	raw, err := os.ReadFile("../../ai/evals/eval-case.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	comp := jsonschema.NewCompiler()
	if err := comp.AddResource("mem://eval-case.json", doc); err != nil {
		t.Fatal(err)
	}
	sch, err := comp.Compile("mem://eval-case.json")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(c)
	inst, _ := jsonschema.UnmarshalJSON(strings.NewReader(string(b)))
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("eval case does not match schema: %v\n%s", err, b)
	}
}

func TestOrchestratorClient(t *testing.T) {
	var got struct {
		hdr  http.Header
		body map[string]any
		path string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.hdr, got.path = r.Header.Clone(), r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got.body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"task_id":"t-42","status":"queued"}`)
	}))
	defer srv.Close()
	if _, err := incidents.NewOrchestratorClient("ftp://x", "tok"); err == nil {
		t.Fatal("non-http url must be rejected")
	}
	if _, err := incidents.NewOrchestratorClient(srv.URL, ""); err == nil {
		t.Fatal("empty token must be rejected")
	}
	c, err := incidents.NewOrchestratorClient(srv.URL+"/", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	id, err := c.StartRCA(context.Background(), incidents.RCATask{Kind: "rca", TenantID: tA, IncidentID: "i-1", Objective: "o", Scope: incidents.RCAScope{AssetIDs: []string{appLinux}}, RequestedBy: "user:op-1"})
	if err != nil || id != "t-42" {
		t.Fatalf("start: %v %v", id, err)
	}
	if got.path != "/v1/tasks" || got.hdr.Get("X-AdminTwin-Service-Token") != "s3cret" || got.hdr.Get("X-AdminTwin-Tenant") != tA {
		t.Fatalf("request: %s %v", got.path, got.hdr)
	}
	for _, k := range []string{"kind", "tenant_id", "incident_id", "objective", "scope", "requested_by", "context"} {
		if _, ok := got.body[k]; !ok {
			t.Fatalf("body must contain %s: %v", k, got.body)
		}
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"task_id":"../../etc"}`)
	}))
	defer bad.Close()
	c2, _ := incidents.NewOrchestratorClient(bad.URL, "x")
	if _, err := c2.StartRCA(context.Background(), incidents.RCATask{TenantID: tA}); err == nil {
		t.Fatal("invalid task id from orchestrator must be rejected")
	}
}

func TestRCAStartFailureIsRecorded(t *testing.T) {
	f := newFixture(t)
	f.rca.err = fmt.Errorf("connection refused")
	ctx := context.Background()
	id := f.handle(t, ev(dockerWb, "container_down", telemetry.SevHigh, f.now))[0]
	inc, err := f.svc.Transition(ctx, operator, id, incidents.TransitionInput{To: incidents.StatusTriaged, Reason: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if inc.Status != incidents.StatusTriaged || inc.RCA.Status != incidents.RCAFailed || inc.RCA.Note == "" {
		t.Fatalf("RCA failure must be visible, triage must stand: %s %+v", inc.Status, inc.RCA)
	}
	f.rca.err = nil
	inc, err = f.svc.Analyze(ctx, operator, id)
	if err != nil || inc.RCA.TaskID == "" || inc.RCA.Status != incidents.RCARunning {
		t.Fatalf("manual analyze: %v %+v", err, inc.RCA)
	}
	if _, err := f.svc.Analyze(ctx, agent, id); !problem.Is(err, problem.Forbidden) {
		t.Fatalf("agent analyze: %v", err)
	}
}

func TestAutoTriageStartsRCA(t *testing.T) {
	inv := inventory.NewStore()
	_ = inv.LoadFixture("../../infra/dev/fixtures.yaml")
	st := &fakeStarter{}
	svc := incidents.New(incidents.NewMemoryRepo(), inv, nil, st, incidents.Config{AutoTriage: true})
	e := ev(dockerWb, "container_down", telemetry.SevCritical, time.Now().UTC())
	start := time.Now()
	ids, err := svc.HandleEvents(context.Background(), tA, []telemetry.Event{e})
	if err != nil || len(ids) != 1 {
		t.Fatal(err)
	}
	inc, _ := svc.Get(context.Background(), operator, ids[0])
	if inc.Status != incidents.StatusTriaged || inc.RCA.TaskID == "" || len(st.tasks) != 1 || time.Since(start) > 30*time.Second {
		t.Fatalf("auto-triage: %s %+v", inc.Status, inc.RCA)
	}
}

func timeNow() time.Time { return time.Now().UTC() }
