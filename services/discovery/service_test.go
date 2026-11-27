package discovery_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/audit"
	evidence "github.com/aitmaganbetov/admintwin/services/compliance-evidence"
	"github.com/aitmaganbetov/admintwin/services/discovery"
	"github.com/aitmaganbetov/admintwin/services/inventory"
)

const (
	tA = "11111111-1111-4111-8111-111111111111"
	tB = "22222222-2222-4222-8222-222222222222"
)

var (
	admin1   = identity.Actor{ID: "adm-1", Kind: identity.KindUser, TenantID: tA, Roles: []identity.Role{identity.RoleTenantAdmin}}
	admin2   = identity.Actor{ID: "adm-2", Kind: identity.KindUser, TenantID: tA, Roles: []identity.Role{identity.RoleTenantAdmin}}
	engineer = identity.Actor{ID: "eng-1", Kind: identity.KindUser, TenantID: tA, Roles: []identity.Role{identity.RoleEngineer}}
	operator = identity.Actor{ID: "op-1", Kind: identity.KindUser, TenantID: tA, Roles: []identity.Role{identity.RoleOperator}}
	agent    = identity.Actor{ID: "linux-admin", Kind: identity.KindAIAgent, TenantID: tA, Roles: []identity.Role{identity.RoleAIAgent}}
	adminB   = identity.Actor{ID: "adm-b", Kind: identity.KindUser, TenantID: tB, Roles: []identity.Role{identity.RoleTenantAdmin, identity.RoleEngineer}}
)

// fakeCollector — read-only сборщик для тестов; результаты по адресу.
type fakeCollector struct {
	method   string
	byAddr   map[string]discovery.Observation
	active   atomic.Int32
	maxSeen  atomic.Int32
	mu       sync.Mutex
	gotCreds []string
}

func (f *fakeCollector) Method() string { return f.method }

func (f *fakeCollector) Collect(_ context.Context, t discovery.Target, cred discovery.Credential) (discovery.Observation, error) {
	n := f.active.Add(1)
	defer f.active.Add(-1)
	for {
		m := f.maxSeen.Load()
		if n <= m || f.maxSeen.CompareAndSwap(m, n) {
			break
		}
	}
	time.Sleep(20 * time.Millisecond)
	f.mu.Lock()
	f.gotCreds = append(f.gotCreds, cred.Username)
	f.mu.Unlock()
	obs, ok := f.byAddr[t.Address]
	if !ok {
		return discovery.Observation{}, fmt.Errorf("host unreachable")
	}
	return obs, nil
}

type fakeCreds struct{}

func (fakeCreds) ReadOnly(_ context.Context, tenantID, ref string) (discovery.Credential, error) {
	return discovery.Credential{Username: "ro-" + ref, Password: "x"}, nil
}

type fixture struct {
	svc  *discovery.Service
	inv  *inventory.Store
	al   *audit.Log
	ev   *evidence.Store
	coll *fakeCollector
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	inv := inventory.NewStore()
	put := func(a inventory.Asset) {
		if err := inv.Put(a); err != nil {
			t.Fatal(err)
		}
	}
	// Существующий классифицированный актив (изменится) и актив, который не будет найден (missing).
	put(inventory.Asset{ID: "a0000000-0000-4000-8000-0000000000a1", TenantID: tA, Name: "web-01", Type: "linux_host", Environment: "production", Criticality: "high", DataClass: "internal", Owner: "web-team", Verified: true,
		Objects: map[string][]string{"systemd_unit": {"nginx.service"}}, Connection: &inventory.Connection{Method: "ssh", Address: "10.0.0.11", CredentialRef: "kv/web", HostKey: "ssh-ed25519 AAAA"}})
	put(inventory.Asset{ID: "a0000000-0000-4000-8000-0000000000a2", TenantID: tA, Name: "old-01", Type: "linux_host", Owner: "ops", Connection: &inventory.Connection{Method: "ssh", Address: "10.0.0.12"}})
	put(inventory.Asset{ID: "b0000000-0000-4000-8000-0000000000b1", TenantID: tB, Name: "web-01", Type: "linux_host", Owner: "b", Connection: &inventory.Connection{Method: "ssh", Address: "10.0.0.11"}})
	coll := &fakeCollector{method: "ssh", byAddr: map[string]discovery.Observation{
		"10.0.0.10": {Confidence: 0.95, Assets: []inventory.Asset{
			// Сборщик пытается выставить атрибуты классификации — они должны быть сброшены.
			{Name: "app-02", Type: "linux_host", Environment: "production", Criticality: "critical", Owner: "attacker", DataClass: "public", Objects: map[string][]string{"systemd_unit": {"nginx.service"}}},
			{Name: "nginx", Type: "application", Connection: &inventory.Connection{Method: "ssh", Address: "203.0.113.9"}},
		}, Dependencies: []discovery.ObservedDependency{{SourceName: "nginx", TargetName: "app-02", RelationType: "runs_on", Confidence: 0.9}}},
		"10.0.0.11": {Confidence: 0.9, Assets: []inventory.Asset{{Name: "web-01", Type: "linux_host", Objects: map[string][]string{"systemd_unit": {"nginx.service", "php-fpm.service"}}}}},
		"10.0.0.12": {Confidence: 0.9, Assets: []inventory.Asset{{Name: "old-01-renamed", Type: "firewall"}}},
		"10.0.0.13": {Confidence: 0.5, Warnings: []string{"partial output"}, Assets: []inventory.Asset{{Name: "mystery", Type: "linux_host"}}},
	}}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	al := audit.New(audit.NewMemoryKeys(), priv)
	ev := evidence.NewStore()
	return &fixture{svc: discovery.New(discovery.NewMemoryRepo(), inv, al, ev, fakeCreds{}, discovery.Config{}, coll), inv: inv, al: al, ev: ev, coll: coll}
}

func scopeIn(ranges ...string) discovery.ScopeInput {
	return discovery.ScopeInput{Name: "dc-1 servers", Ranges: ranges, Methods: []string{"ssh"}, Limits: discovery.Limits{MaxSessions: 2, PPS: 50}, Responsible: "infra lead", ValidUntil: time.Now().Add(30 * 24 * time.Hour)}
}

func (f *fixture) activeScope(t *testing.T, in discovery.ScopeInput) *discovery.Scope {
	t.Helper()
	sc, err := f.svc.CreateScope(admin1, in)
	if err != nil {
		t.Fatal(err)
	}
	if sc, err = f.svc.ApproveScope(admin2, sc.ID); err != nil {
		t.Fatal(err)
	}
	return sc
}

func target(addr string) discovery.TargetInput {
	return discovery.TargetInput{Address: addr, Method: "ssh", Port: 22, CredentialRef: "kv/discovery/ssh", HostKey: "ssh-ed25519 AAAA"}
}

func TestScopeDocumentRules(t *testing.T) {
	f := newFixture(t)
	for _, a := range []identity.Actor{engineer, operator, agent} {
		if _, err := f.svc.CreateScope(a, scopeIn("10.0.0.0/24")); !problem.Is(err, problem.Forbidden) {
			t.Fatalf("%s must not create scope: %v", a.Ref(), err)
		}
	}
	for _, bad := range []discovery.ScopeInput{scopeIn("0.0.0.0/0"), scopeIn("10.0.0.0/8"), scopeIn("not-a-cidr"), {Name: "x", Ranges: []string{"10.0.0.0/24"}, Methods: []string{"telnet"}, Limits: discovery.Limits{MaxSessions: 1, PPS: 1}, Responsible: "r", ValidUntil: time.Now().Add(time.Hour)}} {
		if _, err := f.svc.CreateScope(admin1, bad); !problem.Is(err, problem.InvalidParams) {
			t.Fatalf("%+v must be rejected: %v", bad, err)
		}
	}
	past := scopeIn("10.0.0.0/24")
	past.ValidUntil = time.Now().Add(-time.Hour)
	if _, err := f.svc.CreateScope(admin1, past); !problem.Is(err, problem.InvalidParams) {
		t.Fatalf("expired validity: %v", err)
	}
	sc, err := f.svc.CreateScope(admin1, scopeIn("10.0.0.0/24"))
	if err != nil || sc.Status != "draft" {
		t.Fatalf("create: %v %+v", err, sc)
	}
	if _, err := f.svc.ApproveScope(admin1, sc.ID); !problem.Is(err, problem.SeparationOfDuties) {
		t.Fatalf("author cannot approve: %v", err)
	}
	if _, err := f.svc.ApproveScope(engineer, sc.ID); !problem.Is(err, problem.Forbidden) {
		t.Fatalf("engineer cannot approve: %v", err)
	}
	if _, err := f.svc.ApproveScope(adminB, sc.ID); !problem.Is(err, problem.NotFound) {
		t.Fatalf("other tenant cannot see scope: %v", err)
	}
	if sc, err = f.svc.ApproveScope(admin2, sc.ID); err != nil || sc.Status != "active" {
		t.Fatalf("approve: %v %+v", err, sc)
	}
	list, _ := f.svc.ListScopes(engineer)
	if len(list) != 1 {
		t.Fatal("engineer must see scopes to launch discovery")
	}
	if l, _ := f.svc.ListScopes(adminB); len(l) != 0 {
		t.Fatal("cross-tenant scopes")
	}
	if _, err := f.svc.ListScopes(operator); !problem.Is(err, problem.Forbidden) {
		t.Fatalf("operator list: %v", err)
	}
}

func TestJobRejectedWithoutScopeOrOutsideIt(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	draft, _ := f.svc.CreateScope(admin1, scopeIn("10.0.0.0/24"))
	if _, err := f.svc.CreateJob(ctx, engineer, discovery.JobInput{ScopeID: draft.ID, Targets: []discovery.TargetInput{target("10.0.0.10")}}); !problem.Is(err, problem.PolicyDenied) {
		t.Fatalf("unapproved scope: %v", err)
	}
	sc := f.activeScope(t, scopeIn("10.0.0.0/24"))
	cases := map[string]discovery.JobInput{
		"outside range": {ScopeID: sc.ID, Targets: []discovery.TargetInput{target("10.0.0.10"), target("10.0.1.10")}},
		"method":        {ScopeID: sc.ID, Targets: []discovery.TargetInput{{Address: "10.0.0.10", Method: "docker_api", CredentialRef: "kv/x"}}},
		"no scope":      {ScopeID: "00000000-0000-4000-8000-000000000000", Targets: []discovery.TargetInput{target("10.0.0.10")}},
	}
	for name, in := range cases {
		if _, err := f.svc.CreateJob(ctx, engineer, in); !problem.Is(err, problem.PolicyDenied) {
			t.Fatalf("%s: want 403 policy-denied, got %v", name, err)
		}
	}
	// Scope другого tenant — как отсутствующий.
	if _, err := f.svc.CreateJob(ctx, adminB, discovery.JobInput{ScopeID: sc.ID, Targets: []discovery.TargetInput{target("10.0.0.10")}}); !problem.Is(err, problem.PolicyDenied) {
		t.Fatalf("cross-tenant scope: %v", err)
	}
	if _, err := f.svc.CreateJob(ctx, agent, discovery.JobInput{ScopeID: sc.ID, Targets: []discovery.TargetInput{target("10.0.0.10")}}); !problem.Is(err, problem.Forbidden) {
		t.Fatalf("AI agent: %v", err)
	}
	if _, err := f.svc.CreateJob(ctx, engineer, discovery.JobInput{ScopeID: sc.ID, Targets: []discovery.TargetInput{{Address: "host.example", Method: "ssh", CredentialRef: "kv/x"}}}); !problem.Is(err, problem.InvalidParams) {
		t.Fatalf("hostname target: %v", err)
	}
	rejected := 0
	for _, e := range f.al.Entries(tA) {
		if e.Action == "discovery.job_rejected" {
			rejected++
		}
	}
	if rejected != 4 {
		t.Fatalf("every policy denial must be audited, got %d", rejected)
	}
}

func TestJobReconciliationConfidenceAndEvidence(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	in := scopeIn("10.0.0.0/24")
	in.Limits.MaxSessions = 1
	sc := f.activeScope(t, in)
	job, err := f.svc.CreateJob(ctx, engineer, discovery.JobInput{ScopeID: sc.ID, Targets: []discovery.TargetInput{target("10.0.0.10"), target("10.0.0.11"), target("10.0.0.12"), target("10.0.0.13"), target("10.0.0.99")}})
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Wait()
	job, err = f.svc.GetJob(engineer, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != discovery.JobCompleted {
		t.Fatalf("status: %s %s", job.Status, job.Error)
	}
	if f.coll.maxSeen.Load() != 1 {
		t.Fatalf("max_sessions=1 must limit concurrency, saw %d", f.coll.maxSeen.Load())
	}
	byKey := map[string]discovery.Finding{}
	for _, fd := range job.Findings {
		byKey[fd.Key] = fd
	}
	raw, _ := json.MarshalIndent(job.Findings, "", " ")
	app := byKey["linux_host|app-02"]
	if app.Change != discovery.FindingNew || !app.Applied || app.NeedsConfirmation || !app.ClassificationIncomplete {
		t.Fatalf("new high-confidence: %s", raw)
	}
	a, ok := f.inv.Get(tA, app.AssetID)
	if !ok || a.Environment != "" || a.Criticality != "" || a.Owner != "" || a.DataClass != "" || a.Source != "discovery" || a.Connection.Address != "10.0.0.10" {
		t.Fatalf("discovery must never set classification: %+v", a)
	}
	if len(a.ClassificationComplete()) == 0 {
		t.Fatal("classification must be incomplete (blocks execution)")
	}
	ngx := byKey["application|nginx"]
	if !ngx.Applied {
		t.Fatalf("nginx: %s", raw)
	}
	if n, _ := f.inv.Get(tA, ngx.AssetID); n.Connection != nil {
		t.Fatal("connection outside scope must be dropped")
	}
	if deps := f.inv.Dependencies(tA); len(deps) != 1 || deps[0].VerifiedBy != "discovery" {
		t.Fatalf("dependency: %+v", deps)
	}
	web := byKey["linux_host|web-01"]
	if web.Change != discovery.FindingChanged || !web.Applied {
		t.Fatalf("changed: %s", raw)
	}
	w, _ := f.inv.Get(tA, web.AssetID)
	if w.Environment != "production" || w.Owner != "web-team" || w.Criticality != "high" || !w.HasObject("systemd_unit", "php-fpm.service") || w.Connection.CredentialRef != "kv/discovery/ssh" {
		t.Fatalf("changed asset must keep classification: %+v", w)
	}
	if wb, _ := f.inv.Get(tB, "b0000000-0000-4000-8000-0000000000b1"); wb.HasObject("systemd_unit", "php-fpm.service") {
		t.Fatal("tenant B asset with the same name/address must not be touched")
	}
	if old := byKey["linux_host|old-01"]; old.Change != discovery.FindingMissing || old.Applied {
		t.Fatalf("missing: %s", raw)
	}
	myst := byKey["linux_host|mystery"]
	if myst.Change != discovery.FindingNew || !myst.NeedsConfirmation || myst.Applied {
		t.Fatalf("low confidence must wait for confirmation: %s", raw)
	}
	if job.Summary.PendingConfirmation != 1 || job.Summary.New < 3 || job.Summary.Missing != 1 {
		t.Fatalf("summary: %+v", job.Summary)
	}
	if job.Results[4].Status != "error" {
		t.Fatalf("unreachable target: %+v", job.Results[4])
	}
	// Evidence задания.
	if job.EvidenceID == "" {
		t.Fatal("evidence must be stored")
	}
	if ok, err := f.ev.Verify(tA, job.EvidenceID); !ok || err != nil {
		t.Fatal("evidence digest")
	}
	_, body, err := f.ev.Get(tA, job.EvidenceID, "user:adm-1", "test")
	if err != nil || !json.Valid(body) {
		t.Fatal("evidence body")
	}
	// Подтверждение.
	if _, err := f.svc.Confirm(operator, job.ID, discovery.ConfirmInput{Keys: []string{myst.Key}}); !problem.Is(err, problem.Forbidden) {
		t.Fatalf("operator confirm: %v", err)
	}
	if _, err := f.svc.Confirm(adminB, job.ID, discovery.ConfirmInput{Keys: []string{myst.Key}}); !problem.Is(err, problem.NotFound) {
		t.Fatalf("cross-tenant confirm: %v", err)
	}
	job, err = f.svc.Confirm(engineer, job.ID, discovery.ConfirmInput{Keys: []string{myst.Key}})
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range job.Findings {
		if fd.Key == myst.Key && (!fd.Applied || fd.ConfirmedBy != "user:eng-1") {
			t.Fatalf("confirm: %+v", fd)
		}
	}
	if job.Summary.PendingConfirmation != 0 {
		t.Fatalf("summary after confirm: %+v", job.Summary)
	}
	if _, err := f.svc.GetJob(adminB, job.ID); !problem.Is(err, problem.NotFound) {
		t.Fatalf("cross-tenant job: %v", err)
	}
	actions := map[string]int{}
	for _, e := range f.al.Entries(tA) {
		actions[e.Action]++
	}
	if actions["discovery.job_created"] != 1 || actions["discovery.job_completed"] != 1 || actions["discovery.confirmed"] != 1 || actions["discovery.scope_approved"] != 1 {
		t.Fatalf("audit: %v", actions)
	}
	for _, u := range f.coll.gotCreds {
		if u != "ro-kv/discovery/ssh" {
			t.Fatalf("collector must receive read-only credential from the source: %v", f.coll.gotCreds)
		}
	}
}
