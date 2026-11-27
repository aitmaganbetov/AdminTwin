package incidents_test

// Репозиторий PostgreSQL и миграция 0003 на реальной БД (RLS, инварианты).
// Запуск: ADMINTWIN_TEST_INCIDENTS_DB_URL=postgres://... go test ./services/incidents/ -run PG
// БД должна быть пустой: тест применяет 0001 и 0003 и откатывает их после себя.

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/incidents"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	"github.com/aitmaganbetov/admintwin/services/telemetry"
)

func applyMigrations(t *testing.T, ctx context.Context, c *pgx.Conn) {
	t.Helper()
	read := func(p string) string {
		b, err := os.ReadFile("../../db/migrations/" + p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	down3, down1 := read("0003_observability.down.sql"), read("0001_init.down.sql")
	_, _ = c.Exec(ctx, down3)
	_, _ = c.Exec(ctx, down1)
	for _, m := range []string{"0001_init.up.sql", "0003_observability.up.sql"} {
		if _, err := c.Exec(ctx, read(m)); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
	}
	t.Cleanup(func() {
		_, _ = c.Exec(ctx, "RESET ROLE")
		if _, err := c.Exec(ctx, down3); err != nil {
			t.Errorf("0003 down: %v", err)
		}
		if _, err := c.Exec(ctx, down1); err != nil {
			t.Errorf("0001 down: %v", err)
		}
	})
}

func TestPGRepoAndMigration(t *testing.T) {
	url := os.Getenv("ADMINTWIN_TEST_INCIDENTS_DB_URL")
	if url == "" {
		t.Skip("ADMINTWIN_TEST_INCIDENTS_DB_URL is not set")
	}
	ctx := context.Background()
	c, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(ctx) })
	applyMigrations(t, ctx, c)
	for _, tn := range []string{tA, tB} {
		if _, err := c.Exec(ctx, "SELECT set_config('admintwin.tenant_id', $1, false)", tn); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Exec(ctx, "INSERT INTO tenants (id, name, edition) VALUES ($1::uuid, $1::text, 'enterprise')", tn); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Exec(ctx, "SELECT set_config('admintwin.tenant_id', '', false)"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, "SET ROLE admintwin_app"); err != nil {
		t.Fatal(err)
	}

	inv := inventory.NewStore()
	if err := inv.LoadFixture("../../infra/dev/fixtures.yaml"); err != nil {
		t.Fatal(err)
	}
	st := &fakeStarter{}
	svc := incidents.New(incidents.NewPGRepo(c), inv, nil, st, incidents.Config{})

	e := ev(appLinux, "http_5xx", telemetry.SevHigh, timeNow())
	e.Labels = map[string]string{"status": "502"}
	ids, err := svc.HandleEvents(ctx, tA, []telemetry.Event{e})
	if err != nil || len(ids) != 1 {
		t.Fatalf("create: %v %v", ids, err)
	}
	id := ids[0]
	// Дедупликация через Open() из PostgreSQL.
	again := e
	again.ID = telemetry.NewID()
	if ids2, err := svc.HandleEvents(ctx, tA, []telemetry.Event{again}); err != nil || len(ids2) != 1 || ids2[0] != id {
		t.Fatalf("dedup: %v %v", ids2, err)
	}
	if _, err := svc.Transition(ctx, operator, id, incidents.TransitionInput{To: incidents.StatusTriaged, Reason: "triage"}); err != nil {
		t.Fatal(err)
	}
	inc, err := svc.RecordRCA(ctx, orch, id, incidents.RCAResult{TaskID: "task-1", Status: "completed", Hypotheses: []incidents.Hypothesis{{Cause: "upstream_container_stopped", Confidence: 0.8, Supporting: []incidents.Evidence{{Fact: "exit 137", EvidenceID: "ev-1"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if inc.RCA.Status != incidents.RCACompleted || inc.Owner != "web-team" {
		t.Fatalf("rca/owner: %+v %s", inc.RCA, inc.Owner)
	}
	yes := true
	if _, _, err := svc.SetFeedback(ctx, operator, id, incidents.FeedbackInput{Correct: &yes, Rating: 4}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Get(ctx, viewer, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.EventIDs) != 2 || got.Status != incidents.StatusTriaged || len(got.Timeline) < 6 || got.Feedback == nil || got.Version < 4 {
		t.Fatalf("round trip: events=%d status=%s timeline=%d version=%d", len(got.EventIDs), got.Status, len(got.Timeline), got.Version)
	}
	mgr := operator
	mgr.Roles = append(mgr.Roles, "it_manager")
	if cases, err := svc.ExportCandidates(ctx, mgr); err != nil || len(cases) != 1 {
		t.Fatalf("candidates: %v %v", cases, err)
	}

	// Изоляция: tenant B не видит инцидент A ни через сервис, ни SQL (RLS).
	if _, err := svc.Get(ctx, operB, id); !problem.Is(err, problem.NotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if list, _ := svc.List(ctx, operB, incidents.Filter{}); len(list) != 0 {
		t.Fatal("cross-tenant list")
	}
	count := func(tenant, table string) int {
		tx, err := c.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		_, _ = tx.Exec(ctx, "SELECT set_config('admintwin.tenant_id', $1, true)", tenant)
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, tbl := range []string{"incidents", "incident_timeline", "incident_feedback"} {
		if count(tB, tbl) != 0 || count(tA, tbl) == 0 {
			t.Fatalf("RLS on %s", tbl)
		}
	}
	if n := count("", "incidents"); n != 0 {
		t.Fatal("without tenant no rows must be visible (fail closed)")
	}
	// Инварианты БД.
	mustFail := func(name, sql string, args ...any) {
		t.Helper()
		tx, err := c.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		_, _ = tx.Exec(ctx, "SELECT set_config('admintwin.tenant_id', $1, true)", tA)
		if _, err := tx.Exec(ctx, sql, args...); err == nil {
			t.Fatalf("%s must fail", name)
		}
	}
	mustFail("timeline is append-only", "UPDATE incident_timeline SET text = 'x'")
	mustFail("delete is not granted", "DELETE FROM incidents")
	mustFail("resolved without postmortem", "UPDATE incidents SET status = 'resolved' WHERE id = $1", id)
	mustFail("insert for another tenant", "INSERT INTO events (tenant_id, kind, severity, title, fingerprint, at) VALUES ($1, 'x_y', 'high', 't', 'f', now())", tB)
	mustFail("scope approved by author", `INSERT INTO discovery_scopes (tenant_id, name, methods, responsible, created_by, approved_by, approved_at) VALUES ($1, 's', '{ssh}', 'r', 'user:a', 'user:a', now())`, tA)
}
