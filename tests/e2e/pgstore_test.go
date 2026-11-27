package e2e

// Хранение ядра в PostgreSQL: переживание рестарта, восстановление прерванных исполнений,
// непрерывность hash chain, постоянные ключи ПДн, изоляция tenant через RLS.
// Запуск: ADMINTWIN_TEST_STORE_URL=postgres://... go test ./tests/e2e/ -run TestPostgresStore
// ВНИМАНИЕ: тест пересоздаёт схему public в указанной БД.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aitmaganbetov/admintwin/internal/app"
	"github.com/aitmaganbetov/admintwin/services/audit"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/sim"
)

func key32() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func TestPostgresStore(t *testing.T) {
	url := os.Getenv("ADMINTWIN_TEST_STORE_URL")
	if url == "" {
		t.Skip("ADMINTWIN_TEST_STORE_URL is not set")
	}
	ctx := context.Background()
	c, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public"); err != nil {
		t.Fatal(err)
	}
	c.Close(ctx)

	cfg := app.Config{Root: "../..", FixturesPath: "../../infra/dev/fixtures.yaml", DevAuth: true, Simulator: true,
		DatabaseURL: url, Migrate: true, AuditSigningKey: key32(), PIIMasterKey: key32()}
	mk := func() (*app.App, *env) {
		a, err := app.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(a.Server.Handler())
		t.Cleanup(srv.Close)
		return a, &env{t: t, app: a, srv: srv}
	}

	// --- Экземпляр 1 ---
	a1, e1 := mk()
	r := e1.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": appAPI}, "Idempotency-Key", "pg-1")
	closedID := r.str("id")
	e1.waitStatus(engineerA, closedID, "closed")
	waiting := e1.propose(engineerA, "linux.logs.rotate_cleanup", appLinux, map[string]any{"directory": "/var/log/app"})
	if waiting.str("status") != "waiting_approval" {
		t.Fatalf("setup: %s", waiting.Raw)
	}
	started := make(chan string, 1)
	a1.Sim.Started = started
	a1.Sim.InjectFault(dockerWeb, sim.FaultHangConfirm)
	hung := e1.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": "9b8c7d6e5f4a"})
	<-started
	e1.waitStatus(engineerA, hung.str("id"), "executing")
	ex := e1.do(engineerA, "GET", "/api/v1/changes/"+closedID+"/executions", nil).Body["items"].([]any)
	evID := ex[0].(map[string]any)["result"].(map[string]any)["evidence_id"].(string)
	entriesBefore := len(a1.Audit.Entries(tenantA))

	// --- «Рестарт»: экземпляр 2 на той же БД, пока исполнение в экземпляре 1 висит ---
	a2, e2 := mk()
	if got := e2.do(engineerA, "GET", "/api/v1/changes/"+closedID, nil); got.str("status") != "closed" {
		t.Fatalf("closed change must survive restart: %s", got.Raw)
	}
	if got := e2.do(engineerA, "GET", "/api/v1/changes/"+hung.str("id"), nil); got.str("status") != "manual_review" {
		t.Fatalf("execution interrupted by restart must go to manual_review: %s", got.Raw)
	}
	if again := e2.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": appAPI}, "Idempotency-Key", "pg-1"); again.str("id") != closedID {
		t.Fatalf("idempotency must survive restart: %s", again.Raw)
	}
	if d := e2.do(managerA, "POST", "/api/v1/changes/"+waiting.str("id")+"/decisions", map[string]any{"decision": "approve"}); d.Status != 200 {
		t.Fatalf("approve after restart: %d %s", d.Status, d.Raw)
	}
	e2.waitStatus(managerA, waiting.str("id"), "preflight_failed", "closed")
	if got := e2.do(engineerB, "GET", "/api/v1/changes/"+closedID, nil); got.Status != 404 {
		t.Fatalf("cross-tenant through PostgreSQL: %d", got.Status)
	}
	if got := e2.do(auditorA, "GET", "/api/v1/evidence/"+evID+"?purpose=post-restart-check", nil); got.Status != 200 {
		t.Fatalf("evidence from instance 1 via instance 2: %d %s", got.Status, got.Raw)
	}

	// Аудит: цепочка одна на оба экземпляра и верифицируется; checkpoint подписан тем же ключом.
	integ := e2.do(auditorA, "GET", "/api/v1/audit-logs/integrity", nil)
	if integ.Body["valid"] != true || int(integ.Body["entries"].(float64)) <= entriesBefore {
		t.Fatalf("audit chain across restart: %s", integ.Raw)
	}
	cp, _ := a2.Audit.Checkpoint(tenantA)
	if !audit.VerifyCheckpoint(a1.AuditPub, cp) {
		t.Fatal("checkpoint must verify with the configured signing key across instances")
	}
	// Экземпляр 1 всё ещё жив и продолжает писать: конфликт цепочки разрешается перечитыванием.
	if _, err := a1.Audit.Append(audit.Record{TenantID: tenantA, Actor: "user:x", Action: "test.concurrent", ObjectType: "t", ObjectID: "1"}); err != nil {
		t.Fatalf("concurrent writer: %v", err)
	}
	if ok, at, err := a2.Audit.VerifyTenant(tenantA); !ok {
		t.Fatalf("chain broken at %d: %v", at, err)
	}

	// Ключи ПДн постоянны между экземплярами; crypto-shredding необратим и не ломает цепочку.
	e, err := a2.Audit.Append(audit.Record{TenantID: tenantA, Actor: "user:eng-1", Action: "login", ObjectType: "session", ObjectID: "s1",
		PII: map[string]string{"email": "eng@example.kz"}})
	if err != nil {
		t.Fatal(err)
	}
	a3, _ := mk()
	if got, err := a3.Audit.RevealPII(e); err != nil || got["email"] != "eng@example.kz" {
		t.Fatalf("PII key must persist across instances: %v %v", got, err)
	}
	if err := a3.Audit.ShredTenantPII(tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := a2.Audit.RevealPII(e); err == nil {
		t.Fatal("PII must be unreadable after shredding")
	}
	if ok, _, err := a3.Audit.VerifyTenant(tenantA); !ok {
		t.Fatalf("chain must stay valid after shredding: %v", err)
	}

	// Освободить зависшее исполнение экземпляра 1.
	a1.Kill.Set(tenantA, false, true, "user:test", "cleanup")
	done := make(chan struct{})
	go func() { a1.Coordinator.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("instance 1 did not stop")
	}
}
