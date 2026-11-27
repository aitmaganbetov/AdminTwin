// T-TENANT-001 (уровень БД): изоляция tenant через RLS и инварианты схемы на реальном PostgreSQL.
// Запуск: ADMINTWIN_TEST_DATABASE_URL=postgres://... go test ./tests/security/
// БД должна быть пустой: тест применяет миграцию и удаляет схему после себя.
package security

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

const (
	tA = "11111111-1111-4111-8111-111111111111"
	tB = "22222222-2222-4222-8222-222222222222"
	aA = "a0000000-0000-4000-8000-000000000001"
	aB = "b0000000-0000-4000-8000-000000000001"
	cA = "c0000000-0000-4000-8000-000000000001"
	eA = "e0000000-0000-4000-8000-000000000001"
)

func connect(t *testing.T) (*pgx.Conn, context.Context) {
	t.Helper()
	url := os.Getenv("ADMINTWIN_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("ADMINTWIN_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	c, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(ctx) })
	return c, ctx
}

func exec(t *testing.T, ctx context.Context, c *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := c.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("%s: %v", strings.SplitN(sql, "\n", 2)[0], err)
	}
}

func TestRLSIsolationAndInvariants(t *testing.T) {
	c, ctx := connect(t)
	up, err := os.ReadFile("../../db/migrations/0001_init.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, _ := os.ReadFile("../../db/migrations/0001_init.down.sql")
	_, _ = c.Exec(ctx, string(down))
	exec(t, ctx, c, string(up))
	t.Cleanup(func() { _, _ = c.Exec(ctx, "RESET ROLE"); _, _ = c.Exec(ctx, string(down)) })

	// Данные двух tenant (как владелец схемы; FORCE RLS требует tenant и для владельца).
	for _, tn := range []struct{ id, asset string }{{tA, aA}, {tB, aB}} {
		exec(t, ctx, c, "SELECT set_config('admintwin.tenant_id', $1, false)", tn.id)
		exec(t, ctx, c, "INSERT INTO tenants (id, name, edition) VALUES ($1::uuid, $1::text, 'enterprise')", tn.id)
		exec(t, ctx, c, `INSERT INTO assets (id, tenant_id, name, type, environment, criticality, data_class, owner, verified)
			VALUES ($1, $2, 'h', 'docker_host', 'production', 'high', 'internal', 'ops', true)`, tn.asset, tn.id)
	}
	exec(t, ctx, c, "SELECT set_config('admintwin.tenant_id', $1, false)", tA)
	exec(t, ctx, c, `INSERT INTO change_requests (id, tenant_id, type, status, runbook_id, runbook_version, runbook_digest, risk, asset_id, reason, author_id, author_kind)
		VALUES ($1, $2, 'normal', 'waiting_approval', 'docker.container.restart', '1.3.0', 'sha256:x', 'low', $3, 'r', 'eng-1', 'user')`, cA, tA, aA)
	exec(t, ctx, c, `INSERT INTO evidence (id, tenant_id, kind, ref, hash_sha256, source, collector, collected_at_utc, time_source, storage_ref, retention_class, legal_hold)
		VALUES ($1, $2, 'execution', 'x', 'sha256:x', 's', 'c', now(), 'ntp', 'minio://x', 'compliance-7y', true)`, eA, tA)
	exec(t, ctx, c, `INSERT INTO audit_logs (tenant_id, seq, at, actor, action, object_type, object_id, prev_hash, hash)
		VALUES ($1, 1, now(), 'user:eng-1', 'change.created', 'change_request', $2, 'g', 'h')`, tA, cA)

	// Дальше — от имени роли приложения.
	exec(t, ctx, c, "SET ROLE admintwin_app")
	count := func(table string) int {
		var n int
		if err := c.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return n
	}
	mustFail := func(name, want, sql string, args ...any) {
		t.Helper()
		_, err := c.Exec(ctx, sql, args...)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want error containing %q, got %v", name, want, err)
		}
	}

	t.Run("no tenant set → no rows (fail closed)", func(t *testing.T) {
		exec(t, ctx, c, "SELECT set_config('admintwin.tenant_id', '', false)")
		for _, tb := range []string{"tenants", "assets", "change_requests", "evidence", "audit_logs"} {
			if n := count(tb); n != 0 {
				t.Errorf("%s: %d rows visible without tenant", tb, n)
			}
		}
	})

	t.Run("tenant B sees only own rows", func(t *testing.T) {
		exec(t, ctx, c, "SELECT set_config('admintwin.tenant_id', $1, false)", tB)
		if count("assets") != 1 || count("change_requests") != 0 || count("evidence") != 0 || count("audit_logs") != 0 {
			t.Error("tenant B must not see tenant A data")
		}
		var n int
		_ = c.QueryRow(ctx, "SELECT count(*) FROM assets WHERE id = $1", aA).Scan(&n)
		if n != 0 {
			t.Error("direct lookup by foreign id must return nothing")
		}
		mustFail("write into foreign tenant", "row-level security",
			`INSERT INTO assets (tenant_id, name, type) VALUES ($1, 'x', 'linux_host')`, tA)
		tag, err := c.Exec(ctx, "UPDATE assets SET name = 'pwned' WHERE id = $1", aA)
		if err != nil || tag.RowsAffected() != 0 {
			t.Errorf("update of foreign row must affect 0 rows, got %v %v", tag, err)
		}
		mustFail("change referencing foreign asset", "violates",
			`INSERT INTO change_requests (tenant_id, type, status, runbook_id, runbook_version, runbook_digest, risk, asset_id, reason, author_id, author_kind)
			 VALUES ($1, 'normal', 'draft', 'r', '1', 'd', 'low', $2, 'r', 'x', 'user')`, tB, aA)
	})

	t.Run("schema invariants (tenant A)", func(t *testing.T) {
		exec(t, ctx, c, "SELECT set_config('admintwin.tenant_id', $1, false)", tA)
		mustFail("AI as approver", "approval_decisions_actor_kind_check",
			`INSERT INTO approval_decisions (tenant_id, change_id, actor_id, actor_kind, roles, verdict) VALUES ($1, $2, 'agent', 'ai_agent', '{}', 'approve')`, tA, cA)
		mustFail("author approves own change", "separation of duties",
			`INSERT INTO approval_decisions (tenant_id, change_id, actor_id, actor_kind, roles, verdict) VALUES ($1, $2, 'eng-1', 'user', '{it_manager}', 'approve')`, tA, cA)
		exec(t, ctx, c, `INSERT INTO approval_decisions (tenant_id, change_id, actor_id, actor_kind, roles, verdict) VALUES ($1, $2, 'mgr-1', 'user', '{it_manager}', 'approve')`, tA, cA)
		mustFail("same approver twice", "duplicate key",
			`INSERT INTO approval_decisions (tenant_id, change_id, actor_id, actor_kind, roles, verdict) VALUES ($1, $2, 'mgr-1', 'user', '{it_manager}', 'approve')`, tA, cA)
		mustFail("execution without change", "violates foreign key",
			`INSERT INTO execution_requests (tenant_id, change_id, runbook_id, asset_id, status, fencing_token) VALUES ($1, gen_random_uuid(), 'r', $2, 'x', 0)`, tA, aA)
		mustFail("AI break-glass", "change_requests_check",
			`INSERT INTO change_requests (tenant_id, type, status, runbook_id, runbook_version, runbook_digest, risk, asset_id, reason, author_id, author_kind)
			 VALUES ($1, 'emergency', 'draft', 'r', '1', 'd', 'low', $2, 'r', 'agent', 'ai_agent')`, tA, aA)
		mustFail("audit update", "permission denied", "UPDATE audit_logs SET actor = 'x'")
		mustFail("audit delete", "permission denied", "DELETE FROM audit_logs")
		mustFail("evidence delete by app role", "permission denied", "DELETE FROM evidence WHERE id = $1", eA)
		mustFail("evidence digest rewrite", "permission denied", "UPDATE evidence SET hash_sha256 = 'forged' WHERE id = $1", eA)
		mustFail("evidence access without purpose", "evidence_access_log_purpose_check",
			`INSERT INTO evidence_access_log (tenant_id, evidence_id, actor, purpose) VALUES ($1, $2, 'aud', '')`, tA, eA)
	})

	t.Run("owner is also bound by append-only and legal hold", func(t *testing.T) {
		exec(t, ctx, c, "RESET ROLE")
		exec(t, ctx, c, "SELECT set_config('admintwin.tenant_id', $1, false)", tA)
		mustFail("owner audit update", "append-only", "UPDATE audit_logs SET actor = 'x'")
		mustFail("owner audit truncate", "append-only", "TRUNCATE audit_logs")
		mustFail("owner deletes held evidence", "legal hold", "DELETE FROM evidence WHERE id = $1", eA)
	})
}
