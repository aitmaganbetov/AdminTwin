// Package db — доступ к PostgreSQL (§12): пул соединений, миграции, tenant-scoped транзакции.
//
// Любая транзакция приложения выполняется под ролью admintwin_app (SET LOCAL ROLE) с tenant,
// заданным через set_config('admintwin.tenant_id', ..., true). Поэтому RLS действует даже если
// пул подключён владельцем схемы или суперпользователем. Платформенные операции без tenant
// (миграции, загрузка списка tenants, восстановление после рестарта) — только через Platform.
package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DB — пул соединений.
type DB struct {
	Pool *pgxpool.Pool
}

// Open подключается к БД и проверяет соединение.
func Open(ctx context.Context, url string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("db: parse url: %w", err)
	}
	if cfg.MaxConns == 0 || cfg.MaxConns > 50 {
		cfg.MaxConns = 20
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = "admintwin-core"
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "15000"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return &DB{Pool: pool}, nil
}

// Close закрывает пул.
func (d *DB) Close() { d.Pool.Close() }

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ErrBadTenant — tenant не является UUID (fail closed: RLS-функция ожидает uuid).
var ErrBadTenant = errors.New("db: tenant id must be a uuid")

// WithTenant выполняет fn в транзакции под ролью admintwin_app с заданным tenant.
func (d *DB) WithTenant(ctx context.Context, tenantID string, fn func(tx pgx.Tx) error) error {
	if !uuidRe.MatchString(tenantID) {
		return ErrBadTenant
	}
	return pgx.BeginFunc(ctx, d.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE admintwin_app"); err != nil {
			return fmt.Errorf("db: set role: %w", err)
		}
		if _, err := tx.Exec(ctx, "SELECT set_config('admintwin.tenant_id', $1, true)", tenantID); err != nil {
			return fmt.Errorf("db: set tenant: %w", err)
		}
		return fn(tx)
	})
}

// Platform выполняет fn в транзакции владельца схемы (без SET ROLE). Требует роль с BYPASSRLS или
// суперпользователя. Использовать только для миграций, загрузки tenants и восстановления.
func (d *DB) Platform(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, d.Pool, fn)
}

// Migrate применяет *.up.sql из каталога по порядку имён; учёт — в таблице schema_migrations.
// Каждая миграция — отдельная транзакция (файлы сами содержат BEGIN/COMMIT).
func (d *DB) Migrate(ctx context.Context, dir string) ([]string, error) {
	if _, err := d.Pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.up.sql"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	var applied []string
	for _, f := range files {
		version := strings.TrimSuffix(filepath.Base(f), ".up.sql")
		var exists bool
		if err := d.Pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", version).Scan(&exists); err != nil {
			return applied, err
		}
		if exists {
			continue
		}
		sql, err := os.ReadFile(f)
		if err != nil {
			return applied, err
		}
		// Сериализация параллельных стартов нескольких экземпляров.
		conn, err := d.Pool.Acquire(ctx)
		if err != nil {
			return applied, err
		}
		_, err = conn.Exec(ctx, "SELECT pg_advisory_lock(7438291)")
		if err == nil {
			err = conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", version).Scan(&exists)
		}
		if err == nil && !exists {
			if _, err = conn.Exec(ctx, string(sql)); err == nil {
				_, err = conn.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version)
			}
		}
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock(7438291)")
		conn.Release()
		if err != nil {
			return applied, fmt.Errorf("db: migration %s: %w", version, err)
		}
		if !exists {
			applied = append(applied, version)
		}
	}
	return applied, nil
}

// AppRole — адаптер для репозиториев, которые сами задают tenant (set_config): каждая транзакция
// начинается под ролью admintwin_app, поэтому RLS действует и при подключении владельцем/суперпользователем.
type AppRole struct{ DB *DB }

// Begin начинает транзакцию под ролью admintwin_app.
func (r AppRole) Begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := r.DB.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE admintwin_app"); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("db: set role: %w", err)
	}
	return tx, nil
}
