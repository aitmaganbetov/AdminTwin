// Package db — read-only коннектор PostgreSQL (§14 п.4, тир MVP): инструмент postgres.activity,
// метрики подключений и репликации, discovery (версия, базы данных).
//
// Только чтение: сессия переводится в READ ONLY (`SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY`,
// default_transaction_read_only=on), statement_timeout ограничивает каждый запрос; выполняются только
// фиксированные SELECT/SHOW этого файла. Учётка — read-only роль (рекомендуется pg_monitor) из Vault.
// Тексты запросов из pg_stat_activity не возвращаются: только нормализованный отпечаток без литералов.
package db

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aitmaganbetov/admintwin/connectors/internal/common"
	"github.com/aitmaganbetov/admintwin/services/discovery"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	"github.com/aitmaganbetov/admintwin/services/telemetry"
)

// Method — значение inventory.Connection.Method.
const Method = "postgres"

// Режимы TLS (подмножество libpq sslmode).
const (
	SSLVerifyFull = "verify-full" // по умолчанию: проверка цепочки и имени сервера
	SSLDisable    = "disable"     // только явная настройка коннектора (dev/test), с предупреждением
)

// Options — параметры коннектора.
type Options struct {
	Logger           *slog.Logger
	ConnectTimeout   time.Duration // 5 с
	StatementTimeout time.Duration // 5 с
	// SSLMode — verify-full (по умолчанию) или disable (только dev/test). Connection.TLSSkipVerify=true
	// оставляет шифрование, но отключает проверку сертификата (с предупреждением).
	SSLMode string
	// Database — база для подключения (по умолчанию postgres).
	Database string
	Now      func() time.Time
}

func (o Options) withDefaults() Options {
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = 5 * time.Second
	}
	if o.StatementTimeout <= 0 {
		o.StatementTimeout = 5 * time.Second
	}
	if o.SSLMode == "" {
		o.SSLMode = SSLVerifyFull
	}
	if o.Database == "" {
		o.Database = "postgres"
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	o.Logger = common.Logger(o.Logger)
	return o
}

// Connector — PostgreSQL.
type Connector struct{ o Options }

// New создаёт коннектор.
func New(o Options) *Connector { return &Connector{o: o.withDefaults()} }

// config строит конфигурацию pgx без DSN-строки (секреты не попадают в строку подключения)
// и без fallback на нешифрованное соединение.
func (c *Connector) config(conn *inventory.Connection, cred gateway.Credential) (*pgx.ConnConfig, error) {
	if conn == nil || conn.Address == "" {
		return nil, errors.New("postgres: asset has no connection address")
	}
	if cred.Username == "" {
		return nil, errors.New("postgres: credential has no username")
	}
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, errors.New("postgres: cannot build connection config")
	}
	port := conn.Port
	if port <= 0 {
		port = 5432
	}
	if port > math.MaxUint16 {
		return nil, errors.New("postgres: invalid port")
	}
	cfg.Host, cfg.Port, cfg.Database = conn.Address, uint16(port), c.o.Database
	cfg.User, cfg.Password = cred.Username, cred.Password
	cfg.ConnectTimeout = c.o.ConnectTimeout
	cfg.Fallbacks = nil // никаких повторов без TLS (sslmode=prefer)
	cfg.RuntimeParams = map[string]string{
		"application_name":                    "admintwin-readonly",
		"default_transaction_read_only":       "on",
		"statement_timeout":                   strconv.FormatInt(c.o.StatementTimeout.Milliseconds(), 10),
		"lock_timeout":                        "1000",
		"idle_in_transaction_session_timeout": "10000",
	}
	switch c.o.SSLMode {
	case SSLDisable:
		c.o.Logger.Warn("postgres TLS disabled by connector configuration (dev/test only)", "address", conn.Address)
		cfg.TLSConfig = nil
	case SSLVerifyFull:
		sn := conn.TLSServerName
		if sn == "" {
			sn = conn.Address
		}
		tc, err := common.TLSConfig(common.TLSOptions{ServerName: sn, SkipVerify: conn.TLSSkipVerify, Component: "postgres", Address: conn.Address}, cred, c.o.Logger)
		if err != nil {
			return nil, err
		}
		cfg.TLSConfig = tc
	default:
		return nil, fmt.Errorf("postgres: unsupported sslmode %q", c.o.SSLMode)
	}
	return cfg, nil
}

// connect открывает read-only сессию.
func (c *Connector) connect(ctx context.Context, conn *inventory.Connection, cred gateway.Credential) (*pgx.Conn, error) {
	cfg, err := c.config(conn, cred)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, c.o.ConnectTimeout)
	defer cancel()
	pc, err := pgx.ConnectConfig(cctx, cfg)
	if err != nil {
		return nil, sanitizeErr(err)
	}
	for _, stmt := range []string{
		"SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY",
		fmt.Sprintf("SET statement_timeout = %d", c.o.StatementTimeout.Milliseconds()),
	} {
		if _, err := pc.Exec(cctx, stmt); err != nil {
			_ = pc.Close(context.Background())
			return nil, sanitizeErr(err)
		}
	}
	return pc, nil
}

// sanitizeErr — ошибки pgconn могут содержать host/user; пароль pgx не включает, но наружу отдаём только суть.
func sanitizeErr(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "password authentication failed"), strings.Contains(msg, "SASL"):
		return errors.New("postgres: authentication failed")
	case strings.Contains(msg, "refused TLS"), strings.Contains(msg, "tls:"), strings.Contains(msg, "x509"):
		return errors.New("postgres: TLS negotiation or certificate verification failed")
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline"):
		return errors.New("postgres: timeout")
	case strings.Contains(msg, "connect"):
		return errors.New("postgres: connection failed")
	}
	return fmt.Errorf("postgres: query failed: %s", common.Truncate(msg, 200))
}

func (c *Connector) with(ctx context.Context, conn *inventory.Connection, cred gateway.Credential, fn func(context.Context, *pgx.Conn) error) error {
	pc, err := c.connect(ctx, conn, cred)
	if err != nil {
		return err
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = pc.Close(cctx)
	}()
	qctx, cancel := context.WithTimeout(ctx, c.o.StatementTimeout+c.o.ConnectTimeout)
	defer cancel()
	return fn(qctx, pc)
}

// --- запросы (фиксированные, только чтение) ---

const (
	qMaxConn   = `SELECT setting::int FROM pg_settings WHERE name = 'max_connections'`
	qTotalConn = `SELECT count(*)::int FROM pg_stat_activity WHERE backend_type = 'client backend'`
	qSessions  = `SELECT pid, usename::text, datname::text, state, wait_event_type, wait_event,
       to_char(query_start AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
       EXTRACT(EPOCH FROM (clock_timestamp() - query_start))::float8,
       query
  FROM pg_stat_activity
 WHERE backend_type = 'client backend' AND pid <> pg_backend_pid()
   AND ($1::text IS NULL OR datname = $1)
   AND ($2::float8 IS NULL OR (state IS DISTINCT FROM 'idle' AND query_start <= clock_timestamp() - make_interval(secs => $2)))
 ORDER BY query_start ASC NULLS LAST
 LIMIT $3`
	qRecovery    = `SELECT pg_is_in_recovery()`
	qReplPrimary = `SELECT COALESCE(NULLIF(application_name, ''), host(client_addr), 'unknown'),
       pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn)::float8
  FROM pg_stat_replication WHERE replay_lsn IS NOT NULL`
	qReplStandby = `SELECT pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn())::float8
 WHERE pg_last_wal_receive_lsn() IS NOT NULL AND pg_last_wal_replay_lsn() IS NOT NULL`
	qVersion   = `SHOW server_version`
	qCluster   = `SELECT current_setting('cluster_name', true)`
	qDatabases = `SELECT datname::text FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname LIMIT 500`
)

// ActivityInput — вход postgres.activity (уже проверен по input_schema Tool Service).
type ActivityInput struct {
	Database    string
	MinDuration *float64
	Limit       int
}

// responseBudget — целевой размер ответа (контракт: 32 КиБ).
const responseBudget = 30000

// Activity — данные по контракту ai/tools/read/postgres.activity.json.
func (c *Connector) Activity(ctx context.Context, conn *inventory.Connection, cred gateway.Credential, in ActivityInput) (map[string]any, error) {
	limit := in.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var db *string
	if in.Database != "" {
		db = &in.Database
	}
	var out map[string]any
	err := c.with(ctx, conn, cred, func(ctx context.Context, pc *pgx.Conn) error {
		var maxConn, total int
		if err := pc.QueryRow(ctx, qMaxConn).Scan(&maxConn); err != nil {
			return sanitizeErr(err)
		}
		if err := pc.QueryRow(ctx, qTotalConn).Scan(&total); err != nil {
			return sanitizeErr(err)
		}
		rows, err := pc.Query(ctx, qSessions, db, in.MinDuration, limit)
		if err != nil {
			return sanitizeErr(err)
		}
		defer rows.Close()
		sessions := []map[string]any{}
		budget := responseBudget - 200
		for rows.Next() {
			var (
				pid                                        int
				user, datname, state, wtype, wevent, start *string
				dur                                        *float64
				query                                      *string
			)
			if err := rows.Scan(&pid, &user, &datname, &state, &wtype, &wevent, &start, &dur, &query); err != nil {
				return sanitizeErr(err)
			}
			s := map[string]any{"pid": pid, "usename": nullable(user, 63), "datname": nullable(datname, 63), "state": nullable(state, 64),
				"wait_event_type": nullable(wtype, 64), "wait_event": nullable(wevent, 64), "query_start": nullable(start, 40),
				"duration_s": nil, "query": nil}
			if dur != nil && !math.IsNaN(*dur) && !math.IsInf(*dur, 0) {
				s["duration_s"] = math.Round(*dur*1000) / 1000
			}
			base := 260 // оценка размера полей без query
			if budget < base {
				break
			}
			if query != nil {
				qcap := min(512, budget-base)
				if qcap >= 16 {
					s["query"] = Fingerprint(*query, qcap)
				}
			}
			budget -= base
			if q, ok := s["query"].(string); ok {
				budget -= len(q) + 16
			}
			sessions = append(sessions, s)
		}
		if err := rows.Err(); err != nil {
			return sanitizeErr(err)
		}
		out = map[string]any{"max_connections": max(maxConn, 0), "total_connections": max(total, 0), "sessions": sessions}
		return nil
	})
	return out, err
}

func nullable(s *string, n int) any {
	if s == nil {
		return nil
	}
	return common.Truncate(strings.ToValidUTF8(*s, "?"), n)
}

// Metrics — pg_connections_total, pg_connections_max, pg_replication_lag_bytes{client}.
func (c *Connector) Metrics(ctx context.Context, a inventory.Asset, cred gateway.Credential) ([]telemetry.Sample, error) {
	now := c.o.Now().UTC()
	var out []telemetry.Sample
	add := func(metric string, v float64, lbl map[string]string) {
		out = append(out, telemetry.Sample{TenantID: a.TenantID, AssetID: a.ID, Metric: metric, Labels: lbl, Value: v, At: now})
	}
	err := c.with(ctx, a.Connection, cred, func(ctx context.Context, pc *pgx.Conn) error {
		var maxConn, total int
		if err := pc.QueryRow(ctx, qMaxConn).Scan(&maxConn); err != nil {
			return sanitizeErr(err)
		}
		if err := pc.QueryRow(ctx, qTotalConn).Scan(&total); err != nil {
			return sanitizeErr(err)
		}
		add("pg_connections_total", float64(total), nil)
		add("pg_connections_max", float64(maxConn), nil)
		lags, err := replication(ctx, pc)
		if err != nil {
			return err
		}
		for client, lag := range lags {
			add("pg_replication_lag_bytes", lag, map[string]string{"client": client})
		}
		return nil
	})
	return out, err
}

// replication — отставание реплик (на primary) или собственное отставание воспроизведения (на standby).
func replication(ctx context.Context, pc *pgx.Conn) (map[string]float64, error) {
	var standby bool
	if err := pc.QueryRow(ctx, qRecovery).Scan(&standby); err != nil {
		return nil, sanitizeErr(err)
	}
	out := map[string]float64{}
	if standby {
		var lag float64
		err := pc.QueryRow(ctx, qReplStandby).Scan(&lag)
		if errors.Is(err, pgx.ErrNoRows) {
			return out, nil
		}
		if err != nil {
			return nil, sanitizeErr(err)
		}
		out["local_replay"] = math.Max(lag, 0)
		return out, nil
	}
	rows, err := pc.Query(ctx, qReplPrimary)
	if err != nil {
		return nil, sanitizeErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		var client string
		var lag *float64
		if err := rows.Scan(&client, &lag); err != nil {
			return nil, sanitizeErr(err)
		}
		if lag != nil && len(out) < 100 {
			out[common.Truncate(client, 64)] = math.Max(*lag, 0)
		}
	}
	return out, sanitizeNil(rows.Err())
}

func sanitizeNil(err error) error {
	if err == nil {
		return nil
	}
	return sanitizeErr(err)
}

// --- discovery ---

// Collector — read-only сборщик postgres: версия, роль (primary/standby), базы данных.
func (c *Connector) Collector() discovery.Collector { return collector{c} }

type collector struct{ c *Connector }

func (collector) Method() string { return Method }

func (k collector) Collect(ctx context.Context, t discovery.Target, cred discovery.Credential) (discovery.Observation, error) {
	conn := &inventory.Connection{Method: Method, Address: t.Address, Port: t.Port, CredentialRef: t.CredentialRef, TLSServerName: t.TLSServerName}
	a := inventory.Asset{TenantID: t.TenantID, Type: "database", Source: "discovery", Reachability: "reachable", Connection: conn, Objects: map[string][]string{}}
	obs := discovery.Observation{Confidence: 0.9}
	err := k.c.with(ctx, conn, common.FromDiscovery(cred), func(ctx context.Context, pc *pgx.Conn) error {
		var ver string
		if err := pc.QueryRow(ctx, qVersion).Scan(&ver); err != nil {
			return sanitizeErr(err)
		}
		a.Objects["version"] = []string{common.Truncate(ver, 64)}
		var cluster *string
		if err := pc.QueryRow(ctx, qCluster).Scan(&cluster); err == nil && cluster != nil && *cluster != "" {
			a.Name = common.Truncate(*cluster, 128)
		}
		var standby bool
		if err := pc.QueryRow(ctx, qRecovery).Scan(&standby); err == nil {
			role := "primary"
			if standby {
				role = "standby"
			}
			a.Objects["role"] = []string{role}
		}
		rows, err := pc.Query(ctx, qDatabases)
		if err != nil {
			return sanitizeErr(err)
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return sanitizeErr(err)
			}
			a.Objects["database"] = append(a.Objects["database"], common.Truncate(name, 63))
		}
		return sanitizeNil(rows.Err())
	})
	if err != nil {
		return discovery.Observation{}, err
	}
	if a.Name == "" {
		a.Name = common.HostPort(t.Address, t.Port, 5432)
		obs.Confidence = 0.8
	}
	obs.Assets = []inventory.Asset{a}
	return obs, nil
}

// tlsConfigFor — для тестов: итоговая TLS-конфигурация подключения.
func (c *Connector) tlsConfigFor(conn *inventory.Connection, cred gateway.Credential) (*tls.Config, error) {
	cfg, err := c.config(conn, cred)
	if err != nil {
		return nil, err
	}
	return cfg.TLSConfig, nil
}
