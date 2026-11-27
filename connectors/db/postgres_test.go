package db

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aitmaganbetov/admintwin/connectors/internal/testutil"
	"github.com/aitmaganbetov/admintwin/services/discovery"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/inventory"
)

func TestFingerprint(t *testing.T) {
	cases := map[string]string{
		"SELECT * FROM users WHERE email = 'alice@example.com' AND id = 42":    "SELECT * FROM users WHERE email = ? AND id = ?",
		"select  a,\n\tb from t1 where x in (1, 2, 3)":                         "select a, b from t1 where x in (?, ...)",
		"SELECT 'it''s', E'a\\'b', 3.14e-2, 0x1F":                              "SELECT ?, ...",
		"SELECT $$secret body$$, $fn$ also secret $fn$, $1":                    "SELECT ?, ..., $1",
		"UPDATE t SET pw = 'hunter2' -- comment with 'x'\nWHERE id = $2":       "UPDATE t SET pw = ? WHERE id = $2",
		"SELECT /* card 4111 1111 1111 1111 */ col FROM \"T 1\" WHERE c2 = .5": "SELECT col FROM \"T 1\" WHERE c2 = ?",
		"INSERT INTO t VALUES (B'1010', X'FF', U&'d\\0061t')":                  "INSERT INTO t VALUES (?, ...)",
		"SELECT 'unterminated secret literal":                                  "SELECT ?",
		"SELECT /* unterminated 'secret":                                       "SELECT",
		"SELECT $tag$ unterminated secret":                                     "SELECT ?",
	}
	for in, want := range cases {
		if got := Fingerprint(in, 512); got != want {
			t.Fatalf("Fingerprint(%q)\n got %q\nwant %q", in, got, want)
		}
	}
	for _, secret := range []string{"alice@example.com", "hunter2", "4111", "secret", "1010"} {
		for in := range cases {
			if strings.Contains(Fingerprint(in, 512), secret) {
				t.Fatalf("literal %q leaked from %q", secret, in)
			}
		}
	}
	long := "SELECT " + strings.Repeat("col_name, ", 300) + "x FROM t"
	if got := Fingerprint(long, 100); len(got) > 100 || !strings.HasSuffix(got, "...") {
		t.Fatalf("truncation: %d %q", len(got), got)
	}
}

func TestConfigIsStrict(t *testing.T) {
	c := New(Options{})
	conn := &inventory.Connection{Method: Method, Address: "pg.internal", Port: 5433}
	cred := gateway.Credential{Username: "ro", Password: "secret-pass"}
	cfg, err := c.config(conn, cred)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSConfig == nil || cfg.TLSConfig.InsecureSkipVerify || cfg.TLSConfig.ServerName != "pg.internal" || len(cfg.Fallbacks) != 0 {
		t.Fatalf("default must be verify-full without plaintext fallback: %+v fallbacks=%d", cfg.TLSConfig, len(cfg.Fallbacks))
	}
	if cfg.RuntimeParams["default_transaction_read_only"] != "on" || cfg.RuntimeParams["statement_timeout"] != "5000" || cfg.Port != 5433 {
		t.Fatalf("runtime params: %v", cfg.RuntimeParams)
	}
	skip := &inventory.Connection{Method: Method, Address: "pg.internal", TLSSkipVerify: true}
	if tc, err := c.tlsConfigFor(skip, cred); err != nil || !tc.InsecureSkipVerify {
		t.Fatalf("explicit skip verify: %v", err)
	}
	if _, err := New(Options{SSLMode: "prefer"}).config(conn, cred); err == nil {
		t.Fatal("unsupported sslmode must be rejected")
	}
	if _, err := c.config(conn, gateway.Credential{}); err == nil {
		t.Fatal("missing username must be rejected")
	}
}

// TestNoPlaintextFallback — сервер отказывает в TLS ('N' на SSLRequest): соединение не продолжается открытым текстом.
func TestNoPlaintextFallback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan int, 4)
	go func() {
		for {
			cn, err := ln.Accept()
			if err != nil {
				return
			}
			buf := make([]byte, 8)
			n, _ := cn.Read(buf)
			got <- n
			_, _ = cn.Write([]byte{'N'})
			// Любые дальнейшие байты означали бы startup без TLS.
			_ = cn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			if n2, _ := cn.Read(buf); n2 > 0 {
				got <- -1
			}
			_ = cn.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	c := New(Options{ConnectTimeout: time.Second})
	_, err = c.Activity(context.Background(), &inventory.Connection{Method: Method, Address: "127.0.0.1", Port: port}, gateway.Credential{Username: "ro", Password: "p"}, ActivityInput{})
	if err == nil || strings.Contains(err.Error(), "p@") {
		t.Fatalf("expected TLS failure, got %v", err)
	}
	time.Sleep(400 * time.Millisecond)
	close(got)
	for n := range got {
		if n == -1 {
			t.Fatal("client continued without TLS after the server refused it")
		}
	}
}

// --- интеграционный тест на настоящем PostgreSQL ---

type pgEnv struct {
	url  string
	c    *Connector
	conn *inventory.Connection
	cred gateway.Credential
}

func integration(t *testing.T) pgEnv {
	t.Helper()
	raw := os.Getenv("ADMINTWIN_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("ADMINTWIN_TEST_DATABASE_URL is not set")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	pass, _ := u.User.Password()
	mode := SSLVerifyFull
	if u.Query().Get("sslmode") == "disable" {
		mode = SSLDisable
	}
	return pgEnv{
		url:  raw,
		c:    New(Options{SSLMode: mode, Database: strings.TrimPrefix(u.Path, "/")}),
		conn: &inventory.Connection{Method: Method, Address: u.Hostname(), Port: port},
		cred: gateway.Credential{Username: u.User.Username(), Password: pass},
	}
}

func TestIntegrationPostgres(t *testing.T) {
	e := integration(t)
	ctx := context.Background()

	// Фоновая сессия с литералом в тексте запроса.
	bg, err := pgx.Connect(ctx, e.url)
	if err != nil {
		t.Fatal(err)
	}
	defer bg.Close(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = bg.Exec(ctx, "SELECT 'card-4111-1111-secret' AS s, pg_sleep(2)")
	}()
	time.Sleep(300 * time.Millisecond)

	out, err := e.c.Activity(ctx, e.conn, e.cred, ActivityInput{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	testutil.ValidateToolOutput(t, "postgres.activity", out)
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "card-4111") {
		t.Fatalf("query literal leaked: %s", raw)
	}
	if !strings.Contains(string(raw), "SELECT ? AS s, pg_sleep(?)") {
		t.Fatalf("background session fingerprint not found: %s", raw)
	}
	if out["max_connections"].(int) <= 0 || out["total_connections"].(int) < 2 {
		t.Fatalf("connections: %v", out)
	}
	minDur := 0.1
	if out, err := e.c.Activity(ctx, e.conn, e.cred, ActivityInput{MinDuration: &minDur, Database: "nonexistent_db"}); err != nil || len(out["sessions"].([]map[string]any)) != 0 {
		t.Fatalf("filters: %v %v", out, err)
	}
	<-done

	// Сессия read-only и statement_timeout действует.
	pc, err := e.c.connect(ctx, e.conn, e.cred)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close(ctx)
	if _, err := pc.Exec(ctx, "CREATE TEMP TABLE admintwin_probe(x int)"); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("writes must fail in a read-only session: %v", err)
	}
	var st string
	if err := pc.QueryRow(ctx, "SHOW statement_timeout").Scan(&st); err != nil || st != "5s" {
		t.Fatalf("statement_timeout: %q %v", st, err)
	}
	var ro string
	if err := pc.QueryRow(ctx, "SHOW transaction_read_only").Scan(&ro); err != nil || ro != "on" {
		t.Fatalf("transaction_read_only: %q %v", ro, err)
	}

	samples, err := e.c.Metrics(ctx, inventory.Asset{ID: "pg", TenantID: "t", Connection: e.conn}, e.cred)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]float64{}
	for _, s := range samples {
		names[s.Metric] = s.Value
	}
	if names["pg_connections_max"] <= 0 || names["pg_connections_total"] < 1 {
		t.Fatalf("metrics: %v", names)
	}

	obs, err := e.c.Collector().Collect(ctx, discovery.Target{TenantID: "t", Address: e.conn.Address, Port: e.conn.Port, Method: Method},
		discovery.Credential{Username: e.cred.Username, Password: e.cred.Password})
	if err != nil {
		t.Fatal(err)
	}
	a := obs.Assets[0]
	if a.Type != "database" || len(a.Objects["version"]) != 1 || len(a.Objects["database"]) == 0 || a.Objects["role"][0] != "primary" {
		t.Fatalf("discovery: %+v", a)
	}

	// Неверный пароль — ошибка без пароля в тексте.
	_, err = e.c.Activity(ctx, e.conn, gateway.Credential{Username: e.cred.Username, Password: "wrong-pass-xyz"}, ActivityInput{})
	if err == nil || strings.Contains(err.Error(), "wrong-pass-xyz") {
		t.Fatalf("bad password: %v", err)
	}
}
