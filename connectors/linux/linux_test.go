package linux

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aitmaganbetov/admintwin/connectors/internal/testutil"
	"github.com/aitmaganbetov/admintwin/services/discovery"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	"github.com/aitmaganbetov/admintwin/services/telemetry"
)

type telemetrySample = telemetry.Sample

const tenantID = "11111111-1111-4111-8111-111111111111"

func TestQuote(t *testing.T) {
	cases := map[string]string{
		"systemctl":       "systemctl",
		"nginx.service":   "nginx.service",
		"--property=A,B":  "--property=A,B",
		"":                "''",
		"a b":             "'a b'",
		"it's":            `'it'"'"'s'`,
		"$(id)":           "'$(id)'",
		"`id`":            "'`id`'",
		"; rm -rf /":      "'; rm -rf /'",
		"a|b&c>d<e":       "'a|b&c>d<e'",
		"*.log*":          "'*.log*'",
		`%s\t%p\0`:        `'%s\t%p\0'`,
		"~root":           "'~root'",
		"!":               "'!'",
		"x\\y":            `'x\y'`,
		"'; reboot; echo": `''"'"'; reboot; echo'`,
	}
	for in, want := range cases {
		got, err := Quote(in)
		if err != nil || got != want {
			t.Fatalf("Quote(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"a\nb", "a\tb", "a\x00b", "a\rb", "\x1b[31m", "a\u2028b", string([]byte{0xff, 0xfe}), "\x7f"} {
		if _, err := Quote(bad); !errors.Is(err, ErrUnsafeArgument) {
			t.Fatalf("Quote(%q) must be rejected: %v", bad, err)
		}
	}
	if _, err := Join([]string{"systemctl", "restart", "nginx.service\nreboot"}); err == nil {
		t.Fatal("newline injection must be rejected")
	}
}

// TestQuoteRoundTrip — экранированные аргументы доходят до процесса без изменений в настоящем POSIX sh.
// (Shell используется только здесь, в тесте, как эталон интерпретации строки exec на удалённой стороне.)
func TestQuoteRoundTrip(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not available")
	}
	args := []string{"plain", "a b", "it's", "$(touch /tmp/pwned)", "`id`", "$HOME", "*", "~", "a;b", "a&&b", `back\slash`,
		"'", `"`, "{a,b}", "#comment", "-n", "%s\\t%p\\0", "тест", "!$"}
	line, err := Join(append([]string{"printf", "%s\\0"}, args...))
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(sh, "-c", line).Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	if strings.Join(got, "|") != strings.Join(args, "|") {
		t.Fatalf("round trip mismatch:\n got %q\nwant %q", got, args)
	}
}

func TestAllowlist(t *testing.T) {
	c := New(Options{})
	ok := [][]string{
		{"systemctl", "show", "nginx.service", "--property=ActiveState", "--no-pager"},
		{"systemctl", "restart", "nginx.service"},
		{"df", "-P", "-B1"}, {"df", "-P", "-B1", "/var/log"}, {"df", "-P", "-i"},
		{"journalctl", "-u", "nginx.service", "-n", "50", "--no-pager", "-o", "short-iso"},
		{"cat", "/proc/loadavg", "/proc/meminfo"},
		{"find", "/var/log/nginx", "-xdev", "-type", "f", "-mtime", "+14", "-name", "*.log*", "-printf", findPrintf},
		{"find", "/var/log/nginx", "-xdev", "-type", "f", "-mtime", "+14", "-name", "*.log*", "-printf", findPrintf, "-delete"},
		{"du", "-s", "-x", "-B1", "/var/log/app"},
	}
	for _, a := range ok {
		if err := c.allowed(a); err != nil {
			t.Fatalf("%q must be allowed: %v", a, err)
		}
	}
	bad := [][]string{
		{"rm", "-rf", "/"}, {"sh", "-c", "id"}, {"bash"}, {"systemctl", "restart", "sshd.service"},
		{"systemctl", "stop", "nginx.service"}, {"systemctl", "show", "--help", "--property=A", "--no-pager"},
		{"systemctl", "show", "nginx.service", "--property=A;id", "--no-pager"},
		{"cat", "/etc/shadow"}, {"cat", "/proc/loadavg", "../etc/shadow"},
		{"df", "-P", "-B1", "/var/../etc"}, {"df", "-P", "-B1", "--output=source"},
		{"journalctl", "-u", "nginx.service", "-n", "100000", "--no-pager", "-o", "short-iso"},
		{"journalctl", "-u", "nginx.service", "-n", "050", "--no-pager", "-o", "short-iso"},
		{"find", "/", "-xdev", "-type", "f", "-mtime", "+14", "-name", "*.log*", "-printf", findPrintf, "-delete"},
		{"find", "/etc", "-xdev", "-type", "f", "-mtime", "+14", "-name", "*.log*", "-printf", findPrintf, "-delete"},
		{"find", "/var/log/nginx", "-xdev", "-type", "f", "-mtime", "+1", "-name", "*.log*", "-printf", findPrintf, "-delete"},
		{"find", "/var/log/nginx", "-xdev", "-type", "f", "-mtime", "+14", "-name", "*", "-printf", findPrintf, "-delete"},
		{"find", "/var/log/nginx", "-xdev", "-type", "f", "-mtime", "+14", "-name", "*.log*", "-exec", "rm", "{}", ";"},
		{"find", "/var/lib/docker/containers", "-xdev", "-type", "f", "-mtime", "+14", "-name", "*.log*", "-printf", findPrintf, "-delete"},
		{"du", "-s", "-x", "-B1", "/"},
		{"sudo", "-n", "--", "systemctl", "restart", "nginx.service"}, // Sudo выключен
		{"sudo", "systemctl", "restart", "nginx.service"},
	}
	for _, a := range bad {
		if err := c.allowed(a); err == nil {
			t.Fatalf("%q must be rejected", a)
		}
	}
	cs := New(Options{Sudo: true})
	if err := cs.allowed([]string{"sudo", "-n", "--", "systemctl", "restart", "nginx.service"}); err != nil {
		t.Fatal(err)
	}
	if err := cs.allowed([]string{"sudo", "-n", "--", "cat", "/proc/loadavg"}); err == nil {
		t.Fatal("sudo is only for write commands")
	}
}

// --- окружение с SSH-сервером ---

type env struct {
	srv  *sshServer
	c    *Connector
	a    inventory.Asset
	cred gateway.Credential
}

func newEnv(t *testing.T, o Options) *env {
	t.Helper()
	srv := newSSHServer(t)
	host, port := srv.addr()
	o.DialTimeout, o.ReadTimeout = 2*time.Second, 2*time.Second
	return &env{
		srv: srv, c: New(o),
		a: inventory.Asset{ID: "a0000000-0000-4000-8000-000000000003", TenantID: tenantID, Type: "linux_host",
			Connection: &inventory.Connection{Method: Method, Address: host, Port: port, HostKey: srv.hostKeyLine()},
			Objects: map[string][]string{"systemd_unit": {"nginx.service", "php-fpm.service", "docker.service"},
				"log_directory": {"/var/log/nginx", "/var/log/app", "/var/lib/docker/containers"}},
			Protected: []string{"docker.service"}},
		cred: gateway.Credential{Username: "admintwin", PrivateKey: srv.clientKey},
	}
}

func (e *env) lease() gateway.Lease {
	return gateway.Lease{Handle: "l", ExpiresAt: time.Now().Add(time.Minute), Credential: e.cred}
}

func (e *env) restartReq(unit string) gateway.EngineRequest {
	return gateway.EngineRequest{TenantID: tenantID, AssetID: e.a.ID, Asset: e.a, Action: "systemctl_restart",
		Argv: []string{"systemctl", "restart", unit}, Params: map[string]any{"unit": unit}, Lease: e.lease()}
}

func TestHostKeyVerification(t *testing.T) {
	e := newEnv(t, Options{})
	ctx := context.Background()
	e.srv.on("systemctl show nginx.service --property=ActiveState --no-pager", resp{out: "ActiveState=active\n"})

	if ok, err := e.c.UnitActive(ctx, e.a, e.cred, "nginx.service"); err != nil || !ok {
		t.Fatalf("pinned key: %v %v", ok, err)
	}
	// Без host key — отказ до установления TCP-соединения.
	before := e.srv.conns
	noKey := e.a
	noKey.Connection = &inventory.Connection{Method: Method, Address: e.a.Connection.Address, Port: e.a.Connection.Port}
	if _, err := e.c.UnitActive(ctx, noKey, e.cred, "nginx.service"); !errors.Is(err, ErrNoHostKey) {
		t.Fatalf("missing host key: %v", err)
	}
	if e.srv.conns != before {
		t.Fatal("no connection may be attempted without a pinned host key")
	}
	// Чужой ключ — отказ, команда не выполняется.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(other)
	wrong := e.a
	wrong.Connection = &inventory.Connection{Method: Method, Address: e.a.Connection.Address, Port: e.a.Connection.Port,
		HostKey: string(ssh.MarshalAuthorizedKey(otherSigner.PublicKey()))}
	e.srv.reset()
	if _, err := e.c.UnitActive(ctx, wrong, e.cred, "nginx.service"); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("mismatched host key: %v", err)
	}
	if len(e.srv.commands()) != 0 {
		t.Fatal("no command may run after host key mismatch")
	}
	garbage := e.a
	garbage.Connection = &inventory.Connection{Method: Method, Address: "127.0.0.1", Port: 1, HostKey: "not a key"}
	if _, err := e.c.UnitActive(ctx, garbage, e.cred, "nginx.service"); err == nil {
		t.Fatal("invalid host key must be rejected")
	}
	// Парольная аутентификация и неверные креды.
	if ok, err := e.c.UnitActive(ctx, e.a, gateway.Credential{Username: "u", Password: "pw-123"}, "nginx.service"); err != nil || !ok {
		t.Fatalf("password auth: %v", err)
	}
	_, err := e.c.UnitActive(ctx, e.a, gateway.Credential{Username: "u", Password: "wrong-secret"}, "nginx.service")
	if err == nil || strings.Contains(err.Error(), "wrong-secret") {
		t.Fatalf("bad password: %v", err)
	}
	if _, err := e.c.UnitActive(ctx, e.a, gateway.Credential{Username: "u"}, "nginx.service"); !errors.Is(err, ErrNoAuth) {
		t.Fatalf("no credential: %v", err)
	}
}

func TestRestartEngine(t *testing.T) {
	for _, sudo := range []bool{false, true} {
		e := newEnv(t, Options{Sudo: sudo})
		want := "systemctl restart nginx.service"
		if sudo {
			want = "sudo -n -- " + want
		}
		e.srv.on(want, resp{})
		out, err := e.c.ArgvEngine().Execute(context.Background(), e.restartReq("nginx.service"))
		if err != nil || out.ExitCode != 0 {
			t.Fatalf("restart: %v %+v", err, out)
		}
		if cmds := e.srv.commands(); len(cmds) != 1 || cmds[0] != want {
			t.Fatalf("exact command expected %q, got %q", want, cmds)
		}
		if n := e.c.localRestarts(tenantID, e.a.ID, "nginx.service"); n != 1 {
			t.Fatalf("local restart counter: %d", n)
		}
	}

	e := newEnv(t, Options{})
	bad := map[string]gateway.EngineRequest{
		"not allowlisted unit": e.restartReq("sshd.service"),
		"protected unit":       e.restartReq("docker.service"),
		"not on asset":         e.restartReq("apache2.service"),
		"injection":            e.restartReq("nginx.service; reboot"),
		"newline":              e.restartReq("nginx.service\nreboot"),
	}
	r := e.restartReq("nginx.service")
	r.Argv = []string{"systemctl", "stop", "nginx.service"}
	bad["argv template"] = r
	r = e.restartReq("nginx.service")
	r.Argv = append(r.Argv, "--force")
	bad["extra argv"] = r
	r = e.restartReq("nginx.service")
	r.Params["unit"] = "php-fpm.service"
	bad["params mismatch"] = r
	r = e.restartReq("nginx.service")
	r.Lease.ExpiresAt = time.Time{}
	bad["no lease expiry"] = r
	r = e.restartReq("nginx.service")
	r.DryRun = true
	bad["dry run"] = r
	for name, rq := range bad {
		if _, err := e.c.ArgvEngine().Execute(context.Background(), rq); err == nil {
			t.Fatalf("%s: must be refused", name)
		}
	}
	if len(e.srv.commands()) != 0 {
		t.Fatalf("refused requests must not reach the host: %q", e.srv.commands())
	}
	// Ненулевой код возврата — провал (Gateway → failed + compensation).
	e.srv.on("systemctl restart nginx.service", resp{errOut: "Job for nginx.service failed", exit: 1})
	out, err := e.c.ArgvEngine().Execute(context.Background(), e.restartReq("nginx.service"))
	if err != nil || out.ExitCode != 1 || !strings.Contains(out.Stderr, "failed") {
		t.Fatalf("non-zero exit: %v %+v", err, out)
	}
}

func TestRestartCancellation(t *testing.T) {
	e := newEnv(t, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.c.ArgvEngine().Execute(ctx, e.restartReq("nginx.service")); !errors.Is(err, gateway.ErrCancelConfirmed) {
		t.Fatalf("cancel before send: %v", err)
	}
	if len(e.srv.commands()) != 0 {
		t.Fatal("command must not be sent")
	}
	e.srv.on("systemctl restart nginx.service", resp{hang: true})
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	_, err := e.c.ArgvEngine().Execute(ctx2, e.restartReq("nginx.service"))
	if errors.Is(err, gateway.ErrCancelConfirmed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hang after start must be unknown: %v", err)
	}
	e.srv.on("systemctl restart nginx.service", resp{drop: true})
	if _, err := e.c.ArgvEngine().Execute(context.Background(), e.restartReq("nginx.service")); !errors.Is(err, gateway.ErrChannelLost) {
		t.Fatalf("dropped channel: %v", err)
	}
}

const dfOut = `Filesystem       1-blocks        Used   Available Capacity Mounted on
/dev/sda1     100000000000 91000000000  9000000000      91% /
tmpfs           1000000000           0  1000000000       0% /run
/dev/sdb1      50000000000 10000000000 40000000000      20% /var/log
`

const findmntOut = "/ /dev/sda1 ext4\n/run tmpfs tmpfs\n/var/log /dev/sdb1 xfs\n"

const dfInodes = `Filesystem      Inodes  IUsed   IFree IUse% Mounted on
/dev/sda1      6553600 100000 6453600    2% /
tmpfs           250000      1  249999    1% /run
/dev/sdb1            0      0       0     - /var/log
`

func TestCleanupEngine(t *testing.T) {
	e := newEnv(t, Options{})
	findDry := `find /var/log/nginx -xdev -type f -mtime +14 -name '*.log*' -printf '%s\t%p\0'`
	e.srv.on("df -P -B1 /var/log/nginx", resp{out: "Filesystem 1-blocks Used Available Capacity Mounted on\n/dev/sdb1 50000000000 10000000000 40000000000 20% /var/log\n"})
	e.srv.on(findDry, resp{out: "1000\t/var/log/nginx/access.log.2.gz\x002000\t/var/log/nginx/error.log.3\x00"})
	req := gateway.EngineRequest{TenantID: tenantID, AssetID: e.a.ID, Asset: e.a, Action: "logs_rotate_cleanup",
		Params: map[string]any{"directory": "/var/log/nginx", "older_than_days": int64(14), "dry_run": true}, DryRun: true, Lease: e.lease()}
	out, err := e.c.BuiltinEngine().Execute(context.Background(), req)
	if err != nil || out.ExitCode != 0 {
		t.Fatalf("dry run: %v %+v", err, out)
	}
	if !strings.HasPrefix(out.Stdout, "dry-run: would delete 2 files, 3000 bytes") || !strings.Contains(out.Stdout, "error.log.3") {
		t.Fatalf("report: %q", out.Stdout)
	}
	cmds := e.srv.commands()
	if len(cmds) != 2 || cmds[1] != findDry || strings.Contains(strings.Join(cmds, " "), "-delete") {
		t.Fatalf("dry run must only list: %q", cmds)
	}

	// Настоящий прогон: тот же find с -delete; docker-каталог исключает активные *-json.log.
	e.srv.reset()
	findDel := `find /var/lib/docker/containers -xdev -type f -mtime +30 -name '*.log*' '!' -name '*-json.log' -printf '%s\t%p\0' -delete`
	e.srv.on(findDel, resp{out: "500\t/var/lib/docker/containers/abc/abc-json.log.1\x00"})
	req.Params = map[string]any{"directory": "/var/lib/docker/containers", "older_than_days": float64(30)}
	req.DryRun = false
	out, err = e.c.BuiltinEngine().Execute(context.Background(), req)
	if err != nil || !strings.HasPrefix(out.Stdout, "deleted 1 files, 500 bytes") {
		t.Fatalf("cleanup: %v %+v (cmds %q)", err, out, e.srv.commands())
	}
	if c := e.srv.commands(); c[len(c)-1] != findDel {
		t.Fatalf("exact delete command: %q", c)
	}

	// Отказы без обращения к хосту.
	e.srv.reset()
	refuse := func(name string, mut func(*gateway.EngineRequest)) {
		r := gateway.EngineRequest{TenantID: tenantID, AssetID: e.a.ID, Asset: e.a, Action: "logs_rotate_cleanup",
			Params: map[string]any{"directory": "/var/log/nginx", "older_than_days": int64(14)}, Lease: e.lease()}
		r.Asset.Objects = map[string][]string{"log_directory": {"/var/log/nginx", "/var/log/journal-archive", "/etc"}}
		mut(&r)
		if _, err := e.c.BuiltinEngine().Execute(context.Background(), r); err == nil {
			t.Fatalf("%s: must be refused", name)
		}
	}
	refuse("legal hold", func(r *gateway.EngineRequest) { r.Asset.LegalHold = true })
	refuse("investigation", func(r *gateway.EngineRequest) { r.Asset.ActiveInvestigation = true })
	refuse("not on asset", func(r *gateway.EngineRequest) { r.Params["directory"] = "/var/log/app" })
	refuse("not allowlisted", func(r *gateway.EngineRequest) { r.Params["directory"] = "/etc" })
	refuse("traversal", func(r *gateway.EngineRequest) { r.Params["directory"] = "/var/log/nginx/../../etc" })
	refuse("too young", func(r *gateway.EngineRequest) { r.Params["older_than_days"] = int64(1) })
	refuse("fractional", func(r *gateway.EngineRequest) { r.Params["older_than_days"] = 14.5 })
	refuse("unknown action", func(r *gateway.EngineRequest) { r.Action = "rm_rf" })
	refuse("expired lease", func(r *gateway.EngineRequest) { r.Lease.ExpiresAt = time.Now().Add(-time.Second) })
	if len(e.srv.commands()) != 0 {
		t.Fatalf("refusals must not reach the host: %q", e.srv.commands())
	}
}

func TestFacts(t *testing.T) {
	e := newEnv(t, Options{})
	ctx := context.Background()
	show := "systemctl show nginx.service --property=NRestarts,ActiveState,ActiveEnterTimestampMonotonic --no-pager"
	e.srv.on("cat /proc/uptime", resp{out: "10000.50 20000.00\n"})

	// Активен 2 ч — перезапусков за час нет, несмотря на NRestarts.
	e.srv.on(show, resp{out: "NRestarts=4\nActiveState=active\nActiveEnterTimestampMonotonic=2800000000\n"})
	if n, err := e.c.RestartsLastHour(ctx, e.a, e.cred, "nginx.service"); err != nil || n != 0 {
		t.Fatalf("stable unit: %d %v", n, err)
	}
	// Вошёл в active 10 мин назад — NRestarts + локальные перезапуски.
	e.srv.on(show, resp{out: "NRestarts=2\nActiveState=active\nActiveEnterTimestampMonotonic=9400000000\n"})
	e.c.noteRestart(tenantID, e.a.ID, "nginx.service")
	if n, err := e.c.RestartsLastHour(ctx, e.a, e.cred, "nginx.service"); err != nil || n != 3 {
		t.Fatalf("recent unit: %d %v", n, err)
	}

	e.srv.on("df -P -B1", resp{out: dfOut})
	e.srv.on("findmnt -r -n -o TARGET,SOURCE,FSTYPE", resp{out: findmntOut})
	e.srv.on("df -P -i", resp{out: dfInodes})
	if p, err := e.c.DiskUsagePercent(ctx, e.a, e.cred); err != nil || p != 91 {
		t.Fatalf("disk usage (max of persistent fs): %v %v", p, err)
	}

	writers := "systemctl show systemd-journald.service rsyslog.service nginx.service php-fpm.service docker.service --property=Id,LoadState,ActiveState --no-pager"
	healthy := "Id=systemd-journald.service\nLoadState=loaded\nActiveState=active\n\nId=rsyslog.service\nLoadState=not-found\nActiveState=inactive\n\n" +
		"Id=nginx.service\nLoadState=loaded\nActiveState=active\n\nId=php-fpm.service\nLoadState=loaded\nActiveState=inactive\n\nId=docker.service\nLoadState=loaded\nActiveState=active\n"
	e.srv.on(writers, resp{out: healthy})
	if ok, err := e.c.LogWritersHealthy(ctx, e.a, e.cred); err != nil || !ok {
		t.Fatalf("writers healthy: %v %v", ok, err)
	}
	e.srv.on(writers, resp{out: strings.Replace(healthy, "Id=nginx.service\nLoadState=loaded\nActiveState=active", "Id=nginx.service\nLoadState=loaded\nActiveState=failed", 1)})
	if ok, err := e.c.LogWritersHealthy(ctx, e.a, e.cred); err != nil || ok {
		t.Fatalf("failed writer: %v %v", ok, err)
	}
	e.srv.on("systemctl show nginx.service --property=ActiveState --no-pager", resp{out: "ActiveState=failed\n"})
	if ok, err := e.c.UnitActive(ctx, e.a, e.cred, "nginx.service"); err != nil || ok {
		t.Fatalf("failed unit: %v %v", ok, err)
	}
	if _, err := e.c.UnitActive(ctx, e.a, e.cred, "nginx.service; id"); err == nil {
		t.Fatal("invalid unit must be rejected")
	}
}

func TestTools(t *testing.T) {
	e := newEnv(t, Options{})
	ctx := context.Background()
	e.srv.on("systemctl show nginx.service --property=LoadState,ActiveState,SubState,MainPID,ActiveEnterTimestamp --no-pager",
		resp{out: "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=812\nActiveEnterTimestamp=Fri 2026-11-27 07:00:01 UTC\n"})
	var journal bytes.Buffer
	for i := 0; i < 80; i++ {
		journal.WriteString("2026-11-27T07:00:01+0000 host nginx[812]: line " + strings.Repeat("x", 600) + "\n")
	}
	e.srv.on("journalctl -u nginx.service -n 50 --no-pager -o short-iso", resp{out: journal.String()})
	out, err := e.c.ServiceStatus(ctx, e.a, e.cred, "nginx.service")
	if err != nil {
		t.Fatal(err)
	}
	testutil.ValidateToolOutput(t, "linux.service.status", out)
	if out["main_pid"] != 812 || out["since"] != "Fri 2026-11-27 07:00:01 UTC" || len(out["recent_log"].([]string)) == 0 {
		t.Fatalf("service status: %v", out)
	}

	e.srv.on("df -P -B1", resp{out: dfOut})
	e.srv.on("findmnt -r -n -o TARGET,SOURCE,FSTYPE", resp{out: findmntOut})
	e.srv.on("df -P -i", resp{out: dfInodes})
	e.srv.on("du -s -x -B1 /var/log/nginx", resp{out: "123456\t/var/log/nginx\n"})
	e.srv.on("du -s -x -B1 /var/log/app", resp{out: "1\t/var/log/app\n", errOut: "permission denied", exit: 1})
	out, err = e.c.DiskUsage(ctx, e.a, e.cred, "")
	if err != nil {
		t.Fatal(err)
	}
	testutil.ValidateToolOutput(t, "linux.disk.usage", out)
	fss := out["filesystems"].([]map[string]any)
	if len(fss) != 2 || fss[0]["mount"] != "/" || fss[0]["fstype"] != "ext4" || fss[1]["inodes_use_percent"] != nil {
		t.Fatalf("filesystems: %v", fss)
	}
	if dirs := out["top_dirs"].([]map[string]any); len(dirs) != 1 || dirs[0]["size_bytes"] != int64(123456) {
		t.Fatalf("top dirs: %v", dirs)
	}
	e.srv.on("df -P -B1 /var/log", resp{out: "Filesystem 1-blocks Used Available Capacity Mounted on\n/dev/sdb1 50000000000 10000000000 40000000000 20% /var/log\n"})
	if out, err = e.c.DiskUsage(ctx, e.a, e.cred, "/var/log"); err != nil || len(out["filesystems"].([]map[string]any)) != 1 {
		t.Fatalf("mount filter: %v %v", out, err)
	}
	for _, cmd := range e.srv.commands() {
		if strings.Contains(cmd, "sudo") {
			t.Fatalf("read tools never use sudo: %q", cmd)
		}
	}
}

func TestMetricsAndCollector(t *testing.T) {
	e := newEnv(t, Options{})
	ctx := context.Background()
	proc := func(user, idle int) string {
		return "0.50 0.40 0.30 1/200 1234\nMemTotal:       8000000 kB\nMemFree:  1000000 kB\nMemAvailable:   2000000 kB\n" +
			"cpu  " + itoa(user) + " 0 0 " + itoa(idle) + " 0 0 0 0 0 0\ncpu0 1 2 3 4\n"
	}
	e.srv.on("cat /proc/loadavg /proc/meminfo /proc/stat", resp{out: proc(100, 900)})
	e.srv.on("df -P -B1", resp{out: dfOut})
	e.srv.on("findmnt -r -n -o TARGET,SOURCE,FSTYPE", resp{out: findmntOut})
	e.srv.on("df -P -i", resp{out: dfInodes})
	s1, err := e.c.Metrics(ctx, e.a, e.cred)
	if err != nil {
		t.Fatal(err)
	}
	if has(s1, "node_cpu_usage_percent") || !has(s1, "node_memory_used_percent") {
		t.Fatalf("first poll: %+v", s1)
	}
	e.srv.on("cat /proc/loadavg /proc/meminfo /proc/stat", resp{out: proc(400, 1600)}) // Δuser=300 Δidle=700 → 30%
	s2, err := e.c.Metrics(ctx, e.a, e.cred)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range s2 {
		switch s.Metric {
		case "node_cpu_usage_percent":
			if s.Value != 30 {
				t.Fatalf("cpu: %v", s.Value)
			}
		case "node_memory_used_percent":
			if s.Value != 75 {
				t.Fatalf("mem: %v", s.Value)
			}
		case "node_disk_used_percent":
			if s.Labels["mount"] == "/run" {
				t.Fatal("tmpfs must be excluded")
			}
		}
	}
	if !has(s2, "node_cpu_usage_percent") || count(s2, "node_disk_used_percent") != 2 {
		t.Fatalf("second poll: %+v", s2)
	}

	e.srv.on("cat /proc/sys/kernel/hostname", resp{out: "app-linux-01\n"})
	e.srv.on("cat /etc/os-release", resp{out: "NAME=\"Ubuntu\"\nVERSION_ID=\"22.04\"\nPRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\n"})
	e.srv.on("systemctl list-units --type=service --all --no-legend --no-pager --plain",
		resp{out: "nginx.service loaded active running nginx\nssh.service loaded active running OpenBSD\nghost.service not-found inactive dead ghost\n"})
	obs, err := e.c.Collector().Collect(ctx, discovery.Target{TenantID: tenantID, Address: e.a.Connection.Address, Port: e.a.Connection.Port,
		Method: Method, CredentialRef: "kv/data/tenants/t/ssh", HostKey: e.a.Connection.HostKey},
		discovery.Credential{Username: "ro", PrivateKey: e.srv.clientKey})
	if err != nil {
		t.Fatal(err)
	}
	a := obs.Assets[0]
	if a.Name != "app-linux-01" || a.Type != "linux_host" || strings.Join(a.Objects["systemd_unit"], ",") != "nginx.service,ssh.service" ||
		a.Objects["os"][0] != "Ubuntu 22.04.4 LTS" || strings.Join(a.Objects["filesystem"], ",") != "/,/var/log" {
		t.Fatalf("asset: %+v", a)
	}
	if len(a.Objects["log_directory"]) != 0 || a.Connection.HostKey == "" || len(obs.Warnings) != 1 {
		t.Fatalf("discovery must not authorize cleanup dirs; warnings %v", obs.Warnings)
	}
	if _, err := e.c.Collector().Collect(ctx, discovery.Target{TenantID: tenantID, Address: e.a.Connection.Address, Port: e.a.Connection.Port, Method: Method},
		discovery.Credential{Username: "ro", PrivateKey: e.srv.clientKey}); !errors.Is(err, ErrNoHostKey) {
		t.Fatalf("collector without host key: %v", err)
	}
	// LC_ALL=C передаётся окружением сессии, а не в строке команды.
	e.srv.mu.Lock()
	envOK := len(e.srv.env) > 0 && e.srv.env[0] == "LC_ALL=C"
	e.srv.mu.Unlock()
	if !envOK {
		t.Fatal("LC_ALL=C must be requested via session env")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func has(s []telemetrySample, m string) bool { return count(s, m) > 0 }

func count(s []telemetrySample, m string) int {
	n := 0
	for _, x := range s {
		if x.Metric == m {
			n++
		}
	}
	return n
}
