// Package linux — коннектор Linux/Ubuntu по SSH (§14 п.1): read-only диагностика (systemd, CPU/RAM/disk,
// журналы), движки ssh_argv (systemctl restart) и builtin (logs_rotate_cleanup), discovery и метрики.
//
// Безопасность: shell не используется как интерпретатор команд — каждая команда строится из allowlist,
// каждый аргумент экранируется отдельно (Quote), argv повторно сверяется с шаблонами; проверка host key
// обязательна (Connection.HostKey), без него подключение отклоняется.
package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aitmaganbetov/admintwin/connectors/internal/common"
	"github.com/aitmaganbetov/admintwin/services/discovery"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
	"github.com/aitmaganbetov/admintwin/services/inventory"
	"github.com/aitmaganbetov/admintwin/services/telemetry"
)

// Method — значение inventory.Connection.Method.
const Method = "ssh"

const (
	maxOut     = 1 << 20 // stdout read-only команд
	maxJournal = 256 << 10
)

// Options — параметры коннектора.
type Options struct {
	Logger      *slog.Logger
	DialTimeout time.Duration // подключение и рукопожатие (10 с)
	ReadTimeout time.Duration // одна read-only операция целиком (30 с)
	// Sudo — write-команды (systemctl restart, find очистки) выполняются как `sudo -n -- <argv>`;
	// требуется правило sudoers NOPASSWD ровно для этих команд (см. README).
	Sudo bool
	// LogDirectories — allowlist каталогов очистки (по умолчанию enum runbook linux.logs.rotate_cleanup).
	LogDirectories []string
	// RestartUnits — allowlist служб (по умолчанию enum runbook linux.service.restart).
	RestartUnits []string
	JournalLines int // строк recent_log (≤ 50 по контракту)
	Now          func() time.Time
}

func (o Options) withDefaults() Options {
	if o.DialTimeout <= 0 {
		o.DialTimeout = 10 * time.Second
	}
	if o.ReadTimeout <= 0 {
		o.ReadTimeout = 30 * time.Second
	}
	if len(o.LogDirectories) == 0 {
		o.LogDirectories = DefaultLogDirectories
	}
	if len(o.RestartUnits) == 0 {
		o.RestartUnits = DefaultRestartUnits
	}
	if o.JournalLines <= 0 || o.JournalLines > 50 {
		o.JournalLines = 50
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	o.Logger = common.Logger(o.Logger)
	return o
}

// Connector — SSH-коннектор.
type Connector struct {
	o Options

	mu       sync.Mutex
	restarts map[string][]time.Time // tenant|asset|unit → перезапуски, выполненные этим процессом
	cpuPrev  map[string]cpuTimes    // tenant|asset → предыдущий отсчёт /proc/stat
}

// New создаёт коннектор.
func New(o Options) *Connector {
	return &Connector{o: o.withDefaults(), restarts: map[string][]time.Time{}, cpuPrev: map[string]cpuTimes{}}
}

func key(parts ...string) string { return strings.Join(parts, "|") }

func (c *Connector) readCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.o.ReadTimeout)
}

// --- Engines ---

// ArgvEngine — движок ssh_argv (action systemctl_restart).
func (c *Connector) ArgvEngine() gateway.Engine { return argvEngine{c} }

// BuiltinEngine — движок builtin (action logs_rotate_cleanup).
func (c *Connector) BuiltinEngine() gateway.Engine { return builtinEngine{c} }

type argvEngine struct{ c *Connector }

func (e argvEngine) Execute(ctx context.Context, req gateway.EngineRequest) (gateway.EngineResult, error) {
	c := e.c
	if req.Action != "systemctl_restart" {
		return gateway.EngineResult{}, fmt.Errorf("ssh_argv: unsupported action %q", req.Action)
	}
	if len(req.Argv) != 3 || req.Argv[0] != "systemctl" || req.Argv[1] != "restart" {
		return gateway.EngineResult{}, errors.New("ssh_argv: argv does not match the runbook template")
	}
	unit := req.Argv[2]
	if !validUnit(unit) || !slices.Contains(c.o.RestartUnits, unit) {
		return gateway.EngineResult{}, errors.New("ssh_argv: unit is not in the restart allowlist")
	}
	if p, ok := req.Params["unit"]; ok && p != unit {
		return gateway.EngineResult{}, errors.New("ssh_argv: argv does not match parameters")
	}
	if !req.Asset.HasObject("systemd_unit", unit) || req.Asset.IsProtected(unit) {
		return gateway.EngineResult{}, errors.New("ssh_argv: unit is not an allowed inventory object of the asset")
	}
	if req.DryRun {
		return gateway.EngineResult{}, errors.New("ssh_argv: restart does not support dry run")
	}
	if err := common.CheckLease(req.Lease, c.o.Now()); err != nil {
		return gateway.EngineResult{}, err
	}
	cmd, err := cmdRestart(unit)
	if err != nil {
		return gateway.EngineResult{}, err
	}
	s, err := c.dial(ctx, req.Asset.Connection, req.Lease.Credential)
	if err != nil {
		if ctx.Err() != nil {
			return gateway.EngineResult{}, gateway.ErrCancelConfirmed // подключение не установлено — команда не отправлялась
		}
		return gateway.EngineResult{}, err
	}
	defer s.close()
	out, res, err := s.output(ctx, cmd, 64<<10)
	if res.started {
		// Учитываем перезапуск и при неизвестном исходе (оценка сверху для лимита restart_count).
		c.noteRestart(req.TenantID, req.Asset.ID, unit)
	}
	if err != nil {
		return gateway.EngineResult{Stdout: out, Stderr: res.stderr}, err
	}
	if res.exit == 0 && out == "" {
		out = "restarted " + unit
	}
	return gateway.EngineResult{Stdout: out, Stderr: res.stderr, ExitCode: res.exit}, nil
}

func (c *Connector) noteRestart(tenant, asset, unit string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := key(tenant, asset, unit)
	c.restarts[k] = append(c.restarts[k], c.o.Now())
}

func (c *Connector) localRestarts(tenant, asset, unit string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := key(tenant, asset, unit)
	cut := c.o.Now().Add(-time.Hour)
	kept := c.restarts[k][:0]
	for _, t := range c.restarts[k] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	c.restarts[k] = kept
	return len(kept)
}

type builtinEngine struct{ c *Connector }

func (e builtinEngine) Execute(ctx context.Context, req gateway.EngineRequest) (gateway.EngineResult, error) {
	if req.Action != "logs_rotate_cleanup" {
		return gateway.EngineResult{}, fmt.Errorf("builtin: unsupported action %q", req.Action)
	}
	return e.c.cleanup(ctx, req)
}

// cleanup — очистка старых журналов в каталоге из allowlist. Dry-run: только листинг с объёмом.
// Удаление — `find ... -printf ... -delete` (один проход: удаляется ровно то, что вошло в отчёт).
func (c *Connector) cleanup(ctx context.Context, req gateway.EngineRequest) (gateway.EngineResult, error) {
	a := req.Asset
	dir, _ := req.Params["directory"].(string)
	days, ok := intParam(req.Params["older_than_days"])
	if !ok {
		return gateway.EngineResult{}, errors.New("builtin: older_than_days must be an integer")
	}
	// Defense in depth: allowlist коннектора, объект CMDB актива, legal hold / расследование (§11.6, T-LH-001).
	if !c.logDirAllowed(dir) || !a.HasObject("log_directory", dir) || a.IsProtected(dir) {
		return gateway.EngineResult{}, errors.New("builtin: directory is not in the allowlist of the asset")
	}
	if a.LegalHold || a.ActiveInvestigation {
		return gateway.EngineResult{}, errors.New("builtin: log cleanup is forbidden under legal hold or active investigation")
	}
	if err := common.CheckLease(req.Lease, c.o.Now()); err != nil {
		return gateway.EngineResult{}, err
	}
	find, err := c.cmdFindLogs(dir, int(days), !req.DryRun)
	if err != nil {
		return gateway.EngineResult{}, err
	}
	s, err := c.dial(ctx, a.Connection, req.Lease.Credential)
	if err != nil {
		if ctx.Err() != nil {
			return gateway.EngineResult{}, gateway.ErrCancelConfirmed
		}
		return gateway.EngineResult{}, err
	}
	defer s.close()

	// Размер файловой системы каталога — для отчёта в процентах.
	var fsSize int64
	var fsMount string
	if df, err := cmdDF(dir); err == nil {
		rctx, cancel := c.readCtx(ctx)
		if out, err := s.mustOutput(rctx, df, 64<<10); err == nil {
			if rows := parseDF(out); len(rows) > 0 {
				fsSize, fsMount = rows[0].size, rows[0].mount
			}
		}
		cancel()
	}
	if ctx.Err() != nil {
		return gateway.EngineResult{}, gateway.ErrCancelConfirmed
	}
	st := &findStats{}
	res, err := s.run(ctx, find, st)
	report := st.report(req.DryRun, dir, int(days), fsSize, fsMount)
	if err != nil {
		return gateway.EngineResult{Stdout: report, Stderr: res.stderr}, err
	}
	return gateway.EngineResult{Stdout: report, Stderr: common.Truncate(res.stderr, 8<<10), ExitCode: res.exit}, nil
}

func intParam(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case float64:
		if x == math.Trunc(x) {
			return int64(x), true
		}
	}
	return 0, false
}

// findStats — потоковый разбор вывода find (`<size>\t<path>\0`): счётчики без накопления всего списка.
type findStats struct {
	files   int
	bytes   int64
	samples []string
	partial []byte
}

func (f *findStats) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, 0)
		if i < 0 {
			if len(f.partial) < 8<<10 {
				f.partial = append(f.partial, p...)
			}
			return n, nil
		}
		f.record(append(f.partial, p[:i]...))
		f.partial = f.partial[:0]
		p = p[i+1:]
	}
	return n, nil
}

func (f *findStats) record(rec []byte) {
	size, path, ok := bytes.Cut(rec, []byte{'\t'})
	if !ok {
		return
	}
	n, err := strconv.ParseInt(string(size), 10, 64)
	if err != nil || n < 0 {
		return
	}
	f.files++
	f.bytes += n
	if len(f.samples) < 10 {
		f.samples = append(f.samples, sanitize(string(path), 256))
	}
}

func (f *findStats) report(dry bool, dir string, days int, fsSize int64, mount string) string {
	pct := ""
	if fsSize > 0 {
		pct = fmt.Sprintf(" (%.2f%% of filesystem %s)", float64(f.bytes)*100/float64(fsSize), mount)
	}
	verb := "deleted"
	if dry {
		verb = "dry-run: would delete"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %d files, %d bytes%s in %s older than %d days", verb, f.files, f.bytes, pct, dir, days)
	for _, s := range f.samples {
		b.WriteString("\n  ")
		b.WriteString(s)
	}
	if f.files > len(f.samples) {
		fmt.Fprintf(&b, "\n  ... and %d more", f.files-len(f.samples))
	}
	return b.String()
}

// --- Facts ---

func (c *Connector) showProps(ctx context.Context, s *session, props []string, units ...string) ([]map[string]string, error) {
	cmd, err := cmdShow(props, units...)
	if err != nil {
		return nil, err
	}
	out, err := s.mustOutput(ctx, cmd, maxOut)
	if err != nil {
		return nil, err
	}
	return parseShow(out), nil
}

func (c *Connector) withSession(ctx context.Context, a inventory.Asset, cred gateway.Credential, fn func(context.Context, *session) error) error {
	ctx, cancel := c.readCtx(ctx)
	defer cancel()
	s, err := c.dial(ctx, a.Connection, cred)
	if err != nil {
		return err
	}
	defer s.close()
	return fn(ctx, s)
}

// UnitActive — ActiveState=active.
func (c *Connector) UnitActive(ctx context.Context, a inventory.Asset, cred gateway.Credential, unit string) (bool, error) {
	var ok bool
	err := c.withSession(ctx, a, cred, func(ctx context.Context, s *session) error {
		p, err := c.showProps(ctx, s, []string{"ActiveState"}, unit)
		if err != nil {
			return err
		}
		ok = len(p) > 0 && p[0]["ActiveState"] == "active"
		return nil
	})
	return ok, err
}

// RestartsLastHour — оценка числа перезапусков unit за последний час:
//   - если unit активен непрерывно больше часа (ActiveEnterTimestampMonotonic vs /proc/uptime) — 0:
//     любой перезапуск, ручной или автоматический, обновил бы момент входа в active;
//   - иначе NRestarts (автоматические перезапуски с момента загрузки unit — оценка сверху)
//     плюс перезапуски, выполненные этим процессом за час.
func (c *Connector) RestartsLastHour(ctx context.Context, a inventory.Asset, cred gateway.Credential, unit string) (int, error) {
	var n int
	err := c.withSession(ctx, a, cred, func(ctx context.Context, s *session) error {
		p, err := c.showProps(ctx, s, []string{"NRestarts", "ActiveState", "ActiveEnterTimestampMonotonic"}, unit)
		if err != nil || len(p) == 0 {
			return errors.Join(err, errors.New("ssh: no unit properties"))
		}
		cat, _ := cmdCat("/proc/uptime")
		up, err := s.mustOutput(ctx, cat, 4<<10)
		if err != nil {
			return err
		}
		uptime, err := strconv.ParseFloat(strings.Fields(up + " 0")[0], 64)
		if err != nil {
			return errors.New("ssh: cannot parse /proc/uptime")
		}
		enter, _ := strconv.ParseFloat(p[0]["ActiveEnterTimestampMonotonic"], 64)
		if p[0]["ActiveState"] == "active" && enter > 0 && uptime-enter/1e6 >= 3600 {
			n = 0
			return nil
		}
		nr, err := strconv.Atoi(p[0]["NRestarts"])
		if err != nil {
			nr = 0 // старые версии systemd не сообщают NRestarts
		}
		n = nr + c.localRestarts(a.TenantID, a.ID, unit)
		return nil
	})
	return n, err
}

// DiskUsagePercent — максимальное заполнение среди постоянных файловых систем (консервативно для post-check).
func (c *Connector) DiskUsagePercent(ctx context.Context, a inventory.Asset, cred gateway.Credential) (float64, error) {
	var pct float64
	err := c.withSession(ctx, a, cred, func(ctx context.Context, s *session) error {
		fss, err := c.filesystems(ctx, s, "")
		if err != nil {
			return err
		}
		if len(fss) == 0 {
			return errors.New("ssh: no persistent filesystems reported")
		}
		for _, f := range fss {
			pct = math.Max(pct, f.usePercent())
		}
		return nil
	})
	return pct, err
}

// LogWritersHealthy — systemd-journald активен; rsyslog (если установлен) активен; ни одна служба
// актива из CMDB (Objects["systemd_unit"]) не в состоянии failed (после очистки писатели журналов не упали).
func (c *Connector) LogWritersHealthy(ctx context.Context, a inventory.Asset, cred gateway.Credential) (bool, error) {
	units := []string{"systemd-journald.service", "rsyslog.service"}
	for _, u := range a.Objects["systemd_unit"] {
		if validUnit(u) && !slices.Contains(units, u) {
			units = append(units, u)
		}
	}
	healthy := true
	err := c.withSession(ctx, a, cred, func(ctx context.Context, s *session) error {
		blocks, err := c.showProps(ctx, s, []string{"Id", "LoadState", "ActiveState"}, units...)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, b := range blocks {
			id := b["Id"]
			seen[id] = true
			switch {
			case id == "systemd-journald.service" && b["ActiveState"] != "active":
				healthy = false
			case id == "rsyslog.service" && b["LoadState"] == "loaded" && b["ActiveState"] != "active":
				healthy = false
			case b["ActiveState"] == "failed":
				healthy = false
			}
		}
		if !seen["systemd-journald.service"] {
			healthy = false
		}
		return nil
	})
	return healthy && err == nil, err
}

// --- read tools ---

var activeStates = []string{"active", "reloading", "inactive", "failed", "activating", "deactivating"}

// ServiceStatus — данные по контракту linux.service.status. recent_log не маскируется (маскирование —
// на стороне AI-слоя), но ограничен по числу строк и длине.
func (c *Connector) ServiceStatus(ctx context.Context, a inventory.Asset, cred gateway.Credential, unit string) (map[string]any, error) {
	if !validUnit(unit) {
		return nil, errors.New("invalid unit name")
	}
	var out map[string]any
	err := c.withSession(ctx, a, cred, func(ctx context.Context, s *session) error {
		p, err := c.showProps(ctx, s, []string{"LoadState", "ActiveState", "SubState", "MainPID", "ActiveEnterTimestamp"}, unit)
		if err != nil || len(p) == 0 {
			return errors.Join(err, errors.New("ssh: no unit properties"))
		}
		st := p[0]["ActiveState"]
		if !slices.Contains(activeStates, st) {
			return fmt.Errorf("ssh: unexpected ActiveState %q", common.Truncate(st, 32))
		}
		out = map[string]any{
			"unit": unit, "load_state": common.Truncate(p[0]["LoadState"], 32), "active_state": st,
			"sub_state": common.Truncate(p[0]["SubState"], 32), "since": nil, "main_pid": nil, "recent_log": []string{},
		}
		if ts := p[0]["ActiveEnterTimestamp"]; ts != "" && ts != "n/a" {
			out["since"] = common.Truncate(ts, 64)
		}
		if pid, err := strconv.Atoi(p[0]["MainPID"]); err == nil && pid > 0 {
			out["main_pid"] = pid
		}
		jc, err := cmdJournal(unit, c.o.JournalLines)
		if err != nil {
			return err
		}
		// Журнал может быть недоступен учётке (группа systemd-journal/adm) — статус возвращаем без него.
		if text, res, err := s.output(ctx, jc, maxJournal); err == nil && res.exit == 0 {
			out["recent_log"] = journalLines(text, c.o.JournalLines)
		}
		return nil
	})
	return out, err
}

// journalLines — последние n строк, каждая ≤ 4096 байт, суммарно ≤ 24 КиБ (лимит ответа 32 КиБ).
func journalLines(text string, n int) []string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return []string{}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	budget := 24 << 10
	out := make([]string, 0, len(lines))
	for i := len(lines) - 1; i >= 0; i-- {
		l := common.Truncate(strings.ToValidUTF8(lines[i], "?"), 4096)
		if budget -= len(l) + 4; budget < 0 {
			break
		}
		out = append(out, l)
	}
	slices.Reverse(out)
	return out
}

// DiskUsage — данные по контракту linux.disk.usage; top_dirs — размеры каталогов журналов актива из allowlist.
func (c *Connector) DiskUsage(ctx context.Context, a inventory.Asset, cred gateway.Credential, mount string) (map[string]any, error) {
	var out map[string]any
	err := c.withSession(ctx, a, cred, func(ctx context.Context, s *session) error {
		fss, err := c.filesystems(ctx, s, mount)
		if err != nil {
			return err
		}
		items := make([]map[string]any, 0, len(fss))
		for i, f := range fss {
			if i >= 200 {
				break
			}
			m := map[string]any{"mount": f.mount, "device": f.device, "size_bytes": f.size, "used_bytes": f.used,
				"avail_bytes": f.avail, "use_percent": round1(f.usePercent()), "inodes_use_percent": nil}
			if f.fstype != "" {
				m["fstype"] = f.fstype
			}
			if f.inodes != nil {
				m["inodes_use_percent"] = *f.inodes
			}
			items = append(items, m)
		}
		dirs := []map[string]any{}
		for _, d := range a.Objects["log_directory"] {
			du, err := c.cmdDU(d)
			if err != nil {
				continue
			}
			// du возвращает 1 при частичном отказе в доступе — тогда размер не сообщаем.
			text, res, err := s.output(ctx, du, 4<<10)
			if err != nil || res.exit != 0 {
				continue
			}
			if f := strings.Fields(text); len(f) >= 2 {
				if n, err := strconv.ParseInt(f[0], 10, 64); err == nil && n >= 0 {
					dirs = append(dirs, map[string]any{"path": d, "size_bytes": n})
				}
			}
			if len(dirs) >= 50 {
				break
			}
		}
		out = map[string]any{"filesystems": items, "top_dirs": dirs}
		return nil
	})
	return out, err
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

// filesystem — строка df, дополненная findmnt и df -i.
type filesystem struct {
	device, mount, fstype string
	size, used, avail     int64
	inodes                *float64
}

func (f filesystem) usePercent() float64 {
	if f.used+f.avail <= 0 {
		return 0
	}
	return math.Min(100, float64(f.used)*100/float64(f.used+f.avail))
}

// pseudoFS — виртуальные ФС, не участвующие в оценке заполнения.
var pseudoFS = map[string]bool{
	"tmpfs": true, "devtmpfs": true, "overlay": true, "squashfs": true, "proc": true, "sysfs": true, "cgroup": true,
	"cgroup2": true, "devpts": true, "mqueue": true, "debugfs": true, "tracefs": true, "securityfs": true, "pstore": true,
	"bpf": true, "autofs": true, "hugetlbfs": true, "configfs": true, "fusectl": true, "ramfs": true, "nsfs": true,
	"efivarfs": true, "binfmt_misc": true, "rpc_pipefs": true, "fuse.lxcfs": true, "fuse.portal": true, "fuse.gvfsd-fuse": true,
}

func (c *Connector) filesystems(ctx context.Context, s *session, mount string) ([]filesystem, error) {
	df, err := cmdDF(mount)
	if err != nil {
		return nil, err
	}
	out, err := s.mustOutput(ctx, df, maxOut)
	if err != nil {
		return nil, err
	}
	rows := parseDF(out)
	types := map[string]string{}
	if text, err := s.mustOutput(ctx, cmdFindmnt(), maxOut); err == nil {
		types = parseFindmnt(text)
	}
	inodes := map[string]*float64{}
	if text, err := s.mustOutput(ctx, cmdDFInodes(), maxOut); err == nil {
		inodes = parseDFInodes(text)
	}
	var fss []filesystem
	for _, r := range rows {
		r.fstype = types[r.mount]
		r.inodes = inodes[r.mount]
		if mount == "" && (pseudoFS[r.fstype] || r.size == 0 || slices.Contains([]string{"tmpfs", "devtmpfs", "udev", "overlay", "none"}, r.device)) {
			continue
		}
		fss = append(fss, r)
	}
	sort.SliceStable(fss, func(i, j int) bool { return fss[i].mount < fss[j].mount })
	return fss, nil
}

// --- метрики ---

// Metrics — node_cpu_usage_percent (с второго опроса: разность /proc/stat), node_memory_used_percent,
// node_disk_used_percent{mount}.
func (c *Connector) Metrics(ctx context.Context, a inventory.Asset, cred gateway.Credential) ([]telemetry.Sample, error) {
	var out []telemetry.Sample
	now := c.o.Now().UTC()
	sample := func(metric string, v float64, labels map[string]string) {
		out = append(out, telemetry.Sample{TenantID: a.TenantID, AssetID: a.ID, Metric: metric, Labels: labels, Value: round1(v), At: now})
	}
	err := c.withSession(ctx, a, cred, func(ctx context.Context, s *session) error {
		cat, _ := cmdCat("/proc/loadavg", "/proc/meminfo", "/proc/stat")
		text, err := s.mustOutput(ctx, cat, maxOut)
		if err != nil {
			return err
		}
		if total, avail, ok := parseMeminfo(text); ok && total > 0 {
			sample("node_memory_used_percent", float64(total-avail)*100/float64(total), nil)
		}
		if cur, ok := parseCPU(text); ok {
			k := key(a.TenantID, a.ID)
			c.mu.Lock()
			prev, had := c.cpuPrev[k]
			c.cpuPrev[k] = cur
			c.mu.Unlock()
			if had {
				if p, ok := cpuPercent(prev, cur); ok {
					sample("node_cpu_usage_percent", p, nil)
				}
			}
		}
		fss, err := c.filesystems(ctx, s, "")
		if err != nil {
			return err
		}
		for _, f := range fss {
			sample("node_disk_used_percent", f.usePercent(), map[string]string{"mount": f.mount})
		}
		return nil
	})
	return out, err
}

// --- discovery ---

// Collector — read-only сборщик ssh: hostname, os-release, службы systemd, файловые системы.
// Objects["log_directory"] не заполняется автоматически: каталоги очистки утверждает человек в CMDB.
func (c *Connector) Collector() discovery.Collector { return collector{c} }

type collector struct{ c *Connector }

func (collector) Method() string { return Method }

func (k collector) Collect(ctx context.Context, t discovery.Target, cred discovery.Credential) (discovery.Observation, error) {
	c := k.c
	conn := &inventory.Connection{Method: Method, Address: t.Address, Port: t.Port, CredentialRef: t.CredentialRef, HostKey: t.HostKey}
	a := inventory.Asset{TenantID: t.TenantID, Type: "linux_host", Source: "discovery", Reachability: "reachable",
		Connection: conn, Objects: map[string][]string{}}
	obs := discovery.Observation{Confidence: 0.9}
	err := c.withSession(ctx, a, common.FromDiscovery(cred), func(ctx context.Context, s *session) error {
		hn, _ := cmdCat("/proc/sys/kernel/hostname")
		host, err := s.mustOutput(ctx, hn, 4<<10)
		if err != nil {
			return err
		}
		a.Name = sanitize(strings.TrimSpace(host), 253)
		osr, _ := cmdCat("/etc/os-release")
		if text, err := s.mustOutput(ctx, osr, 64<<10); err == nil {
			if v := parseOSRelease(text); v != "" {
				a.Objects["os"] = []string{sanitize(v, 128)}
			}
		} else {
			obs.Warnings = append(obs.Warnings, "os-release is not readable")
		}
		if text, err := s.mustOutput(ctx, cmdListUnits(), maxOut); err == nil {
			a.Objects["systemd_unit"] = parseListUnits(text)
		} else {
			obs.Warnings = append(obs.Warnings, "systemd units are not listable")
			obs.Confidence = 0.7
		}
		if fss, err := c.filesystems(ctx, s, ""); err == nil {
			for _, f := range fss {
				a.Objects["filesystem"] = append(a.Objects["filesystem"], f.mount)
				if f.usePercent() >= 90 {
					obs.Warnings = append(obs.Warnings, fmt.Sprintf("filesystem %s is %.0f%% full", f.mount, f.usePercent()))
				}
			}
		}
		return nil
	})
	if err != nil {
		return discovery.Observation{}, err
	}
	if a.Name == "" {
		a.Name = t.Address
		obs.Confidence = 0.6
	}
	obs.Assets = []inventory.Asset{a}
	return obs, nil
}

// sanitize — вывод удалённой стороны недоверенный (§18.6): без управляющих символов, ограниченная длина.
func sanitize(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "?"))
	return common.Truncate(s, n)
}
