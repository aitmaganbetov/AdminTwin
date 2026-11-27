package linux

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Allowlist команд (§11.6: произвольный shell запрещён). Команда создаётся только конструкторами этого
// файла, которые проверяют аргументы; перед исполнением argv повторно сверяется с шаблонами (allowed).
// Любая команда вне шаблонов отклоняется, даже если её построил код коннектора.

// command — argv и признак записи (write-команды и очистка журналов могут выполняться через sudo -n).
type command struct {
	argv  []string
	write bool
}

var (
	unitRe  = regexp.MustCompile(`^[a-zA-Z0-9@._:-]{1,200}\.(service|socket|timer|mount|target)$`)
	propRe  = regexp.MustCompile(`^--property=[A-Za-z]+(,[A-Za-z]+)*$`)
	mountRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]{0,255}$`)
)

// ErrNotAllowlisted — команда не входит в allowlist.
var ErrNotAllowlisted = errors.New("command is not in the allowlist")

func validUnit(u string) bool { return unitRe.MatchString(u) && !strings.HasPrefix(u, "-") }

func validPath(p string) bool {
	return mountRe.MatchString(p) && path.Clean(p) == p && !slices.Contains(strings.Split(p, "/"), "..")
}

// catFiles — файлы, которые разрешено читать cat.
var catFiles = []string{"/proc/loadavg", "/proc/meminfo", "/proc/stat", "/proc/uptime", "/etc/os-release", "/proc/sys/kernel/hostname"}

// DefaultLogDirectories — allowlist каталогов очистки (совпадает с enum runbook linux.logs.rotate_cleanup).
var DefaultLogDirectories = []string{"/var/log/nginx", "/var/log/app", "/var/log/journal-archive", "/var/lib/docker/containers"}

// DefaultRestartUnits — allowlist служб для перезапуска (enum runbook linux.service.restart).
var DefaultRestartUnits = []string{"nginx.service", "docker.service", "postgresql.service", "redis-server.service", "php-fpm.service", "apache2.service"}

// --- конструкторы read-only команд ---

func cmdShow(props []string, units ...string) (command, error) {
	if len(units) == 0 || len(units) > 64 {
		return command{}, ErrNotAllowlisted
	}
	for _, u := range units {
		if !validUnit(u) {
			return command{}, fmt.Errorf("invalid unit name")
		}
	}
	argv := append([]string{"systemctl", "show"}, units...)
	argv = append(argv, "--property="+strings.Join(props, ","), "--no-pager")
	return command{argv: argv}, nil
}

func cmdListUnits() command {
	return command{argv: []string{"systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain"}}
}

func cmdDF(p string) (command, error) {
	if p == "" {
		return command{argv: []string{"df", "-P", "-B1"}}, nil
	}
	if !validPath(p) {
		return command{}, fmt.Errorf("invalid path")
	}
	return command{argv: []string{"df", "-P", "-B1", p}}, nil
}

func cmdDFInodes() command { return command{argv: []string{"df", "-P", "-i"}} }

func cmdFindmnt() command {
	return command{argv: []string{"findmnt", "-r", "-n", "-o", "TARGET,SOURCE,FSTYPE"}}
}

func cmdJournal(unit string, n int) (command, error) {
	if !validUnit(unit) || n < 1 || n > 200 {
		return command{}, fmt.Errorf("invalid journal request")
	}
	return command{argv: []string{"journalctl", "-u", unit, "-n", strconv.Itoa(n), "--no-pager", "-o", "short-iso"}}, nil
}

func cmdCat(files ...string) (command, error) {
	if len(files) == 0 {
		return command{}, ErrNotAllowlisted
	}
	for _, f := range files {
		if !slices.Contains(catFiles, f) {
			return command{}, ErrNotAllowlisted
		}
	}
	return command{argv: append([]string{"cat"}, files...)}, nil
}

// --- конструкторы команд, исполняемых только Gateway ---

func cmdRestart(unit string) (command, error) {
	if !validUnit(unit) {
		return command{}, fmt.Errorf("invalid unit name")
	}
	return command{argv: []string{"systemctl", "restart", unit}, write: true}, nil
}

// findPrintf — формат вывода find: размер, табуляция, путь, NUL (пути с переводами строк разбираются корректно).
const findPrintf = `%s\t%p\0`

// dockerActiveLog — активный журнал контейнера (<id>-json.log) не удаляется: его держит открытым dockerd.
const dockerActiveLog = "*-json.log"

func (c *Connector) cmdFindLogs(dir string, days int, del bool) (command, error) {
	if !c.logDirAllowed(dir) || days < 3 || days > 365 {
		return command{}, ErrNotAllowlisted
	}
	argv := []string{"find", dir, "-xdev", "-type", "f", "-mtime", "+" + strconv.Itoa(days), "-name", "*.log*"}
	if dir == "/var/lib/docker/containers" {
		argv = append(argv, "!", "-name", dockerActiveLog)
	}
	argv = append(argv, "-printf", findPrintf)
	if del {
		argv = append(argv, "-delete")
	}
	// Даже листинг (dry-run) выполняется с теми же правами, что и удаление: иначе отчёт неполон.
	return command{argv: argv, write: true}, nil
}

func (c *Connector) cmdDU(dir string) (command, error) {
	if !c.logDirAllowed(dir) {
		return command{}, ErrNotAllowlisted
	}
	return command{argv: []string{"du", "-s", "-x", "-B1", dir}}, nil
}

func (c *Connector) logDirAllowed(dir string) bool {
	return validPath(dir) && slices.Contains(c.o.LogDirectories, dir)
}

// --- повторная проверка argv по шаблонам ---

// allowed сверяет итоговый argv (с возможным префиксом sudo -n --) с allowlist.
func (c *Connector) allowed(argv []string) error {
	if len(argv) >= 3 && argv[0] == "sudo" {
		if argv[1] != "-n" || argv[2] != "--" {
			return ErrNotAllowlisted
		}
		argv = argv[3:]
		if !c.o.Sudo || !c.writeTemplate(argv) {
			return ErrNotAllowlisted
		}
		return nil
	}
	if c.readTemplate(argv) || c.writeTemplate(argv) {
		return nil
	}
	return ErrNotAllowlisted
}

func eq(a []string, b ...string) bool { return slices.Equal(a, b) }

func (c *Connector) readTemplate(a []string) bool {
	if len(a) == 0 {
		return false
	}
	switch a[0] {
	case "systemctl":
		if eq(a, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain") {
			return true
		}
		if len(a) < 5 || a[1] != "show" || a[len(a)-1] != "--no-pager" || !propRe.MatchString(a[len(a)-2]) {
			return false
		}
		for _, u := range a[2 : len(a)-2] {
			if !validUnit(u) {
				return false
			}
		}
		return true
	case "df":
		return eq(a, "df", "-P", "-B1") || eq(a, "df", "-P", "-i") || (len(a) == 4 && eq(a[:3], "df", "-P", "-B1") && validPath(a[3]))
	case "findmnt":
		return eq(a, "findmnt", "-r", "-n", "-o", "TARGET,SOURCE,FSTYPE")
	case "du":
		return len(a) == 5 && eq(a[:4], "du", "-s", "-x", "-B1") && c.logDirAllowed(a[4])
	case "journalctl":
		if len(a) != 8 || a[1] != "-u" || !validUnit(a[2]) || a[3] != "-n" || !eq(a[5:], "--no-pager", "-o", "short-iso") {
			return false
		}
		n, err := strconv.Atoi(a[4])
		return err == nil && n >= 1 && n <= 200 && strconv.Itoa(n) == a[4]
	case "cat":
		if len(a) < 2 {
			return false
		}
		for _, f := range a[1:] {
			if !slices.Contains(catFiles, f) {
				return false
			}
		}
		return true
	}
	return false
}

func (c *Connector) writeTemplate(a []string) bool {
	if len(a) == 3 && a[0] == "systemctl" && a[1] == "restart" {
		return validUnit(a[2]) && slices.Contains(c.o.RestartUnits, a[2])
	}
	if len(a) < 11 || a[0] != "find" || !c.logDirAllowed(a[1]) {
		return false
	}
	if !eq(a[2:6], "-xdev", "-type", "f", "-mtime") || !strings.HasPrefix(a[6], "+") || !eq(a[7:9], "-name", "*.log*") {
		return false
	}
	days, err := strconv.Atoi(a[6][1:])
	if err != nil || days < 3 || days > 365 || "+"+strconv.Itoa(days) != a[6] {
		return false
	}
	rest := a[9:]
	if a[1] == "/var/lib/docker/containers" {
		if len(rest) < 3 || !eq(rest[:3], "!", "-name", dockerActiveLog) {
			return false
		}
		rest = rest[3:]
	}
	return eq(rest, "-printf", findPrintf) || eq(rest, "-printf", findPrintf, "-delete")
}
