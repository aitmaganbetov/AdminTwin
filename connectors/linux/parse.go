package linux

import (
	"sort"
	"strconv"
	"strings"
)

// Разбор вывода команд allowlist. Вывод удалённой стороны недоверенный: разбор строгий,
// нераспознанные строки пропускаются.

// parseShow — `systemctl show` (KEY=VALUE; блоки разных unit разделены пустой строкой).
func parseShow(out string) []map[string]string {
	var blocks []map[string]string
	cur := map[string]string{}
	flush := func() {
		if len(cur) > 0 {
			blocks = append(blocks, cur)
			cur = map[string]string{}
		}
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		cur[k] = v
	}
	flush()
	return blocks
}

// parseDF — `df -P -B1`: Filesystem 1-blocks Used Available Capacity Mounted-on (точка монтирования может содержать пробелы).
func parseDF(out string) []filesystem {
	var rows []filesystem
	for i, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 6 {
			continue
		}
		size, e1 := strconv.ParseInt(f[1], 10, 64)
		used, e2 := strconv.ParseInt(f[2], 10, 64)
		avail, e3 := strconv.ParseInt(f[3], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || size < 0 || used < 0 || avail < 0 || !strings.HasSuffix(f[4], "%") {
			continue
		}
		rows = append(rows, filesystem{device: f[0], size: size, used: used, avail: avail, mount: strings.Join(f[5:], " ")})
	}
	return rows
}

// parseDFInodes — `df -P -i`: IUse% по точке монтирования; «-» (ФС без inodes) → нет значения.
func parseDFInodes(out string) map[string]*float64 {
	m := map[string]*float64{}
	for i, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 6 {
			continue
		}
		p, err := strconv.ParseFloat(strings.TrimSuffix(f[4], "%"), 64)
		if err != nil || p < 0 || p > 100 {
			continue
		}
		m[strings.Join(f[5:], " ")] = &p
	}
	return m
}

// parseFindmnt — `findmnt -r -n -o TARGET,SOURCE,FSTYPE` (raw: пробелы экранированы как \x20) → mount → fstype.
func parseFindmnt(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		m[unescapeHex(f[0])] = f[2]
	}
	return m
}

func unescapeHex(s string) string {
	if !strings.Contains(s, `\x`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// parseMeminfo — MemTotal и MemAvailable (кБ).
func parseMeminfo(out string) (total, avail int64, ok bool) {
	var gotT, gotA bool
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total, gotT = v, true
		case "MemAvailable:":
			avail, gotA = v, true
		}
	}
	return total, avail, gotT && gotA && avail <= total
}

// cpuTimes — агрегированная строка cpu из /proc/stat.
type cpuTimes struct{ idle, total uint64 }

func parseCPU(out string) (cpuTimes, bool) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "cpu" {
			continue
		}
		var t cpuTimes
		for i, s := range f[1:] {
			if i >= 8 { // guest/guest_nice уже включены в user/nice
				break
			}
			v, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				return cpuTimes{}, false
			}
			t.total += v
			if i == 3 || i == 4 { // idle + iowait
				t.idle += v
			}
		}
		return t, true
	}
	return cpuTimes{}, false
}

func cpuPercent(prev, cur cpuTimes) (float64, bool) {
	if cur.total <= prev.total || cur.idle < prev.idle {
		return 0, false
	}
	dt := float64(cur.total - prev.total)
	di := float64(cur.idle - prev.idle)
	if di > dt {
		return 0, false
	}
	return (dt - di) * 100 / dt, true
}

// parseOSRelease — PRETTY_NAME (или NAME VERSION_ID).
func parseOSRelease(out string) string {
	kv := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		kv[k] = strings.Trim(v, `"'`)
	}
	if v := kv["PRETTY_NAME"]; v != "" {
		return v
	}
	return strings.TrimSpace(kv["NAME"] + " " + kv["VERSION_ID"])
}

// parseListUnits — `systemctl list-units --plain --no-legend`: UNIT LOAD ACTIVE SUB DESCRIPTION; только loaded.
func parseListUnits(out string) []string {
	var units []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[1] != "loaded" || !validUnit(f[0]) {
			continue
		}
		units = append(units, f[0])
		if len(units) >= 2000 {
			break
		}
	}
	sort.Strings(units)
	return units
}
