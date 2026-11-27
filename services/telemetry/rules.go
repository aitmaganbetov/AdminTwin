package telemetry

import (
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"
)

// Пороговые правила (MVP-сценарии §1.4: HTTP 502, исчерпание диска, остановка контейнера; плюс соединения PostgreSQL).
const (
	DiskHighPercent     = 90.0 // node_disk_used_percent ≥ 90 → high
	DiskCriticalPercent = 95.0 // ≥ 95 → critical
	HTTP5xxHighPercent  = 5.0  // http_5xx_rate > 5 (проценты, 0..100) → high
	PGConnHighRatio     = 0.9  // pg_connections_total / pg_connections_max > 0.9 → high
)

// LogPattern — правило по тексту журнала. Текст сообщения в событие не копируется:
// заголовок — фиксированный шаблон правила (строки журналов — недоверенные данные).
type LogPattern struct {
	ID       string
	Re       *regexp.Regexp
	Kind     string
	Severity Severity
	Title    string
	Labels   map[string]string
}

// DefaultLogPatterns — шаблоны MVP.
func DefaultLogPatterns() []LogPattern {
	return []LogPattern{
		{
			ID:   "nginx_upstream_502",
			Re:   regexp.MustCompile(`(?i)(upstream timed out|connect\(\) failed[^\n]{0,300}upstream|no live upstreams|upstream prematurely closed|502 bad gateway|" 502 )`),
			Kind: "http_5xx", Severity: SevHigh, Title: "nginx: upstream failure (HTTP 502)",
			Labels: map[string]string{"status": "502", "service_kind": "reverse_proxy"},
		},
		{
			ID: "no_space_left", Re: regexp.MustCompile(`(?i)no space left on device`),
			Kind: "disk_usage", Severity: SevCritical, Title: "No space left on device",
		},
		{
			ID: "oom_kill", Re: regexp.MustCompile(`(?i)(out of memory: kill(ed)? process|oom-kill)`),
			Kind: "oom_kill", Severity: SevHigh, Title: "Kernel OOM killer terminated a process",
		},
	}
}

type firing struct {
	at  time.Time
	sev Severity
}

// Rules превращает точки метрик и строки журналов в события. Повторное срабатывание одного
// fingerprint подавляется на Suppress (кроме эскалации severity); возврат ниже порога сбрасывает состояние.
type Rules struct {
	Patterns []LogPattern
	Suppress time.Duration

	mu     sync.Mutex
	pgMax  map[string]float64 // tenant|asset → pg_connections_max
	active map[string]firing  // tenant|fingerprint
}

// NewRules — правила по умолчанию.
func NewRules() *Rules {
	return &Rules{Patterns: DefaultLogPatterns(), Suppress: 5 * time.Minute, pgMax: map[string]float64{}, active: map[string]firing{}}
}

func (r *Rules) fire(e Event) (Event, bool) {
	key := e.TenantID + "|" + e.Fingerprint
	prev, ok := r.active[key]
	if ok && e.At.Sub(prev.at) < r.Suppress && !(e.Severity.Rank() > prev.sev.Rank()) {
		return e, false
	}
	r.active[key] = firing{at: e.At, sev: e.Severity}
	return e, true
}

func (r *Rules) clear(tenantID, fingerprint string) { delete(r.active, tenantID+"|"+fingerprint) }

// EvaluateSamples применяет пороговые правила. Точки должны быть нормализованы (tenant, asset, время).
func (r *Rules) EvaluateSamples(ss []Sample) []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Сначала запоминаем max_connections из пакета: total может прийти в том же запросе.
	for _, s := range ss {
		if s.Metric == "pg_connections_max" && s.Value > 0 {
			r.pgMax[s.TenantID+"|"+s.AssetID] = s.Value
		}
	}
	var out []Event
	emit := func(s Sample, kind string, sev Severity, fp, title string, labels map[string]string) {
		l := map[string]string{"rule": "threshold", "metric": s.Metric}
		for k, v := range labels {
			l[k] = v
		}
		e := Event{TenantID: s.TenantID, AssetID: s.AssetID, Kind: kind, Severity: sev, Title: title, Fingerprint: fp, Labels: l, Value: s.Value, At: s.At}
		if ev, ok := r.fire(e); ok {
			out = append(out, ev)
		}
	}
	for _, s := range ss {
		switch s.Metric {
		case "node_disk_used_percent":
			mount := s.Labels["mount"]
			fp := fmt.Sprintf("disk_usage:%s:%s", s.AssetID, mount)
			switch {
			case s.Value >= DiskCriticalPercent:
				emit(s, "disk_usage", SevCritical, fp, fmt.Sprintf("Disk usage %.1f%% on %s (>= %.0f%%)", s.Value, orDash(mount), DiskCriticalPercent), map[string]string{"mount": mount})
			case s.Value >= DiskHighPercent:
				emit(s, "disk_usage", SevHigh, fp, fmt.Sprintf("Disk usage %.1f%% on %s (>= %.0f%%)", s.Value, orDash(mount), DiskHighPercent), map[string]string{"mount": mount})
			default:
				r.clear(s.TenantID, fp)
			}
		case "container_up":
			c := s.Labels["container"]
			fp := fmt.Sprintf("container_down:%s:%s", s.AssetID, c)
			if s.Value == 0 {
				emit(s, "container_down", SevHigh, fp, fmt.Sprintf("Container %s is down", orDash(c)), map[string]string{"container": c, "service_kind": "container"})
			} else {
				r.clear(s.TenantID, fp)
			}
		case "http_5xx_rate":
			fp := fmt.Sprintf("http_5xx:%s:http_5xx_rate", s.AssetID)
			if s.Value > HTTP5xxHighPercent {
				emit(s, "http_5xx", SevHigh, fp, fmt.Sprintf("HTTP 5xx rate %.1f%% (> %.0f%%)", s.Value, HTTP5xxHighPercent), nil)
			} else {
				r.clear(s.TenantID, fp)
			}
		case "pg_connections_total":
			max := r.pgMax[s.TenantID+"|"+s.AssetID]
			fp := fmt.Sprintf("db_connections:%s", s.AssetID)
			if max <= 0 {
				continue // без max_connections порог не вычисляется
			}
			if s.Value/max > PGConnHighRatio {
				emit(s, "db_connections", SevHigh, fp, fmt.Sprintf("PostgreSQL connections %.0f of %.0f (> %.0f%%)", s.Value, max, PGConnHighRatio*100), map[string]string{"service_kind": "postgres"})
			} else {
				r.clear(s.TenantID, fp)
			}
		}
	}
	return out
}

// EvaluateLogs применяет шаблоны к записям, сопоставленным с активом.
func (r *Rules) EvaluateLogs(ls []LogRecord) []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Event
	for _, l := range ls {
		if l.AssetID == "" {
			continue
		}
		for _, p := range r.Patterns {
			if !p.Re.MatchString(l.Message) {
				continue
			}
			labels := map[string]string{"rule": p.ID, "source": l.Source}
			for k, v := range p.Labels {
				labels[k] = v
			}
			e := Event{
				TenantID: l.TenantID, AssetID: l.AssetID, Kind: p.Kind, Severity: p.Severity, Title: p.Title,
				Fingerprint: fmt.Sprintf("%s:%s:log:%s", p.Kind, l.AssetID, p.ID), Labels: labels, At: l.At,
			}
			if ev, ok := r.fire(e); ok {
				out = append(out, ev)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
