package telemetry

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

// Retention — сроки хранения горячего слоя (§9.1, «бессрочно» не допускается).
// Нулевые поля заменяются значениями по умолчанию.
type Retention struct {
	MetricsRaw time.Duration // метрики raw: 15 дн
	Logs       time.Duration // журналы систем/приложений: 14 дн горячее (холодное — MinIO, 90 дн)
	Syslog     time.Duration // сетевой syslog: 30 дн горячее (холодное — 1 год)
	Events     time.Duration // события/алерты: 13 мес
}

// DefaultRetention — значения по умолчанию §9.1 для горячего слоя.
func DefaultRetention() Retention {
	return Retention{MetricsRaw: 15 * Day, Logs: 14 * Day, Syslog: 30 * Day, Events: 395 * Day}
}

func (r Retention) withDefaults() Retention {
	d := DefaultRetention()
	if r.MetricsRaw <= 0 {
		r.MetricsRaw = d.MetricsRaw
	}
	if r.Logs <= 0 {
		r.Logs = d.Logs
	}
	if r.Syslog <= 0 {
		r.Syslog = d.Syslog
	}
	if r.Events <= 0 {
		r.Events = d.Events
	}
	return r
}

// Limits — ёмкость кольцевых буферов на tenant (защита памяти; при переполнении вытесняются старейшие).
type Limits struct {
	Samples int
	Logs    int
	Events  int
}

// DefaultLimits — ёмкость по умолчанию (dev/test, небольшой on-prem).
func DefaultLimits() Limits { return Limits{Samples: 200_000, Logs: 50_000, Events: 20_000} }

// ring — кольцевой буфер фиксированной ёмкости.
type ring[T any] struct {
	buf  []T
	next int
	full bool
}

func newRing[T any](n int) *ring[T] { return &ring[T]{buf: make([]T, n)} }

func (r *ring[T]) push(v T) {
	r.buf[r.next] = v
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
}

func (r *ring[T]) len() int {
	if r.full {
		return len(r.buf)
	}
	return r.next
}

// newestFirst обходит элементы от новых к старым, пока fn возвращает true.
func (r *ring[T]) newestFirst(fn func(T) bool) {
	n := r.len()
	for i := 1; i <= n; i++ {
		idx := (r.next - i + len(r.buf)) % len(r.buf)
		if !fn(r.buf[idx]) {
			return
		}
	}
}

type tenantData struct {
	samples *ring[Sample]
	logs    *ring[LogRecord]
	events  *ring[Event]
}

// MemoryStore — in-memory реализация Sink и Query (dev/test и небольшие инсталляции без VictoriaMetrics/Loki).
// Данные каждого tenant лежат в отдельных кольцевых буферах; запросы без tenant_id отклоняются.
type MemoryStore struct {
	mu        sync.RWMutex
	tenants   map[string]*tenantData
	limits    Limits
	retention Retention
	now       func() time.Time
}

var (
	_ Sink  = (*MemoryStore)(nil)
	_ Query = (*MemoryStore)(nil)
)

// NewMemoryStore создаёт хранилище. Нулевые limits/retention — значения по умолчанию.
func NewMemoryStore(l Limits, r Retention) *MemoryStore {
	d := DefaultLimits()
	if l.Samples <= 0 {
		l.Samples = d.Samples
	}
	if l.Logs <= 0 {
		l.Logs = d.Logs
	}
	if l.Events <= 0 {
		l.Events = d.Events
	}
	return &MemoryStore{tenants: map[string]*tenantData{}, limits: l, retention: r.withDefaults(), now: time.Now}
}

// SetClock подменяет часы (тесты).
func (m *MemoryStore) SetClock(now func() time.Time) { m.now = now }

// Retention — действующие сроки хранения.
func (m *MemoryStore) Retention() Retention { return m.retention }

func (m *MemoryStore) tenant(id string) *tenantData {
	t, ok := m.tenants[id]
	if !ok {
		t = &tenantData{samples: newRing[Sample](m.limits.Samples), logs: newRing[LogRecord](m.limits.Logs), events: newRing[Event](m.limits.Events)}
		m.tenants[id] = t
	}
	return t
}

func requireTenant(id string) error {
	if id == "" {
		return fmt.Errorf("telemetry: tenant_id is required")
	}
	return nil
}

// WriteSamples сохраняет точки метрик.
func (m *MemoryStore) WriteSamples(_ context.Context, ss []Sample) error {
	for _, s := range ss {
		if err := requireTenant(s.TenantID); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range ss {
		s.Labels = copyLabels(s.Labels)
		m.tenant(s.TenantID).samples.push(s)
	}
	return nil
}

// WriteLogs сохраняет записи журналов.
func (m *MemoryStore) WriteLogs(_ context.Context, ls []LogRecord) error {
	for _, l := range ls {
		if err := requireTenant(l.TenantID); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range ls {
		l.Labels = copyLabels(l.Labels)
		m.tenant(l.TenantID).logs.push(l)
	}
	return nil
}

// WriteEvents сохраняет события. ID обязателен (его назначает Service).
func (m *MemoryStore) WriteEvents(_ context.Context, es []Event) error {
	for _, e := range es {
		if err := requireTenant(e.TenantID); err != nil {
			return err
		}
		if e.ID == "" {
			return fmt.Errorf("telemetry: event id is required")
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range es {
		e.Labels = copyLabels(e.Labels)
		m.tenant(e.TenantID).events.push(e)
	}
	return nil
}

// QueryMetric возвращает ряды метрики актива за окно с шагом step (последнее значение в шаге).
func (m *MemoryStore) QueryMetric(_ context.Context, q MetricQuery) ([]Series, error) {
	if err := requireTenant(q.TenantID); err != nil {
		return nil, err
	}
	window, step := clampWindow(q.Window, m.retention.MetricsRaw), q.Step
	if step <= 0 {
		step = time.Minute
	}
	if step < time.Second {
		step = time.Second
	}
	now := m.now()
	from := now.Add(-window)
	type bucket struct {
		at time.Time
		v  float64
	}
	series := map[string]map[int64]bucket{}
	labels := map[string]map[string]string{}
	m.mu.RLock()
	if t, ok := m.tenants[q.TenantID]; ok {
		t.samples.newestFirst(func(s Sample) bool {
			if s.AssetID != q.AssetID || s.Metric != q.Metric || s.At.Before(from) || s.At.After(now) {
				return true
			}
			key := labelKey(s.Labels)
			if series[key] == nil {
				series[key] = map[int64]bucket{}
				labels[key] = copyLabels(s.Labels)
			}
			// Конец шага, в который попадает точка.
			slot := s.At.Unix() / int64(step/time.Second)
			if b, ok := series[key][slot]; !ok || s.At.After(b.at) {
				series[key][slot] = bucket{s.At, s.Value}
			}
			return true
		})
	}
	m.mu.RUnlock()
	keys := make([]string, 0, len(series))
	for k := range series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Series, 0, len(keys))
	stepSec := int64(step / time.Second)
	for _, k := range keys {
		slots := make([]int64, 0, len(series[k]))
		for s := range series[k] {
			slots = append(slots, s)
		}
		sort.Slice(slots, func(i, j int) bool { return slots[i] < slots[j] })
		pts := make([][2]float64, 0, len(slots))
		for _, s := range slots {
			pts = append(pts, [2]float64{float64((s + 1) * stepSec), series[k][s].v})
		}
		l := labels[k]
		if l == nil {
			l = map[string]string{}
		}
		out = append(out, Series{Labels: l, Points: pts})
	}
	return out, nil
}

// SearchLogs ищет записи журналов (подстрока без учёта регистра), от новых к старым.
func (m *MemoryStore) SearchLogs(_ context.Context, q LogQuery) ([]LogRecord, error) {
	if err := requireTenant(q.TenantID); err != nil {
		return nil, err
	}
	limit := q.Limit
	if limit <= 0 || limit > 5000 {
		limit = 100
	}
	now := m.now()
	from := now.Add(-clampWindow(q.Window, m.retention.Syslog))
	needle := strings.ToLower(q.Contains)
	var out []LogRecord
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tenants[q.TenantID]
	if !ok {
		return nil, nil
	}
	t.logs.newestFirst(func(l LogRecord) bool {
		if l.At.Before(from) || l.At.Before(now.Add(-m.logRetention(l))) {
			return true
		}
		if q.AssetID != "" && l.AssetID != q.AssetID {
			return true
		}
		if q.MinSev != "" && !l.Severity.AtLeast(q.MinSev) {
			return true
		}
		if needle != "" && !strings.Contains(strings.ToLower(l.Message), needle) {
			return true
		}
		l.Labels = copyLabels(l.Labels)
		out = append(out, l)
		return len(out) < limit
	})
	return out, nil
}

func (m *MemoryStore) logRetention(l LogRecord) time.Duration {
	if l.Source == "syslog" {
		return m.retention.Syslog
	}
	return m.retention.Logs
}

// ListEvents — события tenant от новых к старым.
func (m *MemoryStore) ListEvents(_ context.Context, q EventQuery) ([]Event, error) {
	if err := requireTenant(q.TenantID); err != nil {
		return nil, err
	}
	limit := q.Limit
	if limit <= 0 || limit > 5000 {
		limit = 100
	}
	now := m.now()
	from := now.Add(-clampWindow(q.Window, m.retention.Events))
	var out []Event
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tenants[q.TenantID]
	if !ok {
		return nil, nil
	}
	t.events.newestFirst(func(e Event) bool {
		if e.At.Before(from) {
			return true
		}
		if q.AssetID != "" && e.AssetID != q.AssetID {
			return true
		}
		e.Labels = copyLabels(e.Labels)
		out = append(out, e)
		return len(out) < limit
	})
	return out, nil
}

// clampWindow ограничивает окно сроком хранения; нулевое окно — 15 минут.
func clampWindow(w, max time.Duration) time.Duration {
	if w <= 0 {
		w = 15 * time.Minute
	}
	if w > max {
		w = max
	}
	return w
}

func labelKey(l map[string]string) string {
	if len(l) == 0 {
		return ""
	}
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte(0)
		b.WriteString(l[k])
		b.WriteByte(0)
	}
	return b.String()
}

// Composite объединяет раздельные хранилища: метрики (VictoriaMetrics), журналы (Loki), события (PostgreSQL/память).
type Composite struct {
	Metrics MetricStore
	Logs    LogStore
	Events  EventStore
}

// MetricStore — хранилище метрик.
type MetricStore interface {
	WriteSamples(ctx context.Context, s []Sample) error
	QueryMetric(ctx context.Context, q MetricQuery) ([]Series, error)
}

// LogStore — хранилище журналов.
type LogStore interface {
	WriteLogs(ctx context.Context, l []LogRecord) error
	SearchLogs(ctx context.Context, q LogQuery) ([]LogRecord, error)
}

// EventStore — хранилище событий.
type EventStore interface {
	WriteEvents(ctx context.Context, e []Event) error
	ListEvents(ctx context.Context, q EventQuery) ([]Event, error)
}

// Store — Sink и Query вместе.
type Store interface {
	Sink
	Query
}

var _ Store = Composite{}

// WriteSamples реализует Sink.
func (c Composite) WriteSamples(ctx context.Context, s []Sample) error {
	return c.Metrics.WriteSamples(ctx, s)
}

// WriteLogs реализует Sink.
func (c Composite) WriteLogs(ctx context.Context, l []LogRecord) error {
	return c.Logs.WriteLogs(ctx, l)
}

// WriteEvents реализует Sink.
func (c Composite) WriteEvents(ctx context.Context, e []Event) error {
	return c.Events.WriteEvents(ctx, e)
}

// QueryMetric реализует Query.
func (c Composite) QueryMetric(ctx context.Context, q MetricQuery) ([]Series, error) {
	return c.Metrics.QueryMetric(ctx, q)
}

// SearchLogs реализует Query.
func (c Composite) SearchLogs(ctx context.Context, q LogQuery) ([]LogRecord, error) {
	return c.Logs.SearchLogs(ctx, q)
}

// ListEvents реализует Query.
func (c Composite) ListEvents(ctx context.Context, q EventQuery) ([]Event, error) {
	return c.Events.ListEvents(ctx, q)
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
