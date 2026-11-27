package telemetry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/inventory"
)

// EventSubscriber получает нормализованные события (корреляция в инциденты, M06).
// Возвращает id инцидентов, созданных или дополненных событиями.
type EventSubscriber interface {
	HandleEvents(ctx context.Context, tenantID string, evs []Event) ([]string, error)
}

// Лимиты пакетов приёма.
const (
	MaxSamplesPerBatch = 5000
	MaxLogsPerBatch    = 1000
	MaxEventsPerBatch  = 500
	MaxLogMessage      = 8192
	maxLabels          = 20
	maxLabelValue      = 200
	maxFutureSkew      = 5 * time.Minute
)

var (
	kindRe      = regexp.MustCompile(`^[a-z][a-z0-9_]{1,63}$`)
	sourceRe    = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	assetIDRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	fingerRe    = regexp.MustCompile(`^[\x21-\x7e]{1,200}$`)
	allowedSrcs = map[string]bool{"syslog": true, "journald": true, "docker": true, "app": true, "nginx": true, "k8s": true}
)

// Stats — счётчики приёма (meta-monitoring, M24).
type Stats struct {
	Samples        uint64 `json:"samples"`
	Logs           uint64 `json:"logs"`
	Events         uint64 `json:"events"`
	RuleEvents     uint64 `json:"rule_events"`
	SubscriberErrs uint64 `json:"subscriber_errors"`
}

// Service — конвейер приёма телеметрии: валидация и привязка к tenant/активу → хранилище →
// пороговые и журнальные правила → события → подписчик (инциденты). Также публикует HTTP API и read tools.
type Service struct {
	Store      Store
	Inv        inventory.Repository
	Rules      *Rules
	Subscriber EventSubscriber
	// ServiceToken — если задан, запросы Actor-Kind service к ingest обязаны нести совпадающий
	// X-AdminTwin-Service-Token (защита в глубину поверх проверки в api-gateway).
	ServiceToken string

	now                                          func() time.Time
	nSamples, nLogs, nEvents, nRule, nSubscriber atomic.Uint64
}

// NewService собирает конвейер. store — MemoryStore или Composite (VictoriaMetrics + Loki + события).
func NewService(store Store, inv inventory.Repository) *Service {
	return &Service{Store: store, Inv: inv, Rules: NewRules(), now: time.Now}
}

// SetClock подменяет часы (тесты).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Stats — текущие счётчики.
func (s *Service) Stats() Stats {
	return Stats{Samples: s.nSamples.Load(), Logs: s.nLogs.Load(), Events: s.nEvents.Load(), RuleEvents: s.nRule.Load(), SubscriberErrs: s.nSubscriber.Load()}
}

func invalid(field, format string, args ...any) error {
	p := problem.New(problem.InvalidParams, "invalid telemetry batch")
	p.Errors = []problem.FieldError{{Field: field, Reason: fmt.Sprintf(format, args...)}}
	return p
}

func (s *Service) normTime(t time.Time) time.Time {
	now := s.now().UTC()
	if t.IsZero() || t.After(now.Add(maxFutureSkew)) {
		return now
	}
	return t.UTC()
}

func (s *Service) checkTenant(field, recTenant, tenantID string) error {
	if recTenant != "" && recTenant != tenantID {
		return invalid(field, "tenant_id does not match the authenticated tenant")
	}
	return nil
}

func (s *Service) checkAsset(field, tenantID, assetID string, required bool) error {
	if assetID == "" {
		if required {
			return invalid(field, "asset_id is required")
		}
		return nil
	}
	if !assetIDRe.MatchString(assetID) {
		return invalid(field, "invalid asset_id")
	}
	if s.Inv != nil {
		if _, ok := s.Inv.Get(tenantID, assetID); !ok {
			return invalid(field, "unknown asset")
		}
	}
	return nil
}

func cleanLabels(field string, in map[string]string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > maxLabels {
		return nil, invalid(field, "too many labels (max %d)", maxLabels)
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if reservedLabels[k] {
			continue
		}
		if !labelNameRe.MatchString(k) {
			return nil, invalid(field, "invalid label name %q", k)
		}
		out[k] = Truncate(v, maxLabelValue)
	}
	return out, nil
}

// IngestSamples принимает точки метрик tenant и применяет пороговые правила.
func (s *Service) IngestSamples(ctx context.Context, tenantID string, in []Sample) (int, []string, error) {
	if tenantID == "" {
		return 0, nil, problem.New(problem.Forbidden, "tenant is required")
	}
	if len(in) > MaxSamplesPerBatch {
		return 0, nil, invalid("samples", "batch too large (max %d)", MaxSamplesPerBatch)
	}
	out := make([]Sample, 0, len(in))
	for i, smp := range in {
		f := fmt.Sprintf("samples[%d]", i)
		if err := s.checkTenant(f, smp.TenantID, tenantID); err != nil {
			return 0, nil, err
		}
		if err := s.checkAsset(f, tenantID, smp.AssetID, true); err != nil {
			return 0, nil, err
		}
		if !metricNameRe.MatchString(smp.Metric) {
			return 0, nil, invalid(f, "invalid metric name")
		}
		if !finite(smp.Value) {
			return 0, nil, invalid(f, "value must be finite")
		}
		l, err := cleanLabels(f, smp.Labels)
		if err != nil {
			return 0, nil, err
		}
		out = append(out, Sample{TenantID: tenantID, AssetID: smp.AssetID, Metric: smp.Metric, Labels: l, Value: smp.Value, At: s.normTime(smp.At)})
	}
	if err := s.Store.WriteSamples(ctx, out); err != nil {
		return 0, nil, err
	}
	s.nSamples.Add(uint64(len(out)))
	var incidents []string
	if s.Rules != nil {
		evs := s.Rules.EvaluateSamples(out)
		s.nRule.Add(uint64(len(evs)))
		ids, err := s.emit(ctx, tenantID, evs)
		if err != nil {
			return 0, nil, err
		}
		incidents = ids
	}
	return len(out), incidents, nil
}

// IngestLogs принимает записи журналов. Message сохраняется как есть (недоверенные данные) с ограничением длины.
func (s *Service) IngestLogs(ctx context.Context, tenantID string, in []LogRecord) (int, []string, error) {
	if tenantID == "" {
		return 0, nil, problem.New(problem.Forbidden, "tenant is required")
	}
	if len(in) > MaxLogsPerBatch {
		return 0, nil, invalid("logs", "batch too large (max %d)", MaxLogsPerBatch)
	}
	out := make([]LogRecord, 0, len(in))
	for i, l := range in {
		f := fmt.Sprintf("logs[%d]", i)
		if err := s.checkTenant(f, l.TenantID, tenantID); err != nil {
			return 0, nil, err
		}
		if err := s.checkAsset(f, tenantID, l.AssetID, false); err != nil {
			return 0, nil, err
		}
		if l.Source == "" {
			l.Source = "app"
		}
		if !sourceRe.MatchString(l.Source) || !allowedSrcs[l.Source] {
			return 0, nil, invalid(f, "unknown source %q", Truncate(l.Source, 32))
		}
		if l.Severity == "" {
			l.Severity = SevInfo
		}
		if !l.Severity.Valid() {
			return 0, nil, invalid(f, "invalid severity")
		}
		lb, err := cleanLabels(f, l.Labels)
		if err != nil {
			return 0, nil, err
		}
		out = append(out, LogRecord{
			TenantID: tenantID, AssetID: l.AssetID, Source: l.Source, Host: Truncate(l.Host, 255), App: Truncate(l.App, 64),
			Severity: l.Severity, Message: Truncate(l.Message, MaxLogMessage), Labels: lb, At: s.normTime(l.At),
		})
	}
	if err := s.Store.WriteLogs(ctx, out); err != nil {
		return 0, nil, err
	}
	s.nLogs.Add(uint64(len(out)))
	var incidents []string
	if s.Rules != nil {
		evs := s.Rules.EvaluateLogs(out)
		s.nRule.Add(uint64(len(evs)))
		ids, err := s.emit(ctx, tenantID, evs)
		if err != nil {
			return 0, nil, err
		}
		incidents = ids
	}
	return len(out), incidents, nil
}

// IngestEvents принимает внешние события (сборщики, webhook). ID назначает ядро; внешний id — в labels.external_id.
func (s *Service) IngestEvents(ctx context.Context, tenantID string, in []Event) (int, []string, error) {
	if tenantID == "" {
		return 0, nil, problem.New(problem.Forbidden, "tenant is required")
	}
	if len(in) > MaxEventsPerBatch {
		return 0, nil, invalid("events", "batch too large (max %d)", MaxEventsPerBatch)
	}
	out := make([]Event, 0, len(in))
	for i, e := range in {
		f := fmt.Sprintf("events[%d]", i)
		if err := s.checkTenant(f, e.TenantID, tenantID); err != nil {
			return 0, nil, err
		}
		if err := s.checkAsset(f, tenantID, e.AssetID, false); err != nil {
			return 0, nil, err
		}
		if e.ServiceID != "" && !assetIDRe.MatchString(e.ServiceID) {
			return 0, nil, invalid(f, "invalid service_id")
		}
		if !kindRe.MatchString(e.Kind) {
			return 0, nil, invalid(f, "invalid kind")
		}
		if !e.Severity.Valid() {
			return 0, nil, invalid(f, "invalid severity")
		}
		if strings.TrimSpace(e.Title) == "" {
			return 0, nil, invalid(f, "title is required")
		}
		if e.Fingerprint != "" && !fingerRe.MatchString(e.Fingerprint) {
			return 0, nil, invalid(f, "invalid fingerprint")
		}
		if !finite(e.Value) {
			return 0, nil, invalid(f, "value must be finite")
		}
		lb, err := cleanLabels(f, e.Labels)
		if err != nil {
			return 0, nil, err
		}
		if e.ID != "" {
			if lb == nil {
				lb = map[string]string{}
			}
			lb["external_id"] = Truncate(e.ID, maxLabelValue)
		}
		out = append(out, Event{
			TenantID: tenantID, AssetID: e.AssetID, ServiceID: e.ServiceID, Kind: e.Kind, Severity: e.Severity,
			Title: Truncate(e.Title, 300), Fingerprint: e.Fingerprint, Labels: lb, Value: e.Value, At: s.normTime(e.At),
		})
	}
	ids, err := s.emit(ctx, tenantID, out)
	if err != nil {
		return 0, nil, err
	}
	return len(out), ids, nil
}

// emit назначает id и fingerprint, сохраняет события и передаёт подписчику.
func (s *Service) emit(ctx context.Context, tenantID string, evs []Event) ([]string, error) {
	if len(evs) == 0 {
		return nil, nil
	}
	for i := range evs {
		evs[i].ID = NewID()
		evs[i].TenantID = tenantID
		if evs[i].Fingerprint == "" {
			evs[i].Fingerprint = Fingerprint(evs[i])
		}
	}
	if err := s.Store.WriteEvents(ctx, evs); err != nil {
		return nil, err
	}
	s.nEvents.Add(uint64(len(evs)))
	if s.Subscriber == nil {
		return nil, nil
	}
	ids, err := s.Subscriber.HandleEvents(ctx, tenantID, evs)
	if err != nil {
		// События уже сохранены; ошибка корреляции не должна терять телеметрию и ломать приём.
		s.nSubscriber.Add(1)
		slog.Error("telemetry: event subscriber failed", "tenant_id", tenantID, "error", err)
		return nil, nil
	}
	return ids, nil
}

// Fingerprint — ключ дедупликации по умолчанию: kind, актив/сервис и отсортированные метки (кроме external_id).
func Fingerprint(e Event) string {
	keys := make([]string, 0, len(e.Labels))
	for k := range e.Labels {
		if k != "external_id" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s", e.Kind, e.AssetID, e.ServiceID)
	for _, k := range keys {
		fmt.Fprintf(h, "|%s=%s", k, e.Labels[k])
	}
	return e.Kind + ":" + hex.EncodeToString(h.Sum(nil))[:16]
}
