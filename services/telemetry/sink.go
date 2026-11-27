package telemetry

import (
	"context"
	"fmt"
	"time"
)

// AsSink — telemetry.Sink поверх конвейера для сборщиков внутри процесса (connectors/*): записи
// группируются по TenantID (обязателен) и проходят ту же валидацию, правила и корреляцию, что и HTTP ingest.
func (s *Service) AsSink() Sink { return pipelineSink{s} }

type pipelineSink struct{ s *Service }

func groupByTenant[T any](in []T, tenant func(T) string) (map[string][]T, []string, error) {
	out := map[string][]T{}
	var order []string
	for _, v := range in {
		t := tenant(v)
		if t == "" {
			return nil, nil, fmt.Errorf("telemetry: record without tenant_id")
		}
		if _, ok := out[t]; !ok {
			order = append(order, t)
		}
		out[t] = append(out[t], v)
	}
	return out, order, nil
}

func (p pipelineSink) WriteSamples(ctx context.Context, in []Sample) error {
	g, order, err := groupByTenant(in, func(x Sample) string { return x.TenantID })
	if err != nil {
		return err
	}
	for _, t := range order {
		if _, _, err := p.s.IngestSamples(ctx, t, g[t]); err != nil {
			return err
		}
	}
	return nil
}

func (p pipelineSink) WriteLogs(ctx context.Context, in []LogRecord) error {
	g, order, err := groupByTenant(in, func(x LogRecord) string { return x.TenantID })
	if err != nil {
		return err
	}
	for _, t := range order {
		if _, _, err := p.s.IngestLogs(ctx, t, g[t]); err != nil {
			return err
		}
	}
	return nil
}

func (p pipelineSink) WriteEvents(ctx context.Context, in []Event) error {
	g, order, err := groupByTenant(in, func(x Event) string { return x.TenantID })
	if err != nil {
		return err
	}
	for _, t := range order {
		if _, _, err := p.s.IngestEvents(ctx, t, g[t]); err != nil {
			return err
		}
	}
	return nil
}

// RetentionFromEnv читает сроки хранения горячего слоя из переменных окружения (формат окна: 15d, 720h):
// ADMINTWIN_RETENTION_METRICS_RAW, ADMINTWIN_RETENTION_LOGS, ADMINTWIN_RETENTION_SYSLOG, ADMINTWIN_RETENTION_EVENTS.
// Пустые значения — умолчания §9.1. «Бессрочно» не допускается: значение обязано быть конечным окном.
func RetentionFromEnv(getenv func(string) string) (Retention, error) {
	r := DefaultRetention()
	for _, it := range []struct {
		key string
		dst *time.Duration
	}{
		{"ADMINTWIN_RETENTION_METRICS_RAW", &r.MetricsRaw}, {"ADMINTWIN_RETENTION_LOGS", &r.Logs},
		{"ADMINTWIN_RETENTION_SYSLOG", &r.Syslog}, {"ADMINTWIN_RETENTION_EVENTS", &r.Events},
	} {
		v := getenv(it.key)
		if v == "" {
			continue
		}
		d, err := ParseWindow(v)
		if err != nil {
			return Retention{}, fmt.Errorf("%s: %w", it.key, err)
		}
		*it.dst = d
	}
	return r, nil
}
