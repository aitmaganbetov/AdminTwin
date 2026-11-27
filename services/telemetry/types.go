// Package telemetry — контракт приёма и запроса телеметрии (M05, §9): метрики, журналы, события.
// Сборщики (connectors/*) пишут через Sink; RCA и read tools читают через Query.
// Реализации: in-memory (dev/test) и VictoriaMetrics/Loki (production, ADR-001/002).
package telemetry

import (
	"context"
	"time"
)

// Sample — точка метрики. Labels обязаны содержать tenant_id (multi-tenant хранение, §3.5).
type Sample struct {
	TenantID string            `json:"tenant_id"`
	AssetID  string            `json:"asset_id"`
	Metric   string            `json:"metric"` // node_cpu_usage_percent, node_disk_used_percent, container_up, http_5xx_rate ...
	Labels   map[string]string `json:"labels,omitempty"`
	Value    float64           `json:"value"`
	At       time.Time         `json:"at"`
}

// Severity — уровень события/алерта (§9).
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// LogRecord — строка журнала (системный, приложение, syslog). Message — недоверенные данные.
type LogRecord struct {
	TenantID string            `json:"tenant_id"`
	AssetID  string            `json:"asset_id,omitempty"` // пусто, если источник не сопоставлен с CMDB
	Source   string            `json:"source"`             // syslog | journald | docker | app
	Host     string            `json:"host,omitempty"`
	App      string            `json:"app,omitempty"`
	Severity Severity          `json:"severity"`
	Message  string            `json:"message"`
	Labels   map[string]string `json:"labels,omitempty"`
	At       time.Time         `json:"at"`
}

// Event — нормализованное событие/алерт (порог метрики, health-check, syslog-паттерн, внешний SIEM).
type Event struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	AssetID     string            `json:"asset_id,omitempty"`
	ServiceID   string            `json:"service_id,omitempty"`
	Kind        string            `json:"kind"` // http_5xx | disk_usage | container_down | service_down | db_connections | ...
	Severity    Severity          `json:"severity"`
	Title       string            `json:"title"`
	Fingerprint string            `json:"fingerprint"` // ключ дедупликации
	Labels      map[string]string `json:"labels,omitempty"`
	Value       float64           `json:"value,omitempty"`
	At          time.Time         `json:"at"`
}

// Sink — приём телеметрии от сборщиков.
type Sink interface {
	WriteSamples(ctx context.Context, s []Sample) error
	WriteLogs(ctx context.Context, l []LogRecord) error
	WriteEvents(ctx context.Context, e []Event) error
}

// MetricQuery — запрос метрики актива за окно.
type MetricQuery struct {
	TenantID string
	AssetID  string
	Metric   string
	Window   time.Duration
	Step     time.Duration
}

// Series — временной ряд.
type Series struct {
	Labels map[string]string `json:"labels"`
	Points [][2]float64      `json:"points"` // [unix_seconds, value]
}

// LogQuery — поиск по журналам.
type LogQuery struct {
	TenantID string
	AssetID  string
	Contains string
	MinSev   Severity
	Window   time.Duration
	Limit    int
}

// EventQuery — выборка событий.
type EventQuery struct {
	TenantID string
	AssetID  string
	Window   time.Duration
	Limit    int
}

// Query — чтение телеметрии (tenant-scoped).
type Query interface {
	QueryMetric(ctx context.Context, q MetricQuery) ([]Series, error)
	SearchLogs(ctx context.Context, q LogQuery) ([]LogRecord, error)
	ListEvents(ctx context.Context, q EventQuery) ([]Event, error)
}
