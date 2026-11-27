package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/problem"
	toolsvc "github.com/aitmaganbetov/admintwin/services/tool-service"
)

// Ограничения из output_schema контрактов ai/tools/read/*.json.
const (
	toolMaxSeries    = 50
	toolMaxPoints    = 2000
	toolMaxLogLine   = 8192
	toolMaxLogBytes  = 60000 // запас до max_response_bytes=65536 logs.search
	toolMaxEvents    = 200
	toolMaxSummary   = 2000
	toolMaxEventType = 100
)

// RegisterTools подключает обработчики metrics.query, logs.search, events.list к Tool Service.
func (s *Service) RegisterTools(ts *toolsvc.Service) error {
	for name, h := range map[string]toolsvc.Handler{
		"metrics.query": s.toolMetrics,
		"logs.search":   s.toolLogs,
		"events.list":   s.toolEvents,
	} {
		if err := ts.Register(name, h); err != nil {
			return err
		}
	}
	return nil
}

func inputString(in map[string]any, k string) string {
	v, _ := in[k].(string)
	return v
}

func inputInt(in map[string]any, k string, def int) int {
	switch x := in[k].(type) {
	case float64:
		return int(x)
	case int:
		return x
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return int(n)
		}
	}
	return def
}

func (s *Service) toolMetrics(ctx context.Context, c toolsvc.Call) (toolsvc.Result, error) {
	if c.Asset == nil {
		return toolsvc.Result{}, problem.New(problem.NotFound, "asset not found")
	}
	wstr := inputString(c.Input, "window")
	window, err := ParseWindow(wstr)
	if err != nil {
		return toolsvc.Result{}, problem.New(problem.InvalidParams, "%v", err)
	}
	step := time.Minute
	if st := inputString(c.Input, "step"); st != "" {
		if step, err = ParseWindow(st); err != nil {
			return toolsvc.Result{}, problem.New(problem.InvalidParams, "%v", err)
		}
	}
	// Не больше toolMaxPoints точек на ряд: увеличиваем шаг.
	if min := window / toolMaxPoints; step < min {
		step = (min/time.Second + 1) * time.Second
	}
	metric := inputString(c.Input, "metric")
	series, err := s.Store.QueryMetric(ctx, MetricQuery{TenantID: c.TenantID, AssetID: c.Asset.ID, Metric: metric, Window: window, Step: step})
	if err != nil {
		return toolsvc.Result{}, err
	}
	if len(series) > toolMaxSeries {
		series = series[:toolMaxSeries]
	}
	outSeries := make([]map[string]any, 0, len(series))
	for _, sr := range series {
		pts := sr.Points
		if len(pts) > toolMaxPoints {
			pts = pts[len(pts)-toolMaxPoints:]
		}
		outPts := make([][]any, 0, len(pts))
		for _, p := range pts {
			var v any = p[1]
			if math.IsNaN(p[1]) || math.IsInf(p[1], 0) {
				v = nil
			}
			sec, frac := math.Modf(p[0])
			outPts = append(outPts, []any{time.Unix(int64(sec), int64(frac*1e9)).UTC().Format(time.RFC3339Nano), v})
		}
		labels := map[string]string{}
		for k, v := range sr.Labels {
			labels[k] = v
		}
		outSeries = append(outSeries, map[string]any{"labels": labels, "points": outPts})
	}
	return toolsvc.Result{Data: map[string]any{"asset_id": c.Asset.ID, "metric": metric, "window": wstr, "series": outSeries}}, nil
}

// toolLogs — строки журналов возвращаются как данные (без интерпретации); класс ответа не ниже confidential.
func (s *Service) toolLogs(ctx context.Context, c toolsvc.Call) (toolsvc.Result, error) {
	window, err := ParseWindow(inputString(c.Input, "window"))
	if err != nil {
		return toolsvc.Result{}, problem.New(problem.InvalidParams, "%v", err)
	}
	limit := inputInt(c.Input, "limit", 100)
	q := LogQuery{TenantID: c.TenantID, Contains: inputString(c.Input, "query"), Window: window, Limit: limit + 1}
	if c.Asset != nil {
		q.AssetID = c.Asset.ID
	}
	recs, err := s.Store.SearchLogs(ctx, q)
	if err != nil {
		return toolsvc.Result{}, err
	}
	truncated := len(recs) > limit
	if truncated {
		recs = recs[:limit]
	}
	entries := make([]map[string]any, 0, len(recs))
	size := 0
	for _, r := range recs {
		e := map[string]any{"ts": r.At.UTC().Format(time.RFC3339Nano), "line": Truncate(r.Message, toolMaxLogLine), "source": Truncate(r.Source, 200)}
		if IsUUID(r.AssetID) {
			e["asset_id"] = r.AssetID
		}
		b, _ := json.Marshal(e)
		if size+len(b) > toolMaxLogBytes {
			truncated = true
			break
		}
		size += len(b) + 1
		entries = append(entries, e)
	}
	return toolsvc.Result{Data: map[string]any{"entries": entries, "truncated": truncated}, DataClass: "confidential"}, nil
}

func (s *Service) toolEvents(ctx context.Context, c toolsvc.Call) (toolsvc.Result, error) {
	window, err := ParseWindow(inputString(c.Input, "window"))
	if err != nil {
		return toolsvc.Result{}, problem.New(problem.InvalidParams, "%v", err)
	}
	limit := inputInt(c.Input, "limit", 50)
	if limit > toolMaxEvents {
		limit = toolMaxEvents
	}
	minSev := Severity(inputString(c.Input, "severity"))
	q := EventQuery{TenantID: c.TenantID, Window: window, Limit: 5000}
	if c.Asset != nil {
		q.AssetID = c.Asset.ID
	}
	evs, err := s.Store.ListEvents(ctx, q)
	if err != nil {
		return toolsvc.Result{}, err
	}
	out := make([]map[string]any, 0, limit)
	for _, e := range evs {
		if minSev != "" && !e.Severity.AtLeast(minSev) {
			continue
		}
		if !IsUUID(e.ID) {
			continue
		}
		m := map[string]any{
			"id": e.ID, "ts": e.At.UTC().Format(time.RFC3339Nano), "type": Truncate(e.Kind, toolMaxEventType),
			"severity": string(e.Severity), "summary": Truncate(eventSummary(e), toolMaxSummary),
		}
		if IsUUID(e.AssetID) {
			m["asset_id"] = e.AssetID
		}
		out = append(out, m)
		if len(out) >= limit {
			break
		}
	}
	return toolsvc.Result{Data: map[string]any{"events": out}}, nil
}

func eventSummary(e Event) string {
	if e.Value != 0 {
		return fmt.Sprintf("%s (value=%g)", e.Title, e.Value)
	}
	return e.Title
}
