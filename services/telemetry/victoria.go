package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// TenantLabel — обязательная метка tenant во внешних хранилищах телеметрии (§3.5).
const TenantLabel = "tenant_id"

// AssetLabel — метка актива.
const AssetLabel = "asset_id"

var (
	metricNameRe = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]{0,199}$`)
	labelNameRe  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,99}$`)
)

// reservedLabels — метки, которые нельзя задать из Sample.Labels (иначе подмена tenant/актива).
var reservedLabels = map[string]bool{TenantLabel: true, AssetLabel: true, "__name__": true}

// VictoriaMetrics — адаптер хранилища метрик (ADR-001).
// Запись: POST /api/v1/import/prometheus (текстовый формат, метка tenant_id в каждой строке).
// Чтение: GET /api/v1/query_range с PromQL-селектором, в котором tenant_id задаётся ядром,
// а не вызывающим, и дополнительно enforced через extra_label (VictoriaMetrics добавляет фильтр сам).
type VictoriaMetrics struct {
	URL    string // например, http://victoriametrics:8428
	Client *http.Client
	// Now — часы (тесты).
	Now func() time.Time
}

var _ MetricStore = (*VictoriaMetrics)(nil)

func (v *VictoriaMetrics) client() *http.Client {
	if v.Client != nil {
		return v.Client
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (v *VictoriaMetrics) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// escapeExposition экранирует значение метки для текстового формата Prometheus: \\, \", \n.
func escapeExposition(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// promQuote — строковый литерал PromQL (синтаксис строк Go; экранирует кавычки, \ и управляющие символы).
func promQuote(s string) string { return strconv.Quote(s) }

// ExpositionLine формирует строку импорта. Возвращает ошибку для недопустимых имён.
func ExpositionLine(s Sample) (string, error) {
	if s.TenantID == "" {
		return "", fmt.Errorf("victoriametrics: sample without tenant_id")
	}
	if !metricNameRe.MatchString(s.Metric) {
		return "", fmt.Errorf("victoriametrics: invalid metric name %q", s.Metric)
	}
	if !finite(s.Value) {
		return "", fmt.Errorf("victoriametrics: non-finite value for %s", s.Metric)
	}
	keys := make([]string, 0, len(s.Labels))
	for k := range s.Labels {
		if reservedLabels[k] {
			continue // tenant_id/asset_id задаёт только ядро
		}
		if !labelNameRe.MatchString(k) {
			return "", fmt.Errorf("victoriametrics: invalid label name %q", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(s.Metric)
	b.WriteString(`{` + TenantLabel + `="` + escapeExposition(s.TenantID) + `"`)
	if s.AssetID != "" {
		b.WriteString(`,` + AssetLabel + `="` + escapeExposition(s.AssetID) + `"`)
	}
	for _, k := range keys {
		b.WriteString(`,` + k + `="` + escapeExposition(s.Labels[k]) + `"`)
	}
	b.WriteString(`} `)
	b.WriteString(strconv.FormatFloat(s.Value, 'g', -1, 64))
	if !s.At.IsZero() {
		b.WriteString(" " + strconv.FormatInt(s.At.UnixMilli(), 10))
	}
	return b.String(), nil
}

// WriteSamples отправляет точки в /api/v1/import/prometheus.
func (v *VictoriaMetrics) WriteSamples(ctx context.Context, ss []Sample) error {
	if len(ss) == 0 {
		return nil
	}
	var body bytes.Buffer
	for _, s := range ss {
		line, err := ExpositionLine(s)
		if err != nil {
			return err
		}
		body.WriteString(line)
		body.WriteByte('\n')
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(v.URL, "/")+"/api/v1/import/prometheus", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/plain")
	res, err := v.client().Do(req)
	if err != nil {
		return fmt.Errorf("victoriametrics import: %w", err)
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("victoriametrics import: status %d", res.StatusCode)
	}
	return nil
}

// Selector строит PromQL-селектор с обязательным tenant_id. Значения экранируются; имя метрики проверяется.
func Selector(tenantID, assetID, metric string) (string, error) {
	if tenantID == "" {
		return "", fmt.Errorf("victoriametrics: tenant_id is required")
	}
	if !metricNameRe.MatchString(metric) {
		return "", fmt.Errorf("victoriametrics: invalid metric name %q", metric)
	}
	sel := metric + "{" + TenantLabel + "=" + promQuote(tenantID)
	if assetID != "" {
		sel += "," + AssetLabel + "=" + promQuote(assetID)
	}
	return sel + "}", nil
}

type promResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Values [][2]any          `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

// QueryMetric выполняет query_range. Ряды с чужим tenant_id (если хранилище их вернуло) отбрасываются.
func (v *VictoriaMetrics) QueryMetric(ctx context.Context, q MetricQuery) ([]Series, error) {
	sel, err := Selector(q.TenantID, q.AssetID, q.Metric)
	if err != nil {
		return nil, err
	}
	window, step := q.Window, q.Step
	if window <= 0 {
		window = 15 * time.Minute
	}
	if step < time.Second {
		step = time.Minute
	}
	end := v.now()
	params := url.Values{}
	params.Set("query", sel)
	params.Set("start", strconv.FormatInt(end.Add(-window).Unix(), 10))
	params.Set("end", strconv.FormatInt(end.Unix(), 10))
	params.Set("step", strconv.FormatInt(int64(step/time.Second), 10)+"s")
	// extra_label: VictoriaMetrics принудительно добавляет фильтр ко всем селекторам запроса.
	params.Set("extra_label", TenantLabel+"="+q.TenantID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(v.URL, "/")+"/api/v1/query_range?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	res, err := v.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("victoriametrics query: %w", err)
	}
	defer res.Body.Close()
	var pr promResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, 16<<20)).Decode(&pr); err != nil {
		return nil, fmt.Errorf("victoriametrics query: decode: %w", err)
	}
	if res.StatusCode != http.StatusOK || pr.Status != "success" {
		return nil, fmt.Errorf("victoriametrics query: status %d %s", res.StatusCode, pr.Error)
	}
	out := []Series{}
	for _, r := range pr.Data.Result {
		if r.Metric[TenantLabel] != q.TenantID {
			continue // защита в глубину: ряд другого tenant не отдаётся
		}
		labels := map[string]string{}
		for k, val := range r.Metric {
			if !reservedLabels[k] {
				labels[k] = val
			}
		}
		pts := make([][2]float64, 0, len(r.Values))
		for _, p := range r.Values {
			ts, ok := p[0].(float64)
			if !ok {
				continue
			}
			sv, ok := p[1].(string)
			if !ok {
				continue
			}
			val, err := strconv.ParseFloat(sv, 64)
			if err != nil {
				continue
			}
			pts = append(pts, [2]float64{ts, val})
		}
		out = append(out, Series{Labels: labels, Points: pts})
	}
	return out, nil
}
