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

// Loki — адаптер хранилища журналов (ADR-002).
// Запись: POST /loki/api/v1/push; поток помечается tenant_id, запрос несёт X-Scope-OrgID = tenant
// (мульти-tenant режим Loki). Чтение: GET /loki/api/v1/query_range с LogQL, где tenant-селектор
// формирует ядро; пользовательская подстрока экранируется (regexp.QuoteMeta + строковый литерал).
type Loki struct {
	URL    string // например, http://loki:3100
	Client *http.Client
	// OrgHeader — отправлять X-Scope-OrgID (по умолчанию да; выключать только для single-tenant Loki).
	DisableOrgHeader bool
	Now              func() time.Time
}

var _ LogStore = (*Loki)(nil)

func (l *Loki) client() *http.Client {
	if l.Client != nil {
		return l.Client
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (l *Loki) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

var appLabelRe = regexp.MustCompile(`[^A-Za-z0-9_.-]`)

// streamLabels — метки потока. Hostname из сообщения (недоверенный) в метки не попадает.
func streamLabels(r LogRecord) map[string]string {
	m := map[string]string{TenantLabel: r.TenantID, "source": r.Source, "severity": string(r.Severity)}
	if r.AssetID != "" {
		m[AssetLabel] = r.AssetID
	}
	if r.App != "" {
		app := appLabelRe.ReplaceAllString(r.App, "_")
		if len(app) > 64 {
			app = app[:64]
		}
		m["app"] = app
	}
	return m
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

// WriteLogs отправляет записи; каждый tenant — отдельный запрос со своим X-Scope-OrgID.
func (l *Loki) WriteLogs(ctx context.Context, ls []LogRecord) error {
	byTenant := map[string]map[string]*lokiStream{}
	var order []string
	for _, r := range ls {
		if r.TenantID == "" {
			return fmt.Errorf("loki: log record without tenant_id")
		}
		sl := streamLabels(r)
		key := labelKey(sl)
		if byTenant[r.TenantID] == nil {
			byTenant[r.TenantID] = map[string]*lokiStream{}
			order = append(order, r.TenantID)
		}
		st := byTenant[r.TenantID][key]
		if st == nil {
			st = &lokiStream{Stream: sl}
			byTenant[r.TenantID][key] = st
		}
		at := r.At
		if at.IsZero() {
			at = l.now()
		}
		st.Values = append(st.Values, [2]string{strconv.FormatInt(at.UnixNano(), 10), r.Message})
	}
	for _, tid := range order {
		keys := make([]string, 0, len(byTenant[tid]))
		for k := range byTenant[tid] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		payload := struct {
			Streams []*lokiStream `json:"streams"`
		}{}
		for _, k := range keys {
			payload.Streams = append(payload.Streams, byTenant[tid][k])
		}
		body, _ := json.Marshal(payload)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(l.URL, "/")+"/loki/api/v1/push", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if !l.DisableOrgHeader {
			req.Header.Set("X-Scope-OrgID", tid)
		}
		res, err := l.client().Do(req)
		if err != nil {
			return fmt.Errorf("loki push: %w", err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
		res.Body.Close()
		if res.StatusCode/100 != 2 {
			return fmt.Errorf("loki push: status %d", res.StatusCode)
		}
	}
	return nil
}

// LogQL строит запрос: селектор с tenant_id (и опционально asset_id, severity), фильтр подстроки
// без учёта регистра. Все значения — строковые литералы с экранированием; подстрока — regexp.QuoteMeta.
func LogQL(q LogQuery) (string, error) {
	if q.TenantID == "" {
		return "", fmt.Errorf("loki: tenant_id is required")
	}
	sel := []string{TenantLabel + "=" + strconv.Quote(q.TenantID)}
	if q.AssetID != "" {
		sel = append(sel, AssetLabel+"="+strconv.Quote(q.AssetID))
	}
	if q.MinSev != "" {
		if !q.MinSev.Valid() {
			return "", fmt.Errorf("loki: invalid severity %q", q.MinSev)
		}
		var allowed []string
		for _, s := range []Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo} {
			if s.AtLeast(q.MinSev) {
				allowed = append(allowed, string(s))
			}
		}
		sel = append(sel, "severity=~"+strconv.Quote(strings.Join(allowed, "|")))
	}
	out := "{" + strings.Join(sel, ",") + "}"
	if q.Contains != "" {
		out += " |~ " + strconv.Quote("(?i)"+regexp.QuoteMeta(q.Contains))
	}
	return out, nil
}

type lokiResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string       `json:"resultType"`
		Result     []lokiStream `json:"result"`
	} `json:"data"`
}

// SearchLogs выполняет query_range (direction=backward). Потоки с чужим tenant_id отбрасываются.
func (l *Loki) SearchLogs(ctx context.Context, q LogQuery) ([]LogRecord, error) {
	expr, err := LogQL(q)
	if err != nil {
		return nil, err
	}
	window := q.Window
	if window <= 0 {
		window = 15 * time.Minute
	}
	limit := q.Limit
	if limit <= 0 || limit > 5000 {
		limit = 100
	}
	end := l.now()
	params := url.Values{}
	params.Set("query", expr)
	params.Set("start", strconv.FormatInt(end.Add(-window).UnixNano(), 10))
	params.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	params.Set("limit", strconv.Itoa(limit))
	params.Set("direction", "backward")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(l.URL, "/")+"/loki/api/v1/query_range?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if !l.DisableOrgHeader {
		req.Header.Set("X-Scope-OrgID", q.TenantID)
	}
	res, err := l.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("loki query: %w", err)
	}
	defer res.Body.Close()
	var lr lokiResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, 32<<20)).Decode(&lr); err != nil {
		return nil, fmt.Errorf("loki query: decode: %w", err)
	}
	if res.StatusCode != http.StatusOK || lr.Status != "success" {
		return nil, fmt.Errorf("loki query: status %d", res.StatusCode)
	}
	var out []LogRecord
	for _, st := range lr.Data.Result {
		if st.Stream[TenantLabel] != q.TenantID {
			continue
		}
		for _, v := range st.Values {
			ns, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				continue
			}
			out = append(out, LogRecord{
				TenantID: q.TenantID, AssetID: st.Stream[AssetLabel], Source: st.Stream["source"], App: st.Stream["app"],
				Severity: Severity(st.Stream["severity"]), Message: v[1], At: time.Unix(0, ns).UTC(),
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
