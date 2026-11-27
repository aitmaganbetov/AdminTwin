package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	tA = "11111111-1111-4111-8111-111111111111"
	tB = "22222222-2222-4222-8222-222222222222"
)

func TestVictoriaMetricsWriteAndQuery(t *testing.T) {
	var mu sync.Mutex
	var imported string
	var gotQuery, gotExtra string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/import/prometheus":
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			imported += string(b)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/query_range":
			gotQuery, gotExtra = r.URL.Query().Get("query"), r.URL.Query().Get("extra_label")
			// Хранилище «ошибочно» вернуло и ряд другого tenant — адаптер обязан его отбросить.
			_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"matrix","result":[
				{"metric":{"__name__":"node_disk_used_percent","tenant_id":"`+tA+`","asset_id":"a1","mount":"/var"},"values":[[1700000000,"91.5"],[1700000060,"92"]]},
				{"metric":{"__name__":"node_disk_used_percent","tenant_id":"`+tB+`","asset_id":"a1","mount":"/"},"values":[[1700000000,"10"]]}]}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	vm := &VictoriaMetrics{URL: srv.URL, Now: func() time.Time { return time.Unix(1700000100, 0) }}
	ctx := context.Background()
	at := time.Unix(1700000000, 0)
	err := vm.WriteSamples(ctx, []Sample{
		{TenantID: tA, AssetID: "a1", Metric: "node_disk_used_percent", Labels: map[string]string{"mount": `/v"a\r` + "\n" + `x`, "tenant_id": tB}, Value: 91.5, At: at},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `node_disk_used_percent{tenant_id="` + tA + `",asset_id="a1",mount="/v\"a\\r\nx"} 91.5 1700000000000` + "\n"
	if imported != want {
		t.Fatalf("exposition line:\n got %q\nwant %q", imported, want)
	}
	if strings.Contains(imported, tB) {
		t.Fatal("tenant_id from sample labels must not override the tenant label")
	}
	// Без tenant запись отклоняется; недопустимое имя метрики — тоже.
	if err := vm.WriteSamples(ctx, []Sample{{Metric: "x", Value: 1}}); err == nil {
		t.Fatal("sample without tenant must be rejected")
	}
	if err := vm.WriteSamples(ctx, []Sample{{TenantID: tA, Metric: `x{a="b"}`, Value: 1}}); err == nil {
		t.Fatal("invalid metric name must be rejected")
	}

	// Попытка инъекции через asset_id экранируется в строковом литерале PromQL.
	evil := `a1"} or vector(1) or up{tenant_id="` + tB
	series, err := vm.QueryMetric(ctx, MetricQuery{TenantID: tA, AssetID: evil, Metric: "node_disk_used_percent", Window: 15 * time.Minute, Step: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	wantQ := `node_disk_used_percent{tenant_id="` + tA + `",asset_id="a1\"} or vector(1) or up{tenant_id=\"` + tB + `"}`
	if gotQuery != wantQ {
		t.Fatalf("query:\n got %s\nwant %s", gotQuery, wantQ)
	}
	if gotExtra != "tenant_id="+tA {
		t.Fatalf("extra_label must enforce tenant: %q", gotExtra)
	}
	if len(series) != 1 || series[0].Labels["mount"] != "/var" || len(series[0].Points) != 2 || series[0].Points[1][1] != 92 {
		t.Fatalf("series: %+v", series)
	}
	if _, ok := series[0].Labels["tenant_id"]; ok {
		t.Fatal("tenant label must not leak into result labels")
	}
	if _, err := vm.QueryMetric(ctx, MetricQuery{AssetID: "a1", Metric: "up"}); err == nil {
		t.Fatal("query without tenant must be rejected")
	}
	if _, err := vm.QueryMetric(ctx, MetricQuery{TenantID: tA, Metric: `up or vector(1)`}); err == nil {
		t.Fatal("metric name injection must be rejected")
	}
}

func TestLokiPushAndQuery(t *testing.T) {
	var pushes []struct {
		org  string
		body map[string]any
	}
	var gotQuery, gotOrg string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/loki/api/v1/push":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			pushes = append(pushes, struct {
				org  string
				body map[string]any
			}{r.Header.Get("X-Scope-OrgID"), body})
			w.WriteHeader(http.StatusNoContent)
		case "/loki/api/v1/query_range":
			gotQuery, gotOrg = r.URL.Query().Get("query"), r.Header.Get("X-Scope-OrgID")
			_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"streams","result":[
				{"stream":{"tenant_id":"`+tA+`","asset_id":"a1","source":"syslog","severity":"high"},"values":[["1700000000000000000","upstream timed out"]]},
				{"stream":{"tenant_id":"`+tB+`","asset_id":"b1","source":"syslog","severity":"high"},"values":[["1700000000000000000","secret of B"]]}]}}`)
		}
	}))
	defer srv.Close()
	l := &Loki{URL: srv.URL, Now: func() time.Time { return time.Unix(1700000100, 0) }}
	ctx := context.Background()
	err := l.WriteLogs(ctx, []LogRecord{
		{TenantID: tA, AssetID: "a1", Source: "syslog", Host: "spoofed-host", App: "nginx", Severity: SevHigh, Message: "line A", At: time.Unix(1700000000, 0)},
		{TenantID: tB, AssetID: "b1", Source: "syslog", Severity: SevInfo, Message: "line B", At: time.Unix(1700000000, 0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pushes) != 2 || pushes[0].org != tA || pushes[1].org != tB {
		t.Fatalf("each tenant must be pushed separately with its X-Scope-OrgID: %+v", pushes)
	}
	raw, _ := json.Marshal(pushes[0].body)
	if strings.Contains(string(raw), "line B") || strings.Contains(string(raw), "spoofed-host") {
		t.Fatalf("push of tenant A leaked data or used untrusted hostname as label: %s", raw)
	}
	if !strings.Contains(string(raw), `"tenant_id":"`+tA+`"`) {
		t.Fatalf("stream must carry tenant label: %s", raw)
	}

	recs, err := l.SearchLogs(ctx, LogQuery{TenantID: tA, AssetID: "a1", Contains: `x"} |= "" or {tenant_id=~".+`, MinSev: SevHigh, Window: time.Hour, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	wantQ := `{tenant_id="` + tA + `",asset_id="a1",severity=~"critical|high"} |~ "(?i)x\"\\} \\|= \"\" or \\{tenant_id=~\"\\.\\+"`
	if gotQuery != wantQ {
		t.Fatalf("logql:\n got %s\nwant %s", gotQuery, wantQ)
	}
	if gotOrg != tA {
		t.Fatalf("query must carry X-Scope-OrgID of the tenant, got %q", gotOrg)
	}
	if len(recs) != 1 || recs[0].Message != "upstream timed out" || recs[0].TenantID != tA {
		t.Fatalf("records: %+v", recs)
	}
	if _, err := LogQL(LogQuery{}); err == nil {
		t.Fatal("LogQL without tenant must fail")
	}
}

func TestMemoryStoreRingAndRetention(t *testing.T) {
	m := NewMemoryStore(Limits{Samples: 3, Logs: 2, Events: 2}, Retention{})
	now := time.Now()
	m.SetClock(func() time.Time { return now })
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_ = m.WriteSamples(ctx, []Sample{{TenantID: tA, AssetID: "a", Metric: "m", Value: float64(i), At: now.Add(time.Duration(i-5) * time.Minute)}})
	}
	_ = m.WriteSamples(ctx, []Sample{{TenantID: tB, AssetID: "a", Metric: "m", Value: 100, At: now}})
	s, _ := m.QueryMetric(ctx, MetricQuery{TenantID: tA, AssetID: "a", Metric: "m", Window: time.Hour, Step: time.Minute})
	if len(s) != 1 || len(s[0].Points) != 3 || s[0].Points[0][1] != 2 {
		t.Fatalf("ring buffer must keep the newest 3 samples: %+v", s)
	}
	for _, p := range s[0].Points {
		if p[1] == 100 {
			t.Fatal("cross-tenant sample leaked")
		}
	}
	if _, err := m.QueryMetric(ctx, MetricQuery{AssetID: "a", Metric: "m"}); err == nil {
		t.Fatal("query without tenant must fail")
	}
	// Ретенция: журнал старше 14 дн не возвращается, syslog — до 30 дн.
	_ = m.WriteLogs(ctx, []LogRecord{
		{TenantID: tA, Source: "app", Message: "old app", At: now.Add(-20 * Day)},
		{TenantID: tA, Source: "syslog", Message: "old syslog", At: now.Add(-20 * Day)},
	})
	logs, _ := m.SearchLogs(ctx, LogQuery{TenantID: tA, Window: 30 * Day})
	if len(logs) != 1 || logs[0].Message != "old syslog" {
		t.Fatalf("retention: %+v", logs)
	}
	if r := DefaultRetention(); r.MetricsRaw != 15*Day || r.Events != 395*Day {
		t.Fatalf("defaults must follow §9.1: %+v", r)
	}
}

func TestParseWindow(t *testing.T) {
	for in, want := range map[string]time.Duration{"15m": 15 * time.Minute, "1h": time.Hour, "7d": 7 * Day, "30s": 30 * time.Second} {
		if got, err := ParseWindow(in); err != nil || got != want {
			t.Fatalf("%s: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "0m", "15", "1w", "-1h", "99999m"} {
		if _, err := ParseWindow(in); err == nil {
			t.Fatalf("%q must be rejected", in)
		}
	}
}
