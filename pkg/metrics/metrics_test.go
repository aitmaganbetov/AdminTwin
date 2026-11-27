package metrics

import (
	"strings"
	"testing"
)

func TestExposition(t *testing.T) {
	r := New()
	r.Help("admintwin_http_requests_total", "HTTP requests")
	r.Inc("admintwin_http_requests_total", map[string]string{"route": "GET /api/v1/assets", "status": "200"}, 1)
	r.Inc("admintwin_http_requests_total", map[string]string{"route": "GET /api/v1/assets", "status": "200"}, 1)
	r.Observe("admintwin_http_request_duration_seconds", map[string]string{"route": "x"}, 0.3)
	r.GaugeFunc(func() []Gauge {
		return []Gauge{{Name: "admintwin_kill_switch_active", Labels: map[string]string{"scope": "platform"}, Value: 0}, {Name: "admintwin_up", Value: 100}}
	})
	var b strings.Builder
	r.Write(&b)
	out := b.String()
	for _, want := range []string{
		"# TYPE admintwin_http_requests_total counter",
		`admintwin_http_requests_total{route="GET /api/v1/assets",status="200"} 2`,
		`admintwin_http_request_duration_seconds_bucket{route="x",le="0.25"} 0`,
		`admintwin_http_request_duration_seconds_bucket{route="x",le="0.5"} 1`,
		`admintwin_http_request_duration_seconds_bucket{route="x",le="+Inf"} 1`,
		`admintwin_http_request_duration_seconds_count{route="x"} 1`,
		`admintwin_kill_switch_active{scope="platform"} 0`,
		"admintwin_up 100",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	r.Inc("m", map[string]string{"x": "a\"b\nc"}, 1)
	b.Reset()
	r.Write(&b)
	if !strings.Contains(b.String(), `m{x="a\"b\nc"} 1`) {
		t.Errorf("label escaping: %s", b.String())
	}
}
