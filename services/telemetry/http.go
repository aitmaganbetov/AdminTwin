package telemetry

import (
	"crypto/subtle"
	"net/http"
	"strconv"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/httpapi"
	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
)

// Роли чтения телеметрии (§2.2 «Просмотр»). Журналы — confidential: без Viewer.
var (
	metricReaders = []identity.Role{identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleEngineer, identity.RoleOperator, identity.RoleViewer, identity.RoleAuditor}
	logReaders    = []identity.Role{identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleEngineer, identity.RoleOperator, identity.RoleAuditor}
)

// RequireServiceToken проверяет, что запрос от сервиса и (если token задан) несёт верный
// X-AdminTwin-Service-Token. Сравнение — constant-time.
func RequireServiceToken(r *http.Request, a identity.Actor, token string) error {
	if a.Kind != identity.KindService || a.IsAI() {
		return problem.New(problem.Forbidden, "this endpoint accepts only service identities")
	}
	if token != "" {
		got := r.Header.Get("X-AdminTwin-Service-Token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			return problem.New(problem.Forbidden, "invalid service token")
		}
	}
	return nil
}

func canRead(a identity.Actor, roles []identity.Role) error {
	if a.IsAI() {
		// Агенты читают телеметрию только через Tool Service (tool scope T-CAP-001, класс данных, аудит).
		return problem.New(problem.Forbidden, "AI agents read telemetry through the tool service")
	}
	if a.Kind != identity.KindUser {
		return problem.New(problem.Forbidden, "insufficient identity for telemetry read")
	}
	return httpapi.RequireAny(a, roles...)
}

// Routes публикует API телеметрии (контракты Этапа 1, §3).
func (s *Service) Routes(r *httpapi.Router) {
	r.Handle("POST /api/v1/telemetry/samples", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		if err := RequireServiceToken(req, a, s.ServiceToken); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		var body struct {
			Samples []Sample `json:"samples"`
		}
		if err := httpapi.Decode(req, &body); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		n, inc, err := s.IngestSamples(req.Context(), a.TenantID, body.Samples)
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusAccepted, map[string]any{"accepted": n, "incidents": nonNil(inc)})
	})
	r.Handle("POST /api/v1/telemetry/logs", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		if err := RequireServiceToken(req, a, s.ServiceToken); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		var body struct {
			Logs []LogRecord `json:"logs"`
		}
		if err := httpapi.Decode(req, &body); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		n, inc, err := s.IngestLogs(req.Context(), a.TenantID, body.Logs)
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusAccepted, map[string]any{"accepted": n, "incidents": nonNil(inc)})
	})
	r.Handle("POST /api/v1/telemetry/events", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		if err := RequireServiceToken(req, a, s.ServiceToken); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		var body struct {
			Events []Event `json:"events"`
		}
		if err := httpapi.Decode(req, &body); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		n, inc, err := s.IngestEvents(req.Context(), a.TenantID, body.Events)
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusAccepted, map[string]any{"accepted": n, "incidents": nonNil(inc)})
	})

	r.Handle("GET /api/v1/telemetry/metrics", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		if err := canRead(a, metricReaders); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		q := req.URL.Query()
		assetID, metric := q.Get("asset_id"), q.Get("metric")
		if err := s.requireAsset(a.TenantID, assetID); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		if !metricNameRe.MatchString(metric) {
			httpapi.Fail(w, req, problem.New(problem.InvalidParams, "invalid metric"))
			return
		}
		window, err := windowParam(q.Get("window"), "15m")
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		step, err := windowParam(q.Get("step"), "1m")
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		series, err := s.Store.QueryMetric(req.Context(), MetricQuery{TenantID: a.TenantID, AssetID: assetID, Metric: metric, Window: window, Step: step})
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		if series == nil {
			series = []Series{}
		}
		httpapi.WriteJSON(w, http.StatusOK, map[string]any{"asset_id": assetID, "metric": metric, "window": window.String(), "series": series})
	})
	r.Handle("GET /api/v1/telemetry/logs", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		if err := canRead(a, logReaders); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		q := req.URL.Query()
		assetID := q.Get("asset_id")
		if assetID != "" {
			if err := s.requireAsset(a.TenantID, assetID); err != nil {
				httpapi.Fail(w, req, err)
				return
			}
		}
		window, err := windowParam(q.Get("window"), "15m")
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		minSev := Severity(q.Get("min_severity"))
		if minSev != "" && !minSev.Valid() {
			httpapi.Fail(w, req, problem.New(problem.InvalidParams, "invalid min_severity"))
			return
		}
		contains := q.Get("contains")
		if len(contains) > 500 {
			httpapi.Fail(w, req, problem.New(problem.InvalidParams, "contains is too long"))
			return
		}
		limit, err := limitParam(q.Get("limit"), 100, 500)
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		// Запрашиваем на одну запись больше, чтобы определить truncated.
		entries, err := s.Store.SearchLogs(req.Context(), LogQuery{TenantID: a.TenantID, AssetID: assetID, Contains: contains, MinSev: minSev, Window: window, Limit: limit + 1})
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		truncated := len(entries) > limit
		if truncated {
			entries = entries[:limit]
		}
		if entries == nil {
			entries = []LogRecord{}
		}
		httpapi.WriteJSON(w, http.StatusOK, map[string]any{"entries": entries, "truncated": truncated})
	})
	r.Handle("GET /api/v1/events", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		if err := canRead(a, metricReaders); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		q := req.URL.Query()
		assetID := q.Get("asset_id")
		if assetID != "" {
			if err := s.requireAsset(a.TenantID, assetID); err != nil {
				httpapi.Fail(w, req, err)
				return
			}
		}
		window, err := windowParam(q.Get("window"), "1h")
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		limit, err := limitParam(q.Get("limit"), 100, 1000)
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		evs, err := s.Store.ListEvents(req.Context(), EventQuery{TenantID: a.TenantID, AssetID: assetID, Window: window, Limit: limit})
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		if evs == nil {
			evs = []Event{}
		}
		httpapi.WriteJSON(w, http.StatusOK, map[string]any{"events": evs})
	})
}

func (s *Service) requireAsset(tenantID, assetID string) error {
	if assetID == "" {
		return problem.New(problem.InvalidParams, "asset_id is required")
	}
	if s.Inv != nil {
		if _, ok := s.Inv.Get(tenantID, assetID); !ok {
			return problem.New(problem.NotFound, "asset not found")
		}
	}
	return nil
}

func windowParam(v, def string) (time.Duration, error) {
	if v == "" {
		v = def
	}
	d, err := ParseWindow(v)
	if err != nil {
		return 0, problem.New(problem.InvalidParams, "%v", err)
	}
	return d, nil
}

func limitParam(v string, def, max int) (int, error) {
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > max {
		return 0, problem.New(problem.InvalidParams, "limit must be 1..%d", max)
	}
	return n, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
