package incidents

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/aitmaganbetov/admintwin/pkg/fsm"
	"github.com/aitmaganbetov/admintwin/pkg/httpapi"
	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/telemetry"
)

// Routes публикует API инцидентов (контракты Этапа 1, §3).
func (s *Service) Routes(r *httpapi.Router) {
	r.Handle("GET /api/v1/incidents", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		q := req.URL.Query()
		f := Filter{Status: fsm.State(q.Get("status")), Severity: telemetry.Severity(q.Get("severity"))}
		if l := q.Get("limit"); l != "" {
			n, err := strconv.Atoi(l)
			if err != nil || n < 1 || n > 1000 {
				httpapi.Fail(w, req, problem.New(problem.InvalidParams, "limit must be 1..1000"))
				return
			}
			f.Limit = n
		}
		items, err := s.List(req.Context(), a, f)
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		if items == nil {
			items = []Incident{}
		}
		httpapi.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
	})
	r.Handle("POST /api/v1/incidents", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		var in CreateInput
		if err := httpapi.Decode(req, &in); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		inc, err := s.Create(req.Context(), a, in)
		respond(w, req, http.StatusCreated, inc, err)
	})
	r.Handle("GET /api/v1/incidents/golden-candidates", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		cases, err := s.ExportCandidates(req.Context(), a)
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		// JSONL: одна строка — один eval case (ai/evals/eval-case.schema.json).
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		for _, c := range cases {
			_ = enc.Encode(c)
		}
	})
	r.Handle("GET /api/v1/incidents/{id}", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		inc, err := s.Get(req.Context(), a, req.PathValue("id"))
		respond(w, req, http.StatusOK, inc, err)
	})
	r.Handle("POST /api/v1/incidents/{id}/transitions", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		var in TransitionInput
		if err := httpapi.Decode(req, &in); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		inc, err := s.Transition(req.Context(), a, req.PathValue("id"), in)
		respond(w, req, http.StatusOK, inc, err)
	})
	r.Handle("POST /api/v1/incidents/{id}/analyze", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		inc, err := s.Analyze(req.Context(), a, req.PathValue("id"))
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		if inc.RCA.Status == RCAFailed {
			httpapi.WriteJSON(w, http.StatusAccepted, map[string]any{"task_id": nil, "status": inc.RCA.Status, "note": inc.RCA.Note})
			return
		}
		httpapi.WriteJSON(w, http.StatusAccepted, map[string]any{"task_id": inc.RCA.TaskID, "status": inc.RCA.Status})
	})
	r.Handle("POST /api/v1/incidents/{id}/rca", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		if err := telemetry.RequireServiceToken(req, a, s.ServiceToken); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		var in RCAResult
		if err := httpapi.Decode(req, &in); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		inc, err := s.RecordRCA(req.Context(), a, req.PathValue("id"), in)
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, map[string]any{"id": inc.ID, "status": inc.Status, "rca": inc.RCA})
	})
	r.Handle("POST /api/v1/incidents/{id}/feedback", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		var in FeedbackInput
		if err := httpapi.Decode(req, &in); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		inc, cand, err := s.SetFeedback(req.Context(), a, req.PathValue("id"), in)
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, map[string]any{"incident": inc, "candidate": cand})
	})
	r.Handle("POST /api/v1/incidents/{id}/postmortem", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		var in PostmortemInput
		if err := httpapi.Decode(req, &in); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		inc, err := s.SetPostmortem(req.Context(), a, req.PathValue("id"), in)
		respond(w, req, http.StatusOK, inc, err)
	})
}

func respond(w http.ResponseWriter, req *http.Request, status int, inc *Incident, err error) {
	if err != nil {
		httpapi.Fail(w, req, err)
		return
	}
	httpapi.WriteJSON(w, status, inc)
}
