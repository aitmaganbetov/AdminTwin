package discovery

import (
	"net/http"

	"github.com/aitmaganbetov/admintwin/pkg/httpapi"
	"github.com/aitmaganbetov/admintwin/pkg/identity"
)

// Routes публикует API discovery (контракты Этапа 1, §3).
func (s *Service) Routes(r *httpapi.Router) {
	r.Handle("GET /api/v1/discovery/scopes", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		items, err := s.ListScopes(a)
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
	})
	r.Handle("POST /api/v1/discovery/scopes", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		var in ScopeInput
		if err := httpapi.Decode(req, &in); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		sc, err := s.CreateScope(a, in)
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusCreated, sc)
	})
	r.Handle("POST /api/v1/discovery/scopes/{id}/approve", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		sc, err := s.ApproveScope(a, req.PathValue("id"))
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, sc)
	})
	r.Handle("POST /api/v1/discovery/jobs", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		var in JobInput
		if err := httpapi.Decode(req, &in); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		job, err := s.CreateJob(req.Context(), a, in)
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusAccepted, job)
	})
	r.Handle("GET /api/v1/discovery/jobs/{id}", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		job, err := s.GetJob(a, req.PathValue("id"))
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, job)
	})
	r.Handle("POST /api/v1/discovery/jobs/{id}/confirm", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		var in ConfirmInput
		if err := httpapi.Decode(req, &in); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		job, err := s.Confirm(a, req.PathValue("id"), in)
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		httpapi.WriteJSON(w, http.StatusOK, job)
	})
}
