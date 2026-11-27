package e2e

import (
	"testing"
)

// T-COMP-001: контроль без evidence не может быть implemented/verified (Приложение A.4).
func TestControlWithoutEvidenceCannotBeVerified(t *testing.T) {
	e := newEnv(t)
	cm := who{tenantA, "cm-1", "user", "compliance_manager", ""}
	path := "/api/v1/compliance/controls/STD-10/assessment"
	for _, st := range []string{"verified", "implemented"} {
		r := e.do(cm, "POST", path, map[string]any{"status": st})
		if r.Status != 422 {
			t.Fatalf("%s without evidence: %d %s", st, r.Status, r.Raw)
		}
	}
	if r := e.do(cm, "POST", path, map[string]any{"status": "verified", "evidence_ids": []string{"00000000-0000-4000-8000-000000000000"}}); r.Status != 422 {
		t.Fatalf("nonexistent evidence: %d", r.Status)
	}
	// Evidence появляется из исполнения изменения.
	ch := e.propose(engineerA, "docker.container.restart", dockerWeb, map[string]any{"container_id": appAPI})
	e.waitStatus(engineerA, ch.str("id"), "closed")
	ex := e.do(engineerA, "GET", "/api/v1/changes/"+ch.str("id")+"/executions", nil).Body["items"].([]any)
	ev := ex[0].(map[string]any)["result"].(map[string]any)["evidence_id"].(string)
	if r := e.do(cm, "POST", path, map[string]any{"status": "verified", "evidence_ids": []string{ev}}); r.Status != 200 {
		t.Fatalf("verified with evidence: %d %s", r.Status, r.Raw)
	}
	// Чужой tenant не может сослаться на это evidence.
	cmB := who{tenantB, "cm-b", "user", "compliance_manager", ""}
	if r := e.do(cmB, "POST", path, map[string]any{"status": "verified", "evidence_ids": []string{ev}}); r.Status != 422 {
		t.Fatalf("cross-tenant evidence: %d", r.Status)
	}
	for _, w := range []who{engineerA, auditorA, agentA} {
		if r := e.do(w, "POST", path, map[string]any{"status": "applicable"}); r.Status != 403 {
			t.Errorf("%s must not assess controls: %d", w.id, r.Status)
		}
	}
	if r := e.do(cm, "POST", path, map[string]any{"status": "not_applicable"}); r.Status != 422 {
		t.Errorf("not_applicable without justification: %d", r.Status)
	}
	list := e.do(auditorA, "GET", "/api/v1/compliance/controls", nil)
	var got string
	for _, it := range list.Body["items"].([]any) {
		m := it.(map[string]any)
		if m["id"] == "STD-10" {
			got, _ = m["status"].(string)
		}
	}
	if got != "verified" || len(list.Body["items"].([]any)) != 28 {
		t.Fatalf("controls list: STD-10=%s, items=%d", got, len(list.Body["items"].([]any)))
	}
}
