package incidents

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// Межъязыковой контракт с оркестратором: ядро сериализует RCATask с тем же набором полей,
// что и образец docs/api/fixtures/core_rca_task.json (его же принимает Python-тест ai/tests/test_core_contract.py).
func TestRCATaskMatchesSharedFixture(t *testing.T) {
	raw, err := os.ReadFile("../../docs/api/fixtures/core_rca_task.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]any
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	task := RCATask{Kind: "rca", Context: RCAContext{Events: []RCAEventSummary{{}}}}
	b, _ := json.Marshal(task)
	var ours map[string]any
	_ = json.Unmarshal(b, &ours)
	// asset_id и alert_type/asset_type/... помечены omitempty — сравниваем с образцом, где они заполнены.
	keys := func(m map[string]any) []string {
		out := []string{}
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	missingIn := func(name string, have, want []string) {
		set := map[string]bool{}
		for _, k := range have {
			set[k] = true
		}
		for _, k := range want {
			if !set[k] {
				t.Errorf("%s: field %q not in the shared fixture/serialization", name, k)
			}
		}
	}
	fx, ok := fixture["context"].(map[string]any)
	if !ok {
		t.Fatal("fixture has no context")
	}
	missingIn("task", keys(fixture), keys(ours))
	missingIn("context", keys(fx), keys(ours["context"].(map[string]any)))
	evFx := fx["events"].([]any)[0].(map[string]any)
	evOurs := ours["context"].(map[string]any)["events"].([]any)[0].(map[string]any)
	missingIn("event", keys(evFx), keys(evOurs))
}
