package incidents

import (
	"regexp"
	"strings"

	"github.com/aitmaganbetov/admintwin/services/inventory"
	"github.com/aitmaganbetov/admintwin/services/telemetry"
)

var (
	nonSlugRe = regexp.MustCompile(`[^a-z0-9]+`)
	causeRe   = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
)

// scenarioFor — сценарий golden dataset (ai/evals/eval-case.schema.json) по типу события.
func scenarioFor(kind string) string {
	switch kind {
	case "http_5xx":
		return "http_502"
	case "disk_usage":
		return "disk_exhaustion"
	case "container_down":
		return "container_stop"
	}
	return ""
}

// defaultChecks — минимальные проверки сценария (expected_checks требует ≥ 1).
var defaultChecks = map[string][]string{
	"http_502":        {"logs.search", "docker.container.inspect"},
	"disk_exhaustion": {"linux.disk.usage"},
	"container_stop":  {"docker.container.inspect"},
}

// causeSlug нормализует причину в идентификатор snake_case (`^[a-z][a-z0-9_]{2,63}$`).
func causeSlug(s string) string {
	s = strings.Trim(nonSlugRe.ReplaceAllString(strings.ToLower(s), "_"), "_")
	if s != "" && (s[0] < 'a' || s[0] > 'z') {
		s = "c_" + s
	}
	if len(s) > 64 {
		s = strings.TrimRight(s[:64], "_")
	}
	if !causeRe.MatchString(s) {
		return ""
	}
	return s
}

// buildCandidate формирует eval case из инцидента и оценки оператора. Сигналы — только ссылки на события,
// без строк журналов. Кандидат не попадает в golden dataset без ревью (tags: candidate).
func buildCandidate(inc *Incident, fb *Feedback, inv inventory.Repository) GoldenCandidate {
	c := GoldenCandidate{}
	var top *EventRef
	for i := range inc.Events {
		if top == nil || inc.Events[i].Severity.Rank() > top.Severity.Rank() {
			top = &inc.Events[i]
		}
	}
	scenario := ""
	alert := map[string]any{"type": "manual", "summary": inc.Title}
	if top != nil {
		scenario = scenarioFor(top.Kind)
		alert["type"] = alertType(*top)
		if sk := top.Labels["service_kind"]; sk != "" {
			alert["service_kind"] = sk
		}
	}
	if len(inc.AssetIDs) > 0 && inv != nil {
		if a, ok := inv.Get(inc.TenantID, inc.AssetIDs[0]); ok && a.Type != "" {
			alert["asset_type"] = a.Type
		}
	}
	signals := []any{}
	for _, e := range inc.Events {
		if len(signals) >= 20 {
			break
		}
		signals = append(signals, map[string]any{"tool": "events.list", "event_id": e.ID, "type": e.Kind, "severity": string(e.Severity)})
	}

	var hyps []Hypothesis
	hyps = append(hyps, inc.RCA.Hypotheses...)
	var rootCause string
	var evidence, checks, excluded []string
	if fb.Correct && len(hyps) > 0 {
		rootCause = causeSlug(hyps[0].Cause)
		for _, s := range hyps[0].Supporting {
			evidence = append(evidence, s.Fact)
		}
		checks = append(checks, hyps[0].NextChecks...)
		for _, h := range hyps[1:] {
			if slug := causeSlug(h.Cause); slug != "" {
				excluded = append(excluded, slug)
			}
		}
	} else if fb.ActualCause != "" {
		rootCause = causeSlug(fb.ActualCause)
		for _, h := range hyps {
			if slug := causeSlug(h.Cause); slug != "" && slug != rootCause {
				excluded = append(excluded, slug)
			}
		}
	}
	if len(evidence) == 0 {
		for _, e := range inc.Events {
			evidence = append(evidence, "event "+e.Kind+": "+e.Title)
			if len(evidence) >= 5 {
				break
			}
		}
	}
	if len(checks) == 0 {
		checks = append(checks, defaultChecks[scenario]...)
	}
	tags := []any{"candidate", "from-feedback"}
	switch {
	case scenario == "":
		c.Reason = "incident type does not map to an MVP golden scenario"
	case rootCause == "":
		c.Reason = "root cause unknown: RCA marked incorrect without actual_cause"
	case len(evidence) == 0 || len(checks) == 0:
		c.Reason = "insufficient evidence for an eval case"
	default:
		c.Exportable = true
	}
	expected := map[string]any{"root_cause": rootCause, "evidence": toAny(evidence), "expected_checks": toAny(checks)}
	if len(excluded) > 0 {
		expected["excluded_causes"] = toAny(excluded)
	}
	caseID := "fb-" + strings.ReplaceAll(inc.ID, "-", "")[:16]
	c.Case = map[string]any{
		"case_id": caseID, "scenario": scenario, "title": truncTitle(inc.Title),
		"input": map[string]any{"alert": alert, "signals": signals}, "expected": expected, "tags": tags,
	}
	return c
}

func truncTitle(s string) string {
	s = strings.TrimSpace(s)
	for len(s) < 3 {
		s += "."
	}
	return telemetry.Truncate(s, 300)
}

func toAny(ss []string) []any {
	out := make([]any, 0, len(ss))
	for _, s := range ss {
		out = append(out, s)
	}
	return out
}
