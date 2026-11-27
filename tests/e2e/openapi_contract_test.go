package e2e

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Contract-first (§23 п.1): каждый опубликованный маршрут описан в docs/api/openapi.yaml.
func TestRoutesAreDocumentedInOpenAPI(t *testing.T) {
	e := newEnv(t)
	raw, err := os.ReadFile("../../docs/api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	param := regexp.MustCompile(`\{[^}]+\}`)
	norm := func(p string) string { return param.ReplaceAllString(strings.ReplaceAll(p, "...}", "}"), "{}") }
	documented := map[string]bool{}
	for path, ops := range doc.Paths {
		for m := range ops {
			documented[strings.ToUpper(m)+" "+norm(path)] = true
		}
	}
	e.app.Server.Handler()
	routes := e.app.Server.RoutePatterns()
	if len(routes) < 30 {
		t.Fatalf("expected the full route table, got %d routes", len(routes))
	}
	for _, p := range routes {
		method, path, _ := strings.Cut(p, " ")
		if !documented[method+" "+norm(path)] {
			t.Errorf("route %s is not documented in docs/api/openapi.yaml", p)
		}
	}
}
