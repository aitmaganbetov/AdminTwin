package runbook

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/aitmaganbetov/admintwin/pkg/problem"
)

// InventoryLookup проверяет, что объект существует в CMDB tenant у целевого актива
// (защита от эскалации через параметры, §18.6).
type InventoryLookup func(kind, value string) bool

// ValidateParams проверяет параметры по схеме runbook и allowlist. Неизвестные параметры
// отклоняются. Возвращает нормализованные значения (с подставленными default).
func (s *Spec) ValidateParams(in map[string]any, lookup InventoryLookup) (map[string]any, error) {
	var fe []problem.FieldError
	out := map[string]any{}

	extra := make([]string, 0)
	for k := range in {
		if _, ok := s.Parameters[k]; !ok {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		fe = append(fe, problem.FieldError{Field: "params." + k, Reason: "unknown parameter"})
	}

	names := make([]string, 0, len(s.Parameters))
	for n := range s.Parameters {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		p := s.Parameters[n]
		v, present := in[n]
		if !present {
			if p.Default != nil {
				v = p.Default
			} else if p.IsRequired() {
				fe = append(fe, problem.FieldError{Field: "params." + n, Reason: "required"})
				continue
			} else {
				continue
			}
		}
		norm, reason := p.check(v)
		if reason != "" {
			fe = append(fe, problem.FieldError{Field: "params." + n, Reason: reason})
			continue
		}
		if p.Source == "asset_inventory" {
			if lookup == nil || !lookup(p.Kind, fmt.Sprint(norm)) {
				fe = append(fe, problem.FieldError{Field: "params." + n, Reason: "not found in tenant inventory for the target asset"})
				continue
			}
		}
		out[n] = norm
	}
	if len(fe) > 0 {
		pr := problem.New(problem.InvalidParams, "runbook %s: %d parameter(s) rejected", s.ID, len(fe))
		pr.Errors = fe
		return nil, pr
	}
	return out, nil
}

func (p Param) check(v any) (any, string) {
	switch p.Type {
	case "string":
		str, ok := v.(string)
		if !ok {
			return nil, "must be a string"
		}
		if !utf8.ValidString(str) || strings.ContainsRune(str, 0) {
			return nil, "invalid characters"
		}
		max := p.MaxLength
		if max == 0 {
			max = 256
		}
		if len(str) > max {
			return nil, fmt.Sprintf("longer than %d", max)
		}
		if len(p.Enum) > 0 && !slices.Contains(p.Enum, str) {
			return nil, "not in allowlist"
		}
		if p.re != nil && !p.re.MatchString(str) {
			return nil, "does not match pattern"
		}
		return str, ""
	case "integer":
		var n int64
		switch x := v.(type) {
		case int:
			n = int64(x)
		case int64:
			n = x
		case float64:
			if x != math.Trunc(x) {
				return nil, "must be an integer"
			}
			n = int64(x)
		case json.Number:
			i, err := x.Int64()
			if err != nil {
				return nil, "must be an integer"
			}
			n = i
		default:
			return nil, "must be an integer"
		}
		if p.Minimum != nil && n < int64(*p.Minimum) {
			return nil, fmt.Sprintf("must be >= %d", *p.Minimum)
		}
		if p.Maximum != nil && n > int64(*p.Maximum) {
			return nil, fmt.Sprintf("must be <= %d", *p.Maximum)
		}
		return n, ""
	case "boolean":
		b, ok := v.(bool)
		if !ok {
			return nil, "must be a boolean"
		}
		return b, ""
	}
	return nil, "unsupported type"
}

// RenderArgv подставляет параметры целыми элементами argv. Строковая интерполяция
// в shell не используется: каждый элемент передаётся процессу как отдельный аргумент.
func (s *Spec) RenderArgv(params map[string]any) ([]string, error) {
	out := make([]string, 0, len(s.Execute.Argv))
	for _, a := range s.Execute.Argv {
		m := placeholder.FindStringSubmatch(a)
		if m == nil {
			out = append(out, a)
			continue
		}
		v, ok := params[m[1]]
		if !ok {
			return nil, fmt.Errorf("argv references missing parameter %q", m[1])
		}
		out = append(out, fmt.Sprint(v))
	}
	return out, nil
}
