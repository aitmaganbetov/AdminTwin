// Package toolsvc — Tool Service (§3.3, §3.4): серверная сторона read tools для агентов.
//
// Контракты инструментов — те же JSON Schema, что использует AI-слой (ai/tools/read/*.json).
// Ядро повторно (defense in depth) проверяет: tool scope агента по реестру capabilities (T-CAP-001),
// вид инструмента (только read; execute-инструментов не существует, T-CAP-003), вход и выход по схеме,
// принадлежность актива tenant, лимит размера ответа; помечает класс данных ответа и пишет аудит.
// Обработчики регистрируют модули (connectors, telemetry); asset.get и topology.blast_radius — встроенные.
package toolsvc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/aitmaganbetov/admintwin/pkg/httpapi"
	"github.com/aitmaganbetov/admintwin/pkg/identity"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
	"github.com/aitmaganbetov/admintwin/services/audit"
	"github.com/aitmaganbetov/admintwin/services/inventory"

	"net/http"
)

// DataClass — класс данных (§6.4).
var classRank = map[string]int{"public": 1, "internal": 2, "confidential": 3, "pii": 4, "secret": 5, "unknown": 6}

// MaxClass — более строгий из двух классов.
func MaxClass(a, b string) string {
	if classRank[b] > classRank[a] {
		return b
	}
	return a
}

// Contract — контракт инструмента из ai/tools/read.
type Contract struct {
	Name             string          `json:"name"`
	Kind             string          `json:"kind"`
	Version          string          `json:"version"`
	Description      string          `json:"description"`
	DataClass        string          `json:"data_class"`
	MaxResponseBytes int             `json:"max_response_bytes"`
	RateLimit        int             `json:"rate_limit_per_minute"`
	Capabilities     []string        `json:"capabilities"`
	InputSchema      json.RawMessage `json:"input_schema"`
	OutputSchema     json.RawMessage `json:"output_schema"`

	in, out *jsonschema.Schema
}

// Call — вызов инструмента.
type Call struct {
	TenantID string
	Actor    identity.Actor
	Input    map[string]any
	// Asset — целевой актив (если вход содержит asset_id), уже проверен на принадлежность tenant.
	Asset *inventory.Asset
}

// Result — ответ обработчика. DataClass может повысить класс контракта (например, ПДн в журнале).
type Result struct {
	Data      any
	DataClass string
}

// Handler — реализация инструмента.
type Handler func(ctx context.Context, c Call) (Result, error)

// ScopeFunc возвращает tools, разрешённые агенту (из реестра capabilities).
type ScopeFunc func(agentID string) []string

// Service — реестр контрактов и обработчиков.
type Service struct {
	mu        sync.RWMutex
	contracts map[string]*Contract
	handlers  map[string]Handler
	inv       inventory.Repository
	scope     ScopeFunc
	audit     *audit.Log
	limiter   *limiter
	Timeout   time.Duration
}

// Load читает контракты read tools из каталога (обычно ai/tools/read). Ошибка — отказ старта.
func Load(dir string, inv inventory.Repository, scope ScopeFunc, al *audit.Log) (*Service, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	s := &Service{contracts: map[string]*Contract{}, handlers: map[string]Handler{}, inv: inv, scope: scope, audit: al,
		limiter: newLimiter(), Timeout: 15 * time.Second}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var ct Contract
		if err := json.Unmarshal(raw, &ct); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		if ct.Kind != "read" {
			return nil, fmt.Errorf("%s: tool service serves only read tools, got kind %q", ct.Name, ct.Kind)
		}
		if _, ok := classRank[ct.DataClass]; !ok {
			return nil, fmt.Errorf("%s: unknown data_class %q", ct.Name, ct.DataClass)
		}
		for i, sch := range []json.RawMessage{ct.InputSchema, ct.OutputSchema} {
			doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(sch)))
			if err != nil {
				return nil, fmt.Errorf("%s: schema: %w", ct.Name, err)
			}
			url := fmt.Sprintf("mem://tools/%s/%d.json", ct.Name, i)
			if err := c.AddResource(url, doc); err != nil {
				return nil, err
			}
			compiled, err := c.Compile(url)
			if err != nil {
				return nil, fmt.Errorf("%s: compile schema: %w", ct.Name, err)
			}
			if i == 0 {
				ct.in = compiled
			} else {
				ct.out = compiled
			}
		}
		cp := ct
		s.contracts[ct.Name] = &cp
	}
	s.registerBuiltins()
	return s, nil
}

// Register подключает обработчик к существующему контракту.
func (s *Service) Register(name string, h Handler) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.contracts[name]; !ok {
		return fmt.Errorf("tool %s has no contract in ai/tools/read", name)
	}
	s.handlers[name] = h
	return nil
}

// MustRegister — Register с паникой (для сборки приложения).
func (s *Service) MustRegister(name string, h Handler) {
	if err := s.Register(name, h); err != nil {
		panic(err)
	}
}

// Available — инструменты, у которых есть обработчик.
func (s *Service) Available() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.handlers))
	for n := range s.handlers {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Invoke выполняет инструмент со всеми проверками. Используется HTTP-слоем и тестами.
func (s *Service) Invoke(ctx context.Context, a identity.Actor, name string, input map[string]any) (map[string]any, error) {
	s.mu.RLock()
	ct, ok := s.contracts[name]
	h := s.handlers[name]
	s.mu.RUnlock()
	if !ok {
		// Нет такого read tool: в т.ч. любые попытки вызвать execute/propose здесь (T-CAP-003).
		s.auditRefusal(a, name, "unknown tool")
		return nil, problem.New(problem.NotFound, "tool %q does not exist", name)
	}
	if a.IsAI() {
		if !slices.Contains(s.scope(a.ID), name) {
			s.auditRefusal(a, name, "tool outside agent scope")
			return nil, problem.New(problem.Forbidden, "agent %q has no confirmed tool scope for %q (T-CAP-001)", a.ID, name)
		}
	} else if !a.HasAny(identity.RoleTenantAdmin, identity.RoleITManager, identity.RoleEngineer, identity.RoleOperator) {
		return nil, problem.New(problem.Forbidden, "insufficient role for tool invocation")
	}
	if h == nil {
		return nil, problem.New(problem.NotFound, "tool %q has no backend in this deployment", name)
	}
	if !s.limiter.allow(a.TenantID+"|"+a.ID+"|"+name, ct.RateLimit) {
		return nil, problem.New(problem.Conflict, "rate limit exceeded for tool %q", name)
	}
	if input == nil {
		input = map[string]any{}
	}
	if err := ct.in.Validate(normalize(input)); err != nil {
		pr := problem.New(problem.InvalidParams, "input does not match %s schema", name)
		pr.Errors = []problem.FieldError{{Field: "input", Reason: firstLine(err.Error())}}
		return nil, pr
	}
	call := Call{TenantID: a.TenantID, Actor: a, Input: input}
	if id, ok := input["asset_id"].(string); ok {
		asset, ok := s.inv.Get(a.TenantID, id)
		if !ok {
			return nil, problem.New(problem.NotFound, "asset not found")
		}
		call.Asset = asset
	}
	cctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	res, err := h(cctx, call)
	if err != nil {
		if _, ok := problem.As(err); ok {
			return nil, err
		}
		return nil, problem.New(problem.Internal, "tool backend error")
	}
	raw, err := json.Marshal(res.Data)
	if err != nil {
		return nil, problem.New(problem.Internal, "tool produced unserializable output")
	}
	if ct.MaxResponseBytes > 0 && len(raw) > ct.MaxResponseBytes {
		return nil, problem.New(problem.Conflict, "tool %q response exceeds %d bytes", name, ct.MaxResponseBytes)
	}
	var generic any
	_ = json.Unmarshal(raw, &generic)
	if err := ct.out.Validate(generic); err != nil {
		// Ответ коннектора не соответствует контракту — агенту не отдаём.
		return nil, problem.New(problem.Internal, "tool %q backend returned output outside its contract", name)
	}
	class := MaxClass(ct.DataClass, res.DataClass)
	if call.Asset != nil {
		// Класс данных актива ограничивает снизу класс ответа о нём.
		class = MaxClass(class, classForAsset(call.Asset.DataClass))
	}
	if s.audit != nil {
		data := map[string]any{"tool": name, "version": ct.Version, "data_class": class, "bytes": len(raw)}
		if call.Asset != nil {
			data["asset_id"] = call.Asset.ID
		}
		_, _ = s.audit.Append(audit.Record{TenantID: a.TenantID, Actor: a.Ref(), Action: "tool.invoked", ObjectType: "tool", ObjectID: name, Data: data})
	}
	return map[string]any{"tool": name, "version": ct.Version, "data_class": class, "data": generic}, nil
}

func classForAsset(c string) string {
	// Ответ о конфигурации/состоянии актива с pii-данными сам по себе ПДн не содержит; поднимаем до confidential.
	switch c {
	case "pii", "secret":
		return "confidential"
	}
	return c
}

func (s *Service) auditRefusal(a identity.Actor, name, why string) {
	if s.audit == nil {
		return
	}
	_, _ = s.audit.Append(audit.Record{TenantID: a.TenantID, Actor: a.Ref(), Action: "tool.refused", ObjectType: "tool", ObjectID: name, Data: map[string]any{"reason": why}})
}

// Routes публикует POST /api/v1/tools/{name} и GET /api/v1/tools.
func (s *Service) Routes(r *httpapi.Router) {
	r.Handle("GET /api/v1/tools", func(w http.ResponseWriter, _ *http.Request, a identity.Actor) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		items := []map[string]any{}
		for _, n := range sortedKeys(s.contracts) {
			ct := s.contracts[n]
			if a.IsAI() && !slices.Contains(s.scope(a.ID), n) {
				continue
			}
			items = append(items, map[string]any{"name": n, "kind": ct.Kind, "version": ct.Version, "data_class": ct.DataClass, "available": s.handlers[n] != nil})
		}
		httpapi.WriteJSON(w, 200, map[string]any{"items": items})
	})
	r.Handle("POST /api/v1/tools/{name}", func(w http.ResponseWriter, req *http.Request, a identity.Actor) {
		var body struct {
			Input map[string]any `json:"input"`
		}
		if err := httpapi.Decode(req, &body); err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		out, err := s.Invoke(req.Context(), a, req.PathValue("name"), body.Input)
		if err != nil {
			httpapi.Fail(w, req, err)
			return
		}
		httpapi.WriteJSON(w, 200, out)
	})
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// normalize приводит json.Number к float64/int для валидатора.
func normalize(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// limiter — фиксированное окно в минуту на (tenant, actor, tool).
type limiter struct {
	mu     sync.Mutex
	window map[string]struct {
		start time.Time
		n     int
	}
}

func newLimiter() *limiter {
	return &limiter{window: map[string]struct {
		start time.Time
		n     int
	}{}}
}

func (l *limiter) allow(key string, perMinute int) bool {
	if perMinute <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	w := l.window[key]
	if now.Sub(w.start) >= time.Minute {
		w.start, w.n = now, 0
	}
	if w.n >= perMinute {
		return false
	}
	w.n++
	l.window[key] = w
	return true
}
