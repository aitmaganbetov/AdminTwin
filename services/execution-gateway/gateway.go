// Package gateway — Secure Execution Gateway (M09, §11.2 п.4–10): единственный исполнитель
// write-операций. Принимает только ExecutionRequest, порождённый ChangeRequest; получает
// краткоживущие креды, выполняет preflight, параметризованный runbook (без shell),
// post-check, rollback/compensation, редактирует секреты в выводе и формирует evidence.
package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/killswitch"
	"github.com/aitmaganbetov/admintwin/services/execution-gateway/runbook"
	"github.com/aitmaganbetov/admintwin/services/inventory"
)

// Status — итог исполнения.
type Status string

const (
	StatusVerified        Status = "verified"
	StatusDryRun          Status = "dry_run_completed"
	StatusPreflightFailed Status = "preflight_failed"
	StatusPostCheckFailed Status = "post_check_failed"
	StatusFailed          Status = "failed"
	StatusCancelled       Status = "cancelled"
	StatusUnknown         Status = "unknown" // → manual_review; успех остановки не утверждается
)

// Request — исполнение одного runbook-шага в рамках ChangeRequest.
type Request struct {
	ChangeID      string
	ExecutionID   string
	TenantID      string
	Asset         inventory.Asset
	Runbook       *runbook.Spec
	Params        map[string]any
	FencingToken  uint64
	DryRun        bool
	InWindow      bool // текущий момент внутри maintenance window tenant
	ApprovedBy    []string
	CorrelationID string
	// OnExecuteStart вызывается после успешного preflight, непосредственно перед движком.
	OnExecuteStart func()
}

// StepResult — результат шага.
type StepResult struct {
	Phase   string    `json:"phase"` // preflight | execute | post_check | compensation
	Name    string    `json:"name"`
	OK      bool      `json:"ok"`
	Skipped bool      `json:"skipped,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	At      time.Time `json:"at"`
}

// Result — результат исполнения.
type Result struct {
	ExecutionID  string       `json:"execution_id"`
	Status       Status       `json:"status"`
	Steps        []StepResult `json:"steps"`
	Stdout       string       `json:"stdout,omitempty"`
	Stderr       string       `json:"stderr,omitempty"`
	ExitCode     int          `json:"exit_code"`
	Compensation []string     `json:"compensation,omitempty"`
	Proposals    []string     `json:"proposals,omitempty"` // runbook, предложенные новым ChangeRequest
	EvidenceID   string       `json:"evidence_id,omitempty"`
	Digest       string       `json:"digest,omitempty"`
	StartedAt    time.Time    `json:"started_at"`
	FinishedAt   time.Time    `json:"finished_at"`
}

// EngineRequest — вызов движка исполнения.
type EngineRequest struct {
	TenantID string
	AssetID  string
	Asset    inventory.Asset
	Action   string
	Argv     []string
	Params   map[string]any
	DryRun   bool
	Lease    Lease
}

// EngineResult — ответ движка.
type EngineResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// ErrCancelConfirmed — движок подтвердил, что операция прервана до изменения состояния.
var ErrCancelConfirmed = errors.New("cancellation confirmed by engine")

// ErrChannelLost — потерян управляющий канал; результат неизвестен (§17.2).
var ErrChannelLost = errors.New("management channel lost")

// Engine — исполнитель (docker_api, ssh_argv, builtin). Shell-движка нет.
type Engine interface {
	Execute(ctx context.Context, req EngineRequest) (EngineResult, error)
}

// Lease — краткоживущий доступ (capability handle). Секрет живёт только внутри процесса Gateway
// и передаётся движку; в журналы, evidence и агентам не попадает (String/MarshalJSON редактируют).
type Lease struct {
	Handle     string
	ExpiresAt  time.Time
	Credential Credential
}

// Credential — материал доступа, выданный Vault на время исполнения.
type Credential struct {
	Username   string
	Password   string
	PrivateKey []byte // PEM (SSH)
	Token      string // API-токен (FortiGate и т.п.)
	ClientCert []byte // PEM mTLS (Docker API)
	ClientKey  []byte
	CACert     []byte
}

// String не раскрывает секреты.
func (c Credential) String() string { return "Credential{[REDACTED]}" }

// GoString не раскрывает секреты (%#v).
func (c Credential) GoString() string { return c.String() }

// MarshalJSON не раскрывает секреты.
func (c Credential) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED]"`), nil }

// Empty — материал не выдан.
func (c Credential) Empty() bool {
	return c.Username == "" && c.Password == "" && len(c.PrivateKey) == 0 && c.Token == "" && len(c.ClientCert) == 0
}

// CredentialBroker — Vault / OpenBao. Недоступность = исполнения невозможны (§17.2).
// credentialRef — путь в Vault из inventory.Asset.Connection.CredentialRef (может быть пустым для симулятора).
type CredentialBroker interface {
	Lease(ctx context.Context, tenantID, assetID, credentialRef string, ttl time.Duration) (Lease, error)
	Revoke(ctx context.Context, l Lease) error
}

// Facts — read-only факты об активе для preflight/post-check (реализуются коннекторами).
type Facts interface {
	ContainerRunning(tenantID, assetID, containerID string) (bool, error)
	RestartsLastHour(tenantID, assetID, object string) (int, error)
	UnitActive(tenantID, assetID, unit string) (bool, error)
	DiskUsagePercent(tenantID, assetID string) (float64, error)
	LogWritersHealthy(tenantID, assetID string) (bool, error)
	HealthOK(tenantID, assetID, endpoint string) (bool, error)
}

// EvidenceSink сохраняет evidence с digest.
type EvidenceSink interface {
	Store(tenantID, kind, ref string, body []byte, legalHold bool) (id, digest string, err error)
}

// Gateway — исполнитель.
type Gateway struct {
	Engines  map[string]Engine
	Broker   CredentialBroker
	Facts    Facts
	Evidence EvidenceSink
	Kill     *killswitch.Switch
	Now      func() time.Time
}

// Run выполняет runbook. Gateway никогда не повторяет вслепую и не утверждает успех без проверки.
func (g *Gateway) Run(ctx context.Context, req Request) Result {
	now := g.now
	res := Result{ExecutionID: req.ExecutionID, StartedAt: now()}
	step := func(phase, name string, ok, skipped bool, detail string) {
		res.Steps = append(res.Steps, StepResult{Phase: phase, Name: name, OK: ok, Skipped: skipped, Detail: detail, At: now()})
	}
	finish := func(s Status) Result {
		res.Status = s
		res.FinishedAt = now()
		g.storeEvidence(req, &res)
		return res
	}

	if req.ChangeID == "" || req.ExecutionID == "" {
		step("preflight", "change_binding", false, false, "execution must originate from a ChangeRequest")
		return finish(StatusPreflightFailed)
	}
	if !g.fenceOK(req) {
		step("preflight", "kill_switch", false, false, "kill switch active or fencing token stale")
		return finish(StatusCancelled)
	}

	// Preflight выполняется независимо от решения согласующих (§11.1).
	for _, c := range req.Runbook.Preflight {
		ok, skipped, detail := g.check(req, c)
		step("preflight", c.Check, ok, skipped, detail)
		if !ok && !skipped {
			return finish(StatusPreflightFailed)
		}
	}

	// Краткоживущие креды: TTL ≤ время runbook + 60 с.
	ttl := time.Duration(req.Runbook.Execute.TimeoutS)*time.Second + 60*time.Second
	if g.Broker == nil {
		step("execute", "credentials", false, false, "credential broker unavailable: executions impossible")
		return finish(StatusFailed)
	}
	credRef := ""
	if req.Asset.Connection != nil {
		credRef = req.Asset.Connection.CredentialRef
	}
	lease, err := g.Broker.Lease(ctx, req.TenantID, req.Asset.ID, credRef, ttl)
	if err != nil {
		step("execute", "credentials", false, false, "vault unavailable: "+err.Error())
		return finish(StatusFailed)
	}
	defer func() { _ = g.Broker.Revoke(context.Background(), lease) }()

	if !g.fenceOK(req) {
		step("execute", "kill_switch", false, false, "kill switch activated before execution")
		return finish(StatusCancelled)
	}

	eng, ok := g.Engines[req.Runbook.Execute.Engine]
	if !ok {
		step("execute", req.Runbook.Execute.Engine, false, false, "engine not available")
		return finish(StatusFailed)
	}
	argv, err := req.Runbook.RenderArgv(req.Params)
	if err != nil {
		step("execute", "render", false, false, err.Error())
		return finish(StatusFailed)
	}
	// Dry-run запрашивается флагом ChangeRequest или параметром runbook dry_run; если runbook
	// его не поддерживает — отказ без исполнения (не выполняем «настоящий» прогон вместо пробного).
	dry := req.DryRun || req.Params["dry_run"] == true
	if dry && !req.Runbook.Execute.DryRun {
		step("execute", "dry_run", false, false, "dry run requested but runbook does not support it")
		return finish(StatusFailed)
	}
	if ctx.Err() != nil {
		step("execute", "cancellation", false, false, "cancelled before the engine was invoked")
		return finish(StatusCancelled)
	}
	if req.OnExecuteStart != nil {
		req.OnExecuteStart()
	}
	ectx, cancel := context.WithTimeout(ctx, time.Duration(req.Runbook.Execute.TimeoutS)*time.Second)
	defer cancel()
	out, err := eng.Execute(ectx, EngineRequest{
		TenantID: req.TenantID, AssetID: req.Asset.ID, Asset: req.Asset, Action: req.Runbook.Execute.Action,
		Argv: argv, Params: req.Params, DryRun: dry, Lease: lease,
	})
	res.Stdout, res.Stderr, res.ExitCode = Redact(out.Stdout), Redact(out.Stderr), out.ExitCode
	switch {
	case errors.Is(err, ErrCancelConfirmed):
		step("execute", req.Runbook.Execute.Action, false, false, "cancelled, confirmed by engine")
		return finish(StatusCancelled)
	case errors.Is(err, ErrChannelLost), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// Не повторяем вслепую: состояние неизвестно → manual_review.
		step("execute", req.Runbook.Execute.Action, false, false, "outcome unknown: "+err.Error())
		return finish(StatusUnknown)
	case err != nil || out.ExitCode != 0:
		detail := fmt.Sprintf("exit code %d", out.ExitCode)
		if err != nil {
			detail = Redact(err.Error())
		}
		step("execute", req.Runbook.Execute.Action, false, false, detail)
		g.compensate(req, &res)
		return finish(StatusFailed)
	}
	step("execute", req.Runbook.Execute.Action, true, false, "")
	if dry {
		return finish(StatusDryRun)
	}

	for _, c := range req.Runbook.PostCheck {
		ok, skipped, detail := g.check(req, c)
		step("post_check", c.Check, ok, skipped, detail)
		if !ok && !skipped {
			g.compensate(req, &res)
			return finish(StatusPostCheckFailed)
		}
	}
	return finish(StatusVerified)
}

func (g *Gateway) now() time.Time {
	if g.Now != nil {
		return g.Now().UTC()
	}
	return time.Now().UTC()
}

func (g *Gateway) fenceOK(req Request) bool {
	return g.Kill == nil || g.Kill.Valid(req.TenantID, req.FencingToken)
}

// compensate — rollback невозможен (rollback: none): выполняем компенсирующие меры.
// Предложение другого runbook оформляется новым ChangeRequest, а не исполняется.
func (g *Gateway) compensate(req Request, res *Result) {
	for _, a := range req.Runbook.Compensation {
		if a.When != "" && a.When != "post_check_failed" && a.When != "execute_failed" {
			continue
		}
		if a.Propose != "" {
			res.Proposals = append(res.Proposals, a.Propose)
		}
		res.Compensation = append(res.Compensation, a.Action)
		res.Steps = append(res.Steps, StepResult{Phase: "compensation", Name: a.Action, OK: true, At: g.now()})
	}
}

func (g *Gateway) storeEvidence(req Request, res *Result) {
	if g.Evidence == nil {
		return
	}
	body, _ := json.Marshal(map[string]any{
		"change_id": req.ChangeID, "execution_id": req.ExecutionID, "runbook": req.Runbook.ID + "@" + req.Runbook.Version,
		"runbook_digest": req.Runbook.Digest, "asset_id": req.Asset.ID, "params": req.Params,
		"approved_by": req.ApprovedBy, "result": res,
	})
	id, digest, err := g.Evidence.Store(req.TenantID, "execution", req.ExecutionID, body, req.Asset.LegalHold)
	if err == nil {
		res.EvidenceID, res.Digest = id, digest
	}
}

// Digest — sha256 содержимого evidence.
func Digest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api[_-]?key|authorization)(\s*[:=]\s*|\s+)("[^"]*"|\S+)`),
	regexp.MustCompile(`(?i)bearer\s+[a-z0-9\-._~+/]+=*`),
	regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`),
	regexp.MustCompile(`\b(hvs|hvb|s)\.[A-Za-z0-9]{20,}\b`),
}

// Redact удаляет секреты из stdout/stderr (§11.2 п.8).
func Redact(s string) string {
	for i, re := range secretPatterns {
		if i == 0 {
			s = re.ReplaceAllString(s, "$1$2[REDACTED]")
			continue
		}
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}
