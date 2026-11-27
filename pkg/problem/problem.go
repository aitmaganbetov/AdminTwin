// Package problem реализует ответы об ошибках по RFC 9457 (application/problem+json)
// с доменом типов errors.admintwin.io (ТЗ §13, §25).
package problem

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

const typeBase = "https://errors.admintwin.io/"

// Code — стабильный машинный код ошибки; становится последним сегментом поля type.
type Code string

const (
	PolicyDenied        Code = "policy-denied"
	BudgetExhausted     Code = "budget-exhausted"
	KillSwitchActive    Code = "kill-switch-active"
	LegalHold           Code = "legal-hold"
	SeparationOfDuties  Code = "separation-of-duties"
	InvalidParams       Code = "invalid-params"
	NotFound            Code = "not-found"
	Unauthenticated     Code = "unauthenticated"
	Forbidden           Code = "forbidden"
	InvalidTransition   Code = "invalid-transition"
	Conflict            Code = "conflict"
	IdempotencyMismatch Code = "idempotency-key-reused"
	BadRequest          Code = "bad-request"
	Internal            Code = "internal"
)

var defaults = map[Code]struct {
	status int
	title  string
}{
	PolicyDenied:        {http.StatusForbidden, "Policy denied"},
	BudgetExhausted:     {http.StatusConflict, "Budget exhausted"},
	KillSwitchActive:    {http.StatusConflict, "Kill switch active"},
	LegalHold:           {http.StatusConflict, "Legal hold"},
	SeparationOfDuties:  {http.StatusForbidden, "Separation of duties violated"},
	InvalidParams:       {http.StatusUnprocessableEntity, "Invalid parameters"},
	NotFound:            {http.StatusNotFound, "Not found"},
	Unauthenticated:     {http.StatusUnauthorized, "Unauthenticated"},
	Forbidden:           {http.StatusForbidden, "Forbidden"},
	InvalidTransition:   {http.StatusConflict, "Invalid state transition"},
	Conflict:            {http.StatusConflict, "Conflict"},
	IdempotencyMismatch: {http.StatusUnprocessableEntity, "Idempotency key reused with different payload"},
	BadRequest:          {http.StatusBadRequest, "Bad request"},
	Internal:            {http.StatusInternalServerError, "Internal error"},
}

// Problem — тело ответа RFC 9457 с расширениями AdminTwin.
type Problem struct {
	Type      string         `json:"type"`
	Title     string         `json:"title"`
	Status    int            `json:"status"`
	Detail    string         `json:"detail,omitempty"`
	Code      Code           `json:"-"`
	PolicyID  string         `json:"policy_id,omitempty"`
	ChangeID  string         `json:"change_id,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
	Errors    []FieldError   `json:"errors,omitempty"`
	Extra     map[string]any `json:"-"`
}

// FieldError описывает ошибку валидации конкретного поля.
type FieldError struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

func (p *Problem) Error() string {
	if p.Detail != "" {
		return fmt.Sprintf("%s: %s", p.Code, p.Detail)
	}
	return string(p.Code)
}

// New создаёт Problem с HTTP-статусом и заголовком по умолчанию для кода.
func New(code Code, detail string, args ...any) *Problem {
	d, ok := defaults[code]
	if !ok {
		d = defaults[Internal]
	}
	if len(args) > 0 {
		detail = fmt.Sprintf(detail, args...)
	}
	return &Problem{Type: typeBase + string(code), Title: d.title, Status: d.status, Detail: detail, Code: code}
}

// As извлекает *Problem из цепочки ошибок.
func As(err error) (*Problem, bool) {
	var p *Problem
	if errors.As(err, &p) {
		return p, true
	}
	return nil, false
}

// Is проверяет, что ошибка — Problem с указанным кодом.
func Is(err error, code Code) bool {
	p, ok := As(err)
	return ok && p.Code == code
}

// Write сериализует ошибку. Не-Problem ошибки превращаются в 500 без утечки деталей.
func Write(w http.ResponseWriter, err error, requestID string) {
	p, ok := As(err)
	if !ok {
		p = New(Internal, "internal error")
	}
	cp := *p
	cp.RequestID = requestID
	body := map[string]any{}
	raw, _ := json.Marshal(cp)
	_ = json.Unmarshal(raw, &body)
	for k, v := range cp.Extra {
		body[k] = v
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(cp.Status)
	_ = json.NewEncoder(w).Encode(body)
}
