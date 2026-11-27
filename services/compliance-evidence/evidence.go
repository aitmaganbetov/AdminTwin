// Package evidence — единая сущность evidence (§12 «Evidence (единая)», §18.5): артефакт с digest,
// custody-событиями, retention_class, legal hold и журналом доступа с purpose-of-access.
package evidence

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/aitmaganbetov/admintwin/pkg/problem"
)

// CustodyEvent — событие цепочки хранения.
type CustodyEvent struct {
	Event string    `json:"event"` // collected | stored | accessed | legal_hold_set | legal_hold_released
	Actor string    `json:"actor"`
	At    time.Time `json:"at"`
	Note  string    `json:"note,omitempty"`
}

// AccessLogEntry — доступ с указанием цели.
type AccessLogEntry struct {
	Actor   string    `json:"actor"`
	Purpose string    `json:"purpose"`
	At      time.Time `json:"at"`
}

// Item — evidence.
type Item struct {
	ID             string           `json:"id"`
	TenantID       string           `json:"tenant_id"`
	Kind           string           `json:"kind"` // execution | incident | compliance | forensic
	Ref            string           `json:"ref"`
	Digest         string           `json:"hash_sha256"`
	Source         string           `json:"source"`
	Collector      string           `json:"collector"`
	CollectedAtUTC time.Time        `json:"collected_at_utc"`
	TimeSource     string           `json:"time_source"`
	RetentionClass string           `json:"retention_class"`
	LegalHold      bool             `json:"legal_hold"`
	Custody        []CustodyEvent   `json:"custody_events"`
	AccessLog      []AccessLogEntry `json:"access_log"`
	body           []byte
}

// Store — in-memory хранилище (в production — PostgreSQL + MinIO Object Lock).
type Store struct {
	mu    sync.Mutex
	items map[string]*Item
	now   func() time.Time
}

// NewStore создаёт хранилище.
func NewStore() *Store { return &Store{items: map[string]*Item{}, now: time.Now} }

// Store сохраняет артефакт и возвращает id и digest (реализует gateway.EvidenceSink).
func (s *Store) Store(tenantID, kind, ref string, body []byte, legalHold bool) (string, string, error) {
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	id := newID()
	now := s.now().UTC()
	rc := "operational-1y"
	if kind == "compliance" || kind == "forensic" {
		rc = "compliance-7y"
	}
	it := &Item{
		ID: id, TenantID: tenantID, Kind: kind, Ref: ref, Digest: digest,
		Source: "admintwin-execution-gateway", Collector: "execution-gateway", CollectedAtUTC: now,
		TimeSource: "system-ntp", RetentionClass: rc, LegalHold: legalHold,
		Custody: []CustodyEvent{{Event: "collected", Actor: "service:execution-gateway", At: now}, {Event: "stored", Actor: "service:compliance-evidence", At: now}},
		body:    append([]byte(nil), body...),
	}
	s.mu.Lock()
	s.items[id] = it
	s.mu.Unlock()
	return id, digest, nil
}

// Get выдаёт evidence только с указанием цели доступа; каждый доступ журналируется.
func (s *Store) Get(tenantID, id, actor, purpose string) (*Item, []byte, error) {
	if purpose == "" {
		return nil, nil, problem.New(problem.Forbidden, "purpose_of_access is required for evidence")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.items[id]
	if !ok || it.TenantID != tenantID {
		return nil, nil, problem.New(problem.NotFound, "evidence not found")
	}
	now := s.now().UTC()
	it.AccessLog = append(it.AccessLog, AccessLogEntry{Actor: actor, Purpose: purpose, At: now})
	it.Custody = append(it.Custody, CustodyEvent{Event: "accessed", Actor: actor, At: now, Note: purpose})
	cp := *it
	cp.Custody = append([]CustodyEvent(nil), it.Custody...)
	cp.AccessLog = append([]AccessLogEntry(nil), it.AccessLog...)
	return &cp, append([]byte(nil), it.body...), nil
}

// Verify сверяет digest с содержимым.
func (s *Store) Verify(tenantID, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.items[id]
	if !ok || it.TenantID != tenantID {
		return false, fmt.Errorf("evidence not found")
	}
	sum := sha256.Sum256(it.body)
	return "sha256:"+hex.EncodeToString(sum[:]) == it.Digest, nil
}

// Delete удаляет evidence, если нет legal hold.
func (s *Store) Delete(tenantID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.items[id]
	if !ok || it.TenantID != tenantID {
		return problem.New(problem.NotFound, "evidence not found")
	}
	if it.LegalHold {
		return problem.New(problem.LegalHold, "evidence %s is under legal hold", id)
	}
	delete(s.items, id)
	return nil
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
