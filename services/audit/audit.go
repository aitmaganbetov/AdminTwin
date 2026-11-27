// Package audit — неизменяемый журнал (§12 «Аудит»): append-only, hash chain на tenant,
// подписанные checkpoint'ы, верификация, crypto-shredding ПДн-полей (§9.1, ADR-016).
//
// ПДн-поля записи шифруются ключом tenant (AES-256-GCM); хэш считается по шифртексту,
// поэтому уничтожение ключа делает ПДн нечитаемыми, а цепочка остаётся верифицируемой.
package audit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Entry — запись журнала.
type Entry struct {
	Seq        uint64         `json:"seq"`
	TenantID   string         `json:"tenant_id"`
	At         time.Time      `json:"at"`
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	ObjectType string         `json:"object_type"`
	ObjectID   string         `json:"object_id"`
	Data       map[string]any `json:"data,omitempty"`
	// PII — зашифрованные ПДн-поля (base64 nonce||ciphertext); пусто, если ПДн нет.
	PII      string `json:"pii,omitempty"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Record — входные данные для записи.
type Record struct {
	TenantID   string
	Actor      string
	Action     string
	ObjectType string
	ObjectID   string
	Data       map[string]any
	PII        map[string]string
}

// KeyStore выдаёт ключи tenant для ПДн. В production — Vault Transit / KMS.
type KeyStore interface {
	Key(tenantID string) ([]byte, error)
	Shred(tenantID string) error
}

// ErrShredded — ключ уничтожен.
var ErrShredded = errors.New("pii key shredded")

// MemoryKeys — in-memory KeyStore (dev/test).
type MemoryKeys struct {
	mu       sync.Mutex
	keys     map[string][]byte
	shredded map[string]bool
}

// NewMemoryKeys создаёт хранилище ключей.
func NewMemoryKeys() *MemoryKeys {
	return &MemoryKeys{keys: map[string][]byte{}, shredded: map[string]bool{}}
}

// Key возвращает (создаёт при необходимости) ключ tenant.
func (m *MemoryKeys) Key(t string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.shredded[t] {
		return nil, ErrShredded
	}
	k, ok := m.keys[t]
	if !ok {
		k = make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		m.keys[t] = k
	}
	return k, nil
}

// Shred необратимо уничтожает ключ.
func (m *MemoryKeys) Shred(t string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, t)
	m.shredded[t] = true
	return nil
}

// Checkpoint — подписанная фиксация головы цепочки (в production — в MinIO Object Lock).
type Checkpoint struct {
	TenantID  string    `json:"tenant_id"`
	Seq       uint64    `json:"seq"`
	Hash      string    `json:"hash"`
	At        time.Time `json:"at"`
	Signature string    `json:"signature"`
}

// Log — журнал аудита.
type Log struct {
	mu     sync.Mutex
	chains map[string][]Entry
	keys   KeyStore
	signer ed25519.PrivateKey
	now    func() time.Time
}

// New создаёт журнал. signer — ключ подписи checkpoint'ов.
func New(keys KeyStore, signer ed25519.PrivateKey) *Log {
	return &Log{chains: map[string][]Entry{}, keys: keys, signer: signer, now: time.Now}
}

// Append добавляет запись. Изменение и удаление записей не предусмотрены.
func (l *Log) Append(r Record) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	chain := l.chains[r.TenantID]
	e := Entry{
		Seq: uint64(len(chain)) + 1, TenantID: r.TenantID, At: l.now().UTC(),
		Actor: r.Actor, Action: r.Action, ObjectType: r.ObjectType, ObjectID: r.ObjectID, Data: r.Data,
		PrevHash: genesis(r.TenantID),
	}
	if len(chain) > 0 {
		e.PrevHash = chain[len(chain)-1].Hash
	}
	if len(r.PII) > 0 {
		ct, err := l.seal(r.TenantID, r.PII)
		if err != nil {
			return Entry{}, err
		}
		e.PII = ct
	}
	h, err := hashEntry(e)
	if err != nil {
		return Entry{}, err
	}
	e.Hash = h
	l.chains[r.TenantID] = append(chain, e)
	return e, nil
}

// Entries возвращает копию цепочки tenant.
func (l *Log) Entries(tenantID string) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Entry(nil), l.chains[tenantID]...)
}

// Verify проверяет непрерывность и хэши цепочки. Возвращает номер первой испорченной записи.
func Verify(chain []Entry) (bool, uint64, error) {
	if len(chain) == 0 {
		return true, 0, nil
	}
	prev := genesis(chain[0].TenantID)
	for i, e := range chain {
		if e.Seq != uint64(i)+1 || e.PrevHash != prev {
			return false, e.Seq, fmt.Errorf("chain broken at seq %d", e.Seq)
		}
		h, err := hashEntry(e)
		if err != nil {
			return false, e.Seq, err
		}
		if h != e.Hash {
			return false, e.Seq, fmt.Errorf("hash mismatch at seq %d", e.Seq)
		}
		prev = e.Hash
	}
	return true, 0, nil
}

// VerifyTenant проверяет цепочку tenant.
func (l *Log) VerifyTenant(tenantID string) (bool, uint64, error) { return Verify(l.Entries(tenantID)) }

// Checkpoint подписывает текущую голову цепочки.
func (l *Log) Checkpoint(tenantID string) (Checkpoint, error) {
	chain := l.Entries(tenantID)
	cp := Checkpoint{TenantID: tenantID, At: l.now().UTC(), Hash: genesis(tenantID)}
	if n := len(chain); n > 0 {
		cp.Seq, cp.Hash = chain[n-1].Seq, chain[n-1].Hash
	}
	sig := ed25519.Sign(l.signer, checkpointMessage(cp))
	cp.Signature = base64.StdEncoding.EncodeToString(sig)
	return cp, nil
}

// VerifyCheckpoint проверяет подпись checkpoint.
func VerifyCheckpoint(pub ed25519.PublicKey, cp Checkpoint) bool {
	sig, err := base64.StdEncoding.DecodeString(cp.Signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, checkpointMessage(cp), sig)
}

// RevealPII расшифровывает ПДн-поля записи (только для ролей с правом чтения аудита).
func (l *Log) RevealPII(e Entry) (map[string]string, error) {
	if e.PII == "" {
		return nil, nil
	}
	key, err := l.keys.Key(e.TenantID)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(e.PII)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("pii ciphertext too short")
	}
	pt, err := gcm.Open(nil, raw[:ns], raw[ns:], []byte(e.TenantID))
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	return out, json.Unmarshal(pt, &out)
}

// ShredTenantPII уничтожает ключ ПДн tenant (право на удаление). Цепочка остаётся целой.
func (l *Log) ShredTenantPII(tenantID string) error { return l.keys.Shred(tenantID) }

func (l *Log) seal(tenantID string, pii map[string]string) (string, error) {
	key, err := l.keys.Key(tenantID)
	if err != nil {
		return "", err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	pt, _ := json.Marshal(pii)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, pt, []byte(tenantID))
	return base64.StdEncoding.EncodeToString(ct), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func genesis(tenantID string) string {
	s := sha256.Sum256([]byte("admintwin-audit-genesis:" + tenantID))
	return hex.EncodeToString(s[:])
}

func hashEntry(e Entry) (string, error) {
	e.Hash = ""
	// encoding/json сортирует ключи map — сериализация детерминирована.
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

func checkpointMessage(cp Checkpoint) []byte {
	return []byte(fmt.Sprintf("%s|%d|%s|%s", cp.TenantID, cp.Seq, cp.Hash, cp.At.Format(time.RFC3339Nano)))
}
