package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func newLog(t *testing.T) (*Log, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return New(NewMemoryKeys(), priv), pub
}

func TestHashChainAndTamperDetection(t *testing.T) {
	l, _ := newLog(t)
	for i := 0; i < 5; i++ {
		if _, err := l.Append(Record{TenantID: "t1", Actor: "user:u", Action: "change.created", ObjectID: "c", Data: map[string]any{"i": i}}); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = l.Append(Record{TenantID: "t2", Actor: "user:x", Action: "a"})
	if ok, _, err := l.VerifyTenant("t1"); !ok || err != nil {
		t.Fatalf("chain must verify: %v", err)
	}
	chain := l.Entries("t1")
	chain[2].Data = map[string]any{"i": 999}
	if ok, at, _ := Verify(chain); ok || at != 3 {
		t.Fatalf("tampering must be detected at seq 3, got ok=%v at=%d", ok, at)
	}
	chain = l.Entries("t1")
	chain = append(chain[:1], chain[2:]...)
	if ok, _, _ := Verify(chain); ok {
		t.Fatal("deletion must be detected")
	}
	if len(l.Entries("t2")) != 1 {
		t.Fatal("tenant chains must be separate")
	}
}

func TestCheckpointSignature(t *testing.T) {
	l, pub := newLog(t)
	_, _ = l.Append(Record{TenantID: "t1", Actor: "a", Action: "x"})
	cp, err := l.Checkpoint("t1")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyCheckpoint(pub, cp) {
		t.Fatal("checkpoint signature must verify")
	}
	cp.Seq++
	if VerifyCheckpoint(pub, cp) {
		t.Fatal("altered checkpoint must not verify")
	}
}

// Crypto-shredding: уничтожение ключа делает ПДн нечитаемыми, цепочка остаётся целой (§9.1).
func TestCryptoShredding(t *testing.T) {
	l, _ := newLog(t)
	e, err := l.Append(Record{TenantID: "t1", Actor: "user:u1", Action: "login", PII: map[string]string{"email": "ivanov@example.kz"}})
	if err != nil {
		t.Fatal(err)
	}
	if e.PII == "" || e.Data != nil {
		t.Fatal("PII must be stored encrypted only")
	}
	got, err := l.RevealPII(e)
	if err != nil || got["email"] != "ivanov@example.kz" {
		t.Fatalf("reveal before shredding: %v %v", got, err)
	}
	if err := l.ShredTenantPII("t1"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.RevealPII(e); !errors.Is(err, ErrShredded) {
		t.Fatalf("PII must be unreadable after shredding, got %v", err)
	}
	if ok, _, err := l.VerifyTenant("t1"); !ok || err != nil {
		t.Fatalf("hash chain must survive shredding: %v", err)
	}
}
