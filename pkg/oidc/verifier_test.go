package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestIdP — минимальный OIDC-провайдер для тестов (используется и e2e через пакет oidctest).
type testIdP struct {
	srv *httptest.Server
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

func newIdP(t *testing.T) *testIdP {
	t.Helper()
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	idp := &testIdP{rsa: rk, ec: ek}
	mux := http.NewServeMux()
	idp.srv = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": idp.srv.URL, "jwks_uri": idp.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		b := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "RSA", "kid": "r1", "use": "sig", "n": b(rk.N.Bytes()), "e": b(big.NewInt(int64(rk.E)).Bytes())},
			{"kty": "EC", "kid": "e1", "use": "sig", "crv": "P-256", "x": b(pad32(ek.X.Bytes())), "y": b(pad32(ek.Y.Bytes()))},
		}})
	})
	t.Cleanup(idp.srv.Close)
	return idp
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func (i *testIdP) sign(t *testing.T, alg, kid string, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	head := enc(map[string]string{"alg": alg, "kid": kid, "typ": "JWT"})
	body := enc(claims)
	in := head + "." + body
	d := sha256.Sum256([]byte(in))
	var sig []byte
	switch alg {
	case "RS256":
		sig, _ = rsa.SignPKCS1v15(rand.Reader, i.rsa, crypto.SHA256, d[:])
	case "PS256":
		sig, _ = rsa.SignPSS(rand.Reader, i.rsa, crypto.SHA256, d[:], nil)
	case "ES256":
		r, s, _ := ecdsa.Sign(rand.Reader, i.ec, d[:])
		sig = append(pad32(r.Bytes()), pad32(s.Bytes())...)
	case "HS256":
		// атака подмены алгоритма: HMAC с публичным модулем RSA в качестве ключа
		m := hmac.New(sha256.New, i.rsa.N.Bytes())
		m.Write([]byte(in))
		sig = m.Sum(nil)
	case "none":
		sig = nil
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (i *testIdP) claims(over map[string]any) map[string]any {
	c := map[string]any{"iss": i.srv.URL, "aud": "admintwin", "sub": "user-1", "exp": time.Now().Add(time.Hour).Unix(),
		"admintwin_tenant": "t1", "amr": []string{"pwd", "otp"}}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func TestVerify(t *testing.T) {
	idp := newIdP(t)
	v, err := New(Config{Issuer: idp.srv.URL, Audience: "admintwin"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, alg := range []string{"RS256", "PS256", "ES256"} {
		kid := "r1"
		if alg == "ES256" {
			kid = "e1"
		}
		c, err := v.Verify(ctx, idp.sign(t, alg, kid, idp.claims(nil)))
		if err != nil || c.Subject != "user-1" || c.String("admintwin_tenant") != "t1" {
			t.Fatalf("%s: valid token rejected: %v", alg, err)
		}
		if got := c.Strings("amr"); len(got) != 2 {
			t.Fatalf("amr: %v", got)
		}
	}
	bad := map[string]string{
		"alg none":       idp.sign(t, "none", "r1", idp.claims(nil)),
		"alg confusion":  idp.sign(t, "HS256", "r1", idp.claims(nil)),
		"wrong issuer":   idp.sign(t, "RS256", "r1", idp.claims(map[string]any{"iss": "https://evil.example"})),
		"wrong audience": idp.sign(t, "RS256", "r1", idp.claims(map[string]any{"aud": "other"})),
		"expired":        idp.sign(t, "RS256", "r1", idp.claims(map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})),
		"no exp":         idp.sign(t, "RS256", "r1", idp.claims(map[string]any{"exp": nil})),
		"not yet valid":  idp.sign(t, "RS256", "r1", idp.claims(map[string]any{"nbf": time.Now().Add(time.Hour).Unix()})),
		"unknown kid":    idp.sign(t, "RS256", "nope", idp.claims(nil)),
		"kid/alg swap":   idp.sign(t, "RS256", "e1", idp.claims(nil)),
		"garbage":        "a.b.c",
	}
	tampered := idp.sign(t, "RS256", "r1", idp.claims(nil))
	p := strings.Split(tampered, ".")
	forged, _ := json.Marshal(idp.claims(map[string]any{"admintwin_tenant": "t2"}))
	bad["tampered payload"] = p[0] + "." + base64.RawURLEncoding.EncodeToString(forged) + "." + p[2]
	for name, tok := range bad {
		if _, err := v.Verify(ctx, tok); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
	if _, err := New(Config{Issuer: "http://idp.example", Audience: "x"}); err == nil {
		t.Error("non-https issuer must be refused")
	}
}
