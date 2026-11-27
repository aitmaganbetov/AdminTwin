// Package oidc — проверка ID/access-токенов OIDC (JWT) поставщика SSO (§2.1: OIDC/SAML SSO, MFA).
// Реализовано на стандартной криптографии Go: JWKS с кэшем, алгоритмы RS256/PS256/ES256 (allowlist),
// проверка iss, aud, exp, nbf с допуском рассинхронизации часов. Токены с alg=none или HS* отклоняются.
package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// Config — параметры доверия к IdP.
type Config struct {
	Issuer   string
	Audience string
	// JWKSURL — если пусто, берётся из {Issuer}/.well-known/openid-configuration.
	JWKSURL string
	Leeway  time.Duration
	Client  *http.Client
}

// Claims — проверенные утверждения токена.
type Claims struct {
	Subject string
	Issuer  string
	Expiry  time.Time
	Raw     map[string]any
}

// String возвращает строковое утверждение.
func (c Claims) String(name string) string {
	s, _ := c.Raw[name].(string)
	return s
}

// Strings возвращает массив строк (или строку с разделителями пробел/запятая).
func (c Claims) Strings(name string) []string {
	switch v := c.Raw[name].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ',' })
	}
	return nil
}

// ErrInvalidToken — общий отказ (детали не раскрываются клиенту).
var ErrInvalidToken = errors.New("invalid token")

// Verifier проверяет токены.
type Verifier struct {
	cfg       Config
	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
	lastTry   time.Time
	now       func() time.Time
}

// New создаёт верификатор. Ключи загружаются лениво.
func New(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("oidc: issuer and audience are required")
	}
	if !strings.HasPrefix(cfg.Issuer, "https://") && !strings.HasPrefix(cfg.Issuer, "http://127.0.0.1") && !strings.HasPrefix(cfg.Issuer, "http://localhost") {
		return nil, errors.New("oidc: issuer must use https")
	}
	if cfg.Leeway == 0 {
		cfg.Leeway = 60 * time.Second
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Verifier{cfg: cfg, keys: map[string]crypto.PublicKey{}, now: time.Now}, nil
}

var allowedAlgs = []string{"RS256", "PS256", "ES256"}

// Verify проверяет подпись и стандартные утверждения.
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 16<<10 {
		return Claims{}, ErrInvalidToken
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := decodeSeg(parts[0], &hdr); err != nil || !slices.Contains(allowedAlgs, hdr.Alg) {
		return Claims{}, ErrInvalidToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	key, err := v.key(ctx, hdr.Kid)
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !verifySig(hdr.Alg, key, digest[:], sig) {
		return Claims{}, ErrInvalidToken
	}
	var raw map[string]any
	if err := decodeSeg(parts[1], &raw); err != nil {
		return Claims{}, ErrInvalidToken
	}
	c := Claims{Raw: raw}
	c.Subject, _ = raw["sub"].(string)
	c.Issuer, _ = raw["iss"].(string)
	if c.Subject == "" || c.Issuer != v.cfg.Issuer || !audienceOK(raw["aud"], v.cfg.Audience) {
		return Claims{}, ErrInvalidToken
	}
	now := v.now()
	exp, ok := numClaim(raw["exp"])
	if !ok || now.After(time.Unix(exp, 0).Add(v.cfg.Leeway)) {
		return Claims{}, ErrInvalidToken
	}
	c.Expiry = time.Unix(exp, 0)
	if nbf, ok := numClaim(raw["nbf"]); ok && now.Add(v.cfg.Leeway).Before(time.Unix(nbf, 0)) {
		return Claims{}, ErrInvalidToken
	}
	return c, nil
}

func verifySig(alg string, key crypto.PublicKey, digest, sig []byte) bool {
	switch alg {
	case "RS256":
		k, ok := key.(*rsa.PublicKey)
		return ok && k.N.BitLen() >= 2048 && rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig) == nil
	case "PS256":
		k, ok := key.(*rsa.PublicKey)
		return ok && k.N.BitLen() >= 2048 && rsa.VerifyPSS(k, crypto.SHA256, digest, sig, nil) == nil
	case "ES256":
		k, ok := key.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() || len(sig) != 64 {
			return false
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(k, digest, r, s)
	}
	return false
}

func audienceOK(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func numClaim(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	}
	return 0, false
}

func decodeSeg(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// key возвращает ключ по kid; при неизвестном kid перечитывает JWKS не чаще раза в 30 с.
func (v *Verifier) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	v.mu.RLock()
	k, ok := v.keys[kid]
	stale := time.Since(v.fetchedAt) > 10*time.Minute
	v.mu.RUnlock()
	if ok && !stale {
		return k, nil
	}
	v.mu.Lock()
	if time.Since(v.lastTry) < 30*time.Second && !v.fetchedAt.IsZero() {
		k, ok = v.keys[kid]
		v.mu.Unlock()
		if ok {
			return k, nil
		}
		return nil, errors.New("unknown kid")
	}
	v.lastTry = time.Now()
	v.mu.Unlock()
	keys, err := v.fetch(ctx)
	if err != nil {
		v.mu.RLock()
		k, ok = v.keys[kid]
		v.mu.RUnlock()
		if ok {
			return k, nil // используем кэш при временной недоступности IdP
		}
		return nil, err
	}
	v.mu.Lock()
	v.keys, v.fetchedAt = keys, time.Now()
	k, ok = keys[kid]
	v.mu.Unlock()
	if !ok {
		return nil, errors.New("unknown kid")
	}
	return k, nil
}

func (v *Verifier) fetch(ctx context.Context) (map[string]crypto.PublicKey, error) {
	url := v.cfg.JWKSURL
	if url == "" {
		var disc struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		if err := v.getJSON(ctx, strings.TrimRight(v.cfg.Issuer, "/")+"/.well-known/openid-configuration", &disc); err != nil {
			return nil, err
		}
		if disc.Issuer != v.cfg.Issuer || disc.JWKSURI == "" {
			return nil, errors.New("oidc: discovery document mismatch")
		}
		url = disc.JWKSURI
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := v.getJSON(ctx, url, &set); err != nil {
		return nil, err
	}
	out := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pk, err := k.public()
		if err == nil {
			out[k.Kid] = pk
		}
	}
	if len(out) == 0 {
		return nil, errors.New("oidc: no usable signing keys")
	}
	return out, nil
}

func (v *Verifier) getJSON(ctx context.Context, url string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := v.cfg.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc: %s returned %d", url, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(dst)
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (k jwk) public() (crypto.PublicKey, error) {
	dec := base64.RawURLEncoding.DecodeString
	switch k.Kty {
	case "RSA":
		n, err1 := dec(k.N)
		e, err2 := dec(k.E)
		if err1 != nil || err2 != nil || len(e) > 4 {
			return nil, errors.New("bad rsa jwk")
		}
		ei := 0
		for _, b := range e {
			ei = ei<<8 | int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: ei}, nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, errors.New("unsupported curve")
		}
		x, err1 := dec(k.X)
		y, err2 := dec(k.Y)
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad ec jwk")
		}
		pk := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pk.Curve.IsOnCurve(pk.X, pk.Y) { //nolint:staticcheck // проверка точки на кривой
			return nil, errors.New("ec point not on curve")
		}
		return pk, nil
	}
	return nil, errors.New("unsupported kty")
}
