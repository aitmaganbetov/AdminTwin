// Package vault — CredentialBroker поверх HashiCorp Vault / OpenBao (HTTP API, §11.2 п.6, §18.4).
//
// Gateway получает краткоживущий доступ (Lease) на время runbook: секрет читается из KV v2 по пути
// inventory.Connection.CredentialRef; для динамических секретов (`database/creds/<role>`) используется
// настоящая аренда Vault, которая отзывается после исполнения. Сборщики и read-only коннекторы получают
// отдельную read-only учётку (CredentialSource, соглашение — см. ReadOnly).
//
// Fail closed (§17.2): Vault недоступен, запечатан, вернул неожиданный ответ — ошибка, исполнения невозможны.
// Секреты не журналируются и не попадают в тексты ошибок.
package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aitmaganbetov/admintwin/services/discovery"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
)

// Ошибки брокера. Тексты не содержат секретов, токенов и тел ответов Vault.
var (
	ErrSealed      = errors.New("vault is sealed or unavailable")
	ErrUnreachable = errors.New("vault is unreachable")
	ErrNotFound    = errors.New("secret not found in vault")
	ErrForbidden   = errors.New("vault denied access to secret")
	ErrBadRef      = errors.New("invalid credential reference")
	ErrNoReadOnly  = errors.New("read-only credential is not configured for this reference")
	ErrEmptySecret = errors.New("secret contains no credential material")
)

const (
	maxResponseBytes = 1 << 20 // ответ Vault больше 1 МиБ — отказ
	maxLeaseTTL      = time.Hour
	defaultTimeout   = 10 * time.Second
)

// Config — параметры подключения к Vault/OpenBao.
type Config struct {
	// Addr — адрес Vault, например https://vault.internal:8200 (VAULT_ADDR). Только https,
	// если явно не разрешено AllowHTTP (dev-стенд на loopback).
	Addr string
	// Token — статический токен (VAULT_TOKEN). Если пуст — используется AppRole.
	Token string
	// RoleID/SecretID — AppRole (VAULT_ROLE_ID / VAULT_SECRET_ID), mount — VAULT_APPROLE_MOUNT (approle).
	RoleID, SecretID string
	AppRoleMount     string
	// Namespace — Vault Enterprise / OpenBao namespace (VAULT_NAMESPACE).
	Namespace string
	// CACert — PEM корневых сертификатов Vault (содержимое файла VAULT_CACERT). Пусто — системные корни.
	CACert []byte
	// AllowHTTP — разрешить http:// (только loopback dev). Проверка TLS при https не отключается никогда.
	AllowHTTP bool
	// TenantScoped — путь секрета обязан содержать tenant_id отдельным сегментом
	// (например, kv/data/tenants/<tid>/assets/<id>/ssh) — защита от чтения чужого секрета.
	TenantScoped bool
	Timeout      time.Duration
	Logger       *slog.Logger
	// HTTPClient — для тестов; Transport должен проверять TLS.
	HTTPClient *http.Client
	Now        func() time.Time
}

// ConfigFromEnv читает стандартные переменные окружения Vault.
// ADMINTWIN_VAULT_TENANT_SCOPED=false отключает проверку tenant-сегмента пути (по умолчанию включена).
func ConfigFromEnv() (Config, error) {
	cfg := Config{
		Addr: os.Getenv("VAULT_ADDR"), Token: os.Getenv("VAULT_TOKEN"),
		RoleID: os.Getenv("VAULT_ROLE_ID"), SecretID: os.Getenv("VAULT_SECRET_ID"),
		AppRoleMount: os.Getenv("VAULT_APPROLE_MOUNT"), Namespace: os.Getenv("VAULT_NAMESPACE"),
		TenantScoped: os.Getenv("ADMINTWIN_VAULT_TENANT_SCOPED") != "false",
	}
	if p := os.Getenv("VAULT_CACERT"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return Config{}, fmt.Errorf("vault: read VAULT_CACERT: %w", err)
		}
		cfg.CACert = b
	}
	return cfg, nil
}

// Broker реализует gateway.CredentialBroker и discovery.CredentialSource.
type Broker struct {
	cfg    Config
	base   *url.URL
	client *http.Client
	log    *slog.Logger

	mu       sync.Mutex
	tok      string
	tokUntil time.Time // для AppRole: момент обновления токена
	leases   map[string]leaseInfo
}

type leaseInfo struct {
	vaultLeaseID string // пусто для KV (отзывать нечего)
	expires      time.Time
}

var (
	_ gateway.CredentialBroker   = (*Broker)(nil)
	_ discovery.CredentialSource = (*Broker)(nil)
)

// New создаёт брокер. Ошибка конфигурации — отказ старта (fail closed).
func New(cfg Config) (*Broker, error) {
	if cfg.Addr == "" {
		return nil, errors.New("vault: address is not configured (VAULT_ADDR)")
	}
	u, err := url.Parse(strings.TrimRight(cfg.Addr, "/"))
	if err != nil || u.Host == "" {
		return nil, errors.New("vault: invalid address")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !cfg.AllowHTTP {
			return nil, errors.New("vault: plain http is not allowed; use https with certificate verification")
		}
	default:
		return nil, errors.New("vault: address scheme must be https")
	}
	if cfg.Token == "" && (cfg.RoleID == "" || cfg.SecretID == "") {
		return nil, errors.New("vault: neither token nor AppRole role_id/secret_id configured")
	}
	if cfg.AppRoleMount == "" {
		cfg.AppRoleMount = "approle"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	client := cfg.HTTPClient
	if client == nil {
		tc := &tls.Config{MinVersion: tls.VersionTLS12}
		if len(cfg.CACert) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(cfg.CACert) {
				return nil, errors.New("vault: VAULT_CACERT is not valid PEM")
			}
			tc.RootCAs = pool
		}
		client = &http.Client{
			Timeout:   cfg.Timeout,
			Transport: &http.Transport{TLSClientConfig: tc, Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: cfg.Timeout},
			// Перенаправления Vault (standby → active) не следуем: токен не должен уходить на другой адрес.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &Broker{cfg: cfg, base: u, client: client, log: log, tok: cfg.Token, leases: map[string]leaseInfo{}}, nil
}

// Lease выдаёт краткоживущий доступ для исполнения: читает секрет по credentialRef.
// ExpiresAt = now + ttl (для динамического секрета — не позже срока аренды Vault).
func (b *Broker) Lease(ctx context.Context, tenantID, assetID, credentialRef string, ttl time.Duration) (gateway.Lease, error) {
	if ttl <= 0 {
		return gateway.Lease{}, errors.New("vault: lease ttl must be positive")
	}
	if ttl > maxLeaseTTL {
		ttl = maxLeaseTTL
	}
	ref, err := b.checkRef(tenantID, credentialRef)
	if err != nil {
		return gateway.Lease{}, err
	}
	sec, err := b.read(ctx, ref)
	if err != nil {
		return gateway.Lease{}, err
	}
	cred, err := credentialFrom(sec.data)
	if err != nil {
		b.revokeVaultLease(sec.leaseID)
		return gateway.Lease{}, err
	}
	now := b.cfg.Now()
	exp := now.Add(ttl)
	if sec.leaseID != "" && sec.leaseDuration > 0 {
		if vexp := now.Add(sec.leaseDuration); vexp.Before(exp) {
			exp = vexp
		}
	}
	handle := newHandle()
	b.mu.Lock()
	b.purgeLocked(now)
	b.leases[handle] = leaseInfo{vaultLeaseID: sec.leaseID, expires: exp}
	b.mu.Unlock()
	b.log.Info("credential lease issued", "tenant_id", tenantID, "asset_id", assetID, "handle", handle,
		"dynamic", sec.leaseID != "", "expires_at", exp.UTC().Format(time.RFC3339))
	return gateway.Lease{Handle: handle, ExpiresAt: exp, Credential: cred}, nil
}

// Revoke завершает аренду. Для KV v2 отзывать в Vault нечего (хук сохраняет учёт аренд);
// для динамического секрета вызывается sys/leases/revoke.
func (b *Broker) Revoke(ctx context.Context, l gateway.Lease) error {
	b.mu.Lock()
	info, ok := b.leases[l.Handle]
	delete(b.leases, l.Handle)
	b.mu.Unlock()
	if !ok || info.vaultLeaseID == "" {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, b.cfg.Timeout)
	defer cancel()
	if _, err := b.call(cctx, http.MethodPut, "sys/leases/revoke", map[string]string{"lease_id": info.vaultLeaseID}, nil); err != nil {
		b.log.Warn("vault lease revoke failed; lease will expire by its ttl", "handle", l.Handle, "error", err.Error())
		return err
	}
	b.log.Info("credential lease revoked", "handle", l.Handle)
	return nil
}

// ActiveLeases — число невыведенных аренд (для метрик и тестов).
func (b *Broker) ActiveLeases() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.purgeLocked(b.cfg.Now())
	return len(b.leases)
}

// ReadOnly выдаёт read-only учётку для сборщиков, Facts и read tools. Соглашение:
//  1. секрет `<ref>-readonly` (тот же mount, к последнему сегменту пути добавляется «-readonly»);
//  2. если его нет — вложенный объект `readonly` внутри секрета `<ref>`
//     (например, {"username":"root",...,"readonly":{"username":"admintwin-ro",...}}).
//
// Учётка исполнения никогда не выдаётся вместо read-only: нет ни того, ни другого — ErrNoReadOnly.
func (b *Broker) ReadOnly(ctx context.Context, tenantID, ref string) (discovery.Credential, error) {
	ref, err := b.checkRef(tenantID, ref)
	if err != nil {
		return discovery.Credential{}, err
	}
	sec, err := b.read(ctx, ref+"-readonly")
	switch {
	case err == nil:
		// Динамический read-only секрет живёт до истечения своего TTL в Vault (короткий default_ttl роли).
		c, cerr := credentialFrom(sec.data)
		return toDiscovery(c), cerr
	case !errors.Is(err, ErrNotFound):
		return discovery.Credential{}, err
	}
	sec, err = b.read(ctx, ref)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return discovery.Credential{}, ErrNoReadOnly
		}
		return discovery.Credential{}, err
	}
	sub, ok := sec.data["readonly"].(map[string]any)
	if !ok {
		b.revokeVaultLease(sec.leaseID)
		return discovery.Credential{}, ErrNoReadOnly
	}
	c, err := credentialFrom(sub)
	return toDiscovery(c), err
}

// Health проверяет, что Vault инициализирован и распечатан (sys/health).
func (b *Broker) Health(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, b.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, b.endpoint("sys/health"), nil)
	if err != nil {
		return err
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return ErrUnreachable
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusTooManyRequests, 473: // active, standby, performance standby
		return nil
	}
	return ErrSealed
}

// --- внутреннее ---

var refRe = regexp.MustCompile(`^[A-Za-z0-9_.@-]+(/[A-Za-z0-9_.@-]+)+$`)

// checkRef — путь секрета: без «..», без пустых сегментов; только чтение данных (не metadata/sys/auth);
// при TenantScoped — tenant_id отдельным сегментом пути (или префиксом имени роли database/creds/<tid>-...).
func (b *Broker) checkRef(tenantID, ref string) (string, error) {
	ref = strings.TrimPrefix(strings.TrimSpace(ref), "v1/")
	if ref == "" || !refRe.MatchString(ref) {
		return "", ErrBadRef
	}
	segs := strings.Split(ref, "/")
	for _, s := range segs {
		if s == "." || s == ".." {
			return "", ErrBadRef
		}
	}
	switch segs[0] {
	case "sys", "auth", "identity", "cubbyhole":
		return "", ErrBadRef
	}
	if len(segs) > 1 && (segs[1] == "metadata" || segs[1] == "delete" || segs[1] == "destroy" || segs[1] == "undelete") {
		return "", ErrBadRef
	}
	if b.cfg.TenantScoped {
		if tenantID == "" {
			return "", ErrBadRef
		}
		ok := false
		for _, s := range segs {
			if s == tenantID {
				ok = true
			}
		}
		if isDynamic(segs) && strings.HasPrefix(segs[len(segs)-1], tenantID+"-") {
			ok = true
		}
		if !ok {
			return "", fmt.Errorf("%w: path is not scoped to the tenant", ErrBadRef)
		}
	}
	return ref, nil
}

func isDynamic(segs []string) bool { return len(segs) >= 3 && segs[1] == "creds" }

func isKV2(segs []string) bool { return len(segs) >= 3 && segs[1] == "data" }

type secret struct {
	data          map[string]any
	leaseID       string
	leaseDuration time.Duration
}

func (b *Broker) read(ctx context.Context, ref string) (secret, error) {
	cctx, cancel := context.WithTimeout(ctx, b.cfg.Timeout)
	defer cancel()
	var resp struct {
		LeaseID       string          `json:"lease_id"`
		LeaseDuration int64           `json:"lease_duration"`
		Data          json.RawMessage `json:"data"`
	}
	if _, err := b.call(cctx, http.MethodGet, ref, nil, &resp); err != nil {
		return secret{}, err
	}
	segs := strings.Split(ref, "/")
	var data map[string]any
	if isKV2(segs) {
		var kv struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(resp.Data, &kv); err != nil || kv.Data == nil {
			// Удалённая (soft-deleted) версия KV v2: data = null.
			return secret{}, ErrNotFound
		}
		data = kv.Data
	} else if err := json.Unmarshal(resp.Data, &data); err != nil || data == nil {
		return secret{}, ErrEmptySecret
	}
	return secret{data: data, leaseID: resp.LeaseID, leaseDuration: time.Duration(resp.LeaseDuration) * time.Second}, nil
}

// call — запрос к Vault с токеном. Для AppRole при 403 токен обновляется один раз.
func (b *Broker) call(ctx context.Context, method, path string, body, out any) (int, error) {
	for attempt := 0; ; attempt++ {
		tok, err := b.token(ctx)
		if err != nil {
			return 0, err
		}
		status, err := b.raw(ctx, method, path, tok, body, out)
		if status == http.StatusForbidden && attempt == 0 && b.cfg.Token == "" {
			b.mu.Lock()
			b.tok, b.tokUntil = "", time.Time{}
			b.mu.Unlock()
			continue
		}
		return status, err
	}
}

func (b *Broker) token(ctx context.Context) (string, error) {
	b.mu.Lock()
	if b.cfg.Token != "" {
		defer b.mu.Unlock()
		return b.cfg.Token, nil
	}
	if b.tok != "" && b.cfg.Now().Before(b.tokUntil) {
		t := b.tok
		b.mu.Unlock()
		return t, nil
	}
	b.mu.Unlock()

	var resp struct {
		Auth *struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	login := map[string]string{"role_id": b.cfg.RoleID, "secret_id": b.cfg.SecretID}
	cctx, cancel := context.WithTimeout(ctx, b.cfg.Timeout)
	defer cancel()
	if _, err := b.raw(cctx, http.MethodPost, "auth/"+b.cfg.AppRoleMount+"/login", "", login, &resp); err != nil {
		if errors.Is(err, ErrForbidden) || errors.Is(err, ErrNotFound) {
			return "", errors.New("vault: approle login rejected")
		}
		return "", err
	}
	if resp.Auth == nil || resp.Auth.ClientToken == "" {
		return "", errors.New("vault: approle login returned no token")
	}
	ttl := time.Duration(resp.Auth.LeaseDuration) * time.Second
	// Обновляем токен заранее: за 30 с или на половине срока для коротких токенов.
	margin := 30 * time.Second
	if ttl < 2*margin {
		margin = ttl / 2
	}
	b.mu.Lock()
	b.tok, b.tokUntil = resp.Auth.ClientToken, b.cfg.Now().Add(ttl-margin)
	b.mu.Unlock()
	return resp.Auth.ClientToken, nil
}

func (b *Broker) endpoint(path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return b.base.String() + "/v1/" + strings.Join(segs, "/")
}

// raw выполняет HTTP-запрос. Тело ошибки Vault не читается в текст ошибки.
func (b *Broker) raw(ctx context.Context, method, path, token string, body, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.endpoint(path), rd)
	if err != nil {
		return 0, ErrBadRef
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if b.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", b.cfg.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Vault-Request", "true")
	resp, err := b.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, fmt.Errorf("%w: %v", ErrUnreachable, ctx.Err())
		}
		// url.Error содержит адрес и путь; наружу — только класс ошибки.
		return 0, ErrUnreachable
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return resp.StatusCode, ErrUnreachable
	}
	if len(raw) > maxResponseBytes {
		return resp.StatusCode, errors.New("vault: response exceeds size limit")
	}
	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent:
	case resp.StatusCode == http.StatusNotFound:
		return resp.StatusCode, ErrNotFound
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		return resp.StatusCode, ErrForbidden
	case resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode == 473 || resp.StatusCode == http.StatusNotImplemented:
		return resp.StatusCode, ErrSealed
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return resp.StatusCode, fmt.Errorf("vault: unexpected redirect (status %d)", resp.StatusCode)
	default:
		return resp.StatusCode, fmt.Errorf("vault: unexpected status %d", resp.StatusCode)
	}
	if out != nil && resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, errors.New("vault: malformed response")
		}
	}
	return resp.StatusCode, nil
}

func (b *Broker) revokeVaultLease(id string) {
	if id == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), b.cfg.Timeout)
	defer cancel()
	_, _ = b.call(ctx, http.MethodPut, "sys/leases/revoke", map[string]string{"lease_id": id}, nil)
}

func (b *Broker) purgeLocked(now time.Time) {
	for h, l := range b.leases {
		if !now.Before(l.expires) {
			delete(b.leases, h)
		}
	}
}

func newHandle() string {
	buf := make([]byte, 12)
	_, _ = rand.Read(buf)
	return "lease-" + hex.EncodeToString(buf)
}

// credentialFrom — поля секрета: username, password, private_key (ssh_private_key), token (api_token),
// client_cert (tls_cert), client_key (tls_key), ca_cert (tls_ca). Неизвестные поля игнорируются.
func credentialFrom(m map[string]any) (gateway.Credential, error) {
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := m[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	c := gateway.Credential{
		Username:   str("username", "user"),
		Password:   str("password"),
		PrivateKey: bytesOrNil(str("private_key", "ssh_private_key")),
		Token:      str("token", "api_token", "api_key"),
		ClientCert: bytesOrNil(str("client_cert", "tls_cert")),
		ClientKey:  bytesOrNil(str("client_key", "tls_key")),
		CACert:     bytesOrNil(str("ca_cert", "tls_ca")),
	}
	if c.Empty() && len(c.CACert) == 0 {
		return gateway.Credential{}, ErrEmptySecret
	}
	return c, nil
}

func bytesOrNil(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}

func toDiscovery(c gateway.Credential) discovery.Credential {
	return discovery.Credential{Username: c.Username, Password: c.Password, PrivateKey: c.PrivateKey, Token: c.Token,
		ClientCert: c.ClientCert, ClientKey: c.ClientKey, CACert: c.CACert}
}
