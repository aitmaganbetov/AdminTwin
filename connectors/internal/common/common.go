// Package common — общие помощники коннекторов: преобразование кредов, TLS, лимиты ответов.
// Пакет internal: используется только коннекторами AdminTwin.
package common

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/aitmaganbetov/admintwin/services/discovery"
	gateway "github.com/aitmaganbetov/admintwin/services/execution-gateway"
)

// ErrResponseTooLarge — ответ удалённой системы превысил лимит (защита от исчерпания памяти).
var ErrResponseTooLarge = errors.New("remote response exceeds size limit")

// ErrLeaseExpired — краткоживущий доступ истёк или не выдан (fail closed).
var ErrLeaseExpired = errors.New("credential lease expired or missing expiry")

// FromDiscovery преобразует read-only учётку сборщика в формат Gateway.
func FromDiscovery(c discovery.Credential) gateway.Credential {
	return gateway.Credential{
		Username: c.Username, Password: c.Password, PrivateKey: c.PrivateKey, Token: c.Token,
		ClientCert: c.ClientCert, ClientKey: c.ClientKey, CACert: c.CACert,
	}
}

// ToDiscovery — обратное преобразование.
func ToDiscovery(c gateway.Credential) discovery.Credential {
	return discovery.Credential{
		Username: c.Username, Password: c.Password, PrivateKey: c.PrivateKey, Token: c.Token,
		ClientCert: c.ClientCert, ClientKey: c.ClientKey, CACert: c.CACert,
	}
}

// CheckLease — аренда должна иметь срок и не истечь. Нулевой срок трактуется как отсутствие аренды.
func CheckLease(l gateway.Lease, now time.Time) error {
	if l.ExpiresAt.IsZero() || !now.Before(l.ExpiresAt) {
		return ErrLeaseExpired
	}
	return nil
}

// ReadLimited читает не более max байт; превышение — ошибка (ответ не усекается молча).
func ReadLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrResponseTooLarge
	}
	return b, nil
}

// HostPort собирает адрес host:port с портом по умолчанию.
func HostPort(addr string, port, def int) string {
	if port <= 0 {
		port = def
	}
	return net.JoinHostPort(addr, strconv.Itoa(port))
}

// TLSOptions — параметры TLS клиента.
type TLSOptions struct {
	ServerName string
	SkipVerify bool // только при явном Connection.TLSSkipVerify=true; журналируется предупреждение
	// RequireClientCert — для mTLS (Docker API): без клиентского сертификата — отказ.
	RequireClientCert bool
	Component         string // для журнала
	Address           string // для журнала (не секрет)
}

// TLSConfig строит клиентскую конфигурацию TLS: проверка сертификата обязательна, TLS ≥ 1.2.
// CA берётся из Credential.CACert (если задан), иначе — системные корни.
func TLSConfig(o TLSOptions, cred gateway.Credential, log *slog.Logger) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: o.ServerName}
	if len(cred.CACert) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cred.CACert) {
			return nil, fmt.Errorf("%s: CA certificate from vault is not valid PEM", o.Component)
		}
		cfg.RootCAs = pool
	}
	if len(cred.ClientCert) > 0 || len(cred.ClientKey) > 0 {
		pair, err := tls.X509KeyPair(cred.ClientCert, cred.ClientKey)
		if err != nil {
			// Текст ошибки crypto/tls не содержит ключа, но не пробрасываем его на всякий случай.
			return nil, fmt.Errorf("%s: client certificate/key from vault are invalid", o.Component)
		}
		cfg.Certificates = []tls.Certificate{pair}
	} else if o.RequireClientCert {
		return nil, fmt.Errorf("%s: mutual TLS requires client certificate and key in vault", o.Component)
	}
	if o.SkipVerify {
		if log == nil {
			log = slog.Default()
		}
		log.Warn("TLS certificate verification disabled by asset connection (tls_skip_verify=true)",
			"component", o.Component, "address", o.Address)
		cfg.InsecureSkipVerify = true //nolint:gosec // только по явному флагу актива, с предупреждением
	}
	return cfg, nil
}

// Logger возвращает журнал по умолчанию, если не задан.
func Logger(l *slog.Logger) *slog.Logger {
	if l == nil {
		return slog.Default()
	}
	return l
}

// Truncate обрезает строку до n байт по границе руны.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }
