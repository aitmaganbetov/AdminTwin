// Package testutil — помощники тестов коннекторов: тестовый PKI (mTLS) и проверка вывода
// инструментов по output_schema контрактов ai/tools/read. Только для тестов.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// PKI — тестовый удостоверяющий центр.
type PKI struct {
	CA    *x509.Certificate
	CAKey *ecdsa.PrivateKey
	CAPEM []byte
}

// NewPKI создаёт CA.
func NewPKI(t testing.TB) *PKI {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "admintwin-test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	return &PKI{CA: ca, CAKey: key, CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (p *PKI) issue(t testing.TB, cn string, server bool, serial int64) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if server {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tpl.DNSNames = []string{"localhost", cn}
	} else {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.CA, &key.PublicKey, p.CAKey)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

// ServerTLS — серверная конфигурация с обязательным клиентским сертификатом, выданным этим CA.
func (p *PKI) ServerTLS(t testing.TB, requireClient bool) *tls.Config {
	t.Helper()
	c, k := p.issue(t, "docker-test", true, 2)
	pair, err := tls.X509KeyPair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	if requireClient {
		pool := x509.NewCertPool()
		pool.AddCert(p.CA)
		cfg.ClientCAs, cfg.ClientAuth = pool, tls.RequireAndVerifyClientCert
	}
	return cfg
}

// Client — клиентский сертификат и ключ (PEM).
func (p *PKI) Client(t testing.TB) (certPEM, keyPEM []byte) { return p.issue(t, "admintwin", false, 3) }

// CertPEM кодирует сертификат.
func CertPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// RepoRoot — корень репозитория (по расположению этого файла).
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

// ValidateToolOutput проверяет data по output_schema инструмента (как это делает Tool Service).
func ValidateToolOutput(t testing.TB, tool string, data any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(RepoRoot(), "ai", "tools", "read", tool+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var ct struct {
		Output json.RawMessage `json:"output_schema"`
		Max    int             `json:"max_response_bytes"`
	}
	if err := json.Unmarshal(raw, &ct); err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(ct.Output)))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("mem://out.json", doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("mem://out.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if ct.Max > 0 && len(b) > ct.Max {
		t.Fatalf("%s output is %d bytes, contract max %d", tool, len(b), ct.Max)
	}
	var generic any
	_ = json.Unmarshal(b, &generic)
	if err := sch.Validate(generic); err != nil {
		t.Fatalf("%s output violates contract: %v\n%s", tool, err, b)
	}
}
