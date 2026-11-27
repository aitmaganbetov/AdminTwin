// Package discovery — Discovery (M03, §8.1, Приложение C.9). Контракт сборщиков.
// Сборщики реализуются в connectors/* и только читают (read-only); любые записи — через ChangeRequest.
package discovery

import (
	"context"

	"github.com/aitmaganbetov/admintwin/services/inventory"
)

// Target — объект сканирования в пределах Scope Document.
type Target struct {
	TenantID string
	Address  string // IP или hostname из разрешённого диапазона scope
	Port     int
	Method   string // ssh | docker_api | postgres | fortigate_api | snmpv3
	// CredentialRef — путь в Vault; сборщик получает материал через CredentialSource, не из параметров.
	CredentialRef string
	HostKey       string
	TLSServerName string
}

// Credential — материал доступа для сборщика (read-only учётная запись). Не журналируется.
type Credential struct {
	Username   string
	Password   string
	PrivateKey []byte
	Token      string
	ClientCert []byte
	ClientKey  []byte
	CACert     []byte
}

// String не раскрывает секреты.
func (Credential) String() string { return "Credential{[REDACTED]}" }

// CredentialSource выдаёт read-only учётку по ссылке Vault.
type CredentialSource interface {
	ReadOnly(ctx context.Context, tenantID, ref string) (Credential, error)
}

// Observation — результат сбора по одной цели.
type Observation struct {
	// Assets — обнаруженные объекты. ID может быть пустым: сопоставление с CMDB делает reconciliation
	// по (type, name/address). Атрибуты классификации (environment, criticality, owner) сборщик не угадывает.
	Assets []inventory.Asset
	// Dependencies — связи, Source/Target задаются через ключи Assets[i].Name.
	Dependencies []ObservedDependency
	// Confidence — уверенность в результате (0..1).
	Confidence float64
	Warnings   []string
}

// ObservedDependency — связь между обнаруженными объектами по их именам.
type ObservedDependency struct {
	SourceName   string
	TargetName   string
	RelationType string
	Confidence   float64
}

// Collector — read-only сборщик одного метода.
type Collector interface {
	Method() string
	Collect(ctx context.Context, t Target, cred Credential) (Observation, error)
}
