package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aitmaganbetov/admintwin/pkg/db"
)

// PGStore — CMDB в PostgreSQL (RLS). Граф — recursive CTE (ADR-004, MVP).
type PGStore struct {
	DB      *db.DB
	Timeout time.Duration
}

var _ Repository = (*PGStore)(nil)

// NewPGStore создаёт хранилище.
func NewPGStore(d *db.DB) *PGStore { return &PGStore{DB: d, Timeout: 5 * time.Second} }

func (s *PGStore) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), s.Timeout)
}

const assetCols = `id, tenant_id, name, type, coalesce(environment,''), coalesce(ring,''), service_tier, coalesce(criticality,''),
	coalesce(data_class,''), legal_hold, coalesce(owner,''), verified, reachability, active_investigation,
	coalesce(health_endpoint,''), objects, protected, connection, source`

func scanAsset(row pgx.Row) (*Asset, error) {
	var a Asset
	var tier *int16
	var objects []byte
	var conn []byte
	if err := row.Scan(&a.ID, &a.TenantID, &a.Name, &a.Type, &a.Environment, &a.Ring, &tier, &a.Criticality,
		&a.DataClass, &a.LegalHold, &a.Owner, &a.Verified, &a.Reachability, &a.ActiveInvestigation,
		&a.HealthEndpoint, &objects, &a.Protected, &conn, &a.Source); err != nil {
		return nil, err
	}
	if tier != nil {
		t := int(*tier)
		a.ServiceTier = &t
	}
	if len(objects) > 0 {
		_ = json.Unmarshal(objects, &a.Objects)
	}
	if len(conn) > 0 && string(conn) != "null" {
		a.Connection = &Connection{}
		_ = json.Unmarshal(conn, a.Connection)
	}
	return &a, nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Put вставляет или обновляет актив (upsert по id).
func (s *PGStore) Put(a Asset) error {
	ctx, cancel := s.ctx()
	defer cancel()
	objects, _ := json.Marshal(a.Objects)
	var conn any
	if a.Connection != nil {
		b, _ := json.Marshal(a.Connection)
		conn = b
	}
	var tier any
	if a.ServiceTier != nil {
		tier = *a.ServiceTier
	}
	reach := a.Reachability
	if reach == "" {
		reach = "reachable"
	}
	src := a.Source
	if src == "" {
		src = "user"
	}
	if a.Protected == nil {
		a.Protected = []string{}
	}
	return s.DB.WithTenant(ctx, a.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO assets (id, tenant_id, name, type, environment, ring, service_tier, criticality, data_class,
			legal_hold, owner, verified, reachability, active_investigation, health_endpoint, objects, protected, connection, source)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
			ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, type=EXCLUDED.type, environment=EXCLUDED.environment, ring=EXCLUDED.ring,
			service_tier=EXCLUDED.service_tier, criticality=EXCLUDED.criticality, data_class=EXCLUDED.data_class,
			legal_hold=EXCLUDED.legal_hold, owner=EXCLUDED.owner, verified=EXCLUDED.verified, reachability=EXCLUDED.reachability,
			active_investigation=EXCLUDED.active_investigation, health_endpoint=EXCLUDED.health_endpoint, objects=EXCLUDED.objects,
			protected=EXCLUDED.protected, connection=EXCLUDED.connection, source=EXCLUDED.source`,
			a.ID, a.TenantID, a.Name, a.Type, nullStr(a.Environment), nullStr(a.Ring), tier, nullStr(a.Criticality), nullStr(a.DataClass),
			a.LegalHold, nullStr(a.Owner), a.Verified, reach, a.ActiveInvestigation, nullStr(a.HealthEndpoint), objects, a.Protected, conn, src)
		return err
	})
}

// Get возвращает актив tenant (ошибки БД журналируются и трактуются как отсутствие — fail closed).
func (s *PGStore) Get(tenantID, id string) (*Asset, bool) {
	ctx, cancel := s.ctx()
	defer cancel()
	var out *Asset
	err := s.DB.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		a, err := scanAsset(tx.QueryRow(ctx, "SELECT "+assetCols+" FROM assets WHERE id::text = $1", id))
		out = a
		return err
	})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) && !errors.Is(err, db.ErrBadTenant) {
			slog.Error("inventory: get asset", "error", err)
		}
		return nil, false
	}
	return out, true
}

// List — активы tenant по имени.
func (s *PGStore) List(tenantID string) []Asset {
	ctx, cancel := s.ctx()
	defer cancel()
	var out []Asset
	err := s.DB.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT "+assetCols+" FROM assets ORDER BY name LIMIT 10000")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanAsset(rows)
			if err != nil {
				return err
			}
			out = append(out, *a)
		}
		return rows.Err()
	})
	if err != nil && !errors.Is(err, db.ErrBadTenant) {
		slog.Error("inventory: list assets", "error", err)
	}
	return out
}

// SetLegalHold меняет флаг legal hold.
func (s *PGStore) SetLegalHold(tenantID, id string, hold bool) bool {
	ctx, cancel := s.ctx()
	defer cancel()
	var n int64
	err := s.DB.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE assets SET legal_hold = $2 WHERE id::text = $1", id, hold)
		n = tag.RowsAffected()
		return err
	})
	return err == nil && n == 1
}

// AddDependency добавляет ребро (FK гарантируют, что оба конца в том же tenant).
func (s *PGStore) AddDependency(d Dependency) error {
	ctx, cancel := s.ctx()
	defer cancel()
	if d.DiscoveredAt.IsZero() {
		d.DiscoveredAt = time.Now().UTC()
	}
	vb := d.VerifiedBy
	if vb == "" {
		vb = "discovery"
	}
	return s.DB.WithTenant(ctx, d.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO dependencies (tenant_id, source_id, target_id, relation_type, confidence, verified_by, discovered_at)
			SELECT $1, $2, $3, $4, $5, $6, $7
			WHERE NOT EXISTS (SELECT 1 FROM dependencies WHERE source_id = $2 AND target_id = $3 AND relation_type = $4)`,
			d.TenantID, d.Source, d.Target, d.RelationType, d.Confidence, vb, d.DiscoveredAt)
		return err
	})
}

// Dependencies — рёбра tenant.
func (s *PGStore) Dependencies(tenantID string) []Dependency {
	ctx, cancel := s.ctx()
	defer cancel()
	var out []Dependency
	_ = s.DB.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id, source_id, target_id, relation_type, confidence::float8, verified_by, discovered_at
			FROM dependencies ORDER BY discovered_at LIMIT 100000`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d Dependency
			if err := rows.Scan(&d.TenantID, &d.Source, &d.Target, &d.RelationType, &d.Confidence, &d.VerifiedBy, &d.DiscoveredAt); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out
}

// BlastRadius — транзитивно зависимые активы (recursive CTE, без циклов), глубина ≤ 5.
func (s *PGStore) BlastRadius(tenantID, assetID string, maxDepth int) ([]Impacted, error) {
	if maxDepth <= 0 || maxDepth > 5 {
		maxDepth = 5
	}
	if _, ok := s.Get(tenantID, assetID); !ok {
		return nil, errors.New("asset not found")
	}
	ctx, cancel := s.ctx()
	defer cancel()
	var out []Impacted
	err := s.DB.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `WITH RECURSIVE br(id, depth, conf, path) AS (
				SELECT d.source_id, 1, d.confidence::float8, ARRAY[$1::uuid, d.source_id]
				FROM dependencies d WHERE d.target_id = $1::uuid
				UNION ALL
				SELECT d.source_id, br.depth + 1, br.conf * d.confidence::float8, br.path || d.source_id
				FROM dependencies d JOIN br ON d.target_id = br.id
				WHERE br.depth < $2 AND NOT (d.source_id = ANY (br.path))
			)
			SELECT a.id, a.name, min(br.depth), max(br.conf), a.service_tier, coalesce(a.criticality, '')
			FROM br JOIN assets a ON a.id = br.id
			GROUP BY a.id, a.name, a.service_tier, a.criticality`, assetID, maxDepth)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var it Impacted
			var tier *int16
			if err := rows.Scan(&it.AssetID, &it.Name, &it.Depth, &it.Confidence, &tier, &it.Criticality); err != nil {
				return err
			}
			it.Confidence = round(it.Confidence)
			if tier != nil {
				t := int(*tier)
				it.ServiceTier = &t
			}
			out = append(out, it)
		}
		return rows.Err()
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Depth != out[j].Depth {
			return out[i].Depth < out[j].Depth
		}
		return out[i].Name < out[j].Name
	})
	return out, err
}
