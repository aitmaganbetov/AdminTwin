package incidents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aitmaganbetov/admintwin/pkg/fsm"
	"github.com/aitmaganbetov/admintwin/services/telemetry"
)

// DB — подключение PostgreSQL (*pgx.Conn или *pgxpool.Pool).
type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// PGRepo — Repository на таблицах 0003 (incidents, incident_timeline, incident_feedback).
// Каждая операция — транзакция с set_config('admintwin.tenant_id', ..., true): RLS (FORCE) не позволяет
// прочитать или записать строки другого tenant даже при ошибке в запросе.
type PGRepo struct {
	DB DB
}

var _ Repository = (*PGRepo)(nil)

// NewPGRepo создаёт репозиторий.
func NewPGRepo(db DB) *PGRepo { return &PGRepo{DB: db} }

func (p *PGRepo) tx(ctx context.Context, tenantID string, fn func(pgx.Tx) error) error {
	if tenantID == "" {
		return fmt.Errorf("incidents: tenant is required")
	}
	tx, err := p.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT set_config('admintwin.tenant_id', $1, true)", tenantID); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func js(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func nullJS(v any) *string {
	b, _ := json.Marshal(v)
	if string(b) == "null" {
		return nil
	}
	s := string(b)
	return &s
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

const incidentCols = `id::text, tenant_id::text, title, coalesce(description,''), severity, status, coalesce(owner,''),
	asset_ids::text[], event_ids::text[], fingerprint, fingerprints, events, transitions, rca, postmortem, feedback, slo_impact, latency,
	created_at, updated_at, triaged_at, assigned_at, first_event_at, last_signal_at, created_by, version`

func scanIncident(row pgx.Row) (*Incident, error) {
	var inc Incident
	var sev, status string
	var fps, evs, trs, rca []byte
	var pm, fb, slo, lat []byte
	err := row.Scan(&inc.ID, &inc.TenantID, &inc.Title, &inc.Description, &sev, &status, &inc.Owner,
		&inc.AssetIDs, &inc.EventIDs, &inc.Fingerprint, &fps, &evs, &trs, &rca, &pm, &fb, &slo, &lat,
		&inc.CreatedAt, &inc.UpdatedAt, &inc.TriagedAt, &inc.AssignedAt, &inc.FirstEventAt, &inc.LastSignalAt, &inc.CreatedBy, &inc.Version)
	if err != nil {
		return nil, err
	}
	inc.Severity, inc.Status = telemetry.Severity(sev), fsm.State(status)
	for _, x := range []struct {
		raw []byte
		dst any
	}{{fps, &inc.Fingerprints}, {evs, &inc.Events}, {trs, &inc.Transitions}, {rca, &inc.RCA}, {pm, &inc.Postmortem}, {fb, &inc.Feedback}, {slo, &inc.SLOImpact}, {lat, &inc.Latency}} {
		if len(x.raw) > 0 {
			if err := json.Unmarshal(x.raw, x.dst); err != nil {
				return nil, fmt.Errorf("incidents: decode column: %w", err)
			}
		}
	}
	if inc.AssetIDs == nil {
		inc.AssetIDs = []string{}
	}
	if inc.EventIDs == nil {
		inc.EventIDs = []string{}
	}
	return &inc, nil
}

func loadTimeline(ctx context.Context, tx pgx.Tx, inc *Incident) error {
	rows, err := tx.Query(ctx, `SELECT seq, at, actor, kind, text, coalesce(ref,'') FROM (
		SELECT * FROM incident_timeline WHERE incident_id = $1 ORDER BY seq DESC LIMIT $2) t ORDER BY seq`, inc.ID, maxTimeline)
	if err != nil {
		return err
	}
	defer rows.Close()
	inc.Timeline = []TimelineEntry{}
	first := 0
	for rows.Next() {
		var e TimelineEntry
		var seq int
		if err := rows.Scan(&seq, &e.At, &e.Actor, &e.Kind, &e.Text, &e.Ref); err != nil {
			return err
		}
		if first == 0 {
			first = seq
		}
		inc.Timeline = append(inc.Timeline, e)
	}
	if first > 0 {
		inc.TimelineBase = first - 1
	}
	return rows.Err()
}

// appendTimeline вставляет записи, которых ещё нет в БД (seq = base + индекс + 1).
func appendTimeline(ctx context.Context, tx pgx.Tx, inc *Incident) error {
	var stored int
	if err := tx.QueryRow(ctx, "SELECT coalesce(max(seq), 0) FROM incident_timeline WHERE incident_id = $1", inc.ID).Scan(&stored); err != nil {
		return err
	}
	for i, e := range inc.Timeline {
		seq := inc.TimelineBase + i + 1
		if seq <= stored {
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO incident_timeline (tenant_id, incident_id, seq, at, actor, kind, text, ref)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, inc.TenantID, inc.ID, seq, e.At, e.Actor, e.Kind, e.Text, nullStr(e.Ref)); err != nil {
			return err
		}
	}
	return nil
}

// Create сохраняет новый инцидент.
func (p *PGRepo) Create(ctx context.Context, inc *Incident) error {
	return p.tx(ctx, inc.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO incidents (id, tenant_id, title, description, severity, status, owner, asset_ids, event_ids,
			fingerprint, fingerprints, events, transitions, rca, postmortem, feedback, slo_impact, latency, created_at, updated_at,
			triaged_at, assigned_at, first_event_at, last_signal_at, created_by, version)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8::text[]::uuid[], $9::text[]::uuid[], $10, $11::jsonb, $12::jsonb, $13::jsonb, $14::jsonb,
			$15::jsonb, $16::jsonb, $17::jsonb, $18::jsonb, $19, $20, $21, $22, $23, $24, $25, $26)`,
			inc.ID, inc.TenantID, inc.Title, nullStr(inc.Description), string(inc.Severity), string(inc.Status), nullStr(inc.Owner),
			inc.AssetIDs, inc.EventIDs, inc.Fingerprint, js(orEmptyMap(inc.Fingerprints)), js(orEmpty(inc.Events)), js(orEmpty(inc.Transitions)), js(inc.RCA),
			nullJS(inc.Postmortem), nullJS(inc.Feedback), nullJS(inc.SLOImpact), nullJS(inc.Latency), inc.CreatedAt, inc.UpdatedAt,
			inc.TriagedAt, inc.AssignedAt, inc.FirstEventAt, inc.LastSignalAt, inc.CreatedBy, inc.Version)
		if err != nil {
			return err
		}
		return appendTimeline(ctx, tx, inc)
	})
}

// Get — инцидент tenant с последними записями timeline.
func (p *PGRepo) Get(ctx context.Context, tenantID, id string) (*Incident, error) {
	if !telemetry.IsUUID(id) {
		return nil, ErrNotFound
	}
	var out *Incident
	err := p.tx(ctx, tenantID, func(tx pgx.Tx) error {
		inc, err := scanIncident(tx.QueryRow(ctx, "SELECT "+incidentCols+" FROM incidents WHERE id = $1::uuid", id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out = inc
		return loadTimeline(ctx, tx, inc)
	})
	return out, err
}

// Update — с оптимистической блокировкой по version.
func (p *PGRepo) Update(ctx context.Context, inc *Incident) error {
	return p.tx(ctx, inc.TenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE incidents SET title=$3, description=$4, severity=$5, status=$6, owner=$7,
			asset_ids=$8::text[]::uuid[], event_ids=$9::text[]::uuid[], fingerprints=$10::jsonb, events=$11::jsonb, transitions=$12::jsonb,
			rca=$13::jsonb, postmortem=$14::jsonb, feedback=$15::jsonb, slo_impact=$16::jsonb, latency=$17::jsonb,
			triaged_at=$18, assigned_at=$19, last_signal_at=$20, version=$21
			WHERE id = $1 AND tenant_id = $2 AND version = $21 - 1`,
			inc.ID, inc.TenantID, inc.Title, nullStr(inc.Description), string(inc.Severity), string(inc.Status), nullStr(inc.Owner),
			inc.AssetIDs, inc.EventIDs, js(orEmptyMap(inc.Fingerprints)), js(orEmpty(inc.Events)), js(orEmpty(inc.Transitions)), js(inc.RCA),
			nullJS(inc.Postmortem), nullJS(inc.Feedback), nullJS(inc.SLOImpact), nullJS(inc.Latency),
			inc.TriagedAt, inc.AssignedAt, inc.LastSignalAt, inc.Version)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var exists bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM incidents WHERE id = $1)", inc.ID).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return ErrNotFound
			}
			return ErrConflict
		}
		return appendTimeline(ctx, tx, inc)
	})
}

func (p *PGRepo) query(ctx context.Context, tenantID, where string, args ...any) ([]Incident, error) {
	var out []Incident
	err := p.tx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT "+incidentCols+" FROM incidents "+where, args...)
		if err != nil {
			return err
		}
		var items []*Incident
		for rows.Next() {
			inc, err := scanIncident(rows)
			if err != nil {
				rows.Close()
				return err
			}
			items = append(items, inc)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, inc := range items {
			if err := loadTimeline(ctx, tx, inc); err != nil {
				return err
			}
			out = append(out, *inc)
		}
		return nil
	})
	return out, err
}

// List — инциденты tenant, новые сначала.
func (p *PGRepo) List(ctx context.Context, tenantID string, f Filter) ([]Incident, error) {
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	return p.query(ctx, tenantID, `WHERE ($1 = '' OR status = $1) AND ($2 = '' OR severity = $2) ORDER BY created_at DESC LIMIT $3`,
		string(f.Status), string(f.Severity), limit)
}

// Open — открытые инциденты с активностью не раньше since.
func (p *PGRepo) Open(ctx context.Context, tenantID string, since time.Time) ([]Incident, error) {
	return p.query(ctx, tenantID, `WHERE status NOT IN ('resolved', 'closed') AND updated_at >= $1 ORDER BY created_at`, since)
}

// AddCandidate сохраняет оценку и кандидата golden dataset.
func (p *PGRepo) AddCandidate(ctx context.Context, c GoldenCandidate) error {
	return p.tx(ctx, c.TenantID, func(tx pgx.Tx) error {
		var fb Feedback
		if err := tx.QueryRow(ctx, "SELECT coalesce(feedback, 'null'::jsonb) FROM incidents WHERE id = $1", c.IncidentID).Scan(&fb); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO incident_feedback (id, tenant_id, incident_id, correct, actual_cause, rating, comment, author, at,
			candidate, status, exportable, reason) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $13)`,
			c.ID, c.TenantID, c.IncidentID, fb.Correct, nullStr(fb.ActualCause), max(fb.Rating, 1), nullStr(fb.Comment), c.CreatedBy, c.CreatedAt,
			js(c.Case), c.Status, c.Exportable, nullStr(c.Reason))
		return err
	})
}

// Candidates — последний кандидат по каждому инциденту tenant.
func (p *PGRepo) Candidates(ctx context.Context, tenantID string) ([]GoldenCandidate, error) {
	var out []GoldenCandidate
	err := p.tx(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (incident_id) id::text, tenant_id::text, incident_id::text, at, author, status, exportable,
			coalesce(reason,''), candidate FROM incident_feedback ORDER BY incident_id, at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c GoldenCandidate
			var raw []byte
			if err := rows.Scan(&c.ID, &c.TenantID, &c.IncidentID, &c.CreatedAt, &c.CreatedBy, &c.Status, &c.Exportable, &c.Reason, &raw); err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &c.Case); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func orEmptyMap(m map[string]time.Time) map[string]time.Time {
	if m == nil {
		return map[string]time.Time{}
	}
	return m
}
