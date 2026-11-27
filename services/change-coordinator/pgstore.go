package change

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aitmaganbetov/admintwin/pkg/db"
	"github.com/aitmaganbetov/admintwin/pkg/fsm"
	"github.com/aitmaganbetov/admintwin/services/approval"
)

// PGStore — ChangeRequest в PostgreSQL. Снимок — change_requests.doc; переходы и решения —
// отдельными строками, чтобы инварианты БД (separation of duties, FK на change) действовали всегда.
type PGStore struct{ DB *db.DB }

var _ Persister = PGStore{}

func tctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// Save реализует Persister.
func (s PGStore) Save(cr *ChangeRequest, nt []fsm.Transition, firstSeq int, nd []approval.Decision) error {
	ctx, cancel := tctx()
	defer cancel()
	doc, err := MarshalRecord(cr)
	if err != nil {
		return err
	}
	var policyDoc, impactDoc any
	if cr.Policy != nil {
		policyDoc, _ = json.Marshal(cr.Policy)
	}
	if cr.Impact != nil {
		impactDoc, _ = json.Marshal(cr.Impact)
	}
	var incident any
	if cr.IncidentID != "" {
		incident = cr.IncidentID
	}
	var idem any
	if cr.idemKey != "" {
		idem = cr.idemKey
	}
	params, _ := json.Marshal(cr.Params)
	return s.DB.WithTenant(ctx, cr.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO change_requests (id, tenant_id, type, status, runbook_id, runbook_version, runbook_digest, risk,
				asset_id, params, reason, incident_id, author_id, author_kind, policy_decision, impact, idempotency_key, pir_required,
				pir_due_at, dry_run, awaiting_window, doc, created_at, updated_at, created_by)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$13)
			ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, policy_decision=EXCLUDED.policy_decision, impact=EXCLUDED.impact,
				pir_required=EXCLUDED.pir_required, pir_due_at=EXCLUDED.pir_due_at, awaiting_window=EXCLUDED.awaiting_window,
				doc=EXCLUDED.doc, updated_at=EXCLUDED.updated_at`,
			cr.ID, cr.TenantID, string(cr.Type), string(cr.Status), cr.RunbookID, cr.RunbookVersion, cr.RunbookDigest, string(cr.Risk),
			cr.AssetID, params, cr.Reason, incident, cr.AuthorID, string(cr.AuthorKind), policyDoc, impactDoc, idem, cr.PIRRequired,
			cr.PIRDueAt, cr.DryRun, cr.awaitingWindow, doc, cr.CreatedAt, cr.UpdatedAt); err != nil {
			return err
		}
		for i, t := range nt {
			if _, err := tx.Exec(ctx, `INSERT INTO change_transitions (tenant_id, change_id, seq, from_state, to_state, actor, reason, correlation_id, evidence_ref, at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (change_id, seq) DO NOTHING`,
				cr.TenantID, cr.ID, firstSeq+i+1, string(t.From), string(t.To), t.Actor, t.Reason, t.CorrelationID, t.EvidenceRef, t.At); err != nil {
				return err
			}
		}
		for _, d := range nd {
			if _, err := tx.Exec(ctx, `INSERT INTO approval_decisions (tenant_id, change_id, actor_id, actor_kind, roles, verdict, comment, decided_at)
				VALUES ($1,$2,$3,'user',$4,$5,$6,$7)`, cr.TenantID, cr.ID, d.ActorID, d.Roles, string(d.Verdict), d.Comment, d.At); err != nil {
				return err
			}
		}
		for _, e := range cr.Executions {
			var result any
			if e.Result != nil {
				result, _ = json.Marshal(e.Result)
			}
			var evidenceID any
			var finished any
			if e.Result != nil {
				if e.Result.EvidenceID != "" {
					evidenceID = e.Result.EvidenceID
				}
				if !e.Result.FinishedAt.IsZero() {
					finished = e.Result.FinishedAt
				}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO execution_requests (id, tenant_id, change_id, runbook_id, asset_id, status, fencing_token, result, evidence_id, started_at, finished_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
				ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, result=EXCLUDED.result, evidence_id=EXCLUDED.evidence_id, finished_at=EXCLUDED.finished_at`,
				e.ID, cr.TenantID, cr.ID, e.RunbookID, e.AssetID, e.Status, int64(cr.fence), result, evidenceID, e.StartedAt, finished); err != nil {
				return err
			}
		}
		return nil
	})
}

func decodeRecords(rows pgx.Rows) ([]*ChangeRequest, error) {
	defer rows.Close()
	var out []*ChangeRequest
	for rows.Next() {
		var doc []byte
		if err := rows.Scan(&doc); err != nil {
			return nil, err
		}
		var r Record
		if err := json.Unmarshal(doc, &r); err != nil || r.Change == nil {
			continue
		}
		out = append(out, FromRecord(r))
	}
	return out, rows.Err()
}

// Recent — для восстановления после рестарта (платформенная операция, требует BYPASSRLS).
func (s PGStore) Recent(since time.Time) ([]*ChangeRequest, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out []*ChangeRequest
	err := s.DB.Platform(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT doc FROM change_requests
			WHERE updated_at > $1 OR status NOT IN ('rejected','closed','closed_with_rollback','closed_with_compensation','cancelled','preflight_failed','failed')`, since)
		if err != nil {
			return err
		}
		out, err = decodeRecords(rows)
		return err
	})
	return out, err
}

// Get — снимок change tenant.
func (s PGStore) Get(tenantID, id string) (*ChangeRequest, bool, error) {
	ctx, cancel := tctx()
	defer cancel()
	var out []*ChangeRequest
	err := s.DB.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT doc FROM change_requests WHERE id::text = $1", id)
		if err != nil {
			return err
		}
		out, err = decodeRecords(rows)
		return err
	})
	if errors.Is(err, db.ErrBadTenant) {
		return nil, false, nil
	}
	if err != nil || len(out) == 0 {
		return nil, false, err
	}
	return out[0], true, nil
}

// List — последние изменения tenant.
func (s PGStore) List(tenantID string, limit int) ([]*ChangeRequest, error) {
	ctx, cancel := tctx()
	defer cancel()
	var out []*ChangeRequest
	err := s.DB.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT doc FROM change_requests ORDER BY created_at DESC LIMIT $1", limit)
		if err != nil {
			return err
		}
		out, err = decodeRecords(rows)
		return err
	})
	return out, err
}
