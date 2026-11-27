package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aitmaganbetov/admintwin/pkg/db"
	"github.com/aitmaganbetov/admintwin/pkg/problem"
)

// PGStore — evidence в PostgreSQL: метаданные в evidence, тело в evidence_blobs (временное хранилище
// до адаптера MinIO Object Lock), custody и purpose-of-access — в отдельных журналах.
type PGStore struct{ DB *db.DB }

var _ Repository = PGStore{}

func ctx5() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// Store сохраняет артефакт.
func (s PGStore) Store(tenantID, kind, ref string, body []byte, legalHold bool) (string, string, error) {
	ctx, cancel := ctx5()
	defer cancel()
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	id := newID()
	rc := "operational-1y"
	if kind == "compliance" || kind == "forensic" {
		rc = "compliance-7y"
	}
	err := s.DB.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO evidence (id, tenant_id, kind, ref, hash_sha256, source, collector, collected_at_utc, time_source, storage_ref, retention_class, legal_hold)
			VALUES ($1,$2,$3,$4,$5,'admintwin-execution-gateway','execution-gateway',now(),'system-ntp',$6,$7,$8)`,
			id, tenantID, kind, ref, digest, "pg://evidence_blobs/"+id, rc, legalHold); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO evidence_blobs (evidence_id, tenant_id, body) VALUES ($1,$2,$3)", id, tenantID, body); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO evidence_custody_events (tenant_id, evidence_id, event, actor) VALUES
			($1,$2,'collected','service:execution-gateway'), ($1,$2,'stored','service:compliance-evidence')`, tenantID, id)
		return err
	})
	if err != nil {
		return "", "", err
	}
	return id, digest, nil
}

// Get выдаёт evidence только с purpose-of-access; доступ журналируется в той же транзакции.
func (s PGStore) Get(tenantID, id, actor, purpose string) (*Item, []byte, error) {
	if purpose == "" {
		return nil, nil, problem.New(problem.Forbidden, "purpose_of_access is required for evidence")
	}
	ctx, cancel := ctx5()
	defer cancel()
	var it Item
	var body []byte
	err := s.DB.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT e.id, e.tenant_id, e.kind, e.ref, e.hash_sha256, e.source, e.collector, e.collected_at_utc,
				e.time_source, e.retention_class, e.legal_hold, b.body
			FROM evidence e JOIN evidence_blobs b ON b.evidence_id = e.id WHERE e.id::text = $1`, id).
			Scan(&it.ID, &it.TenantID, &it.Kind, &it.Ref, &it.Digest, &it.Source, &it.Collector, &it.CollectedAtUTC,
				&it.TimeSource, &it.RetentionClass, &it.LegalHold, &body)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO evidence_access_log (tenant_id, evidence_id, actor, purpose) VALUES ($1,$2,$3,$4)", tenantID, it.ID, actor, purpose); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "INSERT INTO evidence_custody_events (tenant_id, evidence_id, event, actor, note) VALUES ($1,$2,'accessed',$3,$4)", tenantID, it.ID, actor, purpose); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, "SELECT event, actor, at, coalesce(note,'') FROM evidence_custody_events WHERE evidence_id = $1 ORDER BY id", it.ID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var c CustodyEvent
			if err := rows.Scan(&c.Event, &c.Actor, &c.At, &c.Note); err != nil {
				rows.Close()
				return err
			}
			it.Custody = append(it.Custody, c)
		}
		rows.Close()
		rows, err = tx.Query(ctx, "SELECT actor, purpose, at FROM evidence_access_log WHERE evidence_id = $1 ORDER BY id", it.ID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a AccessLogEntry
			if err := rows.Scan(&a.Actor, &a.Purpose, &a.At); err != nil {
				return err
			}
			it.AccessLog = append(it.AccessLog, a)
		}
		return rows.Err()
	})
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, db.ErrBadTenant) {
		return nil, nil, problem.New(problem.NotFound, "evidence not found")
	}
	if err != nil {
		return nil, nil, err
	}
	return &it, body, nil
}

// Verify сверяет digest с хранимым телом.
func (s PGStore) Verify(tenantID, id string) (bool, error) {
	ctx, cancel := ctx5()
	defer cancel()
	var digest string
	var body []byte
	err := s.DB.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT e.hash_sha256, b.body FROM evidence e JOIN evidence_blobs b ON b.evidence_id = e.id WHERE e.id::text = $1", id).Scan(&digest, &body)
	})
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(body)
	return "sha256:"+hex.EncodeToString(sum[:]) == digest, nil
}

// Delete — удаление выполняется процедурами ретенции под ролью владельца; роли приложения DELETE не выдан.
func (s PGStore) Delete(tenantID, id string) error {
	return problem.New(problem.Forbidden, "evidence deletion is performed only by retention procedures (legal hold is enforced in the database)")
}
