package audit

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aitmaganbetov/admintwin/pkg/db"
)

// PGStore — аудит в PostgreSQL (append-only таблица audit_logs, hash chain на tenant).
type PGStore struct{ DB *db.DB }

// Append вставляет запись, сериализуя писателей tenant через advisory lock транзакции и
// проверяя, что PrevHash совпадает с последним сохранённым хэшем.
func (s PGStore) Append(e Entry) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.DB.WithTenant(ctx, e.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext('audit:' || $1))", e.TenantID); err != nil {
			return err
		}
		var lastSeq int64
		var lastHash string
		err := tx.QueryRow(ctx, "SELECT seq, hash FROM audit_logs ORDER BY seq DESC LIMIT 1").Scan(&lastSeq, &lastHash)
		switch {
		case err == pgx.ErrNoRows:
			if e.Seq != 1 {
				return ErrChainConflict
			}
		case err != nil:
			return err
		default:
			if lastHash != e.PrevHash || uint64(lastSeq)+1 != e.Seq {
				return ErrChainConflict
			}
		}
		var data any
		if e.Data != nil {
			b, _ := json.Marshal(e.Data)
			data = b
		}
		var pii any
		if e.PII != "" {
			pii = e.PII
		}
		_, err = tx.Exec(ctx, `INSERT INTO audit_logs (tenant_id, seq, at, actor, action, object_type, object_id, data, pii, prev_hash, hash)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			e.TenantID, int64(e.Seq), e.At, e.Actor, e.Action, e.ObjectType, e.ObjectID, data, pii, e.PrevHash, e.Hash)
		return err
	})
}

// Load читает цепочку tenant по порядку.
func (s PGStore) Load(tenantID string) ([]Entry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var out []Entry
	err := s.DB.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT tenant_id, seq, at, actor, action, object_type, object_id, data, coalesce(pii, ''), prev_hash, hash
			FROM audit_logs ORDER BY seq`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e Entry
			var seq int64
			var data []byte
			if err := rows.Scan(&e.TenantID, &seq, &e.At, &e.Actor, &e.Action, &e.ObjectType, &e.ObjectID, &data, &e.PII, &e.PrevHash, &e.Hash); err != nil {
				return err
			}
			e.Seq = uint64(seq)
			e.At = e.At.UTC()
			if len(data) > 0 {
				_ = json.Unmarshal(data, &e.Data)
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// PGKeys — KeyStore в PostgreSQL: случайный DEK tenant, обёрнутый KEK (AES-256-GCM).
// KEK передаётся из конфигурации/Vault и в БД не хранится.
type PGKeys struct {
	DB  *db.DB
	KEK []byte // 32 байта
}

// Key возвращает DEK tenant, создавая его при первом обращении.
func (k PGKeys) Key(tenantID string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var dek []byte
	err := k.DB.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var shredded bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pii_key_shreds)").Scan(&shredded); err != nil {
			return err
		}
		if shredded {
			return ErrShredded
		}
		var wrapped []byte
		err := tx.QueryRow(ctx, "SELECT wrapped_key FROM pii_keys").Scan(&wrapped)
		if err == nil {
			dek, err = k.unwrap(tenantID, wrapped)
			return err
		}
		if err != pgx.ErrNoRows {
			return err
		}
		dek = make([]byte, 32)
		if _, err := rand.Read(dek); err != nil {
			return err
		}
		w, err := k.wrap(tenantID, dek)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "INSERT INTO pii_keys (tenant_id, wrapped_key) VALUES ($1, $2) ON CONFLICT DO NOTHING", tenantID, w)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 { // создан параллельно — читаем существующий
			if err := tx.QueryRow(ctx, "SELECT wrapped_key FROM pii_keys").Scan(&w); err != nil {
				return err
			}
			dek, err = k.unwrap(tenantID, w)
			return err
		}
		return nil
	})
	return dek, err
}

// Shred необратимо удаляет DEK tenant.
func (k PGKeys) Shred(tenantID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return k.DB.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "DELETE FROM pii_keys"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "INSERT INTO pii_key_shreds (tenant_id, shredded_by) VALUES ($1, 'audit-service') ON CONFLICT DO NOTHING", tenantID)
		return err
	})
}

func (k PGKeys) wrap(tenantID string, dek []byte) ([]byte, error) {
	g, err := newGCM(k.KEK)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, dek, []byte("pii-dek:"+tenantID)), nil
}

func (k PGKeys) unwrap(tenantID string, w []byte) ([]byte, error) {
	g, err := newGCM(k.KEK)
	if err != nil {
		return nil, err
	}
	if len(w) < g.NonceSize() {
		return nil, errors.New("wrapped key too short")
	}
	return g.Open(nil, w[:g.NonceSize()], w[g.NonceSize():], []byte("pii-dek:"+tenantID))
}
