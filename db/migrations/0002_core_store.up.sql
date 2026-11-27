-- AdminTwin — хранение ядра (Change Coordinator, CMDB, evidence, политики tenant).
BEGIN;

ALTER TABLE tenants ADD COLUMN policy jsonb NOT NULL DEFAULT '{}';

ALTER TABLE assets
  ADD COLUMN objects jsonb NOT NULL DEFAULT '{}',
  ADD COLUMN protected text[] NOT NULL DEFAULT '{}',
  ADD COLUMN connection jsonb,
  ADD COLUMN health_endpoint text,
  ADD COLUMN active_investigation boolean NOT NULL DEFAULT false,
  ADD COLUMN source text NOT NULL DEFAULT 'user';
CREATE UNIQUE INDEX assets_tenant_name_type ON assets (tenant_id, type, name);

ALTER TABLE change_requests
  ADD COLUMN dry_run boolean NOT NULL DEFAULT false,
  ADD COLUMN awaiting_window boolean NOT NULL DEFAULT false,
  ADD COLUMN doc jsonb NOT NULL DEFAULT '{}';
CREATE INDEX changes_tenant_updated ON change_requests (tenant_id, updated_at);

ALTER TABLE change_transitions ADD COLUMN seq integer NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX change_transitions_seq ON change_transitions (change_id, seq);

-- Тело evidence. Временное хранение в PostgreSQL до адаптера MinIO Object Lock (§3.5); storage_ref = pg://evidence_blobs/<id>.
CREATE TABLE evidence_blobs (
  evidence_id uuid PRIMARY KEY REFERENCES evidence(id),
  tenant_id   uuid NOT NULL,
  body        bytea NOT NULL
);
CREATE OR REPLACE FUNCTION admintwin_blob_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND EXISTS (SELECT 1 FROM evidence e WHERE e.id = OLD.evidence_id AND e.legal_hold) THEN
    RAISE EXCEPTION 'legal hold: evidence blob cannot be deleted' USING ERRCODE = 'check_violation';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'evidence blob is immutable' USING ERRCODE = 'check_violation';
  END IF;
  RETURN OLD;
END $$;
CREATE TRIGGER evidence_blob_guard BEFORE UPDATE OR DELETE ON evidence_blobs FOR EACH ROW EXECUTE FUNCTION admintwin_blob_immutable();

CREATE TABLE evidence_custody_events (
  id          bigserial PRIMARY KEY,
  tenant_id   uuid NOT NULL,
  evidence_id uuid NOT NULL REFERENCES evidence(id),
  event       text NOT NULL,
  actor       text NOT NULL,
  note        text,
  at          timestamptz NOT NULL DEFAULT now()
);

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['evidence_blobs','evidence_custody_events'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = admintwin_current_tenant()) WITH CHECK (tenant_id = admintwin_current_tenant())', t);
  END LOOP;
END $$;

-- Ключи ПДн tenant для crypto-shredding (ADR-016): случайный DEK, обёрнутый master-ключом (KEK вне БД).
-- Удаление строки = необратимое уничтожение ПДн в аудите при сохранении hash chain.
CREATE TABLE pii_keys (
  tenant_id   uuid PRIMARY KEY,
  wrapped_key bytea NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE pii_key_shreds (
  tenant_id   uuid PRIMARY KEY,
  shredded_at timestamptz NOT NULL DEFAULT now(),
  shredded_by text NOT NULL
);
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['pii_keys','pii_key_shreds'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = admintwin_current_tenant()) WITH CHECK (tenant_id = admintwin_current_tenant())', t);
  END LOOP;
END $$;
GRANT SELECT, INSERT, DELETE ON pii_keys TO admintwin_app;
GRANT SELECT, INSERT ON pii_key_shreds TO admintwin_app;

GRANT SELECT, INSERT ON evidence_blobs, evidence_custody_events TO admintwin_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO admintwin_app;

COMMIT;
