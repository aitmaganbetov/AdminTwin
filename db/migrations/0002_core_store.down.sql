BEGIN;
DROP TABLE IF EXISTS pii_key_shreds, pii_keys, evidence_custody_events, evidence_blobs;
DROP FUNCTION IF EXISTS admintwin_blob_immutable;
DROP INDEX IF EXISTS change_transitions_seq, changes_tenant_updated, assets_tenant_name_type;
ALTER TABLE change_transitions DROP COLUMN IF EXISTS seq;
ALTER TABLE change_requests DROP COLUMN IF EXISTS doc, DROP COLUMN IF EXISTS awaiting_window, DROP COLUMN IF EXISTS dry_run;
ALTER TABLE assets DROP COLUMN IF EXISTS source, DROP COLUMN IF EXISTS active_investigation, DROP COLUMN IF EXISTS health_endpoint,
  DROP COLUMN IF EXISTS connection, DROP COLUMN IF EXISTS protected, DROP COLUMN IF EXISTS objects;
ALTER TABLE tenants DROP COLUMN IF EXISTS policy;
COMMIT;
