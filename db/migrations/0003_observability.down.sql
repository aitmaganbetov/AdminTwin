BEGIN;
DROP TABLE IF EXISTS discovery_findings, discovery_jobs, incident_feedback, incident_timeline, incidents,
  alerts, events CASCADE;
DROP FUNCTION IF EXISTS admintwin_timeline_append_only;
ALTER TABLE IF EXISTS discovery_scopes DROP CONSTRAINT IF EXISTS discovery_scopes_tenant_id_key;
ALTER TABLE IF EXISTS discovery_scopes DROP CONSTRAINT IF EXISTS discovery_scopes_approval_complete;
ALTER TABLE IF EXISTS discovery_scopes DROP CONSTRAINT IF EXISTS discovery_scopes_approver_not_author;
ALTER TABLE IF EXISTS discovery_scopes DROP COLUMN IF EXISTS approved_by;
COMMIT;
