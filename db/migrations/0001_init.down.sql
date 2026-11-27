BEGIN;
DROP TABLE IF EXISTS audit_chain_checkpoints, audit_logs, evidence_access_log, evidence, execution_requests,
  approval_decisions, change_transitions, change_requests, runbook_versions, dependencies, assets,
  discovery_scopes, role_bindings, users, tenants CASCADE;
DROP FUNCTION IF EXISTS admintwin_audit_append_only, admintwin_evidence_guard, admintwin_approval_not_author,
  admintwin_touch, admintwin_current_tenant;
COMMIT;
