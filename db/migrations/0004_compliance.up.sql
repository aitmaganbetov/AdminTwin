-- Статусы контролей (M26 минимально, Приложение A.3–A.4). История изменений — в hash chain аудита.
BEGIN;
CREATE TABLE control_assessments (
  tenant_id     uuid NOT NULL REFERENCES tenants(id),
  control_id    text NOT NULL,
  status        text NOT NULL CHECK (status IN ('not_assessed','applicable','implemented','partially_implemented','non_compliant','not_applicable','verified')),
  evidence_ids  text[] NOT NULL DEFAULT '{}',
  justification text,
  assessed_by   text NOT NULL,
  assessed_at   timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, control_id),
  -- T-COMP-001 на уровне БД: implemented/verified без evidence невозможны.
  CHECK (status NOT IN ('implemented','verified') OR cardinality(evidence_ids) > 0),
  CHECK (status <> 'not_applicable' OR length(coalesce(justification,'')) >= 10)
);
ALTER TABLE control_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE control_assessments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON control_assessments USING (tenant_id = admintwin_current_tenant()) WITH CHECK (tenant_id = admintwin_current_tenant());
GRANT SELECT, INSERT, UPDATE ON control_assessments TO admintwin_app;
COMMIT;
