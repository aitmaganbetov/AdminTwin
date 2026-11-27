-- AdminTwin — начальная схема ядра (ТЗ §12). PostgreSQL 16+.
-- Все tenant-owned таблицы: tenant_id + RLS (ENABLE + FORCE). Приложение работает под ролью
-- admintwin_app, которая не владеет таблицами и не может обойти RLS. Tenant задаётся на транзакцию:
--   SELECT set_config('admintwin.tenant_id', '<uuid>', true);
-- Если tenant не задан — запросы не видят ни одной строки (fail closed).

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'admintwin_app') THEN
    CREATE ROLE admintwin_app NOLOGIN NOBYPASSRLS;
  END IF;
END $$;

CREATE OR REPLACE FUNCTION admintwin_current_tenant() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('admintwin.tenant_id', true), '')::uuid
$$;

CREATE OR REPLACE FUNCTION admintwin_touch() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  NEW.version := OLD.version + 1;
  RETURN NEW;
END $$;

-- ---------------------------------------------------------------- IAM
CREATE TABLE tenants (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name          text NOT NULL,
  edition       text NOT NULL CHECK (edition IN ('enterprise', 'saas')),
  autonomy_mode text NOT NULL DEFAULT 'advisor' CHECK (autonomy_mode IN ('observer', 'advisor', 'operator', 'autonomous')),
  local_llm_only boolean NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  version       integer NOT NULL DEFAULT 1
);

CREATE TABLE users (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id),
  -- ПДн: в аудите хранятся только в зашифрованном виде (crypto-shredding, §9.1)
  login       text NOT NULL,
  email       text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  created_by  text,
  version     integer NOT NULL DEFAULT 1,
  retention_class text NOT NULL DEFAULT 'account',
  UNIQUE (tenant_id, login)
);

CREATE TABLE role_bindings (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id),
  user_id     uuid NOT NULL REFERENCES users(id),
  role        text NOT NULL CHECK (role IN ('platform_super_admin','tenant_admin','it_manager','engineer','operator','compliance_manager','auditor','viewer')),
  scopes      text[] NOT NULL DEFAULT '{}',
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, user_id, role)
);

-- ---------------------------------------------------------------- Инфраструктура
CREATE TABLE discovery_scopes (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES tenants(id),
  name          text NOT NULL,
  ranges        cidr[] NOT NULL DEFAULT '{}',
  methods       text[] NOT NULL,
  limits        jsonb NOT NULL DEFAULT '{}',
  responsible   text NOT NULL,
  approved_at   timestamptz,
  valid_until   timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  created_by    text,
  version       integer NOT NULL DEFAULT 1
);

CREATE TABLE assets (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES tenants(id),
  name          text NOT NULL,
  type          text NOT NULL,
  environment   text CHECK (environment IN ('production', 'staging', 'dev', 'test')),
  ring          text,
  service_tier  smallint CHECK (service_tier BETWEEN 0 AND 3),
  criticality   text CHECK (criticality IN ('critical', 'high', 'medium', 'low')),
  data_class    text CHECK (data_class IN ('public', 'internal', 'confidential', 'pii', 'secret')),
  legal_hold    boolean NOT NULL DEFAULT false,
  owner         text,
  verified      boolean NOT NULL DEFAULT false,
  reachability  text NOT NULL DEFAULT 'reachable' CHECK (reachability IN ('reachable', 'unreachable')),
  attributes    jsonb NOT NULL DEFAULT '{}',
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  created_by    text,
  version       integer NOT NULL DEFAULT 1,
  retention_class text NOT NULL DEFAULT 'cmdb',
  UNIQUE (tenant_id, id)
);

CREATE TABLE dependencies (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES tenants(id),
  source_id     uuid NOT NULL,
  target_id     uuid NOT NULL,
  relation_type text NOT NULL,
  confidence    numeric(4,3) NOT NULL CHECK (confidence > 0 AND confidence <= 1),
  verified_by   text NOT NULL CHECK (verified_by IN ('discovery', 'user', 'agent')),
  discovered_at timestamptz NOT NULL DEFAULT now(),
  verified_at   timestamptz,
  -- оба конца ребра обязаны принадлежать тому же tenant
  FOREIGN KEY (tenant_id, source_id) REFERENCES assets(tenant_id, id),
  FOREIGN KEY (tenant_id, target_id) REFERENCES assets(tenant_id, id),
  CHECK (source_id <> target_id)
);

-- ---------------------------------------------------------------- Runbooks (каталог)
-- Глобальные runbooks (tenant_id IS NULL) видны всем tenants; tenant-runbooks — только своему.
CREATE TABLE runbook_versions (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid REFERENCES tenants(id),
  runbook_id    text NOT NULL,
  version       text NOT NULL,
  risk          text NOT NULL CHECK (risk IN ('low', 'medium', 'high', 'critical')),
  spec          jsonb NOT NULL,
  digest        text NOT NULL,
  certified_by  text[] NOT NULL,
  certified_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE NULLS NOT DISTINCT (tenant_id, runbook_id, version)
);

-- ---------------------------------------------------------------- Change & Execution
CREATE TABLE change_requests (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES tenants(id),
  type            text NOT NULL CHECK (type IN ('standard', 'normal', 'emergency')),
  status          text NOT NULL,
  runbook_id      text NOT NULL,
  runbook_version text NOT NULL,
  runbook_digest  text NOT NULL,
  risk            text NOT NULL CHECK (risk IN ('low', 'medium', 'high', 'critical')),
  asset_id        uuid NOT NULL,
  params          jsonb NOT NULL DEFAULT '{}',
  reason          text NOT NULL,
  incident_id     uuid,
  author_id       text NOT NULL,
  author_kind     text NOT NULL CHECK (author_kind IN ('user', 'ai_agent', 'service')),
  policy_decision jsonb,
  impact          jsonb,
  idempotency_key text,
  pir_required    boolean NOT NULL DEFAULT false,
  pir_due_at      timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  created_by      text,
  version         integer NOT NULL DEFAULT 1,
  retention_class text NOT NULL DEFAULT 'change-3y',
  FOREIGN KEY (tenant_id, asset_id) REFERENCES assets(tenant_id, id),
  UNIQUE (tenant_id, id),
  -- AI Agent не может инициировать break-glass (§11.5)
  CHECK (NOT (type = 'emergency' AND author_kind = 'ai_agent'))
);
CREATE UNIQUE INDEX change_requests_idem ON change_requests (tenant_id, author_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TABLE change_transitions (
  id             bigserial PRIMARY KEY,
  tenant_id      uuid NOT NULL,
  change_id      uuid NOT NULL,
  from_state     text NOT NULL,
  to_state       text NOT NULL,
  actor          text NOT NULL,
  reason         text NOT NULL CHECK (reason <> ''),
  correlation_id text,
  evidence_ref   text,
  at             timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, change_id) REFERENCES change_requests(tenant_id, id)
);

CREATE TABLE approval_decisions (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL,
  change_id   uuid NOT NULL,
  actor_id    text NOT NULL,
  actor_kind  text NOT NULL CHECK (actor_kind = 'user'),   -- AI Agent никогда не approver
  roles       text[] NOT NULL,
  verdict     text NOT NULL CHECK (verdict IN ('approve', 'reject')),
  comment     text,
  decided_at  timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, change_id) REFERENCES change_requests(tenant_id, id),
  UNIQUE (change_id, actor_id)                              -- dual control: независимые согласующие
);

CREATE OR REPLACE FUNCTION admintwin_approval_not_author() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM change_requests c WHERE c.id = NEW.change_id AND c.author_id = NEW.actor_id) THEN
    RAISE EXCEPTION 'separation of duties: approver cannot be the author' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER approval_not_author BEFORE INSERT ON approval_decisions FOR EACH ROW EXECUTE FUNCTION admintwin_approval_not_author();

-- ExecutionRequest не существует без родительского ChangeRequest (§11.1).
CREATE TABLE execution_requests (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL,
  change_id     uuid NOT NULL,
  runbook_id    text NOT NULL,
  asset_id      uuid NOT NULL,
  status        text NOT NULL,
  fencing_token bigint NOT NULL,
  result        jsonb,
  evidence_id   uuid,
  started_at    timestamptz NOT NULL DEFAULT now(),
  finished_at   timestamptz,
  FOREIGN KEY (tenant_id, change_id) REFERENCES change_requests(tenant_id, id)
);

-- ---------------------------------------------------------------- Evidence (единая)
CREATE TABLE evidence (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        uuid NOT NULL REFERENCES tenants(id),
  kind             text NOT NULL CHECK (kind IN ('execution', 'incident', 'compliance', 'forensic')),
  ref              text NOT NULL,
  hash_sha256      text NOT NULL,
  source           text NOT NULL,
  collector        text NOT NULL,
  collected_at_utc timestamptz NOT NULL,
  time_source      text NOT NULL,
  storage_ref      text NOT NULL,
  retention_class  text NOT NULL,
  legal_hold       boolean NOT NULL DEFAULT false,
  created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE evidence_access_log (
  id          bigserial PRIMARY KEY,
  tenant_id   uuid NOT NULL,
  evidence_id uuid NOT NULL REFERENCES evidence(id),
  actor       text NOT NULL,
  purpose     text NOT NULL CHECK (purpose <> ''),          -- purpose-of-access обязателен
  at          timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION admintwin_evidence_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND OLD.legal_hold THEN
    RAISE EXCEPTION 'legal hold: evidence % cannot be deleted', OLD.id USING ERRCODE = 'check_violation';
  END IF;
  IF TG_OP = 'UPDATE' AND (NEW.hash_sha256 <> OLD.hash_sha256 OR NEW.storage_ref <> OLD.storage_ref OR NEW.tenant_id <> OLD.tenant_id) THEN
    RAISE EXCEPTION 'evidence content is immutable' USING ERRCODE = 'check_violation';
  END IF;
  RETURN COALESCE(NEW, OLD);
END $$;
CREATE TRIGGER evidence_guard BEFORE UPDATE OR DELETE ON evidence FOR EACH ROW EXECUTE FUNCTION admintwin_evidence_guard();

-- ---------------------------------------------------------------- Аудит (append-only, hash chain)
CREATE TABLE audit_logs (
  tenant_id   uuid NOT NULL,
  seq         bigint NOT NULL,
  at          timestamptz NOT NULL,
  actor       text NOT NULL,
  action      text NOT NULL,
  object_type text NOT NULL,
  object_id   text NOT NULL,
  data        jsonb,
  pii         text,          -- AES-GCM, ключ tenant/субъекта (crypto-shredding)
  prev_hash   text NOT NULL,
  hash        text NOT NULL,
  PRIMARY KEY (tenant_id, seq)
);

CREATE OR REPLACE FUNCTION admintwin_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs is append-only' USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_logs FOR EACH STATEMENT EXECUTE FUNCTION admintwin_audit_append_only();

CREATE TABLE audit_chain_checkpoints (
  tenant_id   uuid NOT NULL,
  seq         bigint NOT NULL,
  hash        text NOT NULL,
  signature   text NOT NULL,
  object_ref  text,          -- копия в MinIO Object Lock (compliance mode)
  at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, seq)
);

-- ---------------------------------------------------------------- Индексы (§12 «Общие поля»)
CREATE INDEX assets_tenant_created   ON assets (tenant_id, created_at);
CREATE INDEX changes_tenant_created  ON change_requests (tenant_id, created_at);
CREATE INDEX changes_tenant_status   ON change_requests (tenant_id, status);
CREATE INDEX changes_tenant_asset    ON change_requests (tenant_id, asset_id);
CREATE INDEX executions_tenant_asset ON execution_requests (tenant_id, asset_id);
CREATE INDEX evidence_tenant_created ON evidence (tenant_id, created_at);

-- ---------------------------------------------------------------- updated_at / version
CREATE TRIGGER tenants_touch BEFORE UPDATE ON tenants FOR EACH ROW EXECUTE FUNCTION admintwin_touch();
CREATE TRIGGER users_touch   BEFORE UPDATE ON users   FOR EACH ROW EXECUTE FUNCTION admintwin_touch();
CREATE TRIGGER assets_touch  BEFORE UPDATE ON assets  FOR EACH ROW EXECUTE FUNCTION admintwin_touch();
CREATE TRIGGER scopes_touch  BEFORE UPDATE ON discovery_scopes FOR EACH ROW EXECUTE FUNCTION admintwin_touch();
CREATE TRIGGER changes_touch BEFORE UPDATE ON change_requests  FOR EACH ROW EXECUTE FUNCTION admintwin_touch();

-- ---------------------------------------------------------------- RLS
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['users','role_bindings','discovery_scopes','assets','dependencies','change_requests',
                           'change_transitions','approval_decisions','execution_requests','evidence',
                           'evidence_access_log','audit_logs','audit_chain_checkpoints']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = admintwin_current_tenant()) WITH CHECK (tenant_id = admintwin_current_tenant())', t);
  END LOOP;
END $$;

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_self ON tenants USING (id = admintwin_current_tenant());

ALTER TABLE runbook_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE runbook_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY runbook_visibility ON runbook_versions
  USING (tenant_id IS NULL OR tenant_id = admintwin_current_tenant())
  WITH CHECK (tenant_id = admintwin_current_tenant());

-- ---------------------------------------------------------------- Права роли приложения
GRANT USAGE ON SCHEMA public TO admintwin_app;
GRANT SELECT ON tenants, runbook_versions TO admintwin_app;
GRANT SELECT, INSERT, UPDATE ON users, role_bindings, discovery_scopes, assets, dependencies, change_requests, execution_requests TO admintwin_app;
GRANT SELECT, INSERT ON change_transitions, approval_decisions, evidence_access_log, audit_logs, audit_chain_checkpoints TO admintwin_app;
GRANT SELECT, INSERT, UPDATE (legal_hold) ON evidence TO admintwin_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO admintwin_app;
-- DELETE не выдаётся: удаление — только через процедуры ретенции с проверкой legal hold.

COMMIT;
