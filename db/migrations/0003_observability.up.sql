-- AdminTwin — Observability (M05), инциденты (M06), RCA (M07), Discovery (M03). PostgreSQL 16+.
-- Требует 0001_init. Все таблицы tenant-owned: tenant_id + RLS (ENABLE + FORCE), как в 0001.
-- Ретенция (§9.1): события/алерты — 13 мес, инциденты/RCA — 3 года; удаление только процедурами ретенции.

BEGIN;

-- ---------------------------------------------------------------- Discovery scope (из 0001) — дополнения
ALTER TABLE discovery_scopes ADD COLUMN approved_by text;
-- Согласующий не может быть автором (§2.1).
ALTER TABLE discovery_scopes ADD CONSTRAINT discovery_scopes_approver_not_author
  CHECK (approved_by IS NULL OR approved_by IS DISTINCT FROM created_by);
ALTER TABLE discovery_scopes ADD CONSTRAINT discovery_scopes_approval_complete
  CHECK ((approved_at IS NULL) = (approved_by IS NULL));
ALTER TABLE discovery_scopes ADD CONSTRAINT discovery_scopes_tenant_id_key UNIQUE (tenant_id, id);

-- ---------------------------------------------------------------- События и алерты
CREATE TABLE events (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES tenants(id),
  asset_id        uuid,
  service_id      text,
  kind            text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_]{1,63}$'),
  severity        text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  title           text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
  fingerprint     text NOT NULL,
  labels          jsonb NOT NULL DEFAULT '{}',
  value           double precision,
  at              timestamptz NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  retention_class text NOT NULL DEFAULT 'events-13m',
  FOREIGN KEY (tenant_id, asset_id) REFERENCES assets(tenant_id, id),
  UNIQUE (tenant_id, id)
);

CREATE TABLE alerts (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES tenants(id),
  fingerprint   text NOT NULL,
  rule          text NOT NULL,
  kind          text NOT NULL,
  severity      text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  state         text NOT NULL CHECK (state IN ('firing', 'resolved')),
  asset_id      uuid,
  first_seen    timestamptz NOT NULL,
  last_seen     timestamptz NOT NULL,
  last_event_id uuid,
  count         integer NOT NULL DEFAULT 1 CHECK (count > 0),
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  version       integer NOT NULL DEFAULT 1,
  retention_class text NOT NULL DEFAULT 'events-13m',
  FOREIGN KEY (tenant_id, asset_id) REFERENCES assets(tenant_id, id),
  FOREIGN KEY (tenant_id, last_event_id) REFERENCES events(tenant_id, id),
  CHECK (last_seen >= first_seen)
);
-- Один активный алерт на fingerprint.
CREATE UNIQUE INDEX alerts_firing_fingerprint ON alerts (tenant_id, fingerprint) WHERE state = 'firing';

-- ---------------------------------------------------------------- Инциденты (C.7)
CREATE TABLE incidents (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES tenants(id),
  title           text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
  description     text,
  severity        text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  status          text NOT NULL CHECK (status IN ('new', 'triaged', 'investigating', 'mitigated', 'resolved', 'closed', 'reopened')),
  owner           text,
  asset_ids       uuid[] NOT NULL DEFAULT '{}',
  event_ids       uuid[] NOT NULL DEFAULT '{}',
  fingerprint     text NOT NULL,
  fingerprints    jsonb NOT NULL DEFAULT '{}',   -- fingerprint → время последнего события (дедупликация 30 мин)
  events          jsonb NOT NULL DEFAULT '[]',   -- сводки событий (без сырых строк журналов)
  transitions     jsonb NOT NULL DEFAULT '[]',
  rca             jsonb NOT NULL DEFAULT '{"status":"not_started"}',
  postmortem      jsonb,
  feedback        jsonb,
  slo_impact      jsonb,
  latency         jsonb,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  triaged_at      timestamptz,
  assigned_at     timestamptz,
  first_event_at  timestamptz,
  last_signal_at  timestamptz,
  created_by      text NOT NULL,
  version         integer NOT NULL DEFAULT 1,
  retention_class text NOT NULL DEFAULT 'incident-3y',
  UNIQUE (tenant_id, id),
  -- mitigated → resolved для severity ≥ high невозможен без постмортема (C.7)
  CHECK (status NOT IN ('resolved', 'closed') OR severity NOT IN ('critical', 'high') OR postmortem IS NOT NULL),
  CHECK (assigned_at IS NULL OR owner IS NOT NULL)
);

-- Timeline — append-only: каждая запись (переход, событие, обновление RCA, связанный change).
CREATE TABLE incident_timeline (
  id          bigserial PRIMARY KEY,
  tenant_id   uuid NOT NULL,
  incident_id uuid NOT NULL,
  seq         integer NOT NULL CHECK (seq > 0),
  at          timestamptz NOT NULL,
  actor       text NOT NULL,
  kind        text NOT NULL,
  text        text NOT NULL,
  ref         text,
  FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents(tenant_id, id),
  UNIQUE (incident_id, seq)
);

CREATE OR REPLACE FUNCTION admintwin_timeline_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'incident_timeline is append-only' USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER timeline_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON incident_timeline
  FOR EACH STATEMENT EXECUTE FUNCTION admintwin_timeline_append_only();

-- Оценка оператора и кандидат в golden dataset (M22).
CREATE TABLE incident_feedback (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL,
  incident_id  uuid NOT NULL,
  correct      boolean NOT NULL,
  actual_cause text,
  rating       smallint NOT NULL CHECK (rating BETWEEN 1 AND 5),
  comment      text,
  author       text NOT NULL,
  at           timestamptz NOT NULL DEFAULT now(),
  candidate    jsonb NOT NULL,                 -- eval case (ai/evals/eval-case.schema.json)
  status       text NOT NULL DEFAULT 'candidate' CHECK (status IN ('candidate', 'accepted', 'rejected')),
  exportable   boolean NOT NULL DEFAULT false,
  reason       text,
  FOREIGN KEY (tenant_id, incident_id) REFERENCES incidents(tenant_id, id)
);

-- ---------------------------------------------------------------- Discovery (C.9)
CREATE TABLE discovery_jobs (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   uuid NOT NULL REFERENCES tenants(id),
  scope_id    uuid NOT NULL,
  status      text NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
  targets     jsonb NOT NULL,
  results     jsonb NOT NULL DEFAULT '[]',
  summary     jsonb NOT NULL DEFAULT '{}',
  created_by  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  started_at  timestamptz,
  finished_at timestamptz,
  evidence_id uuid,
  error       text,
  version     integer NOT NULL DEFAULT 1,
  retention_class text NOT NULL DEFAULT 'operational-1y',
  FOREIGN KEY (tenant_id, scope_id) REFERENCES discovery_scopes(tenant_id, id),
  UNIQUE (tenant_id, id)
);

CREATE TABLE discovery_findings (
  id                        bigserial PRIMARY KEY,
  tenant_id                 uuid NOT NULL,
  job_id                    uuid NOT NULL,
  key                       text NOT NULL,
  change                    text NOT NULL CHECK (change IN ('new', 'changed', 'missing', 'unchanged')),
  asset_id                  uuid,
  name                      text NOT NULL,
  type                      text NOT NULL,
  address                   text,
  method                    text,
  confidence                numeric(4,3) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  diff                      jsonb NOT NULL DEFAULT '[]',
  observed                  jsonb,
  needs_confirmation        boolean NOT NULL,
  applied                   boolean NOT NULL DEFAULT false,
  confirmed_by              text,
  classification_incomplete boolean NOT NULL,
  warnings                  jsonb NOT NULL DEFAULT '[]',
  FOREIGN KEY (tenant_id, job_id) REFERENCES discovery_jobs(tenant_id, id),
  UNIQUE (job_id, key),
  -- объект с низким confidence попадает в CMDB только после подтверждения человеком
  CHECK (NOT (needs_confirmation AND applied) OR confirmed_by IS NOT NULL)
);

-- ---------------------------------------------------------------- Индексы
CREATE INDEX events_tenant_at          ON events (tenant_id, at DESC);
CREATE INDEX events_tenant_asset_at    ON events (tenant_id, asset_id, at DESC);
CREATE INDEX events_tenant_fingerprint ON events (tenant_id, fingerprint, at DESC);
CREATE INDEX incidents_tenant_status   ON incidents (tenant_id, status);
CREATE INDEX incidents_tenant_created  ON incidents (tenant_id, created_at DESC);
CREATE INDEX incidents_tenant_open     ON incidents (tenant_id, updated_at) WHERE status NOT IN ('resolved', 'closed');
CREATE INDEX timeline_tenant_incident  ON incident_timeline (tenant_id, incident_id, seq);
CREATE INDEX feedback_tenant_incident  ON incident_feedback (tenant_id, incident_id);
CREATE INDEX discovery_jobs_tenant     ON discovery_jobs (tenant_id, created_at DESC);
CREATE INDEX discovery_findings_job    ON discovery_findings (tenant_id, job_id);

-- ---------------------------------------------------------------- updated_at / version
CREATE TRIGGER alerts_touch         BEFORE UPDATE ON alerts         FOR EACH ROW EXECUTE FUNCTION admintwin_touch();
CREATE TRIGGER incidents_touch      BEFORE UPDATE ON incidents      FOR EACH ROW EXECUTE FUNCTION admintwin_touch();
CREATE TRIGGER discovery_jobs_touch BEFORE UPDATE ON discovery_jobs FOR EACH ROW EXECUTE FUNCTION admintwin_touch();

-- ---------------------------------------------------------------- RLS
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['events','alerts','incidents','incident_timeline','incident_feedback',
                           'discovery_jobs','discovery_findings']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = admintwin_current_tenant()) WITH CHECK (tenant_id = admintwin_current_tenant())', t);
  END LOOP;
END $$;

-- ---------------------------------------------------------------- Права роли приложения
GRANT SELECT, INSERT ON events, incident_timeline, incident_feedback TO admintwin_app;
GRANT SELECT, INSERT, UPDATE ON alerts, incidents, discovery_jobs, discovery_findings TO admintwin_app;
GRANT UPDATE (status) ON incident_feedback TO admintwin_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO admintwin_app;
-- DELETE не выдаётся: удаление — только процедурами ретенции (§9.1) с проверкой legal hold.

COMMIT;
