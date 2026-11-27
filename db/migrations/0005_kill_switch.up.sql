-- Состояние kill switch (§11.7): переживает рестарт и общее для всех реплик ядра.
-- scope: 'platform' или UUID tenant. Читается и пишется только платформенной ролью ядра (без доступа admintwin_app).
BEGIN;
CREATE TABLE kill_switch_state (
  scope      text PRIMARY KEY,
  active     boolean NOT NULL,
  reason     text NOT NULL DEFAULT '',
  actor      text NOT NULL DEFAULT '',
  generation bigint NOT NULL DEFAULT 0,
  changed_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON kill_switch_state FROM PUBLIC;
COMMIT;
