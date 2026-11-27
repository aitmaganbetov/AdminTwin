#!/usr/bin/env bash
# Сквозной сценарий MVP (ТЗ §21) на живых процессах: ядро (симулятор) + AI-оркестратор (офлайн-модель).
# Событие HTTP 502 → инцидент с владельцем (< 30 с) → triage → RCA (Network/DevOps/DBA параллельно,
# read tools через ядро) → гипотеза с evidence → ChangeRequest по инциденту → исполнение → post-check →
# связь изменения в timeline инцидента. Реальные LLM не вызываются.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
TOKEN="e2e-mvp-service-token-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
T=11111111-1111-4111-8111-111111111111
WEB=a0000000-0000-4000-8000-000000000002
CORE_PORT="${CORE_PORT:-18180}"; ORCH_PORT="${ORCH_PORT:-18190}"
CORE="http://127.0.0.1:$CORE_PORT"
PY="${PYTHON:-$ROOT/ai/.venv/bin/python}"
cleanup() { kill "${CORE_PID:-}" "${ORCH_PID:-}" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- core log"; tail -20 "$WORK/core.log"; echo "--- orchestrator log"; grep -v healthz "$WORK/orch.log" | tail -20; exit 1; }
json() { "$PY" -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {'d': d}))" "$1"; }

(cd "$ROOT" && go build -o "$WORK/core" ./cmd/admintwin-core)
start_core() {
  [ -n "${CORE_PID:-}" ] && { kill "$CORE_PID" 2>/dev/null || true; wait "$CORE_PID" 2>/dev/null || true; }
  for i in $(seq 1 40); do curl -sf "$CORE/api/v1/health/platform" >/dev/null 2>&1 || break; sleep 0.25; done
  (cd "$ROOT" && ADMINTWIN_DEV_AUTH=true ADMINTWIN_SIMULATOR=true ADMINTWIN_FIXTURES=infra/dev/fixtures.yaml \
    ADMINTWIN_ADDR=127.0.0.1:$CORE_PORT ADMINTWIN_METRICS_ADDR=127.0.0.1:0 ADMINTWIN_SERVICE_TOKEN="$TOKEN" \
    ADMINTWIN_ORCHESTRATOR_URL=http://127.0.0.1:$ORCH_PORT ADMINTWIN_INCIDENT_AUTO_TRIAGE=true \
    exec "$WORK/core" >>"$WORK/core.log" 2>&1) & CORE_PID=$!   # exec: PID — сам процесс ядра
  for i in $(seq 1 40); do curl -sf "$CORE/api/v1/health/platform" >/dev/null 2>&1 && return 0; sleep 0.25; done
  fail "core did not start"
}
start_core
(cd "$ROOT/ai" && ADMINTWIN_SERVICE_TOKEN="$TOKEN" ADMINTWIN_AI_OFFLINE_FAKE=true ADMINTWIN_CORE_URL="$CORE" \
  ADMINTWIN_ORCHESTRATOR_HOST=127.0.0.1 ADMINTWIN_ORCHESTRATOR_PORT=$ORCH_PORT exec "$PY" -m admintwin_ai.service >"$WORK/orch.log" 2>&1) & ORCH_PID=$!

for i in $(seq 1 60); do
  st=$(curl -sf "$CORE/api/v1/health/platform" 2>/dev/null | json "d['components'].get('ai_orchestrator')" 2>/dev/null || true)
  [ "$st" = "ok" ] && break; sleep 0.5
done
[ "${st:-}" = "ok" ] || fail "core/orchestrator did not become healthy"

U=(-H "X-AdminTwin-Tenant: $T" -H "Content-Type: application/json")
ENG=("${U[@]}" -H "X-AdminTwin-Actor: eng-1" -H "X-AdminTwin-Roles: engineer" -H "X-AdminTwin-Scopes: devops")
SVC=("${U[@]}" -H "X-AdminTwin-Service-Token: $TOKEN" -H "X-AdminTwin-Actor: nginx-collector" -H "X-AdminTwin-Actor-Kind: service")

# Авария: контейнер app-api убит (OOM).
curl -sf -X POST "${ENG[@]}" "$CORE/api/v1/dev/simulator" -d "{\"asset_id\":\"$WEB\",\"object\":\"3f2a9c1b7d4e\",\"running\":false}" >/dev/null

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
INC=$(curl -sf -X POST "${SVC[@]}" "$CORE/api/v1/telemetry/events" -d "{\"events\":[{\"asset_id\":\"$WEB\",\"kind\":\"http_5xx\",\"severity\":\"high\",\"title\":\"HTTP 502 from upstream app-api\",\"fingerprint\":\"e2e-502-$$\",\"value\":38,\"at\":\"$NOW\"}]}" | json "d['incidents'][0]")
echo "incident $INC"
OWNER=$(curl -sf "${ENG[@]}" "$CORE/api/v1/incidents/$INC" | json "d['owner']")
LAT=$(curl -sf "${ENG[@]}" "$CORE/api/v1/incidents/$INC" | json "d['latency']['event_to_assigned_ms']")
[ "$OWNER" = "web-team" ] || fail "owner=$OWNER"
[ "$LAT" -lt 30000 ] || fail "assignment took ${LAT} ms (>= 30 s)"
echo "PASS incident created and assigned to $OWNER in ${LAT} ms"

for i in $(seq 1 120); do
  RCA=$(curl -sf "${ENG[@]}" "$CORE/api/v1/incidents/$INC" | json "d['rca']['status']")
  case "$RCA" in completed|uncertain|failed) break;; esac; sleep 0.5
done
[ "$RCA" = "completed" ] || fail "RCA status=$RCA"
curl -sf "${ENG[@]}" "$CORE/api/v1/incidents/$INC" >"$WORK/inc.json"
AGENTS=$(json "sorted(d['rca']['agents'])" <"$WORK/inc.json")
TOP=$(json "d['rca']['hypotheses'][0]['cause']" <"$WORK/inc.json")
CONF=$(json "d['rca']['hypotheses'][0]['confidence']" <"$WORK/inc.json")
EVID=$(json "len(d['rca']['hypotheses'][0]['supporting'])" <"$WORK/inc.json")
[ "$AGENTS" = "['dba-engineer', 'devops-engineer', 'network-engineer']" ] || fail "agents=$AGENTS"
case "$TOP" in upstream_container_*) ;; *) fail "top hypothesis=$TOP";; esac
[ "$EVID" -ge 1 ] || fail "top hypothesis has no evidence"
echo "PASS RCA by $AGENTS: $TOP (confidence $CONF, $EVID evidence item(s))"

# Исправление — только через ChangeRequest, привязанный к инциденту (standard change в Operator).
CH=$(curl -sf -X POST "${ENG[@]}" -H "Idempotency-Key: e2e-$$" "$CORE/api/v1/changes" \
  -d "{\"runbook_id\":\"docker.container.restart\",\"asset_id\":\"$WEB\",\"params\":{\"container_id\":\"3f2a9c1b7d4e\"},\"reason\":\"RCA: $TOP\",\"incident_id\":\"$INC\"}" | json "d['id']")
for i in $(seq 1 40); do
  CS=$(curl -sf "${ENG[@]}" "$CORE/api/v1/changes/$CH" | json "d['status']")
  case "$CS" in closed|closed_with_compensation|failed|preflight_failed|manual_review) break;; esac; sleep 0.25
done
[ "$CS" = "closed" ] || fail "change status=$CS"
RUN=$(curl -sf -X POST "${ENG[@]}" "$CORE/api/v1/tools/docker.container.inspect" -d "{\"input\":{\"asset_id\":\"$WEB\",\"container\":\"3f2a9c1b7d4e\"}}" | json "d['data']['state']['running']")
[ "$RUN" = "True" ] || fail "container not running after the change"
LINKED=$(curl -sf "${ENG[@]}" "$CORE/api/v1/incidents/$INC" | json "any('$CH' in (e.get('ref') or '') for e in d['timeline'])")
[ "$LINKED" = "True" ] || fail "change not linked in incident timeline"
echo "PASS change $CH verified and closed; container running; linked to incident"

INTEG=$(curl -sf "${U[@]}" -H "X-AdminTwin-Actor: aud-1" -H "X-AdminTwin-Roles: auditor" "$CORE/api/v1/audit-logs/integrity" | json "d['valid']")
[ "$INTEG" = "True" ] || fail "audit chain invalid"
echo "PASS audit hash chain valid"

# Остальные сценарии MVP (§1.4) — каждый на чистом ядре, чтобы инциденты не коррелировали между собой.
scenario() { # name asset kind severity title sim_json
  start_core
  curl -sf -X POST "${ENG[@]}" "$CORE/api/v1/dev/simulator" -d "$6" >/dev/null
  NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local inc rca
  inc=$(curl -sf -X POST "${SVC[@]}" "$CORE/api/v1/telemetry/events" -d "{\"events\":[{\"asset_id\":\"$2\",\"kind\":\"$3\",\"severity\":\"$4\",\"title\":\"$5\",\"fingerprint\":\"e2e-$3-$$\",\"value\":96,\"at\":\"$NOW\"}]}" | json "d['incidents'][0]")
  for i in $(seq 1 120); do
    rca=$(curl -sf "${ENG[@]}" "$CORE/api/v1/incidents/$inc" | json "d['rca']['status']")
    case "$rca" in completed|uncertain|failed) break;; esac; sleep 0.5
  done
  curl -sf "${ENG[@]}" "$CORE/api/v1/incidents/$inc" >"$WORK/inc.json"
  # Результат — через глобальную R: вызов без $(...), иначе start_core обновил бы CORE_PID только в подоболочке.
  R="$rca|$(json "d['rca']['hypotheses'][0]['cause']" <"$WORK/inc.json")|$(json "d['rca'].get('conclusion','')" <"$WORK/inc.json")"
}
scenario disk a0000000-0000-4000-8000-000000000003 disk_usage critical "Disk at 96%" '{"asset_id":"a0000000-0000-4000-8000-000000000003","disk_percent":96}'
case "$R" in completed\|*|uncertain\|*) ;; *) fail "disk scenario: $R";; esac
case "$R" in uncertain\|*) [[ "$R" == *"нужна проверка"* ]] || fail "uncertain result must name the next check: $R";; esac
echo "PASS disk exhaustion: ${R%%|*} — $(echo "$R" | cut -d'|' -f2)"
scenario container $WEB container_down high "Container nginx stopped" "{\"asset_id\":\"$WEB\",\"object\":\"9b8c7d6e5f4a\",\"running\":false}"
case "$R" in completed\|container_*) ;; *) fail "container scenario: $R";; esac
echo "PASS container stop: $(echo "$R" | cut -d'|' -f2)"
echo "MVP end-to-end scenarios: OK"
