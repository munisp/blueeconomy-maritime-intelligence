#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
docker_prefix=()
if ! docker info >/dev/null 2>&1; then
  if sudo -n docker info >/dev/null 2>&1; then docker_prefix=(sudo docker); else echo 'Docker daemon is unavailable' >&2; exit 1; fi
fi
compose=("${docker_prefix[@]}" compose -f docker-compose.integration.yml)
server_pid=''
server_binary=''
cleanup() {
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
  if [[ -n "$server_binary" ]]; then rm -f "$server_binary"; fi
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
"${compose[@]}" up -d --wait postgres
server_binary=$(mktemp)
GOFLAGS='' go build -o "$server_binary" ./cmd/maritime-intelligence
DATABASE_URL='postgres://blueeconomy:local-only-integration-password@127.0.0.1:55434/blueeconomy_intelligence?sslmode=disable' \
MIGRATION_PATH="$repo_root/migrations" PORT=18081 AUTH_MODE=loopback_trusted_proxy \
  "$server_binary" >"$repo_root/.integration-server.log" 2>&1 &
server_pid=$!
trap - EXIT
for _ in $(seq 1 60); do
  if curl -sf http://127.0.0.1:18081/healthz >/dev/null; then break; fi
  sleep 1
done
curl -sf http://127.0.0.1:18081/healthz >/dev/null
old_key=$(python3 - <<'PY'
import base64
print(base64.urlsafe_b64encode(bytes(range(1,33))).decode().rstrip('='))
PY
)
new_key=$(python3 - <<'PY'
import base64
print(base64.urlsafe_b64encode(bytes(range(33,65))).decode().rstrip('='))
PY
)
admin=(-H 'X-Trusted-Proxy: loopback' -H 'X-Authenticated-Principal: admin-1' -H 'X-Authenticated-Clearance: UNCLASSIFIED')
create=$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18081/v1/feed-sources "${admin[@]}" \
  -H 'Content-Type: application/json' \
  --data "{\"source_id\":\"feed-http-self\",\"source_kind\":\"VTS\",\"authority\":\"local-authority\",\"public_key_base64\":\"$old_key\",\"active\":true}")
[[ "$create" == '400' ]] || { echo "expected self-activation rejection, got $create" >&2; exit 1; }
second_key=$(python3 - <<'PY'
import base64
print(base64.urlsafe_b64encode(bytes(range(65,97))).decode().rstrip('='))
PY
)
conflict=$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18081/v1/feed-sources "${admin[@]}" \
  -H 'Content-Type: application/json' \
  --data "{\"source_id\":\"feed-http-self\",\"source_kind\":\"VTS\",\"authority\":\"local-authority\",\"public_key_base64\":\"$second_key\"}")
[[ "$conflict" == '409' ]] || { echo "expected conflicting re-registration 409, got $conflict" >&2; exit 1; }
status=$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18081/v1/feed-sources "${admin[@]}" \
  -H 'Content-Type: application/json' \
  --data "{\"source_id\":\"feed-http-self\",\"source_kind\":\"VTS\",\"authority\":\"local-authority\",\"public_key_base64\":\"$old_key\"}")
[[ "$status" == '201' ]] || { echo "expected idempotent re-registration 201, got $status" >&2; exit 1; }
rotate=$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18081/v1/feed-sources/feed-http-self/rotate-key "${admin[@]}" \
  -H 'Content-Type: application/json' \
  --data "{\"public_key_base64\":\"$new_key\",\"grace_until\":\"2030-01-01T00:00:00Z\"}")
[[ "$rotate" == '403' ]] || { echo "expected rotate-key denial without activation, got $rotate" >&2; exit 1; }
deny=$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18081/v1/feed-events/admit "${admin[@]}" \
  -H 'Content-Type: application/json' \
  --data "{\"source_id\":\"feed-http-self\",\"source_event_id\":\"evt-1\",\"payload_base64\":\"e30=\",\"signature_base64\":\"$(printf 'x')\"}")
[[ "$deny" == '403' ]] || { echo "expected inactive-source denial, got $deny" >&2; exit 1; }
activated=$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18081/v1/feed-sources/feed-http-self/activate \
  -H 'X-Trusted-Proxy: loopback' -H 'X-Authenticated-Principal: admin-2' -H 'X-Authenticated-Clearance: UNCLASSIFIED')
[[ "$activated" == '403' ]] || { echo "expected activation denial without isr-admin role, got $activated" >&2; exit 1; }
admin_roles=(-H 'X-Trusted-Proxy: loopback' -H 'X-Authenticated-Principal: admin-2' -H 'X-Authenticated-Clearance: UNCLASSIFIED' -H 'X-Authenticated-Roles: isr-admin')
activated=$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18081/v1/feed-sources/feed-http-self/activate "${admin_roles[@]}")
[[ "$activated" == '200' ]] || { echo "expected maker-checker activation 200, got $activated" >&2; exit 1; }
rotate=$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18081/v1/feed-sources/feed-http-self/rotate-key "${admin_roles[@]}" \
  -H 'Content-Type: application/json' \
  --data "{\"public_key_base64\":\"$new_key\",\"grace_until\":\"2030-01-01T00:00:00Z\"}")
[[ "$rotate" == '200' ]] || { echo "expected rotate-key 200 after activation, got $rotate" >&2; exit 1; }
"${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${compose[@]}" up -d --wait postgres
DATABASE_URL='postgres://blueeconomy:local-only-integration-password@127.0.0.1:55434/blueeconomy_intelligence?sslmode=disable' \
MIGRATION_PATH="$repo_root/migrations" PORT=18082 AUTH_MODE=loopback_trusted_proxy \
  "$server_binary" >"$repo_root/.integration-server-2.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 60); do
  if curl -sf http://127.0.0.1:18082/healthz >/dev/null; then break; fi
  sleep 1
done
curl -sf http://127.0.0.1:18082/healthz >/dev/null
list=$(curl -sS http://127.0.0.1:18082/v1/incidents/incident-001 \
  -H 'X-Trusted-Proxy: loopback' -H 'X-Authenticated-Principal: analyst-1' -H 'X-Authenticated-Clearance: UNCLASSIFIED' \
  -H 'X-Authenticated-Roles: isr-analyst')
[[ "$list" == *'"incident_id":"incident-001"'* ]] || { echo 'incident-001 missing after restart' >&2; exit 1; }
psql 'postgres://blueeconomy:local-only-integration-password@127.0.0.1:55434/blueeconomy_intelligence?sslmode=disable' \
  -Atc 'select count(*) from maritime_incident_outbox where incident_id = '\''incident-001'\'';' | grep -q '^1$'
correlation_conflict=$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18082/v1/incidents/incident-001/correlations \
  -H 'X-Trusted-Proxy: loopback' -H 'X-Authenticated-Principal: analyst-1' -H 'X-Authenticated-Clearance: UNCLASSIFIED' \
  -H 'X-Authenticated-Roles: isr-analyst' -H 'Content-Type: application/json' \
  --data '{"geofence_id":"harbour-1","relation":"WITHIN","latitude":6.45,"longitude":3.39,"evidence_sha256":"'$(printf 'b%.0s' {1..64})'","correlated_by":"analyst-2"}')
[[ "$correlation_conflict" == '409' ]] || { echo "expected correlation conflict 409, got $correlation_conflict" >&2; exit 1; }
assignment=$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18082/v1/incidents/incident-001/assignment \
  -H 'X-Trusted-Proxy: loopback' -H 'X-Authenticated-Principal: lead-1' -H 'X-Authenticated-Clearance: UNCLASSIFIED' \
  -H 'X-Authenticated-Roles: isr-analyst' -H 'Content-Type: application/json' \
  --data '{"analyst_id":"analyst-1","assigned_by":"lead-1","expected_version":2}')
[[ "$assignment" == '200' ]] || { echo "expected assignment 200, got $assignment" >&2; exit 1; }
"${compose[@]}" exec -T postgres psql -U blueeconomy -d blueeconomy_intelligence -Atc \
  "select count(*) from maritime_incident_outbox where event_type = 'incident.assigned' and incident_id = 'incident-001';" | grep -q '^1$'
deny=$(curl -sS -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18082/v1/incidents \
  -H 'X-Trusted-Proxy: loopback' -H 'X-Authenticated-Principal: rogue-1' -H 'X-Authenticated-Clearance: UNCLASSIFIED' \
  -H 'X-Authenticated-Roles: auditor' -H 'Content-Type: application/json' \
  --data '{"source_event_id":"rogue:1","category":"SECURITY","severity":"HIGH","title":"forged","occurred_at":"2026-01-01T00:00:00Z"}')
[[ "$deny" == '403' ]] || { echo "expected read-only role denial 403, got $deny" >&2; exit 1; }
kill "$server_pid" 2>/dev/null || true
wait "$server_pid" 2>/dev/null || true
server_pid=''
printf '%s\n' 'S2 real Postgres integration passed (pending-activation discipline, maker-checker activation, key rotation, durable restarts, idempotency conflicts, role-gated mutations).'
