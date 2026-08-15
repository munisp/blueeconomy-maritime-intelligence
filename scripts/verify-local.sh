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
MIGRATION_PATH="$repo_root/db/migrations/0001_incidents.sql,$repo_root/db/migrations/0002_casework.sql,$repo_root/db/migrations/0003_outbox_delivery.sql,$repo_root/db/migrations/0004_authorized_feed_sources.sql" PORT=18081 AUTH_MODE=loopback_trusted_proxy \
"$server_binary" >"$repo_root/.integration-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 30); do if curl --fail --silent http://127.0.0.1:18081/healthz >/dev/null; then break; fi; sleep 1; done
curl --fail --silent http://127.0.0.1:18081/healthz >/dev/null
DATABASE_URL='postgres://blueeconomy:local-only-integration-password@127.0.0.1:55434/blueeconomy_intelligence?sslmode=disable' SKIP_MIGRATION=true go test -tags feedintegration -race ./internal/incident -run 'Test(AuthorizedFeedAdmission|SignedFeedIncidentIsAtomic)AgainstPostgreSQL' -count=1
if curl --silent --show-error -o /tmp/incident-unauthenticated.json -w '%{http_code}' -X GET http://127.0.0.1:18081/v1/incidents/incident-001 | grep -q '^401$'; then :; else echo 'unauthenticated incident request was not rejected' >&2; exit 1; fi
headers=(-H 'Content-Type: application/json' -H 'X-Trusted-Proxy: loopback' -H 'X-Authenticated-Principal: integration-operator')
payload='{"incident_id":"incident-001","source_event_id":"event-001","category":"distress","severity":"HIGH","title":"Distress alert","description":"Verified distress alert from approved source","occurred_at":"2026-08-15T12:00:00Z","created_by":"operator-001"}'
created=$(curl --fail --silent -X POST http://127.0.0.1:18081/v1/incidents "${headers[@]}" --data "$payload")
printf '%s' "$created" | grep -q '"status":"OPEN"'
printf '%s' "$created" | grep -q '"version":1'
correlation_payload='{"geofence_id":"port-a","relation":"INSIDE","latitude":6.45,"longitude":3.39,"evidence_sha256":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","correlated_by":"spatial-engine"}'
correlation=$(curl --fail --silent -X POST http://127.0.0.1:18081/v1/incidents/incident-001/correlations "${headers[@]}" --data "$correlation_payload")
printf '%s' "$correlation" | grep -q '"relation":"INSIDE"'
correlation_replay=$(curl --fail --silent -X POST http://127.0.0.1:18081/v1/incidents/incident-001/correlations "${headers[@]}" --data "$correlation_payload")
test "$correlation" = "$correlation_replay"
if curl --silent --show-error -o /tmp/incident-correlation-conflict.json -w '%{http_code}' -X POST http://127.0.0.1:18081/v1/incidents/incident-001/correlations "${headers[@]}" --data '{"geofence_id":"port-a","relation":"OUTSIDE","latitude":6.45,"longitude":3.39,"evidence_sha256":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","correlated_by":"spatial-engine"}' | grep -q '^409$'; then :; else echo 'conflicting spatial correlation was not rejected' >&2; exit 1; fi
assignment=$(curl --fail --silent -X POST http://127.0.0.1:18081/v1/incidents/incident-001/assignment "${headers[@]}" --data '{"expected_version":1,"analyst_id":"analyst-001","assigned_by":"supervisor-001"}')
printf '%s' "$assignment" | grep -q '"analyst_id":"analyst-001"'
replay=$(curl --fail --silent -X POST http://127.0.0.1:18081/v1/incidents "${headers[@]}" --data "$payload")
printf '%s' "$replay" | grep -q '"source_event_id":"event-001"'
printf '%s' "$replay" | grep -q '"version":2'
if curl --silent --show-error -o /tmp/incident-conflict.json -w '%{http_code}' -X POST http://127.0.0.1:18081/v1/incidents "${headers[@]}" --data '{"incident_id":"incident-001","source_event_id":"event-001","category":"pollution","severity":"CRITICAL","title":"Changed","description":"Changed","occurred_at":"2026-08-15T12:00:00Z","created_by":"operator-001"}' | grep -q '^409$'; then :; else echo 'conflicting source-event reuse was not rejected' >&2; exit 1; fi
ack=$(curl --fail --silent -X POST http://127.0.0.1:18081/v1/incidents/incident-001/acknowledge "${headers[@]}" --data '{"expected_version":2}')
printf '%s' "$ack" | grep -q '"status":"ACKNOWLEDGED"'
investigate=$(curl --fail --silent -X POST http://127.0.0.1:18081/v1/incidents/incident-001/investigate "${headers[@]}" --data '{"expected_version":3}')
printf '%s' "$investigate" | grep -q '"status":"INVESTIGATING"'
resolve=$(curl --fail --silent -X POST http://127.0.0.1:18081/v1/incidents/incident-001/resolve "${headers[@]}" --data '{"expected_version":4}')
printf '%s' "$resolve" | grep -q '"status":"RESOLVED"'
close=$(curl --fail --silent -X POST http://127.0.0.1:18081/v1/incidents/incident-001/close "${headers[@]}" --data '{"expected_version":5}')
printf '%s' "$close" | grep -q '"status":"CLOSED"'
container_id=$("${docker_prefix[@]}" ps --filter name=maritime-intelligence-postgres -q | head -n1)
outbox_count=$("${docker_prefix[@]}" exec "$container_id" psql -p 55434 -U blueeconomy -d blueeconomy_intelligence -Atc 'select count(*) from maritime_incident_outbox where incident_id = '\''incident-001'\'';')
test "$outbox_count" = 7
correlation_count=$(${docker_prefix[@]} exec "$container_id" psql -p 55434 -U blueeconomy -d blueeconomy_intelligence -Atc 'select count(*) from maritime_incident_spatial_correlations where incident_id = '\''incident-001'\'';')
test "$correlation_count" = 1
assignment_count=$(${docker_prefix[@]} exec "$container_id" psql -p 55434 -U blueeconomy -d blueeconomy_intelligence -Atc 'select count(*) from maritime_incident_assignments where incident_id = '\''incident-001'\'';')
test "$assignment_count" = 1
printf '%s\n' 'S2 real PostgreSQL integration passed: authentication, incident creation, exact replay, spatial correlation replay/conflict, analyst assignment, lifecycle and outbox atomicity.'
