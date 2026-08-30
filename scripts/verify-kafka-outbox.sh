#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
docker_prefix=()
if ! docker info >/dev/null 2>&1; then
  if sudo -n docker info >/dev/null 2>&1; then docker_prefix=(sudo docker); else echo 'Docker daemon is unavailable' >&2; exit 1; fi
fi
compose=("${docker_prefix[@]}" compose -f docker-compose.integration.yml)
publisher_pid=''
publisher_binary=''
server_pid=''
server_binary=''
cleanup() {
  if [[ -n "$publisher_pid" ]]; then kill "$publisher_pid" 2>/dev/null || true; wait "$publisher_pid" 2>/dev/null || true; fi
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
  if [[ -n "$publisher_binary" ]]; then rm -f "$publisher_binary"; fi
  if [[ -n "$server_binary" ]]; then rm -f "$server_binary"; fi
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
"${compose[@]}" up -d --wait postgres kafka kafka-init
server_binary=$(mktemp)
publisher_binary=$(mktemp)
GOFLAGS='' go build -o "$server_binary" ./cmd/maritime-intelligence
GOFLAGS='' go build -o "$publisher_binary" ./cmd/maritime-intelligence-outbox-publisher
export DATABASE_URL='postgres://blueeconomy:local-only-integration-password@127.0.0.1:55434/blueeconomy_intelligence?sslmode=disable'
MIGRATION_PATH="$repo_root/db/migrations/0001_incidents.sql,$repo_root/db/migrations/0002_casework.sql,$repo_root/db/migrations/0003_outbox_delivery.sql,$repo_root/db/migrations/0004_authorized_feed_sources.sql,$repo_root/db/migrations/0005_feed_source_revocations.sql,$repo_root/db/migrations/0006_feed_source_key_rotation.sql" PORT=18084 AUTH_MODE=loopback_trusted_proxy "$server_binary" >"$repo_root/.kafka-server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 30); do if curl --fail --silent http://127.0.0.1:18084/healthz >/dev/null; then break; fi; sleep 1; done
curl --fail --silent http://127.0.0.1:18084/healthz >/dev/null
OUTBOX_WORKER_ID='worker-kafka-local' KAFKA_BROKERS='127.0.0.1:29092' KAFKA_TOPIC='maritime.incident.v1' OUTBOX_POLL_INTERVAL='250ms' OUTBOX_MAX_BACKOFF='5s' \
  "$publisher_binary" >"$repo_root/.kafka-publisher.log" 2>&1 &
publisher_pid=$!
python3 - <<'PY'
import base64, hashlib, json, subprocess, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
source_id = 'vts-kafka-feed'
registered_by = 'registrar-kafka'
activated_by = 'activator-kafka'

def run_sql(statement, capture=True):
    return subprocess.run(
        ['psql', 'postgres://blueeconomy:local-only-integration-password@127.0.0.1:55434/blueeconomy_intelligence?sslmode=disable', '-v', 'ON_ERROR_STOP=1', '-Atc', statement],
        check=True, capture_output=capture, text=True,
    ).stdout.strip() if capture else None

def registration_request(public_key_b64, source_id, source_kind, authority, registered_by):
    return f"INSERT INTO maritime_feed_sources (source_id, source_kind, authority, public_key, key_fingerprint, registered_by, active, created_at, updated_at) VALUES ('{source_id}', '{source_kind}', '{authority}', decode('{public_key_b64.hex()}', 'hex'), 'sha256:{hashlib.sha256(public_key_b64).hexdigest()}', '{registered_by}', false, now(), now())"

# Maker-checker registration and activation mirror the service contract: a
# distinct verified principal activates the source after registration.
run_sql(registration_request(public_key, source_id, 'VTS', 'local-authority', registered_by))
run_sql(f"INSERT INTO maritime_feed_source_activations (source_id, registered_by, activated_by, activated_at) VALUES ('{source_id}', '{registered_by}', '{activated_by}', now())")
run_sql(f"UPDATE maritime_feed_sources SET active = true, updated_at = now() WHERE source_id = '{source_id}'")

def feed_signing_bytes(source_id, source_event_id, payload):
    return ('feed-event\\n' + source_id + '\\n' + source_event_id + '\\nsha256:' + hashlib.sha256(payload).hexdigest()).encode()

def post(path, payload):
    request = subprocess.run([
        'curl', '--fail', '--silent', '-X', 'POST', 'http://127.0.0.1:18084' + path,
        '-H', 'Content-Type: application/json', '-H', 'X-Trusted-Proxy: loopback',
        '-H', 'X-Authenticated-Principal: integration-operator',
        '-H', 'X-Authenticated-Clearance: UNCLASSIFIED',
        '-H', 'X-Authenticated-Roles: isr-analyst,isr-feed-ingest',
        '--data', json.dumps(payload),
    ], check=True, capture_output=True, text=True)
    return json.loads(request.stdout)

incident_payload = json.dumps({
    'incident_id': 'incident-kafka-001',
    'source_event_id': source_id + ':vts-event-kafka-001',
    'category': 'SECURITY',
    'severity': 'HIGH',
    'title': 'Signed VTS exception',
    'description': 'Signed feed event admitted through the local HTTP surface',
    'occurred_at': '2026-08-15T12:00:00Z',
    'created_by': 'feed:' + source_id,
}, separators=(',', ':')).encode()
signature = base64.b64encode(private_key.sign(feed_signing_bytes(source_id, 'vts-event-kafka-001', incident_payload))).decode()
created = post('/v1/feed-events/admit-incident', {
    'source_id': source_id,
    'source_event_id': 'vts-event-kafka-001',
    'payload_base64': base64.b64encode(incident_payload).decode(),
    'signature_base64': signature,
})
assert created['incident']['incident_id'] == 'incident-kafka-001', created

def await_outbox(predicate, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        row = run_sql("SELECT event_type, payload::text, published_at IS NOT NULL FROM maritime_incident_outbox WHERE incident_id = 'incident-kafka-001' ORDER BY created_at LIMIT 1")
        if row and predicate(row):
            return row
        time.sleep(0.5)
    raise SystemExit('outbox publication timed out: ' + (row or 'no rows'))

row = await_outbox(lambda value: value.endswith('|t'))
event_type, payload_text, _ = row.split('|')
assert event_type == 'incident.created', row
event = json.loads(payload_text)
assert event['incident_id'] == 'incident-kafka-001', event
print('S3 Kafka outbox publication passed (signed feed incident -> PostgreSQL outbox -> publisher -> marked published).')
PY
