#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
kafka_root=/home/ubuntu/blueeconomy-data-platform/integration/kafka-delta
pg_compose=(sudo docker compose -f "$repo_root/docker-compose.integration.yml")
kafka_compose=(sudo docker compose -f "$kafka_root/compose.yaml")
service_pid=''
publisher_pid=''
service_binary=''
publisher_binary=''
key_dir=''
cleanup() {
  if [[ -n "$publisher_pid" ]]; then kill "$publisher_pid" 2>/dev/null || true; wait "$publisher_pid" 2>/dev/null || true; fi
  if [[ -n "$service_pid" ]]; then kill "$service_pid" 2>/dev/null || true; wait "$service_pid" 2>/dev/null || true; fi
  [[ -z "$service_binary" ]] || rm -f "$service_binary"
  [[ -z "$publisher_binary" ]] || rm -f "$publisher_binary"
  [[ -z "$key_dir" ]] || rm -rf "$key_dir"
  "${pg_compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  "${kafka_compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${pg_compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${kafka_compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${pg_compose[@]}" up -d --wait postgres
"${kafka_compose[@]}" up -d
for _ in $(seq 1 120); do
  if "${kafka_compose[@]}" exec -T kafka /opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server 127.0.0.1:59092 >/dev/null 2>&1; then break; fi
  sleep 1
done
"${kafka_compose[@]}" exec -T kafka /opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server 127.0.0.1:59092 >/dev/null
readonly topic='blueeconomy.maritime.incidents.local'
"${kafka_compose[@]}" exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server 127.0.0.1:59092 --create --if-not-exists --topic "$topic" --partitions 1 --replication-factor 1 >/dev/null

service_binary=$(mktemp)
publisher_binary=$(mktemp)
cd "$repo_root"
go build -o "$service_binary" ./cmd/maritime-intelligence
go build -o "$publisher_binary" ./cmd/maritime-intelligence-outbox-publisher
DATABASE_URL='postgres://blueeconomy:local-only-integration-password@127.0.0.1:55434/blueeconomy_intelligence?sslmode=disable' \
MIGRATION_PATH="$repo_root/db/migrations/0001_incidents.sql,$repo_root/db/migrations/0002_casework.sql,$repo_root/db/migrations/0003_outbox_delivery.sql,$repo_root/db/migrations/0004_authorized_feed_sources.sql" \
PORT=18082 AUTH_MODE=loopback_trusted_proxy "$service_binary" >"$repo_root/.kafka-service.log" 2>&1 &
service_pid=$!
for _ in $(seq 1 30); do if curl --fail --silent http://127.0.0.1:18082/healthz >/dev/null; then break; fi; sleep 1; done
curl --fail --silent http://127.0.0.1:18082/healthz >/dev/null
headers=(-H 'Content-Type: application/json' -H 'X-Trusted-Proxy: loopback' -H 'X-Authenticated-Principal: kafka-integration-operator')
event_id="kafka-outbox-event-$(date +%s%N)"
source_id='kafka-feed-source'
source_event_id="feed-$event_id"
key_dir="$(mktemp -d)"
openssl genpkey -algorithm ED25519 -out "$key_dir/signing.key" >/dev/null 2>&1
public_key_base64="$(openssl pkey -in "$key_dir/signing.key" -pubout -outform DER | tail -c 32 | base64 -w0 | tr -d '=')"
curl --fail --silent -X POST http://127.0.0.1:18082/v1/feed-sources "${headers[@]}" \
  --data "{\"source_id\":\"$source_id\",\"source_kind\":\"RADAR\",\"authority\":\"local-kafka-authority\",\"public_key_base64\":\"$public_key_base64\",\"active\":true}" >/dev/null
payload="{\"incident_id\":\"$event_id\",\"source_event_id\":\"$source_id:$source_event_id\",\"category\":\"distress\",\"severity\":\"HIGH\",\"title\":\"Kafka signed feed integration\",\"description\":\"authorized source to broker delivery\",\"occurred_at\":\"2026-08-15T12:00:00Z\",\"created_by\":\"feed:$source_id\"}"
payload_digest="$(printf '%s' "$payload" | sha256sum | awk '{print $1}')"
printf '%s\n%s\nsha256:%s' "$source_id" "$source_event_id" "$payload_digest" >"$key_dir/signing.input"
signature_base64="$(openssl pkeyutl -sign -rawin -inkey "$key_dir/signing.key" -in "$key_dir/signing.input" | base64 -w0)"
payload_base64="$(printf '%s' "$payload" | base64 -w0)"
curl --fail --silent -X POST http://127.0.0.1:18082/v1/feed-events/admit-incident "${headers[@]}" \
  --data "{\"source_id\":\"$source_id\",\"source_event_id\":\"$source_event_id\",\"payload_base64\":\"$payload_base64\",\"signature_base64\":\"$signature_base64\"}" >/dev/null
DATABASE_URL='postgres://blueeconomy:local-only-integration-password@127.0.0.1:55434/blueeconomy_intelligence?sslmode=disable' \
KAFKA_BROKERS='127.0.0.1:59092' KAFKA_TOPIC="$topic" KAFKA_TRANSPORT=local_plaintext OUTBOX_WORKER_ID='s2-kafka-integration-worker' \
MIGRATION_PATH="$repo_root/db/migrations/0001_incidents.sql,$repo_root/db/migrations/0002_casework.sql,$repo_root/db/migrations/0003_outbox_delivery.sql" \
OUTBOX_POLL_INTERVAL=100ms "$publisher_binary" >"$repo_root/.kafka-publisher.log" 2>&1 &
publisher_pid=$!
container_id=$("${pg_compose[@]}" ps -q postgres)
for _ in $(seq 1 60); do
  published=$(sudo docker exec "$container_id" psql -p 55434 -U blueeconomy -d blueeconomy_intelligence -Atc "select count(*) from maritime_incident_outbox where incident_id = '$event_id' and published_at is not null;")
  [[ "$published" == '1' ]] && break
  sleep 1
done
test "$published" = '1'
message=$("${kafka_compose[@]}" exec -T kafka /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server 127.0.0.1:59092 --topic "$topic" --from-beginning --max-messages 1 --timeout-ms 20000 --property print.key=true --property print.headers=true)
printf '%s\n' "$message" | grep -q "$event_id"
printf '%s\n' "$message" | grep -q 'incident.created'
printf '%s\n' 'S2 authentic Kafka outbox delivery passed: PostgreSQL event claimed, Kafka broker acknowledged, consumer received event identity/type, and PostgreSQL published_at was recorded.'
