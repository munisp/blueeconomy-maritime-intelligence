# Blue Economy Maritime Intelligence

Go HTTP service backed by PostgreSQL implementing the maritime-intelligence
incident lifecycle and Workstream F (Deep Blue Project ISR Analytics —
national-security controlled): multi-modal sensor ingestion with mandatory
classification labelling, vessel-track fusion with behaviour anomaly
detection, a Temporal ISR response workflow, and a dual-control TigerBeetle
outcome ledger.

## Implemented controls

### Incident and signed feed foundation

PostgreSQL-backed incident creation sourced from an approved event identity,
exact replay of the same immutable incident, fail-closed conflicting
source-event reuse (409), strict severity and timestamp validation,
version-checked `OPEN -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED -> CLOSED`
transitions, bounded JSON requests and transactional append-only outbox
events. Feed admission is Ed25519 signature-verified against authorized
sources with revocation and bounded-grace key rotation. Feed replay is
transactional: an identical replay returns the retained evidence, while a
source_event_id reused with a conflicting payload or signature fails closed
with 409.

### Workstream F: ISR analytics

- **Classified-data model.** Every ISR event, track, anomaly and outcome
  record carries a mandatory classification label (`UNCLASSIFIED`,
  `RESTRICTED`, `CONFIDENTIAL`, `SECRET`). Missing or invalid labels are
  rejected fail-closed at validation, service and DB-CHECK layers. Reads are
  clearance-enforced at the service layer (principal clearance must cover the
  record classification; SQL filters constrain on the covered label set and
  every row is re-checked). The `insurer-aggregator` role sees only
  classification-free outcome aggregates — never tracks or detections.
- **Multi-modal ingest.** `POST /v1/isr/detections:admit` admits signed
  detections for modalities AIS (`mmsi`, speed, heading), SAR (`scene_ref` +
  confidence), RF (`frequency_band` + bearing), acoustic (`signature_ref`)
  and optical (`image_ref` + detection boxes). Exactly one modality payload
  per detection; all carry Ed25519 source signatures per the feed pattern.
- **Track fusion.** Multi-modal detections associate into vessel tracks by
  MMSI where available, else by a configurable spatial-temporal correlation
  window (default 10 min / 2 km) under a fused-track ID. An MMSI-bearing
  detection never joins a track carrying a different MMSI. Tracks,
  associations and anomalies are persisted with classification labels.
  Anomaly rules (unit-tested with boundary cases): dark vessel (AIS gap in a
  coverage zone), speed outlier vs the behaviour baseline, rendezvous (two
  tracks within X metres for Y minutes) and loitering in a restricted zone
  (boundary-inclusive polygon containment ported from
  `blueeconomy-waterway-safety/src/geo.rs`). Detection latency is recorded to
  the `isr.anomaly.detection.latency` histogram for the p99 ≤ 5s KPI.
  **Restart discipline.** Before serving, the service rebuilds engine state
  by replaying every persisted `maritime_track_associations` row (joined to
  its retained detection, in observation order) through `Engine.Replay`,
  which pins the original persisted track identity — `GET /v1/isr/tracks`
  serves the pre-restart state immediately. New fused-track IDs are
  UUID-based (`fused-track-<uuid>`), so a post-restart engine can never mint
  an ID that collides with a persisted track. A replay failure aborts
  startup fail-closed. Rule alert flags reset on restart, so a still-active
  anomaly may re-fire once (fail-safe direction). The dark-vessel rule runs
  from a ticker-driven scanner (`ISR_DARK_VESSEL_SCAN_INTERVAL`, default
  `1m`, `0` disables explicitly); emitted anomalies are persisted with their
  `maritime.behaviour.v1` outbox envelopes in the same transaction.
- **Temporal workflow.** `ISRResponseWorkflow`
  (alert → classification by an analyst whose clearance must cover the alert
  → NN officer dispatch → interdiction → outcome capture) with an audit hook
  on every transition and observer queries (`isr.state`, `isr.history`).
  Activities are injected; the testsuite covers the happy path, clearance
  rejection, unconfirmed alerts, audit-failure propagation and startability
  from an admitted anomaly payload. See the starter contract below.

### ISR response workflow starter contract

`cmd/isr-worker` hosts `ISRResponseWorkflow` on the `TEMPORAL_TASK_QUEUE`
task queue (fail-closed on `TEMPORAL_ADDRESS`, `TEMPORAL_NAMESPACE`,
`TEMPORAL_TASK_QUEUE`). The HTTP admission path deliberately stays
Temporal-free: an external starter (alerting rail, security-operations
bridge, or operator tooling) starts one workflow instance per admitted
behaviour anomaly with:

- **Workflow:** `ISRResponseWorkflow` (registered under that exact name).
- **Workflow ID:** the anomaly ID (idempotent start per anomaly).
- **Input:** `workflow.AlertInput{AlertID, AnomalyID, Classification}` mapped
  from the persisted `maritime_behaviour_anomalies` record — `AlertID` and
  `AnomalyID` both set to the anomaly ID, `Classification` to the record's
  clearance label. `internal/workflow/isr_starter_test.go` proves the
  workflow is startable with exactly this payload.
- **Signals:** `isr.classification`, `isr.dispatch`, `isr.interdiction`,
  `isr.outcome`; **queries:** `isr.state`, `isr.history`.
- **Side effects:** audit/outcome envelopes are appended to
  `maritime_isr_outbox` by the worker's activities and drained by the
  outbox publisher.
- **Outcome ledger.** Incident-reduction metrics bind to premium-delta
  evidence through TigerBeetle transfers between two platform accounts.
  Posting is dual-control (`proposed_by` ≠ `confirmed_by`, enforced in the
  service and by a DB CHECK), confirmed entries are immutable (BEFORE
  UPDATE/DELETE trigger, same pattern as financial-controls cvff_approvals),
  and configuration is fail-closed (no outcome confirmation without a
  TigerBeetle client).
- **Events.** Canonical platform envelope v1.0
  (`blueeconomy.contracts.v1.EventEnvelope`, the same camelCase +
  FHIR-message-bundle + provenance shape sealed by the ferry-ticketing and
  financial-controls producers) via the transactional outbox to
  `maritime.isr.v1`, `maritime.behaviour.v1` and `maritime.outcome.v1`. The
  outbox payload column carries the encoded envelope document verbatim.
  Clearance labels map onto the platform `EnvelopeClassification` set
  (`UNCLASSIFIED→INTERNAL`, `RESTRICTED→RESTRICTED`, `CONFIDENTIAL→CONFIDENTIAL`,
  `SECRET→CONFIDENTIAL` — never widening); the original clearance label rides
  as record-level metadata (`clearance`) inside the FHIR bundle entry, and
  the envelope/payload classification match is enforced fail-closed at seal
  time. The outbox publisher runs in `OUTBOX_SOURCE=isr` mode and routes each
  event to the topic recorded on its row.
- **Cross-cluster correlation.** Anomaly payloads carry `correlation_refs`
  (`wsb:ferries.telemetry:<id>`, `wse:fisheries-eez:<id>`) for
  security-operations' `cross-workstream-correlation` rule; see
  [docs/cross-workstream-correlation.md](docs/cross-workstream-correlation.md).

## Authentication and authorization

`AUTH_MODE=loopback_trusted_proxy` keeps the local edge contract (loopback
source, `X-Trusted-Proxy: loopback`, `X-Authenticated-Principal`) and adds
edge-asserted `X-Authenticated-Roles` (comma-separated) and
`X-Authenticated-Clearance`. `AUTH_MODE=keycloak_rs256` verifies Keycloak
RS256 bearer tokens against `OIDC_JWKS_URL` (issuer/audience pinned, JWKS
redirects forbidden, keys refreshed on unknown `kid`), reading roles from
`realm_access.roles`/configured `resource_access` clients and clearance from
the `clearance` claim. Recognized read-side roles: `nimasa-officer`,
`defence-hq-observer`, `nn-officer`, `onsa-observer`, `marine-police`,
`fleet-operator`, `insurer-aggregator` (read-only, aggregates only) and
`auditor`. Every mutating route is additionally gated on a designated
verified-token role (authoritative table in `internal/server/access.go`):
`isr-admin` for feed-source administration (register/activate/revoke/
rotate-key), `isr-feed-ingest` for signed feed event/incident admission and
`detections:admit`, `isr-analyst`/`isr-watch-officer` for incident
create/correlate/assign/transition (including SOS acknowledge),
`isr-analyst` for outcome proposals and `isr-adjudicator` for outcome
confirmations (preserving proposer≠confirmer dual control). Authorization
fails closed: absent, unrecognized or read-only roles are denied every
mutation with 403. Any other `AUTH_MODE` fails closed at startup and per
request.

Feed-source trust is maker-checker: `POST /v1/feed-sources` always creates
the source PENDING (`active:true` in the body is rejected) with the
verified token subject recorded as registrar, and
`POST /v1/feed-sources/{source_id}/activate` requires a distinct
`isr-admin` principal. Signed feed admission accepts only ACTIVE sources;
trust denials (unknown source, non-active source, invalid signature) are
audit-logged in `maritime_feed_admission_denials`. Revocation/key-rotation
audit attribution always comes from the verified token subject — body
`revoked_by`/`rotated_by` fields are ignored.

`/healthz` and `/readyz` (database ping) are unauthenticated; `/metrics`
serves the local Prometheus registry (including the anomaly-detection
latency histogram). OTel tracing follows the sibling-service style:
`OTEL_EXPORTER_OTLP_ENDPOINT` enables OTLP gRPC export; absent or disabled,
an explicit no-op tracer runs and metrics stay local.

Classified-data handling discipline: logs and error responses carry labels
and identifiers only; track content above Unclassified is never logged.

## Configuration

Required: `DATABASE_URL`, `MIGRATION_PATH` (comma-separated, in order),
`PORT`, `AUTH_MODE`. Keycloak mode additionally requires `OIDC_ISSUER`,
`OIDC_AUDIENCE`, `OIDC_JWKS_URL` (https), optional `OIDC_CA_FILE`,
`OIDC_ROLES_CLIENT_IDS`. Fusion zones load from `ISR_ZONES_FILE` (JSON array
of `{zone_id, zone_kind, vertices}`; absent file means no zones, malformed
file fails startup). `ISR_DARK_VESSEL_SCAN_INTERVAL` sets the dark-vessel
scan cadence (default `1m`; `0` disables explicitly; any other non-positive
or unparsable value fails startup). `TIGERBEETLE_ADDRESS` enables the outcome
ledger (optional `TIGERBEETLE_CLUSTER_ID`); unset disables the outcome routes
with 503 rather than fabricating evidence. The service has no in-memory
fallback.

## Local verification

Run:

```bash
scripts/verify-local.sh
```

The runner starts a real PostgreSQL 16.4 container, applies migrations
0001–0009, launches the service with explicit configuration and verifies
unauthenticated rejection, incident replay/conflict behavior, feed signature,
rotation, revocation and outbox behavior. Fusion, anomaly rules,
classification, envelope sealing, auth modes and the Temporal workflow are
covered by unit tests:

```bash
go build ./... && go vet ./... && go test -race ./...
```

## Current boundary

Real S2 casework plus the Workstream F ISR analytics foundation. Track fusion
state is held in-process and rebuilt on startup from the persisted
association audit (track identities are pinned; new IDs are UUID-based and
cannot collide with persisted ones). Remaining: deployed geospatial storage
(PostGIS), external notification rails, retention policy and Ministry
acceptance.
