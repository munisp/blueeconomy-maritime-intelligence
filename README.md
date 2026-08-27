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
- **Temporal workflow.** `ISRResponseWorkflow`
  (alert → classification by an analyst whose clearance must cover the alert
  → NN officer dispatch → interdiction → outcome capture) with an audit hook
  on every transition and observer queries (`isr.state`, `isr.history`).
  Activities are injected; the testsuite covers the happy path, clearance
  rejection, unconfirmed alerts and audit-failure propagation.
- **Outcome ledger.** Incident-reduction metrics bind to premium-delta
  evidence through TigerBeetle transfers between two platform accounts.
  Posting is dual-control (`proposed_by` ≠ `confirmed_by`, enforced in the
  service and by a DB CHECK), confirmed entries are immutable (BEFORE
  UPDATE/DELETE trigger, same pattern as financial-controls cvff_approvals),
  and configuration is fail-closed (no outcome confirmation without a
  TigerBeetle client).
- **Events.** Platform envelope v1.0 via the transactional outbox to
  `maritime.isr.v1`, `maritime.behaviour.v1` and `maritime.outcome.v1`. The
  envelope classification must match the event label; mismatches are rejected
  at seal time. The outbox publisher runs in `OUTBOX_SOURCE=isr` mode and
  routes each event to the topic recorded on its row.
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
the `clearance` claim. Recognized roles: `nimasa-officer`,
`defence-hq-observer`, `nn-officer`, `onsa-observer`, `marine-police`,
`fleet-operator`, `insurer-aggregator` (read-only, aggregates only) and
`auditor`. Observer/auditor/insurer roles are denied every mutating route
generically. Any other `AUTH_MODE` fails closed at startup and per request.

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
file fails startup). `TIGERBEETLE_ADDRESS` enables the outcome ledger
(optional `TIGERBEETLE_CLUSTER_ID`); unset disables the outcome routes with
503 rather than fabricating evidence. The service has no in-memory fallback.

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
state is held in-process (snapshots, associations and anomalies are
persisted); rebuilding engine state from retained detections on restart is
follow-up work. Remaining: deployed geospatial storage (PostGIS), external
notification rails, retention policy and Ministry acceptance.
