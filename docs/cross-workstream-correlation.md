# Cross-Workstream Anomaly Correlation Contract

Deep Blue Project ISR analytics (Workstream F) emits behaviour anomalies so
that `blueeconomy-security-operations`' `cross-workstream-correlation`
detection rule (see `rules/detection-rules.yaml`: window 15m,
`min_workstreams: 2`, severity critical) can fuse them with anomalies from
Workstream B (ferries.telemetry) and Workstream E (fisheries EEZ).

## Emission path

Anomalies are persisted and published through the transactional outbox to
Kafka topic `maritime.behaviour.v1` as platform envelope v1.0 messages:

```json
{
  "envelope_version": "1.0",
  "event_id": "<uuid>",
  "event_type": "behaviour.<kind>",
  "topic": "maritime.behaviour.v1",
  "classification": "UNCLASSIFIED|RESTRICTED|CONFIDENTIAL|SECRET",
  "source": "blueeconomy-maritime-intelligence",
  "aggregate_key": "<anomaly_id>",
  "occurred_at": "<rfc3339>",
  "payload": { ... }
}
```

The envelope `classification` always equals the wrapped event's
classification label; a mismatch is rejected fail-closed at seal time and
cannot reach the topic. The same contract applies to `maritime.isr.v1`
(detection admissions) and `maritime.outcome.v1` (confirmed outcome-ledger
entries).

## Anomaly payload

```json
{
  "anomaly_id": "anomaly-<kind>-<track>-<unix-nanos>",
  "kind": "dark-vessel|speed-outlier|rendezvous|loitering",
  "track_ids": ["<track-or-mmsi-bound-id>", "..."],
  "zone_id": "<optional zone>",
  "classification": "<label>",
  "detected_at": "<rfc3339>",
  "detail": "<operator-readable summary>",
  "correlation_refs": ["wsb:ferries.telemetry:<anomaly-id>", "wse:fisheries-eez:<anomaly-id>"]
}
```

## Correlation reference convention

`correlation_refs` carries cross-cluster anomaly identifiers in the form
`<workstream>:<stream>:<anomaly-id>`:

- `wsb:ferries.telemetry:<id>` — Workstream B ferry telemetry anomaly.
- `wse:fisheries-eez:<id>` — Workstream E fisheries EEZ anomaly.

References are validated as canonical identifiers at detection admission and
propagated verbatim onto every anomaly raised from the fused track. The
security-operations rule consumes the envelope, groups by shared
`correlation_refs` (or shared track/zone identifiers) across at least
`min_workstreams` distinct workstreams inside the 15-minute window, and
raises a critical cross-cluster alert.

## Consumption guarantees

- At-least-once delivery via the leased outbox (`maritime_isr_outbox`);
  consumers must deduplicate on `event_id`.
- Kafka headers repeat `x-blueeconomy-classification` and
  `x-blueeconomy-envelope-version` so consumers can route/filter without
  opening classified payloads above their clearance.
- Classified-data discipline: consumers above `UNCLASSIFIED` clearance handle
  labels and anomaly metadata only; track points are never emitted on the
  topic.
