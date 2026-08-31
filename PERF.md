# Performance Notes (Phase 11 audit)

## Findings

- **Indexes**: migrations 0001-0009 already cover the audited predicates:
  outbox unpublished + claim partials (drain uses `FOR UPDATE SKIP LOCKED
  LIMIT 1`), feed_events `(source_id, source_event_id)` PK + received_at,
  isr_events mmsi/classification/modality, vessel_tracks mmsi +
  track_associations track, outcome_ledger entry_kind. No missing index was
  justified by the query code, so no migration was added.
- **Unbounded queries**: all drains and list reads are `LIMIT`-bounded. The
  one full-set read, `isr.Store.OutcomeAggregates` (`GROUP BY entry_kind,
  metric, unit`), is an aggregate by design and insurer-read-only; a
  materialized rollup is a future option, not a defect.
- **N+1**: none found; feed ingest and casework use single set-based
  statements.

## Changes

- **Connection pool sizing (env, opt-in)** — applied to the incident store
  pool and the isr-worker pool. Unset variables keep pgx defaults; invalid
  values fail closed at startup:
  - `MI_DB_POOL_MAX_CONNS` (default: pgx default = max(4, NumCPU))
  - `MI_DB_POOL_MIN_CONNS` (default: 0)
  - `MI_DB_POOL_MAX_CONN_IDLE_SEC` (default: 1800)
  - `MI_DB_POOL_MAX_CONN_LIFE_SEC` (default: 3600)

## Remaining recommendations

- Outbox publisher (kafka-go, `RequireAll`, `Async=false`) writes one message
  per call; consider `BatchSize`/`BatchTimeout` knobs if publish throughput
  becomes the bottleneck (left unchanged to preserve per-message ack
  semantics).
- `maritime_track_associations` time-ordered replay
  (`ORDER BY observed_at, associated_at, ...`) is served by the track index;
  add `(track_id, observed_at)` if replays over long tracks become hot.
