# Blue Economy Maritime Intelligence

This repository implements a real S2 maritime-intelligence incident lifecycle increment for the Blue Economy Platform. It is a Go HTTP service backed by PostgreSQL and does not claim to provide a complete maritime-domain intelligence system or any external vessel-feed integration.

## Implemented controls

The service provides PostgreSQL-backed incident creation sourced from an approved event identity, exact replay of the same immutable incident, fail-closed conflicting source-event reuse, strict severity and timestamp validation, version-checked `OPEN -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED -> CLOSED` transitions, authenticated local-edge API access, bounded JSON requests and transactional append-only outbox events. It also persists spatial-correlation evidence through `POST /v1/incidents/{incidentID}/correlations` with coordinate/relation/hash validation and exact replay/conflict control, and supports version-checked analyst assignment through `POST /v1/incidents/{incidentID}/assignment` with maker-checker separation.

## Local verification

Run:

```bash
scripts/verify-local.sh
```

The runner starts a real PostgreSQL 16.4 container, applies migrations `0001_incidents.sql` and `0002_casework.sql`, launches the service with explicit configuration and verifies unauthenticated rejection, incident replay/conflict behavior, spatial-correlation replay/conflict behavior, maker-checker assignment, every lifecycle transition, one persisted correlation, one assignment and seven outbox events.

Required configuration is `DATABASE_URL`, `MIGRATION_PATH`, `PORT` and `AUTH_MODE=loopback_trusted_proxy`. The service has no in-memory fallback and does not fabricate vessel, AIS or partner data.

## Current boundary

This is a real S2 incident-management and casework foundation. Remaining S2 work includes approved AIS/VTS/radar/port feeds, source trust and provenance policy, deployed geospatial storage/query and Sedona/PostGIS processing, rule-driven correlation against approved geofences, map delivery, escalation policy, external notification, security-operations integration, retention policy and Ministry acceptance. The local correlation endpoint records an explicitly supplied evaluator result and evidence hash; it does not fabricate or claim an external maritime feed.
