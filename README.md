# Blue Economy Maritime Intelligence

This repository implements a real S2 maritime-intelligence incident lifecycle increment for the Blue Economy Platform. It is a Go HTTP service backed by PostgreSQL and does not claim to provide a complete maritime-domain intelligence system or any external vessel-feed integration.

## Implemented controls

The service provides PostgreSQL-backed incident creation sourced from an approved event identity, exact replay of the same immutable incident, fail-closed conflicting source-event reuse, strict severity and timestamp validation, version-checked `OPEN -> ACKNOWLEDGED -> INVESTIGATING -> RESOLVED -> CLOSED` transitions, authenticated local-edge API access, bounded JSON requests and transactional append-only outbox events.

## Local verification

Run:

```bash
scripts/verify-local.sh
```

The runner starts a real PostgreSQL 16.4 container, applies `db/migrations/0001_incidents.sql`, launches the service with explicit configuration and verifies unauthenticated rejection, exact replay, conflicting replay rejection, every lifecycle transition and five persisted outbox events.

Required configuration is `DATABASE_URL`, `MIGRATION_PATH`, `PORT` and `AUTH_MODE=loopback_trusted_proxy`. The service has no in-memory fallback and does not fabricate vessel, AIS or partner data.

## Current boundary

This is a real S2 incident-management foundation. Remaining S2 work includes approved AIS/VTS/radar/port feeds, source trust and provenance policy, geospatial storage and query, rule-driven correlation, map delivery, assignment/escalation policy, external notification, security-operations integration, retention policy and Ministry acceptance.
