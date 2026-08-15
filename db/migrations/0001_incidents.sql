CREATE TABLE maritime_incidents (
    incident_id TEXT PRIMARY KEY,
    source_event_id TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'CLOSED')),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0)
);

CREATE TABLE maritime_incident_outbox (
    event_id UUID PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES maritime_incidents(incident_id),
    event_type TEXT NOT NULL CHECK (event_type IN ('incident.created', 'incident.status_changed')),
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ
);

CREATE INDEX maritime_incident_outbox_unpublished_idx ON maritime_incident_outbox (created_at) WHERE published_at IS NULL;
