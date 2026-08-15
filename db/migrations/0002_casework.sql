CREATE TABLE maritime_incident_spatial_correlations (
    correlation_id UUID PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES maritime_incidents(incident_id),
    geofence_id TEXT NOT NULL,
    relation TEXT NOT NULL CHECK (relation IN ('INSIDE', 'OUTSIDE', 'BOUNDARY')),
    latitude DOUBLE PRECISION NOT NULL CHECK (latitude >= -90 AND latitude <= 90),
    longitude DOUBLE PRECISION NOT NULL CHECK (longitude >= -180 AND longitude <= 180),
    evidence_sha256 TEXT NOT NULL CHECK (evidence_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    correlated_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (incident_id, geofence_id)
);

CREATE TABLE maritime_incident_assignments (
    incident_id TEXT PRIMARY KEY REFERENCES maritime_incidents(incident_id),
    analyst_id TEXT NOT NULL,
    assigned_by TEXT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL,
    incident_version BIGINT NOT NULL CHECK (incident_version > 0),
    CHECK (analyst_id <> assigned_by)
);

ALTER TABLE maritime_incident_outbox
    DROP CONSTRAINT IF EXISTS maritime_incident_outbox_event_type_check;
ALTER TABLE maritime_incident_outbox
    ADD CONSTRAINT maritime_incident_outbox_event_type_check
    CHECK (event_type IN ('incident.created', 'incident.status_changed', 'incident.spatial_correlated', 'incident.assigned'));

CREATE INDEX maritime_incident_spatial_correlations_geofence_idx
    ON maritime_incident_spatial_correlations (geofence_id, created_at);
