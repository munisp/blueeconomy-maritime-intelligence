-- Workstream F: fused vessel tracks, association audit and behaviour
-- anomalies. Track classification is the maximum over associated detections.

CREATE TABLE maritime_vessel_tracks (
    track_id TEXT PRIMARY KEY CHECK (track_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    mmsi TEXT CHECK (mmsi IS NULL OR mmsi ~ '^[0-9]{9}$'),
    classification TEXT NOT NULL CHECK (classification IN ('UNCLASSIFIED', 'RESTRICTED', 'CONFIDENTIAL', 'SECRET')),
    first_observed_at TIMESTAMPTZ NOT NULL,
    last_observed_at TIMESTAMPTZ NOT NULL,
    point_count INTEGER NOT NULL CHECK (point_count >= 0),
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX maritime_vessel_tracks_classification_idx
    ON maritime_vessel_tracks (classification, last_observed_at DESC);
CREATE INDEX maritime_vessel_tracks_mmsi_idx
    ON maritime_vessel_tracks (mmsi) WHERE mmsi IS NOT NULL;

-- Association audit: which signed detections were fused into which track.
CREATE TABLE maritime_track_associations (
    track_id TEXT NOT NULL REFERENCES maritime_vessel_tracks(track_id),
    source_id TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    modality TEXT NOT NULL CHECK (modality IN ('AIS', 'SAR', 'RF', 'ACOUSTIC', 'OPTICAL')),
    classification TEXT NOT NULL CHECK (classification IN ('UNCLASSIFIED', 'RESTRICTED', 'CONFIDENTIAL', 'SECRET')),
    observed_at TIMESTAMPTZ NOT NULL,
    associated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (source_id, source_event_id)
);

CREATE INDEX maritime_track_associations_track_idx
    ON maritime_track_associations (track_id, observed_at);

CREATE TABLE maritime_behaviour_anomalies (
    anomaly_id TEXT PRIMARY KEY CHECK (anomaly_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,191}$'),
    kind TEXT NOT NULL CHECK (kind IN ('dark-vessel', 'speed-outlier', 'rendezvous', 'loitering')),
    classification TEXT NOT NULL CHECK (classification IN ('UNCLASSIFIED', 'RESTRICTED', 'CONFIDENTIAL', 'SECRET')),
    track_ids JSONB NOT NULL,
    zone_id TEXT,
    detail TEXT NOT NULL CHECK (length(detail) BETWEEN 1 AND 1024),
    correlation_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    detected_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX maritime_behaviour_anomalies_classification_idx
    ON maritime_behaviour_anomalies (classification, detected_at DESC);
