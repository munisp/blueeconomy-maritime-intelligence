-- Workstream F: multi-modal ISR event admission with mandatory
-- classification labelling. Classification is enforced at ingestion and in
-- the schema: no row can exist without an approved label.

-- Extend the approved feed source kinds to the multi-modal ISR sensor
-- families while retaining the existing kinds.
ALTER TABLE maritime_feed_sources DROP CONSTRAINT maritime_feed_sources_source_kind_check;
ALTER TABLE maritime_feed_sources ADD CONSTRAINT maritime_feed_sources_source_kind_check
    CHECK (source_kind IN ('AIS', 'VTS', 'RADAR', 'PORT', 'AGENCY', 'SAR', 'RF', 'ACOUSTIC', 'OPTICAL'));

CREATE TABLE maritime_isr_events (
    event_id TEXT PRIMARY KEY CHECK (event_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    source_id TEXT NOT NULL REFERENCES maritime_feed_sources(source_id),
    source_event_id TEXT NOT NULL CHECK (source_event_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    modality TEXT NOT NULL CHECK (modality IN ('AIS', 'SAR', 'RF', 'ACOUSTIC', 'OPTICAL')),
    classification TEXT NOT NULL CHECK (classification IN ('UNCLASSIFIED', 'RESTRICTED', 'CONFIDENTIAL', 'SECRET')),
    observed_at TIMESTAMPTZ NOT NULL,
    has_position BOOLEAN NOT NULL,
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    mmsi TEXT CHECK (mmsi IS NULL OR mmsi ~ '^[0-9]{9}$'),
    payload JSONB NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK (payload_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    signature BYTEA NOT NULL CHECK (octet_length(signature) = 64),
    correlation_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    received_at TIMESTAMPTZ NOT NULL,
    UNIQUE (source_id, source_event_id),
    CHECK (
        (has_position AND latitude IS NOT NULL AND longitude IS NOT NULL
            AND latitude BETWEEN -90 AND 90 AND longitude BETWEEN -180 AND 180)
        OR (NOT has_position AND latitude IS NULL AND longitude IS NULL)
    )
);

-- Classification-scoped query support: clearance-filtered reads always
-- constrain on classification and time.
CREATE INDEX maritime_isr_events_classification_idx
    ON maritime_isr_events (classification, observed_at DESC);
CREATE INDEX maritime_isr_events_mmsi_idx
    ON maritime_isr_events (mmsi, observed_at DESC) WHERE mmsi IS NOT NULL;
CREATE INDEX maritime_isr_events_modality_idx
    ON maritime_isr_events (modality, observed_at DESC);
