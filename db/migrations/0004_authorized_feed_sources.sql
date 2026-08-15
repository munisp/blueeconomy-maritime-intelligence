CREATE TABLE maritime_feed_sources (
    source_id TEXT PRIMARY KEY CHECK (source_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    source_kind TEXT NOT NULL CHECK (source_kind IN ('AIS', 'VTS', 'RADAR', 'PORT', 'AGENCY')),
    authority TEXT NOT NULL,
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    key_fingerprint TEXT NOT NULL CHECK (key_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    active BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE maritime_feed_events (
    source_id TEXT NOT NULL REFERENCES maritime_feed_sources(source_id),
    source_event_id TEXT NOT NULL CHECK (source_event_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    payload_sha256 TEXT NOT NULL CHECK (payload_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    signature BYTEA NOT NULL CHECK (octet_length(signature) = 64),
    received_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (source_id, source_event_id)
);

CREATE INDEX maritime_feed_events_received_idx ON maritime_feed_events (received_at);
