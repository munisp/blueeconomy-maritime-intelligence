CREATE TABLE maritime_feed_source_key_rotations (
    source_id TEXT NOT NULL REFERENCES maritime_feed_sources(source_id),
    prior_key_fingerprint TEXT NOT NULL CHECK (prior_key_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    prior_public_key BYTEA NOT NULL CHECK (octet_length(prior_public_key) = 32),
    grace_until TIMESTAMPTZ NOT NULL,
    rotated_by TEXT NOT NULL CHECK (rotated_by ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    rotated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (source_id, prior_key_fingerprint)
);

CREATE INDEX maritime_feed_source_key_rotations_grace_idx
    ON maritime_feed_source_key_rotations (source_id, grace_until);
