CREATE TABLE IF NOT EXISTS maritime_feed_source_revocations (
    source_id TEXT PRIMARY KEY REFERENCES maritime_feed_sources(source_id),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 512),
    revoked_by TEXT NOT NULL CHECK (revoked_by ~ '^[A-Za-z0-9._:-]{1,128}$'),
    revoked_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS maritime_feed_source_revocations_revoked_at_idx
    ON maritime_feed_source_revocations (revoked_at DESC);
