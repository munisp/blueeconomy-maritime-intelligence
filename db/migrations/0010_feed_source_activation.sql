-- Phase-6 remediation (MI-2): trusted feed sources never self-activate.
-- Registration records the verified registrar principal and always creates
-- the source PENDING (active=false); activation is a separate maker-checker
-- decision persisted here with the distinct activator principal. Admission
-- denials (unknown source, non-active source, invalid signature) are audited
-- durably so forged "signature-verified" feed attempts leave evidence.

ALTER TABLE maritime_feed_sources
    ADD COLUMN IF NOT EXISTS registered_by TEXT NOT NULL DEFAULT 'legacy-registrar';

CREATE TABLE IF NOT EXISTS maritime_feed_source_activations (
    source_id TEXT PRIMARY KEY REFERENCES maritime_feed_sources(source_id),
    registered_by TEXT NOT NULL,
    activated_by TEXT NOT NULL CHECK (activated_by ~ '^[A-Za-z0-9._:-]{1,128}$'),
    activated_at TIMESTAMPTZ NOT NULL,
    -- Maker-checker: the activating principal must differ from the registrar.
    CHECK (activated_by <> registered_by)
);

CREATE TABLE IF NOT EXISTS maritime_feed_admission_denials (
    denial_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN ('source-unknown', 'source-not-active', 'signature-invalid')),
    denied_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS maritime_feed_admission_denials_source_idx
    ON maritime_feed_admission_denials (source_id, denied_at DESC);
