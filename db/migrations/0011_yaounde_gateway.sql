-- Phase 8: Yaoundé Architecture regional information-exchange gateway.
-- CHECKs mirror the service-layer validation in internal/yaounde; the
-- gateway is fail-closed by construction: NO peers are seeded, so an empty
-- yaounde_peers table means UNCONFIGURED and every exchange surface must
-- report so honestly.

CREATE TABLE yaounde_peers (
    peer_id          TEXT PRIMARY KEY CHECK (peer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    peer_kind        TEXT NOT NULL CHECK (peer_kind IN
                     ('ICC','CRESMAC','CRESMAO','MMCC','MOC','MDAT_GOG','IMB_PRC','OTHER')),
    zone             TEXT CHECK (zone IN ('D','E','F','G','CENTRAL_B','INTERREGIONAL','GLOBAL')),
    endpoint_url     TEXT,                      -- NULL until an approved endpoint exists
    contact_channel  TEXT,                      -- phone/email descriptor for manual fallback (non-secret)
    public_key       BYTEA CHECK (public_key IS NULL OR octet_length(public_key) = 32), -- Ed25519
    status           TEXT NOT NULL CHECK (status IN ('PENDING','ACTIVE','SUSPENDED','REVOKED')),
    registered_by    TEXT NOT NULL,             -- verified principal (never from request body)
    activated_by     TEXT,                      -- must differ from registered_by (maker-checker)
    created_at       TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL,
    CHECK (activated_by IS NULL OR activated_by <> registered_by)
);

-- Maker ≠ checker enforced by trigger, mirroring the geo-service
-- geofence_zones four-eyes pattern: a peer may never be activated by the
-- principal that registered it.
CREATE OR REPLACE FUNCTION yaounde_peers_maker_checker() RETURNS trigger AS $$
BEGIN
    IF NEW.status = 'ACTIVE' AND OLD.status <> 'ACTIVE' THEN
        IF NEW.activated_by IS NULL THEN
            RAISE EXCEPTION 'yaounde peer activation requires an activating principal';
        END IF;
        IF NEW.activated_by = NEW.registered_by THEN
            RAISE EXCEPTION 'yaounde peer registrar may not activate own peer (maker-checker)';
        END IF;
    END IF;
    IF OLD.status = 'REVOKED' AND NEW.status <> 'REVOKED' THEN
        RAISE EXCEPTION 'revoked yaounde peer cannot leave REVOKED';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER yaounde_peers_maker_checker
    BEFORE UPDATE ON yaounde_peers
    FOR EACH ROW EXECUTE FUNCTION yaounde_peers_maker_checker();

CREATE TABLE yaounde_releases (
    release_id       TEXT PRIMARY KEY CHECK (release_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    incident_id      TEXT NOT NULL REFERENCES maritime_incidents(incident_id),
    peer_id          TEXT NOT NULL REFERENCES yaounde_peers(peer_id),
    marking          TEXT NOT NULL CHECK (marking IN
                     ('YAOUNDE_ZONE_E','YAOUNDE_REGIONAL','MDAT_GOG_SHAREABLE')),
    classification   TEXT NOT NULL CHECK (classification IN
                     ('UNCLASSIFIED','RESTRICTED','CONFIDENTIAL','SECRET')),
    report_sha256    TEXT NOT NULL CHECK (report_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    envelope_jws     TEXT NOT NULL,           -- envelope v1.0 document of the sealed report
    state            TEXT NOT NULL CHECK (state IN
                     ('DRAFT','APPROVED','DISPATCHED','ACKNOWLEDGED','FAILED','WITHDRAWN')),
    expected_version BIGINT NOT NULL CHECK (expected_version > 0), -- optimistic lock on maritime_incidents
    released_by      TEXT,
    approved_by      TEXT,                    -- distinct principals (maker-checker)
    dispatched_at    TIMESTAMPTZ,
    acked_at         TIMESTAMPTZ,
    ack_receipt_sha256 TEXT CHECK (ack_receipt_sha256 IS NULL OR ack_receipt_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    created_at       TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL,
    version          BIGINT NOT NULL CHECK (version > 0),
    CHECK (approved_by IS NULL OR released_by IS NULL OR approved_by <> released_by),
    -- An acknowledgement is never asserted without a verifiable receipt.
    CHECK ((state <> 'ACKNOWLEDGED') OR (ack_receipt_sha256 IS NOT NULL AND acked_at IS NOT NULL))
);
-- DRAFT→APPROVED→DISPATCHED→ACKNOWLEDGED; FAILED is retryable-explicit;
-- WITHDRAWN terminal. Transition legality is enforced in internal/yaounde.

CREATE INDEX yaounde_releases_incident_idx ON yaounde_releases (incident_id, created_at DESC);
CREATE INDEX yaounde_peers_status_idx ON yaounde_peers (status);
CREATE INDEX yaounde_releases_state_idx ON yaounde_releases (peer_id, state);

CREATE TABLE yaounde_inbound_reports (
    report_id        TEXT PRIMARY KEY CHECK (report_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    peer_id          TEXT NOT NULL REFERENCES yaounde_peers(peer_id),
    peer_report_ref  TEXT NOT NULL CHECK (length(peer_report_ref) BETWEEN 1 AND 256),
    classification   TEXT NOT NULL CHECK (classification IN
                     ('UNCLASSIFIED','RESTRICTED','CONFIDENTIAL','SECRET')),
    marking          TEXT NOT NULL CHECK (marking IN
                     ('NATIONAL_ONLY','YAOUNDE_ZONE_E','YAOUNDE_REGIONAL','MDAT_GOG_SHAREABLE')),
    payload          JSONB NOT NULL,          -- retained verbatim
    payload_sha256   TEXT NOT NULL CHECK (payload_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    signature        BYTEA NOT NULL CHECK (octet_length(signature) = 64),
    adjudication     TEXT NOT NULL DEFAULT 'PENDING'
                     CHECK (adjudication IN ('PENDING','CORRELATED','REJECTED')),
    incident_id      TEXT REFERENCES maritime_incidents(incident_id), -- set on CORRELATED
    received_at      TIMESTAMPTZ NOT NULL,
    UNIQUE (peer_id, peer_report_ref),        -- replay returns retained evidence
    CHECK ((adjudication <> 'CORRELATED') OR (incident_id IS NOT NULL))
);

CREATE TABLE yaounde_picture_contributions (
    contribution_id  TEXT PRIMARY KEY CHECK (contribution_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    peer_id          TEXT NOT NULL REFERENCES yaounde_peers(peer_id),
    zone             TEXT NOT NULL,           -- geographic scope actually applied
    track_window     TSTZRANGE NOT NULL,
    track_count      INTEGER NOT NULL CHECK (track_count >= 0),
    classification_ceiling TEXT NOT NULL CHECK (classification_ceiling IN
                     ('UNCLASSIFIED','RESTRICTED','CONFIDENTIAL','SECRET')),
    digest_sha256    TEXT NOT NULL CHECK (digest_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    state TEXT NOT NULL CHECK (state IN ('PREPARED','APPROVED','DISPATCHED','ACKNOWLEDGED','FAILED')),
    created_by TEXT NOT NULL, approved_by TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (approved_by IS NULL OR approved_by <> created_by)
);

-- Append-only, hash-chained audit ledger (R-YG-5). No UPDATE/DELETE:
-- enforced by trigger.
CREATE TABLE yaounde_audit_log (
    seq          BIGSERIAL PRIMARY KEY,
    event_type   TEXT NOT NULL CHECK (event_type IN
                 ('peer.registered','peer.activated','peer.suspended','peer.revoked',
                  'release.drafted','release.approved','release.dispatched',
                  'release.acknowledged','release.failed','release.withdrawn',
                  'release.refused',               -- policy refusal, with reason
                  'inbound.admitted','inbound.rejected',
                  'picture.prepared','picture.dispatched','picture.failed')),
    actor        TEXT NOT NULL,               -- verified principal or peer_id
    subject_id   TEXT NOT NULL,
    detail       JSONB NOT NULL,
    prev_hash    TEXT NOT NULL CHECK (prev_hash ~ '^sha256:[0-9a-f]{64}$'),
    entry_hash   TEXT NOT NULL CHECK (entry_hash ~ '^sha256:[0-9a-f]{64}$'),
    created_at   TIMESTAMPTZ NOT NULL
);

CREATE OR REPLACE FUNCTION yaounde_audit_log_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'yaounde_audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER yaounde_audit_log_no_update
    BEFORE UPDATE OR DELETE ON yaounde_audit_log
    FOR EACH ROW EXECUTE FUNCTION yaounde_audit_log_immutable();

-- Transactional outbox for maritime.yaounde.v1, drained by
-- cmd/maritime-intelligence-yaounde-publisher (pattern of 0007's
-- maritime_isr_outbox, carried in a dedicated table so only the yaounde
-- publisher owns these rows).
CREATE TABLE yaounde_outbox (
    event_id UUID PRIMARY KEY,
    topic TEXT NOT NULL CHECK (topic = 'maritime.yaounde.v1'),
    event_type TEXT NOT NULL CHECK (event_type IN (
        'maritime.yaounde.incident_report.v1',
        'maritime.yaounde.release_transitioned.v1',
        'maritime.yaounde.inbound_report_admitted.v1',
        'maritime.yaounde.picture_contribution_transitioned.v1')),
    classification TEXT NOT NULL CHECK (classification IN ('UNCLASSIFIED','RESTRICTED','CONFIDENTIAL','SECRET')),
    aggregate_key TEXT NOT NULL,
    payload JSONB NOT NULL,                   -- canonical envelope document, verbatim
    created_at TIMESTAMPTZ NOT NULL,
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    claimed_at TIMESTAMPTZ,
    claimed_by TEXT,
    last_error TEXT,
    published_at TIMESTAMPTZ
);

CREATE INDEX yaounde_outbox_unpublished_idx
    ON yaounde_outbox (available_at, created_at)
    WHERE published_at IS NULL;
