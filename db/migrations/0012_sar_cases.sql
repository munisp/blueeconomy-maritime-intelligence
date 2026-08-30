-- Phase 8: SAR C2 case engine (IAMSAR-informed). SAR cases anchor to
-- adjudicated maritime_incidents records (category 'SAR'); DB CHECKs mirror
-- the service-layer validation in internal/sar.

-- SAR events ride the existing outbox/publisher machinery: the shared
-- maritime_isr_outbox topic CHECK is widened (additive) with
-- maritime.sar.v1, drained by the existing outbox publisher in isr mode.
-- The SAR intake feed source kind ('SAR') is widened into the authorized
-- feed-source taxonomy (additive), closing the PRA-098 residual.
ALTER TABLE maritime_feed_sources DROP CONSTRAINT maritime_feed_sources_source_kind_check;
ALTER TABLE maritime_feed_sources ADD CONSTRAINT maritime_feed_sources_source_kind_check
    CHECK (source_kind IN ('AIS', 'VTS', 'RADAR', 'PORT', 'AGENCY', 'SAR'));

ALTER TABLE maritime_isr_outbox DROP CONSTRAINT maritime_isr_outbox_topic_check;
ALTER TABLE maritime_isr_outbox ADD CONSTRAINT maritime_isr_outbox_topic_check
    CHECK (topic IN ('maritime.isr.v1', 'maritime.behaviour.v1', 'maritime.outcome.v1', 'maritime.sar.v1'));

CREATE TABLE sar_cases (
    case_id        TEXT PRIMARY KEY CHECK (case_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    incident_id    TEXT NOT NULL UNIQUE REFERENCES maritime_incidents(incident_id), -- category='SAR'
    phase          TEXT NOT NULL CHECK (phase IN ('INCERFA','ALERFA','DETRESFA')),
    stage          TEXT NOT NULL CHECK (stage IN
                   ('AWARENESS','INITIAL_ACTION','COORDINATION','STAND_DOWN')),
    classification TEXT NOT NULL CHECK (classification IN
                   ('UNCLASSIFIED','RESTRICTED','CONFIDENTIAL','SECRET')), -- floor RESTRICTED when SOS-sourced
    -- Intake provenance: exactly one origin.
    intake_kind    TEXT NOT NULL CHECK (intake_kind IN ('WATERWAY_EVENT','GEO_SOS','MANUAL')),
    source_ref     TEXT NOT NULL CHECK (length(source_ref) BETWEEN 1 AND 512),
    persons_at_risk INTEGER CHECK (persons_at_risk IS NULL OR persons_at_risk >= 0),
    last_known_lat DOUBLE PRECISION CHECK (last_known_lat IS NULL OR last_known_lat BETWEEN -90 AND 90),
    last_known_lon DOUBLE PRECISION CHECK (last_known_lon IS NULL OR last_known_lon BETWEEN -180 AND 180),
    last_known_at  TIMESTAMPTZ,
    datum_lat DOUBLE PRECISION CHECK (datum_lat IS NULL OR datum_lat BETWEEN -90 AND 90),
    datum_lon DOUBLE PRECISION CHECK (datum_lon IS NULL OR datum_lon BETWEEN -180 AND 180),
    datum_at TIMESTAMPTZ,                   -- planner-set, from cited evidence
    datum_evidence_sha256 TEXT CHECK (datum_evidence_sha256 IS NULL OR datum_evidence_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    stand_down_reason TEXT CHECK (stand_down_reason IS NULL OR stand_down_reason IN
                   ('RESOLVED','SUSPENDED','FALSE_ALERT','HANDED_OVER')),
    persons_recovered INTEGER CHECK (persons_recovered IS NULL OR persons_recovered >= 0),
    handover_ref TEXT,
    created_by TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    CHECK ( (stage <> 'STAND_DOWN') OR (stand_down_reason IS NOT NULL) ),
    CHECK ( (intake_kind <> 'GEO_SOS') OR (classification <> 'UNCLASSIFIED') ), -- SOS floor: RESTRICTED
    CHECK ( (datum_lat IS NULL) = (datum_lon IS NULL) ),
    CHECK ( (datum_lat IS NULL) OR (datum_evidence_sha256 IS NOT NULL) ), -- no unattributed datum
    CHECK ( (last_known_lat IS NULL) = (last_known_lon IS NULL) ),
    CHECK ( (stand_down_reason IS NULL OR stand_down_reason <> 'HANDED_OVER') OR (handover_ref IS NOT NULL) )
);

CREATE INDEX sar_cases_stage_idx ON sar_cases (stage, phase, updated_at DESC);

CREATE TABLE sar_case_timeline (            -- append-only; every intake/phase/stage/tasking/SITREP fact
    entry_id UUID PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES sar_cases(case_id),
    entry_type TEXT NOT NULL CHECK (entry_type IN
               ('case.opened','phase.changed','stage.changed','datum.set',
                'tasking.proposed','tasking.tasked','tasking.acked','tasking.on_scene',
                'tasking.released','tasking.aborted',
                'sitrep.issued','sos.acknowledged','sos.resolved','case.intake_linked',
                'resource.registered','resource.status_changed')),
    actor TEXT NOT NULL,                    -- verified principal or system
    detail JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX sar_case_timeline_case_idx ON sar_case_timeline (case_id, created_at, entry_id);

CREATE OR REPLACE FUNCTION sar_case_timeline_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'sar_case_timeline is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER sar_case_timeline_no_update
    BEFORE UPDATE OR DELETE ON sar_case_timeline
    FOR EACH ROW EXECUTE FUNCTION sar_case_timeline_immutable();

CREATE TABLE sar_resources (                -- SRU registry; NO seeded rows
    resource_id TEXT PRIMARY KEY CHECK (resource_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    kind TEXT NOT NULL CHECK (kind IN ('VESSEL','AIRCRAFT','TEAM','VOO')), -- VOO = vessel of opportunity
    callsign TEXT NOT NULL CHECK (length(callsign) BETWEEN 1 AND 64),
    capabilities JSONB NOT NULL,            -- comms/equipment/endurance attributes
    home_authority TEXT NOT NULL,           -- e.g. NN, NIMASA MSU, NAF, merchant
    status TEXT NOT NULL CHECK (status IN ('AVAILABLE','TASKED','OFFLINE')),
    registered_by TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE sar_taskings (                 -- tasking orders (IAMSAR App H briefing fields)
    tasking_id TEXT PRIMARY KEY CHECK (tasking_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    case_id TEXT NOT NULL REFERENCES sar_cases(case_id),
    resource_id TEXT NOT NULL REFERENCES sar_resources(resource_id),
    task TEXT NOT NULL CHECK (task IN ('SEARCH_PATTERN','INVESTIGATE','RESCUE','RELAY','MEDEVAC','OTHER')),
    briefing JSONB NOT NULL,                -- search area polygon, datum, pattern, comms plan, on-scene coord
    state TEXT NOT NULL CHECK (state IN ('PROPOSED','TASKED','ACKED','ON_SCENE','RELEASED','ABORTED')),
    tasked_by TEXT NOT NULL, acked_by TEXT,
    created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0)
);

CREATE INDEX sar_taskings_case_idx ON sar_taskings (case_id, created_at);

CREATE TABLE sar_sitreps (                  -- numbered, immutable once issued, signed
    sitrep_id TEXT PRIMARY KEY CHECK (sitrep_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    case_id TEXT NOT NULL REFERENCES sar_cases(case_id),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    body JSONB NOT NULL,                    -- assembled from case state at issue time
    body_sha256 TEXT NOT NULL CHECK (body_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    envelope_jws TEXT NOT NULL,             -- envelope v1.0 signature of the canonical body
    issued_by TEXT NOT NULL, issued_at TIMESTAMPTZ NOT NULL,
    UNIQUE (case_id, sequence)
);

-- Issued SITREPs are immutable: corrections are a new SITREP number.
CREATE OR REPLACE FUNCTION sar_sitreps_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'sar_sitreps is append-only once issued';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER sar_sitreps_no_update
    BEFORE UPDATE OR DELETE ON sar_sitreps
    FOR EACH ROW EXECUTE FUNCTION sar_sitreps_immutable();
