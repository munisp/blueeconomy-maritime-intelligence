-- Workstream F: dual-control outcome ledger binding incident-reduction
-- metrics to premium-delta evidence. Confirmed ledger entries are immutable
-- (BEFORE UPDATE/DELETE trigger, same pattern as financial-controls
-- cvff_approvals) and dual control is DB-enforced: the confirmer must differ
-- from the proposer, so no single operator can influence premium outcomes.

CREATE TABLE maritime_outcome_ledger_proposals (
    entry_id TEXT PRIMARY KEY CHECK (entry_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    entry_kind TEXT NOT NULL CHECK (entry_kind IN ('incident-verified', 'premium-delta')),
    incident_ref TEXT NOT NULL CHECK (incident_ref ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    classification TEXT NOT NULL CHECK (classification IN ('UNCLASSIFIED', 'RESTRICTED', 'CONFIDENTIAL', 'SECRET')),
    metric TEXT NOT NULL CHECK (metric IN ('incident-reduction-count', 'premium-delta-basis-points')),
    quantity BIGINT NOT NULL CHECK (quantity > 0),
    unit TEXT NOT NULL CHECK (unit IN ('incidents', 'basis-points')),
    proposed_by TEXT NOT NULL CHECK (proposed_by ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    proposed_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('PROPOSED', 'CONFIRMED')),
    CHECK (
        (entry_kind = 'incident-verified' AND metric = 'incident-reduction-count' AND unit = 'incidents')
        OR (entry_kind = 'premium-delta' AND metric = 'premium-delta-basis-points' AND unit = 'basis-points')
    )
);

CREATE TABLE maritime_outcome_ledger_entries (
    entry_id TEXT PRIMARY KEY REFERENCES maritime_outcome_ledger_proposals(entry_id),
    entry_kind TEXT NOT NULL CHECK (entry_kind IN ('incident-verified', 'premium-delta')),
    incident_ref TEXT NOT NULL,
    classification TEXT NOT NULL CHECK (classification IN ('UNCLASSIFIED', 'RESTRICTED', 'CONFIDENTIAL', 'SECRET')),
    metric TEXT NOT NULL,
    quantity BIGINT NOT NULL CHECK (quantity > 0),
    unit TEXT NOT NULL,
    tigerbeetle_transfer_id TEXT NOT NULL CHECK (tigerbeetle_transfer_id ~ '^[0-9a-f]{32}$'),
    proposed_by TEXT NOT NULL,
    proposed_at TIMESTAMPTZ NOT NULL,
    confirmed_by TEXT NOT NULL,
    confirmed_at TIMESTAMPTZ NOT NULL,
    -- Dual control, DB-enforced: proposer and confirmer must be distinct
    -- principals so premium outcomes stay beyond single-operator influence.
    CHECK (proposed_by <> confirmed_by),
    CHECK (confirmed_at >= proposed_at)
);

CREATE OR REPLACE FUNCTION maritime_outcome_ledger_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'maritime_outcome_ledger_entries are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER maritime_outcome_ledger_entries_no_update
    BEFORE UPDATE OR DELETE ON maritime_outcome_ledger_entries
    FOR EACH ROW EXECUTE FUNCTION maritime_outcome_ledger_immutable();

CREATE INDEX maritime_outcome_ledger_entries_kind_idx
    ON maritime_outcome_ledger_entries (entry_kind, confirmed_at DESC);

-- ISR platform outbox: envelope-carrying events for the Workstream F topics.
CREATE TABLE maritime_isr_outbox (
    event_id UUID PRIMARY KEY,
    topic TEXT NOT NULL CHECK (topic IN ('maritime.isr.v1', 'maritime.behaviour.v1', 'maritime.outcome.v1')),
    event_type TEXT NOT NULL,
    classification TEXT NOT NULL CHECK (classification IN ('UNCLASSIFIED', 'RESTRICTED', 'CONFIDENTIAL', 'SECRET')),
    aggregate_key TEXT NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ,
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    claimed_at TIMESTAMPTZ,
    claimed_by TEXT,
    last_error TEXT
);

CREATE INDEX maritime_isr_outbox_claim_idx
    ON maritime_isr_outbox (available_at, created_at) WHERE published_at IS NULL;
