package ledger

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
)

var (
	// ErrNotFound is returned when the referenced proposal does not exist.
	ErrNotFound = errors.New("outcome proposal not found")
	// ErrDualControl is returned when proposer and confirmer coincide.
	ErrDualControl = errors.New("dual control requires distinct proposer and confirmer")
	// ErrAlreadyConfirmed is returned when a proposal is already confirmed.
	ErrAlreadyConfirmed = errors.New("outcome proposal is already confirmed")
	// ErrConflict is returned on conflicting replay evidence.
	ErrConflict = errors.New("outcome proposal conflicts with retained evidence")
)

// Proposal is one dual-control outcome-ledger proposal.
type Proposal struct {
	EntryID        string             `json:"entry_id"`
	EntryKind      EntryKind          `json:"entry_kind"`
	IncidentRef    string             `json:"incident_ref"`
	Classification isr.Classification `json:"classification"`
	Metric         string             `json:"metric"`
	Quantity       int64              `json:"quantity"`
	Unit           string             `json:"unit"`
	ProposedBy     string             `json:"proposed_by"`
}

// Entry is one confirmed, immutable outcome-ledger record.
type Entry struct {
	Proposal
	TransferID  string    `json:"tigerbeetle_transfer_id"`
	ProposedAt  time.Time `json:"proposed_at"`
	ConfirmedBy string    `json:"confirmed_by"`
	ConfirmedAt time.Time `json:"confirmed_at"`
}

// Validate enforces the entry contract fail-closed, mirroring the DB CHECKs.
func (proposal Proposal) Validate() error {
	if proposal.EntryKind != EntryKindIncidentVerified && proposal.EntryKind != EntryKindPremiumDelta {
		return errors.New("entry_kind is unsupported")
	}
	if _, err := isr.ParseClassification(string(proposal.Classification)); err != nil {
		return err
	}
	if proposal.EntryID == "" || proposal.IncidentRef == "" || proposal.ProposedBy == "" || len(proposal.EntryID) > 128 || len(proposal.IncidentRef) > 128 || len(proposal.ProposedBy) > 128 {
		return errors.New("entry_id, incident_ref and proposed_by must be canonical non-empty text")
	}
	if proposal.Quantity <= 0 {
		return errors.New("quantity must be positive")
	}
	switch proposal.EntryKind {
	case EntryKindIncidentVerified:
		if proposal.Metric != MetricIncidentReduction || proposal.Unit != UnitIncidents {
			return errors.New("incident-verified entries must carry the incident-reduction-count metric in incidents")
		}
	case EntryKindPremiumDelta:
		if proposal.Metric != MetricPremiumDelta || proposal.Unit != UnitBasisPoints {
			return errors.New("premium-delta entries must carry the premium-delta-basis-points metric in basis-points")
		}
	}
	return nil
}

// OutcomeStore persists proposals and confirmed entries, and emits
// maritime.outcome.v1 envelopes on confirmation.
type OutcomeStore struct {
	pool    *pgxpool.Pool
	service *Service
	signer  *provenance.Signer
}

// NewOutcomeStore fails closed without a pool or a TigerBeetle service.
func NewOutcomeStore(pool *pgxpool.Pool, service *Service) (*OutcomeStore, error) {
	if pool == nil {
		return nil, errors.New("postgres pool is required")
	}
	if service == nil {
		return nil, errors.New("TigerBeetle outcome service is required (fail-closed)")
	}
	return &OutcomeStore{pool: pool, service: service}, nil
}

// WithSigner attaches the provenance signer used to seal every emitted
// envelope. Emission paths fail closed when no signer is attached.
func (store *OutcomeStore) WithSigner(signer *provenance.Signer) *OutcomeStore {
	store.signer = signer
	return store
}

// Propose records one outcome proposal. Exact replay returns the retained
// proposal; conflicting reuse of entry_id fails closed.
func (store *OutcomeStore) Propose(ctx context.Context, proposal Proposal) error {
	if err := proposal.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC()
	tag, err := store.pool.Exec(ctx, `
		INSERT INTO maritime_outcome_ledger_proposals
			(entry_id, entry_kind, incident_ref, classification, metric, quantity, unit, proposed_by, proposed_at, state)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'PROPOSED')
		ON CONFLICT (entry_id) DO NOTHING`,
		proposal.EntryID, string(proposal.EntryKind), proposal.IncidentRef, string(proposal.Classification),
		proposal.Metric, proposal.Quantity, proposal.Unit, proposal.ProposedBy, now)
	if err != nil {
		return fmt.Errorf("record outcome proposal: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var retained Proposal
	var state string
	err = store.pool.QueryRow(ctx, `
		SELECT entry_kind, incident_ref, classification, metric, quantity, unit, proposed_by, state
		FROM maritime_outcome_ledger_proposals WHERE entry_id=$1`, proposal.EntryID).
		Scan(&retained.EntryKind, &retained.IncidentRef, &retained.Classification, &retained.Metric,
			&retained.Quantity, &retained.Unit, &retained.ProposedBy, &state)
	if err != nil {
		return fmt.Errorf("load retained proposal: %w", err)
	}
	if retained.EntryKind != proposal.EntryKind || retained.IncidentRef != proposal.IncidentRef ||
		retained.Classification != proposal.Classification || retained.Metric != proposal.Metric ||
		retained.Quantity != proposal.Quantity || retained.Unit != proposal.Unit ||
		retained.ProposedBy != proposal.ProposedBy {
		return ErrConflict
	}
	return nil
}

// Confirm applies the second control: a distinct confirmer posts the
// TigerBeetle transfer and the immutable ledger record, then emits the
// maritime.outcome.v1 envelope — all fail-closed.
func (store *OutcomeStore) Confirm(ctx context.Context, entryID, confirmedBy string) (Entry, error) {
	if confirmedBy == "" || len(confirmedBy) > 128 {
		return Entry{}, errors.New("confirmed_by must be canonical non-empty text")
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Entry{}, fmt.Errorf("begin outcome confirmation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var proposal Proposal
	var state string
	var proposedAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT entry_id, entry_kind, incident_ref, classification, metric, quantity, unit, proposed_by, proposed_at, state
		FROM maritime_outcome_ledger_proposals WHERE entry_id=$1 FOR UPDATE`, entryID).
		Scan(&proposal.EntryID, &proposal.EntryKind, &proposal.IncidentRef, &proposal.Classification,
			&proposal.Metric, &proposal.Quantity, &proposal.Unit, &proposal.ProposedBy, &proposedAt, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return Entry{}, ErrNotFound
	}
	if err != nil {
		return Entry{}, fmt.Errorf("load outcome proposal: %w", err)
	}
	if proposal.ProposedBy == confirmedBy {
		return Entry{}, ErrDualControl
	}
	if state != "PROPOSED" {
		return Entry{}, ErrAlreadyConfirmed
	}
	// TigerBeetle first: the deterministic transfer id makes a crashed
	// confirmation safe to retry; the immutable record lands in the same
	// transaction as the envelope.
	transferID, err := store.service.PostOutcome(proposal.EntryID, uint64(proposal.Quantity))
	if err != nil {
		return Entry{}, err
	}
	confirmedAt := time.Now().UTC()
	entry := Entry{Proposal: proposal, TransferID: TransferIDHex(transferID), ProposedAt: proposedAt, ConfirmedBy: confirmedBy, ConfirmedAt: confirmedAt}
	if _, err := tx.Exec(ctx, `
		INSERT INTO maritime_outcome_ledger_entries
			(entry_id, entry_kind, incident_ref, classification, metric, quantity, unit,
			 tigerbeetle_transfer_id, proposed_by, proposed_at, confirmed_by, confirmed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		proposal.EntryID, string(proposal.EntryKind), proposal.IncidentRef, string(proposal.Classification),
		proposal.Metric, proposal.Quantity, proposal.Unit, entry.TransferID,
		proposal.ProposedBy, proposedAt, confirmedBy, confirmedAt); err != nil {
		return Entry{}, fmt.Errorf("record immutable outcome entry: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE maritime_outcome_ledger_proposals SET state='CONFIRMED' WHERE entry_id=$1 AND state='PROPOSED'`, entryID); err != nil {
		return Entry{}, fmt.Errorf("close outcome proposal: %w", err)
	}
	envelope, envelopeBytes, err := isr.Seal(store.signer, isr.TopicOutcome, "outcome."+string(proposal.EntryKind), proposal.EntryID, proposal.Classification, confirmedAt, entry)
	if err != nil {
		return Entry{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO maritime_isr_outbox (event_id, topic, event_type, classification, aggregate_key, payload, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		uuid.New(), envelope.Topic, envelope.EventType, string(envelope.Classification), envelope.AggregateKey, envelopeBytes, confirmedAt); err != nil {
		return Entry{}, fmt.Errorf("write outcome outbox event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Entry{}, fmt.Errorf("commit outcome confirmation: %w", err)
	}
	return entry, nil
}
