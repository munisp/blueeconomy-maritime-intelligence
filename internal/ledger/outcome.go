// Package ledger binds Deep Blue Project outcome evidence (verified incident
// reductions and the resulting premium deltas) to TigerBeetle transfers.
// Posting is dual-control: a proposal becomes a confirmed immutable ledger
// entry only when a second, distinct principal confirms it, and the database
// enforces proposer != confirmer plus insert-only immutability so premium
// outcomes stay beyond single-operator influence. Configuration is
// fail-closed: no outcome can be confirmed without a TigerBeetle client.
package ledger

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	tigerbeetle "github.com/tigerbeetle/tigerbeetle-go"
)

// tigerBeetleClient is the minimal TigerBeetle surface used by the outcome
// ledger, so tests substitute a fake.
type tigerBeetleClient interface {
	CreateAccounts([]tigerbeetle.Account) ([]tigerbeetle.CreateAccountResult, error)
	CreateTransfers([]tigerbeetle.Transfer) ([]tigerbeetle.CreateTransferResult, error)
}

// EntryKind enumerates the outcome-ledger evidence kinds.
type EntryKind string

const (
	// EntryKindIncidentVerified records one verified incident reduction.
	EntryKindIncidentVerified EntryKind = "incident-verified"
	// EntryKindPremiumDelta records premium-delta evidence in basis points.
	EntryKindPremiumDelta EntryKind = "premium-delta"
)

// Metric/unit binding per entry kind (also DB-enforced by CHECK).
const (
	MetricIncidentReduction = "incident-reduction-count"
	MetricPremiumDelta      = "premium-delta-basis-points"
	UnitIncidents           = "incidents"
	UnitBasisPoints         = "basis-points"
)

// Platform accounts: incident-reduction evidence flows into premium-delta
// evidence, making the binding explicit in the ledger.
var (
	// IncidentReductionAccountID is account 1 on the outcome ledger.
	IncidentReductionAccountID = tigerbeetle.ToUint128(1)
	// PremiumDeltaAccountID is account 2 on the outcome ledger.
	PremiumDeltaAccountID = tigerbeetle.ToUint128(2)
)

// Service posts outcome transfers to TigerBeetle.
type Service struct {
	client tigerBeetleClient
	ledger uint32
	code   uint16
}

// New fails closed without a client, ledger or code.
func New(client tigerBeetleClient, ledgerID uint32, code uint16) (*Service, error) {
	if client == nil {
		return nil, errors.New("TigerBeetle client is required (fail-closed)")
	}
	if ledgerID == 0 {
		return nil, errors.New("TigerBeetle ledger id must be non-zero")
	}
	if code == 0 {
		return nil, errors.New("TigerBeetle code must be non-zero")
	}
	return &Service{client: client, ledger: ledgerID, code: code}, nil
}

// EnsureAccounts creates the two platform outcome accounts idempotently.
func (service *Service) EnsureAccounts() error {
	accounts := []tigerbeetle.Account{
		{ID: IncidentReductionAccountID, Ledger: service.ledger, Code: service.code},
		{ID: PremiumDeltaAccountID, Ledger: service.ledger, Code: service.code},
	}
	results, err := service.client.CreateAccounts(accounts)
	if err != nil {
		return fmt.Errorf("create outcome accounts: %w", err)
	}
	// TigerBeetle returns only failed operations; an empty result means every
	// account was created.
	for _, result := range results {
		if result.Status != tigerbeetle.AccountCreated && result.Status != tigerbeetle.AccountExists {
			return fmt.Errorf("create outcome account returned %v", result.Status)
		}
	}
	return nil
}

// EntryTransferID deterministically derives the TigerBeetle transfer id from
// the outcome entry id so confirmation replays converge on one transfer.
func EntryTransferID(entryID string) (tigerbeetle.Uint128, error) {
	if strings.TrimSpace(entryID) == "" || len(entryID) > 128 {
		return tigerbeetle.Uint128{}, errors.New("entry_id must be canonical non-empty text")
	}
	digest := sha256.Sum256([]byte("outcome-ledger:" + entryID))
	var bytes [16]byte
	copy(bytes[:], digest[:16])
	return tigerbeetle.BytesToUint128(bytes), nil
}

// TransferIDHex renders the transfer id for the immutable DB record
// (32 lowercase hex characters, matching the DB CHECK).
func TransferIDHex(id tigerbeetle.Uint128) string {
	bytes := id.Bytes()
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 32)
	// Uint128.Bytes is little-endian; render big-endian for readability.
	for index := len(bytes) - 1; index >= 0; index-- {
		out = append(out, digits[bytes[index]>>4], digits[bytes[index]&0x0f])
	}
	return string(out)
}

// PostOutcome posts one outcome transfer binding incident-reduction evidence
// to premium-delta evidence. Amount is the entry quantity (incident count or
// basis points). Any TigerBeetle failure aborts the confirmation.
func (service *Service) PostOutcome(entryID string, quantity uint64) (tigerbeetle.Uint128, error) {
	transferID, err := EntryTransferID(entryID)
	if err != nil {
		return tigerbeetle.Uint128{}, err
	}
	if quantity == 0 {
		return tigerbeetle.Uint128{}, errors.New("outcome quantity must be non-zero")
	}
	results, err := service.client.CreateTransfers([]tigerbeetle.Transfer{{
		ID:              transferID,
		DebitAccountID:  IncidentReductionAccountID,
		CreditAccountID: PremiumDeltaAccountID,
		Amount:          tigerbeetle.ToUint128(quantity),
		Ledger:          service.ledger,
		Code:            service.code,
	}})
	if err != nil {
		return tigerbeetle.Uint128{}, fmt.Errorf("post outcome transfer: %w", err)
	}
	if len(results) > 1 {
		return tigerbeetle.Uint128{}, fmt.Errorf("post outcome transfer returned %d failures, want at most 1", len(results))
	}
	if len(results) == 1 && results[0].Status != tigerbeetle.TransferCreated && results[0].Status != tigerbeetle.TransferExists {
		return tigerbeetle.Uint128{}, fmt.Errorf("post outcome transfer returned %v", results[0].Status)
	}
	return transferID, nil
}
