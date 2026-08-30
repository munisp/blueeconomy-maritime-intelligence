package ledger

import (
	"errors"
	"fmt"

	tigerbeetle "github.com/tigerbeetle/tigerbeetle-go"
	"github.com/tigerbeetle/tigerbeetle-go/pkg/types"
)

// Outcome-ledger TigerBeetle binding. Two platform accounts — incident
// reductions credit the INSURANCE_OUTCOME account from PLATFORM_RESERVE;
// premium deltas move between them — so every confirmed entry is a
// deterministic double-entry transfer whose id derives from the entry id
// (crash-safe retries post the same transfer id).

const (
	ledgerCodeOutcome uint32 = 1
)

// EntryKind enumerates the outcome evidence categories.
type EntryKind string

const (
	EntryKindIncidentVerified EntryKind = "incident-verified"
	EntryKindPremiumDelta     EntryKind = "premium-delta"
)

// Metric and unit constants mirrored by the DB CHECK constraints.
const (
	MetricIncidentReduction = "incident-reduction-count"
	MetricPremiumDelta      = "premium-delta-basis-points"
	UnitIncidents           = "incidents"
	UnitBasisPoints         = "basis-points"
)

// Account identifiers (deterministic, documented in docs).
const (
	accountPlatformReserve uint64 = 1
	accountOutcome         uint64 = 2
)

// Service posts outcome transfers against a TigerBeetle cluster.
type Service struct {
	client    tigerbeetle.Client
	ledgerID  uint32
	accountA  types.Uint128
	accountB  types.Uint128
}

// New fails closed without a connected client.
func New(client tigerbeetle.Client, ledgerID uint32, _ uint64) (*Service, error) {
	if client == nil {
		return nil, errors.New("tigerbeetle client is required (fail-closed)")
	}
	if ledgerID == 0 {
		return nil, errors.New("tigerbeetle ledger id must be positive")
	}
	return &Service{
		client:   client,
		ledgerID: ledgerID,
		accountA: types.ToUint128(accountPlatformReserve),
		accountB: types.ToUint128(accountOutcome),
	}, nil
}

// EnsureAccounts provisions the two outcome accounts idempotently.
func (service *Service) EnsureAccounts() error {
	accounts := []types.Account{
		{ID: service.accountA, Ledger: service.ledgerID, Code: ledgerCodeOutcome},
		{ID: service.accountB, Ledger: service.ledgerID, Code: ledgerCodeOutcome},
	}
	results, err := service.client.CreateAccounts(accounts)
	if err != nil {
		return fmt.Errorf("create outcome accounts: %w", err)
	}
	for _, result := range results {
		if result.Result != types.AccountExists {
			return fmt.Errorf("create outcome account %d: %s", result.Index, result.Result.String())
		}
	}
	return nil
}

// PostOutcome posts the deterministic double-entry transfer for one
// confirmed entry. The transfer id derives from the entry id, so a retried
// confirmation after a crash posts the same transfer idempotently.
func (service *Service) PostOutcome(entryID string, quantity uint64) (types.Uint128, error) {
	if quantity == 0 {
		return types.Uint128{}, errors.New("quantity must be positive")
	}
	transferID, err := transferIDFor(entryID)
	if err != nil {
		return types.Uint128{}, err
	}
	results, err := service.client.CreateTransfers([]types.Transfer{{
		ID:              transferID,
		DebitAccountID:  service.accountA,
		CreditAccountID: service.accountB,
		Amount:          types.ToUint128(quantity),
		Ledger:          service.ledgerID,
		Code:            ledgerCodeOutcome,
	}})
	if err != nil {
		return types.Uint128{}, fmt.Errorf("post outcome transfer: %w", err)
	}
	for _, result := range results {
		if result.Result != types.TransferExists {
			return types.Uint128{}, fmt.Errorf("post outcome transfer %d: %s", result.Index, result.Result.String())
		}
	}
	return transferID, nil
}

// transferIDFor deterministically maps an entry id to a uint128 transfer id
// (first 16 bytes of sha256, big-endian).
func transferIDFor(entryID string) (types.Uint128, error) {
	if entryID == "" {
		return types.Uint128{}, errors.New("entry id is required")
	}
	digest := sha256First16(entryID)
	return types.BytesToUint128(digest), nil
}

// TransferIDHex renders a transfer id as the 32-char lowercase hex string
// persisted on the immutable ledger record.
func TransferIDHex(id types.Uint128) string {
	raw := id.Bytes()
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 32)
	for i, b := range raw {
		out[i*2] = hexdigits[b>>4]
		out[i*2+1] = hexdigits[b&0x0f]
	}
	return string(out)
}
