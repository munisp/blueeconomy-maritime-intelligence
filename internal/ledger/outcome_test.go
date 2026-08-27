package ledger

import (
	"errors"
	"testing"

	tigerbeetle "github.com/tigerbeetle/tigerbeetle-go"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

type fakeClient struct {
	accounts  []tigerbeetle.Account
	transfers []tigerbeetle.Transfer
	failNext  error
}

func (fake *fakeClient) CreateAccounts(accounts []tigerbeetle.Account) ([]tigerbeetle.CreateAccountResult, error) {
	if fake.failNext != nil {
		return nil, fake.failNext
	}
	fake.accounts = append(fake.accounts, accounts...)
	return nil, nil
}

func (fake *fakeClient) CreateTransfers(transfers []tigerbeetle.Transfer) ([]tigerbeetle.CreateTransferResult, error) {
	if fake.failNext != nil {
		return nil, fake.failNext
	}
	fake.transfers = append(fake.transfers, transfers...)
	return nil, nil
}

func TestNewFailsClosed(t *testing.T) {
	if _, err := New(nil, 1, 1); err == nil {
		t.Fatal("nil TigerBeetle client accepted")
	}
	if _, err := New(&fakeClient{}, 0, 1); err == nil {
		t.Fatal("zero ledger accepted")
	}
	if _, err := New(&fakeClient{}, 1, 0); err == nil {
		t.Fatal("zero code accepted")
	}
}

func TestEnsureAccountsAndPostOutcome(t *testing.T) {
	fake := &fakeClient{}
	service, err := New(fake, 7, 42)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureAccounts(); err != nil {
		t.Fatal(err)
	}
	if len(fake.accounts) != 2 {
		t.Fatalf("expected two platform accounts, got %d", len(fake.accounts))
	}
	transferID, err := service.PostOutcome("entry-001", 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.transfers) != 1 {
		t.Fatal("no transfer posted")
	}
	posted := fake.transfers[0]
	if posted.DebitAccountID != IncidentReductionAccountID || posted.CreditAccountID != PremiumDeltaAccountID {
		t.Fatal("outcome transfer must bind incident-reduction to premium-delta")
	}
	// Deterministic: the same entry id converges on the same transfer id.
	again, err := EntryTransferID("entry-001")
	if err != nil {
		t.Fatal(err)
	}
	if again != transferID {
		t.Fatal("transfer id derivation is not deterministic")
	}
	if got := TransferIDHex(transferID); len(got) != 32 {
		t.Fatalf("transfer id hex must be 32 chars, got %q", got)
	}
	if _, err := service.PostOutcome("entry-002", 0); err == nil {
		t.Fatal("zero quantity accepted")
	}
	fake.failNext = errors.New("cluster unavailable")
	if _, err := service.PostOutcome("entry-003", 5); err == nil {
		t.Fatal("TigerBeetle failure must abort posting fail-closed")
	}
}

func TestProposalValidation(t *testing.T) {
	valid := Proposal{
		EntryID: "entry-001", EntryKind: EntryKindIncidentVerified, IncidentRef: "incident-001",
		Classification: isr.ClassificationRestricted, Metric: MetricIncidentReduction,
		Quantity: 3, Unit: UnitIncidents, ProposedBy: "nimasa-analyst",
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	mismatched := valid
	mismatched.EntryKind = EntryKindPremiumDelta
	if err := mismatched.Validate(); err == nil {
		t.Fatal("kind/metric mismatch accepted")
	}
	noLabel := valid
	noLabel.Classification = ""
	if err := noLabel.Validate(); err == nil {
		t.Fatal("missing classification accepted")
	}
	zero := valid
	zero.Quantity = 0
	if err := zero.Validate(); err == nil {
		t.Fatal("zero quantity accepted")
	}
}
