package incident

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

// MI-2: registration validation binds the verified registrar principal.
func TestFeedSourceRegistrationValidateRequiresRegistrar(t *testing.T) {
	valid := FeedSourceRegistration{
		SourceID: "src-1", SourceKind: "AIS", Authority: "auth-1",
		PublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize), RegisteredBy: "registrar-1",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid registration rejected: %v", err)
	}
	missingRegistrar := valid
	missingRegistrar.RegisteredBy = ""
	if err := missingRegistrar.Validate(); err == nil {
		t.Fatal("registration without verified registrar accepted")
	}
}

// MI-2: activation validation binds the verified activator principal.
func TestFeedSourceActivationValidate(t *testing.T) {
	if err := (FeedSourceActivation{SourceID: "src-1", ActivatedBy: "admin-1"}).Validate(); err != nil {
		t.Fatalf("valid activation rejected: %v", err)
	}
	if err := (FeedSourceActivation{SourceID: "src-1", ActivatedBy: ""}).Validate(); err == nil {
		t.Fatal("activation without verified activator accepted")
	}
	if err := (FeedSourceActivation{SourceID: "", ActivatedBy: "admin-1"}).Validate(); err == nil {
		t.Fatal("activation without source id accepted")
	}
}

// MI-2: trust denials map to auditable reasons; other failures do not.
func TestFeedDenialReasonMapping(t *testing.T) {
	cases := []struct {
		err    error
		reason string
	}{
		{ErrNotFound, "source-unknown"},
		{ErrFeedSourceNotActive, "source-not-active"},
		{ErrFeedSignatureInvalid, "signature-invalid"},
		{ErrIdempotencyConflict, ""},
		{errors.New("boom"), ""},
	}
	for _, tc := range cases {
		if reason := feedDenialReason(tc.err); reason != tc.reason {
			t.Fatalf("feedDenialReason(%v) = %q, want %q", tc.err, reason, tc.reason)
		}
	}
}
