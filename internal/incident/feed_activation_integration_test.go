//go:build feedintegration

package incident

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openMigratedStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	store, err := Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if os.Getenv("SKIP_MIGRATION") != "true" {
		for _, migrationPath := range strings.Split(os.Getenv("MIGRATION_PATH"), ",") {
			migration, readErr := os.ReadFile(filepath.Clean(strings.TrimSpace(migrationPath)))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if execErr := store.Exec(ctx, string(migration)); execErr != nil {
				t.Fatal(execErr)
			}
		}
	}
	return store, ctx
}

func denialCount(t *testing.T, store *Store, ctx context.Context, sourceID, reason string) int {
	t.Helper()
	var count int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM maritime_feed_admission_denials WHERE source_id=$1 AND reason=$2`, sourceID, reason).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// MI-2 regression: a self-registered "trusted" feed source must stay PENDING
// until a distinct verified principal activates it (maker-checker), and every
// admission attempt before activation is rejected and audit-logged.
func TestFeedSourceMakerCheckerActivationAgainstPostgreSQL(t *testing.T) {
	store, ctx := openMigratedStore(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sourceID := "pending-feed-integration"
	registrar := "registrar-integration"
	registration := FeedSourceRegistration{SourceID: sourceID, SourceKind: "AIS", Authority: "local-authority", PublicKey: publicKey, RegisteredBy: registrar}
	if err := store.RegisterFeedSource(ctx, registration); err != nil {
		t.Fatal(err)
	}
	// Registration never self-activates: the source is PENDING.
	var active bool
	var registeredBy string
	if err := store.pool.QueryRow(ctx, `SELECT active, registered_by FROM maritime_feed_sources WHERE source_id=$1`, sourceID).Scan(&active, &registeredBy); err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("registration self-activated the feed source")
	}
	if registeredBy != registrar {
		t.Fatalf("registrar not recorded: %q", registeredBy)
	}
	// Forged event from the pending source: rejected and audit-logged.
	payload := []byte(`{"mmsi":"636019999"}`)
	eventID := "pending-forged-event"
	signature := ed25519.Sign(privateKey, feedSigningBytes(sourceID, eventID, payload))
	if _, err := store.AdmitFeedEvent(ctx, FeedAdmissionRequest{SourceID: sourceID, SourceEventID: eventID, Payload: payload, Signature: signature}); !errors.Is(err, ErrFeedSourceNotActive) {
		t.Fatalf("pending source admission must fail with ErrFeedSourceNotActive, got %v", err)
	}
	if count := denialCount(t, store, ctx, sourceID, "source-not-active"); count != 1 {
		t.Fatalf("pending-source denial not audit-logged, count=%d", count)
	}
	// The registrar cannot self-activate (maker-checker).
	if err := store.ActivateFeedSource(ctx, FeedSourceActivation{SourceID: sourceID, ActivatedBy: registrar}); !errors.Is(err, ErrMakerChecker) {
		t.Fatalf("registrar self-activation must fail with ErrMakerChecker, got %v", err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT active FROM maritime_feed_sources WHERE source_id=$1`, sourceID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("registrar self-activation activated the source")
	}
	// A distinct verified principal activates; the activation record persists.
	activator := "activator-integration"
	if err := store.ActivateFeedSource(ctx, FeedSourceActivation{SourceID: sourceID, ActivatedBy: activator}); err != nil {
		t.Fatal(err)
	}
	var auditRegistrar, auditActivator string
	if err := store.pool.QueryRow(ctx, `SELECT registered_by, activated_by FROM maritime_feed_source_activations WHERE source_id=$1`, sourceID).Scan(&auditRegistrar, &auditActivator); err != nil {
		t.Fatal(err)
	}
	if auditRegistrar != registrar || auditActivator != activator {
		t.Fatalf("activation audit record wrong: registrar=%q activator=%q", auditRegistrar, auditActivator)
	}
	if err := store.pool.QueryRow(ctx, `SELECT active FROM maritime_feed_sources WHERE source_id=$1`, sourceID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if !active {
		t.Fatal("source not active after maker-checker activation")
	}
	// Exact activation replay is idempotent; a conflicting activation fails.
	if err := store.ActivateFeedSource(ctx, FeedSourceActivation{SourceID: sourceID, ActivatedBy: activator}); err != nil {
		t.Fatalf("exact activation replay failed: %v", err)
	}
	if err := store.ActivateFeedSource(ctx, FeedSourceActivation{SourceID: sourceID, ActivatedBy: "third-admin"}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting activation must fail with ErrIdempotencyConflict, got %v", err)
	}
	// After activation the previously forged event admits (signature valid).
	if _, err := store.AdmitFeedEvent(ctx, FeedAdmissionRequest{SourceID: sourceID, SourceEventID: eventID, Payload: payload, Signature: signature}); err != nil {
		t.Fatalf("activated source admission failed: %v", err)
	}
}

// MI-2 regression: re-registration cannot replace trusted key material or
// re-activate; unknown-source and bad-signature admissions are audit-logged;
// revoked sources are permanently retired.
func TestFeedSourceRegistrationFailClosedAgainstPostgreSQL(t *testing.T) {
	store, ctx := openMigratedStore(t)
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sourceID := "reregister-feed-integration"
	registration := FeedSourceRegistration{SourceID: sourceID, SourceKind: "RADAR", Authority: "local-authority", PublicKey: publicKey, RegisteredBy: "registrar-integration"}
	if err := store.RegisterFeedSource(ctx, registration); err != nil {
		t.Fatal(err)
	}
	// Identical re-registration is an idempotent replay.
	if err := store.RegisterFeedSource(ctx, registration); err != nil {
		t.Fatalf("identical re-registration failed: %v", err)
	}
	// Re-registration with different key material fails closed and the source
	// stays pending with the original key.
	conflicting := registration
	conflicting.PublicKey = otherKey
	if err := store.RegisterFeedSource(ctx, conflicting); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting re-registration must fail with ErrIdempotencyConflict, got %v", err)
	}
	var active bool
	if err := store.pool.QueryRow(ctx, `SELECT active FROM maritime_feed_sources WHERE source_id=$1`, sourceID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("conflicting re-registration activated the source")
	}
	// Unknown source: admission denied and audit-logged.
	payload := []byte(`{"mmsi":"636019999"}`)
	if _, err := store.AdmitFeedEvent(ctx, FeedAdmissionRequest{SourceID: "unknown-feed-integration", SourceEventID: "evt-1", Payload: payload, Signature: make([]byte, ed25519.SignatureSize)}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown source admission must fail with ErrNotFound, got %v", err)
	}
	if count := denialCount(t, store, ctx, "unknown-feed-integration", "source-unknown"); count != 1 {
		t.Fatalf("unknown-source denial not audit-logged, count=%d", count)
	}
	// Activate, then a bad signature is denied and audit-logged.
	if err := store.ActivateFeedSource(ctx, FeedSourceActivation{SourceID: sourceID, ActivatedBy: "activator-integration"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AdmitFeedEvent(ctx, FeedAdmissionRequest{SourceID: sourceID, SourceEventID: "evt-bad-sig", Payload: payload, Signature: make([]byte, ed25519.SignatureSize)}); !errors.Is(err, ErrFeedSignatureInvalid) {
		t.Fatalf("bad signature must fail with ErrFeedSignatureInvalid, got %v", err)
	}
	if count := denialCount(t, store, ctx, sourceID, "signature-invalid"); count != 1 {
		t.Fatalf("signature denial not audit-logged, count=%d", count)
	}
	// Revocation permanently retires the source; re-activation is denied.
	if err := store.RevokeFeedSource(ctx, FeedSourceRevocation{SourceID: sourceID, Reason: "key-compromise", RevokedBy: "security-operator"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateFeedSource(ctx, FeedSourceActivation{SourceID: sourceID, ActivatedBy: "fourth-admin"}); !errors.Is(err, ErrFeedSourceRevoked) {
		t.Fatalf("revoked source re-activation must fail with ErrFeedSourceRevoked, got %v", err)
	}
}
