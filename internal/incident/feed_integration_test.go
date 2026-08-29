//go:build feedintegration

package incident

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignedFeedIncidentIsAtomicAgainstPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sourceID := "radar-feed-incident"
	if err := store.RegisterFeedSource(ctx, FeedSourceRegistration{SourceID: sourceID, SourceKind: "RADAR", Authority: "local-authority", PublicKey: publicKey, RegisteredBy: "registrar-integration"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateFeedSource(ctx, FeedSourceActivation{SourceID: sourceID, ActivatedBy: "activator-integration"}); err != nil {
		t.Fatal(err)
	}
	eventID := "radar-event-incident-001"
	create := CreateRequest{IncidentID: "incident-radar-feed-001", SourceEventID: sourceID + ":" + eventID, Category: "NAVIGATION", Severity: SeverityHigh, Title: "Signed radar exception", Description: "Authorized feed created incident", OccurredAt: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC), CreatedBy: "feed:" + sourceID}
	payload, err := json.Marshal(create)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, feedSigningBytes(sourceID, eventID, payload))
	result, err := store.AdmitFeedIncident(ctx, SignedFeedIncidentRequest{FeedAdmissionRequest: FeedAdmissionRequest{SourceID: sourceID, SourceEventID: eventID, Payload: payload, Signature: signature}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Incident.IncidentID != create.IncidentID || result.Admission.SourceEventID != eventID {
		t.Fatalf("unexpected feed incident result: %+v", result)
	}
	if _, err := store.AdmitFeedIncident(ctx, SignedFeedIncidentRequest{FeedAdmissionRequest: FeedAdmissionRequest{SourceID: sourceID, SourceEventID: eventID, Payload: payload, Signature: signature}}); err != nil {
		t.Fatalf("exact replay failed: %v", err)
	}
	var outboxCount int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM maritime_incident_outbox WHERE incident_id=$1`, create.IncidentID).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if outboxCount != 1 {
		t.Fatalf("expected one incident outbox event after exact replay, got %d", outboxCount)
	}
	invalidEventID := "radar-event-incident-rollback"
	invalidCreate := create
	invalidCreate.IncidentID = "incident-radar-feed-rollback"
	invalidCreate.SourceEventID = "unbound-source-event"
	invalidPayload, err := json.Marshal(invalidCreate)
	if err != nil {
		t.Fatal(err)
	}
	invalidSignature := ed25519.Sign(privateKey, feedSigningBytes(sourceID, invalidEventID, invalidPayload))
	if _, err := store.AdmitFeedIncident(ctx, SignedFeedIncidentRequest{FeedAdmissionRequest: FeedAdmissionRequest{SourceID: sourceID, SourceEventID: invalidEventID, Payload: invalidPayload, Signature: invalidSignature}}); err == nil {
		t.Fatal("unbound signed incident payload was accepted")
	}
	var retainedFeedCount int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM maritime_feed_events WHERE source_id=$1 AND source_event_id=$2`, sourceID, invalidEventID).Scan(&retainedFeedCount); err != nil {
		t.Fatal(err)
	}
	if retainedFeedCount != 0 {
		t.Fatal("invalid signed incident payload left durable feed evidence")
	}
}

func TestAuthorizedFeedAdmissionAgainstPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
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
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sourceID := "ais-local-integration"
	if err := store.RegisterFeedSource(ctx, FeedSourceRegistration{SourceID: sourceID, SourceKind: "AIS", Authority: "local-authority", PublicKey: publicKey, RegisteredBy: "registrar-integration"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateFeedSource(ctx, FeedSourceActivation{SourceID: sourceID, ActivatedBy: "activator-integration"}); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"mmsi":"636019999","lat":6.45,"lon":3.39}`)
	eventID := "ais-event-integration-001"
	signature := ed25519.Sign(privateKey, feedSigningBytes(sourceID, eventID, payload))
	admitted, err := store.AdmitFeedEvent(ctx, FeedAdmissionRequest{SourceID: sourceID, SourceEventID: eventID, Payload: payload, Signature: signature})
	if err != nil {
		t.Fatal(err)
	}
	if admitted.PayloadSHA256 == "" || admitted.KeyFingerprint == "" {
		t.Fatal("missing feed evidence")
	}
	if _, err := store.AdmitFeedEvent(ctx, FeedAdmissionRequest{SourceID: sourceID, SourceEventID: eventID, Payload: payload, Signature: signature}); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), signature...)
	bad[0] ^= 0xff
	if _, err := store.AdmitFeedEvent(ctx, FeedAdmissionRequest{SourceID: sourceID, SourceEventID: "ais-event-integration-002", Payload: payload, Signature: bad}); err == nil {
		t.Fatal("invalid signature was accepted")
	}
	// Conflicting replay: same source_event_id with a different, validly
	// signed payload must fail closed with ErrIdempotencyConflict, not be
	// silently absorbed.
	conflictingPayload := []byte(`{"mmsi":"636019999","lat":7.45,"lon":4.39}`)
	conflictingSignature := ed25519.Sign(privateKey, feedSigningBytes(sourceID, eventID, conflictingPayload))
	if _, err := store.AdmitFeedEvent(ctx, FeedAdmissionRequest{SourceID: sourceID, SourceEventID: eventID, Payload: conflictingPayload, Signature: conflictingSignature}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting replay must fail with ErrIdempotencyConflict, got %v", err)
	}
}

func TestFeedSourceRevocationAgainstPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sourceID := "revocable-feed-integration"
	if err := store.RegisterFeedSource(ctx, FeedSourceRegistration{SourceID: sourceID, SourceKind: "AIS", Authority: "local-authority", PublicKey: publicKey, RegisteredBy: "registrar-integration"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateFeedSource(ctx, FeedSourceActivation{SourceID: sourceID, ActivatedBy: "activator-integration"}); err != nil {
		t.Fatal(err)
	}
	revocation := FeedSourceRevocation{SourceID: sourceID, Reason: "key-compromise", RevokedBy: "security-operator"}
	if err := store.RevokeFeedSource(ctx, revocation); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeFeedSource(ctx, revocation); err != nil {
		t.Fatalf("exact revocation replay failed: %v", err)
	}
	if err := store.RevokeFeedSource(ctx, FeedSourceRevocation{SourceID: sourceID, Reason: "different-reason", RevokedBy: "security-operator"}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting revocation error = %v", err)
	}
	payload := []byte(`{"mmsi":"636019999"}`)
	signature := ed25519.Sign(privateKey, feedSigningBytes(sourceID, "post-revocation-event", payload))
	if _, err := store.AdmitFeedEvent(ctx, FeedAdmissionRequest{SourceID: sourceID, SourceEventID: "post-revocation-event", Payload: payload, Signature: signature}); err == nil {
		t.Fatal("revoked source admitted signed event")
	}
	var active bool
	if err := store.pool.QueryRow(ctx, `SELECT active FROM maritime_feed_sources WHERE source_id=$1`, sourceID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active {
		t.Fatal("revoked source remains active")
	}
}

func TestFeedSourceKeyRotationAgainstPostgreSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	oldPublic, oldPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPublic, newPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sourceID := "rotating-feed-integration"
	if err := store.RegisterFeedSource(ctx, FeedSourceRegistration{SourceID: sourceID, SourceKind: "VTS", Authority: "local-authority", PublicKey: oldPublic, RegisteredBy: "registrar-integration"}); err != nil {
		t.Fatal(err)
	}
	if err := store.ActivateFeedSource(ctx, FeedSourceActivation{SourceID: sourceID, ActivatedBy: "activator-integration"}); err != nil {
		t.Fatal(err)
	}
	if err := store.RotateFeedSourceKey(ctx, FeedSourceKeyRotation{SourceID: sourceID, NewPublicKey: newPublic, GraceUntil: time.Now().UTC().Add(time.Hour), RotatedBy: "key-operator"}); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"vessel":"test"}`)
	oldSignature := ed25519.Sign(oldPrivate, feedSigningBytes(sourceID, "rotation-grace-event", payload))
	if _, err := store.AdmitFeedEvent(ctx, FeedAdmissionRequest{SourceID: sourceID, SourceEventID: "rotation-grace-event", Payload: payload, Signature: oldSignature}); err != nil {
		t.Fatalf("prior key rejected within grace window: %v", err)
	}
	newSignature := ed25519.Sign(newPrivate, feedSigningBytes(sourceID, "rotation-new-key-event", payload))
	if _, err := store.AdmitFeedEvent(ctx, FeedAdmissionRequest{SourceID: sourceID, SourceEventID: "rotation-new-key-event", Payload: payload, Signature: newSignature}); err != nil {
		t.Fatalf("replacement key rejected: %v", err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE maritime_feed_source_key_rotations SET grace_until=$2 WHERE source_id=$1`, sourceID, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	expiredSignature := ed25519.Sign(oldPrivate, feedSigningBytes(sourceID, "rotation-expired-event", payload))
	if _, err := store.AdmitFeedEvent(ctx, FeedAdmissionRequest{SourceID: sourceID, SourceEventID: "rotation-expired-event", Payload: payload, Signature: expiredSignature}); err == nil {
		t.Fatal("expired prior key was accepted")
	}
}
