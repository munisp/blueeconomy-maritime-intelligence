//go:build feedintegration

package incident

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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
			if readErr != nil { t.Fatal(readErr) }
			if execErr := store.Exec(ctx, string(migration)); execErr != nil { t.Fatal(execErr) }
		}
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sourceID := "ais-local-integration"
	if err := store.RegisterFeedSource(ctx, FeedSourceRegistration{SourceID: sourceID, SourceKind: "AIS", Authority: "local-authority", PublicKey: publicKey, Active: true}); err != nil {
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
}
