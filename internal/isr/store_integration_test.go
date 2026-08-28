//go:build feedintegration

package isr

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/incident"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
)

func openIntegrationStore(t *testing.T) (*Store, *incident.Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if os.Getenv("SKIP_MIGRATION") != "true" {
		for _, migrationPath := range strings.Split(os.Getenv("MIGRATION_PATH"), ",") {
			migration, readErr := os.ReadFile(filepath.Clean(strings.TrimSpace(migrationPath)))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if _, execErr := pool.Exec(ctx, string(migration)); execErr != nil {
				t.Fatal(execErr)
			}
		}
	}
	signer, signerErr := provenance.NewSigner(SigningKeyID, testIntegrationKey(t))
	if signerErr != nil {
		t.Fatal(signerErr)
	}
	return NewStore(pool).WithSigner(signer), incident.NewStore(pool)
}

// testIntegrationKey derives a deterministic throwaway provenance key for
// the emission path exercised by the integration suite.
func testIntegrationKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := sha256.Sum256([]byte("maritime-intelligence-integration-provenance-key"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func signedDetection(t *testing.T, privateKey ed25519.PrivateKey, sourceID, eventID string, detection Detection) SignedDetectionRequest {
	t.Helper()
	payload, err := json.Marshal(detection)
	if err != nil {
		t.Fatal(err)
	}
	return SignedDetectionRequest{
		SourceID: sourceID, SourceEventID: eventID, Payload: payload,
		Signature: ed25519.Sign(privateKey, incident.FeedSigningBytes(sourceID, eventID, payload)),
	}
}

func TestDetectionAdmissionAgainstPostgreSQL(t *testing.T) {
	ctx := context.Background()
	store, feedStore := openIntegrationStore(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sourceID := "sar-feed-integration"
	if err := feedStore.RegisterFeedSource(ctx, incident.FeedSourceRegistration{SourceID: sourceID, SourceKind: "SAR", Authority: "local-authority", PublicKey: publicKey, Active: true}); err != nil {
		t.Fatal(err)
	}
	detection := Detection{
		EventID: "isr-evt-001", SourceID: sourceID, SourceEventID: "sar-001",
		Modality: ModalitySAR, Classification: ClassificationConfidential,
		ObservedAt:  time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC),
		HasPosition: true, Latitude: 6.45, Longitude: 3.39,
		SAR:             &SARPayload{SceneRef: "scene-001", Confidence: 0.9},
		CorrelationRefs: []string{"wsb:ferries.telemetry:anomaly-7"},
	}
	admitted, admission, err := store.AdmitDetection(ctx, signedDetection(t, privateKey, sourceID, "sar-001", detection))
	if err != nil {
		t.Fatal(err)
	}
	if admission.Replayed || admission.Classification != ClassificationConfidential {
		t.Fatalf("unexpected admission: %+v", admission)
	}
	if admitted.EventID != detection.EventID {
		t.Fatal("detection not returned")
	}
	// Exact replay returns retained evidence.
	_, replay, err := store.AdmitDetection(ctx, signedDetection(t, privateKey, sourceID, "sar-001", detection))
	if err != nil || !replay.Replayed {
		t.Fatalf("exact replay must return retained evidence: %v %+v", err, replay)
	}
	// Conflicting replay (same source event id, different payload) fails closed.
	conflicting := detection
	conflicting.SAR = &SARPayload{SceneRef: "scene-002", Confidence: 0.4}
	if _, _, err := store.AdmitDetection(ctx, signedDetection(t, privateKey, sourceID, "sar-001", conflicting)); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting replay must fail with ErrConflict, got %v", err)
	}
	// Missing classification is rejected at admission.
	unlabelled := detection
	unlabelled.SourceEventID = "sar-002"
	unlabelled.EventID = "isr-evt-002"
	unlabelled.Classification = ""
	if _, _, err := store.AdmitDetection(ctx, signedDetection(t, privateKey, sourceID, "sar-002", unlabelled)); !errors.Is(err, ErrInvalidClassification) {
		t.Fatalf("unlabelled detection must fail closed, got %v", err)
	}
	// Clearance-scoped reads: a restricted principal cannot see the
	// confidential detection; a secret principal can.
	restricted := Principal{Subject: "reader-1", Roles: map[string]struct{}{RoleNNOfficer: {}}, Clearance: ClassificationRestricted}
	secret := Principal{Subject: "reader-2", Roles: map[string]struct{}{RoleNNOfficer: {}}, Clearance: ClassificationSecret}
	listed, err := store.ListDetections(ctx, restricted, DetectionFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range listed {
		if item.Classification == ClassificationConfidential {
			t.Fatal("restricted principal received confidential detection")
		}
	}
	listed, err = store.ListDetections(ctx, secret, DetectionFilter{Modality: ModalitySAR})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range listed {
		if item.EventID == "isr-evt-001" {
			found = true
		}
	}
	if !found {
		t.Fatal("secret principal did not receive the confidential detection")
	}
	// The insurer-aggregator is denied detections and may read aggregates.
	insurer := Principal{Subject: "ins-1", Roles: map[string]struct{}{RoleInsurerAggregator: {}}, Clearance: ClassificationSecret}
	if _, err := store.ListDetections(ctx, insurer, DetectionFilter{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("insurer-aggregator must be denied detections, got %v", err)
	}
	if _, err := store.OutcomeAggregates(ctx, insurer); err != nil {
		t.Fatal(err)
	}
	// The detection envelope landed on the ISR outbox.
	var outboxCount int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM maritime_isr_outbox WHERE topic='maritime.isr.v1' AND aggregate_key='isr-evt-001'`).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if outboxCount != 1 {
		t.Fatalf("expected one isr outbox event, got %d", outboxCount)
	}
}
