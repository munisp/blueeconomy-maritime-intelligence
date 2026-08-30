//go:build feedintegration

package yaounde

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/envelope"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/geo"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
)

var migrateOnce sync.Once

func yaoundePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	migrateOnce.Do(func() {
		for _, migrationPath := range strings.Split(os.Getenv("MIGRATION_PATH"), ",") {
			migration, readErr := os.ReadFile(filepath.Clean(strings.TrimSpace(migrationPath)))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if _, execErr := pool.Exec(context.Background(), string(migration)); execErr != nil {
				t.Fatalf("migration %s: %v", migrationPath, execErr)
			}
		}
	})
	t.Cleanup(pool.Close)
	return pool
}

func seedIncident(t *testing.T, pool *pgxpool.Pool, incidentID string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO maritime_incidents (incident_id, source_event_id, category, severity, title, description, occurred_at, created_by, status, created_at, updated_at, version)
		VALUES ($1, $2, 'SAR', 'CRITICAL', 'distress', 'test incident', now(), 'intake:test', 'OPEN', now(), now(), 1)`,
		incidentID, "test:"+incidentID)
	if err != nil {
		t.Fatal(err)
	}
}

type yaoundeStubTracks struct{ tracks []SourcedTrack }

func (stub yaoundeStubTracks) LatestPositions(_ context.Context, _, _ time.Time) ([]SourcedTrack, error) {
	return stub.tracks, nil
}

func TestYaoundeGatewayEndToEnd(t *testing.T) {
	ctx := context.Background()
	pool := yaoundePool(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := provenance.NewSigner("mi-yaounde-it-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool).WithSigner(signer)
	peerPub, peerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seedIncident(t, pool, "inc-ygr-1")

	// Peer registration + maker-checker activation.
	reg := PeerRegistration{
		PeerID: "icc-yaounde", PeerKind: "ICC", Zone: "CENTRAL_B",
		EndpointURL: "https://icc.example.test/yaounde", ContactChannel: "ops",
		PublicKey: peerPub, RegisteredBy: "registrar-1",
	}
	if err := store.RegisterPeer(ctx, reg); err != nil {
		t.Fatal(err)
	}
	// Same principal cannot activate (maker-checker).
	if _, err := store.PeerLifecycle(ctx, "icc-yaounde", "activate", "registrar-1"); !errors.Is(err, ErrMakerChecker) {
		t.Fatalf("expected maker-checker refusal, got %v", err)
	}
	peer, err := store.PeerLifecycle(ctx, "icc-yaounde", "activate", "approver-1")
	if err != nil || peer.Status != PeerActive {
		t.Fatalf("activation failed: %v %+v", err, peer)
	}
	// Replay of registration is idempotent.
	if err := store.RegisterPeer(ctx, reg); err != nil {
		t.Fatalf("registration replay failed: %v", err)
	}

	// Draft → approve (distinct principal) → dispatch.
	release, err := store.DraftRelease(ctx, ReleaseDraftRequest{
		IncidentID: "inc-ygr-1", PeerID: "icc-yaounde", Marking: "YAOUNDE_REGIONAL",
		Classification: "CONFIDENTIAL", ExpectedVersion: 1, Narrative: "operator-cleared narrative",
		ReleasedBy: "releaser-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApproveRelease(ctx, release.ReleaseID, release.Version, "releaser-1"); !errors.Is(err, ErrMakerChecker) {
		t.Fatalf("self-approval must fail maker-checker, got %v", err)
	}
	release, err = store.ApproveRelease(ctx, release.ReleaseID, release.Version, "approver-1")
	if err != nil || release.State != ReleaseApproved {
		t.Fatalf("approval failed: %v %+v", err, release)
	}
	release, err = store.DispatchRelease(ctx, release.ReleaseID, release.Version, "releaser-1")
	if err != nil || release.State != ReleaseDispatched {
		t.Fatalf("dispatch failed: %v %+v", err, release)
	}
	// Peer-signed ack over the published receipt preimage completes the loop.
	ack := ed25519.Sign(peerPriv, []byte(AckReceiptPreimage(release.ReleaseID, release.ReportSHA256)))
	release, err = store.RecordAcknowledgement(ctx, release.ReleaseID, release.Version, ack)
	if err != nil || release.State != ReleaseAcknowledged {
		t.Fatalf("ack failed: %v %+v", err, release)
	}
	// A forged ack on a fresh dispatch is rejected.
	release2, err := store.DraftRelease(ctx, ReleaseDraftRequest{
		IncidentID: "inc-ygr-1", PeerID: "icc-yaounde", Marking: "YAOUNDE_REGIONAL",
		Classification: "RESTRICTED", ExpectedVersion: 1, Narrative: "second narrative", ReleasedBy: "releaser-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	release2, _ = store.ApproveRelease(ctx, release2.ReleaseID, release2.Version, "approver-1")
	release2, _ = store.DispatchRelease(ctx, release2.ReleaseID, release2.Version, "releaser-1")
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	forged := ed25519.Sign(wrongPriv, []byte(AckReceiptPreimage(release2.ReleaseID, release2.ReportSHA256)))
	if _, err := store.RecordAcknowledgement(ctx, release2.ReleaseID, release2.Version, forged); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("forged ack must fail, got %v", err)
	}

	// Envelope verification round-trip against the outbox payload.
	var eventCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM yaounde_outbox`).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount == 0 {
		t.Fatal("no yaounde outbox events emitted")
	}
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT payload FROM yaounde_outbox WHERE event_type='maritime.yaounde.incident_report.v1' LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	directory, err := provenance.ParseDirectory([]byte(`{"mi-yaounde-it-1":"` + base64.RawURLEncoding.EncodeToString(publicKey) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.Admit(raw, directory); err != nil {
		t.Fatalf("emitted envelope fails verification: %v", err)
	}

	// Inbound: peer-signed admission, replay-safe.
	payload := []byte(`{"report":"contact report","ref":"peer-ref-1"}`)
	sig := ed25519.Sign(peerPriv, []byte(InboundSigningPreimage("icc-yaounde", "peer-ref-1", payload)))
	report, err := store.AdmitInbound(ctx, InboundAdmissionRequest{
		PeerID: "icc-yaounde", PeerReportRef: "peer-ref-1", Classification: "RESTRICTED",
		Marking: "YAOUNDE_REGIONAL", Payload: payload, Signature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	report2, err := store.AdmitInbound(ctx, InboundAdmissionRequest{
		PeerID: "icc-yaounde", PeerReportRef: "peer-ref-1", Classification: "RESTRICTED",
		Marking: "YAOUNDE_REGIONAL", Payload: payload, Signature: sig,
	})
	if err != nil || report2.ReportID != report.ReportID {
		t.Fatalf("replay must be idempotent: %v", err)
	}
	if _, err := store.CorrelateInbound(ctx, report.ReportID, "inc-ygr-1", "approver-1"); err != nil {
		t.Fatal(err)
	}

	// Picture: prepare → approve → dispatch re-filters the live track source.
	zone := geo.Zone{ZoneID: "zone-e", Vertices: []geo.Position{
		{Latitude: 0, Longitude: 0}, {Latitude: 10, Longitude: 0}, {Latitude: 10, Longitude: 10}, {Latitude: 0, Longitude: 10},
	}}
	now := time.Now().UTC()
	store.WithTrackSource(yaoundeStubTracks{tracks: []SourcedTrack{
		{TrackID: "trk-1", Classification: isr.ClassificationUnclassified, Position: geo.Position{Latitude: 5, Longitude: 5}, ObservedAt: now},
	}})
	picture, err := store.PreparePicture(ctx, PicturePrepareRequest{
		PeerID: "icc-yaounde", ZoneID: "zone-e", Zone: zone,
		WindowStart: now.Add(-time.Hour), WindowEnd: now.Add(time.Minute),
		Ceiling: "RESTRICTED", CreatedBy: "releaser-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApprovePicture(ctx, picture.ContributionID, "releaser-1"); !errors.Is(err, ErrMakerChecker) {
		t.Fatalf("picture self-approval must fail maker-checker, got %v", err)
	}
	if _, err := store.ApprovePicture(ctx, picture.ContributionID, "approver-1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.DispatchPicture(ctx, picture.ContributionID, "releaser-1", zone); err != nil {
		t.Fatal(err)
	}

	// Audit chain verifies end to end.
	count, err := VerifyAuditChain(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if count < 10 {
		t.Fatalf("expected a populated audit chain, got %d entries", count)
	}
	// Immutability: UPDATE is blocked by trigger.
	if _, err := pool.Exec(ctx, `UPDATE yaounde_audit_log SET detail='{}' WHERE seq=1`); err == nil {
		t.Fatal("audit ledger accepted an UPDATE")
	}
}

func TestYaoundeUnconfiguredPeerDispatchRefusal(t *testing.T) {
	ctx := context.Background()
	pool := yaoundePool(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := provenance.NewSigner("mi-yaounde-it-2", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool).WithSigner(signer)
	peerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	seedIncident(t, pool, "inc-ygr-2")
	// Peer registered WITHOUT an endpoint: ACTIVE but UNCONFIGURED.
	if err := store.RegisterPeer(ctx, PeerRegistration{
		PeerID: "icc-no-endpoint", PeerKind: "ICC", Zone: "CENTRAL_B",
		PublicKey: peerPub, RegisteredBy: "registrar-1",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PeerLifecycle(ctx, "icc-no-endpoint", "activate", "approver-1"); err != nil {
		t.Fatal(err)
	}
	release, err := store.DraftRelease(ctx, ReleaseDraftRequest{
		IncidentID: "inc-ygr-2", PeerID: "icc-no-endpoint", Marking: "YAOUNDE_REGIONAL",
		Classification: "RESTRICTED", ExpectedVersion: 1, Narrative: "narrative", ReleasedBy: "releaser-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	release, err = store.ApproveRelease(ctx, release.ReleaseID, release.Version, "approver-1")
	if err != nil {
		t.Fatal(err)
	}
	// Fail-closed: dispatch to an unconfigured endpoint → 409-class refusal +
	// audited release.refused.
	if _, err := store.DispatchRelease(ctx, release.ReleaseID, release.Version, "releaser-1"); !errors.Is(err, ErrPeerNotConfigured) {
		t.Fatalf("expected ErrPeerNotConfigured, got %v", err)
	}
	var refusalCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM yaounde_audit_log WHERE event_type='release.refused'`).Scan(&refusalCount); err != nil {
		t.Fatal(err)
	}
	if refusalCount == 0 {
		t.Fatal("dispatch refusal was not audited")
	}
	// NATIONAL_ONLY is never releasable (policy refusal audited).
	if _, err := store.DraftRelease(ctx, ReleaseDraftRequest{
		IncidentID: "inc-ygr-2", PeerID: "icc-no-endpoint", Marking: "NATIONAL_ONLY",
		Classification: "RESTRICTED", ExpectedVersion: 1, Narrative: "national only", ReleasedBy: "releaser-1",
	}); !errors.Is(err, ErrPolicyRefusal) {
		t.Fatalf("NATIONAL_ONLY must refuse, got %v", err)
	}
}
