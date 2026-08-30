//go:build feedintegration

package sar

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/envelope"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
)

func sarPool(t *testing.T) *pgxpool.Pool {
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

func TestSARCaseEngineEndToEnd(t *testing.T) {
	ctx := context.Background()
	pool := sarPool(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := provenance.NewSigner("mi-sar-it-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool).WithSigner(signer)
	// Anchor incident.
	if _, err := pool.Exec(ctx, `
		INSERT INTO maritime_incidents (incident_id, source_event_id, category, severity, title, description, occurred_at, created_by, status, created_at, updated_at, version)
		VALUES ('inc-sar-1', 'test:inc-sar-1', 'SAR', 'CRITICAL', 'distress', 'integration incident', now(), 'intake:test', 'OPEN', now(), now(), 1)`); err != nil {
		t.Fatal(err)
	}

	// Manual open; intake replay on the same incident is idempotent.
	sarCase, err := store.OpenCase(ctx, OpenCaseRequest{
		IncidentID: "inc-sar-1", SourceRef: "manual:log-1", Classification: "RESTRICTED", Phase: "INCERFA",
	}, "watchkeeper-1")
	if err != nil {
		t.Fatal(err)
	}
	if sarCase.Stage != StageAwareness || sarCase.Phase != PhaseIncerfa {
		t.Fatalf("unexpected initial state %+v", sarCase)
	}
	replay, err := store.OpenCaseFromIntake(ctx, OpenCaseRequest{
		IncidentID: "inc-sar-1", SourceRef: "waterway:batch:dev:1", Classification: "RESTRICTED", Phase: "INCERFA",
	}, IntakeWaterway, "intake:test")
	if err != nil || replay.CaseID != sarCase.CaseID {
		t.Fatalf("intake replay must return the existing case: %v", err)
	}

	// Phase change with rationale; same-phase carries no fact.
	if _, err := store.TransitionPhase(ctx, sarCase.CaseID, sarCase.Version, "INCERFA", "same", "coordinator-1"); err == nil {
		t.Fatal("same-phase transition accepted")
	}
	if _, err := store.TransitionPhase(ctx, sarCase.CaseID, sarCase.Version, "ALERFA", "", "coordinator-1"); err == nil {
		t.Fatal("phase transition without rationale accepted")
	}
	sarCase, err = store.TransitionPhase(ctx, sarCase.CaseID, sarCase.Version, "ALERFA", "no response to repeated calls", "coordinator-1")
	if err != nil || sarCase.Phase != PhaseAlerfa {
		t.Fatalf("phase transition failed: %v", err)
	}

	// Stage advance, datum, tasking lifecycle, sitrep, stand-down.
	sarCase, err = store.TransitionStage(ctx, sarCase.CaseID, sarCase.Version, "INITIAL_ACTION", "", "coordinator-1", nil, "")
	if err != nil || sarCase.Stage != StageInitialAction {
		t.Fatalf("stage transition failed: %v", err)
	}
	if _, err := store.SetDatum(ctx, sarCase.CaseID, sarCase.Version, 3.8, 9.7, "sha256:"+strings.Repeat("a", 64), "watchkeeper-1"); err != nil {
		t.Fatalf("set datum failed: %v", err)
	}
	sarCase, _ = store.GetCase(ctx, sarCase.CaseID)
	resource, err := store.RegisterResource(ctx, ResourceRegistration{
		ResourceID: "sru-1", Kind: "VESSEL", Callsign: "M/V Responder", HomeAuthority: "national-mrcc", Capabilities: map[string]any{"searches": "surface"},
	}, "resourcer-1")
	if err != nil {
		t.Fatal(err)
	}
	tasking, err := store.ProposeTasking(ctx, sarCase.CaseID, TaskingRequest{
		ResourceID: resource.ResourceID, Task: "SEARCH_PATTERN", Briefing: map[string]any{"pattern": "expanding-square"},
	}, "coordinator-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.TransitionTasking(ctx, sarCase.CaseID, tasking.TaskingID, tasking.Version, "ON_SCENE", "sru-on-scene", "coordinator-1"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("proposed->on_scene must fail, got %v", err)
	}
	tasking, err = store.TransitionTasking(ctx, sarCase.CaseID, tasking.TaskingID, tasking.Version, "TASKED", "order-issued", "coordinator-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.TransitionTasking(ctx, sarCase.CaseID, tasking.TaskingID, tasking.Version, "ACKED", "sru-acknowledged", "coordinator-1"); err != nil {
		t.Fatal(err)
	}

	// SITREPs are numbered, immutable and signed.
	sarCase, _ = store.GetCase(ctx, sarCase.CaseID)
	sitrep1, err := store.IssueSitrep(ctx, sarCase.CaseID, sarCase.Version, "coordinator-1")
	if err != nil || sitrep1.Sequence != 1 {
		t.Fatalf("sitrep 1 failed: %v %+v", err, sitrep1)
	}
	sarCase, _ = store.GetCase(ctx, sarCase.CaseID)
	sitrep2, err := store.IssueSitrep(ctx, sarCase.CaseID, sarCase.Version, "coordinator-1")
	if err != nil || sitrep2.Sequence != 2 {
		t.Fatalf("sitrep 2 failed: %v %+v", err, sitrep2)
	}
	if _, err := pool.Exec(ctx, `UPDATE sar_sitreps SET body_sha256='x' WHERE case_id=$1 AND sequence=1`, sarCase.CaseID); err == nil {
		t.Fatal("sitrep row accepted an UPDATE (immutability broken)")
	}

	// Stand-down closes the case and emits case_closed.
	sarCase, _ = store.GetCase(ctx, sarCase.CaseID)
	if _, err := store.TransitionStage(ctx, sarCase.CaseID, sarCase.Version, "STAND_DOWN", "RESOLVED", "coordinator-1", nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TransitionPhase(ctx, sarCase.CaseID, 99, "DETRESFA", "post-closure", "coordinator-1"); err == nil {
		t.Fatal("transition after stand-down accepted")
	}

	// All emitted envelopes verify against the emission key; the sar topic
	// rides the shared isr outbox.
	rows, err := pool.Query(ctx, `SELECT payload FROM maritime_isr_outbox WHERE topic='maritime.sar.v1' ORDER BY created_at`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	directory, err := provenance.ParseDirectory([]byte(`{"mi-sar-it-1":"` + base64.RawURLEncoding.EncodeToString(publicKey) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	emitted := 0
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if _, err := envelope.Admit(raw, directory); err != nil {
			t.Fatalf("emitted sar envelope fails verification: %v", err)
		}
		emitted++
	}
	// case_opened, phase_changed, stage_changed, tasking changes, sitreps, case_closed.
	if emitted < 8 {
		t.Fatalf("expected >= 8 signed sar events, got %d", emitted)
	}
}

func TestSARGeoSOSClassificationFloor(t *testing.T) {
	ctx := context.Background()
	pool := sarPool(t)
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := provenance.NewSigner("mi-sar-it-2", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool).WithSigner(signer)
	if _, err := pool.Exec(ctx, `
		INSERT INTO maritime_incidents (incident_id, source_event_id, category, severity, title, description, occurred_at, created_by, status, created_at, updated_at, version)
		VALUES ('inc-sar-2', 'test:inc-sar-2', 'SAR', 'CRITICAL', 'sos', 'sos incident', now(), 'intake:test', 'OPEN', now(), now(), 1)`); err != nil {
		t.Fatal(err)
	}
	// DB floor: GEO_SOS intake cannot persist an UNCLASSIFIED case even if
	// service-layer checks were bypassed.
	if _, err := pool.Exec(ctx, `
		INSERT INTO sar_cases (case_id, incident_id, intake_kind, source_ref, classification, phase, stage, version, opened_by, created_at, updated_at)
		VALUES ('sar-x', 'inc-sar-2', 'GEO_SOS', 'geo-sos:sos-x', 'UNCLASSIFIED', 'DETRESFA', 'AWARENESS', 1, 'intake:geo-sos', now(), now())`); err == nil {
		t.Fatal("GEO_SOS UNCLASSIFIED floor not enforced by the database")
	}
	lat, lon := 3.8, 9.7
	now := time.Now().UTC()
	sarCase, err := store.OpenCaseFromIntake(ctx, OpenCaseRequest{
		IncidentID: "inc-sar-2", SourceRef: "geo-sos:sos-1", Classification: "RESTRICTED", Phase: "DETRESFA",
		LastKnownLatitude: &lat, LastKnownLongitude: &lon, LastKnownAt: &now,
	}, IntakeGeoSOS, "intake:geo-sos")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MirrorSOSAcknowledge(ctx, sarCase.CaseID, "geo-sos:sos-1", "coordinator-1"); err != nil {
		t.Fatal(err)
	}
	// Wrong sos_ref refuses to mirror (prevents cross-case smuggling).
	if err := store.MirrorSOSResolve(ctx, sarCase.CaseID, "geo-sos:other", "coordinator-1"); err == nil {
		t.Fatal("mismatched sos_ref mirrored")
	}
}
