package tracks

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

// TestReplayRestoresStateWithoutIDCollision simulates a service restart:
// engine 1 fuses detections (associations persisted), engine 2 rebuilds from
// the persisted association audit via Replay and keeps serving. The replayed
// engine must expose the same track identities, and IDs minted after the
// restart must never collide with a persisted identity.
func TestReplayRestoresStateWithoutIDCollision(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	first, err := NewEngine(testConfig(), testZones(t), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	detections := []isr.Detection{
		aisDetection("123456789", base, 6.45, 3.40),
		aisDetection("123456789", base.Add(time.Minute), 6.45, 3.41),
		sarDetection("sar-1", base.Add(2*time.Minute), 5.50, 5.50),
	}
	persisted := make([]AssociationReplay, 0, len(detections))
	for _, detection := range detections {
		trackID, _, err := first.Ingest(ctx, detection)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := json.Marshal(detection)
		if err != nil {
			t.Fatal(err)
		}
		persisted = append(persisted, AssociationReplay{TrackID: trackID, Payload: payload})
	}
	if len(first.Tracks()) != 2 {
		t.Fatalf("expected 2 fused tracks before restart, got %d", len(first.Tracks()))
	}

	// Restart: a fresh engine replays the persisted associations in
	// observation order, exactly as the startup path does.
	restarted, err := NewEngine(testConfig(), testZones(t), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, replay := range persisted {
		detection, err := isr.DecodeDetection(replay.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := restarted.Replay(replay.TrackID, detection); err != nil {
			t.Fatal(err)
		}
	}
	if len(restarted.Tracks()) != len(first.Tracks()) {
		t.Fatalf("restart lost tracks: %d restored, want %d", len(restarted.Tracks()), len(first.Tracks()))
	}
	for _, original := range first.Tracks() {
		restored, ok := restarted.Track(original.TrackID)
		if !ok {
			t.Fatalf("track %s lost across restart", original.TrackID)
		}
		if restored.MMSI != original.MMSI || restored.Classification != original.Classification || len(restored.Points) != len(original.Points) {
			t.Fatalf("track %s corrupted across restart: %+v vs %+v", original.TrackID, restored, original)
		}
	}

	// A new detection for the known MMSI binds to the restored track — the
	// pre-restart identity keeps serving immediately after restart.
	followUp := aisDetection("123456789", base.Add(3*time.Minute), 6.45, 3.42)
	trackID, _, err := restarted.Ingest(ctx, followUp)
	if err != nil {
		t.Fatal(err)
	}
	if trackID != persisted[0].TrackID {
		t.Fatalf("post-restart detection bound to %s, want restored track %s", trackID, persisted[0].TrackID)
	}

	// A detection for an unknown vessel mints an ID that cannot collide with
	// any persisted identity: UUID-based, not a restartable sequence.
	newTrackID, _, err := restarted.Ingest(ctx, aisDetection("987654321", base.Add(4*time.Minute), 7.0, 4.0))
	if err != nil {
		t.Fatal(err)
	}
	for _, replay := range persisted {
		if newTrackID == replay.TrackID {
			t.Fatalf("post-restart track ID %s collides with a persisted identity", newTrackID)
		}
	}
	if !strings.HasPrefix(newTrackID, "fused-track-") {
		t.Fatalf("unexpected track ID shape %q", newTrackID)
	}
	if _, err := uuid.Parse(strings.TrimPrefix(newTrackID, "fused-track-")); err != nil {
		t.Fatalf("track ID %q is not UUID-suffixed: %v", newTrackID, err)
	}
}

// TestReplayFailsClosed rejects replay rows that cannot rebuild state safely.
func TestReplayFailsClosed(t *testing.T) {
	engine, err := NewEngine(testConfig(), testZones(t), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	if err := engine.Replay("", aisDetection("123456789", base, 6.45, 3.40)); err == nil {
		t.Fatal("replay without the persisted track identity accepted")
	}
	withoutPosition := sarDetection("sar-2", base, 5.5, 5.5)
	withoutPosition.HasPosition = false
	withoutPosition.Latitude, withoutPosition.Longitude = 0, 0
	if err := engine.Replay("fused-track-persisted", withoutPosition); err == nil {
		t.Fatal("replay of a position-less detection accepted")
	}
}
