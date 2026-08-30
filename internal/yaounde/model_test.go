package yaounde

import (
	"testing"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/geo"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

func TestReleaseStateMachine(t *testing.T) {
	legal := [][2]ReleaseState{
		{ReleaseDraft, ReleaseApproved}, {ReleaseDraft, ReleaseWithdrawn},
		{ReleaseApproved, ReleaseDispatched}, {ReleaseApproved, ReleaseWithdrawn},
		{ReleaseDispatched, ReleaseAcknowledged}, {ReleaseDispatched, ReleaseFailed},
		{ReleaseFailed, ReleaseDispatched},
	}
	for _, pair := range legal {
		if !ValidReleaseTransition(pair[0], pair[1]) {
			t.Fatalf("%s -> %s must be legal", pair[0], pair[1])
		}
	}
	illegal := [][2]ReleaseState{
		{ReleaseDraft, ReleaseDispatched}, {ReleaseDraft, ReleaseAcknowledged},
		{ReleaseApproved, ReleaseAcknowledged}, {ReleaseAcknowledged, ReleaseDispatched},
		{ReleaseWithdrawn, ReleaseDraft}, {ReleaseFailed, ReleaseApproved},
		{ReleaseDispatched, ReleaseDraft},
	}
	for _, pair := range illegal {
		if ValidReleaseTransition(pair[0], pair[1]) {
			t.Fatalf("%s -> %s must be illegal", pair[0], pair[1])
		}
	}
}

func TestMarkingMatrix(t *testing.T) {
	icc := Peer{PeerKind: PeerICC}
	mdat := Peer{PeerKind: PeerMDATGoG}
	// NATIONAL_ONLY is never releasable to anyone.
	for _, peer := range []Peer{icc, mdat, {PeerKind: PeerOther}} {
		if err := peerMarkingAllowed(peer, MarkingNationalOnly); err == nil {
			t.Fatalf("NATIONAL_ONLY allowed to %s", peer.PeerKind)
		}
	}
	if err := peerMarkingAllowed(mdat, MarkingYaoundeRegional); err == nil {
		t.Fatal("regional material allowed to MDAT-GoG contact")
	}
	if err := peerMarkingAllowed(icc, MarkingYaoundeRegional); err != nil {
		t.Fatal(err)
	}
	if err := peerMarkingAllowed(mdat, MarkingMDATGoGShareable); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseMarking("FOR_OFFICIAL_USE"); err == nil {
		t.Fatal("unknown marking accepted")
	}
}

func TestClassificationCeilingPolicy(t *testing.T) {
	icc := Peer{PeerKind: PeerICC}
	if got := ClassificationCeiling(icc); got != isr.ClassificationConfidential {
		t.Fatalf("icc ceiling = %s", got)
	}
	// SECRET above the CONFIDENTIAL ceiling refuses.
	if err := CheckReleasePolicy(icc, MarkingYaoundeRegional, isr.ClassificationSecret); err == nil {
		t.Fatal("SECRET release to ICC accepted")
	}
	if err := CheckReleasePolicy(icc, MarkingYaoundeRegional, isr.ClassificationConfidential); err != nil {
		t.Fatal(err)
	}
	other := Peer{PeerKind: PeerOther}
	if err := CheckReleasePolicy(other, MarkingMDATGoGShareable, isr.ClassificationRestricted); err == nil {
		t.Fatal("RESTRICTED release to OTHER accepted")
	}
}

func TestFilterPicture(t *testing.T) {
	zone := geo.Zone{ZoneID: "zone-e", Vertices: []geo.Position{
		{Latitude: 0, Longitude: 0}, {Latitude: 10, Longitude: 0},
		{Latitude: 10, Longitude: 10}, {Latitude: 0, Longitude: 10},
	}}
	now := time.Now().UTC()
	sourced := []SourcedTrack{
		{TrackID: "trk-a", MMSI: "123456789", Classification: isr.ClassificationUnclassified, Position: geo.Position{Latitude: 5, Longitude: 5}, ObservedAt: now},
		{TrackID: "trk-b", Classification: isr.ClassificationSecret, Position: geo.Position{Latitude: 5, Longitude: 5}, ObservedAt: now},
		{TrackID: "trk-c", Classification: isr.ClassificationRestricted, Position: geo.Position{Latitude: 50, Longitude: 50}, ObservedAt: now},
	}
	filtered, err := FilterPicture(sourced, zone, isr.ClassificationRestricted)
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || filtered[0].TrackID != "trk-a" {
		t.Fatalf("expected only trk-a, got %+v", filtered)
	}
	if filtered[0].LatitudeMicros != 5000000 {
		t.Fatalf("micro-degree conversion wrong: %+v", filtered[0])
	}
	if _, _, _, err := BuildPictureArtifact("zone-e", zone, now, now.Add(-time.Hour), isr.ClassificationUnclassified, sourced); err == nil {
		t.Fatal("empty window accepted")
	}
}

func TestEntryHashDeterminism(t *testing.T) {
	at := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	a, err := EntryHash("release.drafted", "op-1", "ygr-1", map[string]any{"k": "v"}, GenesisHash(), at)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EntryHash("release.drafted", "op-1", "ygr-1", map[string]any{"k": "v"}, GenesisHash(), at)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("entry hash not deterministic")
	}
	if _, err := EntryHash("release.drafted", "op-1", "ygr-1", nil, "bad", at); err == nil {
		t.Fatal("bad prev_hash accepted")
	}
}
