package sar

import (
	"context"
	"testing"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/geo"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

type stubTrackSource struct{ tracks []SourcedTrack }

func (stub stubTrackSource) LatestPositions(_ context.Context, _, _ time.Time) ([]SourcedTrack, error) {
	return stub.tracks, nil
}

func TestListVOO(t *testing.T) {
	lat, lon := 4.0, 9.5
	sarCase := Case{CaseID: "sar-1", LastKnownLatitude: &lat, LastKnownLongitude: &lon}
	source := stubTrackSource{tracks: []SourcedTrack{
		{TrackID: "trk-near", MMSI: "671000001", Classification: isr.ClassificationUnclassified, Position: geo.Position{Latitude: 4.1, Longitude: 9.55}, ObservedAt: time.Now()},
		{TrackID: "trk-far", Classification: isr.ClassificationUnclassified, Position: geo.Position{Latitude: 10, Longitude: 20}, ObservedAt: time.Now()},
		{TrackID: "trk-secret", Classification: isr.ClassificationSecret, Position: geo.Position{Latitude: 4.1, Longitude: 9.55}, ObservedAt: time.Now()},
	}}
	entries, err := ListVOO(context.Background(), source, sarCase, 50, isr.ClassificationUnclassified, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].TrackID != "trk-near" {
		t.Fatalf("expected only trk-near (clearance-capped, radius-limited), got %+v", entries)
	}
	// No datum and no last-known: fail closed.
	if _, err := ListVOO(context.Background(), source, Case{CaseID: "sar-2"}, 50, isr.ClassificationUnclassified, time.Hour, time.Now()); err == nil {
		t.Fatal("VOO without any position reference accepted")
	}
	if _, err := ListVOO(context.Background(), nil, sarCase, 50, isr.ClassificationUnclassified, time.Hour, time.Now()); err == nil {
		t.Fatal("VOO without track source accepted")
	}
}
