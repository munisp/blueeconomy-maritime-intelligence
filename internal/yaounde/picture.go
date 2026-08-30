package yaounde

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/envelope"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/geo"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

// PictureTrack is one releasable latest-position entry of the shared
// maritime picture. Positions are fixed-point micro-degrees on the wire
// (degrees × 1e6), matching the contract prohibition on floating-point
// coordinates in exchanged artifacts.
type PictureTrack struct {
	TrackID         string `json:"track_id"`
	MMSI            string `json:"mmsi,omitempty"`
	Classification  string `json:"classification"`
	LatitudeMicros  int64  `json:"latitude_micros"`
	LongitudeMicros int64  `json:"longitude_micros"`
	ObservedAt      string `json:"observed_at"`
}

// TrackSource supplies the national vessel picture: fused-track latest
// positions with their classification labels. Implemented by an adapter over
// the ISR fusion engine (and, where configured, geo-service latest
// positions); the gateway never fabricates entries.
type TrackSource interface {
	// LatestPositions returns every fused track's most recent point whose
	// observation time falls inside [windowStart, windowEnd).
	LatestPositions(ctx context.Context, windowStart, windowEnd time.Time) ([]SourcedTrack, error)
}

// SourcedTrack is one fused track's latest in-window position.
type SourcedTrack struct {
	TrackID        string
	MMSI           string
	Classification isr.Classification
	Position       geo.Position
	ObservedAt     time.Time
}

// FilterPicture applies the zone polygon and the classification ceiling to
// the sourced tracks and returns the deterministic, sorted releasable set.
// The ceiling is enforced, not advisory: a track whose label ranks above the
// ceiling is excluded. Zero tracks is a truthful result, never padded.
func FilterPicture(sourced []SourcedTrack, zone geo.Zone, ceiling isr.Classification) ([]PictureTrack, error) {
	if _, err := isr.ParseClassification(string(ceiling)); err != nil {
		return nil, err
	}
	releasable := make([]PictureTrack, 0, len(sourced))
	for _, track := range sourced {
		if track.TrackID == "" {
			return nil, errors.New("sourced track has no identity")
		}
		if _, err := isr.ParseClassification(string(track.Classification)); err != nil {
			return nil, fmt.Errorf("sourced track %s: %w", track.TrackID, err)
		}
		if track.Classification.Rank() > ceiling.Rank() {
			continue // above the ceiling: excluded
		}
		if !zone.Contains(track.Position) {
			continue // outside the applied zone scope
		}
		releasable = append(releasable, PictureTrack{
			TrackID:         track.TrackID,
			MMSI:            track.MMSI,
			Classification:  string(track.Classification),
			LatitudeMicros:  int64(track.Position.Latitude * 1e6),
			LongitudeMicros: int64(track.Position.Longitude * 1e6),
			ObservedAt:      track.ObservedAt.UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(releasable, func(i, j int) bool { return releasable[i].TrackID < releasable[j].TrackID })
	return releasable, nil
}

// PictureArtifact is the canonical shared-picture artifact bound by the
// contribution digest.
type PictureArtifact struct {
	Zone                  string         `json:"zone"`
	WindowStart           string         `json:"window_start"`
	WindowEnd             string         `json:"window_end"`
	ClassificationCeiling string         `json:"classification_ceiling"`
	Tracks                []PictureTrack `json:"tracks"`
}

// BuildPictureArtifact filters and encodes the canonical artifact, returning
// the releasable track set, the canonical bytes and their digest.
func BuildPictureArtifact(zoneID string, zone geo.Zone, windowStart, windowEnd time.Time, ceiling isr.Classification, sourced []SourcedTrack) (PictureArtifact, []byte, string, error) {
	if !windowEnd.After(windowStart) {
		return PictureArtifact{}, nil, "", errors.New("track window must be a non-empty interval")
	}
	tracks, err := FilterPicture(sourced, zone, ceiling)
	if err != nil {
		return PictureArtifact{}, nil, "", err
	}
	artifact := PictureArtifact{
		Zone:                  zoneID,
		WindowStart:           windowStart.UTC().Format(time.RFC3339),
		WindowEnd:             windowEnd.UTC().Format(time.RFC3339),
		ClassificationCeiling: string(ceiling),
		Tracks:                tracks,
	}
	if artifact.Tracks == nil {
		artifact.Tracks = []PictureTrack{}
	}
	canonical, err := canonicalJSON(artifact)
	if err != nil {
		return PictureArtifact{}, nil, "", fmt.Errorf("encode picture artifact: %w", err)
	}
	return artifact, canonical, envelope.DigestSHA256(canonical), nil
}

// canonicalJSON renders one value as deterministic JSON (struct field order
// fixed, map keys sorted by encoding/json). Used for audit preimages and
// digested artifacts inside the gateway boundary.
func canonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}
