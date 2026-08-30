package sar

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/geo"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

// TrackSource supplies live fused-track latest positions with their
// classification labels (the ISR fusion engine adapter in the server).
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

// VOOEntry is one vessel-of-opportunity candidate on the wire (fixed-point
// micro-degree positions; distance in nautical miles).
type VOOEntry struct {
	TrackID         string  `json:"track_id"`
	MMSI            string  `json:"mmsi,omitempty"`
	Classification  string  `json:"classification"`
	DistanceNM      float64 `json:"distance_nm"`
	LatitudeMicros  int64   `json:"latitude_micros"`
	LongitudeMicros int64   `json:"longitude_micros"`
	ObservedAt      string  `json:"observed_at"`
}

// haversineNM returns the great-circle distance in nautical miles.
func haversineNM(a, b geo.Position) float64 {
	const earthRadiusNM = 3440.065
	toRadians := func(degrees float64) float64 { return degrees * math.Pi / 180 }
	latA, latB := toRadians(a.Latitude), toRadians(b.Latitude)
	deltaLat := toRadians(b.Latitude - a.Latitude)
	deltaLon := toRadians(b.Longitude - a.Longitude)
	h := math.Sin(deltaLat/2)*math.Sin(deltaLat/2) +
		math.Cos(latA)*math.Cos(latB)*math.Sin(deltaLon/2)*math.Sin(deltaLon/2)
	return 2 * earthRadiusNM * math.Asin(math.Sqrt(h))
}

// ListVOO returns the vessels of opportunity within radiusNM of the case
// datum (or last-known position when no datum is set), clearance-capped at
// the requesting principal's ceiling. The result is truthful: only tracks
// that exist, are in-window and within radius are returned; nothing is
// fabricated. Sorted by distance.
func ListVOO(ctx context.Context, source TrackSource, sarCase Case, radiusNM float64, clearance isr.Classification, window time.Duration, now time.Time) ([]VOOEntry, error) {
	if source == nil {
		return nil, errors.New("track source is not configured (fail-closed)")
	}
	if radiusNM <= 0 || radiusNM > 500 {
		return nil, fmt.Errorf("%w: radius must be within (0, 500] nautical miles", ErrValidation)
	}
	if _, err := isr.ParseClassification(string(clearance)); err != nil {
		return nil, err
	}
	var center geo.Position
	switch {
	case sarCase.DatumLatitude != nil:
		center = geo.Position{Latitude: *sarCase.DatumLatitude, Longitude: *sarCase.DatumLongitude}
	case sarCase.LastKnownLatitude != nil:
		center = geo.Position{Latitude: *sarCase.LastKnownLatitude, Longitude: *sarCase.LastKnownLongitude}
	default:
		return nil, fmt.Errorf("%w: case has neither datum nor last-known position; VOO lookup is impossible", ErrValidation)
	}
	if window <= 0 {
		window = 2 * time.Hour
	}
	sourced, err := source.LatestPositions(ctx, now.Add(-window), now)
	if err != nil {
		return nil, fmt.Errorf("source track positions: %w", err)
	}
	entries := make([]VOOEntry, 0, len(sourced))
	for _, track := range sourced {
		if _, err := isr.ParseClassification(string(track.Classification)); err != nil {
			return nil, fmt.Errorf("sourced track %s: %w", track.TrackID, err)
		}
		if track.Classification.Rank() > clearance.Rank() {
			continue // above the principal's clearance: excluded
		}
		distance := haversineNM(center, track.Position)
		if distance > radiusNM {
			continue
		}
		entries = append(entries, VOOEntry{
			TrackID:         track.TrackID,
			MMSI:            track.MMSI,
			Classification:  string(track.Classification),
			DistanceNM:      math.Round(distance*100) / 100,
			LatitudeMicros:  micros(track.Position.Latitude),
			LongitudeMicros: micros(track.Position.Longitude),
			ObservedAt:      track.ObservedAt.UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].DistanceNM != entries[j].DistanceNM {
			return entries[i].DistanceNM < entries[j].DistanceNM
		}
		return entries[i].TrackID < entries[j].TrackID
	})
	return entries, nil
}
