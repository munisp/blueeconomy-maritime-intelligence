package server

import (
	"context"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/geo"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/sar"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/tracks"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/yaounde"
)

// fusionTrackSource adapts the ISR fusion engine to the Phase-8 track
// sources: each fused track's most recent in-window point with its
// classification label. Nothing is fabricated: only tracks the engine
// actually holds are returned.
type fusionTrackSource struct{ engine *tracks.Engine }

func newFusionTrackSource(engine *tracks.Engine) *fusionTrackSource {
	return &fusionTrackSource{engine: engine}
}

func (source *fusionTrackSource) latest(_ context.Context, windowStart, windowEnd time.Time) []sar.SourcedTrack {
	if source.engine == nil {
		return nil
	}
	snapshot := source.engine.Tracks()
	result := make([]sar.SourcedTrack, 0, len(snapshot))
	for _, track := range snapshot {
		var latest *tracks.TrackPoint
		for index := range track.Points {
			point := track.Points[index]
			if !point.ObservedAt.Before(windowStart) && point.ObservedAt.Before(windowEnd) {
				if latest == nil || point.ObservedAt.After(latest.ObservedAt) {
					latest = &track.Points[index]
				}
			}
		}
		if latest == nil {
			continue // no in-window position: excluded, never padded
		}
		result = append(result, sar.SourcedTrack{
			TrackID: track.TrackID, MMSI: track.MMSI, Classification: isr.Classification(track.Classification),
			Position:   geo.Position{Latitude: latest.Position.Latitude, Longitude: latest.Position.Longitude},
			ObservedAt: latest.ObservedAt,
		})
	}
	return result
}

// sarTrackSource satisfies sar.TrackSource over the fusion engine.
type sarTrackSource struct{ inner *fusionTrackSource }

func (source sarTrackSource) LatestPositions(ctx context.Context, windowStart, windowEnd time.Time) ([]sar.SourcedTrack, error) {
	return source.inner.latest(ctx, windowStart, windowEnd), nil
}

// yaoundeTrackSource satisfies yaounde.TrackSource over the fusion engine.
type yaoundeTrackSource struct{ inner *fusionTrackSource }

func (source yaoundeTrackSource) LatestPositions(ctx context.Context, windowStart, windowEnd time.Time) ([]yaounde.SourcedTrack, error) {
	latest := source.inner.latest(ctx, windowStart, windowEnd)
	tracks := make([]yaounde.SourcedTrack, len(latest))
	for index, track := range latest {
		tracks[index] = yaounde.SourcedTrack{
			TrackID: track.TrackID, MMSI: track.MMSI, Classification: track.Classification,
			Position: track.Position, ObservedAt: track.ObservedAt,
		}
	}
	return tracks, nil
}

// NewSARTrackSource adapts the fusion engine for the SAR VOO lookup.
func NewSARTrackSource(engine *tracks.Engine) sar.TrackSource {
	return sarTrackSource{inner: newFusionTrackSource(engine)}
}

// NewYaoundeTrackSource adapts the fusion engine for the Yaounde picture.
func NewYaoundeTrackSource(engine *tracks.Engine) yaounde.TrackSource {
	return yaoundeTrackSource{inner: newFusionTrackSource(engine)}
}
