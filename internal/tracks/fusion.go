// Package tracks implements real-time multi-modal vessel-track fusion and
// behaviour anomaly detection for the Deep Blue Project ISR analytics
// workstream. Detections from every modality (AIS, SAR, RF, acoustic,
// optical) are associated into vessel tracks by MMSI where available and by
// a configurable spatial-temporal correlation window otherwise. Anomaly
// rules (dark vessel, speed outlier, rendezvous, restricted-zone loitering)
// are evaluated deterministically and fail closed; detection latency is
// instrumented against the p99 <= 5s KPI.
package tracks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/geo"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

// AnomalyKind enumerates the behaviour anomaly rules.
type AnomalyKind string

const (
	AnomalyDarkVessel   AnomalyKind = "dark-vessel"
	AnomalySpeedOutlier AnomalyKind = "speed-outlier"
	AnomalyRendezvous   AnomalyKind = "rendezvous"
	AnomalyLoitering    AnomalyKind = "loitering"
)

// Config carries the fusion and rule thresholds. Validate fails closed on
// any non-positive or inconsistent value so the engine never runs with
// operator-tunable silent defaults.
type Config struct {
	// CorrelationWindow is the maximum age gap between a track's last point
	// and a new detection for association without an MMSI.
	CorrelationWindow time.Duration
	// CorrelationRadiusMeters bounds the spatial leg of the correlation
	// window for non-MMSI association.
	CorrelationRadiusMeters float64
	// RendezvousRadiusMeters and RendezvousMinDuration define the rendezvous
	// rule: two distinct tracks within the radius for at least the duration.
	RendezvousRadiusMeters float64
	RendezvousMinDuration  time.Duration
	// LoiteringMinDuration is the minimum continuous presence inside a
	// restricted zone before a loitering anomaly fires.
	LoiteringMinDuration time.Duration
	// DarkVesselAISGap is the minimum AIS silence (while inside a coverage
	// zone) before a dark-vessel anomaly fires.
	DarkVesselAISGap time.Duration
	// BaselineMaxSpeedKnots is the behaviour-baseline speed ceiling; an
	// implied leg speed above it is a speed-outlier anomaly.
	BaselineMaxSpeedKnots float64
}

// DefaultConfig returns the governance-reviewed starting thresholds.
func DefaultConfig() Config {
	return Config{
		CorrelationWindow:       10 * time.Minute,
		CorrelationRadiusMeters: 2_000,
		RendezvousRadiusMeters:  500,
		RendezvousMinDuration:   10 * time.Minute,
		LoiteringMinDuration:    30 * time.Minute,
		DarkVesselAISGap:        30 * time.Minute,
		BaselineMaxSpeedKnots:   45,
	}
}

// Validate rejects non-positive or inconsistent thresholds fail-closed.
func (config Config) Validate() error {
	if config.CorrelationWindow <= 0 || config.CorrelationWindow > 24*time.Hour {
		return errors.New("correlation window must be within (0, 24h]")
	}
	if !positiveFinite(config.CorrelationRadiusMeters) || config.CorrelationRadiusMeters > 50_000 {
		return errors.New("correlation radius must be within (0, 50000] meters")
	}
	if !positiveFinite(config.RendezvousRadiusMeters) || config.RendezvousRadiusMeters > 10_000 {
		return errors.New("rendezvous radius must be within (0, 10000] meters")
	}
	if config.RendezvousMinDuration <= 0 || config.RendezvousMinDuration > 24*time.Hour {
		return errors.New("rendezvous minimum duration must be within (0, 24h]")
	}
	if config.LoiteringMinDuration <= 0 || config.LoiteringMinDuration > 72*time.Hour {
		return errors.New("loitering minimum duration must be within (0, 72h]")
	}
	if config.DarkVesselAISGap <= 0 || config.DarkVesselAISGap > 7*24*time.Hour {
		return errors.New("dark-vessel AIS gap must be within (0, 168h]")
	}
	if !positiveFinite(config.BaselineMaxSpeedKnots) || config.BaselineMaxSpeedKnots > 102.2 {
		return errors.New("baseline max speed must be within (0, 102.2] knots")
	}
	return nil
}

func positiveFinite(value float64) bool {
	return value > 0 && value == value && value < 1e15
}

// TrackPoint is one detection associated into a track.
type TrackPoint struct {
	DetectionRef string       `json:"detection_ref"`
	Modality     isr.Modality `json:"modality"`
	ObservedAt   time.Time    `json:"observed_at"`
	Position     geo.Position `json:"position"`
	SpeedKnots   float64      `json:"speed_knots"`
	HeadingDeg   float64      `json:"heading_deg"`
}

// Track is one fused vessel track. Classification is always the maximum over
// associated detections; MMSI is empty for fused-only tracks.
type Track struct {
	TrackID        string             `json:"track_id"`
	MMSI           string             `json:"mmsi,omitempty"`
	Classification isr.Classification `json:"classification"`
	Points         []TrackPoint       `json:"points"`

	lastAISAt     time.Time
	zoneEnter     map[string]time.Time
	loiterAlerted map[string]bool
	nearSince     map[string]time.Time
	rendezAlerted map[string]bool
	darkAlerted   bool
}

// Last returns the most recent point; ok is false for an empty track.
func (track *Track) Last() (TrackPoint, bool) {
	if len(track.Points) == 0 {
		return TrackPoint{}, false
	}
	return track.Points[len(track.Points)-1], true
}

// Anomaly is one behaviour-anomaly finding. Classification is the maximum of
// the involved tracks; CorrelationRefs carry cross-workstream anomaly
// identifiers for security-operations' cross-workstream-correlation rule.
type Anomaly struct {
	AnomalyID       string             `json:"anomaly_id"`
	Kind            AnomalyKind        `json:"kind"`
	TrackIDs        []string           `json:"track_ids"`
	ZoneID          string             `json:"zone_id,omitempty"`
	Classification  isr.Classification `json:"classification"`
	DetectedAt      time.Time          `json:"detected_at"`
	Detail          string             `json:"detail"`
	CorrelationRefs []string           `json:"correlation_refs,omitempty"`
}

// LatencyRecorder receives anomaly-detection latency observations (seconds
// between the triggering observation and emission) for the p99 <= 5s KPI.
type LatencyRecorder interface {
	RecordDetectionLatency(ctx context.Context, kind AnomalyKind, seconds float64)
}

type noopLatency struct{}

func (noopLatency) RecordDetectionLatency(context.Context, AnomalyKind, float64) {}

// Engine associates detections into tracks and evaluates anomaly rules. It
// is deterministic given the injected clock and ID generator.
type Engine struct {
	config   Config
	zones    []geo.Zone
	recorder LatencyRecorder
	now      func() time.Time
	newID    func() string

	mu     sync.Mutex
	tracks map[string]*Track
	byMMSI map[string]string
}

// NewEngine validates the configuration fail-closed. nil recorder/clock/id
// arguments select safe defaults.
func NewEngine(config Config, zones []geo.Zone, recorder LatencyRecorder, now func() time.Time, newID func() string) (*Engine, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	for _, zone := range zones {
		if _, err := geo.NewZone(zone.ZoneID, zone.ZoneKind, zone.Vertices); err != nil {
			return nil, fmt.Errorf("zone %q: %w", zone.ZoneID, err)
		}
	}
	if recorder == nil {
		recorder = noopLatency{}
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	engine := &Engine{
		config: config, zones: append([]geo.Zone(nil), zones...), recorder: recorder,
		now: now, newID: newID, tracks: make(map[string]*Track), byMMSI: make(map[string]string),
	}
	if engine.newID == nil {
		engine.newID = engine.defaultTrackID
	}
	return engine, nil
}

// defaultTrackID allocates a collision-free fused-track identity. Track IDs
// are UUID-based (not a restartable sequence) so a post-restart engine can
// never mint an ID already persisted in maritime_vessel_tracks; replayed
// associations keep their original persisted identity via Replay.
func (engine *Engine) defaultTrackID() string {
	return "fused-track-" + uuid.NewString()
}

// Ingest associates one validated detection into a track, updates rule state
// and returns the anomalies emitted by this detection (possibly none). The
// detection must already carry a verified source signature and a valid
// classification label; Ingest re-validates fail-closed.
func (engine *Engine) Ingest(ctx context.Context, detection isr.Detection) (string, []Anomaly, error) {
	if err := detection.Validate(); err != nil {
		return "", nil, err
	}
	if !detection.HasPosition {
		return "", nil, errors.New("detections without a position cannot enter track fusion")
	}
	position, err := geo.NewPosition(detection.Latitude, detection.Longitude)
	if err != nil {
		return "", nil, err
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	track := engine.associate(detection, position)
	point := engine.absorbPointLocked(track, detection, position)
	anomalies := engine.evaluateLocked(ctx, track, point, detection)
	return track.TrackID, anomalies, nil
}

// Replay reinstates one persisted track association
// (maritime_track_associations joined to its retained detection payload)
// into engine state after a restart. The persisted track identity is pinned:
// replay never mints a new track ID, so maritime_vessel_tracks rows and the
// in-memory view keep the same identity and GET /v1/isr/tracks serves the
// pre-restart state immediately. Rule bookkeeping (zone entry, pair
// proximity, last-AIS) is restored without re-emitting anomalies — the
// detections were already alerted and persisted at ingest time. Alert flags
// stay reset, so a still-active anomaly re-fires once after restart
// (fail-safe) rather than being silently lost.
func (engine *Engine) Replay(trackID string, detection isr.Detection) error {
	if err := detection.Validate(); err != nil {
		return err
	}
	if !detection.HasPosition {
		return errors.New("replayed association has no position")
	}
	if strings.TrimSpace(trackID) == "" || len(trackID) > 128 {
		return errors.New("replay requires the persisted track identity")
	}
	position, err := geo.NewPosition(detection.Latitude, detection.Longitude)
	if err != nil {
		return err
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	track, ok := engine.tracks[trackID]
	if !ok {
		track = newTrack(trackID, detection.Classification)
		engine.tracks[trackID] = track
	}
	point := engine.absorbPointLocked(track, detection, position)
	engine.restoreRuleStateLocked(track, point)
	return nil
}

// absorbPointLocked appends the detection's point to the track and updates
// the MMSI binding, classification maximum and last-AIS marker.
func (engine *Engine) absorbPointLocked(track *Track, detection isr.Detection, position geo.Position) TrackPoint {
	point := TrackPoint{
		DetectionRef: detection.SourceID + ":" + detection.SourceEventID,
		Modality:     detection.Modality,
		ObservedAt:   detection.ObservedAt,
		Position:     position,
	}
	if detection.AIS != nil {
		point.SpeedKnots = detection.AIS.SpeedKnots
		point.HeadingDeg = detection.AIS.HeadingDeg
		track.lastAISAt = detection.ObservedAt
		if track.MMSI == "" {
			track.MMSI = detection.AIS.MMSI
			engine.byMMSI[detection.AIS.MMSI] = track.TrackID
		}
	}
	if detection.MMSI != "" && track.MMSI == "" {
		track.MMSI = detection.MMSI
		engine.byMMSI[detection.MMSI] = track.TrackID
	}
	track.Points = append(track.Points, point)
	track.Classification = isr.MaxClassification(track.Classification, detection.Classification)
	if len(track.Points) > 4096 {
		track.Points = append([]TrackPoint(nil), track.Points[len(track.Points)-4096:]...)
	}
	return point
}

// restoreRuleStateLocked replays zone-entry and pair-proximity bookkeeping
// for one historical point without emitting anomalies. It mirrors the state
// transitions of evaluateLocked minus the alert emission.
func (engine *Engine) restoreRuleStateLocked(track *Track, point TrackPoint) {
	insideRestricted := make(map[string]bool)
	for _, zone := range engine.zones {
		if zone.ZoneKind == geo.ZoneKindRestricted && zone.Contains(point.Position) {
			insideRestricted[zone.ZoneID] = true
			if _, seen := track.zoneEnter[zone.ZoneID]; !seen {
				track.zoneEnter[zone.ZoneID] = point.ObservedAt
			}
		}
	}
	for zoneID := range track.zoneEnter {
		if !insideRestricted[zoneID] {
			delete(track.zoneEnter, zoneID)
		}
	}
	for _, other := range engine.tracks {
		if other.TrackID == track.TrackID {
			continue
		}
		last, ok := other.Last()
		if !ok {
			continue
		}
		separated := func() {
			delete(track.nearSince, other.TrackID)
			delete(other.nearSince, track.TrackID)
		}
		if point.ObservedAt.Sub(last.ObservedAt) > engine.config.RendezvousMinDuration || last.ObservedAt.Sub(point.ObservedAt) > engine.config.RendezvousMinDuration {
			separated()
			continue
		}
		if geo.DistanceMeters(last.Position, point.Position) > engine.config.RendezvousRadiusMeters {
			separated()
			continue
		}
		since, seen := track.nearSince[other.TrackID]
		if otherSince, ok := other.nearSince[track.TrackID]; ok && (!seen || otherSince.Before(since)) {
			since, seen = otherSince, true
		}
		if !seen {
			since = point.ObservedAt
			if last.ObservedAt.Before(since) {
				since = last.ObservedAt
			}
		}
		track.nearSince[other.TrackID] = since
		other.nearSince[track.TrackID] = since
	}
}

// newTrack builds an empty track with initialized rule state.
func newTrack(trackID string, classification isr.Classification) *Track {
	return &Track{
		TrackID: trackID, Classification: classification,
		zoneEnter: make(map[string]time.Time), loiterAlerted: make(map[string]bool),
		nearSince: make(map[string]time.Time), rendezAlerted: make(map[string]bool),
	}
}

// associate returns the track for the detection: the MMSI-bound track when
// known, else the nearest track inside the spatial-temporal correlation
// window, else a new fused track.
func (engine *Engine) associate(detection isr.Detection, position geo.Position) *Track {
	if detection.MMSI != "" {
		if trackID, ok := engine.byMMSI[detection.MMSI]; ok {
			return engine.tracks[trackID]
		}
	}
	var best *Track
	bestDistance := engine.config.CorrelationRadiusMeters
	for _, candidate := range engine.tracks {
		// Fail-closed identity discipline: an MMSI-bearing detection must
		// never spatially associate into a track carrying a different MMSI.
		if detection.MMSI != "" && candidate.MMSI != "" && candidate.MMSI != detection.MMSI {
			continue
		}
		last, ok := candidate.Last()
		if !ok {
			continue
		}
		gap := detection.ObservedAt.Sub(last.ObservedAt)
		if gap < 0 {
			gap = -gap
		}
		if gap > engine.config.CorrelationWindow {
			continue
		}
		distance := geo.DistanceMeters(last.Position, position)
		if distance <= bestDistance {
			best, bestDistance = candidate, distance
		}
	}
	if best != nil {
		return best
	}
	track := newTrack(engine.newID(), detection.Classification)
	engine.tracks[track.TrackID] = track
	if detection.MMSI != "" {
		track.MMSI = detection.MMSI
		engine.byMMSI[detection.MMSI] = track.TrackID
	}
	return track
}

// evaluateLocked runs the ingest-time rules for the new point.
func (engine *Engine) evaluateLocked(ctx context.Context, track *Track, point TrackPoint, detection isr.Detection) []Anomaly {
	anomalies := make([]Anomaly, 0, 2)
	now := engine.now()
	emit := func(kind AnomalyKind, trackIDs []string, zoneID string, detail string) {
		anomaly := Anomaly{
			AnomalyID: fmt.Sprintf("anomaly-%s-%s-%d", kind, track.TrackID, now.UnixNano()),
			Kind:      kind, TrackIDs: trackIDs, ZoneID: zoneID,
			Classification: track.Classification, DetectedAt: now, Detail: detail,
			CorrelationRefs: append([]string(nil), detection.CorrelationRefs...),
		}
		anomalies = append(anomalies, anomaly)
		latency := now.Sub(point.ObservedAt).Seconds()
		if latency < 0 {
			latency = 0
		}
		engine.recorder.RecordDetectionLatency(ctx, kind, latency)
	}
	// Speed outlier vs the behaviour baseline: implied leg speed between the
	// previous and the new point above the baseline ceiling.
	if len(track.Points) >= 2 {
		previous := track.Points[len(track.Points)-2]
		seconds := point.ObservedAt.Sub(previous.ObservedAt).Seconds()
		if seconds > 0 {
			distanceM := geo.DistanceMeters(previous.Position, point.Position)
			knots := distanceM / seconds * 1.94384
			if knots > engine.config.BaselineMaxSpeedKnots {
				emit(AnomalySpeedOutlier, []string{track.TrackID}, "",
					fmt.Sprintf("implied leg speed %.1f kn exceeds baseline %.1f kn", knots, engine.config.BaselineMaxSpeedKnots))
			}
		}
	}
	// Loitering: continuous presence inside a restricted zone.
	insideRestricted := make(map[string]bool)
	for _, zone := range engine.zones {
		if !zone.Contains(point.Position) {
			continue
		}
		if zone.ZoneKind == geo.ZoneKindRestricted {
			insideRestricted[zone.ZoneID] = true
			if _, seen := track.zoneEnter[zone.ZoneID]; !seen {
				track.zoneEnter[zone.ZoneID] = point.ObservedAt
			}
			if !track.loiterAlerted[zone.ZoneID] && point.ObservedAt.Sub(track.zoneEnter[zone.ZoneID]) >= engine.config.LoiteringMinDuration {
				track.loiterAlerted[zone.ZoneID] = true
				emit(AnomalyLoitering, []string{track.TrackID}, zone.ZoneID,
					fmt.Sprintf("track inside restricted zone %s for >= %s", zone.ZoneID, engine.config.LoiteringMinDuration))
			}
		}
	}
	for zoneID := range track.zoneEnter {
		if !insideRestricted[zoneID] {
			delete(track.zoneEnter, zoneID)
		}
	}
	// Rendezvous: two distinct tracks within the radius for the duration.
	// Pair proximity state is kept symmetrically on both tracks so either
	// track's next report evaluates the true proximity start.
	for _, other := range engine.tracks {
		if other.TrackID == track.TrackID {
			continue
		}
		last, ok := other.Last()
		if !ok {
			continue
		}
		separated := func() {
			delete(track.nearSince, other.TrackID)
			delete(other.nearSince, track.TrackID)
		}
		if point.ObservedAt.Sub(last.ObservedAt) > engine.config.RendezvousMinDuration || last.ObservedAt.Sub(point.ObservedAt) > engine.config.RendezvousMinDuration {
			separated()
			continue
		}
		if geo.DistanceMeters(last.Position, point.Position) > engine.config.RendezvousRadiusMeters {
			separated()
			continue
		}
		since, seen := track.nearSince[other.TrackID]
		if otherSince, ok := other.nearSince[track.TrackID]; ok && (!seen || otherSince.Before(since)) {
			since, seen = otherSince, true
		}
		if !seen {
			since = point.ObservedAt
			if last.ObservedAt.Before(since) {
				since = last.ObservedAt
			}
		}
		track.nearSince[other.TrackID] = since
		other.nearSince[track.TrackID] = since
		if !track.rendezAlerted[other.TrackID] && point.ObservedAt.Sub(since) >= engine.config.RendezvousMinDuration {
			track.rendezAlerted[other.TrackID] = true
			other.rendezAlerted[track.TrackID] = true
			classification := isr.MaxClassification(track.Classification, other.Classification)
			track.Classification = classification
			emit(AnomalyRendezvous, []string{track.TrackID, other.TrackID}, "",
				fmt.Sprintf("tracks within %.0f m for >= %s", engine.config.RendezvousRadiusMeters, engine.config.RendezvousMinDuration))
			anomalies[len(anomalies)-1].Classification = classification
		}
	}
	return anomalies
}

// ScanDarkVessels evaluates the dark-vessel rule at scan time: a track with
// a known MMSI whose most recent point lies inside a coverage (EEZ or
// restricted) zone and whose last AIS report is older than the configured
// gap. Returns newly raised anomalies; each track alerts once.
func (engine *Engine) ScanDarkVessels(ctx context.Context) []Anomaly {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	now := engine.now()
	anomalies := make([]Anomaly, 0)
	for _, track := range engine.tracks {
		if track.darkAlerted || track.MMSI == "" || track.lastAISAt.IsZero() {
			continue
		}
		last, ok := track.Last()
		if !ok || now.Sub(track.lastAISAt) < engine.config.DarkVesselAISGap {
			continue
		}
		inside := geo.ZonesContaining(last.Position, engine.zones)
		if len(inside) == 0 {
			continue
		}
		track.darkAlerted = true
		anomaly := Anomaly{
			AnomalyID: fmt.Sprintf("anomaly-%s-%s-%d", AnomalyDarkVessel, track.TrackID, now.UnixNano()),
			Kind:      AnomalyDarkVessel, TrackIDs: []string{track.TrackID}, ZoneID: inside[0].ZoneID,
			Classification: track.Classification, DetectedAt: now,
			Detail: fmt.Sprintf("AIS silent for >= %s inside zone %s", engine.config.DarkVesselAISGap, inside[0].ZoneID),
		}
		anomalies = append(anomalies, anomaly)
		latency := now.Sub(last.ObservedAt).Seconds()
		if latency < 0 {
			latency = 0
		}
		engine.recorder.RecordDetectionLatency(ctx, AnomalyDarkVessel, latency)
	}
	return anomalies
}

// Track returns a defensive copy of one fused track.
func (engine *Engine) Track(trackID string) (Track, bool) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	track, ok := engine.tracks[trackID]
	if !ok {
		return Track{}, false
	}
	copied := *track
	copied.Points = append([]TrackPoint(nil), track.Points...)
	return copied, true
}

// Tracks lists fused track snapshots (defensive copies). Classified-data
// discipline: callers must enforce clearance before returning any track to a
// principal.
func (engine *Engine) Tracks() []Track {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	snapshots := make([]Track, 0, len(engine.tracks))
	for _, track := range engine.tracks {
		copied := *track
		copied.Points = append([]TrackPoint(nil), track.Points...)
		snapshots = append(snapshots, copied)
	}
	return snapshots
}

// FusionIdentity derives the track identity string persisted with an
// association audit record: the MMSI when available, else the fused ID.
func FusionIdentity(track Track) string {
	if strings.TrimSpace(track.MMSI) != "" {
		return "mmsi:" + track.MMSI
	}
	return track.TrackID
}
