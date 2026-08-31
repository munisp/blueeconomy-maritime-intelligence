package tracks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/geo"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

type recordingLatency struct{ observations []float64 }

func (recorder *recordingLatency) RecordDetectionLatency(_ context.Context, _ AnomalyKind, seconds float64) {
	recorder.observations = append(recorder.observations, seconds)
}

func testZones(t *testing.T) []geo.Zone {
	t.Helper()
	restricted, err := geo.NewZone("restricted-harbour", geo.ZoneKindRestricted, []geo.Position{
		{Latitude: 6.40, Longitude: 3.30}, {Latitude: 6.40, Longitude: 3.50},
		{Latitude: 6.50, Longitude: 3.50}, {Latitude: 6.50, Longitude: 3.30},
	})
	if err != nil {
		t.Fatal(err)
	}
	eez, err := geo.NewZone("nigeria-eez", geo.ZoneKindEEZ, []geo.Position{
		{Latitude: 4.0, Longitude: 2.0}, {Latitude: 4.0, Longitude: 10.0},
		{Latitude: 8.0, Longitude: 10.0}, {Latitude: 8.0, Longitude: 2.0},
	})
	if err != nil {
		t.Fatal(err)
	}
	return []geo.Zone{restricted, eez}
}

func testConfig() Config {
	return Config{
		CorrelationWindow:       10 * time.Minute,
		CorrelationRadiusMeters: 2_000,
		RendezvousRadiusMeters:  300,
		RendezvousMinDuration:   5 * time.Minute,
		LoiteringMinDuration:    20 * time.Minute,
		DarkVesselAISGap:        30 * time.Minute,
		BaselineMaxSpeedKnots:   40,
	}
}

func aisDetection(mmsi string, at time.Time, lat, lon float64) isr.Detection {
	return isr.Detection{
		EventID: "evt-" + mmsi + "-" + at.Format("150405.000"), SourceID: "ais-feed", SourceEventID: "src-" + at.Format("150405.000000"),
		Modality: isr.ModalityAIS, Classification: isr.ClassificationUnclassified,
		ObservedAt: at, HasPosition: true, Latitude: lat, Longitude: lon, MMSI: mmsi,
		AIS: &isr.AISPayload{MMSI: mmsi, SpeedKnots: 10, HeadingDeg: 90},
	}
}

func sarDetection(id string, at time.Time, lat, lon float64) isr.Detection {
	return isr.Detection{
		EventID: "evt-" + id, SourceID: "sar-feed", SourceEventID: "src-" + id,
		Modality: isr.ModalitySAR, Classification: isr.ClassificationConfidential,
		ObservedAt: at, HasPosition: true, Latitude: lat, Longitude: lon,
		SAR: &isr.SARPayload{SceneRef: "scene-" + id, Confidence: 0.9},
	}
}

func TestConfigValidationFailsClosed(t *testing.T) {
	if err := testConfig().Validate(); err != nil {
		t.Fatal(err)
	}
	invalid := testConfig()
	invalid.CorrelationWindow = 0
	if err := invalid.Validate(); err == nil {
		t.Fatal("zero correlation window accepted")
	}
	invalid = testConfig()
	invalid.BaselineMaxSpeedKnots = 200
	if err := invalid.Validate(); err == nil {
		t.Fatal("baseline above AIS encoding ceiling accepted")
	}
}

func TestMMSIAssociationAndFusedTrackID(t *testing.T) {
	engine, err := NewEngine(testConfig(), testZones(t), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	trackID, _, err := engine.Ingest(context.Background(), aisDetection("636019999", base, 6.44, 3.38))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := engine.Ingest(context.Background(), aisDetection("636019999", base.Add(time.Minute), 6.4405, 3.3805))
	if err != nil {
		t.Fatal(err)
	}
	if trackID != second {
		t.Fatal("same MMSI must associate into one track")
	}
	// A SAR detection without MMSI, far outside the correlation radius, seeds
	// a new fused track.
	fused, _, err := engine.Ingest(context.Background(), sarDetection("sar-1", base.Add(2*time.Minute), 5.0, 5.0))
	if err != nil {
		t.Fatal(err)
	}
	if fused == trackID || !strings.HasPrefix(fused, "fused-track-") {
		t.Fatalf("expected a new fused-track ID, got %q", fused)
	}
	// A SAR detection inside the correlation window joins the nearest track.
	near, _, err := engine.Ingest(context.Background(), sarDetection("sar-2", base.Add(3*time.Minute), 6.4408, 3.3808))
	if err != nil {
		t.Fatal(err)
	}
	if near != trackID {
		t.Fatal("spatial-temporal correlation failed to associate")
	}
}

func TestSpeedOutlierBoundary(t *testing.T) {
	config := testConfig()
	config.BaselineMaxSpeedKnots = 40
	engine, err := NewEngine(config, testZones(t), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	if _, _, err := engine.Ingest(context.Background(), aisDetection("636020001", base, 6.44, 3.38)); err != nil {
		t.Fatal(err)
	}
	// Exactly 40 knots over one hour: 40 nm = 74080 m => ~0.6672 degrees lat.
	// Use a one-hour leg of exactly 40*1852 m northward.
	legMeters := 40.0 * 1852.0
	deltaLat := legMeters / 111_320.0
	_, anomalies, err := engine.Ingest(context.Background(), aisDetection("636020001", base.Add(time.Hour), 6.44+deltaLat, 3.38))
	if err != nil {
		t.Fatal(err)
	}
	for _, anomaly := range anomalies {
		if anomaly.Kind == AnomalySpeedOutlier {
			t.Fatalf("exactly-at-baseline speed must not alert: %+v", anomaly)
		}
	}
	// Just above the baseline must alert.
	if _, _, err := engine.Ingest(context.Background(), aisDetection("636020002", base, 5.0, 5.0)); err != nil {
		t.Fatal(err)
	}
	_, anomalies, err = engine.Ingest(context.Background(), aisDetection("636020002", base.Add(time.Hour), 5.0+2*deltaLat, 5.0))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, anomaly := range anomalies {
		if anomaly.Kind == AnomalySpeedOutlier {
			found = true
		}
	}
	if !found {
		t.Fatal("speed above baseline did not alert")
	}
}

func TestRendezvousBoundary(t *testing.T) {
	config := testConfig()
	config.RendezvousRadiusMeters = 300
	config.RendezvousMinDuration = 5 * time.Minute
	engine, err := NewEngine(config, testZones(t), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	// Two tracks ~100 m apart (0.0009 deg lat), inside the radius.
	trackA := "636030001"
	trackB := "636030002"
	if _, _, err := engine.Ingest(context.Background(), aisDetection(trackA, base, 6.44, 3.38)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := engine.Ingest(context.Background(), aisDetection(trackB, base, 6.4409, 3.38)); err != nil {
		t.Fatal(err)
	}
	// At 4m59s of proximity: no alert.
	_, anomalies, err := engine.Ingest(context.Background(), aisDetection(trackA, base.Add(4*time.Minute+59*time.Second), 6.44, 3.38))
	if err != nil {
		t.Fatal(err)
	}
	for _, anomaly := range anomalies {
		if anomaly.Kind == AnomalyRendezvous {
			t.Fatal("rendezvous alerted before the minimum duration")
		}
	}
	if _, _, err := engine.Ingest(context.Background(), aisDetection(trackB, base.Add(4*time.Minute+59*time.Second), 6.4409, 3.38)); err != nil {
		t.Fatal(err)
	}
	// At 5 minutes of continuous proximity: alert on both tracks.
	_, anomalies, err = engine.Ingest(context.Background(), aisDetection(trackA, base.Add(5*time.Minute), 6.44, 3.38))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, anomaly := range anomalies {
		if anomaly.Kind == AnomalyRendezvous {
			found = true
			if len(anomaly.TrackIDs) != 2 {
				t.Fatal("rendezvous must bind both tracks")
			}
		}
	}
	if !found {
		t.Fatal("rendezvous at the minimum duration did not alert")
	}
}

func TestLoiteringBoundary(t *testing.T) {
	config := testConfig()
	config.LoiteringMinDuration = 20 * time.Minute
	engine, err := NewEngine(config, testZones(t), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	mmsi := "636040001"
	if _, _, err := engine.Ingest(context.Background(), aisDetection(mmsi, base, 6.45, 3.40)); err != nil {
		t.Fatal(err)
	}
	// 19m59s inside the restricted zone: no alert.
	_, anomalies, err := engine.Ingest(context.Background(), aisDetection(mmsi, base.Add(19*time.Minute+59*time.Second), 6.4505, 3.4005))
	if err != nil {
		t.Fatal(err)
	}
	for _, anomaly := range anomalies {
		if anomaly.Kind == AnomalyLoitering {
			t.Fatal("loitering alerted before the minimum duration")
		}
	}
	// 20 minutes inside: alert, and only once.
	_, anomalies, err = engine.Ingest(context.Background(), aisDetection(mmsi, base.Add(20*time.Minute), 6.4502, 3.4002))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, anomaly := range anomalies {
		if anomaly.Kind == AnomalyLoitering && anomaly.ZoneID == "restricted-harbour" {
			found = true
		}
	}
	if !found {
		t.Fatal("loitering at the minimum duration did not alert")
	}
	_, anomalies, err = engine.Ingest(context.Background(), aisDetection(mmsi, base.Add(25*time.Minute), 6.4503, 3.4003))
	if err != nil {
		t.Fatal(err)
	}
	for _, anomaly := range anomalies {
		if anomaly.Kind == AnomalyLoitering {
			t.Fatal("loitering alerted twice for the same zone entry")
		}
	}
	// Leaving the zone resets the entry clock.
	if _, _, err := engine.Ingest(context.Background(), aisDetection(mmsi, base.Add(30*time.Minute), 6.60, 3.60)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := engine.Ingest(context.Background(), aisDetection(mmsi, base.Add(31*time.Minute), 6.45, 3.40)); err != nil {
		t.Fatal(err)
	}
	_, anomalies, err = engine.Ingest(context.Background(), aisDetection(mmsi, base.Add(31*time.Minute+19*time.Minute), 6.4501, 3.4001))
	if err != nil {
		t.Fatal(err)
	}
	for _, anomaly := range anomalies {
		if anomaly.Kind == AnomalyLoitering {
			t.Fatal("loitering duration must restart after leaving the zone")
		}
	}
}

func TestDarkVesselScan(t *testing.T) {
	config := testConfig()
	config.DarkVesselAISGap = 30 * time.Minute
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	clock := &now
	engine, err := NewEngine(config, testZones(t), nil, func() time.Time { return *clock }, nil)
	if err != nil {
		t.Fatal(err)
	}
	// AIS report inside the EEZ, then silence.
	if _, _, err := engine.Ingest(context.Background(), aisDetection("636050001", now, 6.0, 4.0)); err != nil {
		t.Fatal(err)
	}
	if anomalies := engine.ScanDarkVessels(context.Background()); len(anomalies) != 0 {
		t.Fatal("dark-vessel scan alerted before the AIS gap elapsed")
	}
	*clock = now.Add(29 * time.Minute)
	if anomalies := engine.ScanDarkVessels(context.Background()); len(anomalies) != 0 {
		t.Fatal("dark-vessel scan alerted at 29 minutes")
	}
	*clock = now.Add(31 * time.Minute)
	anomalies := engine.ScanDarkVessels(context.Background())
	if len(anomalies) != 1 || anomalies[0].Kind != AnomalyDarkVessel {
		t.Fatalf("dark-vessel scan did not alert after the gap: %+v", anomalies)
	}
	if anomalies := engine.ScanDarkVessels(context.Background()); len(anomalies) != 0 {
		t.Fatal("dark-vessel alerted twice")
	}
	// A track outside every zone never alerts.
	if _, _, err := engine.Ingest(context.Background(), aisDetection("636050002", now, 2.0, 0.0)); err != nil {
		t.Fatal(err)
	}
	*clock = now.Add(2 * time.Hour)
	for _, anomaly := range engine.ScanDarkVessels(context.Background()) {
		if anomaly.TrackIDs[0] != "" && len(anomaly.TrackIDs) == 1 && anomaly.Kind == AnomalyDarkVessel {
			track, _ := engine.Track(anomaly.TrackIDs[0])
			if track.MMSI == "636050002" {
				t.Fatal("dark-vessel alerted outside the coverage zone")
			}
		}
	}
}

func TestDetectionLatencyRecorded(t *testing.T) {
	recorder := &recordingLatency{}
	now := time.Date(2026, 8, 15, 13, 0, 0, 0, time.UTC)
	engine, err := NewEngine(testConfig(), testZones(t), recorder, func() time.Time { return now }, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := now.Add(-3 * time.Second)
	mmsi := "636060001"
	if _, _, err := engine.Ingest(context.Background(), aisDetection(mmsi, base, 6.45, 3.40)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := engine.Ingest(context.Background(), aisDetection(mmsi, now, 6.45+20*1852.0/111_320.0, 3.40)); err != nil {
		t.Fatal(err)
	}
	if len(recorder.observations) == 0 {
		t.Fatal("no detection latency recorded for emitted anomaly")
	}
	for _, seconds := range recorder.observations {
		if seconds < 0 || seconds > 5 {
			t.Fatalf("detection latency %.3fs violates the p99 <= 5s KPI envelope", seconds)
		}
	}
}

func TestClassificationEscalatesOnFusion(t *testing.T) {
	engine, err := NewEngine(testConfig(), testZones(t), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	trackID, _, err := engine.Ingest(context.Background(), aisDetection("636070001", base, 6.44, 3.38))
	if err != nil {
		t.Fatal(err)
	}
	// Confidential SAR detection correlates into the track inside the window.
	if _, _, err := engine.Ingest(context.Background(), sarDetection("sar-secret", base.Add(time.Minute), 6.4403, 3.3803)); err != nil {
		t.Fatal(err)
	}
	track, ok := engine.Track(trackID)
	if !ok {
		t.Fatal("track missing")
	}
	if track.Classification != isr.ClassificationConfidential {
		t.Fatalf("track classification must be the maximum of its detections, got %s", track.Classification)
	}
}
