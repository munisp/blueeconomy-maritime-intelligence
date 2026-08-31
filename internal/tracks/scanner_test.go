package tracks

import (
	"context"
	"sync"
	"testing"
	"time"
)

// countingRecorder is an in-test AnomalyRecorder capturing every batch.
type countingRecorder struct {
	mu      sync.Mutex
	batches [][]Anomaly
}

func (recorder *countingRecorder) RecordAnomalies(_ context.Context, anomalies []Anomaly) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.batches = append(recorder.batches, append([]Anomaly(nil), anomalies...))
	return nil
}

func (recorder *countingRecorder) total() int {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	total := 0
	for _, batch := range recorder.batches {
		total += len(batch)
	}
	return total
}

func (recorder *countingRecorder) first() Anomaly {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return recorder.batches[0][0]
}

// TestDarkVesselScannerTicksAndRecords drives the ticker loop against a real
// fusion engine: an AIS-silent track inside a coverage zone is detected on a
// tick and recorded exactly once (the engine alerts once per track).
func TestDarkVesselScannerTicksAndRecords(t *testing.T) {
	base := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	current := base
	engine, err := NewEngine(testConfig(), testZones(t), nil, func() time.Time { return current }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := engine.Ingest(context.Background(), aisDetection("123456789", base, 6.0, 5.0)); err != nil {
		t.Fatal(err)
	}
	// Advance the clock past the dark-vessel AIS gap before the scanner runs.
	current = base.Add(45 * time.Minute)

	recorder := &countingRecorder{}
	scanner, err := NewDarkVesselScanner(engine, recorder, 5*time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- scanner.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for recorder.total() == 0 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("scanner did not record the dark-vessel anomaly")
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	anomaly := recorder.first()
	if anomaly.Kind != AnomalyDarkVessel {
		t.Fatalf("unexpected anomaly kind %q", anomaly.Kind)
	}
	if anomaly.ZoneID == "" || len(anomaly.TrackIDs) != 1 {
		t.Fatalf("anomaly lost zone/track binding: %+v", anomaly)
	}
	// The engine alerts once per track: further ticks must not duplicate.
	time.Sleep(25 * time.Millisecond)
	if total := recorder.total(); total != 1 {
		t.Fatalf("scanner recorded %d anomalies, want exactly 1", total)
	}
}

// TestDarkVesselScannerFailsClosed rejects construction without its required
// dependencies; disabling happens at the call site, never silently.
func TestDarkVesselScannerFailsClosed(t *testing.T) {
	engine, err := NewEngine(testConfig(), testZones(t), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &countingRecorder{}
	if _, err := NewDarkVesselScanner(nil, recorder, time.Second, nil); err == nil {
		t.Fatal("nil engine accepted")
	}
	if _, err := NewDarkVesselScanner(engine, nil, time.Second, nil); err == nil {
		t.Fatal("nil recorder accepted")
	}
	if _, err := NewDarkVesselScanner(engine, recorder, 0, nil); err == nil {
		t.Fatal("non-positive interval accepted")
	}
}
