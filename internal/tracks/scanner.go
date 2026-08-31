package tracks

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// AnomalyRecorder persists scan-time anomalies. *Store satisfies it; the
// store implementation also writes each anomaly's behaviour-topic envelope to
// the ISR outbox in the same transaction.
type AnomalyRecorder interface {
	RecordAnomalies(ctx context.Context, anomalies []Anomaly) error
}

// DarkVesselScanner runs the dark-vessel rule on a ticker: AIS-silent tracks
// inside a coverage zone are detected by Engine.ScanDarkVessels and persisted
// (with their outbox envelopes) through the AnomalyRecorder. Scan and record
// failures are logged and retried on the next tick; the scanner never panics
// and never drops the engine's alerted state.
type DarkVesselScanner struct {
	engine   *Engine
	recorder AnomalyRecorder
	interval time.Duration
	logger   *slog.Logger
}

// NewDarkVesselScanner fails closed on a missing engine, recorder or a
// non-positive interval — an operator who wants the scanner disabled must say
// so explicitly at the call site (the binary simply does not start one).
func NewDarkVesselScanner(engine *Engine, recorder AnomalyRecorder, interval time.Duration, logger *slog.Logger) (*DarkVesselScanner, error) {
	if engine == nil {
		return nil, errors.New("dark-vessel scanner requires a fusion engine")
	}
	if recorder == nil {
		return nil, errors.New("dark-vessel scanner requires an anomaly recorder")
	}
	if interval <= 0 {
		return nil, errors.New("dark-vessel scan interval must be positive")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DarkVesselScanner{engine: engine, recorder: recorder, interval: interval, logger: logger}, nil
}

// Run scans once immediately and then every interval until the context is
// cancelled. It returns nil on shutdown.
func (scanner *DarkVesselScanner) Run(ctx context.Context) error {
	ticker := time.NewTicker(scanner.interval)
	defer ticker.Stop()
	scanner.scanOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			scanner.scanOnce(ctx)
		}
	}
}

func (scanner *DarkVesselScanner) scanOnce(ctx context.Context) {
	anomalies := scanner.engine.ScanDarkVessels(ctx)
	if len(anomalies) == 0 {
		return
	}
	if err := scanner.recorder.RecordAnomalies(ctx, anomalies); err != nil {
		// Classified-data discipline: log counts and kinds only, never track
		// content. The engine already marked these tracks alerted, so a
		// transient failure loses this emission; the error is surfaced for
		// operators rather than swallowed.
		scanner.logger.ErrorContext(ctx, "dark-vessel anomaly record failed",
			"anomaly_count", len(anomalies), "error", err.Error())
		return
	}
	scanner.logger.InfoContext(ctx, "dark-vessel scan emitted anomalies", "anomaly_count", len(anomalies))
}
