// maritime-intelligence-sar-intake is the SAR intake consumer (PRA-098
// residual): it consumes waterway vessel/sensor events from
// ferries.telemetry.v1 and geo SOS alerts from geo.sos.v1 (when configured),
// verifies every record fail-closed against the fleet key directory, routes
// safety-relevant frames through signed feed admission and opens SAR cases.
// Malformed records hold their partition uncommitted (dead-letter
// discipline); no unsigned record is ever admitted and nothing is
// fabricated.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/kafka-go"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/incident"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/sar"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/telemetry"
)

func requiredEnv(name string) (string, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}

func splitNonEmpty(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Telemetry extends the existing pipeline; when OTel is off the service
	// still boots (telemetry never fails the business path).
	telemetryConfig, err := telemetry.LoadConfig("blueeconomy-maritime-intelligence-sar-intake")
	if err != nil {
		return err
	}
	telemetryPipeline, err := telemetry.Setup(ctx, telemetryConfig)
	if err != nil {
		return fmt.Errorf("telemetry setup: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = telemetryPipeline.Shutdown(shutdownCtx)
	}()

	databaseURL, err := requiredEnv("DATABASE_URL")
	if err != nil {
		return err
	}
	brokerRaw, err := requiredEnv("KAFKA_BROKERS")
	if err != nil {
		return err
	}
	brokers := splitNonEmpty(brokerRaw)
	if len(brokers) == 0 {
		return errors.New("KAFKA_BROKERS must list at least one broker")
	}
	// Registered ACTIVE SAR feed source identity for this intake service.
	sourceID, err := requiredEnv("SAR_INTAKE_SOURCE_ID")
	if err != nil {
		return err
	}
	geoSOSTopic := strings.TrimSpace(os.Getenv("SAR_GEO_SOS_TOPIC")) // empty disables the geo SOS leg

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	defer pool.Close()

	directory, err := provenance.LoadDirectoryFromEnv()
	if err != nil {
		return fmt.Errorf("load key directory (fail-closed): %w", err)
	}
	signer, err := provenance.LoadSignerFromEnv(sourceID)
	if err != nil {
		return fmt.Errorf("load intake signing key (fail-closed): %w", err)
	}
	incidents := incident.NewStore(pool)
	cases := sar.NewStore(pool).WithSigner(signer)
	processor := &sar.IntakeProcessor{
		Incidents: incidents, Cases: cases, Directory: directory, Signer: signer, SourceID: sourceID,
	}
	if err := processor.Validate(); err != nil {
		return fmt.Errorf("intake wiring invalid (fail-closed): %w", err)
	}
	// Fail closed at boot: the intake feed source must exist and be ACTIVE.
	var active bool
	if err := pool.QueryRow(ctx, `SELECT active FROM maritime_feed_sources WHERE source_id=$1`, sourceID).Scan(&active); err != nil {
		return fmt.Errorf("intake feed source %s is not registered (fail-closed): %w", sourceID, err)
	}
	if !active {
		return fmt.Errorf("intake feed source %s is not ACTIVE (fail-closed)", sourceID)
	}

	readers := []*kafka.Reader{
		kafka.NewReader(kafka.ReaderConfig{
			Brokers: brokers, Topic: sar.WaterwayTelemetryTopic, GroupID: "maritime-intelligence-sar-intake",
			MinBytes: 1, MaxBytes: 4 << 20, CommitInterval: 0,
		}),
	}
	if geoSOSTopic != "" {
		readers = append(readers, kafka.NewReader(kafka.ReaderConfig{
			Brokers: brokers, Topic: geoSOSTopic, GroupID: "maritime-intelligence-sar-intake",
			MinBytes: 1, MaxBytes: 4 << 20, CommitInterval: 0,
		}))
	}
	errCh := make(chan error, len(readers))
	for _, reader := range readers {
		reader := reader
		go func() {
			defer reader.Close()
			for {
				message, err := reader.FetchMessage(ctx)
				if err != nil {
					if errors.Is(err, context.Canceled) {
						return
					}
					errCh <- err
					return
				}
				var processErr error
				if reader.Config().Topic == sar.WaterwayTelemetryTopic {
					var admitted int
					admitted, processErr = processor.ProcessWaterwayRecord(ctx, message.Key, message.Value)
					if processErr == nil {
						slog.Info("waterway batch processed", "offset", message.Offset, "safety_admitted", admitted)
					}
				} else {
					processErr = processor.ProcessSOSRecord(ctx, message.Value)
				}
				if processErr != nil {
					// Dead-letter discipline: log the rejection reason and do
					// NOT commit the offset. Poison records hold the
					// partition for an operator; never silent loss.
					slog.Error("intake record rejected (offset uncommitted)", "topic", reader.Config().Topic,
						"partition", message.Partition, "offset", message.Offset, "error", processErr)
					continue
				}
				if err := reader.CommitMessages(ctx, message); err != nil {
					slog.Error("commit offset", "error", err)
				}
			}
		}()
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return fmt.Errorf("intake reader failed: %w", err)
	}
}
