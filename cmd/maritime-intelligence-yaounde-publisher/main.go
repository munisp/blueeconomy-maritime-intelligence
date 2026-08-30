// maritime-intelligence-yaounde-publisher drains the yaounde transactional
// outbox onto maritime.yaounde.v1 (pattern of the existing outbox publisher)
// and delivers DISPATCHED releases to configured peer endpoints with
// peer-signed ack verification (at-least-once, release_id idempotency key).
// There is no simulated peer: an ACTIVE peer without an endpoint stays
// UNCONFIGURED and its releases are never dispatched.
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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/kafka-go"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/telemetry"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/yaounde"
)

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
	telemetryConfig, err := telemetry.LoadConfig("blueeconomy-maritime-intelligence-yaounde-publisher")
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

	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	brokerRaw := strings.TrimSpace(os.Getenv("KAFKA_BROKERS"))
	if brokerRaw == "" {
		return errors.New("KAFKA_BROKERS is required")
	}
	workerID := os.Getenv("OUTBOX_WORKER_ID")
	if workerID == "" {
		hostname, _ := os.Hostname()
		workerID = fmt.Sprintf("yaounde-publisher-%s-%d", hostname, os.Getpid())
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	defer pool.Close()
	store := yaounde.NewStore(pool)
	writer := &kafka.Writer{Addr: kafka.TCP(strings.Split(brokerRaw, ",")...), RequiredAcks: kafka.RequireAll}
	defer writer.Close()
	deliverer := yaounde.NewDeliverer(nil)

	publishOne := func() (bool, error) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return false, err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var eventID, aggregateKey string
		var payload []byte
		err = tx.QueryRow(ctx, `
			UPDATE yaounde_outbox SET claimed_at=now(), claimed_by=$1, attempts=attempts+1
			WHERE event_id = (
				SELECT event_id FROM yaounde_outbox
				WHERE published_at IS NULL AND available_at <= now()
				ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED)
			RETURNING event_id, aggregate_key, payload`, workerID).
			Scan(&eventID, &aggregateKey, &payload)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("claim outbox event: %w", err)
		}
		if err := writer.WriteMessages(ctx, kafka.Message{
			Topic: "maritime.yaounde.v1", Key: []byte(aggregateKey), Value: payload, Time: time.Now().UTC(),
		}); err != nil {
			if _, execErr := tx.Exec(ctx, `UPDATE yaounde_outbox SET last_error=$2, available_at=now()+interval '5 seconds' WHERE event_id=$1`,
				eventID, err.Error()); execErr != nil {
				return false, execErr
			}
			return true, tx.Commit(ctx)
		}
		if _, err := tx.Exec(ctx, `UPDATE yaounde_outbox SET published_at=now(), last_error=NULL WHERE event_id=$1`, eventID); err != nil {
			return false, err
		}
		return true, tx.Commit(ctx)
	}

	deliverPending := func() error {
		rows, err := pool.Query(ctx, `
			SELECT release_id, report_sha256, envelope_jws, version, peer_id
			FROM yaounde_releases WHERE state='DISPATCHED' ORDER BY dispatched_at LIMIT 10`)
		if err != nil {
			return err
		}
		type pending struct {
			releaseID, digest, envelopeDoc, peerID string
			version                                int64
		}
		var pendings []pending
		for rows.Next() {
			var p pending
			if err := rows.Scan(&p.releaseID, &p.digest, &p.envelopeDoc, &p.version, &p.peerID); err != nil {
				rows.Close()
				return err
			}
			pendings = append(pendings, p)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, p := range pendings {
			peer, err := store.GetPeer(ctx, p.peerID)
			if err != nil || !peer.Configured() {
				continue // fail-closed peers are refused at dispatch; never delivered here
			}
			result, err := deliverer.Deliver(ctx, peer, p.releaseID, p.digest, []byte(p.envelopeDoc))
			if err != nil {
				if _, failErr := store.FailDelivery(ctx, p.releaseID, p.version, "delivery-failed"); failErr != nil {
					slog.Error("mark delivery failed", "release_id", p.releaseID, "error", failErr)
				}
				slog.Error("release delivery failed", "release_id", p.releaseID, "error", err)
				continue
			}
			if _, err := store.RecordAcknowledgement(ctx, p.releaseID, p.version, result.ReceiptSignature); err != nil {
				slog.Error("record acknowledgement", "release_id", p.releaseID, "error", err)
			}
		}
		return nil
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			for {
				claimed, err := publishOne()
				if err != nil {
					slog.Error("publish outbox", "error", err)
					break
				}
				if !claimed {
					break
				}
			}
			if err := deliverPending(); err != nil {
				slog.Error("deliver releases", "error", err)
			}
		}
	}
}
