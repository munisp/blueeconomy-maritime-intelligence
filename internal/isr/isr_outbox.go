package isr

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrNoPendingISROutbox is returned when no ISR outbox event is claimable.
var ErrNoPendingISROutbox = errors.New("no pending isr outbox events")

// ErrISROutboxOwnership is returned when a worker touches an event it does
// not own.
var ErrISROutboxOwnership = errors.New("isr outbox event is not owned by worker")

// ISROutboxEvent is one claimed platform-envelope event awaiting publish.
type ISROutboxEvent struct {
	EventID        uuid.UUID      `json:"event_id"`
	Topic          string         `json:"topic"`
	EventType      string         `json:"event_type"`
	Classification Classification `json:"classification"`
	AggregateKey   string         `json:"aggregate_key"`
	Payload        []byte         `json:"payload"`
	Attempts       int            `json:"attempts"`
}

// ClaimISROutbox leases the next unpublished ISR outbox event for a worker.
func (store *Store) ClaimISROutbox(ctx context.Context, workerID string, lease time.Duration) (ISROutboxEvent, error) {
	if strings.TrimSpace(workerID) == "" || strings.TrimSpace(workerID) != workerID {
		return ISROutboxEvent{}, errors.New("worker_id must be canonical non-empty text")
	}
	if lease <= 0 || lease > 24*time.Hour {
		return ISROutboxEvent{}, errors.New("lease must be between one nanosecond and 24 hours")
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return ISROutboxEvent{}, fmt.Errorf("begin isr outbox claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var event ISROutboxEvent
	err = tx.QueryRow(ctx, `
		SELECT event_id, topic, event_type, classification, aggregate_key, payload, attempts
		FROM maritime_isr_outbox
		WHERE published_at IS NULL AND available_at <= now()
		  AND (claimed_at IS NULL OR claimed_at < $1)
		ORDER BY created_at, event_id
		FOR UPDATE SKIP LOCKED LIMIT 1`, time.Now().UTC().Add(-lease)).
		Scan(&event.EventID, &event.Topic, &event.EventType, &event.Classification, &event.AggregateKey, &event.Payload, &event.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return ISROutboxEvent{}, ErrNoPendingISROutbox
	}
	if err != nil {
		return ISROutboxEvent{}, fmt.Errorf("select isr outbox event: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE maritime_isr_outbox
		SET claimed_at = now(), claimed_by = $1, attempts = attempts + 1
		WHERE event_id = $2`, workerID, event.EventID); err != nil {
		return ISROutboxEvent{}, fmt.Errorf("claim isr outbox event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ISROutboxEvent{}, fmt.Errorf("commit isr outbox claim: %w", err)
	}
	event.Attempts++
	return event, nil
}

// MarkISROutboxPublished completes a claimed event.
func (store *Store) MarkISROutboxPublished(ctx context.Context, eventID uuid.UUID, workerID string) error {
	if strings.TrimSpace(workerID) == "" {
		return errors.New("worker_id must be canonical non-empty text")
	}
	result, err := store.pool.Exec(ctx, `
		UPDATE maritime_isr_outbox
		SET published_at = now(), claimed_at = NULL, claimed_by = NULL, last_error = NULL
		WHERE event_id = $1 AND claimed_by = $2 AND published_at IS NULL`, eventID, workerID)
	if err != nil {
		return fmt.Errorf("mark isr outbox published: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrISROutboxOwnership
	}
	return nil
}

// MarkISROutboxFailed reschedules a claimed event with a bounded error.
func (store *Store) MarkISROutboxFailed(ctx context.Context, eventID uuid.UUID, workerID, failure string, retryAt time.Time) error {
	if strings.TrimSpace(workerID) == "" {
		return errors.New("worker_id must be canonical non-empty text")
	}
	failure = strings.TrimSpace(failure)
	if failure == "" || len(failure) > 2048 {
		return errors.New("failure must be non-empty and at most 2048 characters")
	}
	result, err := store.pool.Exec(ctx, `
		UPDATE maritime_isr_outbox
		SET available_at = $1, claimed_at = NULL, claimed_by = NULL, last_error = $2
		WHERE event_id = $3 AND claimed_by = $4 AND published_at IS NULL`, retryAt.UTC(), failure, eventID, workerID)
	if err != nil {
		return fmt.Errorf("mark isr outbox failed: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrISROutboxOwnership
	}
	return nil
}
