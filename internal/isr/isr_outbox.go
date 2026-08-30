package isr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ErrNoPendingISROutbox reports an empty claimable set.
var ErrNoPendingISROutbox = errors.New("no pending isr outbox events")

// ISROutboxEvent is one claimed Workstream F outbox event awaiting Kafka
// delivery.
type ISROutboxEvent struct {
	EventID        uuid.UUID `json:"event_id"`
	Topic          string    `json:"topic"`
	EventType      string    `json:"event_type"`
	Classification string    `json:"classification"`
	AggregateKey   string    `json:"aggregate_key"`
	Payload        []byte    `json:"payload"`
	Attempts       int       `json:"attempts"`
}

// ClaimISROutbox claims the oldest claimable Workstream F outbox event for
// one worker with a bounded lease (FOR UPDATE SKIP LOCKED, mirroring the
// incident outbox claim discipline).
func (store *Store) ClaimISROutbox(ctx context.Context, workerID string, lease time.Duration) (ISROutboxEvent, error) {
	if workerID == "" || lease <= 0 {
		return ISROutboxEvent{}, errors.New("worker id and positive lease are required")
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return ISROutboxEvent{}, fmt.Errorf("begin isr outbox claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now().UTC()
	var event ISROutboxEvent
	err = tx.QueryRow(ctx, `
		SELECT event_id, topic, event_type, classification, aggregate_key, payload, attempts
		FROM maritime_isr_outbox
		WHERE published_at IS NULL AND available_at <= $1
			AND (claimed_at IS NULL OR claimed_at < $2)
		ORDER BY created_at
		LIMIT 1
		FOR UPDATE SKIP LOCKED`, now, now.Add(-lease)).
		Scan(&event.EventID, &event.Topic, &event.EventType, &event.Classification, &event.AggregateKey, &event.Payload, &event.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return ISROutboxEvent{}, ErrNoPendingISROutbox
	}
	if err != nil {
		return ISROutboxEvent{}, fmt.Errorf("claim isr outbox event: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE maritime_isr_outbox SET claimed_at=$1, claimed_by=$2, attempts=attempts+1 WHERE event_id=$3`,
		now, workerID, event.EventID); err != nil {
		return ISROutboxEvent{}, fmt.Errorf("mark isr outbox claim: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ISROutboxEvent{}, fmt.Errorf("commit isr outbox claim: %w", err)
	}
	event.Attempts++
	return event, nil
}

// MarkISROutboxPublished records a successful Kafka delivery.
func (store *Store) MarkISROutboxPublished(ctx context.Context, eventID uuid.UUID, workerID string) error {
	tag, err := store.pool.Exec(ctx, `
		UPDATE maritime_isr_outbox SET published_at=$1 WHERE event_id=$2 AND claimed_by=$3 AND published_at IS NULL`,
		time.Now().UTC(), eventID, workerID)
	if err != nil {
		return fmt.Errorf("mark isr outbox published: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("isr outbox event is not claimed by this worker")
	}
	return nil
}

// MarkISROutboxFailed records a failed delivery and releases the claim with
// a bounded retry time.
func (store *Store) MarkISROutboxFailed(ctx context.Context, eventID uuid.UUID, workerID string, failure string, retryAt time.Time) error {
	tag, err := store.pool.Exec(ctx, `
		UPDATE maritime_isr_outbox SET claimed_at=NULL, claimed_by=NULL, last_error=$1, available_at=$2
		WHERE event_id=$3 AND claimed_by=$4 AND published_at IS NULL`,
		failure, retryAt, eventID, workerID)
	if err != nil {
		return fmt.Errorf("release isr outbox event: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("isr outbox event is not claimed by this worker")
	}
	return nil
}

// CountPendingISROutbox reports the backlog for operational visibility.
func (store *Store) CountPendingISROutbox(ctx context.Context) (int64, error) {
	var count int64
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM maritime_isr_outbox WHERE published_at IS NULL`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count isr outbox backlog: %w", err)
	}
	return count, nil
}

// DecodeOutboxPayload decodes one retained outbox payload (used by tooling).
func DecodeOutboxPayload(payload []byte) (map[string]any, error) {
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		return nil, fmt.Errorf("decode outbox payload: %w", err)
	}
	return document, nil
}
