package incident

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrNoPendingOutbox = errors.New("no pending outbox events")
var ErrOutboxOwnership = errors.New("outbox event is not owned by worker")

type OutboxEvent struct {
	EventID    uuid.UUID `json:"event_id"`
	IncidentID string    `json:"incident_id"`
	EventType  string    `json:"event_type"`
	Payload    []byte    `json:"payload"`
	Attempts   int       `json:"attempts"`
}

func (store *Store) ClaimOutbox(ctx context.Context, workerID string, lease time.Duration) (OutboxEvent, error) {
	if strings.TrimSpace(workerID) == "" || strings.TrimSpace(workerID) != workerID {
		return OutboxEvent{}, errors.New("worker_id must be canonical non-empty text")
	}
	if lease <= 0 || lease > 24*time.Hour {
		return OutboxEvent{}, errors.New("lease must be between one nanosecond and 24 hours")
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return OutboxEvent{}, fmt.Errorf("begin outbox claim: %w", err)
	}
	defer tx.Rollback(ctx)
	var event OutboxEvent
	var createdAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT event_id, incident_id, event_type, payload, attempts, created_at
		FROM maritime_incident_outbox
		WHERE published_at IS NULL AND available_at <= now()
		  AND (claimed_at IS NULL OR claimed_at < $1)
		ORDER BY created_at, event_id
		FOR UPDATE SKIP LOCKED LIMIT 1`, time.Now().UTC().Add(-lease)).
		Scan(&event.EventID, &event.IncidentID, &event.EventType, &event.Payload, &event.Attempts, &createdAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return OutboxEvent{}, ErrNoPendingOutbox
	}
	if err != nil {
		return OutboxEvent{}, fmt.Errorf("select outbox event: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE maritime_incident_outbox
		SET claimed_at = now(), claimed_by = $1, attempts = attempts + 1
		WHERE event_id = $2`, workerID, event.EventID); err != nil {
		return OutboxEvent{}, fmt.Errorf("claim outbox event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return OutboxEvent{}, fmt.Errorf("commit outbox claim: %w", err)
	}
	event.Attempts++
	return event, nil
}

func (store *Store) MarkOutboxPublished(ctx context.Context, eventID uuid.UUID, workerID string) error {
	if strings.TrimSpace(workerID) == "" || strings.TrimSpace(workerID) != workerID {
		return errors.New("worker_id must be canonical non-empty text")
	}
	result, err := store.pool.Exec(ctx, `
		UPDATE maritime_incident_outbox
		SET published_at = now(), claimed_at = NULL, claimed_by = NULL, last_error = NULL
		WHERE event_id = $1 AND claimed_by = $2 AND published_at IS NULL`, eventID, workerID)
	if err != nil {
		return fmt.Errorf("mark outbox published: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrOutboxOwnership
	}
	return nil
}

func (store *Store) MarkOutboxFailed(ctx context.Context, eventID uuid.UUID, workerID, failure string, retryAt time.Time) error {
	if strings.TrimSpace(workerID) == "" || strings.TrimSpace(workerID) != workerID {
		return errors.New("worker_id must be canonical non-empty text")
	}
	failure = strings.TrimSpace(failure)
	if failure == "" || len(failure) > 2048 {
		return errors.New("failure must be non-empty and at most 2048 characters")
	}
	result, err := store.pool.Exec(ctx, `
		UPDATE maritime_incident_outbox
		SET available_at = $1, claimed_at = NULL, claimed_by = NULL, last_error = $2
		WHERE event_id = $3 AND claimed_by = $4 AND published_at IS NULL`, retryAt.UTC(), failure, eventID, workerID)
	if err != nil {
		return fmt.Errorf("mark outbox failed: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrOutboxOwnership
	}
	return nil
}
