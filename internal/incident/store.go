package incident

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return NewStore(pool), nil
}

func (store *Store) Close() { store.pool.Close() }

func (store *Store) Exec(ctx context.Context, statement string) error {
	_, err := store.pool.Exec(ctx, statement)
	return err
}

func (store *Store) Create(ctx context.Context, request CreateRequest) (Incident, error) {
	if err := request.Validate(); err != nil {
		return Incident{}, err
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return Incident{}, fmt.Errorf("begin create: %w", err)
	}
	defer tx.Rollback(ctx)
	createdAt := time.Now().UTC()
	var retained Incident
	err = tx.QueryRow(ctx, `
		INSERT INTO maritime_incidents (
			incident_id, source_event_id, category, severity, title, description,
			occurred_at, created_by, status, created_at, updated_at, version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, 1)
		ON CONFLICT (source_event_id) DO NOTHING
		RETURNING incident_id, source_event_id, category, severity, title, description,
			occurred_at, created_by, status, created_at, updated_at, version`,
		request.IncidentID, request.SourceEventID, request.Category, request.Severity,
		request.Title, request.Description, request.OccurredAt, request.CreatedBy,
		StatusOpen, createdAt,
	).Scan(&retained.IncidentID, &retained.SourceEventID, &retained.Category, &retained.Severity,
		&retained.Title, &retained.Description, &retained.OccurredAt, &retained.CreatedBy,
		&retained.Status, &retained.CreatedAt, &retained.UpdatedAt, &retained.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `
			SELECT incident_id, source_event_id, category, severity, title, description,
				occurred_at, created_by, status, created_at, updated_at, version
			FROM maritime_incidents WHERE source_event_id = $1 FOR UPDATE`, request.SourceEventID).
			Scan(&retained.IncidentID, &retained.SourceEventID, &retained.Category, &retained.Severity,
				&retained.Title, &retained.Description, &retained.OccurredAt, &retained.CreatedBy,
				&retained.Status, &retained.CreatedAt, &retained.UpdatedAt, &retained.Version)
		if errors.Is(err, pgx.ErrNoRows) {
			return Incident{}, ErrNotFound
		}
		if err != nil {
			return Incident{}, fmt.Errorf("lookup source event: %w", err)
		}
		if !retained.Matches(request) {
			return Incident{}, ErrIdempotencyConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return Incident{}, fmt.Errorf("commit replay: %w", err)
		}
		return retained, nil
	}
	if err != nil {
		return Incident{}, fmt.Errorf("insert incident: %w", err)
	}
	payload, err := json.Marshal(retained)
	if err != nil {
		return Incident{}, fmt.Errorf("encode incident event: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO maritime_incident_outbox (event_id, incident_id, event_type, payload, created_at)
		VALUES ($1, $2, 'incident.created', $3, $4)`, uuid.New(), retained.IncidentID, payload, createdAt); err != nil {
		return Incident{}, fmt.Errorf("write incident event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Incident{}, fmt.Errorf("commit incident: %w", err)
	}
	return retained, nil
}

func (store *Store) Get(ctx context.Context, incidentID string) (Incident, error) {
	var retained Incident
	err := store.pool.QueryRow(ctx, `
		SELECT incident_id, source_event_id, category, severity, title, description,
			occurred_at, created_by, status, created_at, updated_at, version
		FROM maritime_incidents WHERE incident_id = $1`, incidentID).
		Scan(&retained.IncidentID, &retained.SourceEventID, &retained.Category, &retained.Severity,
			&retained.Title, &retained.Description, &retained.OccurredAt, &retained.CreatedBy,
			&retained.Status, &retained.CreatedAt, &retained.UpdatedAt, &retained.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return Incident{}, ErrNotFound
	}
	if err != nil {
		return Incident{}, fmt.Errorf("get incident: %w", err)
	}
	return retained, nil
}

func (store *Store) Transition(ctx context.Context, incidentID string, expectedVersion int64, next Status) (Incident, error) {
	current, err := store.Get(ctx, incidentID)
	if err != nil {
		return Incident{}, err
	}
	if current.Version != expectedVersion {
		return Incident{}, ErrOptimisticConflict
	}
	if !ValidTransition(current.Status, next) {
		return Incident{}, ErrInvalidTransition
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return Incident{}, fmt.Errorf("begin transition: %w", err)
	}
	defer tx.Rollback(ctx)
	updatedAt := time.Now().UTC()
	var updated Incident
	err = tx.QueryRow(ctx, `
		UPDATE maritime_incidents SET status = $1, updated_at = $2, version = version + 1
		WHERE incident_id = $3 AND status = $4 AND version = $5
		RETURNING incident_id, source_event_id, category, severity, title, description,
			occurred_at, created_by, status, created_at, updated_at, version`,
		next, updatedAt, incidentID, current.Status, expectedVersion).
		Scan(&updated.IncidentID, &updated.SourceEventID, &updated.Category, &updated.Severity,
			&updated.Title, &updated.Description, &updated.OccurredAt, &updated.CreatedBy,
			&updated.Status, &updated.CreatedAt, &updated.UpdatedAt, &updated.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return Incident{}, ErrOptimisticConflict
	}
	if err != nil {
		return Incident{}, fmt.Errorf("transition incident: %w", err)
	}
	payload, err := json.Marshal(updated)
	if err != nil {
		return Incident{}, fmt.Errorf("encode status event: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO maritime_incident_outbox (event_id, incident_id, event_type, payload, created_at)
		VALUES ($1, $2, 'incident.status_changed', $3, $4)`, uuid.New(), updated.IncidentID, payload, updatedAt); err != nil {
		return Incident{}, fmt.Errorf("write status event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Incident{}, fmt.Errorf("commit transition: %w", err)
	}
	return updated, nil
}
