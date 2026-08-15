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
	retained, err := createIncidentInTransaction(ctx, tx, request)
	if err != nil {
		return Incident{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Incident{}, fmt.Errorf("commit incident: %w", err)
	}
	return retained, nil
}

func createIncidentInTransaction(ctx context.Context, tx pgx.Tx, request CreateRequest) (Incident, error) {
	createdAt := time.Now().UTC()
	var retained Incident
	err := tx.QueryRow(ctx, `
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

func (store *Store) Correlate(ctx context.Context, incidentID string, request CorrelationRequest) (SpatialCorrelation, error) {
	if !incidentIDPattern.MatchString(incidentID) {
		return SpatialCorrelation{}, ErrNotFound
	}
	if err := request.Validate(); err != nil {
		return SpatialCorrelation{}, err
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return SpatialCorrelation{}, fmt.Errorf("begin correlation: %w", err)
	}
	defer tx.Rollback(ctx)
	createdAt := time.Now().UTC()
	correlationID := uuid.New()
	var retained SpatialCorrelation
	err = tx.QueryRow(ctx, `
		INSERT INTO maritime_incident_spatial_correlations (
			correlation_id, incident_id, geofence_id, relation, latitude, longitude,
			evidence_sha256, correlated_by, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (incident_id, geofence_id) DO NOTHING
		RETURNING correlation_id, incident_id, geofence_id, relation, latitude, longitude,
			evidence_sha256, correlated_by, created_at`,
		correlationID, incidentID, request.GeofenceID, request.Relation, request.Latitude,
		request.Longitude, request.EvidenceSHA256, request.CorrelatedBy, createdAt,
	).Scan(&retained.CorrelationID, &retained.IncidentID, &retained.GeofenceID, &retained.Relation,
		&retained.Latitude, &retained.Longitude, &retained.EvidenceSHA256, &retained.CorrelatedBy,
		&retained.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `
			SELECT correlation_id, incident_id, geofence_id, relation, latitude, longitude,
				evidence_sha256, correlated_by, created_at
			FROM maritime_incident_spatial_correlations
			WHERE incident_id = $1 AND geofence_id = $2 FOR UPDATE`, incidentID, request.GeofenceID).
			Scan(&retained.CorrelationID, &retained.IncidentID, &retained.GeofenceID, &retained.Relation,
				&retained.Latitude, &retained.Longitude, &retained.EvidenceSHA256, &retained.CorrelatedBy,
				&retained.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return SpatialCorrelation{}, ErrNotFound
		}
		if err != nil {
			return SpatialCorrelation{}, fmt.Errorf("lookup correlation: %w", err)
		}
		if retained.Relation != request.Relation || retained.Latitude != request.Latitude ||
			retained.Longitude != request.Longitude || retained.EvidenceSHA256 != request.EvidenceSHA256 ||
			retained.CorrelatedBy != request.CorrelatedBy {
			return SpatialCorrelation{}, ErrCorrelationConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return SpatialCorrelation{}, fmt.Errorf("commit correlation replay: %w", err)
		}
		return retained, nil
	}
	if err != nil {
		return SpatialCorrelation{}, fmt.Errorf("insert correlation: %w", err)
	}
	payload, err := json.Marshal(retained)
	if err != nil {
		return SpatialCorrelation{}, fmt.Errorf("encode correlation event: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO maritime_incident_outbox (event_id, incident_id, event_type, payload, created_at)
		VALUES ($1, $2, 'incident.spatial_correlated', $3, $4)`, uuid.New(), incidentID, payload, createdAt); err != nil {
		return SpatialCorrelation{}, fmt.Errorf("write correlation event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return SpatialCorrelation{}, fmt.Errorf("commit correlation: %w", err)
	}
	return retained, nil
}

func (store *Store) Assign(ctx context.Context, incidentID string, request AssignmentRequest) (AnalystAssignment, error) {
	if !incidentIDPattern.MatchString(incidentID) {
		return AnalystAssignment{}, ErrNotFound
	}
	if err := request.Validate(); err != nil {
		return AnalystAssignment{}, err
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return AnalystAssignment{}, fmt.Errorf("begin assignment: %w", err)
	}
	defer tx.Rollback(ctx)
	assignedAt := time.Now().UTC()
	var assignment AnalystAssignment
	err = tx.QueryRow(ctx, `
		UPDATE maritime_incidents
		SET updated_at = $1, version = version + 1
		WHERE incident_id = $2 AND version = $3 AND status <> 'CLOSED'
		RETURNING version`, assignedAt, incidentID, request.ExpectedVersion).Scan(&assignment.IncidentVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		current, getErr := store.Get(ctx, incidentID)
		if errors.Is(getErr, ErrNotFound) {
			return AnalystAssignment{}, ErrNotFound
		}
		if getErr != nil || current.Version != request.ExpectedVersion {
			return AnalystAssignment{}, ErrOptimisticConflict
		}
		return AnalystAssignment{}, ErrInvalidTransition
	}
	if err != nil {
		return AnalystAssignment{}, fmt.Errorf("update assignment version: %w", err)
	}
	assignment.IncidentID = incidentID
	assignment.AnalystID = request.AnalystID
	assignment.AssignedBy = request.AssignedBy
	assignment.AssignedAt = assignedAt
	if _, err := tx.Exec(ctx, `
		INSERT INTO maritime_incident_assignments (incident_id, analyst_id, assigned_by, assigned_at, incident_version)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (incident_id) DO UPDATE SET analyst_id = EXCLUDED.analyst_id,
			assigned_by = EXCLUDED.assigned_by, assigned_at = EXCLUDED.assigned_at,
			incident_version = EXCLUDED.incident_version`, incidentID, request.AnalystID, request.AssignedBy,
		assignedAt, assignment.IncidentVersion); err != nil {
		return AnalystAssignment{}, fmt.Errorf("persist assignment: %w", err)
	}
	payload, err := json.Marshal(assignment)
	if err != nil {
		return AnalystAssignment{}, fmt.Errorf("encode assignment event: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO maritime_incident_outbox (event_id, incident_id, event_type, payload, created_at)
		VALUES ($1, $2, 'incident.assigned', $3, $4)`, uuid.New(), incidentID, payload, assignedAt); err != nil {
		return AnalystAssignment{}, fmt.Errorf("write assignment event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return AnalystAssignment{}, fmt.Errorf("commit assignment: %w", err)
	}
	return assignment, nil
}
