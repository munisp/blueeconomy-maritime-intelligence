package tracks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

// Store persists fused-track snapshots, association audit records and
// behaviour anomalies, and emits maritime.behaviour.v1 envelopes through the
// ISR outbox in the same transaction.
type Store struct{ pool *pgxpool.Pool }

// NewStore binds the store to an existing pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// RecordFusion atomically upserts the track snapshot, records the
// association audit for the ingested detection and persists every emitted
// anomaly with its behaviour-topic envelope.
func (store *Store) RecordFusion(ctx context.Context, track Track, detection isr.Detection, anomalies []Anomaly) error {
	if len(track.Points) == 0 {
		return errors.New("track has no points")
	}
	first := track.Points[0].ObservedAt
	last := track.Points[len(track.Points)-1].ObservedAt
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin fusion record: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO maritime_vessel_tracks (track_id, mmsi, classification, first_observed_at, last_observed_at, point_count, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (track_id) DO UPDATE SET
			mmsi = COALESCE(maritime_vessel_tracks.mmsi, EXCLUDED.mmsi),
			classification = EXCLUDED.classification,
			last_observed_at = GREATEST(maritime_vessel_tracks.last_observed_at, EXCLUDED.last_observed_at),
			point_count = EXCLUDED.point_count,
			updated_at = EXCLUDED.updated_at`,
		track.TrackID, nullable(track.MMSI), string(track.Classification), first, last, len(track.Points), time.Now().UTC()); err != nil {
		return fmt.Errorf("upsert track: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO maritime_track_associations (track_id, source_id, source_event_id, modality, classification, observed_at, associated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (source_id, source_event_id) DO NOTHING`,
		track.TrackID, detection.SourceID, detection.SourceEventID, string(detection.Modality),
		string(detection.Classification), detection.ObservedAt, time.Now().UTC()); err != nil {
		return fmt.Errorf("record association audit: %w", err)
	}
	for _, anomaly := range anomalies {
		if err := recordAnomalyInTransaction(ctx, tx, anomaly); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit fusion record: %w", err)
	}
	return nil
}

// RecordAnomalies persists scan-time anomalies (dark vessel) with their
// envelopes, idempotent on anomaly_id.
func (store *Store) RecordAnomalies(ctx context.Context, anomalies []Anomaly) error {
	if len(anomalies) == 0 {
		return nil
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin anomaly record: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, anomaly := range anomalies {
		if err := recordAnomalyInTransaction(ctx, tx, anomaly); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// AssociationReplay is one persisted track association with its retained
// signed detection payload, used to rebuild fusion engine state on startup.
type AssociationReplay struct {
	TrackID string
	Payload []byte
}

// ListAssociationsForReplay returns every persisted track association joined
// to its retained detection payload, ordered by observation time (ties broken
// deterministically) so a startup replay rebuilds engine state in a stable
// order. Fail-closed: a row whose detection payload was purged or is missing
// is an error, never a silently skipped association.
func (store *Store) ListAssociationsForReplay(ctx context.Context) ([]AssociationReplay, error) {
	rows, err := store.pool.Query(ctx, `
		SELECT a.track_id, e.payload
		FROM maritime_track_associations a
		JOIN maritime_isr_events e
			ON e.source_id = a.source_id AND e.source_event_id = a.source_event_id
		ORDER BY a.observed_at ASC, a.associated_at ASC, a.source_id ASC, a.source_event_id ASC`)
	if err != nil {
		return nil, fmt.Errorf("query track associations for replay: %w", err)
	}
	defer rows.Close()
	replays := make([]AssociationReplay, 0)
	for rows.Next() {
		var replay AssociationReplay
		if err := rows.Scan(&replay.TrackID, &replay.Payload); err != nil {
			return nil, fmt.Errorf("scan track association replay row: %w", err)
		}
		replays = append(replays, replay)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate track association replay: %w", err)
	}
	return replays, nil
}

type txExec = pgx.Tx

func recordAnomalyInTransaction(ctx context.Context, tx txExec, anomaly Anomaly) error {
	trackIDs, err := json.Marshal(anomaly.TrackIDs)
	if err != nil {
		return fmt.Errorf("encode anomaly track ids: %w", err)
	}
	refs, err := json.Marshal(anomaly.CorrelationRefs)
	if err != nil {
		return fmt.Errorf("encode anomaly correlation refs: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO maritime_behaviour_anomalies (anomaly_id, kind, classification, track_ids, zone_id, detail, correlation_refs, detected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (anomaly_id) DO NOTHING`,
		anomaly.AnomalyID, string(anomaly.Kind), string(anomaly.Classification), trackIDs,
		nullable(anomaly.ZoneID), anomaly.Detail, refs, anomaly.DetectedAt)
	if err != nil {
		return fmt.Errorf("record anomaly: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	envelope, envelopeBytes, err := isr.Seal(isr.TopicBehaviour, "behaviour."+string(anomaly.Kind), anomaly.AnomalyID, anomaly.Classification, anomaly.DetectedAt, anomaly)
	if err != nil {
		return err
	}
	// The outbox row keeps the record-level clearance label (DB CHECK); the
	// payload column carries the canonical envelope document verbatim.
	if _, err := tx.Exec(ctx, `
		INSERT INTO maritime_isr_outbox (event_id, topic, event_type, classification, aggregate_key, payload, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		uuid.New(), envelope.Topic, envelope.EventType, string(envelope.Clearance), envelope.AggregateKey, envelopeBytes, anomaly.DetectedAt); err != nil {
		return fmt.Errorf("write anomaly outbox event: %w", err)
	}
	return nil
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}
