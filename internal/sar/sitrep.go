package sar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/envelope"
)

// IssueSitrep assembles the SITREP body from the current case state,
// assigns the next monotonic per-case sequence, signs the canonical body
// (envelope v1.0 provenance over the sar.sitrep_issued resource) and
// persists it immutably with its timeline entry and outbox event atomically.
// Corrections are never edits: they are a new SITREP number.
func (store *Store) IssueSitrep(ctx context.Context, caseID string, expectedVersion int64, actor string) (Sitrep, error) {
	if expectedVersion < 1 {
		return Sitrep{}, fmt.Errorf("%w: expected_version must be positive", ErrValidation)
	}
	if err := validIdentifier("actor", actor); err != nil {
		return Sitrep{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Sitrep{}, fmt.Errorf("begin sitrep issuance: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var sarCase Case
	if err := loadCaseInTransaction(ctx, tx, caseID, "", &sarCase); err != nil {
		return Sitrep{}, err
	}
	if sarCase.Version != expectedVersion {
		return Sitrep{}, ErrConflict
	}
	// Next sequence under the case row lock; the UNIQUE(case_id, sequence)
	// constraint enforces monotonicity under any residual race.
	var sequence int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM sar_sitreps WHERE case_id=$1`, caseID).Scan(&sequence); err != nil {
		return Sitrep{}, fmt.Errorf("assign sitrep sequence: %w", err)
	}
	// Assemble the body strictly from retained case state: no field is
	// invented at issue time.
	taskingRows, err := tx.Query(ctx, `
		SELECT tasking_id, resource_id, task, state FROM sar_taskings WHERE case_id=$1 ORDER BY created_at, tasking_id`, caseID)
	if err != nil {
		return Sitrep{}, fmt.Errorf("load taskings for sitrep: %w", err)
	}
	taskings := make([]map[string]any, 0)
	for taskingRows.Next() {
		var taskingID, resourceID, task, state string
		if err := taskingRows.Scan(&taskingID, &resourceID, &task, &state); err != nil {
			taskingRows.Close()
			return Sitrep{}, fmt.Errorf("scan tasking for sitrep: %w", err)
		}
		taskings = append(taskings, map[string]any{
			"tasking_id": taskingID, "resource_id": resourceID, "task": task, "state": state,
		})
	}
	taskingRows.Close()
	if err := taskingRows.Err(); err != nil {
		return Sitrep{}, fmt.Errorf("iterate taskings for sitrep: %w", err)
	}
	now := time.Now().UTC()
	sitrepID := "sitrep-" + uuid.NewString()
	body := map[string]any{
		"sitrep_id": sitrepID, "case_id": caseID, "sequence": sequence,
		"incident_id": sarCase.IncidentID, "phase": string(sarCase.Phase), "stage": string(sarCase.Stage),
		"classification": string(sarCase.Classification), "intake_kind": string(sarCase.IntakeKind),
		"source_ref": sarCase.SourceRef, "taskings": taskings, "issued_by": actor,
		"issued_at": now.Format(time.RFC3339),
	}
	if sarCase.PersonsAtRisk != nil {
		body["persons_at_risk"] = *sarCase.PersonsAtRisk
	}
	if sarCase.DatumLatitude != nil {
		body["datum_lat_micros"] = micros(*sarCase.DatumLatitude)
		body["datum_lon_micros"] = micros(*sarCase.DatumLongitude)
		body["datum_at"] = sarCase.DatumAt.UTC().Format(time.RFC3339)
		body["datum_evidence_sha256"] = sarCase.DatumEvidenceSHA256
	}
	if sarCase.StandDownReason != "" {
		body["stand_down_reason"] = sarCase.StandDownReason
	}
	if sarCase.PersonsRecovered != nil {
		body["persons_recovered"] = *sarCase.PersonsRecovered
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return Sitrep{}, fmt.Errorf("encode sitrep body: %w", err)
	}
	bodySHA256 := envelope.DigestSHA256(bodyBytes)
	_, sealedBytes, err := envelope.Seal(store.signer, envelope.SealRequest{
		EventType:      envelope.EventSARSitrepIssued,
		AggregateKey:   caseID,
		Classification: sarCase.Classification,
		OccurredAt:     now,
		PrincipalID:    actor,
		PrincipalRole:  "sar-producer",
		Resource: map[string]any{
			"caseId": caseID, "sitrepId": sitrepID, "sequence": sequence,
			"bodyDigestSha256": bodySHA256, "phase": string(sarCase.Phase), "stage": string(sarCase.Stage),
			"classification": string(sarCase.Classification), "issuedAt": now.Format(time.RFC3339),
		},
	})
	if err != nil {
		return Sitrep{}, err
	}
	sitrep := Sitrep{
		SitrepID: sitrepID, CaseID: caseID, Sequence: sequence, Body: body,
		BodySHA256: bodySHA256, EnvelopeJWS: string(sealedBytes), IssuedBy: actor, IssuedAt: now,
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO sar_sitreps (sitrep_id, case_id, sequence, body, body_sha256, envelope_jws, issued_by, issued_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		sitrep.SitrepID, sitrep.CaseID, sitrep.Sequence, bodyBytes, sitrep.BodySHA256, sitrep.EnvelopeJWS, actor, now); err != nil {
		return Sitrep{}, fmt.Errorf("insert sitrep: %w", err)
	}
	if err := appendTimeline(ctx, tx, caseID, EntrySitrepIssued, actor, map[string]any{
		"sitrep_id": sitrep.SitrepID, "sequence": sequence, "body_sha256": bodySHA256,
	}); err != nil {
		return Sitrep{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO maritime_isr_outbox (event_id, topic, event_type, classification, aggregate_key, payload, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		uuid.New(), envelope.TopicSAR, envelope.EventSARSitrepIssued, string(sarCase.Classification), caseID, sealedBytes, now); err != nil {
		return Sitrep{}, fmt.Errorf("write sitrep outbox event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Sitrep{}, fmt.Errorf("commit sitrep issuance: %w", err)
	}
	return sitrep, nil
}

// ListSitreps returns the issued SITREPs of one case in sequence order.
func (store *Store) ListSitreps(ctx context.Context, caseID string) ([]Sitrep, error) {
	if err := validIdentifier("case_id", caseID); err != nil {
		return nil, ErrNotFound
	}
	rows, err := store.pool.Query(ctx, `
		SELECT sitrep_id, case_id, sequence, body, body_sha256, envelope_jws, issued_by, issued_at
		FROM sar_sitreps WHERE case_id=$1 ORDER BY sequence`, caseID)
	if err != nil {
		return nil, fmt.Errorf("list sitreps: %w", err)
	}
	defer rows.Close()
	sitreps := make([]Sitrep, 0)
	for rows.Next() {
		var sitrep Sitrep
		if err := rows.Scan(&sitrep.SitrepID, &sitrep.CaseID, &sitrep.Sequence, &sitrep.Body,
			&sitrep.BodySHA256, &sitrep.EnvelopeJWS, &sitrep.IssuedBy, &sitrep.IssuedAt); err != nil {
			return nil, fmt.Errorf("scan sitrep: %w", err)
		}
		sitreps = append(sitreps, sitrep)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sitreps: %w", err)
	}
	return sitreps, nil
}

// GetSitrep returns one issued SITREP.
func (store *Store) GetSitrep(ctx context.Context, caseID, sitrepID string) (Sitrep, error) {
	var sitrep Sitrep
	err := store.pool.QueryRow(ctx, `
		SELECT sitrep_id, case_id, sequence, body, body_sha256, envelope_jws, issued_by, issued_at
		FROM sar_sitreps WHERE case_id=$1 AND sitrepID=$2`, caseID, sitrepID).
		Scan(&sitrep.SitrepID, &sitrep.CaseID, &sitrep.Sequence, &sitrep.Body,
			&sitrep.BodySHA256, &sitrep.EnvelopeJWS, &sitrep.IssuedBy, &sitrep.IssuedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Sitrep{}, ErrNotFound
	}
	if err != nil {
		return Sitrep{}, fmt.Errorf("load sitrep: %w", err)
	}
	return sitrep, nil
}
