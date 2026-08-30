package sar

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/envelope"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/incident"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
)

// Store persists the SAR C2 state: cases, the append-only timeline, the SRU
// registry, tasking orders and issued SITREPs. Every state change appends
// its timeline entry and its maritime.sar.v1 outbox event in the same
// transaction, so evidence and event emission are atomic.
type Store struct {
	pool   *pgxpool.Pool
	signer *provenance.Signer
}

// NewStore binds the store to an existing pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// WithSigner attaches the provenance signer used to seal every emitted
// envelope. Emission paths fail closed when no signer is attached.
func (store *Store) WithSigner(signer *provenance.Signer) *Store {
	store.signer = signer
	return store
}

// Pool exposes the underlying pool.
func (store *Store) Pool() *pgxpool.Pool { return store.pool }

// emitEvent seals one contract envelope and appends it to the shared
// maritime_isr_outbox (topic maritime.sar.v1) inside tx; the existing isr
// outbox publisher drains it.
func (store *Store) emitEvent(ctx context.Context, tx pgx.Tx, eventType, aggregateKey string, classification isr.Classification, at time.Time, principalID, principalRole string, resource any) error {
	sealed, sealedBytes, err := envelope.Seal(store.signer, envelope.SealRequest{
		EventType:      eventType,
		AggregateKey:   aggregateKey,
		Classification: classification,
		OccurredAt:     at,
		PrincipalID:    principalID,
		PrincipalRole:  principalRole,
		Resource:       resource,
	})
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO maritime_isr_outbox (event_id, topic, event_type, classification, aggregate_key, payload, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		uuid.New(), sealed.Topic, sealed.EventType, string(classification), aggregateKey, sealedBytes, at.UTC()); err != nil {
		return fmt.Errorf("write sar outbox event: %w", err)
	}
	return nil
}

// appendTimeline inserts one append-only timeline entry inside tx.
func appendTimeline(ctx context.Context, tx pgx.Tx, caseID, entryType, actor string, detail map[string]any) error {
	if entryType == "" || actor == "" {
		return errors.New("timeline entry_type and actor are required")
	}
	if detail == nil {
		detail = map[string]any{}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO sar_case_timeline (entry_id, case_id, entry_type, actor, detail, created_at)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		uuid.New(), caseID, entryType, actor, detail, time.Now().UTC()); err != nil {
		return fmt.Errorf("append timeline entry: %w", err)
	}
	return nil
}

// caseOpenedPayload is the SarCaseOpened contract resource.
type caseOpenedPayload struct {
	CaseID             string `json:"caseId"`
	IncidentReference  string `json:"incidentReference"`
	IntakeKind         string `json:"intakeKind"`
	SourceReference    string `json:"sourceReference"`
	Phase              string `json:"phase"`
	Stage              string `json:"stage"`
	Classification     string `json:"classification"`
	PersonsAtRisk      *int   `json:"personsAtRisk,omitempty"`
	LastKnownLatMicros *int64 `json:"lastKnownLatitudeMicros,omitempty"`
	LastKnownLonMicros *int64 `json:"lastKnownLongitudeMicros,omitempty"`
	OpenedAt           string `json:"openedAt"`
}

// micros converts degrees to fixed-point micro-degrees (no floats on the
// wire), per the contract coordinate rule.
func micros(degrees float64) int64 { return int64(degrees * 1e6) }

// OpenCase registers one case anchored to an adjudicated incident record.
// MANUAL intake requires the incident to exist already; intake consumers use
// OpenCaseFromIntake after signed feed admission created the incident.
// Replay on the anchored incident returns the retained case.
func (store *Store) OpenCase(ctx context.Context, request OpenCaseRequest, createdBy string) (Case, error) {
	if err := request.Validate(); err != nil {
		return Case{}, err
	}
	if err := validIdentifier("created_by", createdBy); err != nil {
		return Case{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Case{}, fmt.Errorf("begin case open: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM maritime_incidents WHERE incident_id=$1)`, request.IncidentID).Scan(&exists); err != nil {
		return Case{}, fmt.Errorf("check incident: %w", err)
	}
	if !exists {
		return Case{}, ErrNotFound
	}
	return store.openCaseInTransaction(ctx, tx, request, IntakeManual, createdBy)
}

// OpenCaseFromIntake opens a case for a signed-intake incident (WATERWAY or
// GEO_SOS). The intake classification floor is enforced: SOS-sourced cases
// are at least RESTRICTED.
func (store *Store) OpenCaseFromIntake(ctx context.Context, request OpenCaseRequest, kind IntakeKind, intakeActor string) (Case, error) {
	if kind != IntakeWaterway && kind != IntakeGeoSOS {
		return Case{}, fmt.Errorf("%w: intake kind must be WATERWAY_EVENT or GEO_SOS", ErrValidation)
	}
	if err := request.Validate(); err != nil {
		return Case{}, err
	}
	if kind == IntakeGeoSOS {
		classification, err := isr.ParseClassification(request.Classification)
		if err != nil {
			return Case{}, err
		}
		if classification.Rank() < isr.ClassificationRestricted.Rank() {
			return Case{}, fmt.Errorf("%w: SOS-sourced cases carry a RESTRICTED classification floor", ErrValidation)
		}
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Case{}, fmt.Errorf("begin intake case open: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	return store.openCaseInTransaction(ctx, tx, request, kind, intakeActor)
}

func (store *Store) openCaseInTransaction(ctx context.Context, tx pgx.Tx, request OpenCaseRequest, kind IntakeKind, actor string) (Case, error) {
	caseID := request.CaseID
	if caseID == "" {
		caseID = "sar-" + uuid.NewString()
	}
	if err := validIdentifier("case_id", caseID); err != nil {
		return Case{}, err
	}
	phase, err := ParsePhase(request.Phase)
	if err != nil {
		return Case{}, err
	}
	classification, err := isr.ParseClassification(request.Classification)
	if err != nil {
		return Case{}, err
	}
	now := time.Now().UTC()
	newCase := Case{
		CaseID: caseID, IncidentID: request.IncidentID, Phase: phase, Stage: StageAwareness,
		Classification: classification, IntakeKind: kind, SourceRef: request.SourceRef,
		PersonsAtRisk:     request.PersonsAtRisk,
		LastKnownLatitude: request.LastKnownLatitude, LastKnownLongitude: request.LastKnownLongitude,
		LastKnownAt: request.LastKnownAt,
		CreatedBy:   actor, CreatedAt: now, UpdatedAt: now, Version: 1,
	}
	var retainedID string
	err = tx.QueryRow(ctx, `
		INSERT INTO sar_cases (case_id, incident_id, phase, stage, classification, intake_kind, source_ref,
			persons_at_risk, last_known_lat, last_known_lon, last_known_at, created_by, created_at, updated_at, version)
		VALUES ($1,$2,$3,'AWARENESS',$4,$5,$6,$7,$8,$9,$10,$11,$12,$12,1)
		ON CONFLICT (incident_id) DO NOTHING
		RETURNING case_id`,
		newCase.CaseID, newCase.IncidentID, string(phase), string(classification), string(kind), request.SourceRef,
		request.PersonsAtRisk, request.LastKnownLatitude, request.LastKnownLongitude, request.LastKnownAt,
		actor, now).Scan(&retainedID)
	if errors.Is(err, pgx.ErrNoRows) {
		var retained Case
		if loadErr := loadCaseInTransaction(ctx, tx, "", request.IncidentID, &retained); loadErr != nil {
			return Case{}, fmt.Errorf("load retained case: %w", loadErr)
		}
		if retained.IntakeKind == kind && retained.SourceRef == request.SourceRef {
			// Exact replay of the same intake event: pure idempotent replay.
			if err := tx.Commit(ctx); err != nil {
				return Case{}, fmt.Errorf("commit case replay: %w", err)
			}
			return retained, nil
		}
		// A distinct intake event anchoring the same incident correlates to
		// the retained case: recorded on the timeline, never a second case.
		if err := appendTimeline(ctx, tx, retained.CaseID, EntryCaseIntakeLinked, actor, map[string]any{
			"intake_kind": string(kind), "source_ref": request.SourceRef,
			"correlated_to": retained.CaseID,
		}); err != nil {
			return Case{}, fmt.Errorf("record intake correlation: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return Case{}, fmt.Errorf("commit intake correlation: %w", err)
		}
		return retained, nil
	}
	if err != nil {
		return Case{}, fmt.Errorf("insert sar case: %w", err)
	}
	if err := appendTimeline(ctx, tx, caseID, EntryCaseOpened, actor, map[string]any{
		"incident_id": request.IncidentID, "intake_kind": string(kind), "source_ref": request.SourceRef,
		"phase": string(phase), "classification": string(classification),
	}); err != nil {
		return Case{}, err
	}
	payload := caseOpenedPayload{
		CaseID: caseID, IncidentReference: request.IncidentID, IntakeKind: string(kind),
		SourceReference: request.SourceRef, Phase: string(phase), Stage: string(StageAwareness),
		Classification: string(classification), PersonsAtRisk: request.PersonsAtRisk,
		OpenedAt: now.Format(time.RFC3339),
	}
	if request.LastKnownLatitude != nil {
		latMicros := micros(*request.LastKnownLatitude)
		lonMicros := micros(*request.LastKnownLongitude)
		payload.LastKnownLatMicros = &latMicros
		payload.LastKnownLonMicros = &lonMicros
	}
	if err := store.emitEvent(ctx, tx, envelope.EventSARCaseOpened, caseID, classification, now, actor, "sar-producer", payload); err != nil {
		return Case{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Case{}, fmt.Errorf("commit case open: %w", err)
	}
	return newCase, nil
}

func loadCaseInTransaction(ctx context.Context, tx pgx.Tx, caseID, incidentID string, target *Case) error {
	query := `SELECT case_id, incident_id, phase, stage, classification, intake_kind, source_ref,
		persons_at_risk, last_known_lat, last_known_lon, last_known_at, datum_lat, datum_lon, datum_at,
		COALESCE(datum_evidence_sha256,''), COALESCE(stand_down_reason,''), persons_recovered,
		COALESCE(handover_ref,''), created_by, created_at, updated_at, version
		FROM sar_cases WHERE `
	args := []any{}
	if caseID != "" {
		query += `case_id=$1`
		args = append(args, caseID)
	} else {
		query += `incident_id=$1`
		args = append(args, incidentID)
	}
	query += ` FOR UPDATE`
	err := tx.QueryRow(ctx, query, args...).Scan(
		&target.CaseID, &target.IncidentID, &target.Phase, &target.Stage, &target.Classification,
		&target.IntakeKind, &target.SourceRef, &target.PersonsAtRisk, &target.LastKnownLatitude,
		&target.LastKnownLongitude, &target.LastKnownAt, &target.DatumLatitude, &target.DatumLongitude,
		&target.DatumAt, &target.DatumEvidenceSHA256, &target.StandDownReason, &target.PersonsRecovered,
		&target.HandoverRef, &target.CreatedBy, &target.CreatedAt, &target.UpdatedAt, &target.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("load case: %w", err)
	}
	return nil
}

// GetCase returns one case.
func (store *Store) GetCase(ctx context.Context, caseID string) (Case, error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return Case{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var sarCase Case
	if err := loadCaseInTransaction(ctx, tx, caseID, "", &sarCase); err != nil {
		return Case{}, err
	}
	return sarCase, tx.Commit(ctx)
}

// ListCases returns cases, optionally filtered by stage and phase.
func (store *Store) ListCases(ctx context.Context, stage, phase string) ([]Case, error) {
	if stage != "" {
		if _, err := ParseStage(stage); err != nil {
			return nil, err
		}
	}
	if phase != "" {
		if _, err := ParsePhase(phase); err != nil {
			return nil, err
		}
	}
	query := `SELECT case_id, incident_id, phase, stage, classification, intake_kind, source_ref,
		persons_at_risk, last_known_lat, last_known_lon, last_known_at, datum_lat, datum_lon, datum_at,
		COALESCE(datum_evidence_sha256,''), COALESCE(stand_down_reason,''), persons_recovered,
		COALESCE(handover_ref,''), created_by, created_at, updated_at, version
		FROM sar_cases`
	var args []any
	var filters []string
	if stage != "" {
		args = append(args, stage)
		filters = append(filters, fmt.Sprintf("stage=$%d", len(args)))
	}
	if phase != "" {
		args = append(args, phase)
		filters = append(filters, fmt.Sprintf("phase=$%d", len(args)))
	}
	if len(filters) > 0 {
		query += " WHERE " + strings.Join(filters, " AND ")
	}
	query += " ORDER BY updated_at DESC, case_id"
	rows, err := store.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list cases: %w", err)
	}
	defer rows.Close()
	cases := make([]Case, 0)
	for rows.Next() {
		var sarCase Case
		if err := rows.Scan(&sarCase.CaseID, &sarCase.IncidentID, &sarCase.Phase, &sarCase.Stage,
			&sarCase.Classification, &sarCase.IntakeKind, &sarCase.SourceRef, &sarCase.PersonsAtRisk,
			&sarCase.LastKnownLatitude, &sarCase.LastKnownLongitude, &sarCase.LastKnownAt,
			&sarCase.DatumLatitude, &sarCase.DatumLongitude, &sarCase.DatumAt,
			&sarCase.DatumEvidenceSHA256, &sarCase.StandDownReason, &sarCase.PersonsRecovered,
			&sarCase.HandoverRef, &sarCase.CreatedBy, &sarCase.CreatedAt, &sarCase.UpdatedAt, &sarCase.Version); err != nil {
			return nil, fmt.Errorf("scan case: %w", err)
		}
		cases = append(cases, sarCase)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cases: %w", err)
	}
	return cases, nil
}

// Timeline returns the append-only case timeline in fact order.
func (store *Store) Timeline(ctx context.Context, caseID string) ([]TimelineEntry, error) {
	if err := validIdentifier("case_id", caseID); err != nil {
		return nil, ErrNotFound
	}
	rows, err := store.pool.Query(ctx, `
		SELECT entry_id, case_id, entry_type, actor, detail, created_at
		FROM sar_case_timeline WHERE case_id=$1 ORDER BY created_at, entry_id`, caseID)
	if err != nil {
		return nil, fmt.Errorf("list timeline: %w", err)
	}
	defer rows.Close()
	entries := make([]TimelineEntry, 0)
	for rows.Next() {
		var entry TimelineEntry
		if err := rows.Scan(&entry.EntryID, &entry.CaseID, &entry.EntryType, &entry.Actor, &entry.Detail, &entry.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan timeline entry: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate timeline: %w", err)
	}
	return entries, nil
}

// phaseChangedPayload is the SarPhaseChanged contract resource.
type phaseChangedPayload struct {
	CaseID         string `json:"caseId"`
	PriorPhase     string `json:"priorPhase"`
	Phase          string `json:"phase"`
	Stage          string `json:"stage"`
	Rationale      string `json:"rationale"`
	Classification string `json:"classification"`
	ChangedAt      string `json:"changedAt"`
}

// TransitionPhase changes the IAMSAR phase with an operator rationale.
// Phases have no forced order (they may escalate or de-escalate as the
// situation clarifies); a same-phase signal carries no fact and is rejected.
func (store *Store) TransitionPhase(ctx context.Context, caseID string, expectedVersion int64, phase, rationale, actor string) (Case, error) {
	next, err := ParsePhase(phase)
	if err != nil {
		return Case{}, err
	}
	if strings.TrimSpace(rationale) == "" || len(rationale) > 1024 {
		return Case{}, fmt.Errorf("%w: phase changes require a rationale of at most 1024 characters", ErrValidation)
	}
	return store.transitionCase(ctx, caseID, expectedVersion, actor,
		func(current *Case) (string, map[string]any, error) {
			if current.Phase == next {
				return "", nil, ErrInvalidTransition
			}
			if current.Stage == StageStandDown {
				return "", nil, ErrInvalidTransition
			}
			prior := current.Phase
			current.Phase = next
			return EntryPhaseChanged, map[string]any{
				"prior_phase": string(prior), "phase": string(next), "rationale": rationale,
			}, nil
		},
		func(tx pgx.Tx, updated Case, at time.Time) error {
			return store.emitEvent(ctx, tx, envelope.EventSARPhaseChanged, updated.CaseID, updated.Classification, at, actor, "sar-producer", phaseChangedPayload{
				CaseID: updated.CaseID, PriorPhase: "", Phase: string(updated.Phase), Stage: string(updated.Stage),
				Rationale: rationale, Classification: string(updated.Classification), ChangedAt: at.Format(time.RFC3339),
			})
		})
}

// TransitionStage advances the operational stage (never regresses).
// STAND_DOWN requires an audited reason, and HANDED_OVER requires the
// handover reference. STAND_DOWN also emits sar.case_closed.
func (store *Store) TransitionStage(ctx context.Context, caseID string, expectedVersion int64, stage, reasonCode, actor string, personsRecovered *int, handoverRef string) (Case, error) {
	next, err := ParseStage(stage)
	if err != nil {
		return Case{}, err
	}
	var reason StandDownReason
	if next == StageStandDown {
		reason, err = ParseStandDownReason(reasonCode)
		if err != nil {
			return Case{}, err
		}
		if reason == StandDownHandedOver && strings.TrimSpace(handoverRef) == "" {
			return Case{}, fmt.Errorf("%w: HANDED_OVER requires the handover reference", ErrValidation)
		}
		if personsRecovered != nil && *personsRecovered < 0 {
			return Case{}, fmt.Errorf("%w: persons_recovered must be non-negative", ErrValidation)
		}
	}
	var priorStage Stage
	result, err := store.transitionCase(ctx, caseID, expectedVersion, actor,
		func(current *Case) (string, map[string]any, error) {
			if !ValidStageTransition(current.Stage, next) {
				return "", nil, ErrInvalidTransition
			}
			priorStage = current.Stage
			current.Stage = next
			if next == StageStandDown {
				current.StandDownReason = string(reason)
				current.PersonsRecovered = personsRecovered
				current.HandoverRef = strings.TrimSpace(handoverRef)
			}
			detail := map[string]any{"prior_stage": string(priorStage), "stage": string(next)}
			if next == StageStandDown {
				detail["stand_down_reason"] = string(reason)
				if personsRecovered != nil {
					detail["persons_recovered"] = *personsRecovered
				}
				if current.HandoverRef != "" {
					detail["handover_ref"] = current.HandoverRef
				}
			}
			return EntryStageChanged, detail, nil
		},
		func(tx pgx.Tx, updated Case, at time.Time) error {
			if err := store.emitEvent(ctx, tx, envelope.EventSARStageChanged, updated.CaseID, updated.Classification, at, actor, "sar-producer", map[string]any{
				"caseId": updated.CaseID, "priorStage": string(priorStage), "stage": string(next),
				"phase": string(updated.Phase), "classification": string(updated.Classification),
				"changedAt": at.Format(time.RFC3339),
			}); err != nil {
				return err
			}
			if next == StageStandDown {
				return store.emitEvent(ctx, tx, envelope.EventSARCaseClosed, updated.CaseID, updated.Classification, at, actor, "sar-producer", map[string]any{
					"caseId": updated.CaseID, "incidentReference": updated.IncidentID,
					"standDownReason": string(reason), "classification": string(updated.Classification),
					"closedAt": at.Format(time.RFC3339),
				})
			}
			return nil
		})
	return result, err
}

// SetDatum records the planner datum from cited evidence (never unattributed).
func (store *Store) SetDatum(ctx context.Context, caseID string, expectedVersion int64, latitude, longitude float64, evidenceSHA256, actor string) (Case, error) {
	if latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180 {
		return Case{}, fmt.Errorf("%w: datum position out of range", ErrValidation)
	}
	if !digestPattern.MatchString(evidenceSHA256) {
		return Case{}, fmt.Errorf("%w: datum requires a cited evidence digest", ErrValidation)
	}
	return store.transitionCase(ctx, caseID, expectedVersion, actor,
		func(current *Case) (string, map[string]any, error) {
			if current.Stage == StageStandDown {
				return "", nil, ErrInvalidTransition
			}
			now := time.Now().UTC()
			current.DatumLatitude = &latitude
			current.DatumLongitude = &longitude
			current.DatumAt = &now
			current.DatumEvidenceSHA256 = evidenceSHA256
			return EntryDatumSet, map[string]any{
				"datum_lat": latitude, "datum_lon": longitude, "evidence_sha256": evidenceSHA256,
			}, nil
		}, nil)
}

// transitionCase is the shared optimistic-locked case mutation: load FOR
// UPDATE, version-check, mutate, timeline, optional event, persist — all in
// one serializable transaction.
func (store *Store) transitionCase(ctx context.Context, caseID string, expectedVersion int64, actor string,
	mutate func(current *Case) (entryType string, detail map[string]any, err error),
	emit func(tx pgx.Tx, updated Case, at time.Time) error) (Case, error) {
	if expectedVersion < 1 {
		return Case{}, fmt.Errorf("%w: expected_version must be positive", ErrValidation)
	}
	if err := validIdentifier("actor", actor); err != nil {
		return Case{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Case{}, fmt.Errorf("begin case transition: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var sarCase Case
	if err := loadCaseInTransaction(ctx, tx, caseID, "", &sarCase); err != nil {
		return Case{}, err
	}
	if sarCase.Version != expectedVersion {
		return Case{}, ErrConflict
	}
	entryType, detail, err := mutate(&sarCase)
	if err != nil {
		return Case{}, err
	}
	now := time.Now().UTC()
	sarCase.UpdatedAt = now
	if _, err := tx.Exec(ctx, `
		UPDATE sar_cases SET phase=$2, stage=$3, datum_lat=$4, datum_lon=$5, datum_at=$6,
			datum_evidence_sha256=$7, stand_down_reason=$8, persons_recovered=$9, handover_ref=$10,
			updated_at=$11, version=version+1
		WHERE case_id=$1 AND version=$12`,
		sarCase.CaseID, string(sarCase.Phase), string(sarCase.Stage), sarCase.DatumLatitude, sarCase.DatumLongitude,
		sarCase.DatumAt, nullable(sarCase.DatumEvidenceSHA256), nullable(sarCase.StandDownReason),
		sarCase.PersonsRecovered, nullable(sarCase.HandoverRef), now, expectedVersion); err != nil {
		return Case{}, fmt.Errorf("update case: %w", err)
	}
	if err := appendTimeline(ctx, tx, sarCase.CaseID, entryType, actor, detail); err != nil {
		return Case{}, err
	}
	if emit != nil {
		if err := emit(tx, sarCase, now); err != nil {
			return Case{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Case{}, fmt.Errorf("commit case transition: %w", err)
	}
	sarCase.Version = expectedVersion + 1
	return sarCase, nil
}

// --- SRU registry ------------------------------------------------------------

// ResourceRegistration registers one SRU. The registry is never seeded;
// every row is operator-registered and attributed.
type ResourceRegistration struct {
	ResourceID    string         `json:"resource_id"` // optional; generated when empty
	Kind          string         `json:"kind"`
	Callsign      string         `json:"callsign"`
	Capabilities  map[string]any `json:"capabilities"`
	HomeAuthority string         `json:"home_authority"`
}

// Validate enforces the registration contract fail-closed.
func (request ResourceRegistration) Validate() error {
	if request.ResourceID != "" {
		if err := validIdentifier("resource_id", request.ResourceID); err != nil {
			return err
		}
	}
	switch ResourceKind(request.Kind) {
	case ResourceVessel, ResourceAircraft, ResourceTeam, ResourceVOO:
	default:
		return fmt.Errorf("%w: kind %q is not an SRU kind", ErrValidation, request.Kind)
	}
	if strings.TrimSpace(request.Callsign) != request.Callsign || request.Callsign == "" || len(request.Callsign) > 64 {
		return fmt.Errorf("%w: callsign must be canonical text of at most 64 characters", ErrValidation)
	}
	if request.Capabilities == nil {
		return fmt.Errorf("%w: capabilities must be a JSON object", ErrValidation)
	}
	if strings.TrimSpace(request.HomeAuthority) == "" || len(request.HomeAuthority) > 256 {
		return fmt.Errorf("%w: home_authority must be non-empty text of at most 256 characters", ErrValidation)
	}
	return nil
}

// RegisterResource records one SRU AVAILABLE. Identical re-registration is
// an idempotent replay; conflicting evidence fails closed.
func (store *Store) RegisterResource(ctx context.Context, request ResourceRegistration, registeredBy string) (Resource, error) {
	if err := request.Validate(); err != nil {
		return Resource{}, err
	}
	if err := validIdentifier("registered_by", registeredBy); err != nil {
		return Resource{}, err
	}
	resourceID := request.ResourceID
	if resourceID == "" {
		resourceID = "sru-" + uuid.NewString()
	}
	if err := validIdentifier("resource_id", resourceID); err != nil {
		return Resource{}, err
	}
	now := time.Now().UTC()
	resource := Resource{
		ResourceID: resourceID, Kind: ResourceKind(request.Kind), Callsign: request.Callsign,
		Capabilities: request.Capabilities, HomeAuthority: strings.TrimSpace(request.HomeAuthority),
		Status: ResourceAvailable, RegisteredBy: registeredBy, CreatedAt: now, UpdatedAt: now,
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return Resource{}, fmt.Errorf("begin resource registration: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var retainedID string
	err = tx.QueryRow(ctx, `
		INSERT INTO sar_resources (resource_id, kind, callsign, capabilities, home_authority, status, registered_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,'AVAILABLE',$6,$7,$7)
		ON CONFLICT (resource_id) DO NOTHING
		RETURNING resource_id`,
		resourceID, request.Kind, request.Callsign, request.Capabilities, resource.HomeAuthority, registeredBy, now).Scan(&retainedID)
	if errors.Is(err, pgx.ErrNoRows) {
		var retainedKind, retainedCallsign, retainedAuthority, retainedBy string
		if loadErr := tx.QueryRow(ctx, `SELECT kind, callsign, home_authority, registered_by FROM sar_resources WHERE resource_id=$1`,
			resourceID).Scan(&retainedKind, &retainedCallsign, &retainedAuthority, &retainedBy); loadErr != nil {
			return Resource{}, fmt.Errorf("load retained resource: %w", loadErr)
		}
		if retainedKind != request.Kind || retainedCallsign != request.Callsign ||
			retainedAuthority != resource.HomeAuthority || retainedBy != registeredBy {
			return Resource{}, ErrConflict
		}
		return resource, tx.Commit(ctx)
	}
	if err != nil {
		return Resource{}, fmt.Errorf("register resource: %w", err)
	}
	return resource, tx.Commit(ctx)
}

// ListResources returns the SRU registry, optionally filtered by status.
func (store *Store) ListResources(ctx context.Context, status string) ([]Resource, error) {
	if status != "" {
		switch ResourceStatus(status) {
		case ResourceAvailable, ResourceTasked, ResourceOffline:
		default:
			return nil, fmt.Errorf("%w: status filter must be AVAILABLE, TASKED or OFFLINE", ErrValidation)
		}
	}
	query := `SELECT resource_id, kind, callsign, capabilities, home_authority, status, registered_by, created_at, updated_at FROM sar_resources`
	var args []any
	if status != "" {
		args = append(args, status)
		query += " WHERE status=$1"
	}
	query += " ORDER BY resource_id"
	rows, err := store.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list resources: %w", err)
	}
	defer rows.Close()
	resources := make([]Resource, 0)
	for rows.Next() {
		var resource Resource
		if err := rows.Scan(&resource.ResourceID, &resource.Kind, &resource.Callsign, &resource.Capabilities,
			&resource.HomeAuthority, &resource.Status, &resource.RegisteredBy, &resource.CreatedAt, &resource.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan resource: %w", err)
		}
		resources = append(resources, resource)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate resources: %w", err)
	}
	return resources, nil
}

// SetResourceStatus moves one SRU between AVAILABLE and OFFLINE outside of
// tasking (TASKED is driven exclusively by the tasking state machine).
func (store *Store) SetResourceStatus(ctx context.Context, resourceID, status, actor string) (Resource, error) {
	var next ResourceStatus
	switch ResourceStatus(status) {
	case ResourceAvailable, ResourceOffline:
		next = ResourceStatus(status)
	default:
		return Resource{}, fmt.Errorf("%w: registry status changes are AVAILABLE or OFFLINE only", ErrValidation)
	}
	if err := validIdentifier("actor", actor); err != nil {
		return Resource{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Resource{}, fmt.Errorf("begin resource status change: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var resource Resource
	err = tx.QueryRow(ctx, `
		SELECT resource_id, kind, callsign, capabilities, home_authority, status, registered_by, created_at, updated_at
		FROM sar_resources WHERE resource_id=$1 FOR UPDATE`, resourceID).
		Scan(&resource.ResourceID, &resource.Kind, &resource.Callsign, &resource.Capabilities,
			&resource.HomeAuthority, &resource.Status, &resource.RegisteredBy, &resource.CreatedAt, &resource.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Resource{}, ErrNotFound
	}
	if err != nil {
		return Resource{}, fmt.Errorf("load resource: %w", err)
	}
	if resource.Status == ResourceTasked {
		return Resource{}, fmt.Errorf("%w: a TASKED resource changes status only through its tasking", ErrInvalidTransition)
	}
	if resource.Status == next {
		return resource, tx.Commit(ctx) // idempotent replay
	}
	if _, err := tx.Exec(ctx, `UPDATE sar_resources SET status=$2, updated_at=$3 WHERE resource_id=$1`,
		resourceID, string(next), time.Now().UTC()); err != nil {
		return Resource{}, fmt.Errorf("update resource status: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Resource{}, fmt.Errorf("commit resource status change: %w", err)
	}
	resource.Status = next
	return resource, nil
}

// --- tasking --------------------------------------------------------------

// TaskingRequest proposes one tasking order (IAMSAR App H briefing fields).
type TaskingRequest struct {
	TaskingID  string         `json:"tasking_id"` // optional; generated when empty
	ResourceID string         `json:"resource_id"`
	Task       string         `json:"task"`
	Briefing   map[string]any `json:"briefing"`
}

// Validate enforces the tasking contract fail-closed.
func (request TaskingRequest) Validate() error {
	if request.TaskingID != "" {
		if err := validIdentifier("tasking_id", request.TaskingID); err != nil {
			return err
		}
	}
	if err := validIdentifier("resource_id", request.ResourceID); err != nil {
		return err
	}
	switch Task(request.Task) {
	case TaskSearchPattern, TaskInvestigate, TaskRescue, TaskRelay, TaskMedevac, TaskOther:
	default:
		return fmt.Errorf("%w: task %q is not a tasking task type", ErrValidation, request.Task)
	}
	if request.Briefing == nil {
		return fmt.Errorf("%w: briefing must carry the IAMSAR App H briefing fields", ErrValidation)
	}
	return nil
}

// ProposeTasking records a PROPOSED tasking on a non-closed case.
func (store *Store) ProposeTasking(ctx context.Context, caseID string, request TaskingRequest, actor string) (Tasking, error) {
	if err := request.Validate(); err != nil {
		return Tasking{}, err
	}
	if err := validIdentifier("actor", actor); err != nil {
		return Tasking{}, err
	}
	taskingID := request.TaskingID
	if taskingID == "" {
		taskingID = "tsk-" + uuid.NewString()
	}
	if err := validIdentifier("tasking_id", taskingID); err != nil {
		return Tasking{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Tasking{}, fmt.Errorf("begin tasking proposal: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var sarCase Case
	if err := loadCaseInTransaction(ctx, tx, caseID, "", &sarCase); err != nil {
		return Tasking{}, err
	}
	if sarCase.Stage == StageStandDown {
		return Tasking{}, ErrInvalidTransition
	}
	var resourceStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM sar_resources WHERE resource_id=$1 FOR SHARE`, request.ResourceID).Scan(&resourceStatus); errors.Is(err, pgx.ErrNoRows) {
		return Tasking{}, ErrNotFound
	} else if err != nil {
		return Tasking{}, fmt.Errorf("load resource: %w", err)
	}
	if resourceStatus != string(ResourceAvailable) {
		return Tasking{}, fmt.Errorf("%w: resource is not AVAILABLE", ErrInvalidTransition)
	}
	now := time.Now().UTC()
	tasking := Tasking{
		TaskingID: taskingID, CaseID: caseID, ResourceID: request.ResourceID,
		Task: Task(request.Task), Briefing: request.Briefing, State: TaskingProposed,
		TaskedBy: actor, CreatedAt: now, UpdatedAt: now, Version: 1,
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO sar_taskings (tasking_id, case_id, resource_id, task, briefing, state, tasked_by, created_at, updated_at, version)
		VALUES ($1,$2,$3,$4,$5,'PROPOSED',$6,$7,$7,1)`,
		taskingID, caseID, request.ResourceID, request.Task, request.Briefing, actor, now); err != nil {
		return Tasking{}, fmt.Errorf("insert tasking: %w", err)
	}
	if err := appendTimeline(ctx, tx, caseID, EntryTaskingProposed, actor, map[string]any{
		"tasking_id": taskingID, "resource_id": request.ResourceID, "task": request.Task,
	}); err != nil {
		return Tasking{}, err
	}
	if err := store.emitTaskingTransition(ctx, tx, sarCase, tasking, "", TaskingProposed, "", now, actor); err != nil {
		return Tasking{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Tasking{}, fmt.Errorf("commit tasking proposal: %w", err)
	}
	return tasking, nil
}

func (store *Store) emitTaskingTransition(ctx context.Context, tx pgx.Tx, sarCase Case, tasking Tasking, prior, next TaskingState, reasonCode string, at time.Time, actor string) error {
	return store.emitEvent(ctx, tx, envelope.EventSARTaskingChanged, sarCase.CaseID, sarCase.Classification, at, actor, "sar-producer", map[string]any{
		"caseId": sarCase.CaseID, "taskingId": tasking.TaskingID, "resourceId": tasking.ResourceID,
		"task": string(tasking.Task), "priorState": string(prior), "state": string(next),
		"transitionReasonCode": reasonCode, "changedAt": at.Format(time.RFC3339),
	})
}

// TransitionTasking applies one tasking transition with a transition-legal
// reason code; TASKED marks the SRU TASKED, RELEASED/ABORTED return it to
// AVAILABLE.
func (store *Store) TransitionTasking(ctx context.Context, caseID, taskingID string, expectedVersion int64, state, reasonCode, actor string) (Tasking, error) {
	next := TaskingState(state)
	if err := TaskingTransitionReason(next, reasonCode); err != nil {
		return Tasking{}, err
	}
	if err := validIdentifier("actor", actor); err != nil {
		return Tasking{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Tasking{}, fmt.Errorf("begin tasking transition: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var sarCase Case
	if err := loadCaseInTransaction(ctx, tx, caseID, "", &sarCase); err != nil {
		return Tasking{}, err
	}
	var tasking Tasking
	var ackedBy *string
	err = tx.QueryRow(ctx, `
		SELECT tasking_id, case_id, resource_id, task, briefing, state, tasked_by, acked_by, created_at, updated_at, version
		FROM sar_taskings WHERE tasking_id=$1 AND case_id=$2 FOR UPDATE`, taskingID, caseID).
		Scan(&tasking.TaskingID, &tasking.CaseID, &tasking.ResourceID, &tasking.Task, &tasking.Briefing,
			&tasking.State, &tasking.TaskedBy, &ackedBy, &tasking.CreatedAt, &tasking.UpdatedAt, &tasking.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return Tasking{}, ErrNotFound
	}
	if err != nil {
		return Tasking{}, fmt.Errorf("load tasking: %w", err)
	}
	if ackedBy != nil {
		tasking.AckedBy = *ackedBy
	}
	if tasking.Version != expectedVersion {
		return Tasking{}, ErrConflict
	}
	if !ValidTaskingTransition(tasking.State, next) {
		return Tasking{}, ErrInvalidTransition
	}
	prior := tasking.State
	now := time.Now().UTC()
	var newAckedBy any
	if tasking.AckedBy != "" {
		newAckedBy = tasking.AckedBy
	}
	if next == TaskingAcked {
		newAckedBy = actor
		tasking.AckedBy = actor
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sar_taskings SET state=$2, acked_by=$3, updated_at=$4, version=version+1
		WHERE tasking_id=$1 AND version=$5`,
		taskingID, string(next), newAckedBy, now, expectedVersion); err != nil {
		return Tasking{}, fmt.Errorf("update tasking: %w", err)
	}
	// Keep the registry consistent: TASKED marks the SRU; RELEASED/ABORTED
	// free it.
	var newResourceStatus ResourceStatus
	switch next {
	case TaskingTasked:
		newResourceStatus = ResourceTasked
	case TaskingReleased, TaskingAborted:
		newResourceStatus = ResourceAvailable
	}
	if newResourceStatus != "" {
		if _, err := tx.Exec(ctx, `UPDATE sar_resources SET status=$2, updated_at=$3 WHERE resource_id=$1`,
			tasking.ResourceID, string(newResourceStatus), now); err != nil {
			return Tasking{}, fmt.Errorf("update resource status for tasking: %w", err)
		}
	}
	entryTypeByState := map[TaskingState]string{
		TaskingTasked: EntryTaskingTasked, TaskingAcked: EntryTaskingAcked,
		TaskingOnScene: EntryTaskingOnScene, TaskingReleased: EntryTaskingReleased,
		TaskingAborted: EntryTaskingAborted,
	}
	if err := appendTimeline(ctx, tx, caseID, entryTypeByState[next], actor, map[string]any{
		"tasking_id": taskingID, "resource_id": tasking.ResourceID, "prior_state": string(prior),
		"state": string(next), "reason_code": reasonCode,
	}); err != nil {
		return Tasking{}, err
	}
	tasking.State = next
	tasking.UpdatedAt = now
	if err := store.emitTaskingTransition(ctx, tx, sarCase, tasking, prior, next, reasonCode, now, actor); err != nil {
		return Tasking{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Tasking{}, fmt.Errorf("commit tasking transition: %w", err)
	}
	tasking.Version = expectedVersion + 1
	return tasking, nil
}

// ListTaskings returns the tasking orders of one case.
func (store *Store) ListTaskings(ctx context.Context, caseID string) ([]Tasking, error) {
	if err := validIdentifier("case_id", caseID); err != nil {
		return nil, ErrNotFound
	}
	rows, err := store.pool.Query(ctx, `
		SELECT tasking_id, case_id, resource_id, task, briefing, state, tasked_by, COALESCE(acked_by,''),
			created_at, updated_at, version
		FROM sar_taskings WHERE case_id=$1 ORDER BY created_at, tasking_id`, caseID)
	if err != nil {
		return nil, fmt.Errorf("list taskings: %w", err)
	}
	defer rows.Close()
	taskings := make([]Tasking, 0)
	for rows.Next() {
		var tasking Tasking
		if err := rows.Scan(&tasking.TaskingID, &tasking.CaseID, &tasking.ResourceID, &tasking.Task,
			&tasking.Briefing, &tasking.State, &tasking.TaskedBy, &tasking.AckedBy,
			&tasking.CreatedAt, &tasking.UpdatedAt, &tasking.Version); err != nil {
			return nil, fmt.Errorf("scan tasking: %w", err)
		}
		taskings = append(taskings, tasking)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate taskings: %w", err)
	}
	return taskings, nil
}

// MirrorSOSAcknowledge appends the geo SOS acknowledgement fact to a
// GEO_SOS-sourced case timeline. geo-service remains the system of record;
// this store only mirrors an ack that geo-service already accepted (the
// caller performs the geo call first and fails closed when geo-service is
// unconfigured).
func (store *Store) MirrorSOSAcknowledge(ctx context.Context, caseID, sosRef, actor string) error {
	return store.mirrorSOS(ctx, caseID, sosRef, actor, EntrySOSAcknowledged)
}

// MirrorSOSResolve appends the geo SOS resolution fact.
func (store *Store) MirrorSOSResolve(ctx context.Context, caseID, sosRef, actor string) error {
	return store.mirrorSOS(ctx, caseID, sosRef, actor, EntrySOSResolved)
}

func (store *Store) mirrorSOS(ctx context.Context, caseID, sosRef, actor, entryType string) error {
	if strings.TrimSpace(sosRef) == "" || len(sosRef) > 256 {
		return fmt.Errorf("%w: sos reference must be non-empty text of at most 256 characters", ErrValidation)
	}
	if err := validIdentifier("actor", actor); err != nil {
		return err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin sos mirror: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var sarCase Case
	if err := loadCaseInTransaction(ctx, tx, caseID, "", &sarCase); err != nil {
		return err
	}
	if sarCase.IntakeKind != IntakeGeoSOS {
		return fmt.Errorf("%w: sos lifecycle mirrors apply to GEO_SOS-sourced cases only", ErrValidation)
	}
	if sarCase.SourceRef != sosRef {
		return fmt.Errorf("%w: sos reference does not match the case source", ErrValidation)
	}
	if err := appendTimeline(ctx, tx, caseID, entryType, actor, map[string]any{"sos_ref": sosRef}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// referenced to keep the incident import used by intake helpers
var _ = incident.ErrNotFound
