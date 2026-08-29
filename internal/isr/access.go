package isr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Cross-agency roles recognised by the Deep Blue Project ISR service. Role
// membership is asserted by the Keycloak token (or the trusted local edge in
// loopback_trusted_proxy mode) and enforced fail-closed.
const (
	RoleNIMASAOfficer     = "nimasa-officer"
	RoleDefenceHQObserver = "defence-hq-observer"
	RoleNNOfficer         = "nn-officer"
	RoleONSAObserver      = "onsa-observer"
	RoleMarinePolice      = "marine-police"
	RoleFleetOperator     = "fleet-operator"
	RoleInsurerAggregator = "insurer-aggregator"
	RoleAuditor           = "auditor"
	// Mutation roles provisioned by the IdP for the Deep Blue ISR mission
	// (Phase-6 remediation). Every mutating route is gated on exactly one of
	// these (see the authoritative table in internal/server/access.go); the
	// legacy cross-agency roles above retain their read rights only.
	RoleISRAdmin        = "isr-admin"
	RoleISRFeedIngest   = "isr-feed-ingest"
	RoleISRAnalyst      = "isr-analyst"
	RoleISRWatchOfficer = "isr-watch-officer"
	RoleISRAdjudicator  = "isr-adjudicator"
)

// mutatingRoles is the authoritative allow-list: a principal is read-only
// unless it holds at least one of these recognized roles. (There is no
// "read-only roles" deny-list — unrecognized roles fail closed by absence.)
// mutatingRoles may perform at least one mutating call (the per-route role
// gate still applies on top). Any role absent from this set is read-only:
// IsReadOnly fails closed on unrecognized roles.
var mutatingRoles = map[string]struct{}{
	RoleNIMASAOfficer: {}, RoleNNOfficer: {}, RoleMarinePolice: {}, RoleFleetOperator: {},
	RoleISRAdmin: {}, RoleISRFeedIngest: {}, RoleISRAnalyst: {},
	RoleISRWatchOfficer: {}, RoleISRAdjudicator: {},
}

// trackReaderRoles may read vessel tracks and detections (subject to
// clearance). The insurer-aggregator is deliberately absent: it sees only
// outcome aggregates, never tracks.
var trackReaderRoles = map[string]struct{}{
	RoleNIMASAOfficer: {}, RoleDefenceHQObserver: {}, RoleNNOfficer: {},
	RoleONSAObserver: {}, RoleMarinePolice: {}, RoleFleetOperator: {}, RoleAuditor: {},
	RoleISRAnalyst: {}, RoleISRWatchOfficer: {},
}

// outcomeAggregateReaderRoles may read outcome aggregates.
var outcomeAggregateReaderRoles = map[string]struct{}{
	RoleNIMASAOfficer: {}, RoleDefenceHQObserver: {}, RoleNNOfficer: {},
	RoleONSAObserver: {}, RoleMarinePolice: {}, RoleFleetOperator: {},
	RoleInsurerAggregator: {}, RoleAuditor: {},
	RoleISRAnalyst: {}, RoleISRWatchOfficer: {}, RoleISRAdjudicator: {},
}

// Principal is the verified caller: subject, approved roles and clearance.
type Principal struct {
	Subject   string
	Roles     map[string]struct{}
	Clearance Classification
}

// HasRole reports whether the principal holds the role.
func (principal Principal) HasRole(role string) bool {
	_, ok := principal.Roles[role]
	return ok
}

// HasAnyRole reports whether the principal holds at least one of the roles.
func (principal Principal) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if principal.HasRole(role) {
			return true
		}
	}
	return false
}

// IsReadOnly reports whether the principal holds no recognized mutating
// role. Fail-closed: an absent, garbage or mistyped role is NOT in
// mutatingRoles, so the principal is read-only and every mutation is denied.
func (principal Principal) IsReadOnly() bool {
	for role := range principal.Roles {
		if _, mutating := mutatingRoles[role]; mutating {
			return false
		}
	}
	return true
}

// CanReadTracks enforces role + clearance for track/detection reads. The
// insurer-aggregator is denied tracks regardless of clearance.
func (principal Principal) CanReadTracks(eventClassification Classification) error {
	allowed := false
	for role := range principal.Roles {
		if _, ok := trackReaderRoles[role]; ok {
			allowed = true
			break
		}
	}
	if !allowed {
		return ErrForbidden
	}
	if principal.HasRole(RoleInsurerAggregator) && len(principal.Roles) == 1 {
		return ErrForbidden
	}
	if !principal.Clearance.Covers(eventClassification) {
		return ErrForbidden
	}
	return nil
}

// CanReadOutcomeAggregates enforces the aggregate-read role set. Outcome
// aggregates carry no track data, so all recognised roles may read them.
func (principal Principal) CanReadOutcomeAggregates() error {
	for role := range principal.Roles {
		if _, ok := outcomeAggregateReaderRoles[role]; ok {
			return nil
		}
	}
	return ErrForbidden
}

// clearanceCeiling returns the highest classification the principal may read;
// the SQL filter then constrains on the covered label set.
func (principal Principal) clearanceCeiling() (Classification, error) {
	if _, err := ParseClassification(string(principal.Clearance)); err != nil {
		return "", ErrForbidden
	}
	return principal.Clearance, nil
}

// coveredLabels lists the labels at or below the principal's clearance for
// classification-scoped SQL filters.
func coveredLabels(ceiling Classification) []string {
	labels := []string{}
	for _, label := range []Classification{ClassificationUnclassified, ClassificationRestricted, ClassificationConfidential, ClassificationSecret} {
		if ceiling.Covers(label) {
			labels = append(labels, string(label))
		}
	}
	return labels
}

// DetectionFilter scopes a clearance-filtered detection listing.
type DetectionFilter struct {
	Modality Modality
	MMSI     string
	Since    time.Time
	Limit    int
}

// ListDetections returns detections at or below the principal's clearance.
// Fail-closed: a principal without a track-reader role or with an invalid
// clearance receives ErrForbidden and no rows.
func (store *Store) ListDetections(ctx context.Context, principal Principal, filter DetectionFilter) ([]Detection, error) {
	if err := principal.CanReadTracks(ClassificationUnclassified); err != nil {
		return nil, err
	}
	ceiling, err := principal.clearanceCeiling()
	if err != nil {
		return nil, err
	}
	if filter.Limit <= 0 || filter.Limit > 500 {
		filter.Limit = 500
	}
	labels := coveredLabels(ceiling)
	query := `SELECT payload FROM maritime_isr_events WHERE classification = ANY($1)`
	args := []any{labels}
	if filter.Modality != "" {
		args = append(args, string(filter.Modality))
		query += fmt.Sprintf(" AND modality = $%d", len(args))
	}
	if filter.MMSI != "" {
		args = append(args, filter.MMSI)
		query += fmt.Sprintf(" AND mmsi = $%d", len(args))
	}
	if !filter.Since.IsZero() {
		args = append(args, filter.Since)
		query += fmt.Sprintf(" AND observed_at >= $%d", len(args))
	}
	args = append(args, filter.Limit)
	query += fmt.Sprintf(" ORDER BY observed_at DESC LIMIT $%d", len(args))
	rows, err := store.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list detections: %w", err)
	}
	defer rows.Close()
	detections := make([]Detection, 0)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan detection: %w", err)
		}
		detection, err := DecodeDetection(payload)
		if err != nil {
			return nil, fmt.Errorf("decode retained detection: %w", err)
		}
		// Defence in depth: the SQL filter already constrained on
		// classification; re-check every row against the clearance.
		if err := principal.CanReadTracks(detection.Classification); err != nil {
			return nil, err
		}
		detections = append(detections, detection)
	}
	return detections, rows.Err()
}

// AnomalyFilter scopes a clearance-filtered anomaly listing.
type AnomalyFilter struct {
	Kind  string
	Since time.Time
	Limit int
}

// RetainedAnomaly is one persisted behaviour anomaly.
type RetainedAnomaly struct {
	AnomalyID       string         `json:"anomaly_id"`
	Kind            string         `json:"kind"`
	Classification  Classification `json:"classification"`
	TrackIDs        []string       `json:"track_ids"`
	ZoneID          string         `json:"zone_id,omitempty"`
	Detail          string         `json:"detail"`
	CorrelationRefs []string       `json:"correlation_refs,omitempty"`
	DetectedAt      time.Time      `json:"detected_at"`
}

// ListAnomalies returns anomalies at or below the principal's clearance.
func (store *Store) ListAnomalies(ctx context.Context, principal Principal, filter AnomalyFilter) ([]RetainedAnomaly, error) {
	if err := principal.CanReadTracks(ClassificationUnclassified); err != nil {
		return nil, err
	}
	ceiling, err := principal.clearanceCeiling()
	if err != nil {
		return nil, err
	}
	if filter.Limit <= 0 || filter.Limit > 500 {
		filter.Limit = 500
	}
	labels := coveredLabels(ceiling)
	query := `SELECT anomaly_id, kind, classification, track_ids, COALESCE(zone_id,''), detail, correlation_refs, detected_at FROM maritime_behaviour_anomalies WHERE classification = ANY($1)`
	args := []any{labels}
	if filter.Kind != "" {
		args = append(args, filter.Kind)
		query += fmt.Sprintf(" AND kind = $%d", len(args))
	}
	if !filter.Since.IsZero() {
		args = append(args, filter.Since)
		query += fmt.Sprintf(" AND detected_at >= $%d", len(args))
	}
	args = append(args, filter.Limit)
	query += fmt.Sprintf(" ORDER BY detected_at DESC LIMIT $%d", len(args))
	rows, err := store.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list anomalies: %w", err)
	}
	defer rows.Close()
	anomalies := make([]RetainedAnomaly, 0)
	for rows.Next() {
		var anomaly RetainedAnomaly
		var trackIDs, correlationRefs []byte
		if err := rows.Scan(&anomaly.AnomalyID, &anomaly.Kind, &anomaly.Classification, &trackIDs, &anomaly.ZoneID, &anomaly.Detail, &correlationRefs, &anomaly.DetectedAt); err != nil {
			return nil, fmt.Errorf("scan anomaly: %w", err)
		}
		if err := json.Unmarshal(trackIDs, &anomaly.TrackIDs); err != nil {
			return nil, fmt.Errorf("decode anomaly track ids: %w", err)
		}
		if len(correlationRefs) > 0 {
			if err := json.Unmarshal(correlationRefs, &anomaly.CorrelationRefs); err != nil {
				return nil, fmt.Errorf("decode anomaly correlation refs: %w", err)
			}
		}
		if err := principal.CanReadTracks(anomaly.Classification); err != nil {
			return nil, err
		}
		anomalies = append(anomalies, anomaly)
	}
	return anomalies, rows.Err()
}

// OutcomeAggregate is one classification-free aggregate row for insurer and
// oversight consumption: counts and totals only, never track data.
type OutcomeAggregate struct {
	EntryKind string    `json:"entry_kind"`
	Metric    string    `json:"metric"`
	Unit      string    `json:"unit"`
	Entries   int64     `json:"entries"`
	Total     int64     `json:"total"`
	LatestAt  time.Time `json:"latest_confirmed_at"`
}

// OutcomeAggregates returns aggregated confirmed outcome-ledger evidence.
// This is the only ISR read path open to the insurer-aggregator role.
func (store *Store) OutcomeAggregates(ctx context.Context, principal Principal) ([]OutcomeAggregate, error) {
	if err := principal.CanReadOutcomeAggregates(); err != nil {
		return nil, err
	}
	rows, err := store.pool.Query(ctx, `
		SELECT entry_kind, metric, unit, count(*), COALESCE(sum(quantity),0), max(confirmed_at)
		FROM maritime_outcome_ledger_entries
		GROUP BY entry_kind, metric, unit
		ORDER BY entry_kind`)
	if err != nil {
		return nil, fmt.Errorf("outcome aggregates: %w", err)
	}
	defer rows.Close()
	aggregates := make([]OutcomeAggregate, 0)
	for rows.Next() {
		var aggregate OutcomeAggregate
		if err := rows.Scan(&aggregate.EntryKind, &aggregate.Metric, &aggregate.Unit, &aggregate.Entries, &aggregate.Total, &aggregate.LatestAt); err != nil {
			return nil, fmt.Errorf("scan outcome aggregate: %w", err)
		}
		aggregates = append(aggregates, aggregate)
	}
	return aggregates, rows.Err()
}

// LoadFeedSourceActive reports whether a feed source exists and is active.
func (store *Store) LoadFeedSourceActive(ctx context.Context, sourceID string) (bool, error) {
	var active bool
	err := store.pool.QueryRow(ctx, `SELECT active FROM maritime_feed_sources WHERE source_id=$1`, sourceID).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("load feed source: %w", err)
	}
	return active, nil
}
