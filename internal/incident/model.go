package incident

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

type Severity string
type Status string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"

	StatusOpen          Status = "OPEN"
	StatusAcknowledged  Status = "ACKNOWLEDGED"
	StatusInvestigating Status = "INVESTIGATING"
	StatusResolved      Status = "RESOLVED"
	StatusClosed        Status = "CLOSED"
)

var (
	ErrIdempotencyConflict = errors.New("source event conflicts with retained incident")
	ErrNotFound            = errors.New("incident not found")
	ErrInvalidTransition   = errors.New("invalid incident transition")
	ErrOptimisticConflict  = errors.New("incident changed concurrently")
	ErrCorrelationConflict = errors.New("spatial correlation conflicts with retained evidence")
)

var incidentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type CreateRequest struct {
	IncidentID    string    `json:"incident_id"`
	SourceEventID string    `json:"source_event_id"`
	Category      string    `json:"category"`
	Severity      Severity  `json:"severity"`
	Title         string    `json:"title"`
	Description   string    `json:"description"`
	OccurredAt    time.Time `json:"occurred_at"`
	CreatedBy     string    `json:"created_by"`
}

type Incident struct {
	CreateRequest
	Status    Status    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Version   int64     `json:"version"`
}

type CorrelationRequest struct {
	GeofenceID     string  `json:"geofence_id"`
	Relation       string  `json:"relation"`
	Latitude       float64 `json:"latitude"`
	Longitude      float64 `json:"longitude"`
	EvidenceSHA256 string  `json:"evidence_sha256"`
	CorrelatedBy   string  `json:"correlated_by"`
}

type SpatialCorrelation struct {
	CorrelationID  string    `json:"correlation_id"`
	IncidentID     string    `json:"incident_id"`
	GeofenceID     string    `json:"geofence_id"`
	Relation       string    `json:"relation"`
	Latitude       float64   `json:"latitude"`
	Longitude      float64   `json:"longitude"`
	EvidenceSHA256 string    `json:"evidence_sha256"`
	CorrelatedBy   string    `json:"correlated_by"`
	CreatedAt      time.Time `json:"created_at"`
}

type AssignmentRequest struct {
	ExpectedVersion int64  `json:"expected_version"`
	AnalystID       string `json:"analyst_id"`
	AssignedBy      string `json:"assigned_by"`
}

type AnalystAssignment struct {
	IncidentID      string    `json:"incident_id"`
	AnalystID       string    `json:"analyst_id"`
	AssignedBy      string    `json:"assigned_by"`
	AssignedAt      time.Time `json:"assigned_at"`
	IncidentVersion int64     `json:"incident_version"`
}

func (request CorrelationRequest) Validate() error {
	for name, value := range map[string]string{
		"geofence_id": request.GeofenceID, "relation": request.Relation,
		"evidence_sha256": request.EvidenceSHA256, "correlated_by": request.CorrelatedBy,
	} {
		if value == "" || strings.TrimSpace(value) != value || len(value) > 256 {
			return fmt.Errorf("%s must be canonical non-empty text of at most 256 characters", name)
		}
	}
	if request.Relation != "INSIDE" && request.Relation != "OUTSIDE" && request.Relation != "BOUNDARY" {
		return errors.New("relation is not supported")
	}
	if !strings.HasPrefix(request.EvidenceSHA256, "sha256:") || len(request.EvidenceSHA256) != 71 {
		return errors.New("evidence_sha256 must be sha256: followed by 64 hexadecimal characters")
	}
	for _, character := range request.EvidenceSHA256[7:] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return errors.New("evidence_sha256 must use lowercase hexadecimal")
		}
	}
	if !isFiniteCoordinate(request.Latitude, request.Longitude) {
		return errors.New("coordinates must be finite latitude/longitude values")
	}
	return nil
}

func (request AssignmentRequest) Validate() error {
	if request.ExpectedVersion < 1 {
		return errors.New("expected_version must be positive")
	}
	for name, value := range map[string]string{"analyst_id": request.AnalystID, "assigned_by": request.AssignedBy} {
		if value == "" || strings.TrimSpace(value) != value || len(value) > 256 || !incidentIDPattern.MatchString(value) {
			return fmt.Errorf("%s must be a canonical analyst identifier", name)
		}
	}
	if request.AnalystID == request.AssignedBy {
		return errors.New("analyst and assigning principal must be distinct")
	}
	return nil
}

func isFiniteCoordinate(latitude, longitude float64) bool {
	return !math.IsNaN(latitude) && !math.IsInf(latitude, 0) && latitude >= -90 && latitude <= 90 &&
		!math.IsNaN(longitude) && !math.IsInf(longitude, 0) && longitude >= -180 && longitude <= 180
}

func (request CreateRequest) Validate() error {
	for name, value := range map[string]string{
		"incident_id":     request.IncidentID,
		"source_event_id": request.SourceEventID,
		"category":        request.Category,
		"title":           request.Title,
		"description":     request.Description,
		"created_by":      request.CreatedBy,
	} {
		if value == "" || strings.TrimSpace(value) != value || len(value) > 4096 {
			return fmt.Errorf("%s must be canonical non-empty text of at most 4096 characters", name)
		}
	}
	if !incidentIDPattern.MatchString(request.IncidentID) || !incidentIDPattern.MatchString(request.SourceEventID) {
		return errors.New("incident_id and source_event_id contain unsupported characters")
	}
	if request.Severity != SeverityLow && request.Severity != SeverityMedium && request.Severity != SeverityHigh && request.Severity != SeverityCritical {
		return errors.New("severity is not supported")
	}
	if request.OccurredAt.IsZero() {
		return errors.New("occurred_at must be RFC3339")
	}
	return nil
}

func (incident Incident) Matches(request CreateRequest) bool {
	return incident.IncidentID == request.IncidentID && incident.SourceEventID == request.SourceEventID &&
		incident.Category == request.Category && incident.Severity == request.Severity &&
		incident.Title == request.Title && incident.Description == request.Description &&
		incident.OccurredAt.Equal(request.OccurredAt) && incident.CreatedBy == request.CreatedBy
}

func ValidTransition(current, next Status) bool {
	switch current {
	case StatusOpen:
		return next == StatusAcknowledged || next == StatusResolved
	case StatusAcknowledged:
		return next == StatusInvestigating || next == StatusResolved
	case StatusInvestigating:
		return next == StatusResolved
	case StatusResolved:
		return next == StatusClosed
	default:
		return false
	}
}
