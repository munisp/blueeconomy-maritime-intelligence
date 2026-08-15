package incident

import (
	"errors"
	"fmt"
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
