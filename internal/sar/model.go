// Package sar implements the SAR C2 case engine: IAMSAR-informed emergency
// phases (INCERFA/ALERFA/DETRESFA) and operational stages
// (AWARENESS→…→STAND_DOWN), an SRU registry with tasking, numbered immutable
// signed SITREPs, and signed intake from the waterway-safety event stream
// and the geo SOS stream. Every intake, phase, stage, tasking and SITREP
// fact lands on the append-only case timeline; every state change emits a
// signed envelope onto maritime.sar.v1 through the transactional outbox.
//
// Fail-closed everywhere: unknown phases/stages/transitions are rejected,
// classification floors are enforced (RESTRICTED minimum for SOS-sourced
// cases), datum is never set without cited evidence, and nothing is
// fabricated or simulated.
package sar

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

var (
	// ErrNotFound is returned when a referenced record does not exist.
	ErrNotFound = errors.New("sar record not found")
	// ErrConflict is returned on idempotency/optimistic-version conflicts.
	ErrConflict = errors.New("sar record conflicts with retained evidence")
	// ErrInvalidTransition is returned for illegal state-machine moves.
	ErrInvalidTransition = errors.New("invalid sar state transition")
	// ErrValidation is returned for contract violations.
	ErrValidation = errors.New("sar validation failed")
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func validIdentifier(name, value string) error {
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("%w: %s must be a canonical identifier", ErrValidation, name)
	}
	return nil
}

// Phase is the IAMSAR emergency phase (uncertainty/alert/distress).
type Phase string

const (
	PhaseIncerfa  Phase = "INCERFA"
	PhaseAlerfa   Phase = "ALERFA"
	PhaseDetresfa Phase = "DETRESFA"
)

// ParsePhase validates a phase fail-closed.
func ParsePhase(raw string) (Phase, error) {
	switch Phase(raw) {
	case PhaseIncerfa, PhaseAlerfa, PhaseDetresfa:
		return Phase(raw), nil
	default:
		return "", fmt.Errorf("%w: phase %q is not an IAMSAR emergency phase", ErrValidation, raw)
	}
}

// Stage is the operational stage of a case.
type Stage string

const (
	StageAwareness     Stage = "AWARENESS"
	StageInitialAction Stage = "INITIAL_ACTION"
	StageCoordination  Stage = "COORDINATION"
	StageStandDown     Stage = "STAND_DOWN"
)

// ParseStage validates a stage fail-closed.
func ParseStage(raw string) (Stage, error) {
	switch Stage(raw) {
	case StageAwareness, StageInitialAction, StageCoordination, StageStandDown:
		return Stage(raw), nil
	default:
		return "", fmt.Errorf("%w: stage %q is not a SAR operational stage", ErrValidation, raw)
	}
}

// ValidStageTransition enforces AWARENESS→INITIAL_ACTION→COORDINATION→
// STAND_DOWN; a stage may never regress. Same-stage signals are rejected
// (they carry no fact).
func ValidStageTransition(current, next Stage) bool {
	switch current {
	case StageAwareness:
		return next == StageInitialAction || next == StageCoordination || next == StageStandDown
	case StageInitialAction:
		return next == StageCoordination || next == StageStandDown
	case StageCoordination:
		return next == StageStandDown
	default:
		return false // STAND_DOWN is terminal
	}
}

// IntakeKind is the provenance of a case; exactly one origin.
type IntakeKind string

const (
	IntakeWaterway IntakeKind = "WATERWAY_EVENT"
	IntakeGeoSOS   IntakeKind = "GEO_SOS"
	IntakeManual   IntakeKind = "MANUAL"
)

// StandDownReason is the audited closure reason.
type StandDownReason string

const (
	StandDownResolved   StandDownReason = "RESOLVED"
	StandDownSuspended  StandDownReason = "SUSPENDED"
	StandDownFalseAlert StandDownReason = "FALSE_ALERT"
	StandDownHandedOver StandDownReason = "HANDED_OVER"
)

// ParseStandDownReason validates a closure reason fail-closed.
func ParseStandDownReason(raw string) (StandDownReason, error) {
	switch StandDownReason(raw) {
	case StandDownResolved, StandDownSuspended, StandDownFalseAlert, StandDownHandedOver:
		return StandDownReason(raw), nil
	default:
		return "", fmt.Errorf("%w: stand-down reason %q is invalid", ErrValidation, raw)
	}
}

// ResourceKind is the SRU taxonomy.
type ResourceKind string

const (
	ResourceVessel   ResourceKind = "VESSEL"
	ResourceAircraft ResourceKind = "AIRCRAFT"
	ResourceTeam     ResourceKind = "TEAM"
	ResourceVOO      ResourceKind = "VOO" // vessel of opportunity
)

// ResourceStatus is the SRU availability state.
type ResourceStatus string

const (
	ResourceAvailable ResourceStatus = "AVAILABLE"
	ResourceTasked    ResourceStatus = "TASKED"
	ResourceOffline   ResourceStatus = "OFFLINE"
)

// Task is the tasking-order task type.
type Task string

const (
	TaskSearchPattern Task = "SEARCH_PATTERN"
	TaskInvestigate   Task = "INVESTIGATE"
	TaskRescue        Task = "RESCUE"
	TaskRelay         Task = "RELAY"
	TaskMedevac       Task = "MEDEVAC"
	TaskOther         Task = "OTHER"
)

// TaskingState is the tasking lifecycle:
// PROPOSED→TASKED→ACKED→ON_SCENE→RELEASED|ABORTED.
type TaskingState string

const (
	TaskingProposed TaskingState = "PROPOSED"
	TaskingTasked   TaskingState = "TASKED"
	TaskingAcked    TaskingState = "ACKED"
	TaskingOnScene  TaskingState = "ON_SCENE"
	TaskingReleased TaskingState = "RELEASED"
	TaskingAborted  TaskingState = "ABORTED"
)

// ValidTaskingTransition enforces the tasking state machine. ABORTED is
// reachable from any non-terminal state; RELEASED is the stand-down outcome.
func ValidTaskingTransition(current, next TaskingState) bool {
	switch current {
	case TaskingProposed:
		return next == TaskingTasked || next == TaskingAborted
	case TaskingTasked:
		return next == TaskingAcked || next == TaskingAborted
	case TaskingAcked:
		return next == TaskingOnScene || next == TaskingAborted
	case TaskingOnScene:
		return next == TaskingReleased || next == TaskingAborted
	default:
		return false // RELEASED, ABORTED terminal
	}
}

// TaskingTransitionReason codes are closed per transition target.
func TaskingTransitionReason(next TaskingState, reasonCode string) error {
	allowed := map[TaskingState][]string{
		TaskingTasked:   {"order-issued"},
		TaskingAcked:    {"sru-acknowledged"},
		TaskingOnScene:  {"sru-on-scene"},
		TaskingReleased: {"stand-down", "relieved", "task-complete"},
		TaskingAborted:  {"unable", "recalled", "false-alert"},
	}
	for _, code := range allowed[next] {
		if code == reasonCode {
			return nil
		}
	}
	return fmt.Errorf("%w: tasking transition to %s requires a reason code in %v", ErrValidation, next, allowed[next])
}

// Timeline entry types (mirrored by the sar_case_timeline CHECK constraint).
const (
	EntryCaseOpened           = "case.opened"
	EntryPhaseChanged         = "phase.changed"
	EntryStageChanged         = "stage.changed"
	EntryDatumSet             = "datum.set"
	EntryTaskingProposed      = "tasking.proposed"
	EntryTaskingTasked        = "tasking.tasked"
	EntryTaskingAcked         = "tasking.acked"
	EntryTaskingOnScene       = "tasking.on_scene"
	EntryTaskingReleased      = "tasking.released"
	EntryTaskingAborted       = "tasking.aborted"
	EntrySitrepIssued         = "sitrep.issued"
	EntryCaseIntakeLinked     = "case.intake_linked"
	EntrySOSAcknowledged      = "sos.acknowledged"
	EntrySOSResolved          = "sos.resolved"
	EntryResourceRegistered   = "resource.registered"
	EntryResourceStatusChange = "resource.status_changed"
)

// Case is the SAR case aggregate.
type Case struct {
	CaseID              string             `json:"case_id"`
	IncidentID          string             `json:"incident_id"`
	Phase               Phase              `json:"phase"`
	Stage               Stage              `json:"stage"`
	Classification      isr.Classification `json:"classification"`
	IntakeKind          IntakeKind         `json:"intake_kind"`
	SourceRef           string             `json:"source_ref"`
	PersonsAtRisk       *int               `json:"persons_at_risk,omitempty"`
	LastKnownLatitude   *float64           `json:"last_known_lat,omitempty"`
	LastKnownLongitude  *float64           `json:"last_known_lon,omitempty"`
	LastKnownAt         *time.Time         `json:"last_known_at,omitempty"`
	DatumLatitude       *float64           `json:"datum_lat,omitempty"`
	DatumLongitude      *float64           `json:"datum_lon,omitempty"`
	DatumAt             *time.Time         `json:"datum_at,omitempty"`
	DatumEvidenceSHA256 string             `json:"datum_evidence_sha256,omitempty"`
	StandDownReason     string             `json:"stand_down_reason,omitempty"`
	PersonsRecovered    *int               `json:"persons_recovered,omitempty"`
	HandoverRef         string             `json:"handover_ref,omitempty"`
	CreatedBy           string             `json:"created_by"`
	CreatedAt           time.Time          `json:"created_at"`
	UpdatedAt           time.Time          `json:"updated_at"`
	Version             int64              `json:"version"`
}

// TimelineEntry is one append-only case fact.
type TimelineEntry struct {
	EntryID   string         `json:"entry_id"`
	CaseID    string         `json:"case_id"`
	EntryType string         `json:"entry_type"`
	Actor     string         `json:"actor"`
	Detail    map[string]any `json:"detail"`
	CreatedAt time.Time      `json:"created_at"`
}

// Resource is one registered SRU.
type Resource struct {
	ResourceID    string         `json:"resource_id"`
	Kind          ResourceKind   `json:"kind"`
	Callsign      string         `json:"callsign"`
	Capabilities  map[string]any `json:"capabilities"`
	HomeAuthority string         `json:"home_authority"`
	Status        ResourceStatus `json:"status"`
	RegisteredBy  string         `json:"registered_by"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

// Tasking is one tasking order.
type Tasking struct {
	TaskingID  string         `json:"tasking_id"`
	CaseID     string         `json:"case_id"`
	ResourceID string         `json:"resource_id"`
	Task       Task           `json:"task"`
	Briefing   map[string]any `json:"briefing"`
	State      TaskingState   `json:"state"`
	TaskedBy   string         `json:"tasked_by"`
	AckedBy    string         `json:"acked_by,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	Version    int64          `json:"version"`
}

// Sitrep is one issued, immutable, signed situation report.
type Sitrep struct {
	SitrepID    string         `json:"sitrep_id"`
	CaseID      string         `json:"case_id"`
	Sequence    int            `json:"sequence"`
	Body        map[string]any `json:"body"`
	BodySHA256  string         `json:"body_sha256"`
	EnvelopeJWS string         `json:"envelope_jws"`
	IssuedBy    string         `json:"issued_by"`
	IssuedAt    time.Time      `json:"issued_at"`
}

// OpenCaseRequest opens a case (MANUAL intake path).
type OpenCaseRequest struct {
	CaseID             string     `json:"case_id"` // optional; generated when empty
	IncidentID         string     `json:"incident_id"`
	SourceRef          string     `json:"source_ref"`
	Classification     string     `json:"classification"`
	Phase              string     `json:"phase"`
	PersonsAtRisk      *int       `json:"persons_at_risk"`
	LastKnownLatitude  *float64   `json:"last_known_lat"`
	LastKnownLongitude *float64   `json:"last_known_lon"`
	LastKnownAt        *time.Time `json:"last_known_at"`
}

// Validate enforces the open-case contract fail-closed.
func (request OpenCaseRequest) Validate() error {
	if request.CaseID != "" {
		if err := validIdentifier("case_id", request.CaseID); err != nil {
			return err
		}
	}
	if err := validIdentifier("incident_id", request.IncidentID); err != nil {
		return err
	}
	if strings.TrimSpace(request.SourceRef) != request.SourceRef || request.SourceRef == "" || len(request.SourceRef) > 512 {
		return fmt.Errorf("%w: source_ref must be canonical text of at most 512 characters", ErrValidation)
	}
	classification, err := isr.ParseClassification(request.Classification)
	if err != nil {
		return err
	}
	if _, err := ParsePhase(request.Phase); err != nil {
		return err
	}
	if request.PersonsAtRisk != nil && *request.PersonsAtRisk < 0 {
		return fmt.Errorf("%w: persons_at_risk must be non-negative", ErrValidation)
	}
	if (request.LastKnownLatitude == nil) != (request.LastKnownLongitude == nil) {
		return fmt.Errorf("%w: last-known position requires both latitude and longitude", ErrValidation)
	}
	if request.LastKnownLatitude != nil {
		if *request.LastKnownLatitude < -90 || *request.LastKnownLatitude > 90 ||
			*request.LastKnownLongitude < -180 || *request.LastKnownLongitude > 180 {
			return fmt.Errorf("%w: last-known position out of range", ErrValidation)
		}
	}
	_ = classification
	return nil
}
