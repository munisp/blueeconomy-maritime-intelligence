package incident

import (
	"testing"
	"time"
)

func validRequest() CreateRequest {
	return CreateRequest{
		IncidentID: "incident-001", SourceEventID: "event-001", Category: "distress", Severity: SeverityHigh,
		Title: "Distress alert", Description: "Verified distress alert from approved source",
		OccurredAt: time.Date(2026, time.August, 15, 12, 0, 0, 0, time.UTC), CreatedBy: "operator-001",
	}
}

func TestCreateRequestValidation(t *testing.T) {
	if err := validRequest().Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	invalid := validRequest()
	invalid.Severity = "UNKNOWN"
	if err := invalid.Validate(); err == nil {
		t.Fatal("unsupported severity accepted")
	}
	invalid = validRequest()
	invalid.OccurredAt = time.Time{}
	if err := invalid.Validate(); err == nil {
		t.Fatal("zero occurred_at accepted")
	}
}

func TestMatchesRejectsConflictingSourceEventReuse(t *testing.T) {
	request := validRequest()
	retained := Incident{CreateRequest: request}
	if !retained.Matches(request) {
		t.Fatal("exact request did not match")
	}
	request.Description = "changed"
	if retained.Matches(request) {
		t.Fatal("conflicting source event matched")
	}
}

func TestValidIncidentLifecycle(t *testing.T) {
	for _, pair := range [][2]Status{
		{StatusOpen, StatusAcknowledged}, {StatusAcknowledged, StatusInvestigating},
		{StatusInvestigating, StatusResolved}, {StatusResolved, StatusClosed},
	} {
		if !ValidTransition(pair[0], pair[1]) {
			t.Fatalf("expected transition %s -> %s", pair[0], pair[1])
		}
	}
	if ValidTransition(StatusClosed, StatusOpen) || ValidTransition(StatusOpen, StatusClosed) {
		t.Fatal("invalid lifecycle transition accepted")
	}
}

func TestCorrelationRequestValidation(t *testing.T) {
	valid := CorrelationRequest{
		GeofenceID: "port-a", Relation: "INSIDE", Latitude: 6.45, Longitude: 3.39,
		EvidenceSHA256: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		CorrelatedBy:   "spatial-engine",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid correlation rejected: %v", err)
	}
	invalid := valid
	invalid.Latitude = 91
	if err := invalid.Validate(); err == nil {
		t.Fatal("out-of-range latitude accepted")
	}
	invalid = valid
	invalid.EvidenceSHA256 = "sha256:ABC"
	if err := invalid.Validate(); err == nil {
		t.Fatal("invalid evidence hash accepted")
	}
	invalid = valid
	invalid.Relation = "UNKNOWN"
	if err := invalid.Validate(); err == nil {
		t.Fatal("invalid spatial relation accepted")
	}
}

func TestAssignmentRequestRequiresMakerCheckerSeparation(t *testing.T) {
	valid := AssignmentRequest{ExpectedVersion: 1, AnalystID: "analyst-001", AssignedBy: "supervisor-001"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid assignment rejected: %v", err)
	}
	invalid := valid
	invalid.AnalystID = invalid.AssignedBy
	if err := invalid.Validate(); err == nil {
		t.Fatal("self-assignment accepted")
	}
}
