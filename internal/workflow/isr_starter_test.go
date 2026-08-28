package workflow

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/tracks"
)

// TestWorkflowStartsFromAdmittedAnomalyPayload proves the external starter
// contract documented in README ("ISR response workflow starter contract"):
// an ISRResponseWorkflow is startable with an AlertInput mapped from the
// behaviour-anomaly record the incident/alert admission path persists, and
// runs to completion under the standard signals.
func TestWorkflowStartsFromAdmittedAnomalyPayload(t *testing.T) {
	// The admitted record: a behaviour anomaly exactly as the fusion pipeline
	// persists it (maritime_behaviour_anomalies) and seals it to the outbox.
	anomaly := tracks.Anomaly{
		AnomalyID:      "anomaly-dark-vessel-fused-track-000001-1692190000000000000",
		Kind:           tracks.AnomalyDarkVessel,
		TrackIDs:       []string{"fused-track-000001"},
		ZoneID:         "nigeria-eez",
		Classification: isr.ClassificationRestricted,
		DetectedAt:     time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC),
		Detail:         "AIS silent for >= 30m0s inside zone nigeria-eez",
	}
	encoded, err := json.Marshal(anomaly)
	require.NoError(t, err)
	var admitted tracks.Anomaly
	require.NoError(t, json.Unmarshal(encoded, &admitted))

	// The documented starter mapping: alert identity and classification come
	// from the admitted anomaly record, nothing else.
	input := AlertInput{
		AlertID:        admitted.AnomalyID,
		AnomalyID:      admitted.AnomalyID,
		Classification: admitted.Classification,
	}

	spy := &auditSpy{}
	env, workflowDef := newEnvironment(t, spy)
	driveSignals(env,
		ClassificationSignal{AnalystID: "analyst-1", Clearance: isr.ClassificationSecret, Confirmed: true, Assessment: "confirmed dark vessel"},
		DispatchSignal{OfficerID: "nn-officer-1", Unit: "nns-thunder", Approved: true},
		InterdictionSignal{OfficerID: "nn-officer-1", Outcome: "intercepted"},
		OutcomeSignal{RecorderID: "recorder-1", IncidentRef: "incident-001", Verified: true},
	)
	env.ExecuteWorkflow(workflowDef.ISRResponseWorkflow, input)
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())
	var result ResponseResult
	require.NoError(t, env.GetWorkflowResult(&result))
	require.Equal(t, StateOutcomeCapture, result.State)
	require.Equal(t, admitted.AnomalyID, result.AlertID)
	require.Len(t, spy.entries, 4)
	require.Equal(t, []string{"incident-001"}, spy.outcomes)
}
