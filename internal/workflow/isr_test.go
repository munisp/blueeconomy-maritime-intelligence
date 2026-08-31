package workflow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/testsuite"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

type auditSpy struct {
	entries  []AuditEntry
	outcomes []string
}

func (spy *auditSpy) activities() *Activities {
	return &Activities{
		AuditTransition: func(_ context.Context, _ string, entry AuditEntry) error {
			spy.entries = append(spy.entries, entry)
			return nil
		},
		RecordOutcome: func(_ context.Context, _ string, incidentRef string, _ bool) error {
			spy.outcomes = append(spy.outcomes, incidentRef)
			return nil
		},
	}
}

func newEnvironment(t *testing.T, spy *auditSpy) (*testsuite.TestWorkflowEnvironment, *ISRWorkflow) {
	t.Helper()
	workflowDef, err := NewISRWorkflow(spy.activities())
	require.NoError(t, err)
	env := newTestEnv(t)
	env.RegisterActivityWithOptions(spy.activities().AuditTransition, activity.RegisterOptions{Name: ActivityAuditTransition})
	env.RegisterActivityWithOptions(spy.activities().RecordOutcome, activity.RegisterOptions{Name: ActivityRecordOutcome})
	return env, workflowDef
}

func newTestEnv(t *testing.T) *testsuite.TestWorkflowEnvironment {
	t.Helper()
	var suite testsuite.WorkflowTestSuite
	return suite.NewTestWorkflowEnvironment()
}

func alertInput() AlertInput {
	return AlertInput{AlertID: "alert-001", AnomalyID: "anomaly-rendezvous-001", Classification: isr.ClassificationConfidential}
}

func driveSignals(env *testsuite.TestWorkflowEnvironment, classification ClassificationSignal, dispatch DispatchSignal, interdiction InterdictionSignal, outcome OutcomeSignal) {
	env.RegisterDelayedCallback(func() { env.SignalWorkflow(SignalClassification, classification) }, time.Millisecond)
	env.RegisterDelayedCallback(func() { env.SignalWorkflow(SignalDispatch, dispatch) }, 2*time.Millisecond)
	env.RegisterDelayedCallback(func() { env.SignalWorkflow(SignalInterdiction, interdiction) }, 3*time.Millisecond)
	env.RegisterDelayedCallback(func() { env.SignalWorkflow(SignalOutcome, outcome) }, 4*time.Millisecond)
}

func TestNewISRWorkflowFailsClosed(t *testing.T) {
	if _, err := NewISRWorkflow(nil); err == nil {
		t.Fatal("nil activities accepted")
	}
	if _, err := NewISRWorkflow(&Activities{}); err == nil {
		t.Fatal("missing activity functions accepted")
	}
}

func TestISRResponseWorkflowHappyPath(t *testing.T) {
	spy := &auditSpy{}
	env, workflowDef := newEnvironment(t, spy)
	driveSignals(env,
		ClassificationSignal{AnalystID: "analyst-1", Clearance: isr.ClassificationSecret, Confirmed: true, Assessment: "confirmed rendezvous"},
		DispatchSignal{OfficerID: "nn-officer-1", Unit: "nns-thunder", Approved: true},
		InterdictionSignal{OfficerID: "nn-officer-1", Outcome: "boarded"},
		OutcomeSignal{RecorderID: "recorder-1", IncidentRef: "incident-001", Verified: true},
	)
	env.ExecuteWorkflow(workflowDef.ISRResponseWorkflow, alertInput())
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())
	var result ResponseResult
	require.NoError(t, env.GetWorkflowResult(&result))
	require.Equal(t, StateOutcomeCapture, result.State)
	require.Len(t, spy.entries, 4)
	require.Equal(t, []ResponseState{StateAlerted, StateClassified, StateDispatched, StateInterdicted},
		[]ResponseState{spy.entries[0].From, spy.entries[1].From, spy.entries[2].From, spy.entries[3].From})
	require.Equal(t, []string{"incident-001"}, spy.outcomes)
}

func TestISRResponseWorkflowRejectsInsufficientClearance(t *testing.T) {
	spy := &auditSpy{}
	env, workflowDef := newEnvironment(t, spy)
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalClassification, ClassificationSignal{AnalystID: "analyst-2", Clearance: isr.ClassificationRestricted, Confirmed: true})
	}, time.Millisecond)
	env.ExecuteWorkflow(workflowDef.ISRResponseWorkflow, alertInput())
	require.True(t, env.IsWorkflowCompleted())
	require.Error(t, env.GetWorkflowError())
	require.Contains(t, env.GetWorkflowError().Error(), "clearance")
	require.Len(t, spy.entries, 1)
	require.Equal(t, StateRejected, spy.entries[0].To)
}

func TestISRResponseWorkflowUnconfirmedAlertStops(t *testing.T) {
	spy := &auditSpy{}
	env, workflowDef := newEnvironment(t, spy)
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalClassification, ClassificationSignal{AnalystID: "analyst-3", Clearance: isr.ClassificationConfidential, Confirmed: false})
	}, time.Millisecond)
	env.ExecuteWorkflow(workflowDef.ISRResponseWorkflow, alertInput())
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())
	var result ResponseResult
	require.NoError(t, env.GetWorkflowResult(&result))
	require.Equal(t, StateRejected, result.State)
	require.Empty(t, spy.outcomes)
}

func TestISRResponseWorkflowRejectsInvalidInput(t *testing.T) {
	spy := &auditSpy{}
	env, workflowDef := newEnvironment(t, spy)
	env.ExecuteWorkflow(workflowDef.ISRResponseWorkflow, AlertInput{AlertID: "alert-002"})
	require.True(t, env.IsWorkflowCompleted())
	require.Error(t, env.GetWorkflowError())

	env2, _ := newEnvironment(t, spy)
	invalid := alertInput()
	invalid.Classification = "TOP-SECRET"
	env2.ExecuteWorkflow(workflowDef.ISRResponseWorkflow, invalid)
	require.True(t, env2.IsWorkflowCompleted())
	// Temporal serialises workflow errors, so assert on the message.
	require.ErrorContains(t, env2.GetWorkflowError(), "classification")
}

func TestISRResponseWorkflowObserverQuery(t *testing.T) {
	spy := &auditSpy{}
	env, workflowDef := newEnvironment(t, spy)
	states := make([]ResponseState, 0)
	driveSignals(env,
		ClassificationSignal{AnalystID: "analyst-1", Clearance: isr.ClassificationConfidential, Confirmed: true},
		DispatchSignal{OfficerID: "nn-officer-1", Unit: "nns-thunder", Approved: true},
		InterdictionSignal{OfficerID: "nn-officer-1", Outcome: "intercepted"},
		OutcomeSignal{RecorderID: "recorder-1", IncidentRef: "incident-002", Verified: true},
	)
	env.RegisterDelayedCallback(func() {
		value, err := env.QueryWorkflow(QueryState)
		require.NoError(t, err)
		var state ResponseState
		require.NoError(t, value.Get(&state))
		states = append(states, state)
	}, 1500*time.Microsecond)
	env.ExecuteWorkflow(workflowDef.ISRResponseWorkflow, alertInput())
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())
	value, err := env.QueryWorkflow(QueryHistory)
	require.NoError(t, err)
	var history []AuditEntry
	require.NoError(t, value.Get(&history))
	require.Len(t, history, 4)
}

func TestAuditFailurePropagates(t *testing.T) {
	spy := &auditSpy{}
	activities := spy.activities()
	activities.AuditTransition = func(context.Context, string, AuditEntry) error {
		return errors.New("audit store unavailable")
	}
	workflowDef, err := NewISRWorkflow(activities)
	require.NoError(t, err)
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()
	env.RegisterActivityWithOptions(activities.AuditTransition, activity.RegisterOptions{Name: ActivityAuditTransition})
	env.RegisterActivityWithOptions(activities.RecordOutcome, activity.RegisterOptions{Name: ActivityRecordOutcome})
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalClassification, ClassificationSignal{AnalystID: "analyst-1", Clearance: isr.ClassificationConfidential, Confirmed: true})
	}, time.Millisecond)
	env.ExecuteWorkflow(workflowDef.ISRResponseWorkflow, alertInput())
	require.True(t, env.IsWorkflowCompleted())
	require.Error(t, env.GetWorkflowError())
}
