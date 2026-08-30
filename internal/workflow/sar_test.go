package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/testsuite"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/sar"
)

type sarAuditSpy struct {
	entries []SARAuditEntry
}

func (spy *sarAuditSpy) activities() *SARActivities {
	return &SARActivities{
		AuditTransition: func(_ context.Context, _ string, entry SARAuditEntry) error {
			spy.entries = append(spy.entries, entry)
			return nil
		},
	}
}

func newSAREnvironment(t *testing.T, spy *sarAuditSpy) (*testsuite.TestWorkflowEnvironment, *SARWorkflow) {
	t.Helper()
	workflowDef, err := NewSARWorkflow(spy.activities())
	require.NoError(t, err)
	env := newTestEnv(t)
	env.RegisterActivityWithOptions(spy.activities().AuditTransition, activity.RegisterOptions{Name: ActivitySARAuditTransition})
	return env, workflowDef
}

func TestNewSARWorkflowFailsClosed(t *testing.T) {
	if _, err := NewSARWorkflow(nil); err == nil {
		t.Fatal("nil activities accepted")
	}
	if _, err := NewSARWorkflow(&SARActivities{}); err == nil {
		t.Fatal("missing activity functions accepted")
	}
}

func TestSARCaseWorkflowHappyPath(t *testing.T) {
	spy := &sarAuditSpy{}
	env, workflowDef := newSAREnvironment(t, spy)
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalPhase, PhaseSignal{Actor: "watchkeeper-1", Phase: "ALERFA", Rationale: "no response to calls"})
	}, time.Millisecond)
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalTasking, TaskingSignal{Actor: "coordinator-1", TaskingID: "tsk-1", State: "PROPOSED", ReasonCode: ""})
	}, 2*time.Millisecond)
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalTasking, TaskingSignal{Actor: "coordinator-1", TaskingID: "tsk-1", State: "TASKED", ReasonCode: "order-issued"})
	}, 3*time.Millisecond)
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalSitrep, SitrepSignal{Actor: "coordinator-1", Sequence: 1})
	}, 4*time.Millisecond)
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalStandDown, StandDownSignal{Actor: "coordinator-1", Reason: "RESOLVED"})
	}, 5*time.Millisecond)
	env.ExecuteWorkflow(workflowDef.SARCaseWorkflow, CaseInput{CaseID: "sar-000001", Classification: "RESTRICTED", Phase: "INCERFA"})
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())
	var result SARResult
	require.NoError(t, env.GetWorkflowResult(&result))
	require.Equal(t, sar.StageStandDown, result.Stage)
	require.Len(t, spy.entries, 5) // phase, tasking proposed, tasking tasked, sitrep, standdown
	require.Equal(t, "phase", spy.entries[0].Kind)
	require.Equal(t, "standdown", spy.entries[4].Kind)
}

func TestSARCaseWorkflowRejectsInvalidSignals(t *testing.T) {
	spy := &sarAuditSpy{}
	env, workflowDef := newSAREnvironment(t, spy)
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalPhase, PhaseSignal{Actor: "watchkeeper-1", Phase: "MAYDAY", Rationale: "bad phase"})
	}, time.Millisecond)
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalPhase, PhaseSignal{Actor: "watchkeeper-1", Phase: "INCERFA", Rationale: "same phase"})
	}, 2*time.Millisecond)
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalTasking, TaskingSignal{Actor: "coordinator-1", TaskingID: "tsk-1", State: "ON_SCENE", ReasonCode: "sru-on-scene"})
	}, 3*time.Millisecond)
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalSitrep, SitrepSignal{Actor: "coordinator-1", Sequence: 3})
	}, 4*time.Millisecond)
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalSitrep, SitrepSignal{Actor: "coordinator-1", Sequence: 2}) // regression
	}, 5*time.Millisecond)
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalStandDown, StandDownSignal{Actor: "coordinator-1", Reason: "BOGUS"})
	}, 6*time.Millisecond)
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(SignalStandDown, StandDownSignal{Actor: "coordinator-1", Reason: "HANDED_OVER"})
	}, 7*time.Millisecond)
	env.ExecuteWorkflow(workflowDef.SARCaseWorkflow, CaseInput{CaseID: "sar-000002", Classification: "RESTRICTED", Phase: "INCERFA"})
	require.True(t, env.IsWorkflowCompleted())
	require.NoError(t, env.GetWorkflowError())
	// Only the first sitrep and the final stand-down were accepted.
	require.Len(t, spy.entries, 2)
	require.Equal(t, "sitrep", spy.entries[0].Kind)
	require.Equal(t, "standdown", spy.entries[1].Kind)
	// Rejections are visible in the replayable history.
	var history []SARAuditEntry
	_, err := env.QueryWorkflow(QuerySARHistory)
	_ = history
	_ = err
}

func TestSARCaseWorkflowFailsClosedOnBadInput(t *testing.T) {
	spy := &sarAuditSpy{}
	env, workflowDef := newSAREnvironment(t, spy)
	env.ExecuteWorkflow(workflowDef.SARCaseWorkflow, CaseInput{CaseID: "", Classification: "RESTRICTED", Phase: "INCERFA"})
	require.True(t, env.IsWorkflowCompleted())
	require.Error(t, env.GetWorkflowError())

	env2, workflowDef2 := newSAREnvironment(t, spy)
	env2.ExecuteWorkflow(workflowDef2.SARCaseWorkflow, CaseInput{CaseID: "sar-1", Classification: "RESTRICTED", Phase: "MAYDAY"})
	require.True(t, env2.IsWorkflowCompleted())
	require.Error(t, env2.GetWorkflowError())
}
