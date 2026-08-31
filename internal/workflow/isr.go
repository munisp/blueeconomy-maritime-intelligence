// Package workflow implements the Temporal-orchestrated Deep Blue Project
// ISR response rail: alert -> analyst classification (with required
// clearance) -> Nigerian Navy dispatch -> interdiction -> outcome capture.
// Every transition writes an audit hook through activities; observer roles
// replay state through queries. All gates fail closed: an invalid signal or
// insufficient clearance never advances the lifecycle.
package workflow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.temporal.io/sdk/workflow"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

const (
	// SignalClassification carries the analyst classification decision.
	SignalClassification = "isr.classification"
	// SignalDispatch carries the NN officer dispatch decision.
	SignalDispatch = "isr.dispatch"
	// SignalInterdiction carries the interdiction report.
	SignalInterdiction = "isr.interdiction"
	// SignalOutcome carries the outcome capture.
	SignalOutcome = "isr.outcome"

	// QueryState returns the lifecycle state for observer replay.
	QueryState = "isr.state"
	// QueryHistory returns the audit history for observer replay.
	QueryHistory = "isr.history"
)

// Stable activity names referenced by workflow histories.
const (
	ActivityAuditTransition = "isr.audit-transition"
	ActivityRecordOutcome   = "isr.record-outcome"
)

// ResponseState enumerates the ISR response lifecycle.
type ResponseState string

const (
	StateAlerted        ResponseState = "ALERTED"
	StateClassified     ResponseState = "CLASSIFIED"
	StateDispatched     ResponseState = "DISPATCHED"
	StateInterdicted    ResponseState = "INTERDICTED"
	StateOutcomeCapture ResponseState = "OUTCOME_CAPTURED"
	StateRejected       ResponseState = "REJECTED"
)

// AlertInput starts one ISRResponseWorkflow from a behaviour anomaly alert.
type AlertInput struct {
	AlertID        string             `json:"alert_id"`
	AnomalyID      string             `json:"anomaly_id"`
	Classification isr.Classification `json:"classification"`
}

// ClassificationSignal is the analyst decision. The analyst's clearance must
// cover the alert classification or the workflow rejects the signal
// fail-closed.
type ClassificationSignal struct {
	AnalystID  string             `json:"analyst_id"`
	Clearance  isr.Classification `json:"clearance"`
	Confirmed  bool               `json:"confirmed"`
	Assessment string             `json:"assessment"`
}

// DispatchSignal is the NN officer dispatch order.
type DispatchSignal struct {
	OfficerID string `json:"officer_id"`
	Unit      string `json:"unit"`
	Approved  bool   `json:"approved"`
}

// InterdictionSignal reports the interdiction result.
type InterdictionSignal struct {
	OfficerID string `json:"officer_id"`
	Outcome   string `json:"outcome"` // e.g. "intercepted", "boarded", "lost-contact"
}

// OutcomeSignal captures the final outcome evidence reference.
type OutcomeSignal struct {
	RecorderID  string `json:"recorder_id"`
	IncidentRef string `json:"incident_ref"`
	Verified    bool   `json:"verified"`
}

// AuditEntry is one recorded lifecycle transition.
type AuditEntry struct {
	From   ResponseState `json:"from"`
	To     ResponseState `json:"to"`
	Actor  string        `json:"actor"`
	Detail string        `json:"detail"`
}

// ResponseResult is the terminal workflow result.
type ResponseResult struct {
	AlertID string        `json:"alert_id"`
	State   ResponseState `json:"state"`
}

// Activities groups the durable side effects the workflow invokes.
type Activities struct {
	// AuditTransition persists one transition audit record.
	AuditTransition func(ctx context.Context, alertID string, entry AuditEntry) error
	// RecordOutcome persists the terminal outcome evidence.
	RecordOutcome func(ctx context.Context, alertID, incidentRef string, verified bool) error
}

// ISRWorkflow binds the workflow definition to its activity dependencies.
type ISRWorkflow struct{ activities *Activities }

// NewISRWorkflow fails closed when activities are absent.
func NewISRWorkflow(activities *Activities) (*ISRWorkflow, error) {
	if activities == nil || activities.AuditTransition == nil || activities.RecordOutcome == nil {
		return nil, errors.New("isr activities are required (fail-closed)")
	}
	return &ISRWorkflow{activities: activities}, nil
}

// ISRResponseWorkflow drives one alert through classification, dispatch,
// interdiction and outcome capture. Every signal is validated fail-closed;
// every accepted transition is audit-hooked.
func (workflowDef *ISRWorkflow) ISRResponseWorkflow(ctx workflow.Context, input AlertInput) (ResponseResult, error) {
	if input.AlertID == "" || input.AnomalyID == "" {
		return ResponseResult{}, errors.New("alert_id and anomaly_id are required")
	}
	if _, err := isr.ParseClassification(string(input.Classification)); err != nil {
		return ResponseResult{}, err
	}
	result := ResponseResult{AlertID: input.AlertID, State: StateAlerted}
	history := make([]AuditEntry, 0)
	if err := workflow.SetQueryHandler(ctx, QueryState, func() (ResponseState, error) { return result.State, nil }); err != nil {
		return result, fmt.Errorf("register state query: %w", err)
	}
	if err := workflow.SetQueryHandler(ctx, QueryHistory, func() ([]AuditEntry, error) { return history, nil }); err != nil {
		return result, fmt.Errorf("register history query: %w", err)
	}
	options := workflow.ActivityOptions{StartToCloseTimeout: 2 * time.Minute}
	activityCtx := workflow.WithActivityOptions(ctx, options)

	audit := func(from, to ResponseState, actor, detail string) error {
		entry := AuditEntry{From: from, To: to, Actor: actor, Detail: detail}
		if err := workflow.ExecuteActivity(activityCtx, ActivityAuditTransition, input.AlertID, entry).Get(activityCtx, nil); err != nil {
			return fmt.Errorf("audit transition %s -> %s: %w", from, to, err)
		}
		history = append(history, entry)
		result.State = to
		return nil
	}

	// Stage 1: analyst classification. The analyst clearance must cover the
	// alert classification; a non-confirming analyst rejects the alert.
	var classification ClassificationSignal
	selector := workflow.NewSelector(ctx)
	classificationChan := workflow.GetSignalChannel(ctx, SignalClassification)
	selector.AddReceive(classificationChan, func(channel workflow.ReceiveChannel, more bool) {
		channel.Receive(ctx, &classification)
	})
	selector.Select(ctx)
	if classification.AnalystID == "" {
		return result, errors.New("classification signal requires an analyst identity")
	}
	analystClearance, err := isr.ParseClassification(string(classification.Clearance))
	if err != nil {
		return result, fmt.Errorf("classification signal carries an invalid clearance: %w", err)
	}
	if !analystClearance.Covers(input.Classification) {
		if err := audit(StateAlerted, StateRejected, classification.AnalystID, "analyst clearance below alert classification"); err != nil {
			return result, err
		}
		return result, errors.New("analyst clearance does not cover the alert classification (fail-closed)")
	}
	if !classification.Confirmed {
		if err := audit(StateAlerted, StateRejected, classification.AnalystID, "analyst did not confirm the alert"); err != nil {
			return result, err
		}
		return result, nil
	}
	if err := audit(StateAlerted, StateClassified, classification.AnalystID, classification.Assessment); err != nil {
		return result, err
	}

	// Stage 2: NN officer dispatch.
	var dispatch DispatchSignal
	dispatchChan := workflow.GetSignalChannel(ctx, SignalDispatch)
	selector = workflow.NewSelector(ctx)
	selector.AddReceive(dispatchChan, func(channel workflow.ReceiveChannel, more bool) {
		channel.Receive(ctx, &dispatch)
	})
	selector.Select(ctx)
	if dispatch.OfficerID == "" || dispatch.Unit == "" {
		return result, errors.New("dispatch signal requires an officer identity and unit")
	}
	if !dispatch.Approved {
		if err := audit(StateClassified, StateRejected, dispatch.OfficerID, "dispatch not approved"); err != nil {
			return result, err
		}
		return result, nil
	}
	if err := audit(StateClassified, StateDispatched, dispatch.OfficerID, "unit "+dispatch.Unit); err != nil {
		return result, err
	}

	// Stage 3: interdiction report.
	var interdiction InterdictionSignal
	interdictionChan := workflow.GetSignalChannel(ctx, SignalInterdiction)
	selector = workflow.NewSelector(ctx)
	selector.AddReceive(interdictionChan, func(channel workflow.ReceiveChannel, more bool) {
		channel.Receive(ctx, &interdiction)
	})
	selector.Select(ctx)
	if interdiction.OfficerID == "" || interdiction.Outcome == "" {
		return result, errors.New("interdiction signal requires an officer identity and outcome")
	}
	if err := audit(StateDispatched, StateInterdicted, interdiction.OfficerID, interdiction.Outcome); err != nil {
		return result, err
	}

	// Stage 4: outcome capture.
	var outcome OutcomeSignal
	outcomeChan := workflow.GetSignalChannel(ctx, SignalOutcome)
	selector = workflow.NewSelector(ctx)
	selector.AddReceive(outcomeChan, func(channel workflow.ReceiveChannel, more bool) {
		channel.Receive(ctx, &outcome)
	})
	selector.Select(ctx)
	if outcome.RecorderID == "" || outcome.IncidentRef == "" {
		return result, errors.New("outcome signal requires a recorder identity and incident reference")
	}
	if err := workflow.ExecuteActivity(activityCtx, ActivityRecordOutcome, input.AlertID, outcome.IncidentRef, outcome.Verified).Get(activityCtx, nil); err != nil {
		return result, fmt.Errorf("record outcome: %w", err)
	}
	if err := audit(StateInterdicted, StateOutcomeCapture, outcome.RecorderID, "incident "+outcome.IncidentRef); err != nil {
		return result, err
	}
	return result, nil
}
