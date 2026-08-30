package workflow

// SAR case coordination workflow (Phase 8): one SARCaseWorkflow per SAR
// case. Signals drive phase changes, tasking transitions, SITREP issuance
// and stand-down; queries replay state for observer roles. All gates fail
// closed: an invalid phase, tasking transition, SITREP sequence or
// stand-down reason never advances the case and is recorded as a rejected
// signal. Every accepted transition is audit-hooked through the
// sar.audit-transition activity (durable persistence per the isr.go
// precedent).

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.temporal.io/sdk/workflow"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/sar"
)

const (
	// SignalPhase carries an IAMSAR phase change with operator rationale.
	SignalPhase = "sar.phase"
	// SignalTasking carries one tasking state transition.
	SignalTasking = "sar.tasking"
	// SignalSitrep carries a SITREP issuance (monotonic sequence).
	SignalSitrep = "sar.sitrep"
	// SignalStandDown carries the terminal stand-down decision.
	SignalStandDown = "sar.standdown"

	// QueryState returns the case coordination state for observer replay.
	QuerySARState = "sar.state"
	// QueryHistory returns the audit history for observer replay.
	QuerySARHistory = "sar.history"
)

// ActivitySARAuditTransition persists one case transition audit record.
const ActivitySARAuditTransition = "sar.audit-transition"

// CaseInput starts one SARCaseWorkflow from an opened SAR case.
type CaseInput struct {
	CaseID         string `json:"case_id"`
	Classification string `json:"classification"`
	Phase          string `json:"phase"`
}

// PhaseSignal is the operator phase decision.
type PhaseSignal struct {
	Actor     string `json:"actor"`
	Phase     string `json:"phase"`
	Rationale string `json:"rationale"`
}

// TaskingSignal is one tasking transition.
type TaskingSignal struct {
	Actor      string `json:"actor"`
	TaskingID  string `json:"tasking_id"`
	State      string `json:"state"`
	ReasonCode string `json:"reason_code"`
}

// SitrepSignal reports a SITREP issuance.
type SitrepSignal struct {
	Actor    string `json:"actor"`
	Sequence int    `json:"sequence"`
}

// StandDownSignal is the terminal case closure.
type StandDownSignal struct {
	Actor  string `json:"actor"`
	Reason string `json:"reason"`
}

// SARAuditEntry is one recorded coordination fact (accepted or rejected).
type SARAuditEntry struct {
	Kind   string `json:"kind"` // phase, tasking, sitrep, standdown
	Actor  string `json:"actor"`
	Detail string `json:"detail"`
}

// SARState is the queryable coordination state.
type SARState struct {
	CaseID          string            `json:"case_id"`
	Phase           sar.Phase         `json:"phase"`
	Stage           sar.Stage         `json:"stage"`
	Taskings        map[string]string `json:"taskings"`
	LastSitrepSeq   int               `json:"last_sitrep_seq"`
	StandDownReason string            `json:"stand_down_reason,omitempty"`
}

// SARResult is the terminal workflow result.
type SARResult struct {
	CaseID string    `json:"case_id"`
	Stage  sar.Stage `json:"stage"`
}

// SARActivities groups the durable side effects the workflow invokes.
type SARActivities struct {
	// AuditTransition persists one accepted transition audit record.
	AuditTransition func(ctx context.Context, caseID string, entry SARAuditEntry) error
}

// SARWorkflow binds the workflow definition to its activity dependencies.
type SARWorkflow struct{ activities *SARActivities }

// NewSARWorkflow fails closed when activities are absent.
func NewSARWorkflow(activities *SARActivities) (*SARWorkflow, error) {
	if activities == nil || activities.AuditTransition == nil {
		return nil, errors.New("sar activities are required (fail-closed)")
	}
	return &SARWorkflow{activities: activities}, nil
}

// SARCaseWorkflow coordinates one case from AWARENESS to STAND_DOWN. It
// accepts phase, tasking and sitrep signals in any valid order until the
// terminal stand-down signal completes the workflow.
func (workflowDef *SARWorkflow) SARCaseWorkflow(ctx workflow.Context, input CaseInput) (SARResult, error) {
	if input.CaseID == "" {
		return SARResult{}, errors.New("case_id is required")
	}
	phase, err := sar.ParsePhase(input.Phase)
	if err != nil {
		return SARResult{}, err
	}
	state := SARState{
		CaseID: input.CaseID, Phase: phase, Stage: sar.StageAwareness,
		Taskings: map[string]string{},
	}
	history := make([]SARAuditEntry, 0)
	if err := workflow.SetQueryHandler(ctx, QuerySARState, func() (SARState, error) { return state, nil }); err != nil {
		return SARResult{}, fmt.Errorf("register state query: %w", err)
	}
	if err := workflow.SetQueryHandler(ctx, QuerySARHistory, func() ([]SARAuditEntry, error) { return history, nil }); err != nil {
		return SARResult{}, fmt.Errorf("register history query: %w", err)
	}
	activityCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{StartToCloseTimeout: 2 * time.Minute})

	audit := func(entry SARAuditEntry) error {
		if err := workflow.ExecuteActivity(activityCtx, ActivitySARAuditTransition, input.CaseID, entry).Get(activityCtx, nil); err != nil {
			return fmt.Errorf("audit %s transition: %w", entry.Kind, err)
		}
		history = append(history, entry)
		return nil
	}
	reject := func(kind, actor, detail string) {
		history = append(history, SARAuditEntry{Kind: kind, Actor: actor, Detail: "rejected: " + detail})
	}

	phaseChan := workflow.GetSignalChannel(ctx, SignalPhase)
	taskingChan := workflow.GetSignalChannel(ctx, SignalTasking)
	sitrepChan := workflow.GetSignalChannel(ctx, SignalSitrep)
	standDownChan := workflow.GetSignalChannel(ctx, SignalStandDown)

	for {
		selector := workflow.NewSelector(ctx)
		var phaseSignal PhaseSignal
		var taskingSignal TaskingSignal
		var sitrepSignal SitrepSignal
		var standDown StandDownSignal
		stoodDown := false
		selector.AddReceive(phaseChan, func(channel workflow.ReceiveChannel, more bool) {
			channel.Receive(ctx, &phaseSignal)
		})
		selector.AddReceive(taskingChan, func(channel workflow.ReceiveChannel, more bool) {
			channel.Receive(ctx, &taskingSignal)
		})
		selector.AddReceive(sitrepChan, func(channel workflow.ReceiveChannel, more bool) {
			channel.Receive(ctx, &sitrepSignal)
		})
		selector.AddReceive(standDownChan, func(channel workflow.ReceiveChannel, more bool) {
			channel.Receive(ctx, &standDown)
			stoodDown = true
		})
		selector.Select(ctx)

		switch {
		case stoodDown:
			if standDown.Actor == "" {
				reject("standdown", "", "stand-down signal requires an actor identity")
				continue
			}
			reason, err := sar.ParseStandDownReason(standDown.Reason)
			if err != nil {
				reject("standdown", standDown.Actor, err.Error())
				continue
			}
			if err := audit(SARAuditEntry{Kind: "standdown", Actor: standDown.Actor, Detail: string(reason)}); err != nil {
				return SARResult{}, err
			}
			state.Stage = sar.StageStandDown
			state.StandDownReason = string(reason)
			return SARResult{CaseID: input.CaseID, Stage: sar.StageStandDown}, nil
		case phaseSignal.Actor != "" || phaseSignal.Phase != "" || phaseSignal.Rationale != "":
			next, err := sar.ParsePhase(phaseSignal.Phase)
			if err != nil {
				reject("phase", phaseSignal.Actor, err.Error())
				continue
			}
			if phaseSignal.Actor == "" || phaseSignal.Rationale == "" {
				reject("phase", phaseSignal.Actor, "phase signal requires actor and rationale")
				continue
			}
			if state.Phase == next {
				reject("phase", phaseSignal.Actor, "same-phase signal carries no fact")
				continue
			}
			if err := audit(SARAuditEntry{Kind: "phase", Actor: phaseSignal.Actor,
				Detail: fmt.Sprintf("%s -> %s: %s", state.Phase, next, phaseSignal.Rationale)}); err != nil {
				return SARResult{}, err
			}
			state.Phase = next
		case taskingSignal.Actor != "" || taskingSignal.TaskingID != "" || taskingSignal.State != "":
			next := sar.TaskingState(taskingSignal.State)
			current, tracked := state.Taskings[taskingSignal.TaskingID]
			if !tracked {
				if next != sar.TaskingProposed {
					reject("tasking", taskingSignal.Actor, "unknown tasking must first be PROPOSED")
					continue
				}
				current = ""
			}
			// PROPOSED is the registration of the order itself and needs no
			// transition reason; every later transition requires one.
			if next != sar.TaskingProposed {
				if err := sar.TaskingTransitionReason(next, taskingSignal.ReasonCode); err != nil {
					reject("tasking", taskingSignal.Actor, err.Error())
					continue
				}
			}
			if tracked && !sar.ValidTaskingTransition(sar.TaskingState(current), next) {
				reject("tasking", taskingSignal.Actor,
					fmt.Sprintf("illegal tasking transition %s -> %s", current, next))
				continue
			}
			if err := audit(SARAuditEntry{Kind: "tasking", Actor: taskingSignal.Actor,
				Detail: fmt.Sprintf("%s: %s -> %s (%s)", taskingSignal.TaskingID, current, next, taskingSignal.ReasonCode)}); err != nil {
				return SARResult{}, err
			}
			state.Taskings[taskingSignal.TaskingID] = string(next)
		case sitrepSignal.Actor != "" || sitrepSignal.Sequence != 0:
			if sitrepSignal.Actor == "" || sitrepSignal.Sequence <= state.LastSitrepSeq {
				reject("sitrep", sitrepSignal.Actor, "sitrep sequence must increase monotonically")
				continue
			}
			if err := audit(SARAuditEntry{Kind: "sitrep", Actor: sitrepSignal.Actor,
				Detail: fmt.Sprintf("sitrep #%d issued", sitrepSignal.Sequence)}); err != nil {
				return SARResult{}, err
			}
			state.LastSitrepSeq = sitrepSignal.Sequence
		}
	}
}
