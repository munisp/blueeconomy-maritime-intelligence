package sar

import (
	"testing"
)

func TestStageMachine(t *testing.T) {
	if !ValidStageTransition(StageAwareness, StageInitialAction) {
		t.Fatal("awareness->initial_action must be legal")
	}
	if !ValidStageTransition(StageCoordination, StageStandDown) {
		t.Fatal("coordination->stand_down must be legal")
	}
	if ValidStageTransition(StageInitialAction, StageAwareness) {
		t.Fatal("stage regression must be illegal")
	}
	if ValidStageTransition(StageStandDown, StageAwareness) {
		t.Fatal("stand_down must be terminal")
	}
	if ValidStageTransition(StageAwareness, StageAwareness) {
		t.Fatal("same-stage carries no fact")
	}
}

func TestPhaseAndReasonValidation(t *testing.T) {
	if _, err := ParsePhase("MAYDAY"); err == nil {
		t.Fatal("invalid phase accepted")
	}
	if _, err := ParseStandDownReason("BOGUS"); err == nil {
		t.Fatal("invalid stand-down reason accepted")
	}
	if err := TaskingTransitionReason(TaskingTasked, "order-issued"); err != nil {
		t.Fatal(err)
	}
	if err := TaskingTransitionReason(TaskingTasked, "made-up"); err == nil {
		t.Fatal("unknown tasking reason code accepted")
	}
	if err := TaskingTransitionReason(TaskingAcked, ""); err == nil {
		t.Fatal("missing reason code accepted")
	}
}

func TestTaskingStateMachine(t *testing.T) {
	if !ValidTaskingTransition(TaskingProposed, TaskingTasked) {
		t.Fatal("proposed->tasked must be legal")
	}
	if !ValidTaskingTransition(TaskingOnScene, TaskingAborted) {
		t.Fatal("on_scene->aborted must be legal")
	}
	if ValidTaskingTransition(TaskingProposed, TaskingOnScene) {
		t.Fatal("proposed->on_scene must be illegal")
	}
	if ValidTaskingTransition(TaskingReleased, TaskingTasked) {
		t.Fatal("released must be terminal")
	}
}

func TestOpenCaseValidation(t *testing.T) {
	valid := OpenCaseRequest{
		IncidentID: "inc-1", SourceRef: "manual:log-1", Classification: "RESTRICTED", Phase: "INCERFA",
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := valid
	bad.Classification = "NOFORN"
	if err := bad.Validate(); err == nil {
		t.Fatal("invalid classification accepted")
	}
	bad = valid
	negative := -1
	bad.PersonsAtRisk = &negative
	if err := bad.Validate(); err == nil {
		t.Fatal("negative persons_at_risk accepted")
	}
}
