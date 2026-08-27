package isr

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type labelledPayload struct {
	Classification Classification `json:"classification"`
	Note           string         `json:"note"`
}

func TestSealEnvelopeClassificationMatch(t *testing.T) {
	occurred := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	payload := labelledPayload{Classification: ClassificationRestricted, Note: "detection admitted"}
	envelope, _, err := Seal(TopicISR, "isr.detection_admitted", "evt-001", ClassificationRestricted, occurred, payload)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.EnvelopeVersion != EnvelopeVersion || envelope.Topic != TopicISR {
		t.Fatalf("unexpected envelope: %+v", envelope)
	}
	if envelope.Classification != ClassificationRestricted {
		t.Fatal("envelope classification mismatch")
	}
	encoded, err := envelope.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip Envelope
	if err := json.Unmarshal(encoded, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if roundtrip.EventID == "" || !strings.EqualFold(roundtrip.Source, "blueeconomy-maritime-intelligence") {
		t.Fatal("envelope lost identity fields")
	}
}

func TestSealFailsClosedOnMismatch(t *testing.T) {
	occurred := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	payload := labelledPayload{Classification: ClassificationSecret, Note: "track fused"}
	if _, _, err := Seal(TopicBehaviour, "behaviour.anomaly", "track-1", ClassificationUnclassified, occurred, payload); err == nil {
		t.Fatal("envelope/payload classification mismatch accepted")
	}
	if _, _, err := Seal("maritime.unknown.v1", "x", "k", ClassificationSecret, occurred, payload); err == nil {
		t.Fatal("unapproved topic accepted")
	}
	unlabelled := struct {
		Note string `json:"note"`
	}{Note: "no label"}
	if _, _, err := Seal(TopicISR, "isr.x", "k", ClassificationUnclassified, occurred, unlabelled); err == nil {
		t.Fatal("payload without classification label sealed")
	}
	if _, _, err := Seal(TopicISR, "isr.x", "k", "BOGUS", occurred, payload); err == nil {
		t.Fatal("invalid envelope classification accepted")
	}
}
