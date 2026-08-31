package cvconsumer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/tracks"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/workflow"
)

// ── test doubles ────────────────────────────────────────────────────────────

type recordedAnomaly struct{ anomalies []tracks.Anomaly }

func (r *recordedAnomaly) RecordAnomalies(_ context.Context, a []tracks.Anomaly) error {
	r.anomalies = append(r.anomalies, a...)
	return nil
}

type recordedStarts struct{ inputs []workflow.AlertInput }

func (s *recordedStarts) StartISR(_ context.Context, in workflow.AlertInput) error {
	s.inputs = append(s.inputs, in)
	return nil
}

type recordedRejections struct{ reasons []string }

func (r *recordedRejections) RecordRejection(_ context.Context, _, reason string) {
	r.reasons = append(r.reasons, reason)
}

type failingStarter struct{}

func (failingStarter) StartISR(context.Context, workflow.AlertInput) error {
	return fmt.Errorf("temporal unavailable")
}

// ── helpers ─────────────────────────────────────────────────────────────────

func testKey(t *testing.T) (*provenance.Signer, *provenance.Directory) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := provenance.NewSigner("blueeconomy-cv-service-0", priv)
	if err != nil {
		t.Fatal(err)
	}
	pub := base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	directory, err := provenance.ParseDirectory([]byte(fmt.Sprintf(`{"blueeconomy-cv-service-0":%q}`, pub)))
	if err != nil {
		t.Fatal(err)
	}
	return signer, directory
}

func signedEnvelope(t *testing.T, signer *provenance.Signer, eventType, classification string, resource map[string]any) []byte {
	t.Helper()
	envelope := map[string]any{
		"envelopeVersion": "1.0",
		"eventId":         "evt-" + eventType,
		"eventType":       eventType,
		"occurredAt":      time.Now().UTC().Format(time.RFC3339),
		"producer":        "blueeconomy-cv-service",
		"correlationId":   "corr-1",
		"fhir": map[string]any{
			"resourceType": "Bundle",
			"type":         "message",
			"bundleId":     "bdl-1",
			"entry": []any{map[string]any{
				"fullUrl":  "urn:uuid:1",
				"resource": resource,
			}},
		},
		"provenance": map[string]any{
			"principalId": "cv", "principalRole": "SERVICE",
			"ledgerCommitHash": "", "signature": "",
		},
		"classification": classification,
	}
	signature, err := signer.SignEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	envelope["provenance"].(map[string]any)["signature"] = signature
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func vesselResource() map[string]any {
	return map[string]any{
		"@type":           "type.googleapis.com/blueeconomy.cv.v1.VesselDetected",
		"cameraId":        "cam-1",
		"trackId":         "7",
		"vesselClass":     "cargo",
		"confidence":      0.9,
		"bboxXyxy":        []any{1.0, 2.0, 10.0, 20.0},
		"frameSha256":     "abc",
		"modelVersion":    "yolox-s@abc",
		"mmsi":            "",
		"latitudeMicros":  6_000_000,
		"longitudeMicros": 3_000_000,
	}
}

func darkVesselResource() map[string]any {
	return map[string]any{
		"@type":           "type.googleapis.com/blueeconomy.cv.v1.DarkVesselObserved",
		"cameraId":        "cam-2",
		"trackId":         "9",
		"confidence":      0.8,
		"latitudeMicros":  6_100_000,
		"longitudeMicros": 3_100_000,
		"frameSha256":     "def",
		"modelVersion":    "yolox-s@abc",
	}
}

func newTestConsumer(t *testing.T, directory *provenance.Directory, recorder tracks.AnomalyRecorder, starter ISRStarter, rejections RejectionRecorder) *Consumer {
	t.Helper()
	config := tracks.DefaultConfig()
	engine, err := tracks.NewEngine(config, nil, nil, time.Now, func() string { return "track-1" })
	if err != nil {
		t.Fatal(err)
	}
	id := 0
	consumer, err := New(directory, engine, recorder, starter, rejections, nil, func() string {
		id++
		return fmt.Sprintf("id-%d", id)
	})
	if err != nil {
		t.Fatal(err)
	}
	return consumer
}

// ── tests ───────────────────────────────────────────────────────────────────

func TestNewFailsClosedOnMissingDeps(t *testing.T) {
	if _, err := New(nil, nil, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("expected error for nil directory")
	}
}

func TestDarkVesselVerifiedStartsISRWorkflow(t *testing.T) {
	signer, directory := testKey(t)
	recorder := &recordedAnomaly{}
	starter := &recordedStarts{}
	consumer := newTestConsumer(t, directory, recorder, starter, nil)

	raw := signedEnvelope(t, signer, TopicDarkVessel, "RESTRICTED", darkVesselResource())
	if err := consumer.HandleDarkVessel(context.Background(), raw); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(recorder.anomalies) != 1 {
		t.Fatalf("expected 1 persisted anomaly, got %d", len(recorder.anomalies))
	}
	anomaly := recorder.anomalies[0]
	if anomaly.Kind != tracks.AnomalyDarkVessel || anomaly.Classification != isr.ClassificationRestricted {
		t.Fatalf("unexpected anomaly: %+v", anomaly)
	}
	if len(starter.inputs) != 1 {
		t.Fatalf("expected 1 ISR workflow start, got %d", len(starter.inputs))
	}
	start := starter.inputs[0]
	if start.AlertID != anomaly.AnomalyID || start.AnomalyID != anomaly.AnomalyID {
		t.Fatalf("starter contract violated: %+v", start)
	}
	if start.Classification != isr.ClassificationRestricted {
		t.Fatalf("clearance not propagated: %+v", start)
	}
}

func TestDarkVesselTamperedSignatureRejected(t *testing.T) {
	signer, directory := testKey(t)
	starter := &recordedStarts{}
	rejections := &recordedRejections{}
	consumer := newTestConsumer(t, directory, &recordedAnomaly{}, starter, rejections)

	raw := signedEnvelope(t, signer, TopicDarkVessel, "RESTRICTED", darkVesselResource())
	// Tamper: flip the confidence inside the signed payload.
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	entry := doc["fhir"].(map[string]any)["entry"].([]any)[0].(map[string]any)
	entry["resource"].(map[string]any)["confidence"] = 0.01
	tampered, _ := json.Marshal(doc)

	if err := consumer.HandleDarkVessel(context.Background(), tampered); err == nil {
		t.Fatal("expected signature rejection")
	}
	if len(starter.inputs) != 0 {
		t.Fatal("workflow must not start on rejected records")
	}
	if len(rejections.reasons) != 1 || rejections.reasons[0] != RejectSignature {
		t.Fatalf("expected signature rejection reason, got %v", rejections.reasons)
	}
}

func TestDarkVesselUnsignedRejected(t *testing.T) {
	_, directory := testKey(t)
	starter := &recordedStarts{}
	consumer := newTestConsumer(t, directory, &recordedAnomaly{}, starter, nil)
	unsigned := []byte(`{"envelopeVersion":"1.0","eventType":"cv.dark-vessel.v1","provenance":{"signature":""},"fhir":{"resourceType":"Bundle","type":"message","entry":[]}}`)
	if err := consumer.HandleDarkVessel(context.Background(), unsigned); err == nil {
		t.Fatal("expected rejection of unsigned envelope")
	}
	if len(starter.inputs) != 0 {
		t.Fatal("workflow must not start on unsigned records")
	}
}

func TestDarkVesselStarterFailurePropagates(t *testing.T) {
	signer, directory := testKey(t)
	consumer := newTestConsumer(t, directory, &recordedAnomaly{}, failingStarter{}, nil)
	raw := signedEnvelope(t, signer, TopicDarkVessel, "RESTRICTED", darkVesselResource())
	if err := consumer.HandleDarkVessel(context.Background(), raw); err == nil {
		t.Fatal("starter failure must propagate (offset not committed)")
	}
}

func TestVesselDetectionFeedsFusion(t *testing.T) {
	signer, directory := testKey(t)
	recorder := &recordedAnomaly{}
	starter := &recordedStarts{}
	consumer := newTestConsumer(t, directory, recorder, starter, nil)

	raw := signedEnvelope(t, signer, TopicVesselDetection, "INTERNAL", vesselResource())
	if err := consumer.HandleVesselDetection(context.Background(), raw); err != nil {
		t.Fatalf("handle: %v", err)
	}
	// The detection entered the fusion engine as one track.
	engine := consumer.engine
	if got := len(engine.Tracks()); got != 1 {
		t.Fatalf("expected 1 fused track, got %d", got)
	}
	track := engine.Tracks()[0]
	if track.Classification != isr.ClassificationUnclassified {
		t.Fatalf("INTERNAL must map to UNCLASSIFIED, got %s", track.Classification)
	}
	point, ok := track.Last()
	if !ok || point.Position.Latitude != 6.0 || point.Position.Longitude != 3.0 {
		t.Fatalf("position not fused: %+v", point)
	}
}

func TestVesselDetectionWithoutPositionRejected(t *testing.T) {
	signer, directory := testKey(t)
	rejections := &recordedRejections{}
	consumer := newTestConsumer(t, directory, &recordedAnomaly{}, &recordedStarts{}, rejections)
	resource := vesselResource()
	resource["latitudeMicros"] = 0
	resource["longitudeMicros"] = 0
	raw := signedEnvelope(t, signer, TopicVesselDetection, "INTERNAL", resource)
	if err := consumer.HandleVesselDetection(context.Background(), raw); err == nil {
		t.Fatal("expected rejection of positionless detection")
	}
	if len(rejections.reasons) == 0 || rejections.reasons[len(rejections.reasons)-1] != RejectPayload {
		t.Fatalf("expected payload rejection, got %v", rejections.reasons)
	}
}

func TestUnknownClassificationRejected(t *testing.T) {
	signer, directory := testKey(t)
	rejections := &recordedRejections{}
	consumer := newTestConsumer(t, directory, &recordedAnomaly{}, &recordedStarts{}, rejections)
	raw := signedEnvelope(t, signer, TopicDarkVessel, "TOP-SECRET-MAVERICK", darkVesselResource())
	if err := consumer.HandleDarkVessel(context.Background(), raw); err == nil {
		t.Fatal("expected classification rejection")
	}
	if rejections.reasons[len(rejections.reasons)-1] != RejectClassification {
		t.Fatalf("got %v", rejections.reasons)
	}
}

func TestWrongTopicEventTypeRejected(t *testing.T) {
	signer, directory := testKey(t)
	rejections := &recordedRejections{}
	consumer := newTestConsumer(t, directory, &recordedAnomaly{}, &recordedStarts{}, rejections)
	raw := signedEnvelope(t, signer, TopicVesselDetection, "INTERNAL", vesselResource())
	if err := consumer.HandleDarkVessel(context.Background(), raw); err == nil {
		t.Fatal("expected event-type rejection")
	}
	if rejections.reasons[len(rejections.reasons)-1] != RejectUnknownType {
		t.Fatalf("got %v", rejections.reasons)
	}
}
