package isr

import (
	"testing"
	"time"
)

func TestClassificationParseFailsClosed(t *testing.T) {
	for _, raw := range []string{"UNCLASSIFIED", "RESTRICTED", "CONFIDENTIAL", "SECRET"} {
		if _, err := ParseClassification(raw); err != nil {
			t.Fatalf("approved label %q rejected: %v", raw, err)
		}
	}
	for _, raw := range []string{"", "unclassified", "Secret", "TOP SECRET", "none"} {
		if _, err := ParseClassification(raw); err == nil {
			t.Fatalf("invalid label %q accepted", raw)
		}
	}
}

func TestClearanceCovers(t *testing.T) {
	if !ClassificationSecret.Covers(ClassificationConfidential) {
		t.Fatal("secret clearance must cover confidential material")
	}
	if ClassificationRestricted.Covers(ClassificationSecret) {
		t.Fatal("restricted clearance must not cover secret material")
	}
	if !ClassificationUnclassified.Covers(ClassificationUnclassified) {
		t.Fatal("equal clearance must cover")
	}
	if Classification("bogus").Covers(ClassificationUnclassified) {
		t.Fatal("invalid clearance must cover nothing")
	}
	if ClassificationSecret.Covers(Classification("bogus")) {
		t.Fatal("invalid event label must be uncovered")
	}
}

func TestMaxClassification(t *testing.T) {
	if MaxClassification(ClassificationRestricted, ClassificationSecret) != ClassificationSecret {
		t.Fatal("max must pick the more sensitive label")
	}
	if MaxClassification(ClassificationConfidential, ClassificationUnclassified) != ClassificationConfidential {
		t.Fatal("max must pick the more sensitive label")
	}
}

func validDetection() Detection {
	return Detection{
		EventID: "evt-001", SourceID: "sar-feed", SourceEventID: "src-001",
		Modality: ModalitySAR, Classification: ClassificationConfidential,
		ObservedAt:  time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC),
		HasPosition: true, Latitude: 6.45, Longitude: 3.39,
		SAR: &SARPayload{SceneRef: "scene-001", Confidence: 0.85},
	}
}

func TestDetectionValidation(t *testing.T) {
	if err := validDetection().Validate(); err != nil {
		t.Fatal(err)
	}
	missing := validDetection()
	missing.Classification = ""
	if err := missing.Validate(); err == nil {
		t.Fatal("missing classification accepted")
	}
	invalid := validDetection()
	invalid.Classification = "TOP-SECRET"
	if err := invalid.Validate(); err == nil {
		t.Fatal("invalid classification accepted")
	}
	noPayload := validDetection()
	noPayload.SAR = nil
	if err := noPayload.Validate(); err == nil {
		t.Fatal("missing modality payload accepted")
	}
	mixed := validDetection()
	mixed.AIS = &AISPayload{MMSI: "636019999", SpeedKnots: 5, HeadingDeg: 90}
	if err := mixed.Validate(); err == nil {
		t.Fatal("mixed modality payloads accepted")
	}
	noPosition := validDetection()
	noPosition.HasPosition = false
	noPosition.Latitude, noPosition.Longitude = 0, 0
	if err := noPosition.Validate(); err != nil {
		t.Fatal(err)
	}
	badPosition := validDetection()
	badPosition.Latitude = 95
	if err := badPosition.Validate(); err == nil {
		t.Fatal("out-of-range latitude accepted")
	}
}

func TestModalityPayloadValidation(t *testing.T) {
	if err := (AISPayload{MMSI: "636019999", SpeedKnots: 12.5, HeadingDeg: 270}).validate(); err != nil {
		t.Fatal(err)
	}
	if err := (AISPayload{MMSI: "12345", SpeedKnots: 1, HeadingDeg: 1}).validate(); err == nil {
		t.Fatal("short MMSI accepted")
	}
	if err := (AISPayload{MMSI: "636019999", SpeedKnots: 103, HeadingDeg: 1}).validate(); err == nil {
		t.Fatal("impossible AIS speed accepted")
	}
	if err := (SARPayload{SceneRef: "scene-1", Confidence: 0}).validate(); err != nil {
		t.Fatal("zero confidence is a valid explicit value")
	}
	if err := (SARPayload{SceneRef: "scene-1", Confidence: 1.01}).validate(); err == nil {
		t.Fatal("confidence above 1 accepted")
	}
	if err := (SARPayload{Confidence: 0.5}).validate(); err == nil {
		t.Fatal("missing SAR scene ref accepted")
	}
	if err := (RFPayload{FrequencyBand: "VHF", BearingDeg: 45}).validate(); err != nil {
		t.Fatal(err)
	}
	if err := (RFPayload{FrequencyBand: "CB", BearingDeg: 45}).validate(); err == nil {
		t.Fatal("unapproved RF band accepted")
	}
	if err := (RFPayload{FrequencyBand: "UHF", BearingDeg: 361}).validate(); err == nil {
		t.Fatal("bearing above 360 accepted")
	}
	if err := (AcousticPayload{SignatureRef: "hydro-sig-1", Confidence: 0.7}).validate(); err != nil {
		t.Fatal(err)
	}
	if err := (AcousticPayload{Confidence: 0.7}).validate(); err == nil {
		t.Fatal("missing acoustic signature ref accepted")
	}
	optical := OpticalPayload{ImageRef: "img-001", Boxes: []DetectionBox{{X: 0.1, Y: 0.1, Width: 0.2, Height: 0.2, Confidence: 0.9}}}
	if err := optical.validate(); err != nil {
		t.Fatal(err)
	}
	if err := (OpticalPayload{ImageRef: "img-001"}).validate(); err == nil {
		t.Fatal("optical payload without detection boxes accepted")
	}
	overflow := OpticalPayload{ImageRef: "img-001", Boxes: []DetectionBox{{X: 0.9, Y: 0.9, Width: 0.2, Height: 0.2, Confidence: 0.9}}}
	if err := overflow.validate(); err == nil {
		t.Fatal("detection box exceeding image bounds accepted")
	}
}
