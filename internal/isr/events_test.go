package isr

import (
	"strings"
	"testing"
	"time"
)

func validAISDetection() Detection {
	return Detection{
		EventID: "evt-001", SourceID: "ais-feed", SourceEventID: "src-001",
		Modality: ModalityAIS, Classification: ClassificationUnclassified,
		ObservedAt:  time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC),
		HasPosition: true, Latitude: 6.45, Longitude: 3.39,
		MMSI: "636019999",
		AIS:  &AISPayload{MMSI: "636019999", SpeedKnots: 12.5, HeadingDeg: 90, NavStatus: "under way"},
	}
}

func TestDetectionValidationBoundaries(t *testing.T) {
	base := validAISDetection()
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	// Latitude boundary values are accepted; beyond them rejected.
	for _, latitude := range []float64{-90, 90} {
		candidate := base
		candidate.Latitude = latitude
		if err := candidate.Validate(); err != nil {
			t.Fatalf("latitude %v must validate", latitude)
		}
	}
	for _, latitude := range []float64{-90.000001, 90.000001} {
		candidate := base
		candidate.Latitude = latitude
		if err := candidate.Validate(); err == nil {
			t.Fatalf("latitude %v must fail", latitude)
		}
	}
	// Missing classification fails closed.
	candidate := base
	candidate.Classification = ""
	if err := candidate.Validate(); err == nil {
		t.Fatal("missing classification must fail closed")
	}
	// Exactly one modality payload: an AIS detection carrying a SAR payload
	// is rejected.
	candidate = base
	candidate.SAR = &SARPayload{SceneRef: "scene-1", Confidence: 0.5}
	if err := candidate.Validate(); err == nil {
		t.Fatal("multi-modality payload must fail")
	}
	// Modality payload required.
	candidate = base
	candidate.AIS = nil
	if err := candidate.Validate(); err == nil {
		t.Fatal("missing modality payload must fail")
	}
	// Unknown modality fails closed.
	candidate = base
	candidate.Modality = "LIDAR"
	if err := candidate.Validate(); err == nil {
		t.Fatal("unknown modality must fail closed")
	}
	// MMSI must be 9 digits when present.
	candidate = base
	candidate.MMSI = "12345"
	if err := candidate.Validate(); err == nil {
		t.Fatal("short MMSI must fail")
	}
	// A positionless detection (bearing-only RF fix) may be admitted.
	rf := Detection{
		EventID: "evt-rf", SourceID: "rf-feed", SourceEventID: "src-rf",
		Modality: ModalityRF, Classification: ClassificationRestricted,
		ObservedAt: time.Date(2026, 8, 15, 12, 5, 0, 0, time.UTC),
		RF:         &RFPayload{FrequencyBand: "VHF", BearingDeg: 45},
	}
	if err := rf.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestModalityPayloadValidation(t *testing.T) {
	// SAR confidence is a unit interval.
	sar := validAISDetection()
	sar.Modality = ModalitySAR
	sar.AIS = nil
	sar.MMSI = ""
	sar.SAR = &SARPayload{SceneRef: "scene-1", Confidence: 1.000001}
	if err := sar.Validate(); err == nil {
		t.Fatal("SAR confidence above 1 must fail")
	}
	sar.SAR.Confidence = 1.0
	if err := sar.Validate(); err != nil {
		t.Fatal(err)
	}
	// RF band must be approved.
	rf := Detection{
		EventID: "evt-rf2", SourceID: "rf-feed", SourceEventID: "src-rf2",
		Modality: ModalityRF, Classification: ClassificationRestricted,
		ObservedAt: time.Now().UTC(),
		RF:         &RFPayload{FrequencyBand: "CB", BearingDeg: 10},
	}
	if err := rf.Validate(); err == nil {
		t.Fatal("unapproved frequency band must fail closed")
	}
	// Optical boxes must be normalised and bounded.
	optical := Detection{
		EventID: "evt-op", SourceID: "op-feed", SourceEventID: "src-op",
		Modality: ModalityOptical, Classification: ClassificationConfidential,
		ObservedAt: time.Now().UTC(),
		Optical:    &OpticalPayload{ImageRef: "img-1", Boxes: []DetectionBox{{X: 0.9, Y: 0.1, Width: 0.2, Height: 0.1, Confidence: 0.9}}},
	}
	if err := optical.Validate(); err == nil {
		t.Fatal("out-of-bounds detection box must fail")
	}
	optical.Optical.Boxes[0].Width = 0.1
	if err := optical.Validate(); err != nil {
		t.Fatal(err)
	}
	optical.Optical.Boxes = nil
	if err := optical.Validate(); err == nil {
		t.Fatal("empty detection boxes must fail")
	}
	// Acoustic signature reference is required.
	acoustic := Detection{
		EventID: "evt-ac", SourceID: "ac-feed", SourceEventID: "src-ac",
		Modality: ModalityAcoustic, Classification: ClassificationRestricted,
		ObservedAt: time.Now().UTC(),
		Acoustic:   &AcousticPayload{SignatureRef: "", Confidence: 0.5},
	}
	if err := acoustic.Validate(); err == nil {
		t.Fatal("missing acoustic signature ref must fail")
	}
}

func TestClassificationParsing(t *testing.T) {
	for _, raw := range []string{"unclassified", "RESTRICTED", "confidential", " Secret "} {
		if _, err := ParseClassification(raw); err != nil {
			t.Fatalf("%q must parse", raw)
		}
	}
	for _, raw := range []string{"", "TOP-SECRET", "public", "internal"} {
		if _, err := ParseClassification(raw); err == nil {
			t.Fatalf("%q must fail closed", raw)
		}
	}
	if !ClassificationSecret.Covers(ClassificationConfidential) || ClassificationRestricted.Covers(ClassificationSecret) {
		t.Fatal("clearance coverage ordering is wrong")
	}
	if Max(ClassificationRestricted, ClassificationSecret) != ClassificationSecret {
		t.Fatal("classification max is wrong")
	}
	if !strings.EqualFold(string(ClassificationUnclassified), "unclassified") {
		t.Fatal("canonical label changed")
	}
}
