// Package cvconsumer admits signed blueeconomy-cv-service events
// (cv.vessel-detection.v1, cv.dark-vessel.v1) into the maritime-intelligence
// track-fusion and ISR response pipeline.
//
// Admission is fail-closed: every Kafka record must be a canonical platform
// envelope v1.0 whose provenance JWS-EdDSA signature verifies against the
// mounted key directory (internal/provenance). Rejected records are counted
// with their reason code and never reach the fusion engine.
//
// Wiring:
//   - cv.vessel-detection.v1 feeds the track-fusion engine as OPTICAL
//     detections; any dark-vessel anomaly the engine raises starts one
//     ISRResponseWorkflow instance (idempotent, workflow ID = anomaly ID).
//   - cv.dark-vessel.v1 is persisted as a dark-vessel anomaly (with its
//     behaviour outbox envelope) and starts one ISRResponseWorkflow instance
//     per anomaly — replacing the previous "external tooling" starter gap.
package cvconsumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/tracks"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/workflow"
)

// Consumed cv-service topics (blueeconomy-cv-service producers).
const (
	TopicVesselDetection = "cv.vessel-detection.v1"
	TopicDarkVessel      = "cv.dark-vessel.v1"
)

// Rejection reason codes (fail-closed admission discipline).
const (
	RejectSignature      = "signature-verification-failed"
	RejectMalformed      = "malformed-envelope"
	RejectUnknownType    = "unknown-event-type"
	RejectClassification = "unmapped-classification"
	RejectPayload        = "invalid-payload"
)

// ISRStarter starts one ISRResponseWorkflow per anomaly. The Temporal
// implementation uses the anomaly ID as the workflow ID, making restarts
// idempotent.
type ISRStarter interface {
	StartISR(ctx context.Context, input workflow.AlertInput) error
}

// RejectionRecorder receives admission rejections with their reason code.
type RejectionRecorder interface {
	RecordRejection(ctx context.Context, topic, reason string)
}

type noopRejections struct{}

func (noopRejections) RecordRejection(context.Context, string, string) {}

// Consumer verifies and routes cv-service envelopes.
type Consumer struct {
	directory  *provenance.Directory
	engine     *tracks.Engine
	recorder   tracks.AnomalyRecorder
	starter    ISRStarter
	rejections RejectionRecorder
	logger     *slog.Logger
	newID      func() string
	now        func() time.Time
}

// New fails closed on any missing dependency.
func New(directory *provenance.Directory, engine *tracks.Engine, recorder tracks.AnomalyRecorder, starter ISRStarter, rejections RejectionRecorder, logger *slog.Logger, newID func() string) (*Consumer, error) {
	if directory == nil {
		return nil, errors.New("cv consumer requires a provenance key directory")
	}
	if engine == nil {
		return nil, errors.New("cv consumer requires a track-fusion engine")
	}
	if recorder == nil {
		return nil, errors.New("cv consumer requires an anomaly recorder")
	}
	if starter == nil {
		return nil, errors.New("cv consumer requires an ISR workflow starter")
	}
	if newID == nil {
		return nil, errors.New("cv consumer requires an ID generator")
	}
	if rejections == nil {
		rejections = noopRejections{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Consumer{
		directory: directory, engine: engine, recorder: recorder,
		starter: starter, rejections: rejections, logger: logger,
		newID: newID, now: time.Now,
	}, nil
}

// envelopeView is the validated view of one signed envelope document.
type envelopeView struct {
	EnvelopeVersion string `json:"envelopeVersion"`
	EventID         string `json:"eventId"`
	EventType       string `json:"eventType"`
	OccurredAt      string `json:"occurredAt"`
	Producer        string `json:"producer"`
	Classification  string `json:"classification"`
	FHIR            struct {
		ResourceType string `json:"resourceType"`
		Type         string `json:"type"`
		Entry        []struct {
			Resource json.RawMessage `json:"resource"`
		} `json:"entry"`
	} `json:"fhir"`
}

// verify admits one raw envelope: signature verification first (mandatory),
// then structural validation. Returns the parsed view.
func (c *Consumer) verify(ctx context.Context, topic string, raw []byte, wantType string) (*envelopeView, error) {
	if err := c.directory.VerifyEnvelope(raw); err != nil {
		c.rejections.RecordRejection(ctx, topic, RejectSignature)
		return nil, fmt.Errorf("%s: %w", RejectSignature, err)
	}
	var view envelopeView
	if err := json.Unmarshal(raw, &view); err != nil {
		c.rejections.RecordRejection(ctx, topic, RejectMalformed)
		return nil, fmt.Errorf("%s: %w", RejectMalformed, err)
	}
	if view.EnvelopeVersion != "1.0" || view.FHIR.ResourceType != "Bundle" ||
		view.FHIR.Type != "message" || len(view.FHIR.Entry) != 1 {
		c.rejections.RecordRejection(ctx, topic, RejectMalformed)
		return nil, fmt.Errorf("%s: envelope is not a v1.0 FHIR message bundle with one entry", RejectMalformed)
	}
	if view.EventType != wantType {
		c.rejections.RecordRejection(ctx, topic, RejectUnknownType)
		return nil, fmt.Errorf("%s: got %q, want %q", RejectUnknownType, view.EventType, wantType)
	}
	return &view, nil
}

// classificationFromEnvelope maps the platform envelope classification onto
// the ISR clearance lattice, never widening visibility. Unknown labels fail
// closed.
func classificationFromEnvelope(label string) (isr.Classification, error) {
	switch label {
	case "PUBLIC", "INTERNAL":
		return isr.ClassificationUnclassified, nil
	case "RESTRICTED":
		return isr.ClassificationRestricted, nil
	case "CONFIDENTIAL", "FIDUCIARY_SEGREGATED":
		return isr.ClassificationConfidential, nil
	default:
		return "", fmt.Errorf("unmapped envelope classification %q", label)
	}
}

// normalizeBox rescales a pixel-space [x1,y1,x2,y2] bbox into the [0,1]
// unit-frame box the ISR detection contract requires. The cv-service event
// carries absolute pixels without the frame dimensions, so the box is
// rescaled proportionally by its largest extent (aspect preserved); the
// absolute geometry's provenance anchor is the frame SHA-256 on the event.
func normalizeBox(bbox []float64, confidence float64) isr.DetectionBox {
	scale := bbox[2]
	if bbox[3] > scale {
		scale = bbox[3]
	}
	if scale <= 0 {
		scale = 1
	}
	width := (bbox[2] - bbox[0]) / scale
	height := (bbox[3] - bbox[1]) / scale
	if width > 1 {
		width = 1
	}
	if height > 1 {
		height = 1
	}
	return isr.DetectionBox{
		X: bbox[0] / scale, Y: bbox[1] / scale,
		Width: width, Height: height,
		Confidence: confidence,
	}
}

// VesselDetectedResource mirrors blueeconomy.cv.v1.VesselDetected.
type VesselDetectedResource struct {
	Type         string    `json:"@type"`
	CameraID     string    `json:"cameraId"`
	TrackID      string    `json:"trackId"`
	VesselClass  string    `json:"vesselClass"`
	Confidence   float64   `json:"confidence"`
	BboxXyxy     []float64 `json:"bboxXyxy"`
	FrameSHA256  string    `json:"frameSha256"`
	ModelVersion string    `json:"modelVersion"`
	MMSI         string    `json:"mmsi"`
	LatMicros    int64     `json:"latitudeMicros"`
	LonMicros    int64     `json:"longitudeMicros"`
}

// DarkVesselResource mirrors blueeconomy.cv.v1.DarkVesselObserved.
type DarkVesselResource struct {
	Type         string  `json:"@type"`
	CameraID     string  `json:"cameraId"`
	TrackID      string  `json:"trackId"`
	Confidence   float64 `json:"confidence"`
	LatMicros    int64   `json:"latitudeMicros"`
	LonMicros    int64   `json:"longitudeMicros"`
	FrameSHA256  string  `json:"frameSha256"`
	ModelVersion string  `json:"modelVersion"`
}

// HandleVesselDetection processes one cv.vessel-detection.v1 record:
// verify -> track-fusion ingest -> persist emitted anomalies -> start the
// ISR response workflow for dark-vessel anomalies.
func (c *Consumer) HandleVesselDetection(ctx context.Context, raw []byte) error {
	view, err := c.verify(ctx, TopicVesselDetection, raw, TopicVesselDetection)
	if err != nil {
		return err
	}
	clearance, err := classificationFromEnvelope(view.Classification)
	if err != nil {
		c.rejections.RecordRejection(ctx, TopicVesselDetection, RejectClassification)
		return err
	}
	var resource VesselDetectedResource
	if err := json.Unmarshal(view.FHIR.Entry[0].Resource, &resource); err != nil {
		c.rejections.RecordRejection(ctx, TopicVesselDetection, RejectPayload)
		return fmt.Errorf("%s: %w", RejectPayload, err)
	}
	if len(resource.BboxXyxy) != 4 {
		c.rejections.RecordRejection(ctx, TopicVesselDetection, RejectPayload)
		return fmt.Errorf("%s: bboxXyxy must have 4 elements", RejectPayload)
	}
	observedAt, err := time.Parse(time.RFC3339, view.OccurredAt)
	if err != nil {
		observedAt = c.now()
	}
	detection := isr.Detection{
		EventID:        view.EventID,
		SourceID:       "blueeconomy-cv-service",
		SourceEventID:  view.EventID,
		Modality:       isr.ModalityOptical,
		Classification: clearance,
		ObservedAt:     observedAt,
		MMSI:           resource.MMSI,
		Optical: &isr.OpticalPayload{
			ImageRef: resource.FrameSHA256,
			Boxes:    []isr.DetectionBox{normalizeBox(resource.BboxXyxy, resource.Confidence)},
		},
	}
	if resource.LatMicros != 0 || resource.LonMicros != 0 {
		detection.HasPosition = true
		detection.Latitude = float64(resource.LatMicros) / 1e6
		detection.Longitude = float64(resource.LonMicros) / 1e6
	}
	trackID, anomalies, err := c.engine.Ingest(ctx, detection)
	if err != nil {
		// Fusion admission failures (e.g. no position) are payload rejections,
		// not silent drops.
		c.rejections.RecordRejection(ctx, TopicVesselDetection, RejectPayload)
		return fmt.Errorf("%s: fusion ingest: %w", RejectPayload, err)
	}
	if len(anomalies) > 0 {
		if err := c.recorder.RecordAnomalies(ctx, anomalies); err != nil {
			return fmt.Errorf("record fusion anomalies: %w", err)
		}
		for _, anomaly := range anomalies {
			if anomaly.Kind != tracks.AnomalyDarkVessel {
				continue
			}
			if err := c.starter.StartISR(ctx, workflow.AlertInput{
				AlertID:        anomaly.AnomalyID,
				AnomalyID:      anomaly.AnomalyID,
				Classification: anomaly.Classification,
			}); err != nil {
				return fmt.Errorf("start ISR workflow for anomaly %s: %w", anomaly.AnomalyID, err)
			}
			c.logger.InfoContext(ctx, "ISR workflow started from fusion anomaly",
				"anomaly_id", anomaly.AnomalyID, "track_id", trackID)
		}
	}
	return nil
}

// HandleDarkVessel processes one cv.dark-vessel.v1 record: verify -> persist
// the anomaly -> start one ISRResponseWorkflow (the previously external
// starter rail, now wired in-service).
func (c *Consumer) HandleDarkVessel(ctx context.Context, raw []byte) error {
	view, err := c.verify(ctx, TopicDarkVessel, raw, TopicDarkVessel)
	if err != nil {
		return err
	}
	clearance, err := classificationFromEnvelope(view.Classification)
	if err != nil {
		c.rejections.RecordRejection(ctx, TopicDarkVessel, RejectClassification)
		return err
	}
	var resource DarkVesselResource
	if err := json.Unmarshal(view.FHIR.Entry[0].Resource, &resource); err != nil {
		c.rejections.RecordRejection(ctx, TopicDarkVessel, RejectPayload)
		return fmt.Errorf("%s: %w", RejectPayload, err)
	}
	detectedAt, err := time.Parse(time.RFC3339, view.OccurredAt)
	if err != nil {
		detectedAt = c.now()
	}
	anomaly := tracks.Anomaly{
		AnomalyID:      fmt.Sprintf("cv-dark-%s", view.EventID),
		Kind:           tracks.AnomalyDarkVessel,
		TrackIDs:       []string{fmt.Sprintf("cv-%s-%s", resource.CameraID, resource.TrackID)},
		Classification: clearance,
		DetectedAt:     detectedAt,
		Detail: fmt.Sprintf("cv dark-vessel observation camera=%s track=%s confidence=%.2f model=%s",
			resource.CameraID, resource.TrackID, resource.Confidence, resource.ModelVersion),
	}
	if err := c.recorder.RecordAnomalies(ctx, []tracks.Anomaly{anomaly}); err != nil {
		return fmt.Errorf("record dark-vessel anomaly: %w", err)
	}
	if err := c.starter.StartISR(ctx, workflow.AlertInput{
		AlertID:        anomaly.AnomalyID,
		AnomalyID:      anomaly.AnomalyID,
		Classification: anomaly.Classification,
	}); err != nil {
		return fmt.Errorf("start ISR workflow for anomaly %s: %w", anomaly.AnomalyID, err)
	}
	c.logger.InfoContext(ctx, "ISR workflow started from cv.dark-vessel.v1",
		"anomaly_id", anomaly.AnomalyID)
	return nil
}
