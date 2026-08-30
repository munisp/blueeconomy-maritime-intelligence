package sar

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
)

// Waterway-safety batch contract (blueeconomy-waterway-safety src/uplink.rs,
// the PRA-098 producer): each ferries.telemetry.v1 record value is a JSON
// lines payload whose first line is a batch-provenance header record and
// whose remaining lines are TelemetryFrame documents. The header carries a
// fleet JWS-EdDSA signature over the JCS-canonicalized batch document
// {batchKey, encoding:"json-lines", frameCount, frames, producer, schema,
// topic}; the batch key is the hex SHA-256 over
// schema||0||topic||0||(device_id||0||gateway_id||0||seq_be64||payload_sha256||0)*.
const (
	WaterwayBatchProvenanceRecordType = "blueeconomy.waterway-safety.batch-provenance.v1"
	WaterwayBatchSchemaDomain         = "blueeconomy.waterway-safety.gateway-batch.v1"
	WaterwayTelemetryTopic            = "ferries.telemetry.v1"
)

// Intake rejection reason codes (metered, dead-lettered).
const (
	RejectBatchUnsigned      = "batch-unsigned"
	RejectBatchKeyMismatch   = "batch-key-mismatch"
	RejectBatchBadFrame      = "batch-frame-invalid"
	RejectBatchBadSignature  = "batch-signature-invalid"
	RejectNotSafetyRelevant  = "not-safety-relevant"
	RejectEnvelopeUnverified = "envelope-unverified"
)

// BatchFrame is one waterway TelemetryFrame (snake_case per the producer
// serde contract).
type BatchFrame struct {
	DeviceID           string `json:"device_id"`
	GatewayID          string `json:"gateway_id"`
	SourceSequence     uint64 `json:"source_sequence"`
	ObservedAt         string `json:"observed_at"`
	ReceivedAt         string `json:"received_at"`
	DataClassification string `json:"data_classification"`
	PayloadBase64      string `json:"payload_base64"`
	PayloadSHA256      string `json:"payload_sha256"`
}

type batchHeader struct {
	RecordType     string `json:"record_type"`
	BatchKey       string `json:"batch_key"`
	FrameCount     int    `json:"frame_count"`
	Producer       string `json:"producer"`
	Schema         string `json:"schema"`
	Topic          string `json:"topic"`
	SignatureKeyID string `json:"signature_key_id"`
	Signature      string `json:"signature"`
}

// batchKeyDigest recomputes the deterministic batch key over the frame
// identity fields, exactly as the producer computes it.
func batchKeyDigest(topic string, frames []BatchFrame) string {
	digest := sha256.New()
	digest.Write([]byte(WaterwayBatchSchemaDomain))
	digest.Write([]byte{0})
	digest.Write([]byte(topic))
	digest.Write([]byte{0})
	for _, frame := range frames {
		digest.Write([]byte(frame.DeviceID))
		digest.Write([]byte{0})
		digest.Write([]byte(frame.GatewayID))
		digest.Write([]byte{0})
		var sequence [8]byte
		binary.BigEndian.PutUint64(sequence[:], frame.SourceSequence)
		digest.Write(sequence[:])
		digest.Write([]byte(frame.PayloadSHA256))
		digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// ParseWaterwayBatch validates and signature-verifies one waterway telemetry
// batch fail-closed. Any structural, digest or signature failure rejects the
// whole batch (dead-letter discipline); partial admission is never produced.
func ParseWaterwayBatch(recordKey, value []byte, expectedTopic string, directory *provenance.Directory) ([]BatchFrame, error) {
	if directory == nil {
		return nil, errors.New("key directory is required (fail-closed)")
	}
	lines := bytes.Split(value, []byte("\n"))
	nonEmpty := make([][]byte, 0, len(lines))
	for _, line := range lines {
		if len(bytes.TrimSpace(line)) > 0 {
			nonEmpty = append(nonEmpty, line)
		}
	}
	if len(nonEmpty) == 0 {
		return nil, fmt.Errorf("%s: empty batch payload", RejectBatchUnsigned)
	}
	var header batchHeader
	if err := json.Unmarshal(nonEmpty[0], &header); err != nil || header.RecordType != WaterwayBatchProvenanceRecordType {
		return nil, fmt.Errorf("%s: first record is not a signed batch-provenance header", RejectBatchUnsigned)
	}
	if header.Signature == "" {
		return nil, fmt.Errorf("%s: batch header carries no signature", RejectBatchUnsigned)
	}
	if header.Topic != expectedTopic || header.Schema != WaterwayBatchSchemaDomain {
		return nil, fmt.Errorf("%s: header topic/schema mismatch", RejectBatchKeyMismatch)
	}
	frames := make([]BatchFrame, 0, len(nonEmpty)-1)
	frameValues := make([]any, 0, len(nonEmpty)-1)
	for _, line := range nonEmpty[1:] {
		var frame BatchFrame
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&frame); err != nil {
			return nil, fmt.Errorf("%s: frame is not a TelemetryFrame: %v", RejectBatchBadFrame, err)
		}
		payload, err := base64.StdEncoding.DecodeString(frame.PayloadBase64)
		if err != nil {
			return nil, fmt.Errorf("%s: payload_base64 undecodable", RejectBatchBadFrame)
		}
		payloadDigest := sha256.Sum256(payload)
		hexDigest := hex.EncodeToString(payloadDigest[:])
		frameDigest := strings.TrimPrefix(frame.PayloadSHA256, "sha256:")
		if frameDigest != hexDigest {
			return nil, fmt.Errorf("%s: payload digest mismatch for device %s seq %d", RejectBatchBadFrame, frame.DeviceID, frame.SourceSequence)
		}
		if _, err := time.Parse(time.RFC3339, frame.ObservedAt); err != nil {
			return nil, fmt.Errorf("%s: observed_at is not RFC3339", RejectBatchBadFrame)
		}
		frames = append(frames, frame)
		var value any
		if err := json.Unmarshal(line, &value); err != nil {
			return nil, fmt.Errorf("%s: frame JSON undecodable", RejectBatchBadFrame)
		}
		frameValues = append(frameValues, value)
	}
	if header.FrameCount != len(frames) {
		return nil, fmt.Errorf("%s: header frame_count %d != %d frames", RejectBatchKeyMismatch, header.FrameCount, len(frames))
	}
	recomputedKey := batchKeyDigest(header.Topic, frames)
	if header.BatchKey != recomputedKey || (len(recordKey) > 0 && string(recordKey) != recomputedKey) {
		return nil, fmt.Errorf("%s: batch key mismatch", RejectBatchKeyMismatch)
	}
	document := map[string]any{
		"batchKey": header.BatchKey, "encoding": "json-lines", "frameCount": float64(len(frames)),
		"frames": frameValues, "producer": header.Producer, "schema": header.Schema, "topic": header.Topic,
	}
	canonical, err := provenance.Canonicalize(document)
	if err != nil {
		return nil, fmt.Errorf("canonicalize batch document: %w", err)
	}
	if err := directory.Verify(canonical, header.Signature); err != nil {
		return nil, fmt.Errorf("%s: %v", RejectBatchBadSignature, err)
	}
	return frames, nil
}

// SafetyEvent is the documented safety-event marker carried in a waterway
// frame payload (the paired waterway-safety contract): the decoded payload
// JSON object contains "safety_event": {"kind": ..., ...}.
type SafetyEvent struct {
	Kind          string   `json:"kind"`
	Summary       string   `json:"summary"`
	Latitude      *float64 `json:"latitude"`
	Longitude     *float64 `json:"longitude"`
	PersonsAtRisk *int     `json:"persons_at_risk"`
}

// safetyEventKinds is the closed safety-event taxonomy, mapped to the
// incident severity the intake anchors.
var safetyEventKinds = map[string]string{
	"MAN_OVERBOARD":   "CRITICAL",
	"DISTRESS_ALERT":  "CRITICAL",
	"FIRE_FLOODING":   "CRITICAL",
	"VESSEL_DISABLED": "HIGH",
	"OTHER_DISTRESS":  "HIGH",
}

// SafetySeverity returns the anchored incident severity for a safety-event
// kind.
func SafetySeverity(kind string) string { return safetyEventKinds[kind] }

// ExtractSafetyEvent decodes one frame payload and returns the safety-event
// marker when the frame is safety-relevant. Frames without a marker are
// routine telemetry and are skipped (not an error).
func ExtractSafetyEvent(frame BatchFrame) (SafetyEvent, []byte, bool, error) {
	payload, err := base64.StdEncoding.DecodeString(frame.PayloadBase64)
	if err != nil {
		return SafetyEvent{}, nil, false, fmt.Errorf("payload_base64 undecodable: %w", err)
	}
	var document struct {
		SafetyEvent *SafetyEvent `json:"safety_event"`
	}
	if err := json.Unmarshal(payload, &document); err != nil {
		return SafetyEvent{}, nil, false, fmt.Errorf("payload is not a JSON object: %w", err)
	}
	if document.SafetyEvent == nil {
		return SafetyEvent{}, payload, false, nil
	}
	event := *document.SafetyEvent
	if _, ok := safetyEventKinds[event.Kind]; !ok {
		return SafetyEvent{}, nil, false, fmt.Errorf("safety_event kind %q is not in the closed taxonomy", event.Kind)
	}
	if strings.TrimSpace(event.Summary) == "" || len(event.Summary) > 512 {
		return SafetyEvent{}, nil, false, errors.New("safety_event summary must be 1..512 characters")
	}
	if (event.Latitude == nil) != (event.Longitude == nil) {
		return SafetyEvent{}, nil, false, errors.New("safety_event position requires both latitude and longitude")
	}
	if event.Latitude != nil && (*event.Latitude < -90 || *event.Latitude > 90 || *event.Longitude < -180 || *event.Longitude > 180) {
		return SafetyEvent{}, nil, false, errors.New("safety_event position out of range")
	}
	if event.PersonsAtRisk != nil && *event.PersonsAtRisk < 0 {
		return SafetyEvent{}, nil, false, errors.New("safety_event persons_at_risk must be non-negative")
	}
	return event, payload, true, nil
}

// WaterwaySourceEventID derives the deterministic, replay-safe feed event id
// for one safety frame inside one batch.
func WaterwaySourceEventID(batchKey, deviceID string, sequence uint64) string {
	deviceDigest := sha256.Sum256([]byte(deviceID))
	return fmt.Sprintf("ww-%s-%s-%d", batchKey[:32], hex.EncodeToString(deviceDigest[:])[:16], sequence)
}

// frameClassification maps the frame's data_classification onto the national
// label, failing closed to RESTRICTED when the frame label is absent or
// unmapped (never widening below the waterway producer's marking).
func frameClassification(frame BatchFrame) (isr.Classification, error) {
	if frame.DataClassification == "" {
		return isr.ClassificationRestricted, nil
	}
	classification, err := isr.ParseClassification(strings.ToUpper(frame.DataClassification))
	if err != nil {
		return "", fmt.Errorf("frame classification %q is not a national label: %w", frame.DataClassification, err)
	}
	return classification, nil
}

// MapWaterwaySafetyEvent builds the case-opening view of one verified
// waterway safety frame.
func MapWaterwaySafetyEvent(batchKey string, frame BatchFrame, event SafetyEvent) (OpenCaseRequest, error) {
	classification, err := frameClassification(frame)
	if err != nil {
		return OpenCaseRequest{}, err
	}
	observedAt, err := time.Parse(time.RFC3339, frame.ObservedAt)
	if err != nil {
		return OpenCaseRequest{}, fmt.Errorf("observed_at is not RFC3339: %w", err)
	}
	request := OpenCaseRequest{
		SourceRef:      fmt.Sprintf("waterway:%s:%s:%d", batchKey, frame.DeviceID, frame.SourceSequence),
		Classification: string(classification),
		Phase:          string(PhaseIncerfa),
		PersonsAtRisk:  event.PersonsAtRisk,
		LastKnownAt:    &observedAt,
	}
	if event.Latitude != nil {
		request.LastKnownLatitude = event.Latitude
		request.LastKnownLongitude = event.Longitude
	}
	return request, nil
}

// SosAlertRaised is the geo.sos.v1 SosAlertRaised resource (contracts
// camelCase rendering).
type SosAlertRaised struct {
	SosAlertID      string `json:"sosAlertId"`
	ReporterID      string `json:"reporterId"`
	VesselReference string `json:"vesselReference"`
	LatitudeMicros  int64  `json:"latitudeMicros"`
	LongitudeMicros int64  `json:"longitudeMicros"`
	RecordedAt      string `json:"recordedAt"`
	OutboxID        string `json:"outboxId"`
	FreeText        string `json:"freeText"`
	Classification  string `json:"classification"`
}

// sosEnvelopeProbe validates the geo.sos.v1 envelope shape without binding
// it to the Phase-8 event-type registry (the geo event predates Phase 8 and
// uses its own eventType "geo.sos.v1").
type sosEnvelopeProbe struct {
	EnvelopeVersion string `json:"envelopeVersion"`
	EventType       string `json:"eventType"`
	EventID         string `json:"eventId"`
	FHIR            struct {
		ResourceType string `json:"resourceType"`
		Type         string `json:"type"`
		Entry        []struct {
			Resource json.RawMessage `json:"resource"`
		} `json:"entry"`
	} `json:"fhir"`
	Provenance struct {
		Signature string `json:"signature"`
	} `json:"provenance"`
}

// ParseSosEnvelope verifies one raw geo.sos.v1 envelope against the fleet
// key directory and extracts the SosAlertRaised resource. Fail-closed: any
// signature, version, type or shape failure rejects the message.
func ParseSosEnvelope(raw []byte, directory *provenance.Directory) (SosAlertRaised, error) {
	if directory == nil {
		return SosAlertRaised{}, errors.New("key directory is required (fail-closed)")
	}
	if err := directory.VerifyEnvelope(raw); err != nil {
		return SosAlertRaised{}, fmt.Errorf("%s: %v", RejectEnvelopeUnverified, err)
	}
	var probe sosEnvelopeProbe
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&probe); err != nil {
		return SosAlertRaised{}, fmt.Errorf("%s: envelope is not valid JSON: %v", RejectEnvelopeUnverified, err)
	}
	if probe.EnvelopeVersion != "1.0" || probe.EventType != "geo.sos.v1" {
		return SosAlertRaised{}, fmt.Errorf("%s: not a geo.sos.v1 envelope v1.0", RejectEnvelopeUnverified)
	}
	if probe.FHIR.ResourceType != "Bundle" || probe.FHIR.Type != "message" || len(probe.FHIR.Entry) == 0 {
		return SosAlertRaised{}, fmt.Errorf("%s: malformed bundle", RejectEnvelopeUnverified)
	}
	var alert SosAlertRaised
	if err := json.Unmarshal(probe.FHIR.Entry[0].Resource, &alert); err != nil {
		return SosAlertRaised{}, fmt.Errorf("%s: malformed SosAlertRaised resource", RejectEnvelopeUnverified)
	}
	if alert.SosAlertID == "" || len(alert.SosAlertID) > 256 {
		return SosAlertRaised{}, fmt.Errorf("%s: sosAlertId missing", RejectEnvelopeUnverified)
	}
	if _, err := time.Parse(time.RFC3339, alert.RecordedAt); err != nil {
		return SosAlertRaised{}, fmt.Errorf("%s: recordedAt is not RFC3339", RejectEnvelopeUnverified)
	}
	return alert, nil
}

// MapSosAlert builds the case-opening view of one verified SOS alert. The
// classification floor is RESTRICTED (mirroring docs/geo-events.md); a
// higher producer label is preserved, never widened down.
func MapSosAlert(alert SosAlertRaised) (OpenCaseRequest, error) {
	classification, err := isr.ParseClassification(alert.Classification)
	if err != nil {
		return OpenCaseRequest{}, fmt.Errorf("sos classification %q is not a national label: %w", alert.Classification, err)
	}
	if classification.Rank() < isr.ClassificationRestricted.Rank() {
		classification = isr.ClassificationRestricted
	}
	recordedAt, err := time.Parse(time.RFC3339, alert.RecordedAt)
	if err != nil {
		return OpenCaseRequest{}, err
	}
	latitude := float64(alert.LatitudeMicros) / 1e6
	longitude := float64(alert.LongitudeMicros) / 1e6
	return OpenCaseRequest{
		SourceRef:          "geo-sos:" + alert.SosAlertID,
		Classification:     string(classification),
		Phase:              string(PhaseDetresfa), // an asserted distress alert
		LastKnownLatitude:  &latitude,
		LastKnownLongitude: &longitude,
		LastKnownAt:        &recordedAt,
	}, nil
}
