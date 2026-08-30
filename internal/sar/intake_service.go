package sar

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/incident"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
)

// IntakeProcessor is the PRA-098 residual closer: it consumes verified
// waterway telemetry batches and geo SOS envelopes and opens SAR cases via
// signed feed admission (replay-safe on (source_id, source_event_id)) and
// idempotent case creation (unique incident anchor).
type IntakeProcessor struct {
	Incidents     *incident.Store
	Cases         *Store
	Directory     *provenance.Directory
	Signer        *provenance.Signer // intake admission signing key (env-only)
	SourceID      string             // registered ACTIVE feed source id
	WaterwayTopic string             // expected waterway topic (fail-closed check)
}

// Validate fails closed on incomplete wiring.
func (processor *IntakeProcessor) Validate() error {
	if processor.Incidents == nil || processor.Cases == nil || processor.Directory == nil || processor.Signer == nil {
		return errors.New("sar intake: incidents store, cases store, key directory and signer are all required")
	}
	if err := validIdentifier("source_id", processor.SourceID); err != nil {
		return err
	}
	if processor.WaterwayTopic == "" {
		processor.WaterwayTopic = WaterwayTelemetryTopic
	}
	return nil
}

// ProcessWaterwayRecord verifies and processes one ferries.telemetry.v1
// record. Malformed, unsigned or unverifiable records return an error and
// must be dead-lettered by the caller (never committed as consumed).
func (processor *IntakeProcessor) ProcessWaterwayRecord(ctx context.Context, key, value []byte) (int, error) {
	frames, err := ParseWaterwayBatch(key, value, processor.WaterwayTopic, processor.Directory)
	if err != nil {
		return 0, err
	}
	admitted := 0
	for _, frame := range frames {
		event, _, relevant, err := ExtractSafetyEvent(frame)
		if err != nil {
			return admitted, fmt.Errorf("batch %s frame %s/%d: %w", string(key), frame.DeviceID, frame.SourceSequence, err)
		}
		if !relevant {
			continue // routine telemetry: skip
		}
		batchKey := string(key)
		request, err := MapWaterwaySafetyEvent(batchKey, frame, event)
		if err != nil {
			return admitted, fmt.Errorf("map safety event: %w", err)
		}
		observedAt := *request.LastKnownAt
		createRequest := incident.CreateRequest{
			IncidentID:    "inc-" + uuid.NewString(),
			SourceEventID: processor.SourceID + ":" + WaterwaySourceEventID(batchKey, frame.DeviceID, frame.SourceSequence),
			Category:      "SAR",
			Severity:      incident.Severity(SafetySeverity(event.Kind)),
			Title:         "waterway safety event: " + event.Kind,
			Description:   event.Summary,
			OccurredAt:    observedAt,
			CreatedBy:     "feed:" + processor.SourceID,
		}
		payload, err := json.Marshal(createRequest)
		if err != nil {
			return admitted, err
		}
		// Feed admission signs the raw canonical preimage (the feed
		// signature scheme), distinct from envelope JWS signing.
		decodedSignature := ed25519.Sign(processor.Signer.PrivateKey(),
			incident.FeedSigningBytes(processor.SourceID, WaterwaySourceEventID(batchKey, frame.DeviceID, frame.SourceSequence), payload))
		result, err := processor.Incidents.AdmitFeedIncident(ctx, incident.SignedFeedIncidentRequest{FeedAdmissionRequest: incident.FeedAdmissionRequest{
			SourceID: processor.SourceID, SourceEventID: WaterwaySourceEventID(batchKey, frame.DeviceID, frame.SourceSequence),
			Payload: payload, Signature: decodedSignature,
		}})
		if err != nil {
			return admitted, fmt.Errorf("admit waterway safety event: %w", err)
		}
		request.IncidentID = result.Incident.IncidentID
		if _, err := processor.Cases.OpenCaseFromIntake(ctx, request, IntakeWaterway, "intake:"+processor.SourceID); err != nil {
			return admitted, fmt.Errorf("open waterway sar case: %w", err)
		}
		admitted++
	}
	return admitted, nil
}

// ProcessSOSRecord verifies one geo.sos.v1 envelope and opens a GEO_SOS
// case anchored to a freshly created incident (idempotent on the SOS alert
// id through source_ref and the incident source_event_id).
func (processor *IntakeProcessor) ProcessSOSRecord(ctx context.Context, value []byte) error {
	alert, err := ParseSosEnvelope(value, processor.Directory)
	if err != nil {
		return err
	}
	request, err := MapSosAlert(alert)
	if err != nil {
		return err
	}
	recordedAt := *request.LastKnownAt
	createRequest := incident.CreateRequest{
		IncidentID:    "inc-" + uuid.NewString(),
		SourceEventID: processor.SourceID + ":geo-sos:" + alert.SosAlertID,
		Category:      "SAR",
		Severity:      "CRITICAL",
		Title:         "geo SOS alert " + alert.SosAlertID,
		Description:   alert.FreeText,
		OccurredAt:    recordedAt,
		CreatedBy:     "feed:" + processor.SourceID,
	}
	payload, err := json.Marshal(createRequest)
	if err != nil {
		return err
	}
	sourceEventID := "geo-sos:" + alert.SosAlertID
	decodedSignature := ed25519.Sign(processor.Signer.PrivateKey(),
		incident.FeedSigningBytes(processor.SourceID, sourceEventID, payload))
	result, err := processor.Incidents.AdmitFeedIncident(ctx, incident.SignedFeedIncidentRequest{FeedAdmissionRequest: incident.FeedAdmissionRequest{
		SourceID: processor.SourceID, SourceEventID: sourceEventID, Payload: payload, Signature: decodedSignature,
	}})
	if err != nil {
		return fmt.Errorf("admit sos event: %w", err)
	}
	request.IncidentID = result.Incident.IncidentID
	if _, err := processor.Cases.OpenCaseFromIntake(ctx, request, IntakeGeoSOS, "intake:geo-sos"); err != nil {
		return fmt.Errorf("open sos sar case: %w", err)
	}
	return nil
}
