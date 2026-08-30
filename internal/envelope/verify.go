package envelope

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
)

// Admission-rejection reason codes, logged and metered by consumers (the
// fail-closed reason discipline of docs/envelope-signature.md §4).
const (
	RejectMalformedJWS     = "malformed-jws"
	RejectUnknownVersion   = "unknown-envelope-version"
	RejectUnknownEventType = "unknown-event-type"
	RejectMalformedBundle  = "malformed-bundle"
)

// ParsedEnvelope is the validated, signature-verified view of one raw
// envelope document.
type ParsedEnvelope struct {
	EventType            string
	EventID              string
	Producer             string
	CorrelationID        string
	Classification       string
	RecordClassification string
	// Resource is the raw JSON of the primary bundle entry resource,
	// including its "@type" member (already matched against the event type).
	Resource json.RawMessage
}

type envelopeProbe struct {
	EnvelopeVersion      string `json:"envelopeVersion"`
	EventID              string `json:"eventId"`
	EventType            string `json:"eventType"`
	Producer             string `json:"producer"`
	CorrelationID        string `json:"correlationId"`
	Classification       string `json:"classification"`
	RecordClassification string `json:"recordClassification"`
	FHIR                 struct {
		ResourceType string `json:"resourceType"`
		Type         string `json:"type"`
		BundleID     string `json:"bundleId"`
		Entry        []struct {
			FullURL  string          `json:"fullUrl"`
			Resource json.RawMessage `json:"resource"`
		} `json:"entry"`
	} `json:"fhir"`
	Provenance struct {
		Signature string `json:"signature"`
	} `json:"provenance"`
}

// Parse validates the raw envelope document fail-closed: envelope version
// 1.0, a recognized Phase-8 event type, a FHIR message Bundle whose primary
// entry resource @type matches the event type, and a present provenance
// signature. It does NOT verify the signature; callers must then call
// Admit/verify on the same raw bytes.
func Parse(raw []byte) (ParsedEnvelope, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var probe envelopeProbe
	if err := decoder.Decode(&probe); err != nil {
		return ParsedEnvelope{}, fmt.Errorf("%s: envelope is not valid JSON: %w", RejectMalformedBundle, err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ParsedEnvelope{}, fmt.Errorf("%s: trailing data after envelope document", RejectMalformedBundle)
	}
	if probe.EnvelopeVersion != EnvelopeVersion {
		return ParsedEnvelope{}, fmt.Errorf("%s: envelopeVersion %q", RejectUnknownVersion, probe.EnvelopeVersion)
	}
	binding, ok := eventResourceType[probe.EventType]
	if !ok {
		return ParsedEnvelope{}, fmt.Errorf("%s: %q", RejectUnknownEventType, probe.EventType)
	}
	if probe.EventID == "" || probe.Producer == "" {
		return ParsedEnvelope{}, fmt.Errorf("%s: eventId and producer are required", RejectMalformedBundle)
	}
	if probe.FHIR.ResourceType != "Bundle" || probe.FHIR.Type != "message" || probe.FHIR.BundleID == "" || len(probe.FHIR.Entry) == 0 {
		return ParsedEnvelope{}, fmt.Errorf("%s: fhir must be a message Bundle with at least one entry", RejectMalformedBundle)
	}
	var resourceHead struct {
		Type string `json:"@type"`
	}
	if err := json.Unmarshal(probe.FHIR.Entry[0].Resource, &resourceHead); err != nil || resourceHead.Type != typeURLPrefix+binding.resource {
		return ParsedEnvelope{}, fmt.Errorf("%s: primary resource @type does not match event type %q", RejectMalformedBundle, probe.EventType)
	}
	if probe.Provenance.Signature == "" {
		return ParsedEnvelope{}, fmt.Errorf("%s: provenance signature is missing", RejectMalformedJWS)
	}
	return ParsedEnvelope{
		EventType:            probe.EventType,
		EventID:              probe.EventID,
		Producer:             probe.Producer,
		CorrelationID:        probe.CorrelationID,
		Classification:       probe.Classification,
		RecordClassification: probe.RecordClassification,
		Resource:             probe.FHIR.Entry[0].Resource,
	}, nil
}

// Admit parses and signature-verifies one raw envelope against the key
// directory. Any parse or verification failure is terminal for the message:
// callers must dead-letter, never persist or forward.
func Admit(raw []byte, directory *provenance.Directory) (ParsedEnvelope, error) {
	if directory == nil {
		return ParsedEnvelope{}, errors.New("key directory is required (fail-closed)")
	}
	if err := directory.VerifyEnvelope(raw); err != nil {
		return ParsedEnvelope{}, fmt.Errorf("envelope provenance verification failed: %w", err)
	}
	return Parse(raw)
}
