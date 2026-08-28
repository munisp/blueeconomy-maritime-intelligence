package isr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Platform event topics for Workstream F.
const (
	TopicISR       = "maritime.isr.v1"
	TopicBehaviour = "maritime.behaviour.v1"
	TopicOutcome   = "maritime.outcome.v1"
)

// EnvelopeVersion is the binding platform envelope contract version.
const EnvelopeVersion = "1.0"

// ProducerName identifies this service in every envelope.
const ProducerName = "blueeconomy-maritime-intelligence"

// Platform EnvelopeClassification values (blueeconomy.contracts.v1).
const (
	EnvelopeClassificationConfidential = "CONFIDENTIAL"
	EnvelopeClassificationRestricted   = "RESTRICTED"
	EnvelopeClassificationInternal     = "INTERNAL"
	EnvelopeClassificationPublic       = "PUBLIC"
	EnvelopeClassificationFiduciary    = "FIDUCIARY_SEGREGATED"
)

// EnvelopeClassificationOf maps the national-security clearance label carried
// by every ISR record onto the platform EnvelopeClassification set. The
// documented mapping never widens visibility:
//
//	UNCLASSIFIED -> INTERNAL     (ISR material is never PUBLIC)
//	RESTRICTED   -> RESTRICTED
//	CONFIDENTIAL -> CONFIDENTIAL
//	SECRET       -> CONFIDENTIAL (highest platform band)
//
// The original clearance label travels as record-level metadata (the
// `clearance` extension on the FHIR bundle entry resource), so no handling
// information is lost by the mapping. Unknown labels fail closed.
func EnvelopeClassificationOf(label Classification) (string, error) {
	switch label {
	case ClassificationUnclassified:
		return EnvelopeClassificationInternal, nil
	case ClassificationRestricted:
		return EnvelopeClassificationRestricted, nil
	case ClassificationConfidential, ClassificationSecret:
		return EnvelopeClassificationConfidential, nil
	default:
		return "", ErrInvalidClassification
	}
}

// Envelope is the binding platform message envelope
// (blueeconomy.contracts.v1.EventEnvelope, JSON rendering) — the same
// canonical shape sealed by the ferry-ticketing and financial-controls
// producers. Topic, AggregateKey and Clearance are outbox routing metadata
// and are never serialized into the envelope document.
type Envelope struct {
	EnvelopeVersion string     `json:"envelopeVersion"`
	EventID         string     `json:"eventId"`
	EventType       string     `json:"eventType"`
	OccurredAt      string     `json:"occurredAt"`
	Producer        string     `json:"producer"`
	CorrelationID   string     `json:"correlationId"`
	FHIR            FHIRBundle `json:"fhir"`
	Provenance      Provenance `json:"provenance"`
	Classification  string     `json:"classification"`

	Topic        string         `json:"-"`
	AggregateKey string         `json:"-"`
	Clearance    Classification `json:"-"`
}

// FHIRBundle is the FHIR-aligned message wrapper.
type FHIRBundle struct {
	ResourceType string      `json:"resourceType"`
	Type         string      `json:"type"`
	Entry        []FHIREntry `json:"entry"`
}

// FHIREntry wraps one domain resource.
type FHIREntry struct {
	Resource any `json:"resource"`
}

// Provenance binds the envelope to the deciding principal and ledger commit.
type Provenance struct {
	PrincipalID      string `json:"principalId"`
	PrincipalRole    string `json:"principalRole"`
	Signature        string `json:"signature"`
	LedgerCommitHash string `json:"ledgerCommitHash"`
}

// eventClassificationProbe extracts the classification label from the wrapped
// event payload for the fail-closed envelope/payload match.
type eventClassificationProbe struct {
	Classification string `json:"classification"`
}

// Seal builds one canonical platform envelope for an event payload. It fails
// closed when the topic is unknown, the payload carries no valid
// classification label, or the envelope classification would differ from the
// payload's label. The returned bytes are the encoded envelope document —
// what the outbox stores and the publisher delivers verbatim to Kafka.
func Seal(topic, eventType, aggregateKey string, classification Classification, occurredAt time.Time, payload any) (Envelope, []byte, error) {
	switch topic {
	case TopicISR, TopicBehaviour, TopicOutcome:
	default:
		return Envelope{}, nil, fmt.Errorf("topic %q is not an approved Workstream F topic", topic)
	}
	if _, err := ParseClassification(string(classification)); err != nil {
		return Envelope{}, nil, err
	}
	envelopeClassification, err := EnvelopeClassificationOf(classification)
	if err != nil {
		return Envelope{}, nil, err
	}
	if err := validateCanonicalID("aggregate_key", aggregateKey); err != nil {
		return Envelope{}, nil, err
	}
	if eventType == "" || len(eventType) > 128 {
		return Envelope{}, nil, errors.New("event_type must be non-empty and at most 128 characters")
	}
	if occurredAt.IsZero() {
		return Envelope{}, nil, errors.New("occurred_at must be RFC3339")
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, nil, fmt.Errorf("encode event payload: %w", err)
	}
	var probe eventClassificationProbe
	if err := json.Unmarshal(payloadBytes, &probe); err != nil {
		return Envelope{}, nil, errors.New("event payload is not a JSON object")
	}
	payloadLabel, err := ParseClassification(probe.Classification)
	if err != nil {
		return Envelope{}, nil, fmt.Errorf("event payload carries no valid classification label: %w", err)
	}
	if payloadLabel != classification {
		return Envelope{}, nil, fmt.Errorf("envelope classification %s does not match event label %s", classification, payloadLabel)
	}
	var resource map[string]any
	if err := json.Unmarshal(payloadBytes, &resource); err != nil || resource == nil {
		return Envelope{}, nil, errors.New("event payload is not a JSON object")
	}
	// Record-level metadata: the original national-security clearance label
	// and the aggregate key ride inside the bundle entry so the canonical
	// envelope classification loses no handling detail.
	resource["clearance"] = string(classification)
	resource["aggregateKey"] = aggregateKey
	digest := sha256.Sum256(payloadBytes)
	envelope := Envelope{
		EnvelopeVersion: EnvelopeVersion,
		EventID:         uuid.NewString(),
		EventType:       eventType,
		OccurredAt:      occurredAt.UTC().Format(time.RFC3339),
		Producer:        ProducerName,
		CorrelationID:   aggregateKey,
		FHIR: FHIRBundle{
			ResourceType: "Bundle",
			Type:         "message",
			Entry:        []FHIREntry{{Resource: resource}},
		},
		Provenance: Provenance{
			PrincipalID:      stringField(resource, "source_id", "alert_id", "anomaly_id"),
			PrincipalRole:    stringField(resource, "modality", "kind"),
			Signature:        hex.EncodeToString(digest[:]),
			LedgerCommitHash: stringField(resource, "ledger_transfer_id", "incident_ref"),
		},
		Classification: envelopeClassification,
		Topic:          topic,
		AggregateKey:   aggregateKey,
		Clearance:      classification,
	}
	envelopeBytes, err := envelope.Marshal()
	if err != nil {
		return Envelope{}, nil, fmt.Errorf("encode envelope: %w", err)
	}
	return envelope, envelopeBytes, nil
}

func stringField(resource map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := resource[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

// Marshal encodes the sealed envelope for the outbox payload column.
func (envelope Envelope) Marshal() ([]byte, error) {
	return json.Marshal(envelope)
}
