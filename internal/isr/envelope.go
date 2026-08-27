package isr

import (
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

// EnvelopeVersion is the platform envelope contract version.
const EnvelopeVersion = "1.0"

// Envelope is the platform event envelope v1.0 carried through the
// transactional outbox to Kafka. The envelope Classification MUST equal the
// wrapped event's classification label; Seal enforces the match fail-closed.
type Envelope struct {
	EnvelopeVersion string          `json:"envelope_version"`
	EventID         string          `json:"event_id"`
	EventType       string          `json:"event_type"`
	Topic           string          `json:"topic"`
	Classification  Classification  `json:"classification"`
	Source          string          `json:"source"`
	AggregateKey    string          `json:"aggregate_key"`
	OccurredAt      time.Time       `json:"occurred_at"`
	Payload         json.RawMessage `json:"payload"`
}

// eventClassificationProbe extracts the classification label from the wrapped
// event payload for the fail-closed envelope/payload match.
type eventClassificationProbe struct {
	Classification string `json:"classification"`
}

// Seal builds one envelope for an event payload. It fails closed when the
// topic is unknown, the payload carries no valid classification label, or the
// envelope classification would differ from the payload's label.
func Seal(topic, eventType, aggregateKey string, classification Classification, occurredAt time.Time, payload any) (Envelope, []byte, error) {
	switch topic {
	case TopicISR, TopicBehaviour, TopicOutcome:
	default:
		return Envelope{}, nil, fmt.Errorf("topic %q is not an approved Workstream F topic", topic)
	}
	if _, err := ParseClassification(string(classification)); err != nil {
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
	return Envelope{
		EnvelopeVersion: EnvelopeVersion,
		EventID:         uuid.NewString(),
		EventType:       eventType,
		Topic:           topic,
		Classification:  classification,
		Source:          "blueeconomy-maritime-intelligence",
		AggregateKey:    aggregateKey,
		OccurredAt:      occurredAt.UTC(),
		Payload:         payloadBytes,
	}, payloadBytes, nil
}

// Marshal encodes the sealed envelope for the outbox payload column.
func (envelope Envelope) Marshal() ([]byte, error) {
	return json.Marshal(envelope)
}
