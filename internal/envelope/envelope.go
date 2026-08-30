// Package envelope constructs and seals the canonical platform event
// envelope (blueeconomy.contracts.v1.EventEnvelope, envelope_version "1.0")
// for the Phase-8 maritime topics maritime.yaounde.v1 and maritime.sar.v1.
//
// The wire shape follows the merged contracts fixtures byte-for-byte in
// convention: camelCase keys, a FHIR R4 message Bundle whose primary entry
// resource is a google.protobuf.Any rendering ("@type":
// "type.googleapis.com/blueeconomy.contracts.v1.<Message>"), and a
// provenance JWS-EdDSA signature over the RFC 8785 JCS canonicalization of
// the envelope minus the signature field (docs/envelope-signature.md in
// blueeconomy-contracts). Signing reuses internal/provenance; unknown
// topics, unknown event types, unmapped classifications and missing signers
// all fail closed.
package envelope

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
)

// Phase-8 platform topics.
const (
	TopicYaounde = "maritime.yaounde.v1"
	TopicSAR     = "maritime.sar.v1"
)

// EnvelopeVersion is the binding envelope contract version.
const EnvelopeVersion = "1.0"

// ProducerName identifies this service in every envelope.
const ProducerName = "blueeconomy-maritime-intelligence"

// Event types on maritime.yaounde.v1 (blueeconomy-contracts
// docs/yaounde-gateway-events.md).
const (
	EventYaoundeIncidentReport      = "maritime.yaounde.incident_report.v1"
	EventYaoundeReleaseTransitioned = "maritime.yaounde.release_transitioned.v1"
	EventYaoundeInboundAdmitted     = "maritime.yaounde.inbound_report_admitted.v1"
	EventYaoundePictureTransitioned = "maritime.yaounde.picture_contribution_transitioned.v1"
)

// Event types on maritime.sar.v1 (blueeconomy-contracts docs/sar-events.md).
const (
	EventSARCaseOpened     = "maritime.sar.case_opened.v1"
	EventSARPhaseChanged   = "maritime.sar.phase_changed.v1"
	EventSARStageChanged   = "maritime.sar.stage_changed.v1"
	EventSARTaskingChanged = "maritime.sar.tasking_changed.v1"
	EventSARSitrepIssued   = "maritime.sar.sitrep_issued.v1"
	EventSARCaseClosed     = "maritime.sar.case_closed.v1"
)

// typeURLPrefix is the google.protobuf.Any type URL prefix for contract
// resources.
const typeURLPrefix = "type.googleapis.com/blueeconomy.contracts.v1."

// eventResourceType maps every approved event type to its contract resource
// message name; the map is the fail-closed authority for both the topic and
// the @type carried on the wire.
var eventResourceType = map[string]struct {
	topic    string
	resource string
}{
	EventYaoundeIncidentReport:      {TopicYaounde, "RegionalIncidentReport"},
	EventYaoundeReleaseTransitioned: {TopicYaounde, "YaoundeReleaseTransitioned"},
	EventYaoundeInboundAdmitted:     {TopicYaounde, "YaoundeInboundReportAdmitted"},
	EventYaoundePictureTransitioned: {TopicYaounde, "YaoundePictureContributionTransitioned"},
	EventSARCaseOpened:              {TopicSAR, "SarCaseOpened"},
	EventSARPhaseChanged:            {TopicSAR, "SarPhaseChanged"},
	EventSARStageChanged:            {TopicSAR, "SarStageChanged"},
	EventSARTaskingChanged:          {TopicSAR, "SarTaskingChanged"},
	EventSARSitrepIssued:            {TopicSAR, "SarSitrepIssued"},
	EventSARCaseClosed:              {TopicSAR, "SarCaseClosed"},
}

// Envelope is the canonical JSON rendering of
// blueeconomy.contracts.v1.EventEnvelope.
type Envelope struct {
	EnvelopeVersion      string     `json:"envelopeVersion"`
	EventID              string     `json:"eventId"`
	EventType            string     `json:"eventType"`
	OccurredAt           string     `json:"occurredAt"`
	Producer             string     `json:"producer"`
	CorrelationID        string     `json:"correlationId"`
	FHIR                 Bundle     `json:"fhir"`
	Provenance           Provenance `json:"provenance"`
	Classification       string     `json:"classification"`
	RecordClassification string     `json:"recordClassification,omitempty"`

	// Topic and AggregateKey are outbox routing metadata and are never
	// serialized into the envelope document.
	Topic        string `json:"-"`
	AggregateKey string `json:"-"`
}

// Bundle is the FHIR R4-aligned message Bundle carried under "fhir".
type Bundle struct {
	ResourceType string  `json:"resourceType"`
	Type         string  `json:"type"`
	BundleID     string  `json:"bundleId"`
	Entry        []Entry `json:"entry"`
}

// Entry is one bundle entry: a stable fullUrl plus the Any-rendered domain
// resource.
type Entry struct {
	FullURL  string `json:"fullUrl"`
	Resource any    `json:"resource"`
}

// Provenance binds the envelope to the deciding principal; Signature carries
// the JWS compact serialization after sealing.
type Provenance struct {
	PrincipalID      string `json:"principalId"`
	PrincipalRole    string `json:"principalRole"`
	LedgerCommitHash string `json:"ledgerCommitHash"`
	Signature        string `json:"signature"`
}

// SealRequest carries everything needed to seal one contract envelope.
type SealRequest struct {
	EventType      string
	AggregateKey   string
	Classification isr.Classification
	OccurredAt     time.Time
	// Resource is the event resource document (a map or a struct with
	// camelCase JSON tags matching the contract proto JSON rendering). The
	// "@type" member is set by Seal; callers must not set it.
	Resource any
	// PrincipalID/PrincipalRole describe the deciding principal (never
	// credentials or personal data).
	PrincipalID   string
	PrincipalRole string
}

// Seal builds the canonical envelope for one Phase-8 event and seals it with
// the fleet provenance signature. It fails closed on an unknown event type
// (and therefore unknown topic), an invalid classification label, a missing
// signer, or a malformed resource. The returned bytes are the encoded
// envelope document — what the outbox stores and the publisher delivers
// verbatim to Kafka.
func Seal(signer *provenance.Signer, request SealRequest) (Envelope, []byte, error) {
	if signer == nil {
		return Envelope{}, nil, errors.New("provenance signer is required")
	}
	binding, ok := eventResourceType[request.EventType]
	if !ok {
		return Envelope{}, nil, fmt.Errorf("event type %q is not an approved Phase-8 contract event type", request.EventType)
	}
	if _, err := isr.ParseClassification(string(request.Classification)); err != nil {
		return Envelope{}, nil, err
	}
	envelopeClassification, err := isr.EnvelopeClassificationOf(request.Classification)
	if err != nil {
		return Envelope{}, nil, err
	}
	if request.AggregateKey == "" || len(request.AggregateKey) > 128 {
		return Envelope{}, nil, errors.New("aggregate key must be non-empty and at most 128 characters")
	}
	if request.OccurredAt.IsZero() {
		return Envelope{}, nil, errors.New("occurred_at must be RFC3339")
	}
	resourceBytes, err := json.Marshal(request.Resource)
	if err != nil {
		return Envelope{}, nil, fmt.Errorf("encode event resource: %w", err)
	}
	var resource map[string]any
	if err := json.Unmarshal(resourceBytes, &resource); err != nil || resource == nil {
		return Envelope{}, nil, errors.New("event resource is not a JSON object")
	}
	if _, present := resource["@type"]; present {
		return Envelope{}, nil, errors.New("event resource must not set @type; Seal assigns the contract type URL")
	}
	resource["@type"] = typeURLPrefix + binding.resource
	if request.PrincipalID == "" || len(request.PrincipalID) > 128 {
		return Envelope{}, nil, errors.New("principal id must be non-empty and at most 128 characters")
	}
	envelope := Envelope{
		EnvelopeVersion: EnvelopeVersion,
		EventID:         uuid.NewString(),
		EventType:       request.EventType,
		OccurredAt:      request.OccurredAt.UTC().Format(time.RFC3339),
		Producer:        ProducerName,
		CorrelationID:   request.AggregateKey,
		FHIR: Bundle{
			ResourceType: "Bundle",
			Type:         "message",
			BundleID:     "bdl-" + uuid.NewString(),
			Entry:        []Entry{{FullURL: "urn:uuid:" + uuid.NewString(), Resource: resource}},
		},
		Provenance: Provenance{
			PrincipalID:      request.PrincipalID,
			PrincipalRole:    request.PrincipalRole,
			LedgerCommitHash: "",
		},
		Classification: envelopeClassification,
		Topic:          binding.topic,
		AggregateKey:   request.AggregateKey,
	}
	// Per envelope.proto, classified-scope records (RESTRICTED and above)
	// carry the per-record clearance label for row-level filtering.
	if request.Classification.Rank() >= isr.ClassificationRestricted.Rank() {
		envelope.RecordClassification = string(request.Classification)
	}
	signature, err := signer.SignEnvelope(envelope)
	if err != nil {
		return Envelope{}, nil, fmt.Errorf("sign envelope provenance: %w", err)
	}
	envelope.Provenance.Signature = signature
	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		return Envelope{}, nil, fmt.Errorf("encode envelope: %w", err)
	}
	return envelope, envelopeBytes, nil
}

// DigestSHA256 returns the canonical "sha256:<64 lowercase hex>" digest of
// bytes, the platform digest convention enforced by DB CHECK constraints.
func DigestSHA256(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}
