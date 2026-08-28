package isr

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
)

// testSigner returns a throwaway provenance signer for envelope tests.
func testSigner(t *testing.T) *provenance.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := provenance.NewSigner(SigningKeyID, private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// requireValidSignature verifies the sealed envelope provenance signature
// against the signer's public key.
func requireValidSignature(t *testing.T, signer *provenance.Signer, envelopeBytes []byte) {
	t.Helper()
	directory, err := provenance.ParseDirectory([]byte(fmt.Sprintf(`{%q:%q}`, signer.KeyID(), signer.PublicKey())))
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.VerifyEnvelope(envelopeBytes); err != nil {
		t.Fatalf("sealed envelope signature does not verify: %v", err)
	}
}

type labelledPayload struct {
	Classification Classification `json:"classification"`
	Note           string         `json:"note"`
}

// canonicalEnvelopeFixture mirrors the platform envelope contract
// (blueeconomy.contracts.v1.EventEnvelope) shared with the ferry-ticketing
// and financial-controls producers; the conformance test decodes sealed bytes
// into it rather than into the producer's own Envelope type.
type canonicalEnvelopeFixture struct {
	EnvelopeVersion string `json:"envelopeVersion"`
	EventID         string `json:"eventId"`
	EventType       string `json:"eventType"`
	OccurredAt      string `json:"occurredAt"`
	Producer        string `json:"producer"`
	CorrelationID   string `json:"correlationId"`
	FHIR            struct {
		ResourceType string `json:"resourceType"`
		Type         string `json:"type"`
		Entry        []struct {
			Resource map[string]any `json:"resource"`
		} `json:"entry"`
	} `json:"fhir"`
	Provenance struct {
		PrincipalID      string `json:"principalId"`
		PrincipalRole    string `json:"principalRole"`
		Signature        string `json:"signature"`
		LedgerCommitHash string `json:"ledgerCommitHash"`
	} `json:"provenance"`
	Classification string `json:"classification"`
}

func TestSealEnvelopeClassificationMatch(t *testing.T) {
	occurred := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	payload := labelledPayload{Classification: ClassificationRestricted, Note: "detection admitted"}
	envelope, envelopeBytes, err := Seal(testSigner(t), TopicISR, "isr.detection_admitted", "evt-001", ClassificationRestricted, occurred, payload)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.EnvelopeVersion != EnvelopeVersion || envelope.Topic != TopicISR {
		t.Fatalf("unexpected envelope: %+v", envelope)
	}
	if envelope.Classification != EnvelopeClassificationRestricted {
		t.Fatalf("envelope classification %q is not the canonical RESTRICTED", envelope.Classification)
	}
	if envelope.Clearance != ClassificationRestricted {
		t.Fatal("envelope lost the record-level clearance label")
	}
	var roundtrip Envelope
	if err := json.Unmarshal(envelopeBytes, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if roundtrip.EventID == "" || roundtrip.Producer != ProducerName {
		t.Fatal("envelope lost identity fields")
	}
}

// TestSealConformanceCanonicalContract proves the sealed bytes match the
// canonical platform shape (camelCase keys, FHIR message bundle, provenance
// block, canonical classification set) exactly as the ferry/cvff producers
// render it.
func TestSealConformanceCanonicalContract(t *testing.T) {
	occurred := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	payload := labelledPayload{Classification: ClassificationSecret, Note: "track fused"}
	signer := testSigner(t)
	_, envelopeBytes, err := Seal(signer, TopicBehaviour, "behaviour.dark-vessel", "anomaly-001", ClassificationSecret, occurred, payload)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(envelopeBytes, &raw); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	want := []string{"classification", "correlationId", "envelopeVersion", "eventId", "eventType", "fhir", "occurredAt", "producer", "provenance"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("envelope top-level keys %v, want canonical %v", keys, want)
	}
	var fixture canonicalEnvelopeFixture
	if err := json.Unmarshal(envelopeBytes, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.EnvelopeVersion != "1.0" || fixture.EventType != "behaviour.dark-vessel" {
		t.Fatalf("unexpected envelope identity: %+v", fixture)
	}
	if _, err := time.Parse(time.RFC3339, fixture.OccurredAt); err != nil {
		t.Fatalf("occurredAt %q is not RFC3339", fixture.OccurredAt)
	}
	if fixture.Producer != ProducerName || fixture.CorrelationID != "anomaly-001" {
		t.Fatal("producer/correlationId mismatch")
	}
	if fixture.FHIR.ResourceType != "Bundle" || fixture.FHIR.Type != "message" || len(fixture.FHIR.Entry) != 1 {
		t.Fatalf("fhir block is not a message bundle: %+v", fixture.FHIR)
	}
	entry := fixture.FHIR.Entry[0].Resource
	if entry["clearance"] != string(ClassificationSecret) {
		t.Fatalf("record-level clearance metadata lost: %v", entry["clearance"])
	}
	if entry["note"] != "track fused" {
		t.Fatal("bundle entry lost the domain payload")
	}
	if fixture.Classification != EnvelopeClassificationConfidential {
		t.Fatalf("SECRET clearance must map to canonical CONFIDENTIAL, got %q", fixture.Classification)
	}
	if fixture.Provenance.Signature == "" {
		t.Fatal("provenance signature is required")
	}
	requireValidSignature(t, signer, envelopeBytes)
	switch fixture.Classification {
	case EnvelopeClassificationConfidential, EnvelopeClassificationRestricted,
		EnvelopeClassificationInternal, EnvelopeClassificationPublic, EnvelopeClassificationFiduciary:
	default:
		t.Fatalf("classification %q is not a platform EnvelopeClassification", fixture.Classification)
	}
}

func TestEnvelopeClassificationMapping(t *testing.T) {
	cases := map[Classification]string{
		ClassificationUnclassified: EnvelopeClassificationInternal,
		ClassificationRestricted:   EnvelopeClassificationRestricted,
		ClassificationConfidential: EnvelopeClassificationConfidential,
		ClassificationSecret:       EnvelopeClassificationConfidential,
	}
	for clearance, canonical := range cases {
		mapped, err := EnvelopeClassificationOf(clearance)
		if err != nil {
			t.Fatal(err)
		}
		if mapped != canonical {
			t.Fatalf("clearance %s mapped to %s, want %s", clearance, mapped, canonical)
		}
	}
	if _, err := EnvelopeClassificationOf("BOGUS"); err == nil {
		t.Fatal("unknown clearance label accepted")
	}
}

func TestSealFailsClosedOnMismatch(t *testing.T) {
	occurred := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	payload := labelledPayload{Classification: ClassificationSecret, Note: "track fused"}
	if _, _, err := Seal(testSigner(t), TopicBehaviour, "behaviour.anomaly", "track-1", ClassificationUnclassified, occurred, payload); err == nil {
		t.Fatal("envelope/payload classification mismatch accepted")
	}
	if _, _, err := Seal(testSigner(t), "maritime.unknown.v1", "x", "k", ClassificationSecret, occurred, payload); err == nil {
		t.Fatal("unapproved topic accepted")
	}
	unlabelled := struct {
		Note string `json:"note"`
	}{Note: "no label"}
	if _, _, err := Seal(testSigner(t), TopicISR, "isr.x", "k", ClassificationUnclassified, occurred, unlabelled); err == nil {
		t.Fatal("payload without classification label sealed")
	}
	if _, _, err := Seal(testSigner(t), TopicISR, "isr.x", "k", "BOGUS", occurred, payload); err == nil {
		t.Fatal("invalid envelope classification accepted")
	}
}
