package envelope

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
)

// fixtureKey is the throwaway synthetic fixture key documented in
// blueeconomy-contracts fixtures/yaounde|sar README (fixture verification
// only, never a production key).
const fixtureKeyID = "blueeconomy-maritime-intelligence-0"
const fixturePublicKey = "haBzmOnuDF7iFSxa_ktQFDEbNp9nd_sJ0XcIevSOhtY"

func fixtureDirectory(t *testing.T) *provenance.Directory {
	t.Helper()
	directory, err := provenance.ParseDirectory([]byte(`{"` + fixtureKeyID + `":"` + fixturePublicKey + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

// TestContractFixturesVerify proves the consumer path verifies every merged
// contracts fixture envelope (JWS-EdDSA over RFC 8785 JCS) exactly per the
// fixture convention.
func TestContractFixturesVerify(t *testing.T) {
	matches, err := filepath.Glob("testdata/*.json")
	if err != nil || len(matches) == 0 {
		t.Fatalf("fixture glob failed: %v", err)
	}
	if len(matches) != 10 {
		t.Fatalf("expected 10 contract fixtures, got %d", len(matches))
	}
	for _, path := range matches {
		raw, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := Admit(raw, fixtureDirectory(t))
		if err != nil {
			t.Fatalf("fixture %s rejected: %v", path, err)
		}
		wantType := strings.TrimSuffix(filepath.Base(path), ".json")
		if parsed.EventType != wantType {
			t.Fatalf("fixture %s: parsed event type %q", path, parsed.EventType)
		}
		if parsed.Classification != "RESTRICTED" {
			t.Fatalf("fixture %s: unexpected classification %q", path, parsed.Classification)
		}
	}
}

func TestContractFixturesTamperRejected(t *testing.T) {
	raw, err := os.ReadFile("testdata/maritime.sar.case_opened.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	// Flip the case id inside the payload: payload-mismatch must reject.
	tampered := bytes.Replace(raw, []byte(`"caseId": "sar-000001"`), []byte(`"caseId": "sar-999999"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("tamper replacement did not apply")
	}
	if _, err := Admit(tampered, fixtureDirectory(t)); err == nil {
		t.Fatal("tampered fixture verified")
	}
	// Unknown kid must reject.
	otherDirectory, err := provenance.ParseDirectory([]byte(`{"other-producer-0":"` + fixturePublicKey + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Admit(raw, otherDirectory); err == nil {
		t.Fatal("unknown kid verified")
	}
}

func TestSealRoundTrip(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := provenance.NewSigner(ProducerName+"-7", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	sealed, raw, err := Seal(signer, SealRequest{
		EventType:      EventSARCaseOpened,
		AggregateKey:   "sar-000001",
		Classification: isr.ClassificationRestricted,
		OccurredAt:     time.Date(2026, 8, 29, 14, 0, 0, 0, time.UTC),
		PrincipalID:    "f47ac10b-58cc-4372-a567-0e02b2c3d479",
		PrincipalRole:  "sar-producer",
		Resource: map[string]any{
			"caseId":            "sar-000001",
			"incidentReference": "inc-000502",
			"intakeKind":        "GEO_SOS",
			"sourceReference":   "sos-000118",
			"phase":             "INCERFA",
			"stage":             "AWARENESS",
			"classification":    "RESTRICTED",
			"openedAt":          "2026-08-29T12:14:02Z",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Topic != TopicSAR || sealed.AggregateKey != "sar-000001" {
		t.Fatalf("unexpected routing metadata: %+v", sealed)
	}
	if sealed.RecordClassification != "RESTRICTED" {
		t.Fatalf("record classification must carry the RESTRICTED floor, got %q", sealed.RecordClassification)
	}
	directory, err := provenance.ParseDirectory([]byte(`{"` + signer.KeyID() + `":"` + base64.RawURLEncoding.EncodeToString(publicKey) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Admit(raw, directory)
	if err != nil {
		t.Fatalf("sealed envelope did not verify: %v", err)
	}
	if parsed.EventType != EventSARCaseOpened || parsed.EventID != sealed.EventID {
		t.Fatalf("round trip mismatch: %+v", parsed)
	}
	var resource map[string]any
	if err := json.Unmarshal(parsed.Resource, &resource); err != nil {
		t.Fatal(err)
	}
	if resource["@type"] != "type.googleapis.com/blueeconomy.contracts.v1.SarCaseOpened" {
		t.Fatalf("unexpected @type %q", resource["@type"])
	}
}

func TestSealFailClosed(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := provenance.NewSigner(ProducerName+"-7", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	base := SealRequest{
		EventType:      EventYaoundeReleaseTransitioned,
		AggregateKey:   "ygr-000001",
		Classification: isr.ClassificationUnclassified,
		OccurredAt:     time.Now().UTC(),
		PrincipalID:    "principal-1",
		PrincipalRole:  "yaounde-producer",
		Resource:       map[string]any{"releaseId": "ygr-000001"},
	}
	if _, _, err := Seal(nil, base); err == nil {
		t.Fatal("missing signer accepted")
	}
	bad := base
	bad.EventType = "maritime.yaounde.unknown.v9"
	if _, _, err := Seal(signer, bad); err == nil {
		t.Fatal("unknown event type accepted")
	}
	bad = base
	bad.Classification = "TOP-SECRET"
	if _, _, err := Seal(signer, bad); err == nil {
		t.Fatal("unknown classification accepted")
	}
	bad = base
	bad.Resource = map[string]any{"@type": "type.googleapis.com/forged.Type"}
	if _, _, err := Seal(signer, bad); err == nil {
		t.Fatal("caller-set @type accepted")
	}
	bad = base
	bad.AggregateKey = ""
	if _, _, err := Seal(signer, bad); err == nil {
		t.Fatal("empty aggregate key accepted")
	}
	// UNCLASSIFIED content maps to INTERNAL and must not carry a record label.
	sealed, _, err := Seal(signer, base)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Classification != "INTERNAL" || sealed.RecordClassification != "" {
		t.Fatalf("never-widening mapping violated: %+v", sealed)
	}
}

func TestParseRejectsWrongVersionAndType(t *testing.T) {
	raw, err := os.ReadFile("testdata/maritime.yaounde.release_transitioned.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	wrongVersion := bytes.Replace(raw, []byte(`"envelopeVersion": "1.0"`), []byte(`"envelopeVersion": "2.0"`), 1)
	if _, err := Parse(wrongVersion); err == nil || !strings.Contains(err.Error(), RejectUnknownVersion) {
		t.Fatalf("wrong version not rejected with %s: %v", RejectUnknownVersion, err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	delete(document, "fhir")
	missing, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(missing); err == nil {
		t.Fatal("bundle-less envelope accepted")
	}
}
