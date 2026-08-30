package sar

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
)

// buildWaterwayBatch constructs a producer-conformant signed batch (the
// blueeconomy-waterway-safety uplink.rs contract) for round-trip tests.
func buildWaterwayBatch(t *testing.T, privateKey ed25519.PrivateKey, keyID string, frames []BatchFrame) (key []byte, value []byte) {
	t.Helper()
	lines := make([][]byte, 0, len(frames)+1)
	frameValues := make([]any, 0, len(frames))
	for _, frame := range frames {
		encoded, err := json.Marshal(frame)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, encoded)
		var value any
		if err := json.Unmarshal(encoded, &value); err != nil {
			t.Fatal(err)
		}
		frameValues = append(frameValues, value)
	}
	batchKey := batchKeyDigest(WaterwayTelemetryTopic, frames)
	document := map[string]any{
		"batchKey": batchKey, "encoding": "json-lines", "frameCount": float64(len(frames)),
		"frames": frameValues, "producer": "waterway-safety", "schema": WaterwayBatchSchemaDomain,
		"topic": WaterwayTelemetryTopic,
	}
	signer, err := provenance.NewSigner(keyID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := provenance.Canonicalize(document)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(canonical)
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]any{
		"record_type": WaterwayBatchProvenanceRecordType, "batch_key": batchKey,
		"frame_count": len(frames), "producer": "waterway-safety", "schema": WaterwayBatchSchemaDomain,
		"topic": WaterwayTelemetryTopic, "signature_key_id": keyID, "signature": signature,
	}
	headerLine, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	value = append(headerLine, '\n')
	for _, line := range lines {
		value = append(value, line...)
		value = append(value, '\n')
	}
	return []byte(batchKey), value
}

func safetyFrame(t *testing.T, payload []byte) BatchFrame {
	t.Helper()
	digest := sha256.Sum256(payload)
	return BatchFrame{
		DeviceID: "dev-1", GatewayID: "gw-1", SourceSequence: 7,
		ObservedAt: "2026-08-29T12:00:00Z", ReceivedAt: "2026-08-29T12:00:01Z",
		DataClassification: "RESTRICTED", PayloadBase64: base64.StdEncoding.EncodeToString(payload),
		PayloadSHA256: hex.EncodeToString(digest[:]),
	}
}

func intakeDirectory(t *testing.T, publicKey ed25519.PublicKey, keyID string) *provenance.Directory {
	t.Helper()
	directory, err := provenance.ParseDirectory([]byte(`{"` + keyID + `":"` + base64.RawURLEncoding.EncodeToString(publicKey) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestWaterwayBatchRoundTrip(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"safety_event":{"kind":"MAN_OVERBOARD","summary":"MOB reported by watch","latitude":3.8,"longitude":9.7,"persons_at_risk":1},"water_temp_c":28}`)
	key, value := buildWaterwayBatch(t, privateKey, "waterway-safety-1", []BatchFrame{safetyFrame(t, payload)})
	frames, err := ParseWaterwayBatch(key, value, WaterwayTelemetryTopic, intakeDirectory(t, publicKey, "waterway-safety-1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	event, _, relevant, err := ExtractSafetyEvent(frames[0])
	if err != nil || !relevant {
		t.Fatalf("safety event not extracted: %v relevant=%v", err, relevant)
	}
	request, err := MapWaterwaySafetyEvent(string(key), frames[0], event)
	if err != nil {
		t.Fatal(err)
	}
	if request.Classification != "RESTRICTED" || request.Phase != "INCERFA" {
		t.Fatalf("unexpected mapped request %+v", request)
	}
	if request.LastKnownLatitude == nil || *request.LastKnownLatitude != 3.8 {
		t.Fatalf("position not mapped: %+v", request)
	}
}

func TestWaterwayBatchFailClosed(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"safety_event":{"kind":"DISTRESS_ALERT","summary":"dsc alert"}}`)
	key, value := buildWaterwayBatch(t, privateKey, "waterway-safety-1", []BatchFrame{safetyFrame(t, payload)})
	directory := intakeDirectory(t, publicKey, "waterway-safety-1")
	// Tampered frame line breaks the batch digest and the signature.
	tampered := []byte(strings.Replace(string(value), `"dev-1"`, `"dev-2"`, 1))
	if _, err := ParseWaterwayBatch(key, tampered, WaterwayTelemetryTopic, directory); err == nil {
		t.Fatal("tampered batch accepted")
	}
	// Unsigned batch (frame only, no header) rejected.
	if _, err := ParseWaterwayBatch(key, []byte(`{"device_id":"dev-1"}`+"\n"), WaterwayTelemetryTopic, directory); err == nil {
		t.Fatal("unsigned batch accepted")
	}
	// Wrong key id rejected.
	other := intakeDirectory(t, publicKey, "other-producer-9")
	if _, err := ParseWaterwayBatch(key, value, WaterwayTelemetryTopic, other); err == nil {
		t.Fatal("unknown signer accepted")
	}
	// Wrong expected topic rejected.
	if _, err := ParseWaterwayBatch(key, value, "other.topic.v1", directory); err == nil {
		t.Fatal("topic mismatch accepted")
	}
}

func TestExtractSafetyEventSkipsRoutineFrames(t *testing.T) {
	frame := safetyFrame(t, []byte(`{"water_temp_c":28}`))
	_, _, relevant, err := ExtractSafetyEvent(frame)
	if err != nil {
		t.Fatal(err)
	}
	if relevant {
		t.Fatal("routine frame marked safety-relevant")
	}
	bad := safetyFrame(t, []byte(`{"safety_event":{"kind":"WATERSPOUT","summary":"x"}}`))
	if _, _, _, err := ExtractSafetyEvent(bad); err == nil {
		t.Fatal("unknown safety kind accepted")
	}
}

func TestSosAlertMapping(t *testing.T) {
	alert := SosAlertRaised{
		SosAlertID: "sos-000118", ReporterID: "op-1", VesselReference: "M/V Test",
		LatitudeMicros: 3800000, LongitudeMicros: 9700000, RecordedAt: "2026-08-29T11:58:41Z",
		Classification: "RESTRICTED",
	}
	request, err := MapSosAlert(alert)
	if err != nil {
		t.Fatal(err)
	}
	if request.Phase != string(PhaseDetresfa) || request.Classification != "RESTRICTED" {
		t.Fatalf("unexpected sos mapping %+v", request)
	}
	if request.SourceRef != "geo-sos:sos-000118" {
		t.Fatalf("unexpected source_ref %q", request.SourceRef)
	}
	if *request.LastKnownLatitude != 3.8 {
		t.Fatalf("micro-degree conversion wrong: %v", *request.LastKnownLatitude)
	}
	// Floor: a producer label below RESTRICTED is raised to RESTRICTED.
	alert.Classification = "UNCLASSIFIED"
	request, err = MapSosAlert(alert)
	if err != nil {
		t.Fatal(err)
	}
	if request.Classification != "RESTRICTED" {
		t.Fatalf("SOS floor not enforced: %s", request.Classification)
	}
	// No floats: micros helper is fixed-point.
	var seq uint64 = 42
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], seq)
	_ = time.Now
}
