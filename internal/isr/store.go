package isr

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/incident"
)

var (
	// ErrNotFound is returned when a referenced record does not exist.
	ErrNotFound = errors.New("isr record not found")
	// ErrConflict is returned when a replay carries conflicting evidence.
	ErrConflict = errors.New("source event conflicts with retained isr evidence")
	// ErrForbidden is returned when a principal lacks role or clearance.
	ErrForbidden = errors.New("principal lacks role or clearance for this isr resource")
)

// Store persists ISR events, fused-track audit and anomalies and enforces
// clearance-based reads at the service layer.
type Store struct{ pool *pgxpool.Pool }

// NewStore binds the store to an existing pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// SignedDetectionRequest is one signature-verified multi-modal detection
// admission. Payload is the canonical JSON encoding of Detection.
type SignedDetectionRequest struct {
	SourceID      string `json:"source_id"`
	SourceEventID string `json:"source_event_id"`
	Payload       []byte `json:"payload"`
	Signature     []byte `json:"signature"`
}

// DetectionAdmission is the retained admission evidence for one detection.
type DetectionAdmission struct {
	EventID        string         `json:"event_id"`
	Classification Classification `json:"classification"`
	PayloadSHA256  string         `json:"payload_sha256"`
	KeyFingerprint string         `json:"key_fingerprint"`
	ReceivedAt     time.Time      `json:"received_at"`
	Replayed       bool           `json:"replayed"`
}

func (request SignedDetectionRequest) validateEnvelope() error {
	if !identifierPattern.MatchString(request.SourceID) || !identifierPattern.MatchString(request.SourceEventID) {
		return errors.New("source identifiers are invalid")
	}
	if len(request.Payload) == 0 || len(request.Payload) > 1<<20 {
		return errors.New("payload must be between 1 byte and 1 MiB")
	}
	if len(request.Signature) != ed25519.SignatureSize {
		return errors.New("ed25519 signature is required")
	}
	return nil
}

// DecodeDetection strictly decodes one Detection payload (unknown fields
// rejected, single object).
// DecodeDetection strictly decodes one Detection payload (unknown fields
// rejected, exactly one object).
func DecodeDetection(payload []byte) (Detection, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var detection Detection
	if err := decoder.Decode(&detection); err != nil {
		return Detection{}, errors.New("signed detection payload must be one detection object without unknown fields")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Detection{}, errors.New("signed detection payload must contain exactly one detection object")
	}
	return detection, nil
}

// AdmitDetection verifies the feed source signature, enforces the mandatory
// classification label, persists the detection, and writes the platform
// envelope to the ISR outbox — atomically. Replay of an identical admission
// returns the retained evidence; a conflicting replay fails closed.
func (store *Store) AdmitDetection(ctx context.Context, request SignedDetectionRequest) (Detection, DetectionAdmission, error) {
	if err := request.validateEnvelope(); err != nil {
		return Detection{}, DetectionAdmission{}, err
	}
	detection, err := DecodeDetection(request.Payload)
	if err != nil {
		return Detection{}, DetectionAdmission{}, err
	}
	if detection.SourceID != request.SourceID || detection.SourceEventID != request.SourceEventID {
		return Detection{}, DetectionAdmission{}, errors.New("signed detection must bind source_id and source_event_id")
	}
	if err := detection.Validate(); err != nil {
		return Detection{}, DetectionAdmission{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Detection{}, DetectionAdmission{}, fmt.Errorf("begin detection admission: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var publicKey []byte
	var fingerprint string
	var active bool
	if err := tx.QueryRow(ctx, `SELECT public_key, key_fingerprint, active FROM maritime_feed_sources WHERE source_id=$1 FOR SHARE`, request.SourceID).Scan(&publicKey, &fingerprint, &active); errors.Is(err, pgx.ErrNoRows) {
		return Detection{}, DetectionAdmission{}, ErrNotFound
	} else if err != nil {
		return Detection{}, DetectionAdmission{}, fmt.Errorf("load feed source: %w", err)
	}
	if !active {
		return Detection{}, DetectionAdmission{}, errors.New("feed source is inactive")
	}
	signingBytes := incident.FeedSigningBytes(request.SourceID, request.SourceEventID, request.Payload)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), signingBytes, request.Signature) {
		var graceKey []byte
		err := tx.QueryRow(ctx, `SELECT prior_public_key FROM maritime_feed_source_key_rotations WHERE source_id=$1 AND grace_until>$2 ORDER BY rotated_at DESC LIMIT 1`, request.SourceID, time.Now().UTC()).Scan(&graceKey)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(graceKey), signingBytes, request.Signature) {
			return Detection{}, DetectionAdmission{}, errors.New("detection signature verification failed")
		}
	}
	digest := sha256.Sum256(request.Payload)
	payloadSHA256 := "sha256:" + hex.EncodeToString(digest[:])
	receivedAt := time.Now().UTC()
	correlationRefs, err := json.Marshal(detection.CorrelationRefs)
	if err != nil {
		return Detection{}, DetectionAdmission{}, fmt.Errorf("encode correlation refs: %w", err)
	}
	var retainedReceivedAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO maritime_isr_events (
			event_id, source_id, source_event_id, modality, classification,
			observed_at, has_position, latitude, longitude, mmsi, payload,
			payload_sha256, signature, correlation_refs, received_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		ON CONFLICT (source_id, source_event_id) DO NOTHING
		RETURNING received_at`,
		detection.EventID, detection.SourceID, detection.SourceEventID, string(detection.Modality),
		string(detection.Classification), detection.ObservedAt, detection.HasPosition,
		nullableFloat(detection.HasPosition, detection.Latitude), nullableFloat(detection.HasPosition, detection.Longitude),
		nullableString(detection.MMSI), request.Payload, payloadSHA256, request.Signature, correlationRefs, receivedAt).
		Scan(&retainedReceivedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		var retainedDigest string
		var retainedSignature []byte
		var retainedEventID string
		err = tx.QueryRow(ctx, `SELECT event_id, payload_sha256, signature, received_at FROM maritime_isr_events WHERE source_id=$1 AND source_event_id=$2 FOR UPDATE`, request.SourceID, request.SourceEventID).
			Scan(&retainedEventID, &retainedDigest, &retainedSignature, &retainedReceivedAt)
		if err != nil {
			return Detection{}, DetectionAdmission{}, fmt.Errorf("load retained detection: %w", err)
		}
		if retainedDigest != payloadSHA256 || !bytesEqual(retainedSignature, request.Signature) || retainedEventID != detection.EventID {
			return Detection{}, DetectionAdmission{}, ErrConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return Detection{}, DetectionAdmission{}, fmt.Errorf("commit detection replay: %w", err)
		}
		return detection, DetectionAdmission{EventID: detection.EventID, Classification: detection.Classification, PayloadSHA256: payloadSHA256, KeyFingerprint: fingerprint, ReceivedAt: retainedReceivedAt, Replayed: true}, nil
	}
	if err != nil {
		return Detection{}, DetectionAdmission{}, fmt.Errorf("record detection: %w", err)
	}
	envelope, envelopeBytes, err := Seal(TopicISR, "isr.detection_admitted", detection.EventID, detection.Classification, receivedAt, detection)
	if err != nil {
		return Detection{}, DetectionAdmission{}, err
	}
	// The outbox row keeps the record-level clearance label (DB CHECK); the
	// payload column carries the canonical envelope document verbatim.
	if _, err := tx.Exec(ctx, `
		INSERT INTO maritime_isr_outbox (event_id, topic, event_type, classification, aggregate_key, payload, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		uuid.New(), envelope.Topic, envelope.EventType, string(envelope.Clearance), envelope.AggregateKey, envelopeBytes, receivedAt); err != nil {
		return Detection{}, DetectionAdmission{}, fmt.Errorf("write detection outbox event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Detection{}, DetectionAdmission{}, fmt.Errorf("commit detection admission: %w", err)
	}
	return detection, DetectionAdmission{EventID: detection.EventID, Classification: detection.Classification, PayloadSHA256: payloadSHA256, KeyFingerprint: fingerprint, ReceivedAt: retainedReceivedAt}, nil
}

func nullableFloat(present bool, value float64) any {
	if !present {
		return nil
	}
	return value
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for index := range a {
		diff |= a[index] ^ b[index]
	}
	return diff == 0
}
