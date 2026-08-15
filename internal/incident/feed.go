package incident

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type FeedSourceRegistration struct {
	SourceID   string            `json:"source_id"`
	SourceKind string            `json:"source_kind"`
	Authority  string            `json:"authority"`
	PublicKey  ed25519.PublicKey `json:"public_key"`
	Active     bool              `json:"active"`
}

type FeedAdmissionRequest struct {
	SourceID      string `json:"source_id"`
	SourceEventID string `json:"source_event_id"`
	Payload       []byte `json:"payload"`
	Signature     []byte `json:"signature"`
}

type FeedAdmission struct {
	SourceID       string    `json:"source_id"`
	SourceEventID  string    `json:"source_event_id"`
	PayloadSHA256  string    `json:"payload_sha256"`
	KeyFingerprint string    `json:"key_fingerprint"`
	ReceivedAt     time.Time `json:"received_at"`
}

func (registration FeedSourceRegistration) Validate() error {
	if !incidentIDPattern.MatchString(registration.SourceID) || !incidentIDPattern.MatchString(registration.Authority) {
		return errors.New("source_id and authority must be canonical identifiers")
	}
	if registration.SourceKind != "AIS" && registration.SourceKind != "VTS" && registration.SourceKind != "RADAR" && registration.SourceKind != "PORT" && registration.SourceKind != "AGENCY" {
		return errors.New("source_kind is unsupported")
	}
	if len(registration.PublicKey) != ed25519.PublicKeySize {
		return errors.New("ed25519 public key is required")
	}
	return nil
}

func (request FeedAdmissionRequest) Validate() error {
	if !incidentIDPattern.MatchString(request.SourceID) || !incidentIDPattern.MatchString(request.SourceEventID) {
		return errors.New("source identifiers are invalid")
	}
	if len(request.Payload) == 0 || len(request.Payload) > 8<<20 {
		return errors.New("payload must be between 1 byte and 8 MiB")
	}
	if len(request.Signature) != ed25519.SignatureSize {
		return errors.New("ed25519 signature is required")
	}
	return nil
}

func feedSigningBytes(sourceID, eventID string, payload []byte) []byte {
	digest := sha256.Sum256(payload)
	return []byte(sourceID + "\n" + eventID + "\nsha256:" + hex.EncodeToString(digest[:]))
}

func (store *Store) RegisterFeedSource(ctx context.Context, registration FeedSourceRegistration) error {
	if err := registration.Validate(); err != nil {
		return err
	}
	digest := sha256.Sum256(registration.PublicKey)
	_, err := store.pool.Exec(ctx, `INSERT INTO maritime_feed_sources (source_id, source_kind, authority, public_key, key_fingerprint, active, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$7) ON CONFLICT (source_id) DO UPDATE SET source_kind=EXCLUDED.source_kind, authority=EXCLUDED.authority, public_key=EXCLUDED.public_key, key_fingerprint=EXCLUDED.key_fingerprint, active=EXCLUDED.active, updated_at=EXCLUDED.updated_at`, registration.SourceID, registration.SourceKind, registration.Authority, []byte(registration.PublicKey), "sha256:"+hex.EncodeToString(digest[:]), registration.Active, time.Now().UTC())
	return err
}

func (store *Store) AdmitFeedEvent(ctx context.Context, request FeedAdmissionRequest) (FeedAdmission, error) {
	if err := request.Validate(); err != nil {
		return FeedAdmission{}, err
	}
	var publicKey []byte
	var fingerprint string
	var active bool
	err := store.pool.QueryRow(ctx, `SELECT public_key, key_fingerprint, active FROM maritime_feed_sources WHERE source_id=$1`, request.SourceID).Scan(&publicKey, &fingerprint, &active)
	if errors.Is(err, pgx.ErrNoRows) {
		return FeedAdmission{}, ErrNotFound
	}
	if err != nil {
		return FeedAdmission{}, fmt.Errorf("load feed source: %w", err)
	}
	if !active {
		return FeedAdmission{}, errors.New("feed source is inactive")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), feedSigningBytes(request.SourceID, request.SourceEventID, request.Payload), request.Signature) {
		return FeedAdmission{}, errors.New("feed event signature verification failed")
	}
	digest := sha256.Sum256(request.Payload)
	receivedAt := time.Now().UTC()
	_, err = store.pool.Exec(ctx, `INSERT INTO maritime_feed_events (source_id, source_event_id, payload_sha256, signature, received_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (source_id, source_event_id) DO NOTHING`, request.SourceID, request.SourceEventID, "sha256:"+hex.EncodeToString(digest[:]), request.Signature, receivedAt)
	if err != nil {
		return FeedAdmission{}, fmt.Errorf("record feed event: %w", err)
	}
	return FeedAdmission{SourceID: request.SourceID, SourceEventID: request.SourceEventID, PayloadSHA256: "sha256:" + hex.EncodeToString(digest[:]), KeyFingerprint: fingerprint, ReceivedAt: receivedAt}, nil
}

func EncodeFeedSignature(sourceID, eventID string, payload []byte, privateKey ed25519.PrivateKey) string {
	return base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, feedSigningBytes(sourceID, eventID, payload)))
}

func DecodeFeedSignature(value string) ([]byte, error) {
	canonical := strings.TrimSpace(value)
	decoded, err := base64.StdEncoding.DecodeString(canonical)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(canonical)
	}
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.SignatureSize {
		return nil, errors.New("decoded signature has invalid size")
	}
	return decoded, nil
}

func SameFeedPayload(a, b []byte) bool { return bytes.Equal(a, b) }

func FeedEventID() string { return uuid.NewString() }
