package incident

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

type SignedFeedIncidentRequest struct {
	FeedAdmissionRequest
}

type SignedFeedIncidentResult struct {
	Admission FeedAdmission `json:"admission"`
	Incident  Incident      `json:"incident"`
}

func (store *Store) AdmitFeedIncident(ctx context.Context, request SignedFeedIncidentRequest) (SignedFeedIncidentResult, error) {
	if err := request.FeedAdmissionRequest.Validate(); err != nil {
		return SignedFeedIncidentResult{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(request.Payload))
	decoder.DisallowUnknownFields()
	var incidentRequest CreateRequest
	if err := decoder.Decode(&incidentRequest); err != nil {
		return SignedFeedIncidentResult{}, errors.New("signed feed payload must be one incident creation object")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return SignedFeedIncidentResult{}, errors.New("signed feed payload must contain one incident creation object")
	}
	if incidentRequest.SourceEventID != request.SourceID+":"+request.SourceEventID {
		return SignedFeedIncidentResult{}, errors.New("signed incident source_event_id must bind source_id and source_event_id")
	}
	if incidentRequest.CreatedBy != "feed:"+request.SourceID {
		return SignedFeedIncidentResult{}, errors.New("signed incident created_by must bind source_id")
	}
	if err := incidentRequest.Validate(); err != nil {
		return SignedFeedIncidentResult{}, err
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return SignedFeedIncidentResult{}, fmt.Errorf("begin feed incident transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	admission, err := admitFeedEventInTransaction(ctx, tx, request.FeedAdmissionRequest)
	if err != nil {
		return SignedFeedIncidentResult{}, err
	}
	created, err := createIncidentInTransaction(ctx, tx, incidentRequest)
	if err != nil {
		return SignedFeedIncidentResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return SignedFeedIncidentResult{}, fmt.Errorf("commit feed incident transaction: %w", err)
	}
	return SignedFeedIncidentResult{Admission: admission, Incident: created}, nil
}

func admitFeedEventInTransaction(ctx context.Context, tx pgx.Tx, request FeedAdmissionRequest) (FeedAdmission, error) {
	var publicKey []byte
	var fingerprint string
	var active bool
	if err := tx.QueryRow(ctx, `SELECT public_key, key_fingerprint, active FROM maritime_feed_sources WHERE source_id=$1 FOR SHARE`, request.SourceID).Scan(&publicKey, &fingerprint, &active); errors.Is(err, pgx.ErrNoRows) {
		return FeedAdmission{}, ErrNotFound
	} else if err != nil {
		return FeedAdmission{}, fmt.Errorf("load feed source: %w", err)
	}
	if !active {
		return FeedAdmission{}, errors.New("feed source is inactive")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), feedSigningBytes(request.SourceID, request.SourceEventID, request.Payload), request.Signature) {
		return FeedAdmission{}, errors.New("feed event signature verification failed")
	}
	digest := sha256.Sum256(request.Payload)
	payloadSHA256 := "sha256:" + hex.EncodeToString(digest[:])
	receivedAt := time.Now().UTC()
	var retainedReceivedAt time.Time
	err := tx.QueryRow(ctx, `
		INSERT INTO maritime_feed_events (source_id, source_event_id, payload_sha256, signature, received_at)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (source_id, source_event_id) DO NOTHING
		RETURNING received_at`, request.SourceID, request.SourceEventID, payloadSHA256, request.Signature, receivedAt).Scan(&retainedReceivedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		var retainedDigest string
		var retainedSignature []byte
		err = tx.QueryRow(ctx, `SELECT payload_sha256, signature, received_at FROM maritime_feed_events WHERE source_id=$1 AND source_event_id=$2 FOR UPDATE`, request.SourceID, request.SourceEventID).Scan(&retainedDigest, &retainedSignature, &retainedReceivedAt)
		if err != nil {
			return FeedAdmission{}, fmt.Errorf("load retained feed event: %w", err)
		}
		if retainedDigest != payloadSHA256 || !bytes.Equal(retainedSignature, request.Signature) {
			return FeedAdmission{}, ErrIdempotencyConflict
		}
	} else if err != nil {
		return FeedAdmission{}, fmt.Errorf("record feed event: %w", err)
	}
	return FeedAdmission{SourceID: request.SourceID, SourceEventID: request.SourceEventID, PayloadSHA256: payloadSHA256, KeyFingerprint: fingerprint, ReceivedAt: retainedReceivedAt}, nil
}

// FeedSourceRevocation records an irreversible local source-retirement decision.
type FeedSourceRevocation struct {
	SourceID  string `json:"source_id"`
	Reason    string `json:"reason"`
	RevokedBy string `json:"revoked_by"`
}

func (request FeedSourceRevocation) Validate() error {
	if !incidentIDPattern.MatchString(request.SourceID) || !incidentIDPattern.MatchString(request.RevokedBy) {
		return errors.New("source_id and revoked_by must be canonical identifiers")
	}
	if strings.TrimSpace(request.Reason) == "" || len(request.Reason) > 512 {
		return errors.New("reason must be between 1 and 512 characters")
	}
	return nil
}

// RevokeFeedSource deactivates an admitted source and preserves who and why.
// Repeating exactly the same revocation is idempotent; conflicting evidence fails.
func (store *Store) RevokeFeedSource(ctx context.Context, request FeedSourceRevocation) error {
	if err := request.Validate(); err != nil {
		return err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin feed source revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var active bool
	if err := tx.QueryRow(ctx, `SELECT active FROM maritime_feed_sources WHERE source_id=$1 FOR UPDATE`, request.SourceID).Scan(&active); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("load feed source: %w", err)
	}
	var retainedReason, retainedBy string
	err = tx.QueryRow(ctx, `SELECT reason, revoked_by FROM maritime_feed_source_revocations WHERE source_id=$1 FOR UPDATE`, request.SourceID).Scan(&retainedReason, &retainedBy)
	if err == nil {
		if retainedReason != request.Reason || retainedBy != request.RevokedBy {
			return ErrIdempotencyConflict
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("load feed source revocation: %w", err)
	}
	if !active {
		return errors.New("inactive feed source has no retained revocation evidence")
	}
	now := time.Now().UTC()
	if _, err := tx.Exec(ctx, `UPDATE maritime_feed_sources SET active=false, updated_at=$2 WHERE source_id=$1`, request.SourceID, now); err != nil {
		return fmt.Errorf("deactivate feed source: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO maritime_feed_source_revocations (source_id, reason, revoked_by, revoked_at) VALUES ($1,$2,$3,$4)`, request.SourceID, request.Reason, request.RevokedBy, now); err != nil {
		return fmt.Errorf("record feed source revocation: %w", err)
	}
	return tx.Commit(ctx)
}
