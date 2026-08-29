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
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrFeedSourceNotActive is returned when a feed admission references a
	// source that is pending approval or has been revoked. Fail-closed: only
	// ACTIVE sources may admit events.
	ErrFeedSourceNotActive = errors.New("feed source is not active")
	// ErrFeedSignatureInvalid is returned when the ed25519 signature over the
	// canonical feed preimage verifies against neither the active key nor a
	// prior key inside its grace window.
	ErrFeedSignatureInvalid = errors.New("feed event signature verification failed")
	// ErrMakerChecker is returned when the feed-source registrar attempts to
	// activate its own registration; activation requires a distinct verified
	// principal.
	ErrMakerChecker = errors.New("maker-checker violation: registrar and activator must be distinct principals")
	// ErrFeedSourceRevoked is returned when activation is attempted on a
	// revoked (permanently retired) feed source.
	ErrFeedSourceRevoked = errors.New("revoked feed source cannot be re-activated")
)

type FeedSourceRegistration struct {
	SourceID   string            `json:"source_id"`
	SourceKind string            `json:"source_kind"`
	Authority  string            `json:"authority"`
	PublicKey  ed25519.PublicKey `json:"public_key"`
	// RegisteredBy is the verified principal that created the registration.
	// It is never taken from the request body; callers bind the
	// authenticated subject. Activation later requires a distinct principal.
	RegisteredBy string `json:"registered_by"`
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
	if !incidentIDPattern.MatchString(registration.RegisteredBy) {
		return errors.New("registered_by must be the verified registrar principal")
	}
	if registration.SourceKind != "AIS" && registration.SourceKind != "VTS" && registration.SourceKind != "RADAR" && registration.SourceKind != "PORT" && registration.SourceKind != "AGENCY" &&
		registration.SourceKind != "SAR" && registration.SourceKind != "RF" && registration.SourceKind != "ACOUSTIC" && registration.SourceKind != "OPTICAL" {
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

// FeedSigningBytes is the canonical signing preimage for feed admissions,
// exported so the ISR admission path verifies the identical signature scheme.
func FeedSigningBytes(sourceID, eventID string, payload []byte) []byte {
	return feedSigningBytes(sourceID, eventID, payload)
}

// RegisterFeedSource records a new feed source PENDING (active=false). A
// registration can never activate a source — activation is a separate
// maker-checker decision by a distinct verified principal
// (ActivateFeedSource). Re-registering identical evidence is an idempotent
// replay; re-registering with a different key, kind or authority fails
// closed with ErrIdempotencyConflict instead of silently replacing the
// trusted key material, and never re-activates a pending or revoked source.
func (store *Store) RegisterFeedSource(ctx context.Context, registration FeedSourceRegistration) error {
	if err := registration.Validate(); err != nil {
		return err
	}
	digest := sha256.Sum256(registration.PublicKey)
	fingerprint := "sha256:" + hex.EncodeToString(digest[:])
	now := time.Now().UTC()
	var retainedID string
	err := store.pool.QueryRow(ctx, `
		INSERT INTO maritime_feed_sources (source_id, source_kind, authority, public_key, key_fingerprint, active, registered_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,false,$6,$7,$7)
		ON CONFLICT (source_id) DO NOTHING
		RETURNING source_id`,
		registration.SourceID, registration.SourceKind, registration.Authority,
		[]byte(registration.PublicKey), fingerprint, registration.RegisteredBy, now).Scan(&retainedID)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("register feed source: %w", err)
	}
	var retainedKind, retainedAuthority string
	var retainedKey []byte
	if err := store.pool.QueryRow(ctx, `SELECT source_kind, authority, public_key FROM maritime_feed_sources WHERE source_id=$1`, registration.SourceID).Scan(&retainedKind, &retainedAuthority, &retainedKey); err != nil {
		return fmt.Errorf("load retained feed source: %w", err)
	}
	if retainedKind != registration.SourceKind || retainedAuthority != registration.Authority || !bytes.Equal(retainedKey, registration.PublicKey) {
		return ErrIdempotencyConflict
	}
	return nil
}

// FeedSourceActivation is the maker-checker approval that turns a PENDING
// feed source ACTIVE. ActivatedBy is the verified approving principal, which
// must differ from the registrar recorded at registration.
type FeedSourceActivation struct {
	SourceID    string `json:"source_id"`
	ActivatedBy string `json:"activated_by"`
}

func (request FeedSourceActivation) Validate() error {
	if !incidentIDPattern.MatchString(request.SourceID) || !incidentIDPattern.MatchString(request.ActivatedBy) {
		return errors.New("source_id and activated_by must be canonical identifiers")
	}
	return nil
}

// ActivateFeedSource activates a pending feed source under maker-checker
// control: the activator must be a distinct verified principal from the
// registrar, and the activation (registrar, activator, timestamp) is
// persisted as durable audit evidence. Revoked sources are permanently
// retired and cannot be re-activated. Repeating exactly the same activation
// is idempotent; a conflicting activation fails with
// ErrIdempotencyConflict.
func (store *Store) ActivateFeedSource(ctx context.Context, request FeedSourceActivation) error {
	if err := request.Validate(); err != nil {
		return err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin feed source activation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var registeredBy string
	var active bool
	if err := tx.QueryRow(ctx, `SELECT registered_by, active FROM maritime_feed_sources WHERE source_id=$1 FOR UPDATE`, request.SourceID).Scan(&registeredBy, &active); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("load feed source: %w", err)
	}
	var revoked bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM maritime_feed_source_revocations WHERE source_id=$1)`, request.SourceID).Scan(&revoked); err != nil {
		return fmt.Errorf("load feed source revocation: %w", err)
	}
	if revoked {
		return ErrFeedSourceRevoked
	}
	if request.ActivatedBy == registeredBy {
		return ErrMakerChecker
	}
	if active {
		var retainedBy string
		err := tx.QueryRow(ctx, `SELECT activated_by FROM maritime_feed_source_activations WHERE source_id=$1`, request.SourceID).Scan(&retainedBy)
		if err == nil {
			if retainedBy != request.ActivatedBy {
				return ErrIdempotencyConflict
			}
			return tx.Commit(ctx)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("load feed source activation: %w", err)
		}
		// Legacy source activated before maker-checker existed: backfill the
		// audit record so every active source has activation evidence.
		if _, err := tx.Exec(ctx, `INSERT INTO maritime_feed_source_activations (source_id, registered_by, activated_by, activated_at) VALUES ($1,$2,$3,$4)`, request.SourceID, registeredBy, request.ActivatedBy, time.Now().UTC()); err != nil {
			return fmt.Errorf("record feed source activation: %w", err)
		}
		return tx.Commit(ctx)
	}
	now := time.Now().UTC()
	if _, err := tx.Exec(ctx, `INSERT INTO maritime_feed_source_activations (source_id, registered_by, activated_by, activated_at) VALUES ($1,$2,$3,$4)`, request.SourceID, registeredBy, request.ActivatedBy, now); err != nil {
		return fmt.Errorf("record feed source activation: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE maritime_feed_sources SET active=true, updated_at=$2 WHERE source_id=$1`, request.SourceID, now); err != nil {
		return fmt.Errorf("activate feed source: %w", err)
	}
	return tx.Commit(ctx)
}

// AdmitFeedEvent records one signed feed event inside a serializable
// transaction. A replay is accepted only when the retained payload digest and
// signature match exactly; a source_event_id reused with a conflicting payload
// or signature fails closed with ErrIdempotencyConflict instead of being
// silently absorbed by ON CONFLICT DO NOTHING.
func (store *Store) AdmitFeedEvent(ctx context.Context, request FeedAdmissionRequest) (FeedAdmission, error) {
	if err := request.Validate(); err != nil {
		return FeedAdmission{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return FeedAdmission{}, fmt.Errorf("begin feed event admission: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	admission, err := admitFeedEventInTransaction(ctx, tx, request)
	if err != nil {
		if auditErr := store.auditFeedAdmissionDenial(ctx, request, err); auditErr != nil {
			return FeedAdmission{}, auditErr
		}
		return FeedAdmission{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return FeedAdmission{}, fmt.Errorf("commit feed event admission: %w", err)
	}
	return admission, nil
}

// feedDenialReason maps an admission failure to the auditable denial reason,
// or "" when the failure is not a trust denial (validation, conflicts and
// infrastructure errors are not audit-logged here).
func feedDenialReason(err error) string {
	switch {
	case errors.Is(err, ErrNotFound):
		return "source-unknown"
	case errors.Is(err, ErrFeedSourceNotActive):
		return "source-not-active"
	case errors.Is(err, ErrFeedSignatureInvalid):
		return "signature-invalid"
	default:
		return ""
	}
}

// auditFeedAdmissionDenial durably records a rejected admission so forged or
// premature feed attempts leave audit evidence. A failure to write the audit
// record is itself reported (never swallowed); the admission stays denied.
func (store *Store) auditFeedAdmissionDenial(ctx context.Context, request FeedAdmissionRequest, admissionErr error) error {
	reason := feedDenialReason(admissionErr)
	if reason == "" {
		return nil
	}
	if err := RecordFeedAdmissionDenial(ctx, store.pool, request.SourceID, request.SourceEventID, reason); err != nil {
		return fmt.Errorf("audit feed admission denial (%v): %w", admissionErr, err)
	}
	return nil
}

// RecordFeedAdmissionDenial appends one denial audit record. It is exported
// so the ISR detection-admission path (internal/isr) records denials into
// the same audit trail on the shared database.
func RecordFeedAdmissionDenial(ctx context.Context, pool *pgxpool.Pool, sourceID, sourceEventID, reason string) error {
	if _, err := pool.Exec(ctx, `
		INSERT INTO maritime_feed_admission_denials (denial_id, source_id, source_event_id, reason, denied_at)
		VALUES ($1,$2,$3,$4,$5)`, uuid.NewString(), sourceID, sourceEventID, reason, time.Now().UTC()); err != nil {
		return fmt.Errorf("record feed admission denial: %w", err)
	}
	return nil
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
		if auditErr := store.auditFeedAdmissionDenial(ctx, request.FeedAdmissionRequest, err); auditErr != nil {
			return SignedFeedIncidentResult{}, auditErr
		}
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
		return FeedAdmission{}, ErrFeedSourceNotActive
	}
	signingBytes := feedSigningBytes(request.SourceID, request.SourceEventID, request.Payload)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), signingBytes, request.Signature) {
		var graceKey []byte
		err := tx.QueryRow(ctx, `SELECT prior_public_key FROM maritime_feed_source_key_rotations WHERE source_id=$1 AND grace_until>$2 ORDER BY rotated_at DESC LIMIT 1`, request.SourceID, time.Now().UTC()).Scan(&graceKey)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(graceKey), signingBytes, request.Signature) {
			return FeedAdmission{}, ErrFeedSignatureInvalid
		}
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

type FeedSourceKeyRotation struct {
	SourceID     string            `json:"source_id"`
	NewPublicKey ed25519.PublicKey `json:"new_public_key"`
	GraceUntil   time.Time         `json:"grace_until"`
	RotatedBy    string            `json:"rotated_by"`
}

func (request FeedSourceKeyRotation) Validate(now time.Time) error {
	if !incidentIDPattern.MatchString(request.SourceID) || !incidentIDPattern.MatchString(request.RotatedBy) {
		return errors.New("source_id and rotated_by must be canonical identifiers")
	}
	if len(request.NewPublicKey) != ed25519.PublicKeySize {
		return errors.New("new ed25519 public key is required")
	}
	if !request.GraceUntil.After(now) || request.GraceUntil.After(now.Add(30*24*time.Hour)) {
		return errors.New("grace_until must be after now and no more than 30 days ahead")
	}
	return nil
}

// RotateFeedSourceKey replaces the active verification key while retaining the prior key only until grace_until.
func (store *Store) RotateFeedSourceKey(ctx context.Context, request FeedSourceKeyRotation) error {
	now := time.Now().UTC()
	if err := request.Validate(now); err != nil {
		return err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin feed source key rotation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var priorKey []byte
	var priorFingerprint string
	var active bool
	if err := tx.QueryRow(ctx, `SELECT public_key, key_fingerprint, active FROM maritime_feed_sources WHERE source_id=$1 FOR UPDATE`, request.SourceID).Scan(&priorKey, &priorFingerprint, &active); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("load feed source: %w", err)
	}
	if !active {
		return errors.New("feed source is inactive")
	}
	if bytes.Equal(priorKey, request.NewPublicKey) {
		return errors.New("new key must differ from active key")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO maritime_feed_source_key_rotations (source_id, prior_key_fingerprint, prior_public_key, grace_until, rotated_by, rotated_at) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (source_id, prior_key_fingerprint) DO UPDATE SET grace_until=EXCLUDED.grace_until, rotated_by=EXCLUDED.rotated_by, rotated_at=EXCLUDED.rotated_at`, request.SourceID, priorFingerprint, priorKey, request.GraceUntil, request.RotatedBy, now); err != nil {
		return fmt.Errorf("record prior key: %w", err)
	}
	digest := sha256.Sum256(request.NewPublicKey)
	if _, err := tx.Exec(ctx, `UPDATE maritime_feed_sources SET public_key=$2, key_fingerprint=$3, updated_at=$4 WHERE source_id=$1`, request.SourceID, []byte(request.NewPublicKey), "sha256:"+hex.EncodeToString(digest[:]), now); err != nil {
		return fmt.Errorf("activate replacement key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit feed source key rotation: %w", err)
	}
	return nil
}
