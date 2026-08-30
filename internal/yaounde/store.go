package yaounde

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/envelope"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/geo"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/provenance"
)

// Store persists the gateway state: peers, releases, inbound reports,
// picture contributions, the hash-chained audit ledger and the transactional
// yaounde outbox. Every state change appends its audit entry and outbox
// event in the same transaction, so evidence and event emission are atomic.
type Store struct {
	pool   *pgxpool.Pool
	signer *provenance.Signer
	tracks TrackSource
}

// NewStore binds the store to an existing pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// WithSigner attaches the provenance signer used to seal every emitted
// envelope. Emission paths fail closed when no signer is attached.
func (store *Store) WithSigner(signer *provenance.Signer) *Store {
	store.signer = signer
	return store
}

// WithTrackSource attaches the national-picture track source used by the
// shared-picture pipeline. Picture routes fail closed when absent.
func (store *Store) WithTrackSource(source TrackSource) *Store {
	store.tracks = source
	return store
}

// Pool exposes the underlying pool for sibling stores sharing the database.
func (store *Store) Pool() *pgxpool.Pool { return store.pool }

// --- peers ---------------------------------------------------------------

// RegisterPeer records one peer PENDING. Registration never self-activates;
// activation is a maker-checker decision by a distinct principal. Identical
// re-registration is an idempotent replay; conflicting evidence fails closed.
func (store *Store) RegisterPeer(ctx context.Context, request PeerRegistration) error {
	if err := request.Validate(); err != nil {
		return err
	}
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin peer registration: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now().UTC()
	var retainedID string
	err = tx.QueryRow(ctx, `
		INSERT INTO yaounde_peers (peer_id, peer_kind, zone, endpoint_url, contact_channel, public_key, status, registered_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,'PENDING',$7,$8,$8)
		ON CONFLICT (peer_id) DO NOTHING
		RETURNING peer_id`,
		request.PeerID, request.PeerKind, nullable(request.Zone), nullable(request.EndpointURL),
		nullable(request.ContactChannel), nullableBytes(request.PublicKey), request.RegisteredBy, now).Scan(&retainedID)
	if errors.Is(err, pgx.ErrNoRows) {
		var retainedKind, retainedZone, retainedEndpoint, retainedContact, retainedBy string
		var retainedKey []byte
		if loadErr := tx.QueryRow(ctx, `
			SELECT peer_kind, COALESCE(zone,''), COALESCE(endpoint_url,''), COALESCE(contact_channel,''),
				COALESCE(public_key, ''::bytea), registered_by
			FROM yaounde_peers WHERE peer_id=$1`, request.PeerID).
			Scan(&retainedKind, &retainedZone, &retainedEndpoint, &retainedContact, &retainedKey, &retainedBy); loadErr != nil {
			return fmt.Errorf("load retained peer: %w", loadErr)
		}
		if retainedKind != request.PeerKind || retainedZone != request.Zone || retainedEndpoint != request.EndpointURL ||
			retainedContact != request.ContactChannel || !bytes.Equal(retainedKey, request.PublicKey) || retainedBy != request.RegisteredBy {
			return ErrConflict
		}
		return tx.Commit(ctx)
	}
	if err != nil {
		return fmt.Errorf("register peer: %w", err)
	}
	if _, err := appendAuditInTransaction(ctx, tx, AuditPeerRegistered, request.RegisteredBy, request.PeerID, map[string]any{
		"peer_kind": request.PeerKind, "zone": request.Zone,
		"endpoint_configured": request.EndpointURL != "", "has_public_key": len(request.PublicKey) == 32,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// PeerLifecycle applies activate/suspend/revoke under maker-checker control
// (activation requires a distinct principal from the registrar; the DB
// trigger enforces the same rule). Revocation is terminal.
func (store *Store) PeerLifecycle(ctx context.Context, peerID, action, actor string) (Peer, error) {
	if err := validIdentifier("peer_id", peerID); err != nil {
		return Peer{}, ErrNotFound
	}
	if err := validIdentifier("actor", actor); err != nil {
		return Peer{}, err
	}
	var next PeerStatus
	var auditType string
	switch action {
	case "activate":
		next, auditType = PeerActive, AuditPeerActivated
	case "suspend":
		next, auditType = PeerSuspended, AuditPeerSuspended
	case "revoke":
		next, auditType = PeerRevoked, AuditPeerRevoked
	default:
		return Peer{}, errors.New("peer lifecycle action must be activate, suspend or revoke")
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Peer{}, fmt.Errorf("begin peer lifecycle: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	peer, err := loadPeerForUpdate(ctx, tx, peerID)
	if err != nil {
		return Peer{}, err
	}
	switch next {
	case PeerActive:
		if peer.Status == PeerRevoked {
			return Peer{}, ErrInvalidTransition
		}
		if peer.RegisteredBy == actor {
			return Peer{}, ErrMakerChecker
		}
		if peer.Status == PeerActive {
			if peer.ActivatedBy != actor {
				return Peer{}, ErrConflict
			}
			return peer, tx.Commit(ctx) // idempotent replay
		}
		if peer.Status != PeerPending && peer.Status != PeerSuspended {
			return Peer{}, ErrInvalidTransition
		}
		if len(peer.publicKey) != 32 {
			return Peer{}, errors.New("peer activation requires a registered Ed25519 public key (signed inbound admission)")
		}
	case PeerSuspended:
		if peer.Status != PeerActive {
			return Peer{}, ErrInvalidTransition
		}
	case PeerRevoked:
		if peer.Status == PeerRevoked {
			return Peer{}, ErrInvalidTransition
		}
	}
	now := time.Now().UTC()
	var activatedBy any
	if next == PeerActive {
		activatedBy = actor
	} else {
		activatedBy = nullable(peer.ActivatedBy)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE yaounde_peers SET status=$2, activated_by=$3, updated_at=$4 WHERE peer_id=$1`,
		peerID, string(next), activatedBy, now); err != nil {
		return Peer{}, fmt.Errorf("update peer lifecycle: %w", err)
	}
	if _, err := appendAuditInTransaction(ctx, tx, auditType, actor, peerID, map[string]any{
		"prior_status": string(peer.Status), "status": string(next),
	}); err != nil {
		return Peer{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Peer{}, fmt.Errorf("commit peer lifecycle: %w", err)
	}
	peer.Status = next
	peer.UpdatedAt = now
	if next == PeerActive {
		peer.ActivatedBy = actor
	}
	return peer, nil
}

func loadPeerForUpdate(ctx context.Context, tx pgx.Tx, peerID string) (Peer, error) {
	var peer Peer
	var zone, endpoint, contact, activatedBy *string
	err := tx.QueryRow(ctx, `
		SELECT peer_id, peer_kind, zone, endpoint_url, contact_channel, public_key, status, registered_by, activated_by, created_at, updated_at
		FROM yaounde_peers WHERE peer_id=$1 FOR UPDATE`, peerID).
		Scan(&peer.PeerID, &peer.PeerKind, &zone, &endpoint, &contact, &peer.publicKey, &peer.Status,
			&peer.RegisteredBy, &activatedBy, &peer.CreatedAt, &peer.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Peer{}, ErrNotFound
	}
	if err != nil {
		return Peer{}, fmt.Errorf("load peer: %w", err)
	}
	peer.Zone = deref(zone)
	peer.EndpointURL = deref(endpoint)
	peer.ContactChannel = deref(contact)
	peer.ActivatedBy = deref(activatedBy)
	peer.HasPublicKey = len(peer.publicKey) == 32
	return peer, nil
}

// GetPeer returns one directory entry.
func (store *Store) GetPeer(ctx context.Context, peerID string) (Peer, error) {
	if err := validIdentifier("peer_id", peerID); err != nil {
		return Peer{}, ErrNotFound
	}
	rows := store.pool.QueryRow(ctx, `
		SELECT peer_id, peer_kind, COALESCE(zone,''), COALESCE(endpoint_url,''), COALESCE(contact_channel,''),
			(public_key IS NOT NULL), status, registered_by, COALESCE(activated_by,''), created_at, updated_at
		FROM yaounde_peers WHERE peer_id=$1`, peerID)
	var peer Peer
	err := rows.Scan(&peer.PeerID, &peer.PeerKind, &peer.Zone, &peer.EndpointURL, &peer.ContactChannel,
		&peer.HasPublicKey, &peer.Status, &peer.RegisteredBy, &peer.ActivatedBy, &peer.CreatedAt, &peer.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Peer{}, ErrNotFound
	}
	if err != nil {
		return Peer{}, fmt.Errorf("load peer: %w", err)
	}
	return peer, nil
}

// ListPeers returns the peer directory (honest status; endpoint_url is empty
// when unconfigured).
func (store *Store) ListPeers(ctx context.Context) ([]Peer, error) {
	rows, err := store.pool.Query(ctx, `
		SELECT peer_id, peer_kind, COALESCE(zone,''), COALESCE(endpoint_url,''), COALESCE(contact_channel,''),
			(public_key IS NOT NULL), status, registered_by, COALESCE(activated_by,''), created_at, updated_at
		FROM yaounde_peers ORDER BY peer_id`)
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	defer rows.Close()
	peers := make([]Peer, 0)
	for rows.Next() {
		var peer Peer
		if err := rows.Scan(&peer.PeerID, &peer.PeerKind, &peer.Zone, &peer.EndpointURL, &peer.ContactChannel,
			&peer.HasPublicKey, &peer.Status, &peer.RegisteredBy, &peer.ActivatedBy, &peer.CreatedAt, &peer.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan peer: %w", err)
		}
		peers = append(peers, peer)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate peers: %w", err)
	}
	return peers, nil
}

// loadPeerFull loads one peer including its key material (internal use).
func (store *Store) loadPeerFull(ctx context.Context, peerID string) (Peer, error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return Peer{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	peer, err := loadPeerForUpdate(ctx, tx, peerID)
	if err != nil {
		return Peer{}, err
	}
	return peer, tx.Commit(ctx)
}

// --- releases ------------------------------------------------------------

// ReleaseDraftRequest drafts one outbound incident-report release.
type ReleaseDraftRequest struct {
	ReleaseID       string `json:"release_id"` // optional; generated when empty
	IncidentID      string `json:"incident_id"`
	PeerID          string `json:"peer_id"`
	Marking         string `json:"marking"`
	Classification  string `json:"classification"`
	ExpectedVersion int64  `json:"expected_version"` // optimistic lock on maritime_incidents
	Narrative       string `json:"narrative"`        // operator-written, release-cleared, attributed
	// PositionEvidenceSHA256 optionally cites a retained spatial-correlation
	// evidence digest of the incident; the released position is the recorded
	// correlation coordinate, never invented at seal time.
	PositionEvidenceSHA256 string   `json:"position_evidence_sha256"`
	TrackDigests           []string `json:"track_digest_sha256"`
	ReleasedBy             string   `json:"-"` // verified principal
}

// releaseIncidentView is the adjudicated incident record a release draws
// from. Content is assembled strictly from retained platform records.
type releaseIncidentView struct {
	IncidentID string
	Category   string
	Severity   string
	OccurredAt time.Time
	Version    int64
}

// incidentReportPayload is the RegionalIncidentReport resource document
// (contracts camelCase JSON rendering).
type incidentReportPayload struct {
	ReleaseID            string   `json:"releaseId"`
	IncidentReference    string   `json:"incidentReference"`
	PeerReference        string   `json:"peerReference"`
	Marking              string   `json:"marking"`
	Classification       string   `json:"classification"`
	IncidentCategoryCode string   `json:"incidentCategoryCode"`
	SeverityLevel        string   `json:"severityLevel"`
	OccurredAt           string   `json:"occurredAt"`
	LatitudeMicros       *int64   `json:"latitudeMicros,omitempty"`
	LongitudeMicros      *int64   `json:"longitudeMicros,omitempty"`
	Narrative            string   `json:"narrative"`
	TrackDigestSHA256    []string `json:"trackDigestSha256"`
	ReportDigestSHA256   string   `json:"reportDigestSha256"`
}

// DraftRelease validates the release policy fail-closed, assembles the
// report strictly from the adjudicated incident record, seals it as an
// envelope v1.0 document and persists the DRAFT release with its audit entry
// and outbox transition atomically. Policy refusals are audited
// (release.refused) and never create a row.
func (store *Store) DraftRelease(ctx context.Context, request ReleaseDraftRequest) (Release, error) {
	marking, err := ParseMarking(request.Marking)
	if err != nil {
		return Release{}, err
	}
	classification, err := isr.ParseClassification(request.Classification)
	if err != nil {
		return Release{}, fmt.Errorf("%w: %v", ErrPolicyRefusal, err)
	}
	if err := validIdentifier("incident_id", request.IncidentID); err != nil {
		return Release{}, err
	}
	if err := validIdentifier("released_by", request.ReleasedBy); err != nil {
		return Release{}, err
	}
	if request.ExpectedVersion < 1 {
		return Release{}, errors.New("expected_version must be positive")
	}
	narrative := strings.TrimSpace(request.Narrative)
	if narrative == "" || len(narrative) > 4096 {
		return Release{}, errors.New("narrative must be operator-written release-cleared text of at most 4096 characters")
	}
	for _, digest := range request.TrackDigests {
		if !digestPattern.MatchString(digest) {
			return Release{}, errors.New("track digests must be sha256:<64 lowercase hex>")
		}
	}
	if len(request.TrackDigests) > 64 {
		return Release{}, errors.New("at most 64 track digests per release")
	}
	if request.PositionEvidenceSHA256 != "" && !digestPattern.MatchString(request.PositionEvidenceSHA256) {
		return Release{}, errors.New("position_evidence_sha256 must be sha256:<64 lowercase hex>")
	}
	releaseID := request.ReleaseID
	if releaseID == "" {
		releaseID = "ygr-" + uuid.NewString()
	}
	if err := validIdentifier("release_id", releaseID); err != nil {
		return Release{}, err
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Release{}, fmt.Errorf("begin release draft: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var incidentView releaseIncidentView
	err = tx.QueryRow(ctx, `
		SELECT incident_id, category, severity, occurred_at, version
		FROM maritime_incidents WHERE incident_id=$1 FOR SHARE`, request.IncidentID).
		Scan(&incidentView.IncidentID, &incidentView.Category, &incidentView.Severity, &incidentView.OccurredAt, &incidentView.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return Release{}, ErrNotFound
	}
	if err != nil {
		return Release{}, fmt.Errorf("load incident: %w", err)
	}
	if incidentView.Version != request.ExpectedVersion {
		return Release{}, ErrConflict
	}
	peer, err := loadPeerForUpdate(ctx, tx, request.PeerID)
	if err != nil {
		return Release{}, err
	}
	if peer.Status != PeerActive {
		return Release{}, ErrPeerNotActive
	}
	if err := CheckReleasePolicy(peer, marking, classification); err != nil {
		return Release{}, store.refuseRelease(ctx, tx, request.ReleasedBy, releaseID, err)
	}

	payload := incidentReportPayload{
		ReleaseID:            releaseID,
		IncidentReference:    incidentView.IncidentID,
		PeerReference:        peer.PeerID,
		Marking:              string(marking),
		Classification:       string(classification),
		IncidentCategoryCode: incidentView.Category,
		SeverityLevel:        incidentView.Severity,
		OccurredAt:           incidentView.OccurredAt.UTC().Format(time.RFC3339),
		Narrative:            narrative,
		TrackDigestSHA256:    request.TrackDigests,
	}
	if payload.TrackDigestSHA256 == nil {
		payload.TrackDigestSHA256 = []string{}
	}
	if request.PositionEvidenceSHA256 != "" {
		var latitude, longitude float64
		positionErr := tx.QueryRow(ctx, `
			SELECT latitude, longitude FROM maritime_incident_spatial_correlations
			WHERE incident_id=$1 AND evidence_sha256=$2`, request.IncidentID, request.PositionEvidenceSHA256).
			Scan(&latitude, &longitude)
		if errors.Is(positionErr, pgx.ErrNoRows) {
			return Release{}, fmt.Errorf("%w: position evidence digest cites no retained correlation of the incident", ErrPolicyRefusal)
		}
		if positionErr != nil {
			return Release{}, fmt.Errorf("load cited position evidence: %w", positionErr)
		}
		latitudeMicros := int64(latitude * 1e6)
		longitudeMicros := int64(longitude * 1e6)
		payload.LatitudeMicros = &latitudeMicros
		payload.LongitudeMicros = &longitudeMicros
	}
	// The report digest binds the payload content before the digest field
	// itself is populated.
	reportDigestInput, err := canonicalJSON(payload)
	if err != nil {
		return Release{}, err
	}
	payload.ReportDigestSHA256 = envelope.DigestSHA256(reportDigestInput)
	_, sealedBytes, err := envelope.Seal(store.signer, envelope.SealRequest{
		EventType:      envelope.EventYaoundeIncidentReport,
		AggregateKey:   releaseID,
		Classification: classification,
		OccurredAt:     time.Now().UTC(),
		PrincipalID:    request.ReleasedBy,
		PrincipalRole:  "yaounde-releaser",
		Resource:       payload,
	})
	if err != nil {
		return Release{}, err
	}
	now := time.Now().UTC()
	release := Release{
		ReleaseID: releaseID, IncidentID: incidentView.IncidentID, PeerID: peer.PeerID,
		Marking: marking, Classification: classification,
		ReportSHA256: payload.ReportDigestSHA256, EnvelopeJWS: string(sealedBytes),
		State: ReleaseDraft, ExpectedVersion: request.ExpectedVersion,
		ReleasedBy: request.ReleasedBy, CreatedAt: now, UpdatedAt: now, Version: 1,
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO yaounde_releases (release_id, incident_id, peer_id, marking, classification,
			report_sha256, envelope_jws, state, expected_version, released_by, created_at, updated_at, version)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'DRAFT',$8,$9,$10,$10,1)`,
		release.ReleaseID, release.IncidentID, release.PeerID, string(release.Marking),
		string(release.Classification), release.ReportSHA256, release.EnvelopeJWS,
		release.ExpectedVersion, release.ReleasedBy, now); err != nil {
		return Release{}, fmt.Errorf("insert release: %w", err)
	}
	if _, err := appendAuditInTransaction(ctx, tx, AuditReleaseDrafted, request.ReleasedBy, releaseID, map[string]any{
		"incident_id": release.IncidentID, "peer_id": release.PeerID,
		"marking": string(marking), "classification": string(classification),
		"report_sha256": release.ReportSHA256,
	}); err != nil {
		return Release{}, err
	}
	if err := store.emitReleaseTransition(ctx, tx, release, "", ReleaseDraft, "", now, request.ReleasedBy); err != nil {
		return Release{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Release{}, fmt.Errorf("commit release draft: %w", err)
	}
	return release, nil
}

// refuseRelease records an audited policy refusal and returns the refusal
// error. The audit entry commits in its own transaction so the refusal is
// durable even though no release row exists.
func (store *Store) refuseRelease(ctx context.Context, tx pgx.Tx, actor, subjectID string, refusal error) error {
	_ = tx.Rollback(ctx)
	if err := store.AppendAudit(ctx, AuditReleaseRefused, actor, subjectID, map[string]any{"reason": refusal.Error()}); err != nil {
		return fmt.Errorf("audit release refusal (%v): %w", refusal, err)
	}
	return refusal
}

// releaseTransitionedPayload is the YaoundeReleaseTransitioned resource.
type releaseTransitionedPayload struct {
	ReleaseID              string `json:"releaseId"`
	IncidentReference      string `json:"incidentReference"`
	PeerReference          string `json:"peerReference"`
	Marking                string `json:"marking"`
	PriorState             string `json:"priorState"`
	State                  string `json:"state"`
	TransitionReasonCode   string `json:"transitionReasonCode"`
	EnvelopeDigestSHA256   string `json:"envelopeDigestSha256"`
	AckReceiptDigestSHA256 string `json:"ackReceiptDigestSha256,omitempty"`
	TransitionedAt         string `json:"transitionedAt"`
}

// emitReleaseTransition seals and outboxes one release_transitioned event.
func (store *Store) emitReleaseTransition(ctx context.Context, tx pgx.Tx, release Release, prior, next ReleaseState, reasonCode string, at time.Time, actor string) error {
	payload := releaseTransitionedPayload{
		ReleaseID:              release.ReleaseID,
		IncidentReference:      release.IncidentID,
		PeerReference:          release.PeerID,
		Marking:                string(release.Marking),
		PriorState:             string(prior),
		State:                  string(next),
		TransitionReasonCode:   reasonCode,
		EnvelopeDigestSHA256:   envelope.DigestSHA256([]byte(release.EnvelopeJWS)),
		AckReceiptDigestSHA256: release.AckReceiptSHA256,
		TransitionedAt:         at.UTC().Format(time.RFC3339),
	}
	return store.emitEvent(ctx, tx, envelope.EventYaoundeReleaseTransitioned, release.ReleaseID, release.Classification, at, actor, "yaounde-producer", payload)
}

// emitEvent seals one contract envelope and appends it to the yaounde
// outbox inside tx.
func (store *Store) emitEvent(ctx context.Context, tx pgx.Tx, eventType, aggregateKey string, classification isr.Classification, at time.Time, principalID, principalRole string, resource any) error {
	sealed, sealedBytes, err := envelope.Seal(store.signer, envelope.SealRequest{
		EventType:      eventType,
		AggregateKey:   aggregateKey,
		Classification: classification,
		OccurredAt:     at,
		PrincipalID:    principalID,
		PrincipalRole:  principalRole,
		Resource:       resource,
	})
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO yaounde_outbox (event_id, topic, event_type, classification, aggregate_key, payload, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		uuid.New(), sealed.Topic, sealed.EventType, string(classification), aggregateKey, sealedBytes, at.UTC()); err != nil {
		return fmt.Errorf("write yaounde outbox event: %w", err)
	}
	return nil
}

func (store *Store) loadReleaseForUpdate(ctx context.Context, tx pgx.Tx, releaseID string) (Release, error) {
	var release Release
	var releasedBy, approvedBy, ackDigest *string
	err := tx.QueryRow(ctx, `
		SELECT release_id, incident_id, peer_id, marking, classification, report_sha256, envelope_jws,
			state, expected_version, released_by, approved_by, dispatched_at, acked_at, ack_receipt_sha256,
			created_at, updated_at, version
		FROM yaounde_releases WHERE release_id=$1 FOR UPDATE`, releaseID).
		Scan(&release.ReleaseID, &release.IncidentID, &release.PeerID, &release.Marking, &release.Classification,
			&release.ReportSHA256, &release.EnvelopeJWS, &release.State, &release.ExpectedVersion,
			&releasedBy, &approvedBy, &release.DispatchedAt, &release.AckedAt, &ackDigest,
			&release.CreatedAt, &release.UpdatedAt, &release.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return Release{}, ErrNotFound
	}
	if err != nil {
		return Release{}, fmt.Errorf("load release: %w", err)
	}
	release.ReleasedBy = deref(releasedBy)
	release.ApprovedBy = deref(approvedBy)
	release.AckReceiptSHA256 = deref(ackDigest)
	return release, nil
}

// GetRelease returns one release.
func (store *Store) GetRelease(ctx context.Context, releaseID string) (Release, error) {
	return store.loadRelease(ctx, releaseID)
}

func (store *Store) loadRelease(ctx context.Context, releaseID string) (Release, error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return Release{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	release, err := store.loadReleaseForUpdate(ctx, tx, releaseID)
	if err != nil {
		return Release{}, err
	}
	return release, tx.Commit(ctx)
}

// ListReleases returns releases, optionally filtered by state.
func (store *Store) ListReleases(ctx context.Context, state string) ([]Release, error) {
	if state != "" {
		switch ReleaseState(state) {
		case ReleaseDraft, ReleaseApproved, ReleaseDispatched, ReleaseAcknowledged, ReleaseFailed, ReleaseWithdrawn:
		default:
			return nil, errors.New("state filter must be a valid release state")
		}
	}
	query := `SELECT release_id, incident_id, peer_id, marking, classification, report_sha256, envelope_jws,
		state, expected_version, COALESCE(released_by,''), COALESCE(approved_by,''), dispatched_at, acked_at,
		COALESCE(ack_receipt_sha256,''), created_at, updated_at, version
		FROM yaounde_releases`
	var args []any
	if state != "" {
		args = append(args, state)
		query += " WHERE state=$1"
	}
	query += " ORDER BY created_at DESC, release_id"
	rows, err := store.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list releases: %w", err)
	}
	defer rows.Close()
	releases := make([]Release, 0)
	for rows.Next() {
		var release Release
		if err := rows.Scan(&release.ReleaseID, &release.IncidentID, &release.PeerID, &release.Marking,
			&release.Classification, &release.ReportSHA256, &release.EnvelopeJWS, &release.State,
			&release.ExpectedVersion, &release.ReleasedBy, &release.ApprovedBy, &release.DispatchedAt,
			&release.AckedAt, &release.AckReceiptSHA256, &release.CreatedAt, &release.UpdatedAt, &release.Version); err != nil {
			return nil, fmt.Errorf("scan release: %w", err)
		}
		releases = append(releases, release)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate releases: %w", err)
	}
	return releases, nil
}

// transitionRelease applies one validated release transition with optimistic
// locking, audit and outbox emission atomically.
func (store *Store) transitionRelease(ctx context.Context, releaseID string, expectedVersion int64, next ReleaseState, actor, reasonCode string, mutate func(release *Release)) (Release, error) {
	if expectedVersion < 1 {
		return Release{}, errors.New("expected_version must be positive")
	}
	if err := validIdentifier("actor", actor); err != nil {
		return Release{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Release{}, fmt.Errorf("begin release transition: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	release, err := store.loadReleaseForUpdate(ctx, tx, releaseID)
	if err != nil {
		return Release{}, err
	}
	if release.Version != expectedVersion {
		return Release{}, ErrConflict
	}
	if !ValidReleaseTransition(release.State, next) {
		return Release{}, ErrInvalidTransition
	}
	prior := release.State
	if mutate != nil {
		mutate(&release)
	}
	now := time.Now().UTC()
	release.State = next
	release.UpdatedAt = now
	if _, err := tx.Exec(ctx, `
		UPDATE yaounde_releases SET state=$2, approved_by=$3, dispatched_at=$4, acked_at=$5,
			ack_receipt_sha256=$6, updated_at=$7, version=version+1
		WHERE release_id=$1 AND version=$8`,
		release.ReleaseID, string(next), nullable(release.ApprovedBy), release.DispatchedAt, release.AckedAt,
		nullable(release.AckReceiptSHA256), now, expectedVersion); err != nil {
		return Release{}, fmt.Errorf("update release: %w", err)
	}
	auditTypeByState := map[ReleaseState]string{
		ReleaseApproved: AuditReleaseApproved, ReleaseDispatched: AuditReleaseDispatched,
		ReleaseAcknowledged: AuditReleaseAcknowledged, ReleaseFailed: AuditReleaseFailed,
		ReleaseWithdrawn: AuditReleaseWithdrawn,
	}
	detail := map[string]any{"prior_state": string(prior), "state": string(next)}
	if reasonCode != "" {
		detail["reason_code"] = reasonCode
	}
	if _, err := appendAuditInTransaction(ctx, tx, auditTypeByState[next], actor, release.ReleaseID, detail); err != nil {
		return Release{}, err
	}
	if err := store.emitReleaseTransition(ctx, tx, release, prior, next, reasonCode, now, actor); err != nil {
		return Release{}, err
	}
	if next == ReleaseApproved {
		// Approving publishes the sealed incident-report artifact itself.
		if _, err := tx.Exec(ctx, `
			INSERT INTO yaounde_outbox (event_id, topic, event_type, classification, aggregate_key, payload, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			uuid.New(), envelope.TopicYaounde, envelope.EventYaoundeIncidentReport, string(release.Classification),
			release.ReleaseID, []byte(release.EnvelopeJWS), now); err != nil {
			return Release{}, fmt.Errorf("write incident report outbox event: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Release{}, fmt.Errorf("commit release transition: %w", err)
	}
	release.Version = expectedVersion + 1
	return release, nil
}

// ApproveRelease applies the maker-checker approval: the approver must
// differ from the releasing principal. The envelope was sealed at draft time
// (report content is immutable thereafter); approval publishes it.
func (store *Store) ApproveRelease(ctx context.Context, releaseID string, expectedVersion int64, approver string) (Release, error) {
	release, err := store.loadRelease(ctx, releaseID)
	if err != nil {
		return Release{}, err
	}
	if release.ReleasedBy == approver {
		return Release{}, ErrMakerChecker
	}
	return store.transitionRelease(ctx, releaseID, expectedVersion, ReleaseApproved, approver, "", func(release *Release) {
		release.ApprovedBy = approver
	})
}

// DispatchRelease marks an APPROVED release DISPATCHED for delivery. It
// fails closed when the peer has no configured endpoint (state stays
// APPROVED and the refusal is audited) or the peer is not ACTIVE. Retry of a
// FAILED release is explicit through the same route.
func (store *Store) DispatchRelease(ctx context.Context, releaseID string, expectedVersion int64, actor string) (Release, error) {
	release, err := store.loadRelease(ctx, releaseID)
	if err != nil {
		return Release{}, err
	}
	peer, err := store.loadPeerFull(ctx, release.PeerID)
	if err != nil {
		return Release{}, err
	}
	if peer.Status != PeerActive {
		return Release{}, ErrPeerNotActive
	}
	if !peer.Configured() {
		if err := store.AppendAudit(ctx, AuditReleaseRefused, actor, releaseID, map[string]any{
			"reason": ErrPeerNotConfigured.Error(), "peer_id": peer.PeerID,
		}); err != nil {
			return Release{}, fmt.Errorf("audit dispatch refusal: %w", err)
		}
		return Release{}, ErrPeerNotConfigured
	}
	now := time.Now().UTC()
	return store.transitionRelease(ctx, releaseID, expectedVersion, ReleaseDispatched, actor, "", func(release *Release) {
		release.DispatchedAt = &now
	})
}

// WithdrawRelease withdraws a DRAFT or APPROVED release (terminal).
func (store *Store) WithdrawRelease(ctx context.Context, releaseID string, expectedVersion int64, actor, reasonCode string) (Release, error) {
	if reasonCode == "" {
		return Release{}, errors.New("withdrawal requires a reason code")
	}
	return store.transitionRelease(ctx, releaseID, expectedVersion, ReleaseWithdrawn, actor, reasonCode, nil)
}

// FailDelivery records a failed delivery (retryable-explicit). Called by the
// delivery worker after a verifiable delivery failure; never fabricated.
func (store *Store) FailDelivery(ctx context.Context, releaseID string, expectedVersion int64, reasonCode string) (Release, error) {
	if reasonCode == "" {
		return Release{}, errors.New("delivery failure requires a reason code")
	}
	return store.transitionRelease(ctx, releaseID, expectedVersion, ReleaseFailed, "yaounde-publisher", reasonCode, nil)
}

// AckReceiptPreimage is the canonical signing preimage a peer signs to
// acknowledge a release: "yaounde-ack-v1\n<release_id>\n<report_sha256>".
func AckReceiptPreimage(releaseID, reportSHA256 string) []byte {
	return []byte("yaounde-ack-v1\n" + releaseID + "\n" + reportSHA256)
}

// RecordAcknowledgement verifies the peer-signed ack receipt against the
// registered peer key and transitions DISPATCHED→ACKNOWLEDGED. An
// acknowledgement is never asserted without a verifiable receipt.
func (store *Store) RecordAcknowledgement(ctx context.Context, releaseID string, expectedVersion int64, receiptSignature []byte) (Release, error) {
	if len(receiptSignature) != ed25519.SignatureSize {
		return Release{}, ErrSignatureInvalid
	}
	release, err := store.loadRelease(ctx, releaseID)
	if err != nil {
		return Release{}, err
	}
	peer, err := store.loadPeerFull(ctx, release.PeerID)
	if err != nil {
		return Release{}, err
	}
	if len(peer.publicKey) != 32 {
		return Release{}, ErrSignatureInvalid
	}
	if !ed25519.Verify(ed25519.PublicKey(peer.publicKey), AckReceiptPreimage(release.ReleaseID, release.ReportSHA256), receiptSignature) {
		return Release{}, ErrSignatureInvalid
	}
	receiptDigest := envelope.DigestSHA256(receiptSignature)
	now := time.Now().UTC()
	return store.transitionRelease(ctx, releaseID, expectedVersion, ReleaseAcknowledged, "peer:"+peer.PeerID, "", func(release *Release) {
		release.AckReceiptSHA256 = receiptDigest
		release.AckedAt = &now
	})
}

// --- inbound reports ------------------------------------------------------

// InboundAdmissionRequest admits one peer-originated report.
type InboundAdmissionRequest struct {
	ReportID       string `json:"report_id"` // optional; generated when empty
	PeerID         string `json:"peer_id"`
	PeerReportRef  string `json:"peer_report_ref"`
	Classification string `json:"classification"`
	Marking        string `json:"marking"`
	Payload        []byte `json:"-"`
	Signature      []byte `json:"-"`
}

// InboundSigningPreimage is the canonical peer signing preimage for inbound
// reports: "yaounde-inbound-v1\n<peer_id>\n<peer_report_ref>\nsha256:<hex>".
func InboundSigningPreimage(peerID, peerReportRef string, payload []byte) []byte {
	return []byte("yaounde-inbound-v1\n" + peerID + "\n" + peerReportRef + "\n" + envelope.DigestSHA256(payload))
}

// AdmitInbound verifies the peer Ed25519 signature over the payload against
// the registered peer key and retains the payload verbatim. Admission is
// replay-safe on (peer_id, peer_report_ref): identical replay returns the
// retained evidence; conflicting reuse fails closed. Rejections are audited.
func (store *Store) AdmitInbound(ctx context.Context, request InboundAdmissionRequest) (InboundReport, error) {
	if err := validIdentifier("peer_id", request.PeerID); err != nil {
		return InboundReport{}, err
	}
	if strings.TrimSpace(request.PeerReportRef) != request.PeerReportRef || request.PeerReportRef == "" || len(request.PeerReportRef) > 256 {
		return InboundReport{}, errors.New("peer_report_ref must be canonical text of at most 256 characters")
	}
	classification, err := isr.ParseClassification(request.Classification)
	if err != nil {
		return InboundReport{}, err
	}
	marking, err := ParseMarking(request.Marking)
	if err != nil {
		return InboundReport{}, err
	}
	if len(request.Payload) == 0 || len(request.Payload) > 1<<20 {
		return InboundReport{}, errors.New("payload must be between 1 byte and 1 MiB")
	}
	if !json.Valid(request.Payload) {
		return InboundReport{}, errors.New("payload must be a JSON document")
	}
	if len(request.Signature) != ed25519.SignatureSize {
		return InboundReport{}, ErrSignatureInvalid
	}
	reportID := request.ReportID
	if reportID == "" {
		reportID = "ygi-" + uuid.NewString()
	}
	if err := validIdentifier("report_id", reportID); err != nil {
		return InboundReport{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return InboundReport{}, fmt.Errorf("begin inbound admission: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	peer, err := loadPeerForUpdate(ctx, tx, request.PeerID)
	if err != nil {
		return InboundReport{}, store.rejectInbound(ctx, tx, request.PeerID, request.PeerReportRef, "peer-unknown", ErrNotFound)
	}
	if peer.Status != PeerActive {
		return InboundReport{}, store.rejectInbound(ctx, tx, request.PeerID, request.PeerReportRef, "peer-not-active", ErrPeerNotActive)
	}
	if len(peer.publicKey) != 32 ||
		!ed25519.Verify(ed25519.PublicKey(peer.publicKey), InboundSigningPreimage(request.PeerID, request.PeerReportRef, request.Payload), request.Signature) {
		return InboundReport{}, store.rejectInbound(ctx, tx, request.PeerID, request.PeerReportRef, "signature-invalid", ErrSignatureInvalid)
	}
	payloadSHA256 := envelope.DigestSHA256(request.Payload)
	receivedAt := time.Now().UTC()
	report := InboundReport{
		ReportID: reportID, PeerID: peer.PeerID, PeerReportRef: request.PeerReportRef,
		Classification: classification, Marking: marking, Payload: request.Payload,
		PayloadSHA256: payloadSHA256, Signature: request.Signature,
		Adjudication: AdjudicationPending, ReceivedAt: receivedAt,
	}
	var retainedID string
	err = tx.QueryRow(ctx, `
		INSERT INTO yaounde_inbound_reports (report_id, peer_id, peer_report_ref, classification, marking,
			payload, payload_sha256, signature, adjudication, received_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'PENDING',$9)
		ON CONFLICT (peer_id, peer_report_ref) DO NOTHING
		RETURNING report_id`,
		reportID, peer.PeerID, request.PeerReportRef, string(classification), string(marking),
		request.Payload, payloadSHA256, request.Signature, receivedAt).Scan(&retainedID)
	if errors.Is(err, pgx.ErrNoRows) {
		var retained InboundReport
		if loadErr := tx.QueryRow(ctx, `
			SELECT report_id, payload_sha256, signature, adjudication, COALESCE(incident_id,''), received_at
			FROM yaounde_inbound_reports WHERE peer_id=$1 AND peer_report_ref=$2 FOR UPDATE`,
			peer.PeerID, request.PeerReportRef).
			Scan(&retained.ReportID, &retained.PayloadSHA256, &retained.Signature, &retained.Adjudication, &retained.IncidentID, &retained.ReceivedAt); loadErr != nil {
			return InboundReport{}, fmt.Errorf("load retained inbound report: %w", loadErr)
		}
		if retained.PayloadSHA256 != payloadSHA256 || !bytes.Equal(retained.Signature, request.Signature) {
			return InboundReport{}, store.rejectInbound(ctx, tx, request.PeerID, request.PeerReportRef, "conflicting-replay", ErrConflict)
		}
		retained.PeerID = peer.PeerID
		retained.PeerReportRef = request.PeerReportRef
		retained.Classification = classification
		retained.Marking = marking
		if err := tx.Commit(ctx); err != nil {
			return InboundReport{}, fmt.Errorf("commit inbound replay: %w", err)
		}
		return retained, nil
	}
	if err != nil {
		return InboundReport{}, fmt.Errorf("record inbound report: %w", err)
	}
	if _, err := appendAuditInTransaction(ctx, tx, AuditInboundAdmitted, "peer:"+peer.PeerID, reportID, map[string]any{
		"peer_id": peer.PeerID, "peer_report_ref": request.PeerReportRef,
		"classification": string(classification), "marking": string(marking),
		"payload_sha256": payloadSHA256,
	}); err != nil {
		return InboundReport{}, err
	}
	payload := map[string]any{
		"reportId": reportID, "peerReference": peer.PeerID, "peerKind": string(peer.PeerKind),
		"peerReportReference": request.PeerReportRef, "classification": string(classification),
		"marking": string(marking), "payloadDigestSha256": payloadSHA256,
		"signatureDigestSha256": envelope.DigestSHA256(request.Signature),
		"adjudication":          string(AdjudicationPending), "receivedAt": receivedAt.Format(time.RFC3339),
	}
	if err := store.emitEvent(ctx, tx, envelope.EventYaoundeInboundAdmitted, reportID, classification, receivedAt, "peer:"+peer.PeerID, "yaounde-gateway", payload); err != nil {
		return InboundReport{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return InboundReport{}, fmt.Errorf("commit inbound admission: %w", err)
	}
	return report, nil
}

// rejectInbound audits a rejected inbound admission in its own transaction
// and returns the rejection error.
func (store *Store) rejectInbound(ctx context.Context, tx pgx.Tx, peerID, peerReportRef, reason string, rejection error) error {
	_ = tx.Rollback(ctx)
	if err := store.AppendAudit(ctx, AuditInboundRejected, "peer:"+peerID, peerID+":"+peerReportRef, map[string]any{"reason": reason}); err != nil {
		return fmt.Errorf("audit inbound rejection (%v): %w", rejection, err)
	}
	return rejection
}

// CorrelateInbound correlates a PENDING inbound report to a maritime
// incident (analyst adjudication). The inbound item never overwrites the
// national record; the link is one-directional evidence.
func (store *Store) CorrelateInbound(ctx context.Context, reportID, incidentID, actor string) (InboundReport, error) {
	return store.adjudicateInbound(ctx, reportID, incidentID, AdjudicationCorrelated, actor)
}

// RejectInbound marks a PENDING inbound report REJECTED.
func (store *Store) RejectInbound(ctx context.Context, reportID, actor string) (InboundReport, error) {
	return store.adjudicateInbound(ctx, reportID, "", AdjudicationRejected, actor)
}

func (store *Store) adjudicateInbound(ctx context.Context, reportID, incidentID string, adjudication Adjudication, actor string) (InboundReport, error) {
	if err := validIdentifier("actor", actor); err != nil {
		return InboundReport{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return InboundReport{}, fmt.Errorf("begin inbound adjudication: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var report InboundReport
	err = tx.QueryRow(ctx, `
		SELECT report_id, peer_id, peer_report_ref, classification, marking, payload_sha256, adjudication,
			COALESCE(incident_id,''), received_at
		FROM yaounde_inbound_reports WHERE report_id=$1 FOR UPDATE`, reportID).
		Scan(&report.ReportID, &report.PeerID, &report.PeerReportRef, &report.Classification, &report.Marking,
			&report.PayloadSHA256, &report.Adjudication, &report.IncidentID, &report.ReceivedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return InboundReport{}, ErrNotFound
	}
	if err != nil {
		return InboundReport{}, fmt.Errorf("load inbound report: %w", err)
	}
	if report.Adjudication != AdjudicationPending {
		return InboundReport{}, ErrInvalidTransition
	}
	if adjudication == AdjudicationCorrelated {
		if err := validIdentifier("incident_id", incidentID); err != nil {
			return InboundReport{}, err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM maritime_incidents WHERE incident_id=$1)`, incidentID).Scan(&exists); err != nil {
			return InboundReport{}, fmt.Errorf("check incident: %w", err)
		}
		if !exists {
			return InboundReport{}, ErrNotFound
		}
	}
	if _, err := tx.Exec(ctx, `
		UPDATE yaounde_inbound_reports SET adjudication=$2, incident_id=$3 WHERE report_id=$1`,
		reportID, string(adjudication), nullable(incidentID)); err != nil {
		return InboundReport{}, fmt.Errorf("adjudicate inbound report: %w", err)
	}
	if _, err := appendAuditInTransaction(ctx, tx, AuditInboundAdmitted, actor, reportID, map[string]any{
		"adjudication": string(adjudication), "incident_id": incidentID,
	}); err != nil {
		return InboundReport{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return InboundReport{}, fmt.Errorf("commit inbound adjudication: %w", err)
	}
	report.Adjudication = adjudication
	report.IncidentID = incidentID
	return report, nil
}

// --- picture contributions -------------------------------------------------

// PicturePrepareRequest prepares one shared-picture contribution.
type PicturePrepareRequest struct {
	ContributionID string    `json:"contribution_id"` // optional; generated when empty
	PeerID         string    `json:"peer_id"`
	ZoneID         string    `json:"zone_id"`
	Zone           geo.Zone  `json:"-"` // resolved zone polygon (never from the request body)
	WindowStart    time.Time `json:"window_start"`
	WindowEnd      time.Time `json:"window_end"`
	Ceiling        string    `json:"classification_ceiling"`
	CreatedBy      string    `json:"-"`
}

// PreparePicture filters the national picture by zone and ceiling, digests
// the canonical artifact and persists a PREPARED contribution with its audit
// entry and outbox event atomically.
func (store *Store) PreparePicture(ctx context.Context, request PicturePrepareRequest) (PictureContribution, error) {
	if store.tracks == nil {
		return PictureContribution{}, errors.New("track source is not configured (fail-closed)")
	}
	if err := validIdentifier("peer_id", request.PeerID); err != nil {
		return PictureContribution{}, err
	}
	if err := validIdentifier("created_by", request.CreatedBy); err != nil {
		return PictureContribution{}, err
	}
	ceiling, err := isr.ParseClassification(request.Ceiling)
	if err != nil {
		return PictureContribution{}, err
	}
	contributionID := request.ContributionID
	if contributionID == "" {
		contributionID = "ygp-" + uuid.NewString()
	}
	if err := validIdentifier("contribution_id", contributionID); err != nil {
		return PictureContribution{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return PictureContribution{}, fmt.Errorf("begin picture prepare: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	peer, err := loadPeerForUpdate(ctx, tx, request.PeerID)
	if err != nil {
		return PictureContribution{}, err
	}
	if peer.Status != PeerActive {
		return PictureContribution{}, ErrPeerNotActive
	}
	// The ceiling may never exceed what the peer may receive.
	peerCeiling := ClassificationCeiling(peer)
	if ceiling.Rank() > peerCeiling.Rank() {
		return PictureContribution{}, fmt.Errorf("%w: picture ceiling %s exceeds the %s peer ceiling %s", ErrPolicyRefusal, ceiling, peer.PeerKind, peerCeiling)
	}
	sourced, err := store.tracks.LatestPositions(ctx, request.WindowStart, request.WindowEnd)
	if err != nil {
		return PictureContribution{}, fmt.Errorf("source track picture: %w", err)
	}
	artifact, _, digest, err := BuildPictureArtifact(request.ZoneID, request.Zone, request.WindowStart, request.WindowEnd, ceiling, sourced)
	if err != nil {
		return PictureContribution{}, err
	}
	now := time.Now().UTC()
	contribution := PictureContribution{
		ContributionID: contributionID, PeerID: peer.PeerID, Zone: request.ZoneID,
		WindowStart: request.WindowStart.UTC(), WindowEnd: request.WindowEnd.UTC(),
		TrackCount: len(artifact.Tracks), ClassificationCeiling: ceiling,
		DigestSHA256: digest, State: PicturePrepared,
		CreatedBy: request.CreatedBy, CreatedAt: now, UpdatedAt: now,
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO yaounde_picture_contributions (contribution_id, peer_id, zone, track_window, track_count,
			classification_ceiling, digest_sha256, state, created_by, created_at, updated_at)
		VALUES ($1,$2,$3,tstzrange($4,$5,'[)'),$6,$7,$8,'PREPARED',$9,$10,$10)`,
		contribution.ContributionID, contribution.PeerID, contribution.Zone, contribution.WindowStart,
		contribution.WindowEnd, contribution.TrackCount, string(ceiling), digest, contribution.CreatedBy, now); err != nil {
		return PictureContribution{}, fmt.Errorf("insert picture contribution: %w", err)
	}
	if _, err := appendAuditInTransaction(ctx, tx, AuditPicturePrepared, request.CreatedBy, contributionID, map[string]any{
		"peer_id": peer.PeerID, "zone": request.ZoneID, "track_count": contribution.TrackCount,
		"classification_ceiling": string(ceiling), "digest_sha256": digest,
	}); err != nil {
		return PictureContribution{}, err
	}
	if err := store.emitPictureTransition(ctx, tx, contribution, "", PicturePrepared, "", now, request.CreatedBy); err != nil {
		return PictureContribution{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PictureContribution{}, fmt.Errorf("commit picture prepare: %w", err)
	}
	return contribution, nil
}

// pictureTransitionedPayload is the YaoundePictureContributionTransitioned
// resource.
type pictureTransitionedPayload struct {
	ContributionID           string `json:"contributionId"`
	PeerReference            string `json:"peerReference"`
	Zone                     string `json:"zone"`
	PriorState               string `json:"priorState"`
	State                    string `json:"state"`
	ClassificationCeiling    string `json:"classificationCeiling"`
	TrackCount               int    `json:"trackCount"`
	WindowStart              string `json:"windowStart"`
	WindowEnd                string `json:"windowEnd"`
	ContributionDigestSHA256 string `json:"contributionDigestSha256"`
	TransitionReasonCode     string `json:"transitionReasonCode"`
	TransitionedAt           string `json:"transitionedAt"`
}

func (store *Store) emitPictureTransition(ctx context.Context, tx pgx.Tx, contribution PictureContribution, prior, next PictureState, reasonCode string, at time.Time, actor string) error {
	payload := pictureTransitionedPayload{
		ContributionID: contribution.ContributionID, PeerReference: contribution.PeerID,
		Zone: contribution.Zone, PriorState: string(prior), State: string(next),
		ClassificationCeiling:    string(contribution.ClassificationCeiling),
		TrackCount:               contribution.TrackCount,
		WindowStart:              contribution.WindowStart.UTC().Format(time.RFC3339),
		WindowEnd:                contribution.WindowEnd.UTC().Format(time.RFC3339),
		ContributionDigestSHA256: contribution.DigestSHA256,
		TransitionReasonCode:     reasonCode,
		TransitionedAt:           at.UTC().Format(time.RFC3339),
	}
	return store.emitEvent(ctx, tx, envelope.EventYaoundePictureTransitioned, contribution.ContributionID, contribution.ClassificationCeiling, at, actor, "yaounde-producer", payload)
}

func (store *Store) loadPictureForUpdate(ctx context.Context, tx pgx.Tx, contributionID string) (PictureContribution, error) {
	var contribution PictureContribution
	var approvedBy *string
	err := tx.QueryRow(ctx, `
		SELECT contribution_id, peer_id, zone, lower(track_window), upper(track_window), track_count,
			classification_ceiling, digest_sha256, state, created_by, approved_by, created_at, updated_at
		FROM yaounde_picture_contributions WHERE contribution_id=$1 FOR UPDATE`, contributionID).
		Scan(&contribution.ContributionID, &contribution.PeerID, &contribution.Zone, &contribution.WindowStart,
			&contribution.WindowEnd, &contribution.TrackCount, &contribution.ClassificationCeiling,
			&contribution.DigestSHA256, &contribution.State, &contribution.CreatedBy, &approvedBy,
			&contribution.CreatedAt, &contribution.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return PictureContribution{}, ErrNotFound
	}
	if err != nil {
		return PictureContribution{}, fmt.Errorf("load picture contribution: %w", err)
	}
	contribution.ApprovedBy = deref(approvedBy)
	return contribution, nil
}

// ApprovePicture applies the maker-checker approval (approver ≠ creator).
func (store *Store) ApprovePicture(ctx context.Context, contributionID, approver string) (PictureContribution, error) {
	if err := validIdentifier("actor", approver); err != nil {
		return PictureContribution{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return PictureContribution{}, fmt.Errorf("begin picture approval: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	contribution, err := store.loadPictureForUpdate(ctx, tx, contributionID)
	if err != nil {
		return PictureContribution{}, err
	}
	if contribution.CreatedBy == approver {
		return PictureContribution{}, ErrMakerChecker
	}
	if !ValidPictureTransition(contribution.State, PictureApproved) {
		return PictureContribution{}, ErrInvalidTransition
	}
	prior := contribution.State
	now := time.Now().UTC()
	if _, err := tx.Exec(ctx, `
		UPDATE yaounde_picture_contributions SET state='APPROVED', approved_by=$2, updated_at=$3 WHERE contribution_id=$1`,
		contributionID, approver, now); err != nil {
		return PictureContribution{}, fmt.Errorf("approve picture contribution: %w", err)
	}
	contribution.State = PictureApproved
	contribution.ApprovedBy = approver
	contribution.UpdatedAt = now
	if err := store.emitPictureTransition(ctx, tx, contribution, prior, PictureApproved, "", now, approver); err != nil {
		return PictureContribution{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PictureContribution{}, fmt.Errorf("commit picture approval: %w", err)
	}
	return contribution, nil
}

// DispatchPicture re-applies the zone and ceiling filter at dispatch time —
// tracks that gained a higher classification since preparation are excluded —
// binds the contribution digest to the exact dispatched set, and marks the
// contribution DISPATCHED. It fails closed when the peer has no configured
// endpoint (state unchanged, audited) and returns the canonical artifact for
// delivery.
func (store *Store) DispatchPicture(ctx context.Context, contributionID, actor string, zone geo.Zone) (PictureContribution, []byte, error) {
	if store.tracks == nil {
		return PictureContribution{}, nil, errors.New("track source is not configured (fail-closed)")
	}
	if err := validIdentifier("actor", actor); err != nil {
		return PictureContribution{}, nil, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return PictureContribution{}, nil, fmt.Errorf("begin picture dispatch: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	contribution, err := store.loadPictureForUpdate(ctx, tx, contributionID)
	if err != nil {
		return PictureContribution{}, nil, err
	}
	if contribution.State != PictureApproved && contribution.State != PictureFailed {
		return PictureContribution{}, nil, ErrInvalidTransition
	}
	peer, err := loadPeerForUpdate(ctx, tx, contribution.PeerID)
	if err != nil {
		return PictureContribution{}, nil, err
	}
	if peer.Status != PeerActive {
		return PictureContribution{}, nil, ErrPeerNotActive
	}
	if !peer.Configured() {
		_ = tx.Rollback(ctx)
		if auditErr := store.AppendAudit(ctx, AuditPictureFailed, actor, contributionID, map[string]any{
			"reason": ErrPeerNotConfigured.Error(), "peer_id": peer.PeerID,
		}); auditErr != nil {
			return PictureContribution{}, nil, fmt.Errorf("audit picture dispatch refusal: %w", auditErr)
		}
		return PictureContribution{}, nil, ErrPeerNotConfigured
	}
	// Re-filter at dispatch: the ceiling is enforced against current track
	// classifications, not the prepared snapshot.
	sourced, err := store.tracks.LatestPositions(ctx, contribution.WindowStart, contribution.WindowEnd)
	if err != nil {
		return PictureContribution{}, nil, fmt.Errorf("re-source track picture at dispatch: %w", err)
	}
	artifact, canonical, digest, err := BuildPictureArtifact(contribution.Zone, zone, contribution.WindowStart, contribution.WindowEnd, contribution.ClassificationCeiling, sourced)
	if err != nil {
		return PictureContribution{}, nil, err
	}
	prior := contribution.State
	now := time.Now().UTC()
	preparedDigest := contribution.DigestSHA256
	contribution.DigestSHA256 = digest
	contribution.TrackCount = len(artifact.Tracks)
	if _, err := tx.Exec(ctx, `
		UPDATE yaounde_picture_contributions SET state='DISPATCHED', digest_sha256=$2, track_count=$3, updated_at=$4
		WHERE contribution_id=$1`, contributionID, digest, contribution.TrackCount, now); err != nil {
		return PictureContribution{}, nil, fmt.Errorf("dispatch picture contribution: %w", err)
	}
	contribution.State = PictureDispatched
	contribution.UpdatedAt = now
	if _, err := appendAuditInTransaction(ctx, tx, AuditPictureDispatched, actor, contributionID, map[string]any{
		"peer_id": peer.PeerID, "prepared_digest_sha256": preparedDigest,
		"dispatched_digest_sha256": digest, "track_count": contribution.TrackCount,
		"refiltered": preparedDigest != digest,
	}); err != nil {
		return PictureContribution{}, nil, err
	}
	if err := store.emitPictureTransition(ctx, tx, contribution, prior, PictureDispatched, "", now, actor); err != nil {
		return PictureContribution{}, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PictureContribution{}, nil, fmt.Errorf("commit picture dispatch: %w", err)
	}
	return contribution, canonical, nil
}

// --- helpers ---------------------------------------------------------------

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// GetPicture returns one picture contribution.
func (store *Store) GetPicture(ctx context.Context, contributionID string) (PictureContribution, error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return PictureContribution{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	contribution, err := store.loadPictureForUpdate(ctx, tx, contributionID)
	if err != nil {
		return PictureContribution{}, err
	}
	return contribution, tx.Commit(ctx)
}

// ListPicture returns the picture contributions, newest first.
func (store *Store) ListPicture(ctx context.Context) ([]PictureContribution, error) {
	rows, err := store.pool.Query(ctx, `
		SELECT contribution_id, peer_id, zone, lower(track_window), upper(track_window), track_count,
			classification_ceiling, digest_sha256, state, created_by, COALESCE(approved_by,''), created_at, updated_at
		FROM yaounde_picture_contributions ORDER BY created_at DESC, contribution_id`)
	if err != nil {
		return nil, fmt.Errorf("list picture contributions: %w", err)
	}
	defer rows.Close()
	contributions := make([]PictureContribution, 0)
	for rows.Next() {
		var contribution PictureContribution
		if err := rows.Scan(&contribution.ContributionID, &contribution.PeerID, &contribution.Zone,
			&contribution.WindowStart, &contribution.WindowEnd, &contribution.TrackCount,
			&contribution.ClassificationCeiling, &contribution.DigestSHA256, &contribution.State,
			&contribution.CreatedBy, &contribution.ApprovedBy, &contribution.CreatedAt, &contribution.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan picture contribution: %w", err)
		}
		contributions = append(contributions, contribution)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate picture contributions: %w", err)
	}
	return contributions, nil
}
