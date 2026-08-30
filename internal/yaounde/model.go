// Package yaounde implements the Yaoundé Architecture regional
// information-exchange gateway: configured peers, human-gated outbound
// incident-report releases, signed inbound admission, classification-capped
// shared-picture contribution and a hash-chained append-only audit ledger.
//
// The gateway is fail-closed everywhere: with no ACTIVE peer configured,
// every exchange surface reports UNCONFIGURED honestly; there is no
// simulated peer, no fabricated acknowledgement and no invented incident
// content. Release markings are a closed enum; NATIONAL_ONLY is never
// releasable and its assertion is an audited policy refusal, not a dispatch.
package yaounde

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

var (
	// ErrNotFound is returned when a referenced record does not exist.
	ErrNotFound = errors.New("yaounde record not found")
	// ErrConflict is returned on idempotency/optimistic-version conflicts.
	ErrConflict = errors.New("yaounde record conflicts with retained evidence")
	// ErrInvalidTransition is returned for illegal state-machine moves.
	ErrInvalidTransition = errors.New("invalid yaounde state transition")
	// ErrMakerChecker is returned when maker and checker are the same
	// principal.
	ErrMakerChecker = errors.New("maker-checker violation: distinct principals are required")
	// ErrPolicyRefusal is returned when release policy forbids the exchange
	// (NATIONAL_ONLY marking, classification above ceiling, unknown marking).
	// Every refusal is audited as release.refused.
	ErrPolicyRefusal = errors.New("yaounde release policy refusal")
	// ErrPeerNotConfigured is returned when a dispatch references a peer
	// without an approved endpoint (fail-closed; never queued-and-pretend).
	ErrPeerNotConfigured = errors.New("peer endpoint not configured")
	// ErrPeerNotActive is returned when the peer is not ACTIVE.
	ErrPeerNotActive = errors.New("yaounde peer is not active")
	// ErrSignatureInvalid is returned when the peer Ed25519 signature over an
	// inbound payload or an ack receipt does not verify.
	ErrSignatureInvalid = errors.New("peer signature verification failed")
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// PeerKind is the fail-closed taxonomy of regional exchange peers.
type PeerKind string

const (
	PeerICC     PeerKind = "ICC"
	PeerCRESMAC PeerKind = "CRESMAC"
	PeerCRESMAO PeerKind = "CRESMAO"
	PeerMMCC    PeerKind = "MMCC"
	PeerMOC     PeerKind = "MOC"
	PeerMDATGoG PeerKind = "MDAT_GOG"
	PeerIMBPRC  PeerKind = "IMB_PRC"
	PeerOther   PeerKind = "OTHER"
)

// Zone is the Yaoundé Architecture zone scoping.
type Zone string

const (
	ZoneD             Zone = "D"
	ZoneE             Zone = "E"
	ZoneF             Zone = "F"
	ZoneG             Zone = "G"
	ZoneCentralB      Zone = "CENTRAL_B"
	ZoneInterregional Zone = "INTERREGIONAL"
	ZoneGlobal        Zone = "GLOBAL"
)

// PeerStatus is the peer lifecycle state.
type PeerStatus string

const (
	PeerPending   PeerStatus = "PENDING"
	PeerActive    PeerStatus = "ACTIVE"
	PeerSuspended PeerStatus = "SUSPENDED"
	PeerRevoked   PeerStatus = "REVOKED" // terminal
)

// Marking is the release/handling marking (distribution caveat) carried by
// every exchanged message. Wire values match the contracts ReleaseMarking
// enum JSON rendering.
type Marking string

const (
	MarkingNationalOnly     Marking = "NATIONAL_ONLY" // never releasable
	MarkingYaoundeZoneE     Marking = "YAOUNDE_ZONE_E"
	MarkingYaoundeRegional  Marking = "YAOUNDE_REGIONAL"
	MarkingMDATGoGShareable Marking = "MDAT_GOG_SHAREABLE"
)

// ParseMarking validates a raw marking fail-closed.
func ParseMarking(raw string) (Marking, error) {
	switch Marking(raw) {
	case MarkingNationalOnly, MarkingYaoundeZoneE, MarkingYaoundeRegional, MarkingMDATGoGShareable:
		return Marking(raw), nil
	default:
		return "", fmt.Errorf("%w: marking %q is not in the closed release-marking enum", ErrPolicyRefusal, raw)
	}
}

// ReleaseState is the outbound-release lifecycle:
// DRAFT→APPROVED→DISPATCHED→ACKNOWLEDGED; FAILED retryable-explicit from
// DISPATCHED; WITHDRAWN terminal from DRAFT or APPROVED.
type ReleaseState string

const (
	ReleaseDraft        ReleaseState = "DRAFT"
	ReleaseApproved     ReleaseState = "APPROVED"
	ReleaseDispatched   ReleaseState = "DISPATCHED"
	ReleaseAcknowledged ReleaseState = "ACKNOWLEDGED"
	ReleaseFailed       ReleaseState = "FAILED"
	ReleaseWithdrawn    ReleaseState = "WITHDRAWN"
)

// ValidReleaseTransition enforces the release state machine.
func ValidReleaseTransition(current, next ReleaseState) bool {
	switch current {
	case ReleaseDraft:
		return next == ReleaseApproved || next == ReleaseWithdrawn
	case ReleaseApproved:
		return next == ReleaseDispatched || next == ReleaseWithdrawn
	case ReleaseDispatched:
		return next == ReleaseAcknowledged || next == ReleaseFailed
	case ReleaseFailed:
		return next == ReleaseDispatched // retryable-explicit
	default:
		return false // ACKNOWLEDGED, WITHDRAWN terminal
	}
}

// Adjudication is the inbound-report adjudication state.
type Adjudication string

const (
	AdjudicationPending    Adjudication = "PENDING"
	AdjudicationCorrelated Adjudication = "CORRELATED"
	AdjudicationRejected   Adjudication = "REJECTED"
)

// PictureState is the shared-picture contribution lifecycle:
// PREPARED→APPROVED→DISPATCHED→ACKNOWLEDGED; FAILED retryable-explicit.
type PictureState string

const (
	PicturePrepared     PictureState = "PREPARED"
	PictureApproved     PictureState = "APPROVED"
	PictureDispatched   PictureState = "DISPATCHED"
	PictureAcknowledged PictureState = "ACKNOWLEDGED"
	PictureFailed       PictureState = "FAILED"
)

// ValidPictureTransition enforces the contribution state machine.
func ValidPictureTransition(current, next PictureState) bool {
	switch current {
	case PicturePrepared:
		return next == PictureApproved
	case PictureApproved:
		return next == PictureDispatched
	case PictureDispatched:
		return next == PictureAcknowledged || next == PictureFailed
	case PictureFailed:
		return next == PictureDispatched // retryable-explicit
	default:
		return false
	}
}

func validPeerKind(kind PeerKind) bool {
	switch kind {
	case PeerICC, PeerCRESMAC, PeerCRESMAO, PeerMMCC, PeerMOC, PeerMDATGoG, PeerIMBPRC, PeerOther:
		return true
	default:
		return false
	}
}

func validZone(zone Zone) bool {
	switch zone {
	case ZoneD, ZoneE, ZoneF, ZoneG, ZoneCentralB, ZoneInterregional, ZoneGlobal:
		return true
	default:
		return false
	}
}

func validIdentifier(name, value string) error {
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("%s must be a canonical identifier", name)
	}
	return nil
}

// PeerRegistration registers one peer (PENDING; never self-activates).
type PeerRegistration struct {
	PeerID         string `json:"peer_id"`
	PeerKind       string `json:"peer_kind"`
	Zone           string `json:"zone"`
	EndpointURL    string `json:"endpoint_url"` // may be empty until an approved endpoint exists
	ContactChannel string `json:"contact_channel"`
	PublicKey      []byte `json:"-"` // Ed25519; required for signed inbound admission before activation
	RegisteredBy   string `json:"-"` // verified principal, never from the request body
}

// Validate enforces the registration contract fail-closed.
func (request PeerRegistration) Validate() error {
	if err := validIdentifier("peer_id", request.PeerID); err != nil {
		return err
	}
	if !validPeerKind(PeerKind(request.PeerKind)) {
		return errors.New("peer_kind is not in the closed peer taxonomy")
	}
	if request.Zone != "" && !validZone(Zone(request.Zone)) {
		return errors.New("zone is not a Yaoundé Architecture zone")
	}
	if len(request.EndpointURL) > 512 || strings.TrimSpace(request.EndpointURL) != request.EndpointURL {
		return errors.New("endpoint_url must be canonical text of at most 512 characters")
	}
	if request.EndpointURL != "" && !strings.HasPrefix(request.EndpointURL, "https://") {
		return errors.New("endpoint_url must use https")
	}
	if len(request.ContactChannel) > 256 || strings.TrimSpace(request.ContactChannel) != request.ContactChannel {
		return errors.New("contact_channel must be canonical text of at most 256 characters")
	}
	if len(request.PublicKey) != 0 && len(request.PublicKey) != 32 {
		return errors.New("public_key must be a 32-byte Ed25519 public key when present")
	}
	if err := validIdentifier("registered_by", request.RegisteredBy); err != nil {
		return err
	}
	return nil
}

// Peer is the retained peer directory entry. EndpointURL empty means the
// exchange surface reports UNCONFIGURED for that peer honestly.
type Peer struct {
	PeerID         string     `json:"peer_id"`
	PeerKind       PeerKind   `json:"peer_kind"`
	Zone           string     `json:"zone,omitempty"`
	EndpointURL    string     `json:"endpoint_url"`
	ContactChannel string     `json:"contact_channel,omitempty"`
	HasPublicKey   bool       `json:"has_public_key"`
	Status         PeerStatus `json:"status"`
	RegisteredBy   string     `json:"registered_by"`
	ActivatedBy    string     `json:"activated_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	publicKey      []byte
}

// Configured reports whether the peer has an approved endpoint; an ACTIVE
// peer without one still reports UNCONFIGURED for dispatch purposes.
func (peer Peer) Configured() bool { return peer.EndpointURL != "" }

// Release is one outbound incident-report release instance.
type Release struct {
	ReleaseID        string             `json:"release_id"`
	IncidentID       string             `json:"incident_id"`
	PeerID           string             `json:"peer_id"`
	Marking          Marking            `json:"marking"`
	Classification   isr.Classification `json:"classification"`
	ReportSHA256     string             `json:"report_sha256"`
	EnvelopeJWS      string             `json:"envelope_jws"`
	State            ReleaseState       `json:"state"`
	ExpectedVersion  int64              `json:"expected_version"`
	ReleasedBy       string             `json:"released_by,omitempty"`
	ApprovedBy       string             `json:"approved_by,omitempty"`
	DispatchedAt     *time.Time         `json:"dispatched_at,omitempty"`
	AckedAt          *time.Time         `json:"acked_at,omitempty"`
	AckReceiptSHA256 string             `json:"ack_receipt_sha256,omitempty"`
	CreatedAt        time.Time          `json:"created_at"`
	UpdatedAt        time.Time          `json:"updated_at"`
	Version          int64              `json:"version"`
}

// InboundReport is one retained inbound regional report.
type InboundReport struct {
	ReportID       string             `json:"report_id"`
	PeerID         string             `json:"peer_id"`
	PeerReportRef  string             `json:"peer_report_ref"`
	Classification isr.Classification `json:"classification"`
	Marking        Marking            `json:"marking"`
	Payload        []byte             `json:"payload"`
	PayloadSHA256  string             `json:"payload_sha256"`
	Signature      []byte             `json:"-"`
	Adjudication   Adjudication       `json:"adjudication"`
	IncidentID     string             `json:"incident_id,omitempty"`
	ReceivedAt     time.Time          `json:"received_at"`
}

// PictureContribution is one shared-maritime-picture release.
type PictureContribution struct {
	ContributionID        string             `json:"contribution_id"`
	PeerID                string             `json:"peer_id"`
	Zone                  string             `json:"zone"`
	WindowStart           time.Time          `json:"window_start"`
	WindowEnd             time.Time          `json:"window_end"`
	TrackCount            int                `json:"track_count"`
	ClassificationCeiling isr.Classification `json:"classification_ceiling"`
	DigestSHA256          string             `json:"digest_sha256"`
	State                 PictureState       `json:"state"`
	CreatedBy             string             `json:"created_by"`
	ApprovedBy            string             `json:"approved_by,omitempty"`
	CreatedAt             time.Time          `json:"created_at"`
	UpdatedAt             time.Time          `json:"updated_at"`
}

// peerMarkingAllowed enforces the (peer kind × marking) distribution
// matrix. Release rules never widen visibility: MDAT-GoG-style contacts
// only receive MDAT_GOG_SHAREABLE material.
func peerMarkingAllowed(peer Peer, marking Marking) error {
	switch marking {
	case MarkingNationalOnly:
		return fmt.Errorf("%w: NATIONAL_ONLY material is never releasable to any peer", ErrPolicyRefusal)
	case MarkingYaoundeZoneE, MarkingYaoundeRegional:
		if peer.PeerKind == PeerMDATGoG || peer.PeerKind == PeerIMBPRC {
			return fmt.Errorf("%w: %s material is not releasable to %s contacts", ErrPolicyRefusal, marking, peer.PeerKind)
		}
		return nil
	case MarkingMDATGoGShareable:
		return nil // releasable to any configured peer, including MDAT-GoG
	default:
		return fmt.Errorf("%w: marking %q is not in the closed release-marking enum", ErrPolicyRefusal, marking)
	}
}

// ClassificationCeiling returns the highest national clearance label a peer
// may receive. Regional architecture peers (ICC/CRESMAC/CRESMAO/MMCC/MOC)
// receive up to CONFIDENTIAL operational material; MDAT-GoG-style and IMB
// contacts receive up to RESTRICTED; OTHER peers receive only UNCLASSIFIED.
// SECRET is never releasable to any peer.
func ClassificationCeiling(peer Peer) isr.Classification {
	switch peer.PeerKind {
	case PeerICC, PeerCRESMAC, PeerCRESMAO, PeerMMCC, PeerMOC:
		return isr.ClassificationConfidential
	case PeerMDATGoG, PeerIMBPRC:
		return isr.ClassificationRestricted
	default:
		return isr.ClassificationUnclassified
	}
}

// CheckReleasePolicy evaluates the full allow/refuse matrix for drafting a
// release: marking validity, NATIONAL_ONLY refusal, peer marking scope and
// the classification ceiling. Every refusal is auditable.
func CheckReleasePolicy(peer Peer, marking Marking, classification isr.Classification) error {
	if _, err := isr.ParseClassification(string(classification)); err != nil {
		return fmt.Errorf("%w: %v", ErrPolicyRefusal, err)
	}
	if _, err := ParseMarking(string(marking)); err != nil {
		return err
	}
	if err := peerMarkingAllowed(peer, marking); err != nil {
		return err
	}
	ceiling := ClassificationCeiling(peer)
	if classification.Rank() > ceiling.Rank() {
		return fmt.Errorf("%w: classification %s is above the %s peer ceiling %s", ErrPolicyRefusal, classification, peer.PeerKind, ceiling)
	}
	return nil
}
