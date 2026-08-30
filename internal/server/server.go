package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/geo"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/incident"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/ledger"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/sar"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/telemetry"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/tracks"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/yaounde"
)

type Server struct {
	store         *incident.Store
	isr           *ISRDeps
	telemetry     *telemetry.Telemetry
	geoSOS        *geoSOSClient
	authenticator Authenticator
	readyzCheck   func(ctx context.Context) error
	metrics       http.Handler
	logger        *slog.Logger
}

// ISRDeps carries the Workstream F dependencies. Nil fields disable the
// corresponding routes fail-closed (they answer 503, never panic).
type ISRDeps struct {
	ISRStore   *isr.Store
	TrackStore *tracks.Store
	Fusion     *tracks.Engine
	Outcomes   *ledger.OutcomeStore
	// Phase 8: Yaounde gateway + SAR C2 console. Nil disables the routes
	// fail-closed (503). Zones are the configured ISR geofence zones used
	// for picture scoping; SARTracks feeds VOO lookups.
	Yaounde   *yaounde.Store
	SAR       *sar.Store
	Zones     []geo.Zone
	SARTracks sar.TrackSource
	// GeoSOSBaseURL/GeoSOSToken configure the geo-service SOS lifecycle
	// client; unset => UNCONFIGURED (503), never simulated.
	GeoSOSBaseURL string
	GeoSOSToken   string
	// FusionErrorHook counts fusion ingest failures observed after durable
	// detection admission (metric hook); nil disables the counter, never the
	// structured log.
	FusionErrorHook func(ctx context.Context)
}

// Config binds the HTTP surface. Authenticator is mandatory (fail-closed);
// ReadyzCheck defaults to a trivially-ready probe when nil.
type Config struct {
	Store         *incident.Store
	ISR           *ISRDeps
	Telemetry     *telemetry.Telemetry
	Authenticator Authenticator
	ReadyzCheck   func(ctx context.Context) error
	Metrics       http.Handler
	Logger        *slog.Logger
}

func New(config Config) http.Handler {
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	server := &Server{store: config.Store, isr: config.ISR, authenticator: config.Authenticator, readyzCheck: config.ReadyzCheck, metrics: config.Metrics, logger: logger, telemetry: config.Telemetry}
	if config.ISR != nil {
		server.geoSOS = &geoSOSClient{baseURL: config.ISR.GeoSOSBaseURL, token: config.ISR.GeoSOSToken, client: &http.Client{Timeout: 15 * time.Second}}
	}
	api := http.NewServeMux()
	// Every mutating route is registered through requireMutationRoles, which
	// applies the authoritative role table (internal/server/access.go) and
	// fails closed at startup if a mutation route lacks a role requirement.
	requireMutationRoles(api, "POST /v1/incidents", server.create)
	requireMutationRoles(api, "POST /v1/feed-sources", server.registerFeedSource)
	requireMutationRoles(api, "POST /v1/feed-sources/{sourceID}/activate", server.activateFeedSource)
	requireMutationRoles(api, "POST /v1/feed-sources/{sourceID}/revoke", server.revokeFeedSource)
	requireMutationRoles(api, "POST /v1/feed-sources/{sourceID}/rotate-key", server.rotateFeedSourceKey)
	requireMutationRoles(api, "POST /v1/feed-events/admit", server.admitFeedEvent)
	requireMutationRoles(api, "POST /v1/feed-events/admit-incident", server.admitFeedIncident)
	api.HandleFunc("GET /v1/incidents/", server.get)
	requireMutationRoles(api, "POST /v1/incidents/{incidentID}/correlations", server.correlate)
	requireMutationRoles(api, "POST /v1/incidents/{incidentID}/assignment", server.assign)
	requireMutationRoles(api, "POST /v1/incidents/", server.transition)
	// Workstream F: Deep Blue Project ISR analytics.
	requireMutationRoles(api, "POST /v1/isr/detections:admit", server.admitDetection)
	api.HandleFunc("GET /v1/isr/detections", server.listDetections)
	api.HandleFunc("GET /v1/isr/tracks", server.listTracks)
	api.HandleFunc("GET /v1/isr/anomalies", server.listAnomalies)
	api.HandleFunc("GET /v1/outcomes/aggregates", server.outcomeAggregates)
	requireMutationRoles(api, "POST /v1/outcomes", server.proposeOutcome)
	requireMutationRoles(api, "POST /v1/outcomes/{entryID}/confirm", server.confirmOutcome)

	// Phase 8: Yaounde gateway (human-gated exchange).
	if server.isr != nil && server.isr.Yaounde != nil {
		api.HandleFunc("GET /v1/yaounde/status", server.yaoundeStatus)
		api.HandleFunc("GET /v1/yaounde/peers", server.yaoundeListPeers)
		requireMutationRoles(api, "POST /v1/yaounde/peers", server.yaoundeRegisterPeer)
		requireMutationRoles(api, "POST /v1/yaounde/peers/{peerID}/activate", func(w http.ResponseWriter, r *http.Request) { server.yaoundePeerLifecycle(w, r, "activate") })
		requireMutationRoles(api, "POST /v1/yaounde/peers/{peerID}/suspend", func(w http.ResponseWriter, r *http.Request) { server.yaoundePeerLifecycle(w, r, "suspend") })
		requireMutationRoles(api, "POST /v1/yaounde/peers/{peerID}/revoke", func(w http.ResponseWriter, r *http.Request) { server.yaoundePeerLifecycle(w, r, "revoke") })
		api.HandleFunc("GET /v1/yaounde/releases", server.yaoundeListReleases)
		api.HandleFunc("GET /v1/yaounde/releases/{releaseID}", server.yaoundeGetRelease)
		requireMutationRoles(api, "POST /v1/yaounde/releases", server.yaoundeDraftRelease)
		requireMutationRoles(api, "POST /v1/yaounde/releases/{releaseID}/approve", server.yaoundeApproveRelease)
		requireMutationRoles(api, "POST /v1/yaounde/releases/{releaseID}/dispatch", server.yaoundeDispatchRelease)
		requireMutationRoles(api, "POST /v1/yaounde/releases/{releaseID}/withdraw", server.yaoundeWithdrawRelease)
		requireMutationRoles(api, "POST /v1/yaounde/releases/{releaseID}/acknowledge", server.yaoundeAcknowledgeRelease)
		requireMutationRoles(api, "POST /v1/yaounde/inbound/admit", server.yaoundeAdmitInbound)
		requireMutationRoles(api, "POST /v1/yaounde/inbound/{reportID}/correlate", func(w http.ResponseWriter, r *http.Request) { server.yaoundeCorrelateInbound(w, r, false) })
		requireMutationRoles(api, "POST /v1/yaounde/inbound/{reportID}/reject", func(w http.ResponseWriter, r *http.Request) { server.yaoundeCorrelateInbound(w, r, true) })
		requireMutationRoles(api, "POST /v1/yaounde/picture/prepare", server.yaoundePreparePicture)
		requireMutationRoles(api, "POST /v1/yaounde/picture/{contributionID}/approve", server.yaoundeApprovePicture)
		requireMutationRoles(api, "POST /v1/yaounde/picture/{contributionID}/dispatch", server.yaoundeDispatchPicture)
		api.HandleFunc("GET /v1/yaounde/picture", server.yaoundeListPicture)
		api.HandleFunc("GET /v1/yaounde/audit", server.yaoundeAudit)
	}

	// Phase 8: SAR C2 case engine.
	if server.isr != nil && server.isr.SAR != nil {
		api.HandleFunc("GET /v1/sar/cases", server.sarListCases)
		requireMutationRoles(api, "POST /v1/sar/cases", server.sarOpenCase)
		api.HandleFunc("GET /v1/sar/cases/{caseID}", server.sarGetCaseHandler)
		api.HandleFunc("GET /v1/sar/cases/{caseID}/timeline", server.sarTimeline)
		requireMutationRoles(api, "POST /v1/sar/cases/{caseID}/phase", server.sarTransitionPhase)
		requireMutationRoles(api, "POST /v1/sar/cases/{caseID}/stage", server.sarTransitionStage)
		requireMutationRoles(api, "POST /v1/sar/cases/{caseID}/datum", server.sarSetDatum)
		api.HandleFunc("GET /v1/sar/resources", server.sarListResources)
		requireMutationRoles(api, "POST /v1/sar/resources", server.sarRegisterResource)
		requireMutationRoles(api, "POST /v1/sar/resources/{resourceID}/status", server.sarSetResourceStatus)
		api.HandleFunc("GET /v1/sar/cases/{caseID}/taskings", server.sarListTaskings)
		requireMutationRoles(api, "POST /v1/sar/cases/{caseID}/taskings", server.sarProposeTasking)
		requireMutationRoles(api, "POST /v1/sar/cases/{caseID}/taskings/{taskingID}/transition", server.sarTransitionTasking)
		requireMutationRoles(api, "POST /v1/sar/cases/{caseID}/sitrep", server.sarIssueSitrep)
		api.HandleFunc("GET /v1/sar/cases/{caseID}/sitrep", server.sarListSitreps)
		api.HandleFunc("GET /v1/sar/cases/{caseID}/voo", server.sarListVOO)
		requireMutationRoles(api, "POST /v1/sar/cases/{caseID}/sos-acknowledge", func(w http.ResponseWriter, r *http.Request) { server.sarMirrorSOS(w, r, false) })
		requireMutationRoles(api, "POST /v1/sar/cases/{caseID}/sos-resolve", func(w http.ResponseWriter, r *http.Request) { server.sarMirrorSOS(w, r, true) })
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", server.health)
	mux.HandleFunc("GET /readyz", server.readyz)
	if server.metrics != nil {
		mux.Handle("GET /metrics", server.metrics)
	}
	mux.Handle("/v1/", server.requireAuthentication(api))
	return http.MaxBytesHandler(mux, 1<<20)
}

type principalContextKey struct{}

func principalFrom(request *http.Request) (isr.Principal, bool) {
	principal, ok := request.Context().Value(principalContextKey{}).(isr.Principal)
	return principal, ok
}

// requireAuthentication authenticates every /v1 request and stores the
// verified principal in the request context. Read-only principals (observer,
// insurer-aggregator, auditor roles) are denied every mutating method
// generically.
func (server *Server) requireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if server.authenticator == nil {
			writeError(response, http.StatusInternalServerError, "authentication is not configured")
			return
		}
		principal, err := server.authenticator.Authenticate(request)
		if err != nil {
			writeError(response, http.StatusUnauthorized, "authentication failed")
			return
		}
		mutating := request.Method != http.MethodGet && request.Method != http.MethodHead && request.Method != http.MethodOptions
		if mutating && principal.IsReadOnly() {
			writeError(response, http.StatusForbidden, "read-only principals may not mutate ISR state")
			return
		}
		next.ServeHTTP(response, request.WithContext(context.WithValue(request.Context(), principalContextKey{}, principal)))
	})
}

func (server *Server) health(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
}

func (server *Server) readyz(response http.ResponseWriter, request *http.Request) {
	if server.readyzCheck != nil {
		if err := server.readyzCheck(request.Context()); err != nil {
			writeError(response, http.StatusServiceUnavailable, "not ready")
			return
		}
	}
	writeJSON(response, http.StatusOK, map[string]string{"status": "ready"})
}

func (server *Server) registerFeedSource(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input struct {
		SourceID        string `json:"source_id"`
		SourceKind      string `json:"source_kind"`
		Authority       string `json:"authority"`
		PublicKeyBase64 string `json:"public_key_base64"`
		Active          bool   `json:"active"`
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid feed source JSON")
		return
	}
	// Fail-closed: a feed source can never self-activate. Registration always
	// creates the source PENDING; activation is a separate maker-checker
	// decision by a distinct isr-admin principal via the activate endpoint.
	if input.Active {
		writeError(response, http.StatusBadRequest, "feed sources are never self-activated; a distinct administrator must activate via /v1/feed-sources/{source_id}/activate")
		return
	}
	key, err := base64.RawStdEncoding.DecodeString(input.PublicKeyBase64)
	if err != nil {
		writeError(response, http.StatusBadRequest, "public_key_base64 is invalid")
		return
	}
	if err := server.store.RegisterFeedSource(request.Context(), incident.FeedSourceRegistration{SourceID: input.SourceID, SourceKind: input.SourceKind, Authority: input.Authority, PublicKey: key, RegisteredBy: principal.Subject}); err != nil {
		writeIncidentError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, map[string]string{"source_id": input.SourceID, "status": "pending_activation"})
}

// activateFeedSource applies the maker-checker approval: the verified
// isr-admin principal activating the source must differ from the registrar
// recorded at registration (enforced again in the store, with the activation
// persisted as audit evidence).
func (server *Server) activateFeedSource(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	if err := server.store.ActivateFeedSource(request.Context(), incident.FeedSourceActivation{SourceID: request.PathValue("sourceID"), ActivatedBy: principal.Subject}); err != nil {
		writeIncidentError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"source_id": request.PathValue("sourceID"), "status": "active"})
}

func (server *Server) revokeFeedSource(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input struct {
		Reason string `json:"reason"`
		// RevokedBy is decoded only so legacy clients do not break; it is
		// NEVER used. Audit attribution always comes from the verified token
		// subject — body-supplied actor fields are ignored (MI-3).
		RevokedBy string `json:"revoked_by"`
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid feed source revocation JSON")
		return
	}
	if err := server.store.RevokeFeedSource(request.Context(), incident.FeedSourceRevocation{SourceID: request.PathValue("sourceID"), Reason: input.Reason, RevokedBy: principal.Subject}); err != nil {
		writeIncidentError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"source_id": request.PathValue("sourceID"), "status": "revoked"})
}

func (server *Server) rotateFeedSourceKey(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input struct {
		PublicKeyBase64 string    `json:"public_key_base64"`
		GraceUntil      time.Time `json:"grace_until"`
		// RotatedBy is decoded only so legacy clients do not break; it is
		// NEVER used. Audit attribution always comes from the verified token
		// subject — body-supplied actor fields are ignored (MI-3).
		RotatedBy string `json:"rotated_by"`
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid feed key rotation JSON")
		return
	}
	key, err := base64.RawStdEncoding.DecodeString(input.PublicKeyBase64)
	if err != nil {
		writeError(response, http.StatusBadRequest, "public_key_base64 is invalid")
		return
	}
	if err := server.store.RotateFeedSourceKey(request.Context(), incident.FeedSourceKeyRotation{SourceID: request.PathValue("sourceID"), NewPublicKey: key, GraceUntil: input.GraceUntil, RotatedBy: principal.Subject}); err != nil {
		writeIncidentError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"source_id": request.PathValue("sourceID"), "status": "key_rotated"})
}

func (server *Server) admitFeedEvent(response http.ResponseWriter, request *http.Request) {
	var input struct {
		SourceID        string `json:"source_id"`
		SourceEventID   string `json:"source_event_id"`
		PayloadBase64   string `json:"payload_base64"`
		SignatureBase64 string `json:"signature_base64"`
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid feed event JSON")
		return
	}
	payload, err := base64.StdEncoding.DecodeString(input.PayloadBase64)
	if err != nil {
		writeError(response, http.StatusBadRequest, "payload_base64 is invalid")
		return
	}
	signature, err := incident.DecodeFeedSignature(input.SignatureBase64)
	if err != nil {
		writeError(response, http.StatusBadRequest, "signature_base64 is invalid")
		return
	}
	admission, err := server.store.AdmitFeedEvent(request.Context(), incident.FeedAdmissionRequest{SourceID: input.SourceID, SourceEventID: input.SourceEventID, Payload: payload, Signature: signature})
	if err != nil {
		writeIncidentError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, admission)
}

func (server *Server) admitFeedIncident(response http.ResponseWriter, request *http.Request) {
	var input struct {
		SourceID        string `json:"source_id"`
		SourceEventID   string `json:"source_event_id"`
		PayloadBase64   string `json:"payload_base64"`
		SignatureBase64 string `json:"signature_base64"`
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid feed incident JSON")
		return
	}
	payload, err := base64.StdEncoding.DecodeString(input.PayloadBase64)
	if err != nil {
		writeError(response, http.StatusBadRequest, "payload_base64 is invalid")
		return
	}
	signature, err := incident.DecodeFeedSignature(input.SignatureBase64)
	if err != nil {
		writeError(response, http.StatusBadRequest, "signature_base64 is invalid")
		return
	}
	result, err := server.store.AdmitFeedIncident(request.Context(), incident.SignedFeedIncidentRequest{FeedAdmissionRequest: incident.FeedAdmissionRequest{SourceID: input.SourceID, SourceEventID: input.SourceEventID, Payload: payload, Signature: signature}})
	if err != nil {
		writeIncidentError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, result)
}

func (server *Server) create(response http.ResponseWriter, request *http.Request) {
	var input incident.CreateRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid JSON request")
		return
	}
	created, err := server.store.Create(request.Context(), input)
	if err != nil {
		writeIncidentError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, created)
}

func (server *Server) get(response http.ResponseWriter, request *http.Request) {
	incidentID := strings.TrimPrefix(request.URL.Path, "/v1/incidents/")
	if incidentID == "" || strings.Contains(incidentID, "/") {
		writeError(response, http.StatusNotFound, "incident not found")
		return
	}
	retained, err := server.store.Get(request.Context(), incidentID)
	if err != nil {
		writeIncidentError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, retained)
}

type transitionRequest struct {
	ExpectedVersion int64 `json:"expected_version"`
}

func (server *Server) correlate(response http.ResponseWriter, request *http.Request) {
	var input incident.CorrelationRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid spatial correlation JSON request")
		return
	}
	correlation, err := server.store.Correlate(request.Context(), request.PathValue("incidentID"), input)
	if err != nil {
		writeIncidentError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, correlation)
}

func (server *Server) assign(response http.ResponseWriter, request *http.Request) {
	var input incident.AssignmentRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid analyst assignment JSON request")
		return
	}
	assignment, err := server.store.Assign(request.Context(), request.PathValue("incidentID"), input)
	if err != nil {
		writeIncidentError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, assignment)
}

func (server *Server) transition(response http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/v1/incidents/"), "/")
	if len(parts) != 2 || parts[0] == "" {
		writeError(response, http.StatusNotFound, "incident operation not found")
		return
	}
	nextByOperation := map[string]incident.Status{
		"acknowledge": incident.StatusAcknowledged,
		"investigate": incident.StatusInvestigating,
		"resolve":     incident.StatusResolved,
		"close":       incident.StatusClosed,
	}
	next, ok := nextByOperation[parts[1]]
	if !ok {
		writeError(response, http.StatusNotFound, "incident operation not found")
		return
	}
	var input transitionRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || input.ExpectedVersion < 1 {
		writeError(response, http.StatusBadRequest, "expected_version must be a positive integer")
		return
	}
	updated, err := server.store.Transition(request.Context(), parts[0], input.ExpectedVersion, next)
	if err != nil {
		writeIncidentError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, updated)
}

func writeIncidentError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, incident.ErrNotFound), errors.Is(err, isr.ErrNotFound), errors.Is(err, ledger.ErrNotFound):
		writeError(response, http.StatusNotFound, err.Error())
	case errors.Is(err, isr.ErrForbidden), errors.Is(err, incident.ErrFeedSourceNotActive), errors.Is(err, incident.ErrFeedSignatureInvalid):
		writeError(response, http.StatusForbidden, err.Error())
	case errors.Is(err, incident.ErrIdempotencyConflict), errors.Is(err, incident.ErrCorrelationConflict), errors.Is(err, incident.ErrOptimisticConflict), errors.Is(err, incident.ErrInvalidTransition),
		errors.Is(err, incident.ErrMakerChecker), errors.Is(err, incident.ErrFeedSourceRevoked),
		errors.Is(err, isr.ErrConflict), errors.Is(err, ledger.ErrConflict), errors.Is(err, ledger.ErrDualControl), errors.Is(err, ledger.ErrAlreadyConfirmed):
		writeError(response, http.StatusConflict, err.Error())
	default:
		writeError(response, http.StatusInternalServerError, "internal maritime intelligence failure")
	}
}

func writeError(response http.ResponseWriter, status int, message string) {
	writeJSON(response, status, map[string]string{"error": message})
}
func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
