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

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/incident"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/ledger"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/tracks"
)

type Server struct {
	store         *incident.Store
	isr           *ISRDeps
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
	server := &Server{store: config.Store, isr: config.ISR, authenticator: config.Authenticator, readyzCheck: config.ReadyzCheck, metrics: config.Metrics, logger: logger}
	api := http.NewServeMux()
	api.HandleFunc("POST /v1/incidents", server.create)
	api.HandleFunc("POST /v1/feed-sources", server.registerFeedSource)
	api.HandleFunc("POST /v1/feed-sources/{sourceID}/revoke", server.revokeFeedSource)
	api.HandleFunc("POST /v1/feed-sources/{sourceID}/rotate-key", server.rotateFeedSourceKey)
	api.HandleFunc("POST /v1/feed-events/admit", server.admitFeedEvent)
	api.HandleFunc("POST /v1/feed-events/admit-incident", server.admitFeedIncident)
	api.HandleFunc("GET /v1/incidents/", server.get)
	api.HandleFunc("POST /v1/incidents/{incidentID}/correlations", server.correlate)
	api.HandleFunc("POST /v1/incidents/{incidentID}/assignment", server.assign)
	api.HandleFunc("POST /v1/incidents/", server.transition)
	// Workstream F: Deep Blue Project ISR analytics.
	api.HandleFunc("POST /v1/isr/detections:admit", server.admitDetection)
	api.HandleFunc("GET /v1/isr/detections", server.listDetections)
	api.HandleFunc("GET /v1/isr/tracks", server.listTracks)
	api.HandleFunc("GET /v1/isr/anomalies", server.listAnomalies)
	api.HandleFunc("GET /v1/outcomes/aggregates", server.outcomeAggregates)
	api.HandleFunc("POST /v1/outcomes", server.proposeOutcome)
	api.HandleFunc("POST /v1/outcomes/{entryID}/confirm", server.confirmOutcome)
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
	key, err := base64.RawStdEncoding.DecodeString(input.PublicKeyBase64)
	if err != nil {
		writeError(response, http.StatusBadRequest, "public_key_base64 is invalid")
		return
	}
	if err := server.store.RegisterFeedSource(request.Context(), incident.FeedSourceRegistration{SourceID: input.SourceID, SourceKind: input.SourceKind, Authority: input.Authority, PublicKey: key, Active: input.Active}); err != nil {
		writeIncidentError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, map[string]string{"source_id": input.SourceID, "status": "registered"})
}

func (server *Server) revokeFeedSource(response http.ResponseWriter, request *http.Request) {
	var input struct {
		Reason    string `json:"reason"`
		RevokedBy string `json:"revoked_by"`
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid feed source revocation JSON")
		return
	}
	if err := server.store.RevokeFeedSource(request.Context(), incident.FeedSourceRevocation{SourceID: request.PathValue("sourceID"), Reason: input.Reason, RevokedBy: input.RevokedBy}); err != nil {
		writeIncidentError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"source_id": request.PathValue("sourceID"), "status": "revoked"})
}

func (server *Server) rotateFeedSourceKey(response http.ResponseWriter, request *http.Request) {
	var input struct {
		PublicKeyBase64 string    `json:"public_key_base64"`
		GraceUntil      time.Time `json:"grace_until"`
		RotatedBy       string    `json:"rotated_by"`
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
	if err := server.store.RotateFeedSourceKey(request.Context(), incident.FeedSourceKeyRotation{SourceID: request.PathValue("sourceID"), NewPublicKey: key, GraceUntil: input.GraceUntil, RotatedBy: input.RotatedBy}); err != nil {
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
	case errors.Is(err, isr.ErrForbidden):
		writeError(response, http.StatusForbidden, "insufficient role or clearance")
	case errors.Is(err, incident.ErrIdempotencyConflict), errors.Is(err, incident.ErrCorrelationConflict), errors.Is(err, incident.ErrOptimisticConflict), errors.Is(err, incident.ErrInvalidTransition),
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
