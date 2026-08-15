package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/incident"
)

type Server struct{ store *incident.Store }

func New(store *incident.Store, authMode string) http.Handler {
	server := &Server{store: store}
	api := http.NewServeMux()
	api.HandleFunc("POST /v1/incidents", server.create)
	api.HandleFunc("POST /v1/feed-sources", server.registerFeedSource)
	api.HandleFunc("POST /v1/feed-events/admit", server.admitFeedEvent)
	api.HandleFunc("GET /v1/incidents/", server.get)
	api.HandleFunc("POST /v1/incidents/{incidentID}/correlations", server.correlate)
	api.HandleFunc("POST /v1/incidents/{incidentID}/assignment", server.assign)
	api.HandleFunc("POST /v1/incidents/", server.transition)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", server.health)
	mux.Handle("/v1/", requireAuthentication(authMode, api))
	return http.MaxBytesHandler(mux, 1<<20)
}

func (server *Server) health(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
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
	case errors.Is(err, incident.ErrNotFound):
		writeError(response, http.StatusNotFound, err.Error())
	case errors.Is(err, incident.ErrIdempotencyConflict), errors.Is(err, incident.ErrCorrelationConflict), errors.Is(err, incident.ErrOptimisticConflict), errors.Is(err, incident.ErrInvalidTransition):
		writeError(response, http.StatusConflict, err.Error())
	default:
		writeError(response, http.StatusInternalServerError, "internal maritime incident failure")
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
