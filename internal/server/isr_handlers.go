package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/incident"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/ledger"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/tracks"
)

// isrUnavailable answers 503 when a Workstream F dependency is not wired.
func (server *Server) isrUnavailable(response http.ResponseWriter) bool {
	if server.isr == nil || server.isr.ISRStore == nil {
		writeError(response, http.StatusServiceUnavailable, "isr analytics are not configured")
		return true
	}
	return false
}

// admitDetection admits one signed multi-modal detection, feeds the fusion
// engine and persists track/association/anomaly evidence atomically per
// store transaction. Classified-data discipline: admission logs and errors
// carry labels and identifiers only, never track content.
func (server *Server) admitDetection(response http.ResponseWriter, request *http.Request) {
	if server.isrUnavailable(response) {
		return
	}
	var input struct {
		SourceID        string `json:"source_id"`
		SourceEventID   string `json:"source_event_id"`
		PayloadBase64   string `json:"payload_base64"`
		SignatureBase64 string `json:"signature_base64"`
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid detection admission JSON")
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
	detection, admission, err := server.isr.ISRStore.AdmitDetection(request.Context(), isr.SignedDetectionRequest{
		SourceID: input.SourceID, SourceEventID: input.SourceEventID, Payload: payload, Signature: signature,
	})
	if err != nil {
		writeISRError(response, err)
		return
	}
	// Fusion runs after durable admission; replayed admissions must not
	// duplicate associations or anomalies. A fusion failure never fails the
	// request (admission is already durable and the startup replay rebuilds
	// engine state), but it is always logged and counted — never swallowed.
	if !admission.Replayed && server.isr.Fusion != nil && detection.HasPosition {
		trackID, anomalies, fusionErr := server.isr.Fusion.Ingest(request.Context(), detection)
		if fusionErr != nil {
			// Classified-data discipline: identifiers and labels only, never
			// track content.
			server.logger.ErrorContext(request.Context(), "isr fusion ingest failed after durable admission",
				"event_id", detection.EventID, "source_id", detection.SourceID,
				"classification", string(detection.Classification), "error", fusionErr.Error())
			if server.isr.FusionErrorHook != nil {
				server.isr.FusionErrorHook(request.Context())
			}
		} else if server.isr.TrackStore != nil {
			track, ok := server.isr.Fusion.Track(trackID)
			if ok {
				if recordErr := server.isr.TrackStore.RecordFusion(request.Context(), track, detection, anomalies); recordErr != nil {
					writeISRError(response, recordErr)
					return
				}
			}
		}
	}
	writeJSON(response, http.StatusCreated, admission)
}

func (server *Server) listDetections(response http.ResponseWriter, request *http.Request) {
	if server.isrUnavailable(response) {
		return
	}
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	filter := isr.DetectionFilter{
		Modality: isr.Modality(strings.ToUpper(request.URL.Query().Get("modality"))),
		MMSI:     strings.TrimSpace(request.URL.Query().Get("mmsi")),
		Limit:    queryLimit(request),
	}
	if since := request.URL.Query().Get("since"); since != "" {
		parsed, err := time.Parse(time.RFC3339, since)
		if err != nil {
			writeError(response, http.StatusBadRequest, "since must be RFC3339")
			return
		}
		filter.Since = parsed
	}
	detections, err := server.isr.ISRStore.ListDetections(request.Context(), principal, filter)
	if err != nil {
		writeISRError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"detections": detections})
}

// trackView is the clearance-filtered track projection. Only principals whose
// clearance covers the track classification receive it.
type trackView struct {
	TrackID        string             `json:"track_id"`
	Identity       string             `json:"identity"`
	Classification isr.Classification `json:"classification"`
	PointCount     int                `json:"point_count"`
	Points         []tracksPointView  `json:"points"`
}

type tracksPointView struct {
	ObservedAt time.Time `json:"observed_at"`
	Latitude   float64   `json:"latitude"`
	Longitude  float64   `json:"longitude"`
	Modality   string    `json:"modality"`
}

func (server *Server) listTracks(response http.ResponseWriter, request *http.Request) {
	if server.isrUnavailable(response) || server.isr.Fusion == nil {
		writeError(response, http.StatusServiceUnavailable, "isr analytics are not configured")
		return
	}
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	views := make([]trackView, 0)
	for _, track := range server.isr.Fusion.Tracks() {
		if err := principal.CanReadTracks(track.Classification); err != nil {
			continue
		}
		view := trackView{
			TrackID: track.TrackID, Identity: tracks.FusionIdentity(track),
			Classification: track.Classification, PointCount: len(track.Points),
		}
		for _, point := range track.Points {
			view.Points = append(view.Points, tracksPointView{
				ObservedAt: point.ObservedAt, Latitude: point.Position.Latitude,
				Longitude: point.Position.Longitude, Modality: string(point.Modality),
			})
		}
		views = append(views, view)
	}
	writeJSON(response, http.StatusOK, map[string]any{"tracks": views})
}

func (server *Server) listAnomalies(response http.ResponseWriter, request *http.Request) {
	if server.isrUnavailable(response) {
		return
	}
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	filter := isr.AnomalyFilter{Kind: strings.TrimSpace(request.URL.Query().Get("kind")), Limit: queryLimit(request)}
	if since := request.URL.Query().Get("since"); since != "" {
		parsed, err := time.Parse(time.RFC3339, since)
		if err != nil {
			writeError(response, http.StatusBadRequest, "since must be RFC3339")
			return
		}
		filter.Since = parsed
	}
	anomalies, err := server.isr.ISRStore.ListAnomalies(request.Context(), principal, filter)
	if err != nil {
		writeISRError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"anomalies": anomalies})
}

func (server *Server) outcomeAggregates(response http.ResponseWriter, request *http.Request) {
	if server.isrUnavailable(response) {
		return
	}
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	aggregates, err := server.isr.ISRStore.OutcomeAggregates(request.Context(), principal)
	if err != nil {
		writeISRError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"aggregates": aggregates})
}

func (server *Server) proposeOutcome(response http.ResponseWriter, request *http.Request) {
	if server.isrUnavailable(response) || server.isr.Outcomes == nil {
		writeError(response, http.StatusServiceUnavailable, "outcome ledger is not configured")
		return
	}
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input struct {
		EntryID        string `json:"entry_id"`
		EntryKind      string `json:"entry_kind"`
		IncidentRef    string `json:"incident_ref"`
		Classification string `json:"classification"`
		Metric         string `json:"metric"`
		Quantity       int64  `json:"quantity"`
		Unit           string `json:"unit"`
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid outcome proposal JSON")
		return
	}
	proposal := ledger.Proposal{
		EntryID: input.EntryID, EntryKind: ledger.EntryKind(input.EntryKind),
		IncidentRef: input.IncidentRef, Classification: isr.Classification(input.Classification),
		Metric: input.Metric, Quantity: input.Quantity, Unit: input.Unit,
		ProposedBy: principal.Subject,
	}
	if err := server.isr.Outcomes.Propose(request.Context(), proposal); err != nil {
		writeISRError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, map[string]string{"entry_id": proposal.EntryID, "state": "PROPOSED"})
}

func (server *Server) confirmOutcome(response http.ResponseWriter, request *http.Request) {
	if server.isrUnavailable(response) || server.isr.Outcomes == nil {
		writeError(response, http.StatusServiceUnavailable, "outcome ledger is not configured")
		return
	}
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	entry, err := server.isr.Outcomes.Confirm(request.Context(), request.PathValue("entryID"), principal.Subject)
	if err != nil {
		writeISRError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, entry)
}

func queryLimit(request *http.Request) int {
	value := strings.TrimSpace(request.URL.Query().Get("limit"))
	if value == "" {
		return 0
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return parsed
}

// writeISRError maps service-layer errors. Validation failures (plain
// errors from Validate) are 422; classification/role failures 403.
func writeISRError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, isr.ErrForbidden):
		writeError(response, http.StatusForbidden, "insufficient role or clearance")
	case errors.Is(err, isr.ErrNotFound), errors.Is(err, ledger.ErrNotFound):
		writeError(response, http.StatusNotFound, err.Error())
	case errors.Is(err, isr.ErrConflict), errors.Is(err, ledger.ErrConflict):
		writeError(response, http.StatusConflict, err.Error())
	case errors.Is(err, ledger.ErrDualControl), errors.Is(err, ledger.ErrAlreadyConfirmed):
		writeError(response, http.StatusConflict, err.Error())
	case errors.Is(err, isr.ErrInvalidClassification):
		writeError(response, http.StatusUnprocessableEntity, err.Error())
	default:
		writeError(response, http.StatusUnprocessableEntity, err.Error())
	}
}
