package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/sar"
)

func writeSARError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sar.ErrNotFound):
		writeError(response, http.StatusNotFound, "sar record not found")
	case errors.Is(err, sar.ErrConflict):
		writeError(response, http.StatusConflict, "conflicting idempotency or optimistic-version evidence")
	case errors.Is(err, sar.ErrInvalidTransition):
		writeError(response, http.StatusConflict, "invalid sar state transition")
	case errors.Is(err, sar.ErrValidation):
		writeError(response, http.StatusBadRequest, err.Error())
	default:
		writeError(response, http.StatusBadRequest, err.Error())
	}
}

// sarListCases lists cases with stage/phase filters; records above the
// principal's clearance are filtered out per record.
func (server *Server) sarListCases(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	query := request.URL.Query()
	cases, err := server.isr.SAR.ListCases(request.Context(), query.Get("stage"), query.Get("phase"))
	if err != nil {
		writeSARError(response, err)
		return
	}
	visible := make([]sar.Case, 0, len(cases))
	for _, sarCase := range cases {
		if principal.Clearance.Covers(sarCase.Classification) {
			visible = append(visible, sarCase)
		}
	}
	writeJSON(response, http.StatusOK, map[string]any{"cases": visible})
}

// sarGetCase returns one case, role+clearance gated per record.
func (server *Server) sarGetCase(response http.ResponseWriter, request *http.Request) (sar.Case, bool) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return sar.Case{}, false
	}
	sarCase, err := server.isr.SAR.GetCase(request.Context(), request.PathValue("caseID"))
	if err != nil {
		writeSARError(response, err)
		return sar.Case{}, false
	}
	if err := principal.CanReadSAR(sarCase.Classification); err != nil {
		writeError(response, http.StatusForbidden, "insufficient sar read scope or clearance")
		return sar.Case{}, false
	}
	return sarCase, true
}

func (server *Server) sarGetCaseHandler(response http.ResponseWriter, request *http.Request) {
	sarCase, ok := server.sarGetCase(response, request)
	if !ok {
		return
	}
	writeJSON(response, http.StatusOK, sarCase)
}

func (server *Server) sarOpenCase(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input sar.OpenCaseRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid case JSON")
		return
	}
	sarCase, err := server.isr.SAR.OpenCase(request.Context(), input, principal.Subject)
	if err != nil {
		writeSARError(response, err)
		return
	}
	server.telemetry.RecordSARCase(request.Context(), string(sarCase.IntakeKind))
	writeJSON(response, http.StatusCreated, sarCase)
}

func (server *Server) sarTimeline(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.sarGetCase(response, request); !ok {
		return
	}
	entries, err := server.isr.SAR.Timeline(request.Context(), request.PathValue("caseID"))
	if err != nil {
		writeSARError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"entries": entries})
}

func (server *Server) sarTransitionPhase(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input struct {
		Phase           string `json:"phase"`
		Rationale       string `json:"rationale"`
		ExpectedVersion int64  `json:"expected_version"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid phase JSON")
		return
	}
	sarCase, err := server.isr.SAR.TransitionPhase(request.Context(), request.PathValue("caseID"), input.ExpectedVersion, input.Phase, input.Rationale, principal.Subject)
	if err != nil {
		writeSARError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, sarCase)
}

func (server *Server) sarTransitionStage(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input struct {
		Stage            string `json:"stage"`
		ReasonCode       string `json:"reason_code"`
		ExpectedVersion  int64  `json:"expected_version"`
		PersonsRecovered *int   `json:"persons_recovered"`
		HandoverRef      string `json:"handover_ref"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid stage JSON")
		return
	}
	sarCase, err := server.isr.SAR.TransitionStage(request.Context(), request.PathValue("caseID"), input.ExpectedVersion, input.Stage, input.ReasonCode, principal.Subject, input.PersonsRecovered, input.HandoverRef)
	if err != nil {
		writeSARError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, sarCase)
}

func (server *Server) sarSetDatum(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input struct {
		Latitude        float64 `json:"lat"`
		Longitude       float64 `json:"lon"`
		EvidenceSHA256  string  `json:"evidence_sha256"`
		ExpectedVersion int64   `json:"expected_version"`
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid datum JSON")
		return
	}
	sarCase, err := server.isr.SAR.SetDatum(request.Context(), request.PathValue("caseID"), input.ExpectedVersion, input.Latitude, input.Longitude, input.EvidenceSHA256, principal.Subject)
	if err != nil {
		writeSARError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, sarCase)
}

func (server *Server) sarListResources(response http.ResponseWriter, request *http.Request) {
	resources, err := server.isr.SAR.ListResources(request.Context(), request.URL.Query().Get("status"))
	if err != nil {
		writeSARError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"resources": resources})
}

func (server *Server) sarRegisterResource(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input sar.ResourceRegistration
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid resource JSON")
		return
	}
	resource, err := server.isr.SAR.RegisterResource(request.Context(), input, principal.Subject)
	if err != nil {
		writeSARError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, resource)
}

func (server *Server) sarSetResourceStatus(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid resource status JSON")
		return
	}
	resource, err := server.isr.SAR.SetResourceStatus(request.Context(), request.PathValue("resourceID"), input.Status, principal.Subject)
	if err != nil {
		writeSARError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, resource)
}

func (server *Server) sarProposeTasking(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input sar.TaskingRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid tasking JSON")
		return
	}
	tasking, err := server.isr.SAR.ProposeTasking(request.Context(), request.PathValue("caseID"), input, principal.Subject)
	if err != nil {
		writeSARError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, tasking)
}

func (server *Server) sarTransitionTasking(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input struct {
		State           string `json:"state"`
		ReasonCode      string `json:"reason_code"`
		ExpectedVersion int64  `json:"expected_version"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid tasking transition JSON")
		return
	}
	tasking, err := server.isr.SAR.TransitionTasking(request.Context(), request.PathValue("caseID"), request.PathValue("taskingID"), input.ExpectedVersion, input.State, input.ReasonCode, principal.Subject)
	if err != nil {
		writeSARError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, tasking)
}

func (server *Server) sarListTaskings(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.sarGetCase(response, request); !ok {
		return
	}
	taskings, err := server.isr.SAR.ListTaskings(request.Context(), request.PathValue("caseID"))
	if err != nil {
		writeSARError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"taskings": taskings})
}

func (server *Server) sarIssueSitrep(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input struct {
		ExpectedVersion int64 `json:"expected_version"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid sitrep JSON")
		return
	}
	sitrep, err := server.isr.SAR.IssueSitrep(request.Context(), request.PathValue("caseID"), input.ExpectedVersion, principal.Subject)
	if err != nil {
		writeSARError(response, err)
		return
	}
	server.telemetry.RecordSARSitrep(request.Context())
	writeJSON(response, http.StatusCreated, sitrep)
}

func (server *Server) sarListSitreps(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.sarGetCase(response, request); !ok {
		return
	}
	sitreps, err := server.isr.SAR.ListSitreps(request.Context(), request.PathValue("caseID"))
	if err != nil {
		writeSARError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"sitreps": sitreps})
}

// sarListVOO returns clearance-capped vessels of opportunity near the case
// datum (or last-known position).
func (server *Server) sarListVOO(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	sarCase, ok := server.sarGetCase(response, request)
	if !ok {
		return
	}
	radiusNM := 50.0
	if raw := request.URL.Query().Get("radius_nm"); raw != "" {
		parsed, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			writeError(response, http.StatusBadRequest, "radius_nm must be numeric")
			return
		}
		radiusNM = parsed
	}
	entries, err := sar.ListVOO(request.Context(), server.isr.SARTracks, sarCase, radiusNM, principal.Clearance, 2*time.Hour, time.Now().UTC())
	if err != nil {
		writeSARError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"voo": entries})
}

// geoSOSClient is the minimal geo-service client for SOS lifecycle mirroring.
// geo-service remains the system of record; when GEO_SERVICE_URL is unset
// the console reports the capability UNCONFIGURED (503), never simulated.
type geoSOSClient struct {
	baseURL string
	token   string
	client  *http.Client
}

func (client *geoSOSClient) configured() bool { return client != nil && client.baseURL != "" }

func (client *geoSOSClient) postLifecycle(request *http.Request, sosRef, action string) error {
	if !client.configured() {
		return errors.New("geo-service is not configured (UNCONFIGURED)")
	}
	endpoint := fmt.Sprintf("%s/v1/sos/%s/%s", strings.TrimSuffix(client.baseURL, "/"), sosRef, action)
	httpRequest, err := http.NewRequestWithContext(request.Context(), http.MethodPost, endpoint, bytes.NewReader([]byte("{}")))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	if client.token != "" {
		httpRequest.Header.Set("Authorization", "Bearer "+client.token)
	}
	response, err := client.client.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("geo-service call failed: %w", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("geo-service answered %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// sarMirrorSOS performs the geo SOS lifecycle call (system of record) and
// mirrors the accepted fact onto the case timeline.
func (server *Server) sarMirrorSOS(response http.ResponseWriter, request *http.Request, resolve bool) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input struct {
		SOSRef string `json:"sos_ref"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid sos mirror JSON")
		return
	}
	if server.geoSOS == nil || !server.geoSOS.configured() {
		writeError(response, http.StatusServiceUnavailable, "geo-service is not configured (UNCONFIGURED)")
		return
	}
	action := "acknowledge"
	if resolve {
		action = "resolve"
	}
	if err := server.geoSOS.postLifecycle(request, input.SOSRef, action); err != nil {
		writeError(response, http.StatusBadGateway, err.Error())
		return
	}
	caseID := request.PathValue("caseID")
	var err error
	if resolve {
		err = server.isr.SAR.MirrorSOSResolve(request.Context(), caseID, input.SOSRef, principal.Subject)
	} else {
		err = server.isr.SAR.MirrorSOSAcknowledge(request.Context(), caseID, input.SOSRef, principal.Subject)
	}
	if err != nil {
		writeSARError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"case_id": caseID, "sos_ref": input.SOSRef, "mirrored": action})
}
