package server

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/geo"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/yaounde"
)

func writeYaoundeError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, yaounde.ErrNotFound):
		writeError(response, http.StatusNotFound, "yaounde record not found")
	case errors.Is(err, yaounde.ErrConflict):
		writeError(response, http.StatusConflict, "conflicting idempotency or optimistic-version evidence")
	case errors.Is(err, yaounde.ErrInvalidTransition):
		writeError(response, http.StatusConflict, "invalid state transition")
	case errors.Is(err, yaounde.ErrMakerChecker):
		writeError(response, http.StatusForbidden, "maker-checker violation: distinct principals are required")
	case errors.Is(err, yaounde.ErrPeerNotConfigured):
		// Fail-closed honesty: the exchange surface is UNCONFIGURED.
		writeError(response, http.StatusConflict, "peer endpoint not configured (UNCONFIGURED)")
	case errors.Is(err, yaounde.ErrPeerNotActive):
		writeError(response, http.StatusConflict, "yaounde peer is not active")
	case errors.Is(err, yaounde.ErrSignatureInvalid):
		writeError(response, http.StatusUnprocessableEntity, "peer signature verification failed")
	case errors.Is(err, yaounde.ErrPolicyRefusal):
		writeError(response, http.StatusUnprocessableEntity, err.Error())
	default:
		writeError(response, http.StatusBadRequest, err.Error())
	}
}

// yaoundeStatus reports the exchange-surface configuration honestly.
func (server *Server) yaoundeStatus(response http.ResponseWriter, request *http.Request) {
	peers, err := server.isr.Yaounde.ListPeers(request.Context())
	if err != nil {
		writeError(response, http.StatusInternalServerError, "list peers")
		return
	}
	activeConfigured := 0
	for _, peer := range peers {
		if peer.Status == yaounde.PeerActive && peer.Configured() {
			activeConfigured++
		}
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"peers_total": len(peers), "peers_active_configured": activeConfigured,
		"configured": activeConfigured > 0,
	})
}

func (server *Server) yaoundeListPeers(response http.ResponseWriter, request *http.Request) {
	peers, err := server.isr.Yaounde.ListPeers(request.Context())
	if err != nil {
		writeError(response, http.StatusInternalServerError, "list peers")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"peers": peers})
}

func (server *Server) yaoundeRegisterPeer(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input struct {
		PeerID          string `json:"peer_id"`
		PeerKind        string `json:"peer_kind"`
		Zone            string `json:"zone"`
		EndpointURL     string `json:"endpoint_url"`
		ContactChannel  string `json:"contact_channel"`
		PublicKeyBase64 string `json:"public_key_base64"`
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid peer registration JSON")
		return
	}
	var publicKey []byte
	if input.PublicKeyBase64 != "" {
		decoded, err := base64.RawStdEncoding.DecodeString(input.PublicKeyBase64)
		if err != nil {
			if decoded, err = base64.RawURLEncoding.DecodeString(input.PublicKeyBase64); err != nil {
				writeError(response, http.StatusBadRequest, "public_key_base64 is invalid")
				return
			}
		}
		publicKey = decoded
	}
	if err := server.isr.Yaounde.RegisterPeer(request.Context(), yaounde.PeerRegistration{
		PeerID: input.PeerID, PeerKind: input.PeerKind, Zone: input.Zone,
		EndpointURL: input.EndpointURL, ContactChannel: input.ContactChannel,
		PublicKey: publicKey, RegisteredBy: principal.Subject,
	}); err != nil {
		writeYaoundeError(response, err)
		return
	}
	server.telemetry.RecordYaoundeInbound(request.Context(), "peer.registered")
	writeJSON(response, http.StatusCreated, map[string]string{"peer_id": input.PeerID, "status": "pending_activation"})
}

func (server *Server) yaoundePeerLifecycle(response http.ResponseWriter, request *http.Request, action string) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	peer, err := server.isr.Yaounde.PeerLifecycle(request.Context(), request.PathValue("peerID"), action, principal.Subject)
	if err != nil {
		writeYaoundeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"peer_id": peer.PeerID, "status": peer.Status})
}

func (server *Server) yaoundeDraftRelease(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input yaounde.ReleaseDraftRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid release draft JSON")
		return
	}
	input.ReleasedBy = principal.Subject
	release, err := server.isr.Yaounde.DraftRelease(request.Context(), input)
	if err != nil {
		if errors.Is(err, yaounde.ErrPolicyRefusal) {
			server.telemetry.RecordYaoundeRefusal(request.Context(), "release-policy")
		}
		writeYaoundeError(response, err)
		return
	}
	server.telemetry.RecordYaoundeRelease(request.Context(), string(release.State), "draft")
	writeJSON(response, http.StatusCreated, release)
}

func (server *Server) yaoundeListReleases(response http.ResponseWriter, request *http.Request) {
	releases, err := server.isr.Yaounde.ListReleases(request.Context(), request.URL.Query().Get("state"))
	if err != nil {
		writeError(response, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"releases": releases})
}

func (server *Server) yaoundeGetRelease(response http.ResponseWriter, request *http.Request) {
	release, err := server.isr.Yaounde.GetRelease(request.Context(), request.PathValue("releaseID"))
	if err != nil {
		writeYaoundeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, release)
}

func (server *Server) yaoundeApproveRelease(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input struct {
		ExpectedVersion int64 `json:"expected_version"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid approval JSON")
		return
	}
	release, err := server.isr.Yaounde.ApproveRelease(request.Context(), request.PathValue("releaseID"), input.ExpectedVersion, principal.Subject)
	if err != nil {
		writeYaoundeError(response, err)
		return
	}
	server.telemetry.RecordYaoundeRelease(request.Context(), string(release.State), "approved")
	writeJSON(response, http.StatusOK, release)
}

func (server *Server) yaoundeDispatchRelease(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input struct {
		ExpectedVersion int64 `json:"expected_version"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid dispatch JSON")
		return
	}
	release, err := server.isr.Yaounde.DispatchRelease(request.Context(), request.PathValue("releaseID"), input.ExpectedVersion, principal.Subject)
	if err != nil {
		if errors.Is(err, yaounde.ErrPeerNotConfigured) {
			server.telemetry.RecordYaoundeRefusal(request.Context(), "peer-endpoint-unconfigured")
		}
		writeYaoundeError(response, err)
		return
	}
	server.telemetry.RecordYaoundeDispatch(request.Context(), "dispatched")
	writeJSON(response, http.StatusOK, release)
}

func (server *Server) yaoundeWithdrawRelease(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input struct {
		ExpectedVersion int64  `json:"expected_version"`
		ReasonCode      string `json:"reason_code"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid withdrawal JSON")
		return
	}
	release, err := server.isr.Yaounde.WithdrawRelease(request.Context(), request.PathValue("releaseID"), input.ExpectedVersion, principal.Subject, input.ReasonCode)
	if err != nil {
		writeYaoundeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, release)
}

func (server *Server) yaoundeAcknowledgeRelease(response http.ResponseWriter, request *http.Request) {
	var input struct {
		ExpectedVersion     int64  `json:"expected_version"`
		ReceiptSignatureB64 string `json:"receipt_signature_base64"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid acknowledgement JSON")
		return
	}
	signature, err := base64.StdEncoding.DecodeString(input.ReceiptSignatureB64)
	if err != nil {
		if signature, err = base64.RawURLEncoding.DecodeString(input.ReceiptSignatureB64); err != nil {
			writeError(response, http.StatusBadRequest, "receipt_signature_base64 is invalid")
			return
		}
	}
	release, err := server.isr.Yaounde.RecordAcknowledgement(request.Context(), request.PathValue("releaseID"), input.ExpectedVersion, signature)
	if err != nil {
		writeYaoundeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, release)
}

func (server *Server) yaoundeAdmitInbound(response http.ResponseWriter, request *http.Request) {
	var input struct {
		PeerID          string `json:"peer_id"`
		PeerReportRef   string `json:"peer_report_ref"`
		Classification  string `json:"classification"`
		Marking         string `json:"marking"`
		PayloadBase64   string `json:"payload_base64"`
		SignatureBase64 string `json:"signature_base64"`
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid inbound admission JSON")
		return
	}
	payload, err := base64.StdEncoding.DecodeString(input.PayloadBase64)
	if err != nil {
		writeError(response, http.StatusBadRequest, "payload_base64 is invalid")
		return
	}
	signature, err := base64.StdEncoding.DecodeString(input.SignatureBase64)
	if err != nil {
		if signature, err = base64.RawURLEncoding.DecodeString(input.SignatureBase64); err != nil {
			writeError(response, http.StatusBadRequest, "signature_base64 is invalid")
			return
		}
	}
	report, err := server.isr.Yaounde.AdmitInbound(request.Context(), yaounde.InboundAdmissionRequest{
		PeerID: input.PeerID, PeerReportRef: input.PeerReportRef,
		Classification: input.Classification, Marking: input.Marking,
		Payload: payload, Signature: signature,
	})
	if err != nil {
		server.telemetry.RecordYaoundeInbound(request.Context(), "rejected")
		writeYaoundeError(response, err)
		return
	}
	server.telemetry.RecordYaoundeInbound(request.Context(), "admitted")
	writeJSON(response, http.StatusCreated, report)
}

func (server *Server) yaoundeCorrelateInbound(response http.ResponseWriter, request *http.Request, reject bool) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	reportID := request.PathValue("reportID")
	if reject {
		report, err := server.isr.Yaounde.RejectInbound(request.Context(), reportID, principal.Subject)
		if err != nil {
			writeYaoundeError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, report)
		return
	}
	var input struct {
		IncidentID string `json:"incident_id"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid correlation JSON")
		return
	}
	report, err := server.isr.Yaounde.CorrelateInbound(request.Context(), reportID, input.IncidentID, principal.Subject)
	if err != nil {
		writeYaoundeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, report)
}

func (server *Server) yaoundePreparePicture(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	var input struct {
		PeerID      string `json:"peer_id"`
		ZoneID      string `json:"zone_id"`
		WindowStart string `json:"window_start"`
		WindowEnd   string `json:"window_end"`
		Ceiling     string `json:"classification_ceiling"`
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid picture prepare JSON")
		return
	}
	windowStart, err := time.Parse(time.RFC3339, input.WindowStart)
	if err != nil {
		writeError(response, http.StatusBadRequest, "window_start must be RFC3339")
		return
	}
	windowEnd, err := time.Parse(time.RFC3339, input.WindowEnd)
	if err != nil {
		writeError(response, http.StatusBadRequest, "window_end must be RFC3339")
		return
	}
	zone, ok := server.resolveZone(input.ZoneID)
	if !ok {
		writeError(response, http.StatusNotFound, "zone is not a configured geofence zone")
		return
	}
	contribution, err := server.isr.Yaounde.PreparePicture(request.Context(), yaounde.PicturePrepareRequest{
		PeerID: input.PeerID, ZoneID: input.ZoneID, Zone: zone,
		WindowStart: windowStart, WindowEnd: windowEnd, Ceiling: input.Ceiling,
		CreatedBy: principal.Subject,
	})
	if err != nil {
		writeYaoundeError(response, err)
		return
	}
	writeJSON(response, http.StatusCreated, contribution)
}

// resolveZone resolves a configured ISR geofence zone by id (fail-closed:
// unknown zones are not found).
func (server *Server) resolveZone(zoneID string) (geo.Zone, bool) {
	for _, zone := range server.isr.Zones {
		if zone.ZoneID == zoneID {
			return zone, true
		}
	}
	return geo.Zone{}, false
}

func (server *Server) yaoundeApprovePicture(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	contribution, err := server.isr.Yaounde.ApprovePicture(request.Context(), request.PathValue("contributionID"), principal.Subject)
	if err != nil {
		writeYaoundeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, contribution)
}

func (server *Server) yaoundeDispatchPicture(response http.ResponseWriter, request *http.Request) {
	principal, ok := principalFrom(request)
	if !ok {
		writeError(response, http.StatusUnauthorized, "authentication failed")
		return
	}
	contributionID := request.PathValue("contributionID")
	existing, err := server.isr.Yaounde.GetPicture(request.Context(), contributionID)
	if err != nil {
		writeYaoundeError(response, err)
		return
	}
	zone, ok := server.resolveZone(existing.Zone)
	if !ok {
		writeError(response, http.StatusNotFound, "contribution zone is not a configured geofence zone")
		return
	}
	contribution, artifact, err := server.isr.Yaounde.DispatchPicture(request.Context(), contributionID, principal.Subject, zone)
	if err != nil {
		writeYaoundeError(response, err)
		return
	}
	server.telemetry.RecordYaoundeDispatch(request.Context(), "picture-dispatched")
	writeJSON(response, http.StatusOK, map[string]any{
		"contribution": contribution, "artifact": json.RawMessage(artifact),
	})
}

func (server *Server) yaoundeListPicture(response http.ResponseWriter, request *http.Request) {
	contributions, err := server.isr.Yaounde.ListPicture(request.Context())
	if err != nil {
		writeError(response, http.StatusInternalServerError, "list picture contributions")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"contributions": contributions})
}

func (server *Server) yaoundeAudit(response http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	var from, to time.Time
	var err error
	if raw := query.Get("from"); raw != "" {
		if from, err = time.Parse(time.RFC3339, raw); err != nil {
			writeError(response, http.StatusBadRequest, "from must be RFC3339")
			return
		}
	}
	if raw := query.Get("to"); raw != "" {
		if to, err = time.Parse(time.RFC3339, raw); err != nil {
			writeError(response, http.StatusBadRequest, "to must be RFC3339")
			return
		}
	}
	entries, err := server.isr.Yaounde.ListAudit(request.Context(), from, to)
	if err != nil {
		writeError(response, http.StatusInternalServerError, "list audit")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"entries": entries})
}
