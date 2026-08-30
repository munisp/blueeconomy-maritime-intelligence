package server

import (
	"net/http"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

// mutationRoleRequirements is the single authoritative route → required-role
// table for every mutating endpoint. The Go 1.22 ServeMux pattern is the
// key; the value lists the verified-token roles allowed to call it (any one
// suffices). Read endpoints are intentionally absent: their role and
// clearance gates live in the service layer (isr.Principal.CanReadTracks /
// CanReadOutcomeAggregates) and are unchanged.
//
// Dual control is preserved by construction: outcome proposals require
// isr-analyst while confirmations require the distinct isr-adjudicator role,
// on top of the ledger's proposer≠confirmer enforcement. Feed-source
// administration (register/activate/revoke/rotate) is isr-admin only; the
// maker-checker activation rule (registrar ≠ activator) is enforced in the
// incident store.
var mutationRoleRequirements = map[string][]string{
	"POST /v1/incidents":                           {isr.RoleISRAnalyst, isr.RoleISRWatchOfficer},
	"POST /v1/incidents/{incidentID}/correlations": {isr.RoleISRAnalyst, isr.RoleISRWatchOfficer},
	"POST /v1/incidents/{incidentID}/assignment":   {isr.RoleISRAnalyst, isr.RoleISRWatchOfficer},
	"POST /v1/incidents/":                          {isr.RoleISRAnalyst, isr.RoleISRWatchOfficer}, // transitions incl. SOS acknowledge
	"POST /v1/feed-sources":                        {isr.RoleISRAdmin},
	"POST /v1/feed-sources/{sourceID}/activate":    {isr.RoleISRAdmin},
	"POST /v1/feed-sources/{sourceID}/revoke":      {isr.RoleISRAdmin},
	"POST /v1/feed-sources/{sourceID}/rotate-key":  {isr.RoleISRAdmin},
	"POST /v1/feed-events/admit":                   {isr.RoleISRFeedIngest},
	"POST /v1/feed-events/admit-incident":          {isr.RoleISRFeedIngest},
	"POST /v1/isr/detections:admit":                {isr.RoleISRFeedIngest},
	"POST /v1/outcomes":                            {isr.RoleISRAnalyst},
	"POST /v1/outcomes/{entryID}/confirm":          {isr.RoleISRAdjudicator},

	// Phase 8: Yaounde gateway.
	"POST /v1/yaounde/peers":                             {isr.RoleYaoundeRegistrar},
	"POST /v1/yaounde/peers/{peerID}/activate":           {isr.RoleYaoundeApprover},
	"POST /v1/yaounde/peers/{peerID}/suspend":            {isr.RoleYaoundeRegistrar, isr.RoleYaoundeApprover},
	"POST /v1/yaounde/peers/{peerID}/revoke":             {isr.RoleYaoundeRegistrar, isr.RoleYaoundeApprover},
	"POST /v1/yaounde/releases":                          {isr.RoleYaoundeReleaser},
	"POST /v1/yaounde/releases/{releaseID}/approve":      {isr.RoleYaoundeApprover},
	"POST /v1/yaounde/releases/{releaseID}/dispatch":     {isr.RoleYaoundeReleaser},
	"POST /v1/yaounde/releases/{releaseID}/withdraw":     {isr.RoleYaoundeReleaser},
	"POST /v1/yaounde/releases/{releaseID}/acknowledge":  {isr.RoleYaoundeReleaser, isr.RoleYaoundeApprover},
	"POST /v1/yaounde/inbound/admit":                     {isr.RoleYaoundeRegistrar},
	"POST /v1/yaounde/inbound/{reportID}/correlate":      {isr.RoleYaoundeApprover},
	"POST /v1/yaounde/inbound/{reportID}/reject":         {isr.RoleYaoundeApprover},
	"POST /v1/yaounde/picture/prepare":                   {isr.RoleYaoundeReleaser},
	"POST /v1/yaounde/picture/{contributionID}/approve":  {isr.RoleYaoundeApprover},
	"POST /v1/yaounde/picture/{contributionID}/dispatch": {isr.RoleYaoundeReleaser},

	// Phase 8: SAR C2 console.
	"POST /v1/sar/cases":                                          {isr.RoleSARWatchkeeper, isr.RoleSARCoordinator},
	"POST /v1/sar/cases/{caseID}/phase":                           {isr.RoleSARCoordinator},
	"POST /v1/sar/cases/{caseID}/stage":                           {isr.RoleSARCoordinator},
	"POST /v1/sar/cases/{caseID}/datum":                           {isr.RoleSARWatchkeeper, isr.RoleSARCoordinator},
	"POST /v1/sar/resources":                                      {isr.RoleSARResourcer},
	"POST /v1/sar/resources/{resourceID}/status":                  {isr.RoleSARResourcer},
	"POST /v1/sar/cases/{caseID}/taskings":                        {isr.RoleSARCoordinator},
	"POST /v1/sar/cases/{caseID}/taskings/{taskingID}/transition": {isr.RoleSARCoordinator},
	"POST /v1/sar/cases/{caseID}/sitrep":                          {isr.RoleSARCoordinator},
	"POST /v1/sar/cases/{caseID}/sos-acknowledge":                 {isr.RoleSARCoordinator},
	"POST /v1/sar/cases/{caseID}/sos-resolve":                     {isr.RoleSARCoordinator},
}

// requireMutationRoles registers pattern → handler with the authoritative
// role gate applied. Every mutating route MUST be registered through this
// helper; the helper fails closed (panics at startup) if the pattern has no
// entry in mutationRoleRequirements, so a new mutation route cannot ship
// without an explicit role decision.
func requireMutationRoles(api *http.ServeMux, pattern string, handler http.HandlerFunc) {
	roles, ok := mutationRoleRequirements[pattern]
	if !ok || len(roles) == 0 {
		panic("mutating route registered without an authoritative role requirement: " + pattern)
	}
	api.HandleFunc(pattern, func(response http.ResponseWriter, request *http.Request) {
		principal, ok := principalFrom(request)
		if !ok {
			writeError(response, http.StatusUnauthorized, "authentication failed")
			return
		}
		if !principal.HasAnyRole(roles...) {
			writeError(response, http.StatusForbidden, "insufficient role for this operation")
			return
		}
		handler(response, request)
	})
}
