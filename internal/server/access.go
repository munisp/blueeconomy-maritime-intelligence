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
