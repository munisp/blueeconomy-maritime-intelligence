package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

// mutationCase describes one mutating route from the authoritative table and
// the roles that may call it.
type mutationCase struct {
	name         string
	path         string
	allowedRoles []string
}

func mutationCases() []mutationCase {
	return []mutationCase{
		{"incident create", "/v1/incidents", []string{isr.RoleISRAnalyst, isr.RoleISRWatchOfficer}},
		{"incident correlate", "/v1/incidents/inc-1/correlations", []string{isr.RoleISRAnalyst, isr.RoleISRWatchOfficer}},
		{"incident assign", "/v1/incidents/inc-1/assignment", []string{isr.RoleISRAnalyst, isr.RoleISRWatchOfficer}},
		{"incident acknowledge (SOS)", "/v1/incidents/inc-1/acknowledge", []string{isr.RoleISRAnalyst, isr.RoleISRWatchOfficer}},
		{"incident resolve", "/v1/incidents/inc-1/resolve", []string{isr.RoleISRAnalyst, isr.RoleISRWatchOfficer}},
		{"feed-source register", "/v1/feed-sources", []string{isr.RoleISRAdmin}},
		{"feed-source revoke", "/v1/feed-sources/src-1/revoke", []string{isr.RoleISRAdmin}},
		{"feed-source rotate-key", "/v1/feed-sources/src-1/rotate-key", []string{isr.RoleISRAdmin}},
		{"feed event admit", "/v1/feed-events/admit", []string{isr.RoleISRFeedIngest}},
		{"feed incident admit", "/v1/feed-events/admit-incident", []string{isr.RoleISRFeedIngest}},
		{"detection admit", "/v1/isr/detections:admit", []string{isr.RoleISRFeedIngest}},
		{"outcome propose", "/v1/outcomes", []string{isr.RoleISRAnalyst}},
		{"outcome confirm", "/v1/outcomes/entry-1/confirm", []string{isr.RoleISRAdjudicator}},
	}
}

// loopbackRequest builds an authenticated request as asserted by the trusted
// local edge. roles == "" leaves the role header absent.
func loopbackRequest(method, path, subject, roles, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:9000"
	request.Header.Set("X-Trusted-Proxy", "loopback")
	request.Header.Set("X-Authenticated-Principal", subject)
	if roles != "" {
		request.Header.Set("X-Authenticated-Roles", roles)
	}
	return request
}

func newRoleTestHandler() http.Handler {
	return New(Config{Authenticator: loopbackAuthenticator{}})
}

func serve(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// MI-1 regression: an unrecognized (garbage/typo) or absent role must be
// denied on EVERY mutating route. Previously IsReadOnly failed open and no
// per-route role check existed, so such tokens could mutate everything.
func TestMutationsDeniedForUnknownAbsentAndLegacyRoles(t *testing.T) {
	handler := newRoleTestHandler()
	deniedPrincipals := map[string]string{
		"garbage role":       "garbage-role",
		"typo role":          "isr-adminn",
		"absent role":        "",
		"legacy nimasa role": isr.RoleNIMASAOfficer, // read-side legacy roles retain no mutation rights
		"legacy nn role":     isr.RoleNNOfficer,
		"read-only observer": isr.RoleDefenceHQObserver,
		"auditor":            isr.RoleAuditor,
	}
	for _, tc := range mutationCases() {
		for name, roles := range deniedPrincipals {
			recorder := serve(handler, loopbackRequest(http.MethodPost, tc.path, "subject-"+name, roles, ""))
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("%s: %s expected 403, got %d", tc.name, name, recorder.Code)
			}
		}
	}
}

// MI-1 regression: every mutating route is reachable by its designated
// role(s). The gate must pass the request through to the handler; with the
// test configuration (no stores wired, empty body) handlers answer 400 or
// 503 — never 401/403.
func TestMutationsReachableByDesignatedRoles(t *testing.T) {
	handler := newRoleTestHandler()
	for _, tc := range mutationCases() {
		for _, role := range tc.allowedRoles {
			recorder := serve(handler, loopbackRequest(http.MethodPost, tc.path, "subject-"+role, role, ""))
			if recorder.Code == http.StatusUnauthorized || recorder.Code == http.StatusForbidden {
				t.Fatalf("%s: designated role %s was denied with %d", tc.name, role, recorder.Code)
			}
		}
	}
}

// MI-1 regression: a designated role for one route does not unlock any other
// route (least privilege per route), including the outcome dual control
// split (isr-analyst proposes, isr-adjudicator confirms — never vice versa).
func TestMutationRolesAreRouteSpecific(t *testing.T) {
	handler := newRoleTestHandler()
	allMutationRoles := []string{isr.RoleISRAdmin, isr.RoleISRFeedIngest, isr.RoleISRAnalyst, isr.RoleISRWatchOfficer, isr.RoleISRAdjudicator}
	for _, tc := range mutationCases() {
		allowed := map[string]bool{}
		for _, role := range tc.allowedRoles {
			allowed[role] = true
		}
		for _, role := range allMutationRoles {
			if allowed[role] {
				continue
			}
			recorder := serve(handler, loopbackRequest(http.MethodPost, tc.path, "subject-"+role, role, ""))
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("%s: non-designated role %s expected 403, got %d", tc.name, role, recorder.Code)
			}
		}
	}
}

// MI-1 regression: read behavior is unchanged — read-only and unknown-role
// principals are not blocked at the middleware for GET (service-layer
// role/clearance gates decide); health probes stay public.
func TestReadBehaviorUnchanged(t *testing.T) {
	handler := newRoleTestHandler()
	for _, roles := range []string{isr.RoleDefenceHQObserver, isr.RoleInsurerAggregator, "garbage-role", isr.RoleISRAnalyst} {
		recorder := serve(handler, loopbackRequest(http.MethodGet, "/v1/isr/detections", "reader", roles, ""))
		// nil ISRDeps answers 503 after the middleware; the middleware itself
		// must not deny GETs (401/403).
		if recorder.Code != http.StatusServiceUnavailable {
			t.Fatalf("GET with roles %q: expected 503 past the middleware, got %d", roles, recorder.Code)
		}
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		recorder := serve(handler, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s expected 200, got %d", path, recorder.Code)
		}
	}
}

// MI-1 structural guard: the authoritative table must cover exactly the
// mutating routes registered by New, and registering a mutation route without
// a table entry must fail closed at startup.
func TestAuthoritativeTableCoversEveryRegisteredMutation(t *testing.T) {
	registered := map[string]bool{}
	mux := http.NewServeMux()
	for pattern := range mutationRoleRequirements {
		if registered[pattern] {
			t.Fatalf("duplicate pattern %s", pattern)
		}
		registered[pattern] = true
		if !strings.HasPrefix(pattern, "POST /v1/") {
			t.Fatalf("non-mutation pattern in table: %s", pattern)
		}
		// The pattern must be a valid ServeMux pattern.
		mux.HandleFunc(pattern, func(http.ResponseWriter, *http.Request) {})
	}
	defer func() {
		if recover() == nil {
			t.Fatal("registering a mutation route without a table entry must panic (fail-closed)")
		}
	}()
	requireMutationRoles(http.NewServeMux(), "POST /v1/ungoverned", func(http.ResponseWriter, *http.Request) {})
}
