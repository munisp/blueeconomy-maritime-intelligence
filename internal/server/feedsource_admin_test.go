package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFeedSourceAdminRoutesRequireDedicatedRole is the C1 regression: feed
// trust-anchor administration must be denied to every principal without the
// dedicated feed-source-admin role, including other non-read-only writers.
func TestFeedSourceAdminRoutesRequireDedicatedRole(t *testing.T) {
	handler := New(Config{Authenticator: loopbackAuthenticator{}})
	for _, route := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/feed-sources"},
		{http.MethodPost, "/v1/feed-sources/ais-1/revoke"},
		{http.MethodPost, "/v1/feed-sources/ais-1/rotate-key"},
	} {
		// Anonymous: 401.
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(route.method, route.path, strings.NewReader("{}")))
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous %s = %d, want 401", route.path, response.Code)
		}
		// Non-admin writer (marine-police incident creator): 403.
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, loopbackRequest(t, route.method, route.path, "officer-1", "marine-police"))
		if response.Code != http.StatusForbidden {
			t.Fatalf("marine-police %s = %d, want 403", route.path, response.Code)
		}
		// Read-only principal: 403 (mutating denial precedes the role gate).
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, loopbackRequest(t, route.method, route.path, "auditor-1", "auditor"))
		if response.Code != http.StatusForbidden {
			t.Fatalf("auditor %s = %d, want 403", route.path, response.Code)
		}
	}
}
