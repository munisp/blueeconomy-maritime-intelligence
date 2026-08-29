package server

import (
	"net/http"
	"testing"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

// MI-2 regression: registration must never self-activate. A body carrying
// active:true is rejected before any store write, even for an isr-admin.
func TestRegisterFeedSourceRejectsSelfActivation(t *testing.T) {
	handler := newRoleTestHandler(t)
	for _, body := range []string{
		`{"source_id":"src-9","source_kind":"AIS","authority":"auth-1","public_key_base64":"AAAA","active":true}`,
	} {
		recorder := serve(handler, loopbackRequest(http.MethodPost, "/v1/feed-sources", "admin-1", isr.RoleISRAdmin, body))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("self-activating registration expected 400, got %d", recorder.Code)
		}
	}
}

// MI-2 regression: the activation endpoint exists and is role-gated like the
// other feed-source administration routes (the maker-checker split itself is
// enforced in the store; see feed_activation_integration_test.go).
func TestActivateFeedSourceRouteGated(t *testing.T) {
	handler := newRoleTestHandler(t)
	// Unauthenticated: 401.
	recorder := serve(handler, func() *http.Request {
		request := loopbackRequest(http.MethodPost, "/v1/feed-sources/src-1/activate", "admin-1", isr.RoleISRAdmin, "")
		request.RemoteAddr = "10.0.0.5:9000" // not loopback: authentication must fail
		return request
	}())
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated activation expected 401, got %d", recorder.Code)
	}
	// Wrong role (the ingest service identity may not administer sources): 403.
	recorder = serve(handler, loopbackRequest(http.MethodPost, "/v1/feed-sources/src-1/activate", "ingest-1", isr.RoleISRFeedIngest, ""))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("non-admin activation expected 403, got %d", recorder.Code)
	}
}
