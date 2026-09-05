package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// loopbackRequest builds a request the loopback trusted-proxy authenticator
// accepts, carrying the given principal subject and roles.
func loopbackRequest(t *testing.T, method, path, subject, roles string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	request.RemoteAddr = "127.0.0.1:4321"
	request.Header.Set("X-Trusted-Proxy", "loopback")
	request.Header.Set("X-Authenticated-Principal", subject)
	request.Header.Set("X-Authenticated-Roles", roles)
	return request
}

// TestMetricsRequiresAuthentication is the S3 regression: /metrics leaks
// operational internals and must never be anonymous.
func TestMetricsRequiresAuthentication(t *testing.T) {
	metrics := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("# metrics"))
	})
	handler := New(Config{Authenticator: loopbackAuthenticator{}, Metrics: metrics})

	// Anonymous: 401, metrics body not leaked.
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous /metrics = %d, want 401", response.Code)
	}

	// Authenticated: 200.
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, loopbackRequest(t, http.MethodGet, "/metrics", "ops-1", "nn-officer"))
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated /metrics = %d, want 200", response.Code)
	}
}

// TestSecurityHeaders is the S5 regression: every response, including
// errors, carries the platform HTTP security headers.
func TestSecurityHeaders(t *testing.T) {
	handler := New(Config{Authenticator: loopbackAuthenticator{}})
	for _, path := range []string{"/healthz", "/v1/incidents/", "/does-not-exist"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		for header, want := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"Referrer-Policy":        "no-referrer",
		} {
			if got := response.Header().Get(header); got != want {
				t.Fatalf("%s %s = %q, want %q", path, header, got, want)
			}
		}
		if got := response.Header().Get("Strict-Transport-Security"); got == "" {
			t.Fatalf("%s missing Strict-Transport-Security", path)
		}
	}
}
