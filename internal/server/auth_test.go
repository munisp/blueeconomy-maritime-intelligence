package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

func TestLoadAuthConfigFailsClosed(t *testing.T) {
	if _, err := LoadAuthConfig(func(string) string { return "" }); err == nil {
		t.Fatal("empty AUTH_MODE accepted")
	}
	values := map[string]string{"AUTH_MODE": "keycloak_rs256"}
	if _, err := LoadAuthConfig(func(key string) string { return values[key] }); err == nil {
		t.Fatal("keycloak mode without issuer/audience/jwks accepted")
	}
	values["OIDC_ISSUER"] = "https://keycloak.example/realms/blueeconomy"
	values["OIDC_AUDIENCE"] = "maritime-intelligence"
	values["OIDC_JWKS_URL"] = "http://keycloak.example/jwks"
	if _, err := LoadAuthConfig(func(key string) string { return values[key] }); err == nil {
		t.Fatal("non-https JWKS URL accepted")
	}
	values["OIDC_JWKS_URL"] = "https://keycloak.example/jwks"
	config, err := LoadAuthConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if config.Mode != AuthModeKeycloakRS256 {
		t.Fatal("mode not preserved")
	}
	if _, err := LoadAuthConfig(func(key string) string {
		if key == "AUTH_MODE" {
			return AuthModeLoopbackTrustedProxy
		}
		return ""
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLoopbackAuthenticator(t *testing.T) {
	auth := loopbackAuthenticator{}
	request := httptest.NewRequest(http.MethodGet, "/v1/isr/detections", nil)
	request.RemoteAddr = "10.0.0.5:1234"
	if _, err := auth.Authenticate(request); err == nil {
		t.Fatal("non-loopback source accepted")
	}
	request.RemoteAddr = "127.0.0.1:1234"
	if _, err := auth.Authenticate(request); err == nil {
		t.Fatal("missing trusted proxy headers accepted")
	}
	request.Header.Set("X-Trusted-Proxy", "loopback")
	request.Header.Set("X-Authenticated-Principal", "nn-officer-1")
	request.Header.Set("X-Authenticated-Roles", "nn-officer, marine-police")
	request.Header.Set("X-Authenticated-Clearance", "secret")
	principal, err := auth.Authenticate(request)
	if err != nil {
		t.Fatal(err)
	}
	if principal.Clearance != isr.ClassificationSecret || !principal.HasRole("nn-officer") {
		t.Fatalf("unexpected principal: %+v", principal)
	}
	if principal.IsReadOnly() {
		t.Fatal("nn-officer must not be read-only")
	}
	// Missing clearance header defaults to Unclassified (least privilege).
	request.Header.Del("X-Authenticated-Clearance")
	principal, err = auth.Authenticate(request)
	if err != nil || principal.Clearance != isr.ClassificationUnclassified {
		t.Fatal("absent clearance must default to Unclassified")
	}
	// Unknown clearance label fails closed.
	request.Header.Set("X-Authenticated-Clearance", "cosmic")
	if _, err := auth.Authenticate(request); err == nil {
		t.Fatal("unknown clearance label accepted")
	}
	// Read-only observer principal is denied mutations generically.
	request.Header.Del("X-Authenticated-Clearance")
	request.Header.Set("X-Authenticated-Roles", "onsa-observer")
	principal, err = auth.Authenticate(request)
	if err != nil || !principal.IsReadOnly() {
		t.Fatal("onsa-observer must be read-only")
	}
}

// jwksFixture serves a JWKS document for a generated RSA key.
type jwksFixture struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
}

func newJWKSFixture(t *testing.T) *jwksFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &jwksFixture{key: key, kid: "test-key-1"}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
		response.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(response, `{"keys":[{"kty":"RSA","kid":%q,"use":"sig","alg":"RS256","n":%q,"e":%q}]}`, fixture.kid, n, e)
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (fixture *jwksFixture) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"alg":"RS256","kid":%q}`, fixture.kid)))
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	digest := sha256.Sum256([]byte(header + "." + payload))
	signature, err := rsa.SignPKCS1v15(rand.Reader, fixture.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestOIDCAuthenticator(t *testing.T) {
	fixture := newJWKSFixture(t)
	jwksURL, err := url.Parse(fixture.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := newOIDCAuthenticator(AuthConfig{
		Mode: AuthModeKeycloakRS256, OIDCIssuer: "https://keycloak.example/realms/blueeconomy",
		OIDCAudience: "maritime-intelligence", OIDCJWKSURL: jwksURL, OIDCCAFile: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	auth.client = fixture.server.Client()
	claims := map[string]any{
		"iss": "https://keycloak.example/realms/blueeconomy", "sub": "kc-nimasa-1",
		"aud": "maritime-intelligence", "exp": time.Now().Add(5 * time.Minute).Unix(),
		"clearance":    "CONFIDENTIAL",
		"realm_access": map[string]any{"roles": []string{"nimasa-officer"}},
	}
	token := fixture.sign(t, claims)
	request := httptest.NewRequest(http.MethodGet, "/v1/isr/detections", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	principal, err := auth.Authenticate(request)
	if err != nil {
		t.Fatal(err)
	}
	if principal.Subject != "kc-nimasa-1" || principal.Clearance != isr.ClassificationConfidential || !principal.HasRole("nimasa-officer") {
		t.Fatalf("unexpected principal: %+v", principal)
	}

	// Wrong audience fails.
	badAud := fixture.sign(t, map[string]any{
		"iss": "https://keycloak.example/realms/blueeconomy", "sub": "kc-x",
		"aud": "other-service", "exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	request = httptest.NewRequest(http.MethodGet, "/v1/isr/detections", nil)
	request.Header.Set("Authorization", "Bearer "+badAud)
	if _, err := auth.Authenticate(request); err == nil {
		t.Fatal("wrong audience accepted")
	}
	// Expired token fails.
	expired := fixture.sign(t, map[string]any{
		"iss": "https://keycloak.example/realms/blueeconomy", "sub": "kc-x",
		"aud": "maritime-intelligence", "exp": time.Now().Add(-time.Minute).Unix(),
	})
	request = httptest.NewRequest(http.MethodGet, "/v1/isr/detections", nil)
	request.Header.Set("Authorization", "Bearer "+expired)
	if _, err := auth.Authenticate(request); err == nil {
		t.Fatal("expired token accepted")
	}
	// Invalid clearance claim fails closed.
	badClearance := fixture.sign(t, map[string]any{
		"iss": "https://keycloak.example/realms/blueeconomy", "sub": "kc-x",
		"aud": "maritime-intelligence", "exp": time.Now().Add(5 * time.Minute).Unix(),
		"clearance": "cosmic",
	})
	request = httptest.NewRequest(http.MethodGet, "/v1/isr/detections", nil)
	request.Header.Set("Authorization", "Bearer "+badClearance)
	if _, err := auth.Authenticate(request); err == nil {
		t.Fatal("invalid clearance claim accepted")
	}
	// Token signed by an unknown key fails.
	other := newJWKSFixture(t)
	forged := other.sign(t, claims)
	request = httptest.NewRequest(http.MethodGet, "/v1/isr/detections", nil)
	request.Header.Set("Authorization", "Bearer "+forged)
	if _, err := auth.Authenticate(request); err == nil {
		t.Fatal("token from an untrusted key accepted")
	}
}

func TestRequireAuthenticationMiddleware(t *testing.T) {
	handler := New(Config{
		Authenticator: loopbackAuthenticator{},
	})
	// Unauthenticated /v1 request: 401.
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/isr/detections", nil)
	request.RemoteAddr = "127.0.0.1:9000"
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recorder.Code)
	}
	// Read-only observer attempting a mutation: 403.
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/v1/isr/detections:admit", nil)
	request.RemoteAddr = "127.0.0.1:9000"
	request.Header.Set("X-Trusted-Proxy", "loopback")
	request.Header.Set("X-Authenticated-Principal", "observer-1")
	request.Header.Set("X-Authenticated-Roles", "defence-hq-observer")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for read-only mutation, got %d", recorder.Code)
	}
	// healthz and readyz stay unauthenticated.
	for _, path := range []string{"/healthz", "/readyz"} {
		recorder = httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s expected 200, got %d", path, recorder.Code)
		}
	}
}
