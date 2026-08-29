//go:build feedintegration

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/incident"
	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

// openServerIntegrationStore mirrors the migration convention of the
// incident/isr integration suites: DATABASE_URL points at the local stack,
// MIGRATION_PATH lists the migrations unless SKIP_MIGRATION=true.
func openServerIntegrationStore(t *testing.T) *incident.Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	store, err := incident.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if os.Getenv("SKIP_MIGRATION") != "true" {
		for _, migrationPath := range strings.Split(os.Getenv("MIGRATION_PATH"), ",") {
			migration, readErr := os.ReadFile(filepath.Clean(strings.TrimSpace(migrationPath)))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if execErr := store.Exec(ctx, string(migration)); execErr != nil {
				t.Fatal(execErr)
			}
		}
	}
	return store
}

func integrationRequest(t *testing.T, method, path, subject, roles, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = "127.0.0.1:9000"
	request.Header.Set("X-Trusted-Proxy", "loopback")
	request.Header.Set("X-Authenticated-Principal", subject)
	request.Header.Set("X-Authenticated-Roles", roles)
	return request
}

func call(t *testing.T, handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// MI-2 + MI-3 end-to-end regression over HTTP: self-registered sources stay
// pending and cannot admit, the registrar cannot self-activate, admission
// denials are audit-logged, and revoke/rotate audit attribution always comes
// from the verified token subject — never from the request body.
func TestFeedSourceLifecycleAndAttributionOverHTTP(t *testing.T) {
	store := openServerIntegrationStore(t)
	handler := New(Config{Store: store, Authenticator: loopbackAuthenticator{}})
	ctx := context.Background()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyBase64 := base64.RawStdEncoding.EncodeToString(publicKey)
	registrar := "registrar-http"
	sourceID := "http-lifecycle-feed"

	// Registration (isr-admin) records the verified registrar and stays PENDING.
	body := fmt.Sprintf(`{"source_id":%q,"source_kind":"AIS","authority":"local-authority","public_key_base64":%q}`, sourceID, keyBase64)
	recorder := call(t, handler, integrationRequest(t, http.MethodPost, "/v1/feed-sources", registrar, isr.RoleISRAdmin, body))
	if recorder.Code != http.StatusCreated || !strings.Contains(recorder.Body.String(), "pending_activation") {
		t.Fatalf("registration expected 201 pending_activation, got %d %s", recorder.Code, recorder.Body.String())
	}
	var registeredBy string
	var active bool
	if err := store.Pool().QueryRow(ctx, `SELECT registered_by, active FROM maritime_feed_sources WHERE source_id=$1`, sourceID).Scan(&registeredBy, &active); err != nil {
		t.Fatal(err)
	}
	if registeredBy != registrar || active {
		t.Fatalf("registration must persist registrar %q and stay pending, got registrar=%q active=%v", registrar, registeredBy, active)
	}

	// Forged event from the pending source: rejected (403) and audit-logged.
	payload := []byte(`{"mmsi":"636019999"}`)
	eventID := "http-forged-event"
	admitBody := fmt.Sprintf(`{"source_id":%q,"source_event_id":%q,"payload_base64":%q,"signature_base64":%q}`,
		sourceID, eventID,
		base64.StdEncoding.EncodeToString(payload),
		incident.EncodeFeedSignature(sourceID, eventID, payload, privateKey))
	recorder = call(t, handler, integrationRequest(t, http.MethodPost, "/v1/feed-events/admit", "ingest-http", isr.RoleISRFeedIngest, admitBody))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("pending-source admission expected 403, got %d", recorder.Code)
	}
	var denials int
	if err := store.Pool().QueryRow(ctx, `SELECT count(*) FROM maritime_feed_admission_denials WHERE source_id=$1 AND reason='source-not-active'`, sourceID).Scan(&denials); err != nil {
		t.Fatal(err)
	}
	if denials != 1 {
		t.Fatalf("pending-source denial not audit-logged, count=%d", denials)
	}

	// The registrar cannot self-activate (maker-checker): 409.
	recorder = call(t, handler, integrationRequest(t, http.MethodPost, "/v1/feed-sources/"+sourceID+"/activate", registrar, isr.RoleISRAdmin, ""))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("registrar self-activation expected 409, got %d", recorder.Code)
	}
	// A distinct isr-admin activates; the admission then succeeds.
	activator := "activator-http"
	recorder = call(t, handler, integrationRequest(t, http.MethodPost, "/v1/feed-sources/"+sourceID+"/activate", activator, isr.RoleISRAdmin, ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("maker-checker activation expected 200, got %d %s", recorder.Code, recorder.Body.String())
	}
	var auditRegistrar, auditActivator string
	if err := store.Pool().QueryRow(ctx, `SELECT registered_by, activated_by FROM maritime_feed_source_activations WHERE source_id=$1`, sourceID).Scan(&auditRegistrar, &auditActivator); err != nil {
		t.Fatal(err)
	}
	if auditRegistrar != registrar || auditActivator != activator {
		t.Fatalf("activation audit wrong: registrar=%q activator=%q", auditRegistrar, auditActivator)
	}
	recorder = call(t, handler, integrationRequest(t, http.MethodPost, "/v1/feed-events/admit", "ingest-http", isr.RoleISRFeedIngest, admitBody))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("activated-source admission expected 201, got %d", recorder.Code)
	}

	// MI-3: body-supplied rotated_by is ignored; the audit shows the token subject.
	newPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rotationPrincipal := "key-admin-http"
	rotateBody := fmt.Sprintf(`{"public_key_base64":%q,"grace_until":%q,"rotated_by":"mallory-body-forgery"}`,
		base64.RawStdEncoding.EncodeToString(newPublicKey), time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	recorder = call(t, handler, integrationRequest(t, http.MethodPost, "/v1/feed-sources/"+sourceID+"/rotate-key", rotationPrincipal, isr.RoleISRAdmin, rotateBody))
	if recorder.Code != http.StatusOK {
		t.Fatalf("rotation expected 200, got %d %s", recorder.Code, recorder.Body.String())
	}
	var rotatedBy string
	if err := store.Pool().QueryRow(ctx, `SELECT rotated_by FROM maritime_feed_source_key_rotations WHERE source_id=$1`, sourceID).Scan(&rotatedBy); err != nil {
		t.Fatal(err)
	}
	if rotatedBy != rotationPrincipal {
		t.Fatalf("rotation audit must show token subject %q, got %q (body-supplied actor must be ignored)", rotationPrincipal, rotatedBy)
	}

	// MI-3: body-supplied revoked_by is ignored; the audit shows the token subject.
	revocationPrincipal := "security-admin-http"
	recorder = call(t, handler, integrationRequest(t, http.MethodPost, "/v1/feed-sources/"+sourceID+"/revoke", revocationPrincipal, isr.RoleISRAdmin, `{"reason":"key-compromise","revoked_by":"mallory-body-forgery"}`))
	if recorder.Code != http.StatusOK {
		t.Fatalf("revocation expected 200, got %d %s", recorder.Code, recorder.Body.String())
	}
	var revokedBy string
	if err := store.Pool().QueryRow(ctx, `SELECT revoked_by FROM maritime_feed_source_revocations WHERE source_id=$1`, sourceID).Scan(&revokedBy); err != nil {
		t.Fatal(err)
	}
	if revokedBy != revocationPrincipal {
		t.Fatalf("revocation audit must show token subject %q, got %q (body-supplied actor must be ignored)", revocationPrincipal, revokedBy)
	}
}
