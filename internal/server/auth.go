package server

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/munisp/blueeconomy-maritime-intelligence/internal/isr"
)

// Approved authentication modes. loopback_trusted_proxy is the local edge
// mode; keycloak_rs256 verifies Keycloak-issued RS256 bearer tokens against
// the realm JWKS. Any other mode fails closed at startup and per request.
const (
	AuthModeLoopbackTrustedProxy = "loopback_trusted_proxy"
	AuthModeKeycloakRS256        = "keycloak_rs256"
)

// AuthConfig is the validated authentication configuration.
type AuthConfig struct {
	Mode               string
	OIDCIssuer         string
	OIDCAudience       string
	OIDCJWKSURL        *url.URL
	OIDCCAFile         string
	OIDCRolesClientIDs []string
}

// LoadAuthConfig reads and validates the authentication environment
// fail-closed. In keycloak_rs256 mode the issuer, audience and JWKS URL are
// mandatory; loopback_trusted_proxy needs no additional settings.
func LoadAuthConfig(getenv func(string) string) (AuthConfig, error) {
	mode := strings.TrimSpace(getenv("AUTH_MODE"))
	config := AuthConfig{Mode: mode}
	switch mode {
	case AuthModeLoopbackTrustedProxy:
		return config, nil
	case AuthModeKeycloakRS256:
		config.OIDCIssuer = strings.TrimSpace(getenv("OIDC_ISSUER"))
		config.OIDCAudience = strings.TrimSpace(getenv("OIDC_AUDIENCE"))
		jwks := strings.TrimSpace(getenv("OIDC_JWKS_URL"))
		config.OIDCCAFile = strings.TrimSpace(getenv("OIDC_CA_FILE"))
		if clients := strings.TrimSpace(getenv("OIDC_ROLES_CLIENT_IDS")); clients != "" {
			config.OIDCRolesClientIDs = strings.Split(clients, ",")
		}
		if config.OIDCIssuer == "" || config.OIDCAudience == "" || jwks == "" {
			return AuthConfig{}, errors.New("keycloak_rs256 mode requires OIDC_ISSUER, OIDC_AUDIENCE and OIDC_JWKS_URL")
		}
		parsed, err := url.Parse(jwks)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return AuthConfig{}, errors.New("OIDC_JWKS_URL must be an https URL")
		}
		config.OIDCJWKSURL = parsed
		return config, nil
	default:
		return AuthConfig{}, fmt.Errorf("AUTH_MODE %q is not an approved mode", mode)
	}
}

// Authenticator verifies one request into a Principal (subject, roles,
// clearance).
type Authenticator interface {
	Authenticate(*http.Request) (isr.Principal, error)
}

// NewAuthenticator builds the authenticator for the configured mode.
func NewAuthenticator(config AuthConfig) (Authenticator, error) {
	switch config.Mode {
	case AuthModeLoopbackTrustedProxy:
		return loopbackAuthenticator{}, nil
	case AuthModeKeycloakRS256:
		return newOIDCAuthenticator(config)
	default:
		return nil, fmt.Errorf("authentication mode %q is not approved", config.Mode)
	}
}

// loopbackAuthenticator trusts only the loopback edge, which asserts the
// principal subject, roles and clearance through dedicated headers.
type loopbackAuthenticator struct{}

func (loopbackAuthenticator) Authenticate(request *http.Request) (isr.Principal, error) {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return isr.Principal{}, errors.New("request is not from the trusted local edge")
	}
	if strings.TrimSpace(request.Header.Get("X-Trusted-Proxy")) != "loopback" {
		return isr.Principal{}, errors.New("verified caller identity is required")
	}
	subject := strings.TrimSpace(request.Header.Get("X-Authenticated-Principal"))
	if subject == "" || len(subject) > 512 {
		return isr.Principal{}, errors.New("verified caller identity is required")
	}
	clearance, err := parseClearanceHeader(request.Header.Get("X-Authenticated-Clearance"))
	if err != nil {
		return isr.Principal{}, err
	}
	return isr.Principal{Subject: subject, Roles: parseRoleHeader(request.Header.Get("X-Authenticated-Roles")), Clearance: clearance}, nil
}

// parseClearanceHeader maps an asserted clearance header to a label. Absent
// means Unclassified (least privilege); an unknown label fails closed.
func parseClearanceHeader(value string) (isr.Classification, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return isr.ClassificationUnclassified, nil
	}
	return isr.ParseClassification(value)
}

func parseRoleHeader(value string) map[string]struct{} {
	return normalizeRoles(strings.Split(value, ","))
}

func normalizeRoles(raw []string) map[string]struct{} {
	roles := make(map[string]struct{}, len(raw))
	for _, value := range raw {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 128 || len(roles) >= 64 {
			continue
		}
		roles[value] = struct{}{}
	}
	return roles
}

// oidcAuthenticator verifies Keycloak RS256 bearer tokens against the realm
// JWKS (ported from blueeconomy-administration-service). Clearance is read
// from the "clearance" token claim; roles from realm_access.roles plus
// configured resource_access clients.
type oidcAuthenticator struct {
	issuer         string
	audience       string
	jwksURL        *url.URL
	rolesClientIDs []string
	client         *http.Client
	mu             sync.RWMutex
	keys           map[string]*rsa.PublicKey
	loadedAt       time.Time
}

func newOIDCAuthenticator(config AuthConfig) (*oidcAuthenticator, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if config.OIDCCAFile != "" {
		pemBytes, err := os.ReadFile(config.OIDCCAFile)
		if err != nil {
			return nil, fmt.Errorf("read OIDC CA file: %w", err)
		}
		pool, poolErr := x509.SystemCertPool()
		if poolErr != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("OIDC CA file did not contain a usable PEM certificate")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &oidcAuthenticator{
		issuer:         config.OIDCIssuer,
		audience:       config.OIDCAudience,
		jwksURL:        config.OIDCJWKSURL,
		rolesClientIDs: config.OIDCRolesClientIDs,
		client:         &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("JWKS redirects are not permitted") }},
		keys:           make(map[string]*rsa.PublicKey),
	}, nil
}

func (auth *oidcAuthenticator) Authenticate(request *http.Request) (isr.Principal, error) {
	value := strings.TrimSpace(request.Header.Get("Authorization"))
	parts := strings.SplitN(value, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
		return isr.Principal{}, errors.New("Bearer authorization is required")
	}
	token := strings.TrimSpace(parts[1])
	segments := strings.Split(token, ".")
	if len(segments) != 3 || segments[0] == "" || segments[1] == "" || segments[2] == "" {
		return isr.Principal{}, errors.New("JWT compact serialization is invalid")
	}
	headerBytes, err := decodeBase64URL(segments[0])
	if err != nil {
		return isr.Principal{}, errors.New("JWT header is invalid")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Alg != "RS256" || strings.TrimSpace(header.Kid) == "" {
		return isr.Principal{}, errors.New("JWT algorithm or key ID is invalid")
	}
	key, err := auth.key(header.Kid, true)
	if err != nil {
		return isr.Principal{}, err
	}
	signature, err := decodeBase64URL(segments[2])
	if err != nil {
		return isr.Principal{}, errors.New("JWT signature is invalid")
	}
	digest := sha256.Sum256([]byte(segments[0] + "." + segments[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return isr.Principal{}, errors.New("JWT signature verification failed")
	}
	payloadBytes, err := decodeBase64URL(segments[1])
	if err != nil {
		return isr.Principal{}, errors.New("JWT claims are invalid")
	}
	var claims tokenClaims
	decoder := json.NewDecoder(strings.NewReader(string(payloadBytes)))
	decoder.UseNumber()
	if err := decoder.Decode(&claims); err != nil {
		return isr.Principal{}, errors.New("JWT claims are invalid")
	}
	if claims.Issuer != auth.issuer || !audienceContains(claims.Audience, auth.audience) {
		return isr.Principal{}, errors.New("JWT issuer or audience is invalid")
	}
	now := time.Now().Unix()
	expires, err := claims.Expires.Int64()
	if err != nil || now >= expires {
		return isr.Principal{}, errors.New("JWT is expired or has no valid expiry")
	}
	if claims.NotBefore != "" {
		notBefore, parseErr := claims.NotBefore.Int64()
		if parseErr != nil || now < notBefore {
			return isr.Principal{}, errors.New("JWT is not yet valid")
		}
	}
	subject := strings.TrimSpace(claims.Subject)
	if subject == "" || len(subject) > 512 {
		return isr.Principal{}, errors.New("authenticated subject is required")
	}
	clearance, err := parseClearanceHeader(claims.Clearance)
	if err != nil {
		return isr.Principal{}, errors.New("JWT clearance claim is invalid")
	}
	return isr.Principal{Subject: subject, Roles: auth.extractRoles(claims), Clearance: clearance}, nil
}

type tokenClaims struct {
	Issuer      string          `json:"iss"`
	Subject     string          `json:"sub"`
	Audience    json.RawMessage `json:"aud"`
	Expires     json.Number     `json:"exp"`
	NotBefore   json.Number     `json:"nbf"`
	Clearance   string          `json:"clearance"`
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
}

func (auth *oidcAuthenticator) extractRoles(claims tokenClaims) map[string]struct{} {
	roles := normalizeRoles(claims.RealmAccess.Roles)
	for _, clientID := range auth.rolesClientIDs {
		access, ok := claims.ResourceAccess[clientID]
		if !ok {
			continue
		}
		for role := range normalizeRoles(access.Roles) {
			roles[role] = struct{}{}
		}
	}
	return roles
}

func (auth *oidcAuthenticator) key(kid string, refresh bool) (*rsa.PublicKey, error) {
	auth.mu.RLock()
	key := auth.keys[kid]
	fresh := time.Since(auth.loadedAt) < 5*time.Minute
	auth.mu.RUnlock()
	if key != nil && fresh {
		return key, nil
	}
	if !refresh {
		return nil, errors.New("JWT key is not trusted")
	}
	if err := auth.loadKeys(); err != nil {
		return nil, fmt.Errorf("load OIDC JWKS: %w", err)
	}
	auth.mu.RLock()
	defer auth.mu.RUnlock()
	if key := auth.keys[kid]; key != nil {
		return key, nil
	}
	return nil, errors.New("JWT key ID is not trusted")
}

func (auth *oidcAuthenticator) loadKeys() error {
	request, err := http.NewRequest(http.MethodGet, auth.jwksURL.String(), nil)
	if err != nil {
		return err
	}
	response, err := auth.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	var document struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return err
	}
	loaded := make(map[string]*rsa.PublicKey)
	for _, item := range document.Keys {
		if item.Kty != "RSA" || item.Use != "sig" || item.Alg != "RS256" || item.Kid == "" || item.N == "" || item.E == "" {
			continue
		}
		modulus, err := decodeBase64URL(item.N)
		if err != nil {
			continue
		}
		exponentBytes, err := decodeBase64URL(item.E)
		if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
			continue
		}
		exponent := 0
		for _, value := range exponentBytes {
			exponent = exponent<<8 | int(value)
		}
		if exponent < 3 || exponent%2 == 0 {
			continue
		}
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}
		if key.N.BitLen() < 2048 {
			continue
		}
		loaded[item.Kid] = key
	}
	if len(loaded) == 0 {
		return errors.New("JWKS contains no approved RSA signing keys")
	}
	auth.mu.Lock()
	auth.keys = loaded
	auth.loadedAt = time.Now()
	auth.mu.Unlock()
	return nil
}

func decodeBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func audienceContains(raw json.RawMessage, expected string) bool {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return single == expected
	}
	var multiple []string
	if json.Unmarshal(raw, &multiple) != nil {
		return false
	}
	for _, value := range multiple {
		if value == expected {
			return true
		}
	}
	return false
}
