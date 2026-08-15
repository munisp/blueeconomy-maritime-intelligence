package server

import (
	"net"
	"net/http"
	"strings"
)

const AuthModeLoopbackTrustedProxy = "loopback_trusted_proxy"

func requireAuthentication(mode string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if mode != AuthModeLoopbackTrustedProxy {
			writeError(response, http.StatusInternalServerError, "authentication mode is not approved")
			return
		}
		host, _, err := net.SplitHostPort(request.RemoteAddr)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			writeError(response, http.StatusForbidden, "request is not from the trusted local edge")
			return
		}
		if strings.TrimSpace(request.Header.Get("X-Trusted-Proxy")) != "loopback" || strings.TrimSpace(request.Header.Get("X-Authenticated-Principal")) == "" {
			writeError(response, http.StatusUnauthorized, "verified caller identity is required")
			return
		}
		next.ServeHTTP(response, request)
	})
}
