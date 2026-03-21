// Package middleware provides HTTP middleware for CyberArmor enforcement.
package middleware

import (
	"net/http"
	"time"
)

// CyberArmorHandler wraps an http.Handler with CyberArmor enforcement.
type CyberArmorHandler struct {
	next   http.Handler
	client interface {
		NewRoundTripper(http.RoundTripper) http.RoundTripper
	}
}

// Handler creates a new HTTP middleware.
func Handler(next http.Handler, client interface {
	NewRoundTripper(http.RoundTripper) http.RoundTripper
}) http.Handler {
	return &CyberArmorHandler{next: next, client: client}
}

func (h *CyberArmorHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Set("X-CyberArmor-Request-Id", generateRequestID())
	start := time.Now()
	rw := &responseWriter{ResponseWriter: w, status: 200}
	h.next.ServeHTTP(rw, r)
	_ = time.Since(start)
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func generateRequestID() string {
	// Simple time-based ID
	return time.Now().Format("20060102150405.000000")
}
