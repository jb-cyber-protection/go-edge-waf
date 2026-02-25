package logging

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"time"
)

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// RequestLogger returns middleware that logs one JSON event per request.
func RequestLogger(l *Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			rw := &responseWriter{ResponseWriter: w, statusCode: 200}

			requestID := newRequestID()
			remoteIP := clientIP(r)

			// Put request_id in response header (useful for debugging)
			rw.Header().Set("X-Request-Id", requestID)

			next.ServeHTTP(rw, r)

			dur := time.Since(start)

			l.Log(Event{
				"request_id":  requestID,
				"remote_ip":   remoteIP,
				"method":      r.Method,
				"path":        r.URL.Path,
				"status":      rw.statusCode,
				"duration_ms": dur.Milliseconds(),
				"user_agent":  r.UserAgent(),
			})
		})
	}
}

func newRequestID() string {
	// 16 random bytes => 32 hex chars
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func clientIP(r *http.Request) string {
	// If later you add proxy headers, you can extend here.
	// For local development, RemoteAddr is enough.
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
