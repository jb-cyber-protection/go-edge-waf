package logging

import (
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

// RequestLogger logs one JSON event per request.
// If a request_id already exists in context, it reuses it.
func RequestLogger(l *Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			rw := &responseWriter{ResponseWriter: w, statusCode: 200}

			requestID, ok := GetRequestID(r)
			if !ok {
				requestID = NewRequestID()
				r = WithRequestID(r, requestID)
			}

			remoteIP := clientIP(r)

			// Propagate request id to client
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

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
