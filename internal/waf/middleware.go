package waf

import (
	"net/http"
	"strings"

	"go-edge-waf/internal/logging"
)

func SQLiBlocker(detector *SQLiDetector, logger *logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Ensure request_id exists early so logs correlate
			reqID, ok := logging.GetRequestID(r)
			if !ok {
				reqID = logging.NewRequestID()
				r = logging.WithRequestID(r, reqID)
			}

			if match, bad := detector.Inspect(r); bad {
				logger.Log(logging.Event{
					"type":       "security_event",
					"category":   "sqli",
					"action":     "blocked",
					"rule_id":    match.RuleID,
					"location":   match.Where,
					"request_id": reqID,
					"remote_ip":  clientIPOnly(r.RemoteAddr),
					"method":     r.Method,
					"path":       r.URL.Path,
				})

				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func clientIPOnly(remoteAddr string) string {
	// Handles "ip:port" or just "ip"
	if i := strings.LastIndex(remoteAddr, ":"); i > 0 && strings.Count(remoteAddr, ":") == 1 {
		return remoteAddr[:i]
	}
	// For IPv6 formats or unexpected, return as-is
	return remoteAddr
}
