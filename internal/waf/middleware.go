package waf

import (
	"net/http"
	"strings"

	"go-edge-waf/internal/logging"
)

func SQLiEnforcer(mode Mode, detector *SQLiDetector, logger *logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID, ok := logging.GetRequestID(r)
			if !ok {
				reqID = logging.NewRequestID()
				r = logging.WithRequestID(r, reqID)
			}

			if match, bad := detector.Inspect(r); bad {
				logger.Log(logging.Event{
					"type":       "security_event",
					"category":   "sqli",
					"action":     "detected",
					"rule_id":    match.RuleID,
					"location":   match.Where,
					"mode":       string(mode),
					"request_id": reqID,
					"remote_ip":  clientIPOnly(r.RemoteAddr),
					"method":     r.Method,
					"path":       r.URL.Path,
				})

				if mode == ModeBlock {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				// audit mode: allow request through
			}

			next.ServeHTTP(w, r)
		})
	}
}

func clientIPOnly(remoteAddr string) string {
	if strings.HasPrefix(remoteAddr, "[") {
		if end := strings.LastIndex(remoteAddr, "]"); end != -1 {
			return remoteAddr[1:end]
		}
	}
	if i := strings.LastIndex(remoteAddr, ":"); i > 0 && strings.Count(remoteAddr, ":") == 1 {
		return remoteAddr[:i]
	}
	return remoteAddr
}
