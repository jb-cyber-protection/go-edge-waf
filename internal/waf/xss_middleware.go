package waf

import (
	"net/http"

	"go-edge-waf/internal/logging"
)

func XSSEnforcer(mode Mode, detector *XSSDetector, logger *logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID, ok := logging.GetRequestID(r)
			if !ok {
				reqID = logging.NewRequestID()
				r = logging.WithRequestID(r, reqID)
			}

			if match, bad := detector.InspectXSS(r); bad {
				logger.Log(logging.Event{
					"type":       "security_event",
					"category":   "xss",
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
			}

			next.ServeHTTP(w, r)
		})
	}
}
