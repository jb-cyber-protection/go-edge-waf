package waf

import (
	"net/http"
	"strconv"
	"time"

	"go-edge-waf/internal/logging"
)

func RateLimit(rl *RateLimiter, logger *logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Ensure request_id exists for correlation
			reqID, ok := logging.GetRequestID(r)
			if !ok {
				reqID = logging.NewRequestID()
				r = logging.WithRequestID(r, reqID)
			}

			ip := clientIPOnly(r.RemoteAddr)
			logger.Log(logging.Event{"type": "debug", "msg": "rate_limit_key", "ip_key": ip, "remote_addr": r.RemoteAddr})
			if !rl.Allow(ip) {
				// Helpful headers for clients
				w.Header().Set("Retry-After", "10") // seconds (matches default window)
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.limit))
				w.Header().Set("X-RateLimit-Window", strconv.Itoa(int(rl.window.Seconds())))

				logger.Log(logging.Event{
					"type":       "security_event",
					"category":   "rate_limit",
					"action":     "blocked",
					"request_id": reqID,
					"remote_ip":  ip,
					"method":     r.Method,
					"path":       r.URL.Path,
				})

				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Helper to construct a limiter from env-friendly values.
// Used in main.go wiring.
func NewRateLimiterFromConfig(limit int, windowSeconds int) *RateLimiter {
	if limit <= 0 {
		limit = 30
	}
	if windowSeconds <= 0 {
		windowSeconds = 10
	}
	return NewRateLimiter(limit, time.Duration(windowSeconds)*time.Second)
}
