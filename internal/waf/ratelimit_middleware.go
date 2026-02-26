package waf

import (
	"net/http"
	"strconv"
	"time"

	"go-edge-waf/internal/logging"
)

func RateLimitEnforcer(mode Mode, rl *RateLimiter, logger *logging.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID, ok := logging.GetRequestID(r)
			if !ok {
				reqID = logging.NewRequestID()
				r = logging.WithRequestID(r, reqID)
			}

			ip := clientIPOnly(r.RemoteAddr)

			if !rl.Allow(ip) {
				logger.Log(logging.Event{
					"type":       "security_event",
					"category":   "rate_limit",
					"action":     "detected",
					"mode":       string(mode),
					"request_id": reqID,
					"remote_ip":  ip,
					"method":     r.Method,
					"path":       r.URL.Path,
					"limit":      rl.limit,
					"window_sec": int(rl.window.Seconds()),
				})

				if mode == ModeBlock {
					w.Header().Set("Retry-After", strconv.Itoa(int(rl.window.Seconds())))
					w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.limit))
					w.Header().Set("X-RateLimit-Window", strconv.Itoa(int(rl.window.Seconds())))
					http.Error(w, "too many requests", http.StatusTooManyRequests)
					return
				}
				// audit mode: allow request through
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Helper for main.go wiring
func NewRateLimiterFromConfig(limit int, windowSeconds int) *RateLimiter {
	if limit <= 0 {
		limit = 30
	}
	if windowSeconds <= 0 {
		windowSeconds = 10
	}
	return NewRateLimiter(limit, time.Duration(windowSeconds)*time.Second)
}
