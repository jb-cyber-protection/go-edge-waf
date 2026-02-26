package waf

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu     sync.Mutex
	window time.Duration
	limit  int

	// key: ip -> list of request timestamps in current window
	hits map[string][]time.Time
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		window: window,
		limit:  limit,
		hits:   make(map[string][]time.Time),
	}
}

// Allow returns true if the request is allowed, false if rate limited.
func (rl *RateLimiter) Allow(ip string) bool {
	now := time.Now()
	cutoff := now.Add(-rl.window)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Prune old timestamps
	times := rl.hits[ip]
	j := 0
	for _, t := range times {
		if t.After(cutoff) {
			times[j] = t
			j++
		}
	}
	times = times[:j]

	// Check if limit exceeded
	if len(times) >= rl.limit {
		rl.hits[ip] = times
		return false
	}

	// Record this hit
	times = append(times, now)
	rl.hits[ip] = times

	// Opportunistic cleanup: remove empty entries
	// (small safeguard even though above logic keeps some arrays around)
	if len(rl.hits[ip]) == 0 {
		delete(rl.hits, ip)
	}

	return true
}
