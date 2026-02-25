package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

// NewReverseProxy returns an http.Handler that proxies requests to targetBaseURL.
// Example targetBaseURL: "http://localhost:9000"
func NewReverseProxy(targetBaseURL string) (http.Handler, error) {
	u, err := url.Parse(targetBaseURL)
	if err != nil {
		return nil, err
	}

	rp := httputil.NewSingleHostReverseProxy(u)

	// Director mutates the incoming request before forwarding it upstream.
	originalDirector := rp.Director
	rp.Director = func(r *http.Request) {
		originalDirector(r)

		// Ensure Host header reflects upstream host (common reverse proxy behavior).
		r.Host = u.Host
	}

	// Basic error handler so failures return a clean 502.
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	return rp, nil
}
