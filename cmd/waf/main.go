package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"go-edge-waf/internal/logging"
	"go-edge-waf/internal/proxy"
	"go-edge-waf/internal/waf"
)

func main() {
	backendURL := getEnv("BACKEND_URL", "http://localhost:9000")
	listenAddr := getEnv("LISTEN_ADDR", ":8080")

	limit := getEnvInt("RATE_LIMIT_MAX", 30)
	windowSeconds := getEnvInt("RATE_LIMIT_WINDOW_SECONDS", 10)

	p, err := proxy.NewReverseProxy(backendURL)
	if err != nil {
		log.Fatalf("failed to create proxy: %v", err)
	}

	logger := logging.New()
	reqLogger := logging.RequestLogger(logger)

	// Detectors + blockers
	sqliDetector := waf.NewSQLiDetector()
	sqli := waf.SQLiBlocker(sqliDetector, logger)

	xssDetector := waf.NewXSSDetector()
	xss := waf.XSSBlocker(xssDetector, logger)

	rl := waf.NewRateLimiterFromConfig(limit, windowSeconds)
	rateLimit := waf.RateLimit(rl, logger)

	mux := http.NewServeMux()
	mux.Handle("/", reqLogger(rateLimit(sqli(xss(p)))))

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("go-edge-waf listening on %s (proxying to %s)", listenAddr, backendURL)
	log.Printf("rate limiting: %d requests / %ds window", limit, windowSeconds)

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

func getEnv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}

func getEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
