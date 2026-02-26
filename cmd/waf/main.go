package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"go-edge-waf/internal/config"
	"go-edge-waf/internal/logging"
	"go-edge-waf/internal/proxy"
	"go-edge-waf/internal/waf"
)

func main() {
	backendURL := getEnv("BACKEND_URL", "http://localhost:9000")
	listenAddr := getEnv("LISTEN_ADDR", ":8080")

	limit := getEnvInt("RATE_LIMIT_MAX", 30)
	windowSeconds := getEnvInt("RATE_LIMIT_WINDOW_SECONDS", 10)

	rulesPath := getEnv("WAF_RULES_PATH", "config/waf_rules.yaml")

	p, err := proxy.NewReverseProxy(backendURL)
	if err != nil {
		log.Fatalf("failed to create proxy: %v", err)
	}

	logger := logging.New()
	reqLogger := logging.RequestLogger(logger)

	// Load rules from config (fallback gracefully if invalid)
	compiled, err := config.LoadWAFRules(rulesPath)
	if err != nil {
		log.Printf("warning: failed to load WAF rules from %s: %v (using defaults)", rulesPath, err)
	}

	var sqliDetector *waf.SQLiDetector
	var xssDetector *waf.XSSDetector

	if compiled != nil {
		sqliDetector = waf.NewSQLiDetectorFromRules(compiled.SQLi)
		xssDetector = waf.NewXSSDetectorFromRules(compiled.XSS)
	} else {
		sqliDetector = waf.NewSQLiDetector()
		xssDetector = waf.NewXSSDetector()
	}

	sqli := waf.SQLiBlocker(sqliDetector, logger)
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
	log.Printf("rules file: %s", rulesPath)

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
