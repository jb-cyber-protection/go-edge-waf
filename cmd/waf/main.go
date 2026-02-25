package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"go-edge-waf/internal/logging"
	"go-edge-waf/internal/proxy"
)

func main() {
	backendURL := getEnv("BACKEND_URL", "http://localhost:9000")
	listenAddr := getEnv("LISTEN_ADDR", ":8080")

	p, err := proxy.NewReverseProxy(backendURL)
	if err != nil {
		log.Fatalf("failed to create proxy: %v", err)
	}

	logger := logging.New()
	reqLogger := logging.RequestLogger(logger)

	mux := http.NewServeMux()
	mux.Handle("/", reqLogger(p))

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("go-edge-waf listening on %s (proxying to %s)", listenAddr, backendURL)
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
