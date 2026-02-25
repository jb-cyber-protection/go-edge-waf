package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"go-edge-waf/internal/proxy"
)

func main() {
	backendURL := getEnv("BACKEND_URL", "http://localhost:9000")
	listenAddr := getEnv("LISTEN_ADDR", ":8080")

	p, err := proxy.NewReverseProxy(backendURL)
	if err != nil {
		log.Fatalf("failed to create proxy: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", withBasicLogging(p))

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

func withBasicLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap ResponseWriter so we can log status codes
		lw := &loggingResponseWriter{ResponseWriter: w, statusCode: 200}
		next.ServeHTTP(lw, r)

		dur := time.Since(start)
		log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, lw.statusCode, dur)
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lw *loggingResponseWriter) WriteHeader(code int) {
	lw.statusCode = code
	lw.ResponseWriter.WriteHeader(code)
}

func getEnv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}
