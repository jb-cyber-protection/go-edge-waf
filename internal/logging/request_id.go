package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

type ctxKey string

const requestIDKey ctxKey = "request_id"

func NewRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func WithRequestID(r *http.Request, id string) *http.Request {
	ctx := context.WithValue(r.Context(), requestIDKey, id)
	return r.WithContext(ctx)
}

func GetRequestID(r *http.Request) (string, bool) {
	v := r.Context().Value(requestIDKey)
	s, ok := v.(string)
	return s, ok
}
