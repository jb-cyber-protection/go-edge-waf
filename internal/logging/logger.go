package logging

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

type Logger struct {
	mu  sync.Mutex
	out io.Writer
}

func New() *Logger {
	return &Logger{out: os.Stdout}
}

type Event map[string]any

func (l *Logger) Log(event Event) {
	// Ensure timestamp exists
	if _, ok := event["ts"]; !ok {
		event["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	}

	b, err := json.Marshal(event)
	if err != nil {
		// Fallback: minimal, non-JSON output should never crash the server
		l.mu.Lock()
		defer l.mu.Unlock()
		_, _ = l.out.Write([]byte(`{"ts":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","level":"error","msg":"failed to marshal log event"}` + "\n"))
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.out.Write(append(b, '\n'))
}
