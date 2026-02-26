package waf

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"go-edge-waf/internal/config"
)

type Match struct {
	RuleID string
	Where  string // "query" or "body" or "header:Name"
}

type SQLiDetector struct {
	rules        []config.CompiledRule
	maxBodyBytes int64
}

func NewSQLiDetectorFromRules(rules []config.CompiledRule) *SQLiDetector {
	return &SQLiDetector{
		rules:        rules,
		maxBodyBytes: 1 << 20, // 1MB
	}
}

// Fallback default rules if config fails
func NewSQLiDetector() *SQLiDetector {
	defaultRules := []config.CompiledRule{
		{ID: "sqli_or_true", RE: regexp.MustCompile(`(?i)(?:'|%27)?\s*or\s+1\s*=\s*1`)},
		{ID: "sqli_union_select", RE: regexp.MustCompile(`(?i)\bunion\b\s+\bselect\b`)},
		{ID: "sqli_drop_table", RE: regexp.MustCompile(`(?i)\bdrop\b\s+\btable\b`)},
		{ID: "sqli_comment", RE: regexp.MustCompile(`(?i)(--|#|/\*)`)},
	}
	return NewSQLiDetectorFromRules(defaultRules)
}

func (d *SQLiDetector) Inspect(r *http.Request) (*Match, bool) {
	if m, ok := d.inspectQuery(r.URL); ok {
		return m, true
	}

	if r.Body == nil {
		return nil, false
	}

	bodyBytes, restored, ok := readAndRestoreBodyLocal(r, d.maxBodyBytes)
	if !ok {
		return nil, false
	}
	r.Body = restored

	if len(bodyBytes) == 0 {
		return nil, false
	}

	body := string(bodyBytes)

	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/x-www-form-urlencoded") {
		if decoded, err := url.QueryUnescape(body); err == nil {
			body = decoded
		}
	}

	for _, ru := range d.rules {
		if ru.RE.MatchString(body) {
			return &Match{RuleID: ru.ID, Where: "body"}, true
		}
	}

	return nil, false
}

func (d *SQLiDetector) inspectQuery(u *url.URL) (*Match, bool) {
	raw := u.RawQuery

	if raw != "" {
		for _, ru := range d.rules {
			if ru.RE.MatchString(raw) {
				return &Match{RuleID: ru.ID, Where: "query"}, true
			}
		}
	}

	vals := u.Query()
	for _, arr := range vals {
		for _, item := range arr {
			for _, ru := range d.rules {
				if ru.RE.MatchString(item) {
					return &Match{RuleID: ru.ID, Where: "query"}, true
				}
			}
		}
	}

	return nil, false
}

func readAndRestoreBodyLocal(r *http.Request, max int64) ([]byte, io.ReadCloser, bool) {
	limited := io.LimitReader(r.Body, max)
	b, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, false
	}
	_ = r.Body.Close()
	return b, io.NopCloser(bytes.NewReader(b)), true
}
