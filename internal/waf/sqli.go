package waf

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type Match struct {
	RuleID string
	Where  string // "query" or "body"
}

type SQLiDetector struct {
	rules        []rule
	maxBodyBytes int64
}

type rule struct {
	id string
	re *regexp.Regexp
}

func NewSQLiDetector() *SQLiDetector {
	// Minimal targeted rules for Issue #3.
	// (?i) = case-insensitive.
	rules := []rule{
		{id: "sqli_or_true", re: regexp.MustCompile(`(?i)(?:'|%27)?\s*or\s+1\s*=\s*1`)},
		{id: "sqli_union_select", re: regexp.MustCompile(`(?i)\bunion\b\s+\bselect\b`)},
		{id: "sqli_drop_table", re: regexp.MustCompile(`(?i)\bdrop\b\s+\btable\b`)},
		// Common SQL comment tokens often used to truncate queries
		{id: "sqli_comment", re: regexp.MustCompile(`(?i)(--|#|/\*)`)},
	}
	return &SQLiDetector{
		rules:        rules,
		maxBodyBytes: 1 << 20, // 1MB
	}
}

// Inspect checks query params and request body.
// If it reads the body, it restores it so downstream (reverse proxy) can still use it.
func (d *SQLiDetector) Inspect(r *http.Request) (*Match, bool) {
	// 1) Query string / URL params
	if m, ok := d.inspectQuery(r.URL); ok {
		return m, true
	}

	// 2) Body (only if present)
	if r.Body == nil {
		return nil, false
	}

	bodyBytes, restored, ok := d.readAndRestoreBody(r)
	if !ok {
		return nil, false
	}
	r.Body = restored

	if len(bodyBytes) == 0 {
		return nil, false
	}

	body := string(bodyBytes)

	// If form data, decode once for readability
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/x-www-form-urlencoded") {
		if decoded, err := url.QueryUnescape(body); err == nil {
			body = decoded
		}
	}

	for _, ru := range d.rules {
		if ru.re.MatchString(body) {
			return &Match{RuleID: ru.id, Where: "body"}, true
		}
	}

	return nil, false
}

func (d *SQLiDetector) inspectQuery(u *url.URL) (*Match, bool) {
	raw := u.RawQuery

	if raw != "" {
		for _, ru := range d.rules {
			if ru.re.MatchString(raw) {
				return &Match{RuleID: ru.id, Where: "query"}, true
			}
		}
	}

	vals := u.Query()
	for _, arr := range vals {
		for _, item := range arr {
			for _, ru := range d.rules {
				if ru.re.MatchString(item) {
					return &Match{RuleID: ru.id, Where: "query"}, true
				}
			}
		}
	}

	return nil, false
}

func (d *SQLiDetector) readAndRestoreBody(r *http.Request) ([]byte, io.ReadCloser, bool) {
	limited := io.LimitReader(r.Body, d.maxBodyBytes)
	b, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, false
	}
	_ = r.Body.Close()
	return b, io.NopCloser(bytes.NewReader(b)), true
}
