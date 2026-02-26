package waf

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type XSSDetector struct {
	rules        []rule
	maxBodyBytes int64
}

func NewXSSDetector() *XSSDetector {
	// High-signal patterns to keep false positives minimal.
	rules := []rule{
		{id: "xss_script_tag", re: regexp.MustCompile(`(?i)<\s*script\b`)},
		{id: "xss_javascript_scheme", re: regexp.MustCompile(`(?i)javascript\s*:`)},
		{id: "xss_event_handler", re: regexp.MustCompile(`(?i)\bon\w+\s*=`)}, // onerror=, onclick=, etc.

		// Common URL-encoded forms
		{id: "xss_encoded_script", re: regexp.MustCompile(`(?i)%3c\s*script\b`)},
		{id: "xss_encoded_js_scheme", re: regexp.MustCompile(`(?i)javascript%3a`)},
	}

	return &XSSDetector{
		rules:        rules,
		maxBodyBytes: 1 << 20, // 1MB
	}
}

// InspectXSS checks headers, query params, and body. If it reads the body, it restores it.
func (d *XSSDetector) InspectXSS(r *http.Request) (*Match, bool) {
	// 1) Headers
	if m, ok := d.inspectHeaders(r.Header); ok {
		return m, true
	}

	// 2) Query params / URL
	if m, ok := d.inspectQuery(r.URL); ok {
		return m, true
	}

	// 3) Body
	if r.Body == nil {
		return nil, false
	}

	bodyBytes, restored, ok := readAndRestoreBody(r, d.maxBodyBytes)
	if !ok {
		return nil, false
	}
	r.Body = restored

	if len(bodyBytes) == 0 {
		return nil, false
	}

	body := string(bodyBytes)

	// If form-encoded, decode once
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

func (d *XSSDetector) inspectHeaders(h http.Header) (*Match, bool) {
	// Scan a small subset of headers to reduce noise/false positives.
	keys := []string{"User-Agent", "Referer", "Cookie", "X-Forwarded-For", "X-Real-Ip"}
	for _, k := range keys {
		v := h.Get(k)
		if v == "" {
			continue
		}
		for _, ru := range d.rules {
			if ru.re.MatchString(v) {
				return &Match{RuleID: ru.id, Where: "header:" + k}, true
			}
		}
	}
	return nil, false
}

func (d *XSSDetector) inspectQuery(u *url.URL) (*Match, bool) {
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

func readAndRestoreBody(r *http.Request, max int64) ([]byte, io.ReadCloser, bool) {
	limited := io.LimitReader(r.Body, max)
	b, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, false
	}
	_ = r.Body.Close()
	return b, io.NopCloser(bytes.NewReader(b)), true
}
