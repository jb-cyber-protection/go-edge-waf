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

type XSSDetector struct {
	rules        []config.CompiledRule
	maxBodyBytes int64
}

func NewXSSDetectorFromRules(rules []config.CompiledRule) *XSSDetector {
	return &XSSDetector{
		rules:        rules,
		maxBodyBytes: 1 << 20, // 1MB
	}
}

// Fallback default rules if config fails
func NewXSSDetector() *XSSDetector {
	defaultRules := []config.CompiledRule{
		{ID: "xss_script_tag", RE: regexp.MustCompile(`(?i)<\s*script\b`)},
		{ID: "xss_javascript_scheme", RE: regexp.MustCompile(`(?i)javascript\s*:`)},
		{ID: "xss_event_handler", RE: regexp.MustCompile(`(?i)\bon\w+\s*=`)},
		{ID: "xss_encoded_script", RE: regexp.MustCompile(`(?i)%3c\s*script\b`)},
		{ID: "xss_encoded_js_scheme", RE: regexp.MustCompile(`(?i)javascript%3a`)},
	}
	return NewXSSDetectorFromRules(defaultRules)
}

func (d *XSSDetector) InspectXSS(r *http.Request) (*Match, bool) {
	if m, ok := d.inspectHeaders(r.Header); ok {
		return m, true
	}

	if m, ok := d.inspectQuery(r.URL); ok {
		return m, true
	}

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

func (d *XSSDetector) inspectHeaders(h http.Header) (*Match, bool) {
	keys := []string{"User-Agent", "Referer", "Cookie", "X-Forwarded-For", "X-Real-Ip"}
	for _, k := range keys {
		v := h.Get(k)
		if v == "" {
			continue
		}
		for _, ru := range d.rules {
			if ru.RE.MatchString(v) {
				return &Match{RuleID: ru.ID, Where: "header:" + k}, true
			}
		}
	}
	return nil, false
}

func (d *XSSDetector) inspectQuery(u *url.URL) (*Match, bool) {
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

func readAndRestoreBody(r *http.Request, max int64) ([]byte, io.ReadCloser, bool) {
	limited := io.LimitReader(r.Body, max)
	b, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, false
	}
	_ = r.Body.Close()
	return b, io.NopCloser(bytes.NewReader(b)), true
}
