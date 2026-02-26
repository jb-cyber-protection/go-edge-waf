# go-edge-waf

A lightweight reverse proxy WAF written in Go.

## Run
Start a backend (example):
python3 -m http.server 9000

Run the proxy:
go run ./cmd/waf

Test:
curl -i http://localhost:8080

## Issue #1 – Reverse Proxy Implementation

### Proxy Running
![Proxy Running](docs/images/issue-1-proxy-running.png)

### Request Flow + Logging
![Request Flow](docs/images/issue-1-request-flow.png)

## Logging
Each request emits a single JSON log line (one event per request) and includes an `X-Request-Id` response header for traceability.
EOF

## Issue #2 – Structured JSON Logging

### Proxy Running
![Proxy Running JSON](docs/images/issue-2-proxy-running-json.png)

### JSON Log Output
![JSON Log Output](docs/images/issue-2-json-log-output.png)

## Issue #3 – SQL Injection Blocking

### Blocked Request (403)
![SQLi 403](docs/images/issue-3-sqli-403.png)

### Security Event Log
![SQLi security event](docs/images/issue-3-security-event.png)

## Issue #4 – XSS Blocking

### Blocked Request (403)
![XSS 403](docs/images/issue-4-xss-403.png)

### Security Event Log
![XSS security event](docs/images/issue-4-xss-security-event.png)

## Issue #5 – IP Rate Limiting

### Rate Limit Triggered (429)
![Rate limit 429](docs/images/issue-5-rate-limit-429.png)

### Security Event Log
![Rate limit security event](docs/images/issue-5-rate-limit-security-event.png)

### Config
Rate limiting can be configured via environment variables:
- `RATE_LIMIT_MAX` (default: 30)
- `RATE_LIMIT_WINDOW_SECONDS` (default: 10)
