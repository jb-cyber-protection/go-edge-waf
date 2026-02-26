# go-edge-waf

A lightweight reverse proxy Web Application Firewall (WAF) written in
Go.

This project models core edge-security concepts inspired by modern
CDN/WAF platforms:

-   Reverse proxy request handling
-   Structured JSON request logging
-   SQL injection detection
-   XSS detection
-   IP-based rate limiting
-   YAML-configurable rule engine
-   Audit (log-only) enforcement mode

------------------------------------------------------------------------

## Architecture Overview

    Client → go-edge-waf → Backend Server

The WAF:

-   Terminates incoming HTTP requests
-   Inspects headers, query strings, and request bodies
-   Applies detection rules
-   Emits structured JSON logs
-   Enforces blocking or audit mode
-   Forwards allowed traffic to the backend

------------------------------------------------------------------------

## Quick Start

### 1️⃣ Start a backend server

``` bash
python3 -m http.server 9000 --bind 127.0.0.1
```

### 2️⃣ Run the WAF

``` bash
go run ./cmd/waf
```

### 3️⃣ Send a request

``` bash
curl -i http://localhost:8080
```

------------------------------------------------------------------------

## Features

------------------------------------------------------------------------

## Issue #1 -- Reverse Proxy Implementation

### Proxy Running

![Proxy Running](docs/images/issue-1-proxy-running.png)

### Request Flow + Logging

![Request Flow](docs/images/issue-1-request-flow.png)

------------------------------------------------------------------------

## Issue #2 -- Structured JSON Logging

### Proxy Running

![Proxy Running JSON](docs/images/issue-2-proxy-running-json.png)

### JSON Log Output

![JSON Log Output](docs/images/issue-2-json-log-output.png)

------------------------------------------------------------------------

## Issue #3 -- SQL Injection Blocking

### Blocked Request (403)

![SQLi 403](docs/images/issue-3-sqli-403.png)

### Security Event Log

![SQLi security event](docs/images/issue-3-security-event.png)

------------------------------------------------------------------------

## Issue #4 -- XSS Blocking

### Blocked Request (403)

![XSS 403](docs/images/issue-4-xss-403.png)

### Security Event Log

![XSS security event](docs/images/issue-4-xss-security-event.png)

------------------------------------------------------------------------

## Issue #5 -- IP Rate Limiting

### Rate Limit Triggered (429)

![Rate limit 429](docs/images/issue-5-rate-limit-429.png)

### Security Event Log

![Rate limit security
event](docs/images/issue-5-rate-limit-security-event.png)

### Config

Rate limiting can be configured via environment variables:

-   `RATE_LIMIT_MAX` (default: 30)
-   `RATE_LIMIT_WINDOW_SECONDS` (default: 10)

------------------------------------------------------------------------

## Issue #6 -- Configurable Rule Engine

WAF detection rules are externalized into:

`config/waf_rules.yaml`

Rules are:

-   Loaded at startup
-   Compiled into regex
-   Validated before use
-   Gracefully fallback to safe defaults if config fails

### YAML Rule Configuration

![Rules config](docs/images/issue-6-rules-config.png)

### Config-Based Rule Blocking

![Config rule block](docs/images/issue-6-config-rule-block.png)

Override rule path:

-   `WAF_RULES_PATH` (default: config/waf_rules.yaml)

------------------------------------------------------------------------

## Issue #7 -- Audit Mode (Log-Only Enforcement)

The WAF supports two operating modes:

-   `block` → actively blocks malicious requests (403 / 429)
-   `audit` → logs detections but allows traffic to pass

Mode can be configured via:

-   `config/waf_rules.yaml` → `mode: block|audit`
-   Environment variable override → `WAF_MODE`

### Audit Mode -- Request Allowed

![Audit allowed](docs/images/issue-7-audit-mode-allowed.png)

### Audit Mode -- Security Event Logged

![Audit security
event](docs/images/issue-7-audit-mode-security-event.png)

This enables safe monitoring before enabling blocking in production.

------------------------------------------------------------------------

## Security Event Format

``` json
{
  "type": "security_event",
  "category": "xss",
  "rule_id": "xss_script_tag",
  "mode": "audit",
  "request_id": "...",
  "remote_ip": "...",
  "method": "GET",
  "path": "/"
}
```

------------------------------------------------------------------------

## Configuration Options

Environment variables:

-   `BACKEND_URL` (default: http://127.0.0.1:9000)
-   `LISTEN_ADDR` (default: :8080)
-   `RATE_LIMIT_MAX` (default: 30)
-   `RATE_LIMIT_WINDOW_SECONDS` (default: 10)
-   `WAF_RULES_PATH` (default: config/waf_rules.yaml)
-   `WAF_MODE` (optional override: block \| audit)

------------------------------------------------------------------------

## Design Considerations

-   Request body size capped (1MB) to prevent memory abuse
-   Regex compiled at startup (fail fast on invalid rules)
-   Graceful fallback to default rules if config invalid
-   Request ID correlation for observability
-   Clear separation of detection and enforcement logic
-   Audit mode for safe production rollout

------------------------------------------------------------------------

## Future Improvements

-   Distributed rate limiting
-   Prometheus metrics
-   Rule severity levels
-   IP allow/deny lists
-   Request sampling in audit mode
-   Expanded unit test coverage

------------------------------------------------------------------------

## Why This Project

This WAF demonstrates:

-   Secure request inspection at the edge
-   Middleware chaining patterns in Go
-   Structured security event logging
-   Config-driven detection systems
-   Safe rollout strategies (audit mode)

It models foundational concepts used in real-world edge security
platforms.
