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
