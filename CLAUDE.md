# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

go-egress-proxy is a MITM HTTP/HTTPS proxy that implements split-brain DNS functionality. It intercepts egress traffic, applies ACL policies (whitelist/blacklist with regex), rewrites specific domains to internal IPs (with wildcard support), and injects custom headers.

## Build and Run Commands

```bash
make build          # Build binary
make test           # Run tests with race detector
make lint           # Run golangci-lint
make run            # Run directly with go run
make certs          # Generate CA certificates
make docker-build   # Build Docker image
make docker-run     # Run in Docker
make install-tools  # Install dev tools (golangci-lint, goimports)

# Validate configuration without starting the proxy
go run . validate --config config.yaml
```

## Testing

```bash
make test           # Run all tests with race detector
make test-short     # Run tests without race detector (faster)
make test-e2e       # Run end-to-end tests (requires Docker)
go test -v -run TestConfigValidate ./...  # Run specific test
```

## Architecture

Single-file application (`main.go`) using goproxy library with thread-safe hot-reloadable configuration.

**Request Flow:**
1. Client connects → Proxy presents cert signed by internal CA (MITM)
2. Request ID generated and injected (`X-Request-ID`)
3. Rule matching: Check rewrites first (exact then wildcard, with optional `path_pattern` regex filtering), then ACL blacklist/whitelist (regex), then default policy
4. Actions: `REWRITTEN`, `WHITE-LISTED`, `BLACK-LISTED`, `ALLOWED-BY-DEFAULT`, `BLOCKED`
5. For rewrites: Custom `DialContext` routes TCP to `target_ip` instead of DNS resolution
6. Headers injected on rewritten requests

**Response Status Codes:**

| Code | Meaning | When |
|------|---------|------|
| 200 | OK | Request succeeded through to upstream |
| 403 | Forbidden | Request blocked by ACL (blacklisted or default BLOCK policy) |
| 502 | Bad Gateway | Upstream unreachable: DNS lookup failed, connection refused, or connection reset |
| 504 | Gateway Timeout | Upstream accepted the connection but did not respond in time |

The proxy distinguishes timeout errors (`net.Error.Timeout()`, `context.DeadlineExceeded`) from all other upstream failures. This applies to both plain HTTP requests (via the `OnResponse` handler) and CONNECT-level failures (via `ConnectionErrHandler`).

**Key Components:**
- `RuntimeConfig` - Thread-safe config holder with RWMutex for hot reload
- `loadConfig()` - Loads YAML, applies env overrides, validates
- `compileACL()` / `compileRewrites()` - Pre-compiles patterns via `wildcardToRegex()`
- `wildcardToRegex()` - Converts `*.example.com` to regex; `~` prefix enables raw regex mode
- `handleRequest()` - Request handler with policy evaluation; stores matched rewrite in request context for path-based rules
- `lookupRewrite()` - Shared rewrite rule lookup (exact map → pattern match); skips path-pattern rules (resolved via context)
- `makeDialer()` - Custom DialContext for plain HTTP split-brain DNS; reads context-based rewrites first
- `makeTLSDialer()` - Custom DialTLSContext for HTTPS with per-rewrite InsecureSkipVerify; reads context-based rewrites first
- `loadTruststoreCerts()` - Extracts CA certificates from PKCS#12 truststore
- `normalizeDomainForMetrics()` - Bounds metrics cardinality

**Configuration:**
- YAML file (path via `CONFIG_PATH` env var, default: `config.yaml`)
- Environment variable overrides: `PROXY_PORT`, `PROXY_METRICS_PORT`, `PROXY_DEFAULT_POLICY`, `PROXY_BLOCKED_LOG_PATH`, `PROXY_OUTGOING_TRUSTSTORE_PATH`, `PROXY_OUTGOING_TRUSTSTORE_PASSWORD`, `PROXY_INSECURE_SKIP_VERIFY`
- MITM CA: PEM cert+key (`mitm_cert_path`/`mitm_key_path`) or PKCS#12 keystore (`mitm_keystore_path`/`mitm_keystore_password`), mutually exclusive
- Outgoing TLS: optional PEM CA bundle (`outgoing_ca_bundle`) and/or PKCS#12 truststore (`outgoing_truststore_path`/`outgoing_truststore_password`), additive with system CAs
- Global `insecure_skip_verify`: disables upstream TLS verification (dev/test only)
- Per-rewrite `insecure`: skips TLS verification for specific rewrite targets (self-signed internal services)
- Per-rewrite `path_pattern`: optional regex matched against `r.URL.Path` for path-based routing (rules evaluated in YAML order, first match wins; passed to dialers via request context)
- Blocked request log: optional JSON log file (`blocked_log_path` / `PROXY_BLOCKED_LOG_PATH`) capturing only `BLACK-LISTED` and `BLOCKED` requests; reopened on SIGHUP for log rotation
- Hot reload via SIGHUP signal

**Metrics:** Prometheus metrics on `:9090/metrics`:
- `proxy_traffic_total` - requests by domain and action
- `proxy_request_duration_seconds` - request latency histogram
- `proxy_active_connections` - current connections
- `proxy_config_load_errors_total` / `proxy_config_reloads_total` - config operations
- `proxy_upstream_errors_total` - upstream connection errors by type
- `proxy_response_status_total` - response status codes by class
- `proxy_bytes_total` - bytes transferred by direction

**Health Endpoints:** `/healthz` (liveness), `/readyz` (readiness)

**Graceful Shutdown:** SIGINT/SIGTERM with 30s drain period

**Hot Reload:** SIGHUP reloads config without restart

## Code Organization

- `main.go` - All application code
- `main_test.go` - Unit tests
- `Makefile` - Build and dev commands
- `.golangci.yml` - Linter configuration
- `.github/workflows/ci.yaml` - CI pipeline
- `.github/dependabot.yml` - Dependency updates
- `docker-compose.yaml` - Local dev environment

## Dependencies

- `github.com/elazarl/goproxy` - HTTP proxy with MITM support
- `github.com/prometheus/client_golang` - Prometheus metrics
- `golang.org/x/crypto/pkcs12` - PKCS#12 keystore support
- `gopkg.in/yaml.v3` - Config parsing
