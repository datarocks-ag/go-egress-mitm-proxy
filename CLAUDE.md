# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

go-egress-proxy is a MITM HTTP/HTTPS proxy that implements split-brain DNS functionality. It intercepts egress traffic, applies ACL policies (whitelist/blacklist with regex), rewrites specific domains to internal IPs (with wildcard support), and injects custom headers.

## Build and Run Commands

```bash
make build          # Build binary (injects version from git describe)
make test           # Run tests with race detector
make lint           # Run golangci-lint
make run            # Run directly with go run
make certs          # Generate CA certificates
make docker-build   # Build Docker image
make docker-run     # Run in Docker
make install-tools  # Install dev tools (golangci-lint, goimports)

# CLI flags
./mitm-proxy --version       # Print version and exit
./mitm-proxy --help          # Show usage
./mitm-proxy -vv             # Run with debug logging
./mitm-proxy -vvv            # Run with trace logging (most verbose)

# Validate configuration without starting the proxy
go run ./cmd/mitm-proxy validate --config config.yaml

# Generate CA certificates (replaces make certs / OpenSSL)
go run ./cmd/mitm-proxy gencert --help

# Build with specific version
VERSION=1.0.0 make build
```

## Testing

```bash
make test           # Run all tests with race detector
make test-short     # Run tests without race detector (faster)
make test-e2e       # Run end-to-end tests (requires Docker)
go test -v -run TestConfigValidate ./...  # Run specific test
```

## Architecture

Multi-package application using goproxy library with thread-safe hot-reloadable configuration.

**Package Layout:**
```
cmd/mitm-proxy/main.go        # CLI entrypoint: arg parsing, signal handling, wiring
internal/config/config.go      # Types, YAML loading, validation, env overrides, ACL/rewrite compilation
internal/cert/cert.go          # MITM cert loading (PEM/PKCS#12), signing, TLS pool building
internal/cert/gencert.go       # gencert subcommand + key pair generation
internal/proxy/handler.go      # Request handling, dialers, rewrite lookup, domain metrics
internal/metrics/metrics.go    # Prometheus metric vars (promauto registrations)
internal/health/health.go      # Health and readiness HTTP handlers
e2e_test.go                    # End-to-end tests (build tag: e2e, uses testcontainers)
```

**Package Dependency Graph (no cycles):**
```
metrics     → (none)
health      → (none)
config      → metrics
cert        → config
proxy       → config, metrics, cert
cmd/main    → config, cert, proxy, metrics, health
```

**Request Flow:**
1. Client connects → Proxy presents cert signed by internal CA (MITM)
2. Request ID generated and injected (`X-Request-ID`)
3. Rule matching: Check rewrites first (exact then wildcard, with optional `path_pattern` regex filtering), then ACL blacklist/whitelist (regex), then default policy
4. Actions: `REWRITTEN`, `WHITE-LISTED`, `BLACK-LISTED`, `ALLOWED-BY-DEFAULT`, `BLOCKED`
5. For rewrites: Custom `DialContext` routes TCP to `target_ip` instead of DNS resolution
6. Headers dropped (`drop_headers`) and injected (`headers`) on rewritten requests
7. Request scheme optionally changed (`target_scheme`) before forwarding

**Response Status Codes:**

| Code | Meaning | When |
|------|---------|------|
| 200 | OK | Request succeeded through to upstream |
| 403 | Forbidden | Request blocked by ACL (blacklisted or default BLOCK policy) |
| 502 | Bad Gateway | Upstream unreachable: DNS lookup failed, connection refused, or connection reset |
| 504 | Gateway Timeout | Upstream accepted the connection but did not respond in time |

The proxy distinguishes timeout errors (`net.Error.Timeout()`, `context.DeadlineExceeded`) from all other upstream failures. This applies to both plain HTTP requests (via the `OnResponse` handler) and CONNECT-level failures (via `ConnectionErrHandler`).

**Key Components:**

`internal/config`:
- `RuntimeConfig` - Thread-safe config holder with RWMutex for hot reload
- `LoadConfig()` - Loads YAML, applies env overrides, validates
- `CompileACL()` / `CompileRewrites()` - Pre-compiles patterns via `WildcardToRegex()`
- `WildcardToRegex()` - Converts `*.example.com` to regex; `~` prefix enables raw regex mode
- `RunValidate()` - CLI subcommand: validates config file without starting the proxy

`internal/cert`:
- `LoadMITMCertificate()` - Loads MITM CA from PEM or PKCS#12
- `SignHost()` - Generates MITM leaf certificates with custom Organization (key type matches CA)
- `MitmTLSConfigFromCA()` - TLS config factory for custom MITM certs with sync.Map cache
- `BuildOutboundTLSConfig()` - Builds outbound TLS config with custom CA pool
- `LoadCertPool()` - Loads CA certificates from PEM bundle and/or PKCS#12 truststore
- `LoadTruststoreCerts()` - Extracts CA certificates from PKCS#12 truststore
- `RunGencert()` - CLI subcommand: generates root/intermediate CA certs with optional client trust bundles

`internal/proxy`:
- `HandleRequest()` - Request handler with policy evaluation; stores matched rewrite in request context for path-based rules
- `LookupRewrite()` - Shared rewrite rule lookup (exact map → pattern match); skips path-pattern rules (resolved via context)
- `MakeDialer()` - Custom DialContext for plain HTTP split-brain DNS; reads context-based rewrites first
- `MakeTLSDialer()` - Custom DialTLSContext for HTTPS with per-rewrite InsecureSkipVerify; reads context-based rewrites first
- `NormalizeDomainForMetrics()` - Bounds metrics cardinality

`internal/metrics`: All Prometheus metric vars (`TrafficTotal`, `RequestDuration`, etc.)

`internal/health`: `HealthHandler()`, `ReadyHandler()`

**Configuration:**
- YAML file (path via `CONFIG_PATH` env var, default: `config.yaml`)
- Environment variable overrides: `PROXY_PORT`, `PROXY_METRICS_PORT`, `PROXY_DEFAULT_POLICY`, `PROXY_BLOCKED_LOG_PATH`, `PROXY_OUTGOING_TRUSTSTORE_PATH`, `PROXY_OUTGOING_TRUSTSTORE_PASSWORD`, `PROXY_INSECURE_SKIP_VERIFY`, `PROXY_MITM_ORG`
- MITM CA: PEM cert+key (`mitm_cert_path`/`mitm_key_path`) or PKCS#12 keystore (`mitm_keystore_path`/`mitm_keystore_password`), mutually exclusive
- `mitm_org`: optional custom Organization for MITM leaf certificates (default: goproxy's built-in `"GoProxy untrusted MITM proxy Inc"`)
- Outgoing TLS: optional PEM CA bundle (`outgoing_ca_bundle`) and/or PKCS#12 truststore (`outgoing_truststore_path`/`outgoing_truststore_password`), additive with system CAs
- Global `insecure_skip_verify`: disables upstream TLS verification (dev/test only)
- Per-rewrite `insecure`: skips TLS verification for specific rewrite targets (self-signed internal services)
- Per-rewrite `target_scheme`: optional `"http"` or `"https"` to change the request scheme before forwarding (e.g., HTTPS client → HTTP backend)
- Per-rewrite `drop_headers`: list of header names to strip from the request before forwarding (case-insensitive via `r.Header.Del()`)
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

**Certificate Generation (`gencert` subcommand):**

Generates root or intermediate CA certificates with optional client trust bundles. No OpenSSL dependency required.

```bash
# Root CA (self-signed)
./mitm-proxy gencert --type root --key-algo ecdsa-p256 \
  --cn "My Root CA" --org "ACME Corp" --country CH --validity 3650 \
  --out-cert root-ca.crt --out-key root-ca.key

# Intermediate CA (signed by root, leaf-signing only)
./mitm-proxy gencert --type intermediate \
  --signing-cert root-ca.crt --signing-key root-ca.key \
  --key-algo ecdsa-p256 --cn "MITM Proxy CA" --org "ACME Corp" \
  --max-path-len 0 --validity 365 \
  --out-cert mitm-ca.crt --out-key mitm-ca.key --out-chain mitm-chain.crt

# With client trust bundles (PEM + PKCS#12 truststore for Java)
./mitm-proxy gencert --type root --cn "My Root CA" \
  --out-client-bundle trust.pem \
  --out-client-p12 truststore.p12 --client-p12-password changeit
```

Key flags:
- `--type`: `root` (self-signed) or `intermediate` (signed by `--signing-cert`/`--signing-key`)
- `--key-algo`: `rsa-2048`, `rsa-4096`, `ecdsa-p256` (default), `ecdsa-p384`, `ed25519`
- `--max-path-len`: BasicConstraints PathLen (`-1` unlimited, `0` leaf-signing only)
- `--out-chain`: PEM chain file (intermediate + parent certs) for use as `mitm_cert_path`
- `--out-p12` / `--p12-password`: PKCS#12 keystore (cert+key) for use as `mitm_keystore_path`
- `--out-client-bundle`: PEM trust bundle containing the root CA for client distribution
- `--out-client-p12` / `--client-p12-password`: PKCS#12 truststore for Java (`-Djavax.net.ssl.trustStore=... -Djavax.net.ssl.trustStoreType=PKCS12`)

Typical production workflow: generate root CA (store offline) → generate intermediate CA signed by root → configure proxy with `mitm_cert_path: mitm-chain.crt` + `mitm_key_path: mitm-ca.key` → distribute root CA to clients via `--out-client-p12` or `--out-client-bundle`.

## Code Organization

```
cmd/mitm-proxy/
  main.go                      # CLI entrypoint, signal handling, wiring
  main_test.go                 # Version and usage tests
internal/config/
  config.go                    # Config types, loading, validation, ACL/rewrite compilation
  config_test.go               # Config, ACL, rewrite, runtime, validate tests
internal/cert/
  cert.go                      # MITM cert loading, signing, TLS pool building
  gencert.go                   # gencert subcommand, key pair generation
  cert_test.go                 # Cert, signing, gencert, truststore tests
internal/proxy/
  handler.go                   # Request handling, dialers, rewrite lookup, metrics recording
  handler_test.go              # Handler, dialer, rewrite, metrics tests
internal/metrics/
  metrics.go                   # Prometheus metric var registrations
internal/health/
  health.go                    # Health and readiness HTTP handlers
e2e_test.go                    # End-to-end tests (build tag: e2e, Docker-based)
Makefile                       # Build and dev commands
.golangci.yml                  # Linter configuration
.github/workflows/ci.yaml     # CI pipeline (feature branches)
.github/workflows/release.yaml # Release pipeline (develop/tags)
.github/dependabot.yml         # Dependency updates
docker-compose.yaml            # Local dev environment
```

## Dependencies

- `github.com/elazarl/goproxy` - HTTP proxy with MITM support
- `github.com/prometheus/client_golang` - Prometheus metrics
- `golang.org/x/crypto/pkcs12` - PKCS#12 keystore decoding
- `software.sslmate.com/src/go-pkcs12` - PKCS#12 keystore/truststore encoding (for `gencert`)
- `gopkg.in/yaml.v3` - Config parsing
