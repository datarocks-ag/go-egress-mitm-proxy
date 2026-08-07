# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

go-egress-proxy is a MITM HTTP/HTTPS proxy that implements split-brain DNS functionality. It intercepts egress traffic, applies ACL policies (whitelist/blacklist/passthrough with regex), rewrites specific domains to internal IPs (with wildcard support), and injects custom headers. Passthrough ACL entries tunnel CONNECT requests without TLS interception for services with their own PKI (e.g., Kubernetes API).

## Build and Run Commands

```bash
make build          # Build binary (injects version from git describe)
make test           # Run tests with race detector
make lint           # Run golangci-lint
make run            # Run directly with go run
make certs          # Generate CA certificates
make docker-build   # Build Docker image
make docker-run     # Run in Docker
make install-tools  # Install dev tools (goimports). golangci-lint is NOT installed here — it runs via the go.mod tool directive: `go tool golangci-lint run` (what `make lint` does)

# CLI flags
./mitm-proxy --version       # Print version and exit
./mitm-proxy --help          # Show usage
./mitm-proxy -v              # Info: enables info logs including access logs (default is warn-only; subcommands default to info)
./mitm-proxy -vv             # Debug: ACCESS log + REQUEST_DETAIL (scheme, url, proto, user-agent, content-type, rewrite info)
./mitm-proxy -vvv            # Trace: all of the above + full request headers

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
cmd/mitm-proxy/reload.go       # SIGHUP reload: config swap, log reopen, transport pool reset
cmd/mitm-proxy/drain.go        # Graceful-shutdown sequence (extracted from main for testability)
internal/config/config.go      # Types, YAML loading, validation, env overrides, ACL/rewrite compilation
internal/cert/cert.go          # MITM cert loading (PEM/PKCS#12), signing, TLS pool building
internal/cert/gencert.go       # gencert subcommand + key pair generation
internal/netx/halfclose.go     # Half-close preservation shared by proxy and trace
internal/proxy/handler.go      # Request handling, dialers, rewrite lookup, domain metrics
internal/proxy/connect.go      # CONNECT decision handling, reject responses, passthrough trace wiring
internal/proxy/listener.go     # Connection-tracking listener for CONNECT-tunnel drain
internal/proxy/transport.go    # Per-rewrite-target upstream transport pool
internal/cert/store.go         # Bounded, TTL'd MITM leaf certificate cache
internal/trace/trace.go        # Selective trace Record, redaction, body capture, aggregated emit
internal/trace/conn.go         # Passthrough tunnel tracing dialer + byte-counting conn
internal/metrics/metrics.go    # Prometheus metric vars (promauto registrations)
internal/health/health.go      # Health and readiness HTTP handlers
e2e_test.go                    # End-to-end tests (build tag: e2e, uses testcontainers)
```

**Package Dependency Graph (no cycles):**
```
metrics     → (none)
health      → (none)
netx        → (none)
config      → (none)
cert        → config
trace       → config, metrics, netx
proxy       → config, metrics, netx, trace
cmd/main    → cert, config, health, metrics, proxy, trace
```

**Request Flow:**
1. Client connects → CONNECT handler checks passthrough ACL; if matched, tunnel is established without MITM (`PASSTHROUGH`)
2. Otherwise, proxy presents cert signed by internal CA (MITM)
3. Request ID generated and injected (`X-Request-ID`)
4. Rule matching: **blacklist first** (a match blocks with 403 and short-circuits the rewrite table), then rewrites (exact then wildcard, with optional `path_pattern` regex filtering), then whitelist, then default policy. Rewrites otherwise bypass the ACL — a rewritten host is implicitly allowed — but a denylist is not a preference, so it outranks them
5. Actions: `PASSTHROUGH`, `REWRITTEN`, `WHITE-LISTED`, `BLACK-LISTED`, `ALLOWED-BY-DEFAULT`, `BLOCKED`, plus `BLACK-LISTED-CONNECT` — recorded at the CONNECT stage when a blacklisted host is intercepted, so the attempt stays visible even if the client refuses the proxy certificate and never reaches `HandleRequest`. A host that is both passthrough and blacklisted is refused outright and counts as `BLACK-LISTED`
6. For rewrites: Custom `DialContext` routes TCP to `target_ip` instead of DNS resolution
7. Headers dropped (`drop_headers`) and injected (`headers`) on rewritten requests
8. Request scheme optionally changed (`target_scheme`) before forwarding

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
- `CompileACL()` / `CompileRewrites()` - Pre-compiles patterns (whitelist, blacklist, passthrough) via `WildcardToRegex()`
- `NormalizeHost()` - Lowercases and strips the trailing dot. **Every policy decision must compare normalized values**: DNS is case-insensitive and `evil.example.com.` is the same FQDN, so matching raw input let either form bypass a blacklist and silently miss rewrite rules.
- `WildcardToRegex()` - Converts `*.example.com` to regex; `~` prefix enables raw regex mode. Patterns are lowercased, anchored, and compiled case-insensitively (the `(?i)` is redundant given callers normalize — it is there so a future call site that forgets fails closed)
- `WildcardToURLRegex()` - As above but leaves raw `~` patterns unanchored, for trace `url` rules where substring matching against the full URL is intended. URL rules select what to observe and grant no access, so the fail-open concern that motivates anchoring does not apply
- `ReloadIgnoredFields()` - Diffs settings SIGHUP cannot apply (`mitm_*`, ports) so the reload warns instead of reporting success and silently discarding them
- `RunValidate()` - CLI subcommand: validates config file without starting the proxy

`internal/cert`:
- `LoadMITMCertificate()` - Loads MITM CA from PEM or PKCS#12
- `SignHost()` - Generates MITM leaf certificates with custom Organization (key type matches CA)
- `MitmTLSConfigFromCA()` - TLS config factory for custom MITM leaf certificates. Uses the shared `CertStore`; cache keys are qualified by a hash of the signing CA chain plus the Organization, so two callers with different CAs cannot be served each other's leaves
- `BuildOutboundTLSConfig()` - Builds outbound TLS config with custom CA pool
- `LoadCertPool()` - Loads CA certificates from PEM bundle and/or PKCS#12 truststore. Returns an error when a *configured* source cannot be loaded (a missing system pool is still only a warning), so startup aborts and a reload keeps the previous config rather than installing a degraded pool alongside a success message
- `CertStore` - Bounded LRU with TTL implementing `goproxy.CertStorage`, shared by both signing paths. Without it goproxy re-signs on every CONNECT; the `mitm_org` path previously used an unbounded cache with no expiry, so the caching policy depended on a cosmetic field
- `LoadTruststoreCerts()` - Extracts CA certificates from PKCS#12 truststore
- `RunGencert()` - CLI subcommand: generates root/intermediate CA certs with optional client trust bundles

`internal/proxy`:
- `HandleRequest()` - Request handler with policy evaluation; stores matched rewrite in request context for path-based rules
- `LookupRewrite()` - Shared rewrite rule lookup (exact map → pattern match); skips path-pattern rules (resolved via context)
- `MakeDialer()` - Custom DialContext for plain HTTP split-brain DNS; reads context-based rewrites first
- `MakeTLSDialer()` - Custom DialTLSContext for HTTPS with per-rewrite InsecureSkipVerify; reads context-based rewrites first
- `NormalizeDomainForMetrics()` - Bounds metrics cardinality
- `NewConnectHandler()` - The CONNECT-stage handler: normalization, `DecideConnect` dispatch, metric labeling, blocked-request auditing and passthrough trace wiring. Extracted from `main()` because as an anonymous closure none of it was reachable from a test — which is how a downgraded tunnel went unnoticed
- `DecideConnect()` - ACL policy for a CONNECT target. Rejects **only** a host that is both passthrough and blacklisted: passthrough accepts an uninspected tunnel that never reaches `HandleRequest`, so a denied host must not get one. Every other host is intercepted, blacklisted or not — nothing is forwarded upstream before `HandleRequest` applies policy, and the client gets a readable 403 instead of a rejected CONNECT that clients surface as an opaque transport error
- `LogBlocked()` - Shared blocked-request audit log emission, used by both the request path and the CONNECT reject path
- `NormalizeResponseProto()` - Forces HTTP/1.1 framing so goproxy's `resp.Write()` cannot emit an unusable status line
- `NewOutboundTransport()` - Builds the upstream transport (extracted from main so the real construction is testable)
- `TrackingListener` - Counts client connections at the listener. `http.Server` cannot drain this proxy's main traffic class, because goproxy hijacks the connection for every CONNECT and the server stops tracking hijacked connections
- `TransportPool` - One `http.Transport` per distinct upstream identity (`target_ip` + `target_host` + `insecure`). Go keys idle connections on the request URL's `host:port`, which is fixed before the dialers substitute the target, so a single shared transport would let rules for the same domain reuse each other's connections (misrouting traffic, and leaking `insecure` TLS connections to requests that require verification). `RoundTrip()` dispatches on the rewrite result stored in the request context; `Reset()` is called on SIGHUP so reloaded targets do not keep serving from stale pools.

`internal/metrics`: All Prometheus metric vars (`TrafficTotal`, `RequestDuration`, etc.)

`internal/health`: `HealthHandler()`, `ReadyHandler()`

**Configuration:**
- YAML file (path via `CONFIG_PATH` env var, default: `config.yaml`)
- Environment variable overrides: `PROXY_PORT`, `PROXY_METRICS_PORT`, `PROXY_DEFAULT_POLICY`, `PROXY_BLOCKED_LOG_PATH`, `PROXY_OUTGOING_TRUSTSTORE_PATH`, `PROXY_OUTGOING_TRUSTSTORE_PASSWORD`, `PROXY_INSECURE_SKIP_VERIFY`, `PROXY_MITM_ORG`, `PROXY_MAX_CONNECTIONS`
- MITM CA: PEM cert+key (`mitm_cert_path`/`mitm_key_path`) or PKCS#12 keystore (`mitm_keystore_path`/`mitm_keystore_password`), mutually exclusive
- `mitm_org`: optional custom Organization for MITM leaf certificates (default: goproxy's built-in `"GoProxy untrusted MITM proxy Inc"`)
- Outgoing TLS: optional PEM CA bundle (`outgoing_ca_bundle`) and/or PKCS#12 truststore (`outgoing_truststore_path`/`outgoing_truststore_password`), additive with system CAs
- Global `insecure_skip_verify`: disables upstream TLS verification (dev/test only)
- `max_connections` / `PROXY_MAX_CONNECTIONS`: ceiling on concurrent client connections (0 = unlimited). A hijacked CONNECT tunnel has no deadline at any layer, so this is the only bound on a client that connects and goes silent. At the cap the listener pauses accepting, warns, and increments `proxy_listener_saturated_total`. `TrackingListener.Close()` releases a parked accept, without which `http.Server.Shutdown` deadlocks waiting on its listener group
- Per-rewrite `insecure`: skips TLS verification for specific rewrite targets (self-signed internal services)
- Per-rewrite `target_scheme`: optional `"http"` or `"https"` to change the request scheme before forwarding (e.g., HTTPS client → HTTP backend). The port moves with the scheme when the client's port was that scheme's default — an intercepted HTTPS request carries `:443` from the CONNECT authority, so without this a downgrade sent cleartext HTTP to the TLS port. An explicitly chosen port is preserved
- Per-rewrite `target_port`: optional TCP port overriding both the client's port and the scheme default, for backends that do not listen on 80/443
- Per-rewrite `drop_headers`: list of header names to strip from the request before forwarding (case-insensitive via `r.Header.Del()`)
- Per-rewrite `path_pattern`: optional regex matched against `r.URL.Path` for path-based routing (rules evaluated in YAML order, first match wins; passed to dialers via request context)
- Blocked request log: optional JSON log file (`blocked_log_path` / `PROXY_BLOCKED_LOG_PATH`) capturing only `BLACK-LISTED` and `BLOCKED` requests; reopened on SIGHUP for log rotation. Written from `proxy.LogBlocked`, called from both the request path and the CONNECT reject path — a rejected tunnel never reaches `HandleRequest`, so without the second call site the log would silently omit those hosts
- Selective request tracing (`trace:` block, see below)
- Hot reload via SIGHUP signal

**Selective Request Tracing (`trace:` block):**

Opt-in, full-detail tracing of a *subset* of requests selected by host and/or URL. Each traced request is emitted as a single aggregated JSON record (keyed by `trace_id` = `X-Request-ID`) spanning every layer: CONNECT/TCP (resolved/connected IP, dial timing, TLS version/cipher), request (inbound headers, outbound post-mutation headers, the dropped/added/modified/scheme-changed diff), response (status, headers), and optionally request/response bodies. Independent of the `-v/-vv/-vvv` log level.

- `enabled`: master switch; when false, tracing is fully short-circuited (no per-request overhead)
- `log_path`: optional dedicated JSON-lines file (reopened on SIGHUP for rotation, like `blocked_log_path`); empty = main log stream
- `rules`: OR across rules; within a rule `host` AND `url` must both match. `host`/`url` use the `WildcardToRegex` convention (wildcard, or `~` prefix for raw regex); `url` is matched against the full `scheme://host/path?query`. Rules carrying a `url` are skipped at CONNECT time (URL not yet known), so passthrough hosts are matched by `host` only.
- Redaction is secure-by-default: built-in masked headers (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, plus the URL-bearing `Location`, `Content-Location`, `Referer`) always apply, and `redactURL` strips `user:password@`. **Bodies are never redacted** — `renderBody` takes no redactor; `redact_headers` extends the set; `redact_query` masks query-string values and **defaults to true** (set `false` to opt out); `log_secrets: true` is the escape hatch that disables all redaction.
- Per-rule `bodies`: `enabled`, `capture` (request/response/both), `max_request_bytes`/`max_response_bytes` (default 8192), `content_types` allowlist (logged as text; supports `type/*`), `on_binary` (base64/skip). Bodies are teed (streaming preserved). With response-body capture enabled the record is emitted when that body finishes streaming; otherwise — capture off (the default), a 101 upgrade, or an empty body — it is emitted at response-header time. Emission is once-only (`sync.Once`).
- Passthrough (non-MITM) hosts are traced TCP-only via goproxy's per-request `ctx.Dialer` (connected IP, dial timing, bytes up/down); headers/bodies are inherently invisible.
- The record is threaded from `HandleRequest` to the dialers via the request context (`trace.CtxKey`) and to the response handler via goproxy `ctx.UserData`.

**Metrics:** Prometheus metrics on `:9090/metrics`:
- `proxy_traffic_total` - requests by domain and action
- `proxy_request_duration_seconds` - request latency by action. Forwarded requests are observed once the upstream round-trip returns, so the span covers DNS, dial, TLS handshake and upstream think-time; blocked requests record in the handler, where their elapsed time is the whole request
- `proxy_active_connections` - client connections currently open, published as a GaugeFunc backed by `TrackingListener.Open()`. It was previously incremented around the `OnRequest` filter, which returns before the upstream round-trip, so it bracketed rule evaluation and read ~0 at every scrape
- `proxy_config_load_errors_total` / `proxy_config_reloads_total` - config operations
- `proxy_upstream_errors_total` - upstream connection errors by type
- `proxy_response_status_total` - response status codes by class
- `proxy_bytes_total` - bytes transferred by direction
- `proxy_trace_records_total` - emitted trace records by mode (mitm/passthrough)

**Health Endpoints:** `/healthz` (liveness), `/readyz` (readiness).

`/readyz` is backed by an atomic flag: 503 until the proxy listener is bound, 200 while serving, 503 again as the first step of shutdown so load balancers stop sending traffic before draining begins. `/healthz` stays independent — failing it during a drain would have Kubernetes kill the pod mid-drain.

**Graceful Shutdown:** SIGINT/SIGTERM. Readiness fails first, then the proxy keeps serving for `PROXY_PRESTOP_GRACE` (default 10s) — failing readiness and closing the listener in the same instant just produces ECONNREFUSED until the next probe, so only already-accepted connections would benefit from the drain. Then `http.Server.Shutdown` drains non-hijacked connections, and `TrackingListener.WaitForDrain` waits out the CONNECT tunnels `http.Server` cannot see, within a 30s budget. The sequence lives in `drain()` (cmd/mitm-proxy/drain.go), extracted from `main` so its ordering is testable. `main` joins the drain goroutine rather than returning underneath it, and `stop()` runs as soon as the context cancels so a second SIGINT/SIGTERM terminates rather than being swallowed for the whole window. Deployment grace periods must exceed grace + drain: the k8s manifest and docker-compose both use 45s.

**Hot Reload:** SIGHUP reloads ACL, rewrites, trace config, both log files and outbound TLS, and calls `transportPool.Reset()`. It does **not** reload the MITM CA, `mitm_org` or the listen ports — those are captured at startup — and logs a warning naming any that changed.

**Timeouts:** upstream TCP dial 5s, upstream TLS handshake 10s (nothing else bounds it: `TLSHandshakeTimeout` does not apply with a custom `DialTLSContext`), response header 30s, server `ReadHeaderTimeout` 10s, idle 120s. There is deliberately no whole-request deadline: a proxy streams arbitrary bodies, and the previous absolute `ReadTimeout` severed plain HTTP mid-body while leaving every hijacked CONNECT tunnel unbounded.

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
  reload.go                    # SIGHUP reload (extracted from main for testability)
  drain.go                     # Graceful-shutdown sequence (readiness, grace, drain, release)
  drain_test.go                # Shutdown ordering tests
  main_test.go                 # Version and usage tests
  prestop_test.go              # PROXY_PRESTOP_GRACE parsing tests
  reload_test.go               # Reload, fd cleanup, log rotation tests
  reload_signal_test.go        # SIGHUP-driven reload (build tag: unix)
internal/config/
  config.go                    # Config types, loading, validation, ACL/rewrite compilation
  config_test.go               # Config, ACL, rewrite, runtime, validate tests
internal/cert/
  cert.go                      # MITM cert loading, signing, TLS pool building
  gencert.go                   # gencert subcommand, key pair generation
  cert_test.go                 # Cert, signing, gencert, truststore tests
internal/proxy/
  handler.go                   # Request handling, dialers, rewrite lookup, metrics recording
  connect.go                   # CONNECT-stage handler (extracted from main for testability)
  transport.go                 # Per-rewrite-target transport pool
  handler_test.go              # Handler, dialer, rewrite, metrics tests
  transport_test.go            # Transport pool keying, reset, concurrency tests
  pool_integration_test.go     # Connection-reuse correctness (target + insecure isolation)
  trace_handler_test.go        # Trace setup, header-diff, context threading tests
  trace_integration_test.go    # In-process end-to-end trace through goproxy + real dialer
internal/trace/
  trace.go                     # Trace Record, redaction, body capture, aggregated emit
  conn.go                      # Passthrough tunnel dialer + byte-counting conn
  trace_test.go                # Record emit, redaction, body truncation/binary tests
internal/metrics/
  metrics.go                   # Prometheus metric var registrations
internal/health/
  health.go                    # Health and readiness HTTP handlers
e2e_test.go                    # End-to-end tests (build tag: e2e, Docker-based)
Makefile                       # Build and dev commands
.golangci.yml                  # Linter configuration
.github/workflows/ci.yaml     # CI pipeline (pull requests targeting main)
.github/workflows/release.yaml # Release pipeline (main pushes/tags; publishes on v* tags)
.github/dependabot.yml         # Dependency updates
docker-compose.yaml            # Local dev environment
```

## Dependencies

- `github.com/elazarl/goproxy` - HTTP proxy with MITM support
- `github.com/prometheus/client_golang` - Prometheus metrics
- `software.sslmate.com/src/go-pkcs12` - PKCS#12 keystore/truststore encoding and decoding
- `gopkg.in/yaml.v3` - Config parsing

## Conventions

- Git branching: `feature/`, `bugfix/`, `hotfix/`, `release/` prefixes
- **Never push directly to `main`** — always create a feature branch and open a pull request
- Do not add `Co-Authored-By` lines in commit messages
- Do not add `Generated with Claude Code` lines in pull request descriptions
