# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries summarize each release at a high level; see the linked pull requests and
git history for the full detail.

## [Unreleased]

### Fixed
- **Connection pool no longer ignores the rewrite target.** Go keys idle
  connections on the request URL's `host:port`, which is fixed before the
  split-brain dialers substitute the target address. Rules for the same domain
  that differed only by `target_ip`/`target_host` — notably `path_pattern`
  rules — therefore shared one pool key and reused each other's connections, so
  a request could be silently served by the wrong backend. Each distinct upstream
  identity now gets its own `http.Transport` (`proxy.TransportPool`), keeping
  pooling and HTTP/2 intact while making the pool key correct.
- **Per-rewrite `insecure` no longer leaks across requests.** The same defect let
  a connection negotiated with `InsecureSkipVerify: true` be handed to a later
  request that required full certificate verification, silently bypassing it.
  Verification mode is now part of the transport identity.
- SIGHUP reload drops pooled connections to the previous rewrite targets instead
  of letting them serve until `IdleConnTimeout` (90s) expires.

Findings from a full multi-lens code review of `main`, grouped by area:

- **Hostnames are normalized before every policy decision.** DNS names are
  case-insensitive and a trailing dot denotes the same FQDN, but patterns were
  compiled case-sensitively and hosts were matched verbatim. In the documented
  denylist deployment (`default_policy: ALLOW` plus a blacklist) that was a full
  egress-control bypass costing one uppercase letter, and it silently disabled
  rewrite rules in the other direction — sending a request over public DNS
  without its injected headers.
- **The blacklist is evaluated before passthrough.** A passthrough match accepts
  the tunnel, and an accepted tunnel never reaches the request handler where
  every other blacklist check lives, so a broad passthrough pattern voided the
  blacklist entries it overlapped.
- **Raw `~` host patterns are anchored.** Unanchored, a whitelist entry such as
  `~api\.corp\.com` also matched `api.corp.com.attacker.net`. Trace `url`
  patterns deliberately remain substring matches.
- **Tracing no longer alters the traffic it observes.** Enabling trace on a
  passthrough host replaced the dialer, losing rewrite targets and dial metrics
  (so tracing a route changed the route); the tunnel wrapper hid
  `CloseRead`/`CloseWrite`, truncating protocols that half-close; and response
  bodies were wrapped unconditionally, re-framing every traced response as
  chunked and emitting an invalid chunked 204/304. Also fixes a data race in the
  body buffer.
- **Graceful shutdown actually drains.** The drain ran in a goroutine nothing
  joined, so the process exited mid-drain and the 30s budget never elapsed; and
  CONNECT tunnels — all HTTPS traffic — were never tracked at all, because
  `http.Server` stops tracking hijacked connections.
- **`/readyz` reports real state.** Previously a hardcoded 200, so it reported
  ready before the proxy port was bound and stayed ready while draining.
- **SIGHUP warns about settings it cannot apply** (`mitm_*`, `port`,
  `metrics_port`) instead of reporting a clean reload that ignored them.
- **Leaf certificates share one bounded, expiring cache.** The default path
  re-signed on every CONNECT; setting `mitm_org` switched to a cache with no
  eviction and no expiry. `SignHost` also attached only the first CA
  certificate, breaking path building for multi-level chains.
- **Unloadable CA sources are fatal** rather than warned-and-continued with a
  success message and an incremented success counter.
- **The upstream TLS handshake is bounded** (10s). Nothing bounded it before —
  `TLSHandshakeTimeout` does not apply with a custom `DialTLSContext` — so a
  target that accepted the connection and then went silent parked a goroutine
  and two file descriptors indefinitely.
- **`HTTPS_PROXY` in the environment no longer bypasses the dialers**, which had
  silently disabled `target_ip` substitution, tracing and dial metrics for every
  CONNECT.
- **The Security Scan CI job can fail.** All trivy steps lacked `exit-code`, so
  a CRITICAL shipped with a green pipeline. The scanned image is now the pushed
  image.
- `gencert` creates its output directories, so the documented Quick Start works
  on a fresh clone.

### Breaking
- **Configs containing a misplaced `*` no longer load.** Only a leading `*.`
  label is expanded; a `*` anywhere else survived escaping and was then anchored,
  so `api.*.evil.com` compiled to a pattern that matched nothing. On a blacklist
  that fails open — the entry blocked nothing, `validate` reported the file as
  valid, and every host it was meant to deny was `ALLOWED-BY-DEFAULT`. Such a
  pattern is now a load error naming the offending entry. The bare `*.` form is
  rejected for the same reason. Use a `~` prefix for a raw regex if you need a
  `*` elsewhere. **Run `mitm-proxy validate --config <file>` before upgrading:**
  a config that silently under-enforced will now refuse to start.

### Changed
- Server timeouts: `ReadTimeout`/`WriteTimeout` replaced with
  `ReadHeaderTimeout`. The old absolute deadlines severed plain-HTTP transfers
  at 60s mid-body while leaving every CONNECT tunnel unbounded, since hijacking
  clears the deadline.
- Idle connection limits are sized per transport rather than assuming a single
  global pool, since `TransportPool` clones a transport per rewrite target.
  `MaxConnsPerHost` is deliberately left unset: Go keys it on the request URL
  host, which is computed before the dialer substitutes `target_ip`, so it does
  not bound sockets to a shared upstream IP — and on reaching the cap it parks
  requests with no deadline, trading a bound for unbounded latency.
  `TransportPool.Len()` makes pool growth observable instead.
- The example configuration ships with `trace.enabled: false`. It is the file the
  Quick Start copies, and the previous default both failed validation (its
  `log_path` parent directory does not exist) and captured full headers and
  bodies by default.
- `cert.BuildOutboundTLSConfig` and `cert.LoadCertPool` now return errors.
- `trace.redact_query` defaults to `true`. Query strings routinely carry tokens
  in `?access_token=`/`?sig=` form, so the safe setting is the one you get by
  omitting the field; set `redact_query: false` to opt out.
- Trace records reach the main log stream at the default (warn) verbosity. They
  are written at info, so with no `trace.log_path` set they were previously
  discarded by the default handler while `proxy_trace_records_total` still
  counted them — the counter and the log disagreed permanently. The main-stream
  trace logger now always admits info, and the counter only advances when a
  record is actually written.
- Kubernetes example manifests: corrected the config mount path (the container
  read `/app/config.yaml` while the ConfigMap mounted at `/root/config.yaml`, so
  it exited on start), fixed a whitelist pattern that could never match, and
  added readiness/liveness probes with a grace period exceeding the drain budget.

### Added
- `PROXY_PRESTOP_GRACE` (default `10s`): how long to keep serving after `/readyz`
  starts failing on SIGTERM, so load balancers observe the failure and route away
  before the listener closes. Set `0` when a `preStop` hook already sleeps.

## [3.0.0] - 2026-06-03

### Added
- **Selective full-detail request tracing** (`trace:` config block). Trace a
  configurable subset of requests — selected by host and/or URL regex — as a
  single aggregated JSON record spanning every layer at once:
  - CONNECT/TCP/TLS: host (with port), SNI, resolved/connected IP, dial timing,
    negotiated TLS version/cipher
  - Request: inbound headers, outbound (post-mutation) headers, and the
    `dropped`/`added`/`modified`/`scheme_changed` diff
  - Response: status, proto, headers
  - Optional per-rule request/response bodies (size-capped, content-type-gated,
    streaming preserved)

  Redaction is secure-by-default (`Authorization`, `Proxy-Authorization`,
  `Cookie`, `Set-Cookie` always masked; `redact_headers`/`redact_query` extend
  it; `log_secrets` is an explicit escape hatch). Passthrough (non-MITM) hosts
  are traced TCP-only. Tracing is independent of the `-v/-vv/-vvv` log level,
  hot-reloadable via SIGHUP, and writes to an optional dedicated JSON-lines file.
- New `proxy_trace_records_total{mode}` Prometheus metric.

### Changed
- Refreshed dependencies (goproxy, testcontainers-go, go-pkcs12, golangci-lint,
  and the `golang.org/x` / OpenTelemetry / gRPC chains).

## [2.3.0] - 2026-02-15

### Changed
- Default log level changed from `info` to `warn` (errors and warnings only);
  subcommands still default to `info`. Verbosity flag ordering, help text, and
  per-subcommand levels refined.
- End-to-end test suite now runs in the CI pipeline.

## [2.2.1] - 2026-02-11

Patch release with log-level/verbosity fixes.

## [2.2.0] - 2026-02-11

### Added
- ACL `passthrough` entries: tunnel CONNECT requests without MITM interception,
  for services that present their own PKI (e.g. the Kubernetes API).
- Debug-level (`-vv`) request-detail logging for troubleshooting.
- Comprehensive input validation for the `gencert` subcommand.

## [2.1.0] - 2026-02-10

### Added
- `gencert` subcommand: generate root and intermediate CA certificates (and
  client trust bundles, PEM + PKCS#12) without an OpenSSL dependency.
- Configurable `mitm_org` for the Organization on MITM leaf certificates.
- `outgoing_ca` list support and HTTPS proxy flow documentation (Mermaid).

### Changed
- Refactored the monolithic `main.go` into a `cmd/` + `internal/` package layout
  (`config`, `cert`, `proxy`, `metrics`, `health`).

## [2.0.0] - 2026-02-06

### Added
- Expanded rewrite options: `target_host` (DNS-resolved at dial time),
  path-based routing (`path_pattern`), scheme rewriting (`target_scheme`), and
  header stripping (`drop_headers`).
- Outgoing TLS trust controls: PKCS#12 truststore, global `insecure_skip_verify`,
  and per-rewrite `insecure`.
- Optional blocked-request JSON log.
- `validate` subcommand to verify configuration without starting the proxy.
- End-to-end (Docker / testcontainers) test suite.

### Changed
- Unified pattern syntax across ACLs and rewrites (exact, wildcard, `~` regex).
- Distinguish upstream failure modes with proper status codes
  (502 Bad Gateway / 504 Gateway Timeout).

## [1.1.0] - 2026-02-05

### Added
- PKCS#12 keystore support for the MITM CA certificate and key.
- Outbound HTTP/2 negotiation with upstream servers via ALPN.

## [1.0.0] - 2026-01-28

Initial release: a MITM HTTP/HTTPS proxy implementing split-brain DNS via TCP
dial interception (not DNS-level). Includes ACL enforcement
(whitelist/blacklist), domain rewriting (`target_ip`), header injection with an
automatic `X-Request-ID`, Prometheus metrics, health endpoints, hot reload
(SIGHUP), graceful shutdown, and a CI pipeline.

[3.0.0]: https://github.com/datarocks-ag/go-egress-mitm-proxy/compare/v2.3.0...v3.0.0
[2.3.0]: https://github.com/datarocks-ag/go-egress-mitm-proxy/compare/v2.2.1...v2.3.0
[2.2.1]: https://github.com/datarocks-ag/go-egress-mitm-proxy/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/datarocks-ag/go-egress-mitm-proxy/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/datarocks-ag/go-egress-mitm-proxy/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/datarocks-ag/go-egress-mitm-proxy/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/datarocks-ag/go-egress-mitm-proxy/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/datarocks-ag/go-egress-mitm-proxy/releases/tag/v1.0.0
