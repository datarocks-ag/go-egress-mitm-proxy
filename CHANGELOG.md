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
