# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries summarize each release at a high level; see the linked pull requests and
git history for the full detail.

## [Unreleased]

### Added
- **`trace.redact_headers` entries may be prefixed with `-` to remove a built-in
  default.** `redact_headers: ["-location"]` makes redirect targets visible while
  `Authorization` and `Cookie` stay masked. Until now the only way to see a
  masked header was `log_secrets: true`, which disables redaction entirely -- so
  an operator who needed `Location` to follow a redirect chain had to give up the
  masking of every credential to get it, and an all-or-nothing escape hatch
  invites reaching for the widest setting to solve the narrowest problem.

  Entries apply in order, so `["-location", "location"]` re-masks it. Removing a
  credential-bearing default (`Authorization`, `Proxy-Authorization`, `Cookie`,
  `Set-Cookie`) is allowed but logs a warning at startup naming the header.
  Removing a header that is not masked is a load error listing the built-ins,
  rather than a no-op that reads as having taken effect -- for a redaction
  setting, silently doing nothing means believing a header is visible when it
  was never masked.

## [4.0.0] - 2026-08-07

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

- **A rewrite rule no longer overrides the blacklist.** The rewrite table was
  consulted before the denylist, so a host that matched both was `REWRITTEN` and
  forwarded — to the rule's `target_ip`, carrying that rule's injected headers.
  A denied host was not merely allowed, it was allowed with credentials attached.
  The blacklist is now evaluated first on the request path.
- **Blacklisted HTTPS hosts get a 403 and an audit-log entry.** Narrowing the
  CONNECT-stage check to passthrough hosts removed the backstop for everything
  else; blacklisted hosts are now intercepted and refused by the handler, which
  is also what puts them in the blocked-request log.
- **A blacklisted HTTPS attempt is recorded even when interception fails.** A
  blacklisted host is intercepted rather than refused so the handler can answer
  with a readable 403, but that leaves the denial recorded only if the client
  completes the handshake with the proxy's certificate — a pinning SDK or a JVM
  truststore never will, and goproxy routes that failure to debug level. The
  attempt now warns and counts under a distinct `BLACK-LISTED-CONNECT` action at
  the CONNECT stage, so a denial is observable regardless of whether the client
  cooperates. The separate label keeps it from inflating the `BLACK-LISTED`
  count that `HandleRequest` records when the handshake does succeed.
- **The truststore password is kept out of the log stream.**
- **The leaf-certificate cache is keyed by signing identity**, not by hostname
  alone, so two callers configured with different CAs cannot be served each
  other's leaves.
- **A metrics-port bind failure is fatal** instead of leaving the proxy running
  with no observability.
- **Trace records survive log rotation.** The logger is resolved when the record
  is emitted rather than captured when the request starts, so a SIGHUP mid-request
  no longer writes the record to the closed file.
- **Body capture no longer breaks WebSocket upgrades.** A 101 response hands the
  body to the caller as an `io.ReadWriter` for the upgraded connection; wrapping
  it broke the upgrade outright.
- **A late dial cannot contradict a reused connection.** An abandoned dial could
  still write `connected_ip` and dial timing onto a record already marked
  `connection_reused`, producing a trace that answered "where did this request
  go" with a socket the request never used.

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
- **A rewrite rule's `headers: {Host: ...}` reaches the backend.** `Host` is not
  stored in `Request.Header`: net/http excludes it from `Header.WriteSubset` and
  derives the wire value, and the HTTP/2 `:authority`, from `Request.Host`. The
  injected value was silently discarded, so a rewrite aimed at a name-based vhost
  got the load balancer's default backend -- while the ACCESS log said `REWRITTEN`
  and the trace diff listed `Host` as added. Every observability surface reported
  success.
- **`target_scheme` moves the port with the scheme.** goproxy builds the MITM
  request URL from the CONNECT authority, so an intercepted HTTPS request carries
  `:443`. Rewriting only the scheme sent cleartext HTTP to port 443 of the target,
  which a backend serving HTTP on 80 or 8080 refuses and a TLS listener reads as a
  malformed record. The documented "HTTPS client to HTTP backend" rewrite could
  not work under any configuration. A port that was the old scheme's default now
  moves to the new one's; a port the operator chose explicitly is kept.
- **A saturated connection ceiling no longer deadlocks shutdown.** `Accept` waits
  for a free slot before calling the underlying `Accept`, and closing a
  `net.Listener` does not interrupt a channel send. `http.Server.Shutdown` waits
  on its listener group for `Serve` to return and that wait ignores its context,
  so `Shutdown` never returned -- and in the drain sequence it is the first call,
  leaving the tunnel drain, metrics shutdown and log close unrun and the process
  hanging until SIGKILL. Closing the listener now releases a parked accept.
- **A second SIGINT/SIGTERM terminates.** `signal.NotifyContext` keeps the signal
  suppressed until `stop()`, which ran only at the end of `main` -- so a second
  Ctrl-C did nothing for up to 40s and the operator needed SIGKILL from another
  shell.
- **Trace records no longer claim connection reuse for requests that were never
  forwarded.** The inference was "no dial, no error", which is also true of the
  403 synthesized for a blocked host, so the record asserted an upstream
  connection to a host the proxy refused to contact. Upstream errors that the
  round-trip wrapper converts into a synthetic 502/504 are now recorded too;
  previously such a record carried the status and no cause at all.
- **A request refused after its body was counted no longer inflates
  `proxy_bytes_total`.** The request-bytes increment ran before the block check,
  so a 10 MB POST to a blacklisted host was counted as egress that never left.
- **The blocked-request audit write holds the read lock.** A SIGHUP between
  fetching the logger and writing closed the file underneath the write, and slog
  discards handler errors, so the entry appeared in neither the rotated nor the
  new file.
- **The Kubernetes example gates cleartext egress.** It set only `HTTPS_PROXY`;
  every proxy-aware client selects by request scheme, so all plain-HTTP egress
  went direct -- no ACL evaluation, no 403, no blocked-log entry, no metric.
- **Fail-open denylist entries in the example configuration.** The example is
  what the Quick Start says to copy, so its denylist reads as an idiom. A raw
  regex was annotated as a substring match when raw patterns are anchored
  (`ads.social-media.internal` went straight through), and the wildcard entries
  left the bare apex domains `ALLOWED-BY-DEFAULT`. The example config, the
  Kubernetes ConfigMap and the Deployment's config mount path are now covered by
  tests, which is what had been missing when each of them shipped broken.

### Breaking
- **Trace records mask `Location`, `Content-Location` and `Referer` by default.**
  `redact_query` only ever saw the request URL, and header values are masked by
  name, so an OAuth 302 wrote the authorization code to the trace log verbatim.
  These three now join the always-masked set and `redactURL` strips
  `user:password@`. Anything parsing redirect targets out of trace records will
  see `<redacted>`; add them to an allowlist only by setting `log_secrets: true`,
  which disables all redaction.
- **`proxy_traffic_total{domain}` changes for rewritten requests.** A rewrite is
  now labelled with the matching rule's configured pattern (for example
  `*.internal.example.com`) instead of the request host. Previously only
  exact-match rules got their own label and every wildcard or regex rewrite
  collapsed into `_other`. **Dashboards and alerts grouping on `domain` will see
  new series for rewritten traffic and a drop in `_other`.**
- **A rewrite configuring `Content-Length`, `Transfer-Encoding` or `Trailer` in
  `headers`, or `Host` in `drop_headers`, no longer loads.** net/http derives
  those from the request body and discards a configured value, and `Host` cannot
  be removed from the header map at all, so the settings silently did nothing.
  Run `mitm-proxy validate --config <file>` before upgrading.
- **The blocked-request log renames `path` to `target`.** A CONNECT carries
  `host:port` in its request-target rather than a path, so the old field was
  empty for exactly the entries an audit log most needs — rejected HTTPS
  tunnels. Log consumers keying on `path` must be updated.
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
- The container image is built with the toolchain the tests run against. The
  Dockerfile used Go 1.26 while `go.mod` declared 1.25 and every CI step pinned
  1.25; the `go` directive fixes the language version, not the linked standard
  library, so the published image and the release binaries linked a different
  `crypto/tls`, `net/http` and hijacked-connection implementation from the one the
  unit tests exercised. `go.mod` is now the single source and the workflows read
  it via `go-version-file`.
- The example Kubernetes manifest declares the proxy as a native sidecar (an
  `initContainer` with `restartPolicy: Always`, Kubernetes 1.29+). As an ordinary
  container the kubelet stops it alongside the application, so egress died while
  the application was still draining.
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
- `proxy_request_duration_seconds` measures the request, not the policy handler.
  It was observed around rule evaluation and returned before the upstream
  round-trip, so it reported proxy overhead while looking like request latency.
  Forwarded requests are now observed once the round-trip returns, so the span
  covers DNS, dial, TLS handshake and upstream think-time. **Existing dashboards
  and alert thresholds on this histogram will shift upward.**
- `proxy_active_connections` is a `GaugeFunc` backed by the listener's live
  count. It was incremented around the `OnRequest` filter, which returns before
  the upstream round-trip and never saw hijacked CONNECT tunnels at all, so it
  read approximately zero at every scrape.
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
- Per-rewrite `target_port`: the TCP port to connect to, overriding both the
  client's port and the scheme default. Needed whenever a rewrite target does not
  listen on 80/443 -- a legacy backend on `8080` behind a `target_scheme`
  downgrade is the usual case.
- `max_connections` / `PROXY_MAX_CONNECTIONS` (default `0`, unlimited): a ceiling
  on concurrent client connections. A hijacked CONNECT tunnel carries no deadline
  at any layer -- `ReadHeaderTimeout` covers only the CONNECT request line, and
  hijacking clears the deadline -- so a client that connects and goes silent holds
  a descriptor and a goroutine until the process exits. At the cap the listener
  pauses accepting until one closes, warns, and increments the new
  `proxy_listener_saturated_total`. The shipped Kubernetes example sets 2048.
- `proxy_listener_saturated_total`: times the connection ceiling was reached.
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

[4.0.0]: https://github.com/datarocks-ag/go-egress-mitm-proxy/compare/v3.0.0...v4.0.0
[3.0.0]: https://github.com/datarocks-ag/go-egress-mitm-proxy/compare/v2.3.0...v3.0.0
[2.3.0]: https://github.com/datarocks-ag/go-egress-mitm-proxy/compare/v2.2.1...v2.3.0
[2.2.1]: https://github.com/datarocks-ag/go-egress-mitm-proxy/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/datarocks-ag/go-egress-mitm-proxy/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/datarocks-ag/go-egress-mitm-proxy/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/datarocks-ag/go-egress-mitm-proxy/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/datarocks-ag/go-egress-mitm-proxy/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/datarocks-ag/go-egress-mitm-proxy/releases/tag/v1.0.0
