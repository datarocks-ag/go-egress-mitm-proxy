# go-egress-proxy

A MITM HTTP/HTTPS proxy implementing split-brain DNS for egress traffic control in containerized environments.

## Features

- **Split-brain DNS** via TCP dial interception (not DNS-level), with `target_ip` or `target_host` routing
- **Path-based routing** - route different URL paths on the same domain to different backends (`path_pattern`)
- **Scheme rewriting** - change the request scheme before forwarding (`target_scheme`)
- **ACL** with whitelist/blacklist support (exact match, wildcards, regex)
- **Header injection** on rewritten requests, plus automatic `X-Request-ID` for tracing
- **Header stripping** - remove sensitive headers before forwarding (`drop_headers`)
- **Per-rewrite TLS bypass** - skip upstream TLS verification for specific targets (`insecure`)
- **Outgoing TLS trust** - custom CA bundle (PEM) and/or PKCS#12 truststore for upstream verification
- **Hot reload** via SIGHUP signal (no restart required)
- **Blocked request log** - optional JSON log file for auditing blocked requests
- **Environment variable overrides** for 12-factor app compatibility
- **Outbound HTTP/2** - negotiates HTTP/2 with upstream servers via ALPN
- **Prometheus metrics** - request counts, latency histograms, active connections, upstream errors
- **Graceful shutdown** - proper connection draining on SIGTERM
- **Health endpoints** - `/healthz` and `/readyz` for Kubernetes probes

## Quick Start

```bash
# 1. Generate internal CA certificates
make certs

# 2. Create config.yaml (copy from example)
cp doc/examples/configuration.yaml config.yaml

# 3. Edit config.yaml with your rules

# 4. Run the proxy
make run

# 5. Test (in another terminal)
curl -v -x http://localhost:8080 --cacert certs/ca.crt https://example.com
```

## Configuration

Create a `config.yaml` file (or set `CONFIG_PATH` environment variable):

```yaml
proxy:
  port: "8080"              # Proxy listen port
  metrics_port: "9090"      # Metrics/health endpoint port
  default_policy: "BLOCK"   # ALLOW or BLOCK unmatched hosts
  outgoing_ca_bundle: ""    # Optional: PEM CA bundle for upstream TLS
  blocked_log_path: ""      # Optional: JSON log file for blocked requests

  # Optional: PKCS#12 truststore for upstream TLS (additive with outgoing_ca_bundle)
  # outgoing_truststore_path: "certs/upstream-cas.p12"
  # outgoing_truststore_password: "changeit"

  # Disable upstream TLS certificate verification globally (for dev/test only!)
  # insecure_skip_verify: false

  # MITM CA certificate - provide either PEM cert+key or a PKCS#12 keystore (not both)

  # Option A: PEM cert + key (default)
  mitm_cert_path: "certs/ca.crt"
  mitm_key_path: "certs/ca.key"

  # Option B: PKCS#12 keystore (mutually exclusive with cert+key)
  # mitm_keystore_path: "certs/ca.p12"
  # mitm_keystore_password: "changeit"

rewrites:
  # Route by IP address
  - domain: "api.production.com"
    target_ip: "10.20.30.40"
    headers:
      X-Proxy-Source: "egress-gateway"

  # Route by hostname (DNS-resolved at dial time)
  - domain: "external-api.partner.com"
    target_host: "internal-gateway.corp.example.com"

  # Wildcard match (any subdomain depth)
  - domain: "*.internal.example.com"
    target_ip: "10.20.30.50"

  # Regex match (prefix with ~)
  - domain: "~^api[0-9]+\\.example\\.com$"
    target_ip: "10.20.30.60"

  # Per-rewrite TLS bypass for self-signed internal services
  - domain: "self-signed.internal.com"
    target_ip: "10.20.30.70"
    insecure: true

  # Path-based routing (first match wins, evaluated in YAML order)
  - domain: "api.example.com"
    path_pattern: "^/v1/"
    target_ip: "10.20.30.80"
    headers:
      X-Backend: "v1"
  - domain: "api.example.com"
    path_pattern: "^/v2/"
    target_ip: "10.20.30.81"
  - domain: "api.example.com"       # Catch-all (no path_pattern)
    target_ip: "10.20.30.82"

  # Scheme rewriting: forward HTTPS client requests as HTTP to backend
  - domain: "legacy-backend.internal.com"
    target_ip: "10.20.30.90"
    target_scheme: "http"

  # Strip sensitive headers before forwarding
  - domain: "sanitized-api.internal.com"
    target_ip: "10.20.30.91"
    drop_headers:
      - "Authorization"
      - "Cookie"

acl:
  whitelist:
    - "*.google.com"
    - "github.com"
  blacklist:
    - "*.tiktok.com"
```

See [doc/examples/configuration.yaml](doc/examples/configuration.yaml) for a complete example.

### Rewrite Rule Reference

Each rewrite rule supports these fields:

| Field | Required | Description |
|-------|----------|-------------|
| `domain` | yes | Domain pattern: exact, wildcard (`*.example.com`), or regex (`~<pattern>`) |
| `target_ip` | one of | IP address to route to (mutually exclusive with `target_host`) |
| `target_host` | one of | Hostname to route to, resolved via DNS at dial time |
| `path_pattern` | no | Regex matched against `r.URL.Path` for path-based routing |
| `target_scheme` | no | `"http"` or `"https"` to change the request scheme before forwarding |
| `headers` | no | Map of headers to inject into the request |
| `drop_headers` | no | List of header names to remove before forwarding |
| `insecure` | no | Skip upstream TLS verification for this target only |

### Response Status Codes

| Code | Meaning | When |
|------|---------|------|
| 200 | OK | Request succeeded through to upstream |
| 403 | Forbidden | Request blocked by ACL (blacklisted or default BLOCK policy) |
| 502 | Bad Gateway | Upstream unreachable: DNS lookup failed, connection refused, or connection reset |
| 504 | Gateway Timeout | Upstream accepted the connection but did not respond in time |

### Configuration Validation

Validate your configuration file without starting the proxy:

```bash
# Use --config flag
go-egress-proxy validate --config config.yaml

# Or use CONFIG_PATH environment variable
CONFIG_PATH=config.yaml go-egress-proxy validate

# Default: reads config.yaml from current directory
go-egress-proxy validate
```

The `validate` subcommand checks:
- YAML syntax and structure
- Required fields and valid values (including `target_scheme`, `path_pattern` regex)
- Mutual exclusivity of `target_ip`/`target_host` and cert+key/keystore
- ACL and rewrite pattern compilation
- Referenced files exist and are readable (certificates, CA bundles, truststores)
- Parent directory exists for `blocked_log_path`

Exits with code 0 on success, 1 on failure.

### Environment Variable Overrides

All config options can be overridden via environment variables:

| Variable | Description |
|----------|-------------|
| `CONFIG_PATH` | Path to config file (default: `config.yaml`) |
| `PROXY_PORT` | Proxy listen port |
| `PROXY_METRICS_PORT` | Metrics endpoint port |
| `PROXY_DEFAULT_POLICY` | `ALLOW` or `BLOCK` |
| `PROXY_MITM_CERT_PATH` | Path to MITM CA certificate (PEM) |
| `PROXY_MITM_KEY_PATH` | Path to MITM CA private key (PEM) |
| `PROXY_MITM_KEYSTORE_PATH` | Path to PKCS#12 keystore (`.p12`) containing cert and key |
| `PROXY_MITM_KEYSTORE_PASSWORD` | Password for PKCS#12 keystore |
| `PROXY_OUTGOING_CA_BUNDLE` | Path to PEM CA bundle for upstream TLS |
| `PROXY_OUTGOING_TRUSTSTORE_PATH` | Path to PKCS#12 truststore for upstream TLS |
| `PROXY_OUTGOING_TRUSTSTORE_PASSWORD` | Password for PKCS#12 truststore |
| `PROXY_INSECURE_SKIP_VERIFY` | Set to `true` to disable all upstream TLS verification |
| `PROXY_BLOCKED_LOG_PATH` | Path to JSON log file for blocked requests |

> **Note:** Provide either `PROXY_MITM_CERT_PATH`/`PROXY_MITM_KEY_PATH` **or** `PROXY_MITM_KEYSTORE_PATH`, not both.

## Development

```bash
# Install development tools
make install-tools

# Run linter
make lint

# Run tests
make test

# Run end-to-end tests (requires Docker)
make test-e2e

# Build binary
make build

# Format code
make fmt
```

## Docker

```bash
# Build
make docker-build

# Run
make docker-run

# Or with docker-compose
docker-compose up
```

## Kubernetes

Deploy as a sidecar container. See [doc/k8s/](doc/k8s/) for example manifests.

```yaml
# In your application deployment
env:
  - name: HTTPS_PROXY
    value: "http://localhost:8080"
  - name: HTTP_PROXY
    value: "http://localhost:8080"
```

## Hot Reload

Reload configuration without restarting the proxy:

```bash
# Find the process ID
pgrep go-egress-proxy

# Send SIGHUP to reload config
kill -HUP <pid>
```

The proxy will log successful reloads and any errors. SIGHUP also reopens the blocked request log file, enabling log rotation.

## Blocked Request Log

When `blocked_log_path` is configured, the proxy writes a JSON log entry for every request with action `BLACK-LISTED` or `BLOCKED`. Each entry includes `request_id`, `client`, `host`, `method`, `path`, and `action`. The log file is reopened on SIGHUP for log rotation support.

## Metrics

Available at `http://localhost:9090/metrics`:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `proxy_traffic_total` | Counter | domain, action | Request count |
| `proxy_request_duration_seconds` | Histogram | action | Request latency |
| `proxy_active_connections` | Gauge | - | Current connections |
| `proxy_config_load_errors_total` | Counter | - | Config load failures |
| `proxy_config_reloads_total` | Counter | - | Successful config reloads |
| `proxy_upstream_errors_total` | Counter | type | Upstream connection errors |
| `proxy_response_status_total` | Counter | class | Response status codes (2xx, 4xx, 5xx) |
| `proxy_bytes_total` | Counter | direction | Bytes transferred (request/response) |

Actions: `REWRITTEN`, `WHITE-LISTED`, `BLACK-LISTED`, `ALLOWED-BY-DEFAULT`, `BLOCKED`

## Health Endpoints

- `GET /healthz` - Liveness probe (always returns 200 if process is running)
- `GET /readyz` - Readiness probe (returns 200 when ready to accept traffic)

## Request Tracing

The proxy automatically injects an `X-Request-ID` header into all forwarded requests for distributed tracing. This ID is also logged with each access log entry.

## Client Setup

Clients must trust the internal CA certificate. Install `certs/ca.crt` as a trusted root CA:

```bash
# Linux (system-wide)
sudo cp certs/ca.crt /usr/local/share/ca-certificates/proxy-ca.crt
sudo update-ca-certificates

# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/ca.crt

# curl (per-request)
curl --cacert certs/ca.crt -x http://localhost:8080 https://example.com
```

## Architecture

See [doc/architecture.md](doc/architecture.md) for detailed design documentation.

## License

MIT
