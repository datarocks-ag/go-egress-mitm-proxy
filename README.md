# go-egress-proxy

A MITM HTTP/HTTPS proxy implementing split-brain DNS for egress traffic control in containerized environments.

## Features

- **Split-brain DNS** via TCP dial interception (not DNS-level)
- **Regex-based ACL** with whitelist/blacklist support
- **Domain rewriting** with wildcard support (`*.example.com`)
- **Header injection** including automatic `X-Request-ID` for tracing
- **Hot reload** via SIGHUP signal (no restart required)
- **Environment variable overrides** for 12-factor app compatibility
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
  mitm_cert_path: "certs/ca.crt"
  mitm_key_path: "certs/ca.key"
  outgoing_ca_bundle: ""    # Optional: custom CA for upstream TLS

rewrites:
  - domain: "api.production.com"      # Exact match
    target_ip: "10.20.30.40"
    headers:
      X-Proxy-Source: "egress-gateway"
  - domain: "*.internal.example.com"  # Wildcard match
    target_ip: "10.20.30.50"

acl:
  whitelist:
    - "^.*\\.google\\.com$"
    - "github.com"
  blacklist:
    - "^.*\\.tiktok\\.com$"
```

See [doc/examples/configuration.yaml](doc/examples/configuration.yaml) for a complete example.

### Environment Variable Overrides

All config options can be overridden via environment variables:

| Variable | Description |
|----------|-------------|
| `CONFIG_PATH` | Path to config file (default: `config.yaml`) |
| `PROXY_PORT` | Proxy listen port |
| `PROXY_METRICS_PORT` | Metrics endpoint port |
| `PROXY_DEFAULT_POLICY` | `ALLOW` or `BLOCK` |
| `PROXY_MITM_CERT_PATH` | Path to MITM certificate |
| `PROXY_MITM_KEY_PATH` | Path to MITM private key |
| `PROXY_OUTGOING_CA_BUNDLE` | Path to CA bundle for upstream |

## Development

```bash
# Install development tools
make install-tools

# Run linter
make lint

# Run tests
make test

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
pgrep mitm-proxy

# Send SIGHUP to reload config
kill -HUP <pid>
```

The proxy will log successful reloads and any errors.

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
