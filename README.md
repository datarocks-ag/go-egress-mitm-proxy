# go-egress-proxy

A MITM HTTP/HTTPS proxy implementing split-brain DNS for egress traffic control in containerized environments.

## Features

- **Split-brain DNS** via TCP dial interception (not DNS-level), with `target_ip` or `target_host` routing
- **Path-based routing** - route different URL paths on the same domain to different backends (`path_pattern`)
- **Scheme rewriting** - change the request scheme before forwarding (`target_scheme`)
- **ACL** with whitelist/blacklist/passthrough support (exact match, wildcards, regex)
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
mitm-proxy gencert --type root --cn "My MITM CA" --out-cert certs/ca.crt --out-key certs/ca.key

# 2. Create config.yaml (copy from example)
cp doc/examples/configuration.yaml config.yaml

# 3. Edit config.yaml with your rules

# 4. Run the proxy
make run

# 5. Test (in another terminal)
curl -v -x http://localhost:8080 --cacert certs/ca.crt https://example.com
```

## CLI Usage

```bash
# Print version
mitm-proxy --version

# Show help
mitm-proxy --help

# Run with default verbosity (info level)
mitm-proxy

# Run with debug output
mitm-proxy -vv

# Validate configuration
mitm-proxy validate --config config.yaml

# Generate certificates (see Certificate Generation section below)
mitm-proxy gencert --help
```

| Flag | Description |
|------|-------------|
| `--version` | Print version and exit |
| `-h`, `--help` | Show help message |
| `-v` | Info level (default) — ACCESS log per request (host, action, method, path) |
| `-vv` | Debug — adds `REQUEST_DETAIL` per request (scheme, full URL, proto, remote addr, content-length, user-agent, content-type, rewrite target) |
| `-vvv` | Trace — adds full request headers to `REQUEST_DETAIL` |

| Subcommand | Description |
|------------|-------------|
| `validate` | Validate configuration file and exit |
| `gencert` | Generate CA certificates (root or intermediate) |

The version is injected at build time. Use `VERSION=1.0.0 make build` to set a specific version, otherwise it defaults to the git describe output or `dev`.

## Configuration

Create a `config.yaml` file (or set `CONFIG_PATH` environment variable):

```yaml
proxy:
  port: "8080"              # Proxy listen port
  metrics_port: "9090"      # Metrics/health endpoint port
  default_policy: "BLOCK"   # ALLOW or BLOCK unmatched hosts
  outgoing_ca_bundle: ""    # Optional: PEM CA bundle for upstream TLS
  outgoing_ca:              # Optional: list of individual CA cert files
    - "certs/internal-ca.crt"
    - "certs/partner-ca.crt"
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
  passthrough:                    # Tunnel without MITM (for services with their own PKI)
    - "kubernetes.default.svc"
    - "*.vault.internal"
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
mitm-proxy validate --config config.yaml

# Or use CONFIG_PATH environment variable
CONFIG_PATH=config.yaml mitm-proxy validate

# Default: reads config.yaml from current directory
mitm-proxy validate
```

The `validate` subcommand checks:
- YAML syntax and structure
- Required fields and valid values (including `target_scheme`, `path_pattern` regex)
- Mutual exclusivity of `target_ip`/`target_host` and cert+key/keystore
- ACL and rewrite pattern compilation
- Referenced files exist and are readable (certificates, CA bundles, truststores)
- Parent directory exists for `blocked_log_path`

Exits with code 0 on success, 1 on failure.

### Certificate Generation

The `gencert` subcommand generates root and intermediate CA certificates with optional client trust bundles. It replaces the need for OpenSSL and the `make certs` script.

```bash
# Generate a root CA (self-signed, ECDSA P-256, 10-year validity)
mitm-proxy gencert --type root \
  --cn "My Root CA" --org "ACME Corp" --country CH \
  --out-cert certs/root-ca.crt --out-key certs/root-ca.key

# Generate an intermediate CA signed by the root (leaf-signing only)
mitm-proxy gencert --type intermediate \
  --signing-cert certs/root-ca.crt --signing-key certs/root-ca.key \
  --cn "MITM Proxy CA" --org "ACME Corp" \
  --max-path-len 0 --validity 365 \
  --out-cert certs/mitm-ca.crt --out-key certs/mitm-ca.key \
  --out-chain certs/mitm-chain.crt

# Generate a root CA with client trust bundles
mitm-proxy gencert --type root --cn "My Root CA" \
  --out-client-bundle certs/trust.pem \
  --out-client-p12 certs/truststore.p12 --client-p12-password changeit
```

| Flag | Default | Description |
|------|---------|-------------|
| `--type` | `root` | `root` (self-signed) or `intermediate` (signed by parent) |
| `--key-algo` | `ecdsa-p256` | `rsa-2048`, `rsa-4096`, `ecdsa-p256`, `ecdsa-p384`, `ed25519` |
| `--cn` | `MITM Proxy CA` | Certificate CommonName |
| `--org` | `MITM Proxy` | Certificate Organization |
| `--country` | *(empty)* | Country code (e.g. `CH`) |
| `--validity` | `3650` | Validity in days |
| `--max-path-len` | `-1` | BasicConstraints PathLen (`-1` unlimited, `0` leaf-signing only) |
| `--signing-cert` | | Parent CA certificate (required for `intermediate`) |
| `--signing-key` | | Parent CA private key (required for `intermediate`) |
| `--out-cert` | `ca.crt` | Output certificate (PEM) |
| `--out-key` | `ca.key` | Output private key (PEM, 0600 permissions) |
| `--out-chain` | | Output full chain: cert + parent certs (PEM) |
| `--out-p12` | | Output PKCS#12 keystore with cert+key (for `mitm_keystore_path`) |
| `--p12-password` | | Password for `--out-p12` |
| `--out-client-bundle` | | Output client trust bundle (PEM, for distribution to clients) |
| `--out-client-p12` | | Output client PKCS#12 truststore (for Java keystore import) |
| `--client-p12-password` | `changeit` | Password for `--out-client-p12` |

**Production workflow with intermediate CA:**

```bash
# 1. Generate root CA (store offline / in vault)
mitm-proxy gencert --type root --cn "Corp Root CA" --org "Corp" \
  --out-cert root-ca.crt --out-key root-ca.key \
  --out-client-p12 client-truststore.p12 --client-p12-password changeit

# 2. Generate intermediate CA for the proxy
mitm-proxy gencert --type intermediate \
  --signing-cert root-ca.crt --signing-key root-ca.key \
  --cn "Corp MITM Proxy CA" --org "Corp" \
  --max-path-len 0 --validity 365 \
  --out-cert mitm-ca.crt --out-key mitm-ca.key \
  --out-chain mitm-chain.crt

# 3. Configure proxy with the intermediate chain
#    mitm_cert_path: mitm-chain.crt   (intermediate + root)
#    mitm_key_path:  mitm-ca.key

# 4. Distribute root CA to clients:
#    - PEM: trust.pem (for curl --cacert, system trust stores)
#    - PKCS#12: client-truststore.p12 (for Java applications)
```

**Java client trust store usage:**

```bash
# Use directly as Java truststore
java -Djavax.net.ssl.trustStore=client-truststore.p12 \
     -Djavax.net.ssl.trustStoreType=PKCS12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -jar myapp.jar

# Or import into an existing JKS keystore
keytool -importkeystore \
  -srckeystore client-truststore.p12 -srcstoretype PKCS12 -srcstorepass changeit \
  -destkeystore truststore.jks -deststorepass changeit
```

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
>
> **Note:** `outgoing_ca` (list of individual CA cert files) is YAML-only and has no environment variable override. It can be used alongside `outgoing_ca_bundle` — all certificates are merged into one trust pool.

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
pgrep mitm-proxy

# Send SIGHUP to reload config
kill -HUP <pid>
```

The proxy will log successful reloads and any errors. SIGHUP also reopens the blocked request log file, enabling log rotation.

## Logging

All log output is structured JSON via `slog`. The verbosity flag controls which log levels are emitted:

| Level | Flag | What is logged |
|-------|------|----------------|
| Info | `-v` (default) | `ACCESS` line per request: request_id, client, host, action, method, path |
| Debug | `-vv` | Adds `REQUEST_DETAIL` per request: scheme, full URL, proto, remote_addr, content_length, user_agent, content_type, and rewrite target info (target_ip, target_host, original) when a rewrite matched |
| Trace | `-vvv` | Adds all request headers to `REQUEST_DETAIL` |

Debug and trace logging have zero overhead when not enabled — the log construction is gated behind `slog.Default().Enabled()`.

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

Actions: `REWRITTEN`, `WHITE-LISTED`, `BLACK-LISTED`, `ALLOWED-BY-DEFAULT`, `BLOCKED`, `PASSTHROUGH`

## Health Endpoints

- `GET /healthz` - Liveness probe (always returns 200 if process is running)
- `GET /readyz` - Readiness probe (returns 200 when ready to accept traffic)

## Request Tracing

The proxy automatically injects an `X-Request-ID` header into all forwarded requests for distributed tracing. This ID is also logged with each access log entry.

## Client Setup

Clients must trust the MITM root CA certificate. You can generate a client trust bundle with `gencert` (see [Certificate Generation](#certificate-generation)) or distribute the CA cert manually:

```bash
# Linux (system-wide)
sudo cp certs/ca.crt /usr/local/share/ca-certificates/proxy-ca.crt
sudo update-ca-certificates

# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/ca.crt

# curl (per-request)
curl --cacert certs/ca.crt -x http://localhost:8080 https://example.com

# Java (using PKCS#12 truststore from gencert --out-client-p12)
java -Djavax.net.ssl.trustStore=truststore.p12 \
     -Djavax.net.ssl.trustStoreType=PKCS12 \
     -Djavax.net.ssl.trustStorePassword=changeit \
     -jar myapp.jar
```

## Architecture

See [doc/architecture.md](doc/architecture.md) for detailed design documentation.

## License

MIT
