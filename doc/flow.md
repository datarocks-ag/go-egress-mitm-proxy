# HTTPS Proxy Flow & Certificate Architecture

This document describes the complete flow of an HTTPS request through the MITM proxy, including all certificates involved, how they are generated, and how TLS is terminated and re-established.

## Certificates Overview

There are **four** certificate/key artifacts involved in a proxied HTTPS connection:

| # | Artifact | Who holds it | Purpose |
|---|----------|-------------|---------|
| 1 | **MITM CA Certificate** (`ca.crt`) | Proxy + all clients (trust store) | Root of trust for intercepted connections |
| 2 | **MITM CA Private Key** (`ca.key`) | Proxy only | Signs per-domain certificates on the fly |
| 3 | **Per-domain certificate** | Generated in memory by proxy | Presented to the client, impersonates the real server |
| 4 | **Upstream server's real certificate** | Origin server | Verified by the proxy using system CAs (+ optional `outgoing_ca_bundle`) |

### Certificate Generation

The MITM CA is generated once and distributed ahead of time:

```bash
# scripts/gen-ca.sh
openssl genrsa -out certs/ca.key 4096
openssl req -x509 -new -nodes -key certs/ca.key -sha256 -days 3650 -out certs/ca.crt \
  -subj "/C=US/ST=State/L=City/O=ProxyCorp/OU=Security/CN=Internal-MITM-CA"
```

Alternatively, the CA can be provided as a PKCS#12 keystore (`.p12`) instead of separate PEM files.

**Deployment requirements:**
- `ca.crt` + `ca.key` (or `.p12`) must be available to the proxy at startup.
- `ca.crt` must be installed as a **Trusted Root CA** on every client machine (OS trust store, browser, container, etc.). Without this, clients will reject the proxy-generated certificates.

### Per-Domain Certificate (On-the-Fly)

When the proxy intercepts a CONNECT tunnel, `goproxy` dynamically generates a TLS certificate for the requested domain:
1. Creates a new X.509 certificate with the target hostname as Subject/SAN.
2. Signs it with the MITM CA private key.
3. This certificate lives only in memory for the duration of the connection.

## Full HTTPS Connection Flow

### Step-by-step

1. **Client initiates CONNECT** -- The client sends an HTTP `CONNECT host:443` request to the proxy over plaintext HTTP.

2. **Proxy accepts the tunnel** -- The proxy responds with `200 Connection Established`. The TCP tunnel is now open.

3. **Client-side TLS handshake (MITM)** -- The proxy acts as the TLS server. `goproxy` generates a certificate for `host` signed by the MITM CA and presents it. The client verifies it against its trust store (which includes the MITM CA) and the handshake completes.

4. **Client sends HTTP request** -- Over the now-encrypted tunnel, the client sends the actual HTTP request (e.g., `GET /api/data`).

5. **Proxy evaluates policy** -- The `handleRequest` function processes the request:
   - Generates and injects `X-Request-ID` header
   - Checks **rewrite rules** (exact match, then wildcard patterns)
   - If no rewrite matched: checks **blacklist** -> **whitelist** -> **default policy**
   - If blocked (`BLACK-LISTED` or `BLOCKED`): returns `403 Forbidden` immediately; no upstream connection is made.

6. **Proxy dials upstream** -- For allowed/rewritten requests, the custom `DialContext` resolves the destination:
   - **Normal case:** dials the original `host:443` via DNS
   - **Rewrite case (split-brain DNS):** dials `target_ip:443` instead, bypassing DNS entirely. TLS SNI still uses the original hostname, so the upstream server's certificate is verified against the original domain.

7. **Upstream TLS handshake** -- The proxy acts as a TLS client toward the origin server. It verifies the server's real certificate against:
   - System CA trust store
   - Optional `outgoing_ca_bundle` (for internal/corporate CAs)

8. **Request forwarded** -- The proxy forwards the (potentially modified) request to the upstream server. For rewritten domains, custom headers are injected.

9. **Response relayed** -- The upstream response flows back through both TLS tunnels to the client. Response metrics are recorded.

### Two Independent TLS Sessions

The proxy maintains **two separate TLS sessions** simultaneously:

```mermaid
graph LR
    C["Client"] -- "TLS Session #1<br/>MITM cert (forged for domain)<br/>Proxy = TLS server" --> P["MITM Proxy<br/>(plaintext access)"]
    P -- "TLS Session #2<br/>Real server cert<br/>Proxy = TLS client" --> U["Upstream Server"]

    style C fill:#dceeff,stroke:#4a90d9
    style P fill:#e8f5e9,stroke:#66bb6a,font-weight:bold
    style U fill:#fff3e0,stroke:#e6a23c
```

The proxy has access to the plaintext HTTP request/response between these two TLS sessions, which is what enables inspection, policy enforcement, header injection, and logging.

## Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant C as Client
    participant P as MITM Proxy
    participant U as Upstream Server

    note over C,P: Plaintext HTTP (port 8080)

    C->>P: CONNECT api.example.com:443 HTTP/1.1
    P->>C: HTTP/1.1 200 Connection Established

    note over C,P: TLS Handshake #1 (Client ↔ Proxy)
    rect rgb(220, 240, 255)
        C->>P: ClientHello (SNI: api.example.com)
        note right of P: goproxy generates cert for<br/>api.example.com signed by MITM CA
        P->>C: ServerHello + Certificate (signed by MITM CA)
        note left of C: Client verifies cert against<br/>trust store (MITM CA installed)
        C->>P: Finished
        P->>C: Finished
    end

    note over C,P: Encrypted tunnel established

    C->>P: GET /api/data HTTP/1.1<br/>Host: api.example.com
    note right of P: handleRequest() evaluates policy:<br/>1. Inject X-Request-ID<br/>2. Check rewrites (exact → wildcard)<br/>3. Check blacklist → whitelist<br/>4. Apply default policy

    alt BLOCKED or BLACK-LISTED
        P->>C: HTTP/1.1 403 Forbidden<br/>"Policy Blocked"
    else REWRITTEN
        note right of P: Custom DialContext routes<br/>TCP to target_ip instead of DNS
        note over P,U: TLS Handshake #2 (Proxy ↔ Upstream)
        rect rgb(255, 240, 220)
            P->>U: TCP connect to target_ip:443
            P->>U: ClientHello (SNI: api.example.com)
            U->>P: ServerHello + Certificate (real cert)
            note left of P: Proxy verifies real cert against<br/>system CAs + outgoing_ca_bundle
            P->>U: Finished
            U->>P: Finished
        end
        note right of P: Inject custom headers<br/>(e.g. X-Proxy-Source)
        P->>U: GET /api/data HTTP/1.1<br/>Host: api.example.com<br/>X-Request-ID: abc123<br/>X-Proxy-Source: egress-gateway
        U->>P: HTTP/1.1 200 OK + body
        P->>C: HTTP/1.1 200 OK + body
    else WHITE-LISTED or ALLOWED-BY-DEFAULT
        note over P,U: TLS Handshake #2 (Proxy ↔ Upstream)
        rect rgb(220, 255, 220)
            P->>U: TCP connect to api.example.com:443 (via DNS)
            P->>U: ClientHello (SNI: api.example.com)
            U->>P: ServerHello + Certificate (real cert)
            note left of P: Proxy verifies real cert against<br/>system CAs + outgoing_ca_bundle
            P->>U: Finished
            U->>P: Finished
        end
        P->>U: GET /api/data HTTP/1.1<br/>Host: api.example.com<br/>X-Request-ID: abc123
        U->>P: HTTP/1.1 200 OK + body
        P->>C: HTTP/1.1 200 OK + body
    end
```

## Split-Brain DNS Detail

In the rewrite case, the proxy achieves split-brain DNS **at the TCP dial layer**, not at DNS level. The upstream server at the `target_ip` must present a valid certificate for the original domain. This is the typical pattern for routing traffic to an internal load balancer or service mesh endpoint that terminates TLS for the original domain.

```mermaid
graph LR
    subgraph dns["Public DNS"]
        R["api.example.com<br/>→ 203.0.113.50"]
    end

    subgraph config["Proxy Rewrite Rule"]
        RW["domain: api.example.com<br/>target_ip: 10.20.30.40"]
    end

    C["Client"] -- "CONNECT api.example.com:443" --> P["MITM Proxy"]

    P -. "DNS would resolve to<br/>203.0.113.50 (ignored)" .-x R

    P -- "TCP dial → 10.20.30.40:443<br/>TLS SNI: api.example.com" --> U["Internal Server<br/>10.20.30.40"]

    U -- "presents valid cert for<br/>api.example.com ✅" --> P

    style dns fill:#f5f5f5,stroke:#999,stroke-dasharray: 5 5
    style config fill:#e8f5e9,stroke:#66bb6a
    style P fill:#dceeff,stroke:#4a90d9
    style U fill:#fff3e0,stroke:#e6a23c
```

## Trust Chain Summary

```mermaid
graph TB
    subgraph client_store["Client Trust Store"]
        SysCA1["System CAs<br/>(DigiCert, Let's Encrypt, ...)"]
        MITMCA["MITM CA (ca.crt)"]
    end

    subgraph proxy_store["Proxy Trust Store"]
        SysCA2["System CAs<br/>(DigiCert, Let's Encrypt, ...)"]
        CustomCA["outgoing_ca_bundle<br/>(optional, for internal CAs)"]
    end

    subgraph tls1["TLS Session #1: Client ↔ Proxy"]
        GenCert["Per-domain certificate<br/>CN: api.example.com<br/>(generated on the fly)"]
    end

    subgraph tls2["TLS Session #2: Proxy ↔ Upstream"]
        RealCert["Real server certificate<br/>CN: api.example.com<br/>(issued by public/corporate CA)"]
    end

    MITMCA -- "signs" --> GenCert
    MITMCA -. "trusted by client" .-> client_store
    GenCert -- "presented to Client<br/>Client verifies ✅" --> client_store

    SysCA2 -. "verifies public upstreams" .-> RealCert
    CustomCA -. "verifies internal upstreams" .-> RealCert
    RealCert -- "presented to Proxy<br/>Proxy verifies ✅" --> proxy_store

    style client_store fill:#dceeff,stroke:#4a90d9
    style proxy_store fill:#fff3e0,stroke:#e6a23c
    style tls1 fill:#e8f5e9,stroke:#66bb6a
    style tls2 fill:#fce4ec,stroke:#ef5350
    style MITMCA fill:#bbdefb,stroke:#1976d2,font-weight:bold
```
