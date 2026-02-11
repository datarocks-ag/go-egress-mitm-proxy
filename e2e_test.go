// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

//go:build e2e

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// generateE2ECerts creates a CA certificate and key, writes them as PEM files,
// and returns the cert pool for client trust.
func generateE2ECerts(t *testing.T, dir string) *x509.CertPool {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "E2E Test CA",
			Organization: []string{"E2E Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if writeErr := os.WriteFile(filepath.Join(dir, "ca.crt"), certPEM, 0o600); writeErr != nil {
		t.Fatalf("write CA cert: %v", writeErr)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if writeErr := os.WriteFile(filepath.Join(dir, "ca.key"), keyPEM, 0o600); writeErr != nil {
		t.Fatalf("write CA key: %v", writeErr)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return pool
}

// writeE2EConfig writes the proxy config YAML to dir/config.yaml with the given httpbin IP.
func writeE2EConfig(t *testing.T, dir, httpbinIP string) {
	t.Helper()

	config := fmt.Sprintf(`proxy:
  port: "8080"
  metrics_port: "9090"
  default_policy: "BLOCK"
  mitm_cert_path: "/app/certs/ca.crt"
  mitm_key_path: "/app/certs/ca.key"
rewrites:
  # Exact domain + target_ip (existing)
  - domain: "rewrite.example.com"
    target_ip: %[1]q
    headers:
      X-Rewritten: "true"
      X-Custom-Header: "proxy-injected"

  # Wildcard domain + target_ip
  - domain: "*.wildcard.example.com"
    target_ip: %[1]q
    headers:
      X-Rewrite-Type: "wildcard"

  # Regex domain + target_ip
  - domain: "~^regex[0-9]+\\.example\\.com$"
    target_ip: %[1]q
    headers:
      X-Rewrite-Type: "regex"

  # Exact domain + target_host (DNS-resolved via Docker network alias)
  - domain: "hostrouted.example.com"
    target_host: "httpbin-internal"
    headers:
      X-Rewrite-Type: "target-host"

  # Path-based rewrites (first-match-wins order)
  - domain: "pathtest.example.com"
    path_pattern: "^/anything/v1"
    target_ip: %[1]q
    headers:
      X-Backend: "v1"

  - domain: "pathtest.example.com"
    path_pattern: "^/anything/v2"
    target_ip: %[1]q
    headers:
      X-Backend: "v2"

  # Catch-all for pathtest.example.com (no path_pattern = matches all paths)
  - domain: "pathtest.example.com"
    target_ip: %[1]q
    headers:
      X-Backend: "default"

  # Path-only domain (no catch-all — unmatched paths get blocked)
  - domain: "pathonly.example.com"
    path_pattern: "^/anything/allowed"
    target_ip: %[1]q
    headers:
      X-Backend: "pathonly"

  # target_scheme: client connects via HTTPS, proxy forwards as HTTP to backend
  - domain: "schemetest.example.com"
    target_ip: %[1]q
    target_scheme: "http"
    headers:
      X-Scheme-Test: "downgraded"

  # drop_headers: strip Authorization and X-Secret before forwarding
  - domain: "droptest.example.com"
    target_ip: %[1]q
    drop_headers:
      - "Authorization"
      - "X-Secret"
    headers:
      X-Drop-Test: "applied"
acl:
  whitelist:
    - "whitelisted.example.com"
  blacklist:
    - "blacklisted.example.com"
`, httpbinIP)

	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(config), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// e2eCheckHeader parses an httpbin JSON response and verifies that a specific header was injected.
func e2eCheckHeader(t *testing.T, body []byte, headerName, expectedValue string) {
	t.Helper()

	var result struct {
		Headers map[string][]string `json:"headers"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshal response: %v (body: %s)", err, string(body))
	}

	vals, ok := result.Headers[headerName]
	if !ok {
		t.Errorf("header %q not found in response headers: %v", headerName, result.Headers)
		return
	}
	found := false
	for _, v := range vals {
		if v == expectedValue {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("header %q = %v, want value %q", headerName, vals, expectedValue)
	}
}

// doGet is a helper that performs an HTTP GET via the given client with a proper context.
func doGet(ctx context.Context, client *http.Client, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	return client.Do(req)
}

func TestE2E(t *testing.T) {
	ctx := context.Background()

	// Create temp dir for certs and config
	tmpDir := t.TempDir()
	certsDir := filepath.Join(tmpDir, "certs")
	if err := os.Mkdir(certsDir, 0o750); err != nil {
		t.Fatalf("create certs dir: %v", err)
	}

	// Generate CA certs (proxy container needs these files, tests need the CA pool)
	caPool := generateE2ECerts(t, certsDir)

	// Create Docker network
	nw, err := network.New(ctx)
	if err != nil {
		t.Fatalf("create docker network: %v", err)
	}
	t.Cleanup(func() {
		if rmErr := nw.Remove(ctx); rmErr != nil {
			t.Logf("remove network: %v", rmErr)
		}
	})

	// Start go-httpbin container (with network alias for target_host tests)
	httpbinCtr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          "mccutchen/go-httpbin:v2.15.0",
			ExposedPorts:   []string{"8080/tcp"},
			Networks:       []string{nw.Name},
			NetworkAliases: map[string][]string{nw.Name: {"httpbin-internal"}},
			WaitingFor:     wait.ForHTTP("/get").WithPort("8080/tcp").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start httpbin container: %v", err)
	}
	t.Cleanup(func() {
		if termErr := testcontainers.TerminateContainer(httpbinCtr); termErr != nil {
			t.Logf("terminate httpbin: %v", termErr)
		}
	})

	// Get httpbin container IP on the shared network
	httpbinIP, err := httpbinCtr.ContainerIP(ctx)
	if err != nil {
		t.Fatalf("get httpbin IP: %v", err)
	}
	t.Logf("httpbin container IP: %s", httpbinIP)

	// Write proxy config with httpbin IP
	writeE2EConfig(t, tmpDir, httpbinIP)

	// Build and start proxy container from project Dockerfile
	proxyCtr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    ".",
				Dockerfile: "Dockerfile",
			},
			ExposedPorts: []string{"8080/tcp", "9090/tcp"},
			Networks:     []string{nw.Name},
			Files: []testcontainers.ContainerFile{
				{
					HostFilePath:      filepath.Join(certsDir, "ca.crt"),
					ContainerFilePath: "/app/certs/ca.crt",
					FileMode:          0o644,
				},
				{
					HostFilePath:      filepath.Join(certsDir, "ca.key"),
					ContainerFilePath: "/app/certs/ca.key",
					FileMode:          0o644,
				},
				{
					HostFilePath:      filepath.Join(tmpDir, "config.yaml"),
					ContainerFilePath: "/app/config.yaml",
					FileMode:          0o644,
				},
			},
			WaitingFor: wait.ForHTTP("/healthz").WithPort("9090/tcp").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start proxy container: %v", err)
	}
	t.Cleanup(func() {
		if termErr := testcontainers.TerminateContainer(proxyCtr); termErr != nil {
			t.Logf("terminate proxy: %v", termErr)
		}
	})

	// Get mapped proxy port
	proxyPort, err := proxyCtr.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("get proxy port: %v", err)
	}
	proxyMetricsPort, err := proxyCtr.MappedPort(ctx, "9090/tcp")
	if err != nil {
		t.Fatalf("get proxy metrics port: %v", err)
	}
	proxyHost, err := proxyCtr.Host(ctx)
	if err != nil {
		t.Fatalf("get proxy host: %v", err)
	}

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%s", proxyHost, proxyPort.Port()))
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	metricsBase := fmt.Sprintf("http://%s:%s", proxyHost, proxyMetricsPort.Port())

	t.Logf("proxy at %s, metrics at %s", proxyURL, metricsBase)

	// HTTP client that routes through the proxy (no TLS — for policy checks)
	plainClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
		// Don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// HTTP client with TLS trust for MITM CA (for HTTPS tests through proxy)
	tlsClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: 10 * time.Second,
	}

	// Direct HTTP client (no proxy, for health endpoints)
	directClient := &http.Client{Timeout: 5 * time.Second}

	t.Run("blacklisted_domain_returns_403", func(t *testing.T) {
		resp, err := doGet(ctx, plainClient, "http://blacklisted.example.com/")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403, got %d", resp.StatusCode)
		}
	})

	t.Run("default_block_policy_returns_403", func(t *testing.T) {
		resp, err := doGet(ctx, plainClient, "http://unknown.example.com/")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403, got %d", resp.StatusCode)
		}
	})

	t.Run("whitelisted_domain_not_blocked", func(t *testing.T) {
		// The domain won't actually resolve, but the proxy should NOT return 403.
		// We expect 502 Bad Gateway since the DNS lookup fails.
		resp, err := doGet(ctx, plainClient, "http://whitelisted.example.com/")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("expected 502 for unresolvable whitelisted domain, got %d", resp.StatusCode)
		}
	})

	t.Run("rewrite_routes_to_upstream", func(t *testing.T) {
		// Use HTTP (not HTTPS) because the upstream httpbin speaks plain HTTP.
		// The proxy's handleRequest still fires for plain HTTP proxy requests,
		// and the custom DialContext routes to the httpbin container IP.
		resp, err := doGet(ctx, plainClient, "http://rewrite.example.com:8080/get")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				t.Fatalf("expected 200, got %d (and failed to read body: %v)", resp.StatusCode, readErr)
			}
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("rewrite_injects_headers", func(t *testing.T) {
		resp, err := doGet(ctx, plainClient, "http://rewrite.example.com:8080/headers")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}

		var result struct {
			Headers map[string][]string `json:"headers"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("unmarshal response: %v (body: %s)", err, string(body))
		}

		checkHeader := func(name, expected string) {
			t.Helper()
			vals, ok := result.Headers[name]
			if !ok {
				t.Errorf("header %q not found in response: %v", name, result.Headers)
				return
			}
			found := false
			for _, v := range vals {
				if v == expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("header %q = %v, want value %q", name, vals, expected)
			}
		}

		checkHeader("X-Rewritten", "true")
		checkHeader("X-Custom-Header", "proxy-injected")
	})

	t.Run("https_whitelisted_not_blocked", func(t *testing.T) {
		// HTTPS to whitelisted.example.com through the MITM proxy.
		// CONNECT is accepted, TLS established with custom CA, handleRequest
		// allows it (whitelisted). DNS fails → 502, proving it was NOT policy-blocked (403).
		resp, err := doGet(ctx, tlsClient, "https://whitelisted.example.com/")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusForbidden {
			t.Fatal("whitelisted domain should not be blocked with 403")
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("expected 502 for unresolvable whitelisted domain, got %d", resp.StatusCode)
		}
	})

	t.Run("mitm_uses_custom_ca", func(t *testing.T) {
		// Verify the MITM-presented certificate is signed by our test CA,
		// not goproxy's embedded default (CN=goproxy.github.io, O=GoProxy).
		resp, err := doGet(ctx, tlsClient, "https://whitelisted.example.com/")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.TLS == nil {
			t.Fatal("response has no TLS connection state")
		}
		if len(resp.TLS.PeerCertificates) == 0 {
			t.Fatal("no peer certificates in TLS handshake")
		}

		leaf := resp.TLS.PeerCertificates[0]
		issuer := leaf.Issuer

		if issuer.CommonName == "goproxy.github.io" {
			t.Fatal("MITM cert is signed by goproxy's embedded default CA, not the custom CA")
		}
		if issuer.CommonName != "E2E Test CA" {
			t.Errorf("MITM cert issuer CN = %q, want %q", issuer.CommonName, "E2E Test CA")
		}
		if len(issuer.Organization) == 0 || issuer.Organization[0] != "E2E Test" {
			t.Errorf("MITM cert issuer Org = %v, want [%q]", issuer.Organization, "E2E Test")
		}
		t.Logf("MITM cert issuer: CN=%s, O=%v (verified custom CA)", issuer.CommonName, issuer.Organization)
	})

	t.Run("https_blacklisted_returns_403", func(t *testing.T) {
		// HTTPS to blacklisted.example.com through the MITM proxy.
		// The proxy does AlwaysMitm (CONNECT accepted, TLS established),
		// then handleRequest sees the blacklisted domain and returns 403.
		resp, err := doGet(ctx, tlsClient, "https://blacklisted.example.com/")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403, got %d", resp.StatusCode)
		}
	})

	t.Run("wildcard_rewrite_routes_to_upstream", func(t *testing.T) {
		resp, err := doGet(ctx, plainClient, "http://sub.wildcard.example.com:8080/headers")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("read body: %v", readErr)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
		e2eCheckHeader(t, body, "X-Rewrite-Type", "wildcard")
	})

	t.Run("wildcard_deep_subdomain", func(t *testing.T) {
		resp, err := doGet(ctx, plainClient, "http://a.b.c.wildcard.example.com:8080/headers")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("read body: %v", readErr)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
		e2eCheckHeader(t, body, "X-Rewrite-Type", "wildcard")
	})

	t.Run("regex_rewrite_routes_to_upstream", func(t *testing.T) {
		resp, err := doGet(ctx, plainClient, "http://regex42.example.com:8080/headers")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("read body: %v", readErr)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
		e2eCheckHeader(t, body, "X-Rewrite-Type", "regex")
	})

	t.Run("target_host_rewrite_routes_to_upstream", func(t *testing.T) {
		// target_host resolves "httpbin-internal" via Docker DNS to the httpbin container
		resp, err := doGet(ctx, plainClient, "http://hostrouted.example.com:8080/headers")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("read body: %v", readErr)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
		e2eCheckHeader(t, body, "X-Rewrite-Type", "target-host")
	})

	t.Run("path_rewrite_v1", func(t *testing.T) {
		resp, err := doGet(ctx, plainClient, "http://pathtest.example.com:8080/anything/v1/foo")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("read body: %v", readErr)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
		e2eCheckHeader(t, body, "X-Backend", "v1")
	})

	t.Run("path_rewrite_v2", func(t *testing.T) {
		resp, err := doGet(ctx, plainClient, "http://pathtest.example.com:8080/anything/v2/bar")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("read body: %v", readErr)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
		e2eCheckHeader(t, body, "X-Backend", "v2")
	})

	t.Run("path_rewrite_catchall", func(t *testing.T) {
		// Path /anything/other/baz does not match /v1 or /v2, falls through to catch-all
		resp, err := doGet(ctx, plainClient, "http://pathtest.example.com:8080/anything/other/baz")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("read body: %v", readErr)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
		e2eCheckHeader(t, body, "X-Backend", "default")
	})

	t.Run("path_only_match_allowed", func(t *testing.T) {
		resp, err := doGet(ctx, plainClient, "http://pathonly.example.com:8080/anything/allowed/ok")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("read body: %v", readErr)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
		e2eCheckHeader(t, body, "X-Backend", "pathonly")
	})

	t.Run("path_only_no_match_blocked", func(t *testing.T) {
		// No path_pattern matches /anything/denied, no catch-all → default BLOCK → 403
		resp, err := doGet(ctx, plainClient, "http://pathonly.example.com:8080/anything/denied/nope")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403, got %d", resp.StatusCode)
		}
	})

	t.Run("target_scheme_rewrites_to_http", func(t *testing.T) {
		// Client sends HTTP request, proxy applies target_scheme: "http" and routes to httpbin.
		// httpbin's /headers endpoint shows what arrived.
		resp, err := doGet(ctx, plainClient, "http://schemetest.example.com:8080/headers")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("read body: %v", readErr)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
		e2eCheckHeader(t, body, "X-Scheme-Test", "downgraded")
	})

	t.Run("drop_headers_strips_specified_headers", func(t *testing.T) {
		// Send request with Authorization and X-Secret headers; they should be stripped.
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, "http://droptest.example.com:8080/headers", nil)
		if reqErr != nil {
			t.Fatalf("create request: %v", reqErr)
		}
		req.Header.Set("Authorization", "Bearer secret-token")
		req.Header.Set("X-Secret", "do-not-forward")
		req.Header.Set("X-Keep-Me", "should-survive")

		resp, err := plainClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("read body: %v", readErr)
		}

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}

		var result struct {
			Headers map[string][]string `json:"headers"`
		}
		if unmarshalErr := json.Unmarshal(body, &result); unmarshalErr != nil {
			t.Fatalf("unmarshal response: %v (body: %s)", unmarshalErr, string(body))
		}

		// Dropped headers should NOT be present
		if _, ok := result.Headers["Authorization"]; ok {
			t.Errorf("Authorization header should have been dropped, but found: %v", result.Headers["Authorization"])
		}
		if _, ok := result.Headers["X-Secret"]; ok {
			t.Errorf("X-Secret header should have been dropped, but found: %v", result.Headers["X-Secret"])
		}

		// Non-dropped headers should survive
		if _, ok := result.Headers["X-Keep-Me"]; !ok {
			t.Errorf("X-Keep-Me header should have survived, but was not found")
		}

		// Injected header should be present
		e2eCheckHeader(t, body, "X-Drop-Test", "applied")
	})

	t.Run("health_endpoints", func(t *testing.T) {
		for _, endpoint := range []string{"/healthz", "/readyz"} {
			resp, err := doGet(ctx, directClient, metricsBase+endpoint)
			if err != nil {
				t.Fatalf("GET %s failed: %v", endpoint, err)
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("GET %s returned %d, want 200", endpoint, resp.StatusCode)
			}
		}
	})
}

// generateUpstreamTLSCerts creates an upstream CA and server certificate for TLS testing.
// The server cert is signed by the CA and includes the given DNS names as SANs.
// Writes ca.crt, ca.key, server.crt, server.key to dir.
func generateUpstreamTLSCerts(t *testing.T, dir string, dnsNames []string) {
	t.Helper()

	// Generate CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate upstream CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "E2E Upstream CA", Organization: []string{"E2E Upstream"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create upstream CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("parse upstream CA cert: %v", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	if writeErr := os.WriteFile(filepath.Join(dir, "ca.crt"), caCertPEM, 0o600); writeErr != nil {
		t.Fatalf("write upstream CA cert: %v", writeErr)
	}
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		t.Fatalf("marshal upstream CA key: %v", err)
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER})
	if writeErr := os.WriteFile(filepath.Join(dir, "ca.key"), caKeyPEM, 0o600); writeErr != nil {
		t.Fatalf("write upstream CA key: %v", writeErr)
	}

	// Generate server cert signed by CA
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate upstream server key: %v", err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
	}
	srvCertDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create upstream server cert: %v", err)
	}
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvCertDER})
	if writeErr := os.WriteFile(filepath.Join(dir, "server.crt"), srvCertPEM, 0o600); writeErr != nil {
		t.Fatalf("write upstream server cert: %v", writeErr)
	}

	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		t.Fatalf("marshal upstream server key: %v", err)
	}
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})
	if writeErr := os.WriteFile(filepath.Join(dir, "server.key"), srvKeyPEM, 0o600); writeErr != nil {
		t.Fatalf("write upstream server key: %v", writeErr)
	}
}

func TestE2ETLS(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available (needed for PKCS#12 generation)")
	}

	ctx := context.Background()
	tmpDir := t.TempDir()

	// --- Certificates ---

	// MITM CA (proxy client-facing)
	mitmCertsDir := filepath.Join(tmpDir, "mitm-certs")
	if err := os.Mkdir(mitmCertsDir, 0o750); err != nil {
		t.Fatalf("create mitm certs dir: %v", err)
	}
	mitmCAPool := generateE2ECerts(t, mitmCertsDir)

	// Upstream CA + server cert (for nginx TLS)
	upstreamDir := filepath.Join(tmpDir, "upstream-certs")
	if err := os.Mkdir(upstreamDir, 0o750); err != nil {
		t.Fatalf("create upstream certs dir: %v", err)
	}
	generateUpstreamTLSCerts(t, upstreamDir, []string{
		"insecure-tls.example.com",
		"truststore-tls.example.com",
	})

	// Create PKCS#12 truststore from upstream CA
	truststorePath := filepath.Join(tmpDir, "upstream-truststore.p12")
	//nolint:gosec // test helper: all arguments are test-controlled constants
	cmd := exec.CommandContext(ctx, "openssl", "pkcs12", "-export",
		"-in", filepath.Join(upstreamDir, "ca.crt"),
		"-inkey", filepath.Join(upstreamDir, "ca.key"),
		"-out", truststorePath,
		"-passout", "pass:truststorepass",
		"-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES", "-macalg", "SHA1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create truststore p12: %v\n%s", err, out)
	}

	// --- nginx TLS configuration ---
	nginxConf := filepath.Join(tmpDir, "nginx.conf")
	nginxConfContent := `events {
    worker_connections 64;
}

http {
    server {
        listen 443 ssl;
        ssl_certificate /etc/nginx/certs/server.crt;
        ssl_certificate_key /etc/nginx/certs/server.key;

        location / {
            return 200 'nginx-tls-ok';
            default_type text/plain;
        }
    }
}
`
	if err := os.WriteFile(nginxConf, []byte(nginxConfContent), 0o600); err != nil {
		t.Fatalf("write nginx.conf: %v", err)
	}

	// --- Docker network ---
	nw, err := network.New(ctx)
	if err != nil {
		t.Fatalf("create docker network: %v", err)
	}
	t.Cleanup(func() {
		if rmErr := nw.Remove(ctx); rmErr != nil {
			t.Logf("remove network: %v", rmErr)
		}
	})

	// --- Start nginx TLS container ---
	nginxCtr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "nginx:1.27-alpine",
			ExposedPorts: []string{"443/tcp"},
			Networks:     []string{nw.Name},
			Files: []testcontainers.ContainerFile{
				{
					HostFilePath:      filepath.Join(upstreamDir, "server.crt"),
					ContainerFilePath: "/etc/nginx/certs/server.crt",
					FileMode:          0o644,
				},
				{
					HostFilePath:      filepath.Join(upstreamDir, "server.key"),
					ContainerFilePath: "/etc/nginx/certs/server.key",
					FileMode:          0o644,
				},
				{
					HostFilePath:      nginxConf,
					ContainerFilePath: "/etc/nginx/nginx.conf",
					FileMode:          0o644,
				},
			},
			WaitingFor: wait.ForListeningPort("443/tcp").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start nginx container: %v", err)
	}
	t.Cleanup(func() {
		if termErr := testcontainers.TerminateContainer(nginxCtr); termErr != nil {
			t.Logf("terminate nginx: %v", termErr)
		}
	})

	nginxIP, err := nginxCtr.ContainerIP(ctx)
	if err != nil {
		t.Fatalf("get nginx IP: %v", err)
	}
	t.Logf("nginx TLS container IP: %s", nginxIP)

	// --- Write proxy config ---
	proxyConfig := fmt.Sprintf(`proxy:
  port: "8080"
  metrics_port: "9090"
  default_policy: "BLOCK"
  mitm_cert_path: "/app/certs/ca.crt"
  mitm_key_path: "/app/certs/ca.key"
  outgoing_truststore_path: "/app/certs/upstream-truststore.p12"
  outgoing_truststore_password: "truststorepass"
rewrites:
  - domain: "insecure-tls.example.com"
    target_ip: %q
    insecure: true
  - domain: "truststore-tls.example.com"
    target_ip: %q
`, nginxIP, nginxIP)

	if writeErr := os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte(proxyConfig), 0o600); writeErr != nil {
		t.Fatalf("write proxy config: %v", writeErr)
	}

	// --- Start proxy container ---
	proxyCtr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    ".",
				Dockerfile: "Dockerfile",
			},
			ExposedPorts: []string{"8080/tcp", "9090/tcp"},
			Networks:     []string{nw.Name},
			Files: []testcontainers.ContainerFile{
				{
					HostFilePath:      filepath.Join(mitmCertsDir, "ca.crt"),
					ContainerFilePath: "/app/certs/ca.crt",
					FileMode:          0o644,
				},
				{
					HostFilePath:      filepath.Join(mitmCertsDir, "ca.key"),
					ContainerFilePath: "/app/certs/ca.key",
					FileMode:          0o644,
				},
				{
					HostFilePath:      truststorePath,
					ContainerFilePath: "/app/certs/upstream-truststore.p12",
					FileMode:          0o644,
				},
				{
					HostFilePath:      filepath.Join(tmpDir, "config.yaml"),
					ContainerFilePath: "/app/config.yaml",
					FileMode:          0o644,
				},
			},
			WaitingFor: wait.ForHTTP("/healthz").WithPort("9090/tcp").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start proxy container: %v", err)
	}
	t.Cleanup(func() {
		if termErr := testcontainers.TerminateContainer(proxyCtr); termErr != nil {
			t.Logf("terminate proxy: %v", termErr)
		}
	})

	proxyPort, err := proxyCtr.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("get proxy port: %v", err)
	}
	proxyHost, err := proxyCtr.Host(ctx)
	if err != nil {
		t.Fatalf("get proxy host: %v", err)
	}

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%s", proxyHost, proxyPort.Port()))
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	t.Logf("proxy at %s", proxyURL)

	// Client trusts MITM CA (for client-to-proxy TLS via CONNECT+MITM)
	tlsClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:    mitmCAPool,
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: 15 * time.Second,
	}

	t.Run("insecure_rewrite_to_tls_upstream", func(t *testing.T) {
		// Client → HTTPS → CONNECT/MITM → proxy → DialTLSContext (insecure:true) → nginx:443
		// Upstream cert NOT trusted by proxy, but insecure=true skips verification.
		resp, err := doGet(ctx, tlsClient, "https://insecure-tls.example.com/")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("read body: %v", readErr)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
		t.Logf("insecure rewrite response: %d %s", resp.StatusCode, string(body))
	})

	t.Run("truststore_rewrite_to_tls_upstream", func(t *testing.T) {
		// Client → HTTPS → CONNECT/MITM → proxy → DialTLSContext → nginx:443
		// Upstream cert signed by CA that is in the proxy's PKCS#12 truststore.
		resp, err := doGet(ctx, tlsClient, "https://truststore-tls.example.com/")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("read body: %v", readErr)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
		t.Logf("truststore rewrite response: %d %s", resp.StatusCode, string(body))
	})
}

func TestE2EPassthrough(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// --- Certificates ---

	// MITM CA (proxy client-facing, NOT trusted by the passthrough client)
	mitmCertsDir := filepath.Join(tmpDir, "mitm-certs")
	if err := os.Mkdir(mitmCertsDir, 0o750); err != nil {
		t.Fatalf("create mitm certs dir: %v", err)
	}
	generateE2ECerts(t, mitmCertsDir) // we don't need the pool; passthrough client trusts upstream CA instead

	// Upstream CA + server cert (for nginx TLS)
	upstreamDir := filepath.Join(tmpDir, "upstream-certs")
	if err := os.Mkdir(upstreamDir, 0o750); err != nil {
		t.Fatalf("create upstream certs dir: %v", err)
	}
	generateUpstreamTLSCerts(t, upstreamDir, []string{"passthrough-tls.example.com"})

	// Build upstream CA pool for client trust
	upstreamCAPEM, err := os.ReadFile(filepath.Join(upstreamDir, "ca.crt"))
	if err != nil {
		t.Fatalf("read upstream CA: %v", err)
	}
	upstreamCAPool := x509.NewCertPool()
	if !upstreamCAPool.AppendCertsFromPEM(upstreamCAPEM) {
		t.Fatal("failed to parse upstream CA PEM")
	}

	// --- Docker network ---
	nw, err := network.New(ctx)
	if err != nil {
		t.Fatalf("create docker network: %v", err)
	}
	t.Cleanup(func() {
		if rmErr := nw.Remove(ctx); rmErr != nil {
			t.Logf("remove network: %v", rmErr)
		}
	})

	// --- nginx TLS container ---
	nginxConf := filepath.Join(tmpDir, "nginx.conf")
	nginxConfContent := `events {
    worker_connections 64;
}

http {
    server {
        listen 443 ssl;
        ssl_certificate /etc/nginx/certs/server.crt;
        ssl_certificate_key /etc/nginx/certs/server.key;

        location / {
            return 200 'passthrough-ok';
            default_type text/plain;
        }
    }
}
`
	if writeErr := os.WriteFile(nginxConf, []byte(nginxConfContent), 0o600); writeErr != nil {
		t.Fatalf("write nginx.conf: %v", writeErr)
	}

	nginxCtr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:          "nginx:1.27-alpine",
			ExposedPorts:   []string{"443/tcp"},
			Networks:       []string{nw.Name},
			NetworkAliases: map[string][]string{nw.Name: {"passthrough-tls.example.com"}},
			Files: []testcontainers.ContainerFile{
				{
					HostFilePath:      filepath.Join(upstreamDir, "server.crt"),
					ContainerFilePath: "/etc/nginx/certs/server.crt",
					FileMode:          0o644,
				},
				{
					HostFilePath:      filepath.Join(upstreamDir, "server.key"),
					ContainerFilePath: "/etc/nginx/certs/server.key",
					FileMode:          0o644,
				},
				{
					HostFilePath:      nginxConf,
					ContainerFilePath: "/etc/nginx/nginx.conf",
					FileMode:          0o644,
				},
			},
			WaitingFor: wait.ForListeningPort("443/tcp").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start nginx container: %v", err)
	}
	t.Cleanup(func() {
		if termErr := testcontainers.TerminateContainer(nginxCtr); termErr != nil {
			t.Logf("terminate nginx: %v", termErr)
		}
	})

	t.Logf("nginx passthrough container started")

	// --- Proxy config: passthrough for the nginx domain ---
	proxyConfig := `proxy:
  port: "8080"
  metrics_port: "9090"
  default_policy: "BLOCK"
  mitm_cert_path: "/app/certs/ca.crt"
  mitm_key_path: "/app/certs/ca.key"
acl:
  passthrough:
    - "passthrough-tls.example.com"
`
	if writeErr := os.WriteFile(filepath.Join(tmpDir, "config.yaml"), []byte(proxyConfig), 0o600); writeErr != nil {
		t.Fatalf("write proxy config: %v", writeErr)
	}

	// --- Start proxy container ---
	proxyCtr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    ".",
				Dockerfile: "Dockerfile",
			},
			ExposedPorts: []string{"8080/tcp", "9090/tcp"},
			Networks:     []string{nw.Name},
			Files: []testcontainers.ContainerFile{
				{
					HostFilePath:      filepath.Join(mitmCertsDir, "ca.crt"),
					ContainerFilePath: "/app/certs/ca.crt",
					FileMode:          0o644,
				},
				{
					HostFilePath:      filepath.Join(mitmCertsDir, "ca.key"),
					ContainerFilePath: "/app/certs/ca.key",
					FileMode:          0o644,
				},
				{
					HostFilePath:      filepath.Join(tmpDir, "config.yaml"),
					ContainerFilePath: "/app/config.yaml",
					FileMode:          0o644,
				},
			},
			WaitingFor: wait.ForHTTP("/healthz").WithPort("9090/tcp").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start proxy container: %v", err)
	}
	t.Cleanup(func() {
		if termErr := testcontainers.TerminateContainer(proxyCtr); termErr != nil {
			t.Logf("terminate proxy: %v", termErr)
		}
	})

	proxyPort, err := proxyCtr.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("get proxy port: %v", err)
	}
	proxyHost, err := proxyCtr.Host(ctx)
	if err != nil {
		t.Fatalf("get proxy host: %v", err)
	}

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%s", proxyHost, proxyPort.Port()))
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	t.Logf("proxy at %s", proxyURL)

	// Client trusts the UPSTREAM CA (not the MITM CA).
	// If the proxy were doing MITM, the TLS handshake would fail because
	// the MITM cert is not trusted by this client.
	passthroughClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:    upstreamCAPool,
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: 15 * time.Second,
	}

	t.Run("passthrough_tunnels_without_mitm", func(t *testing.T) {
		// The client trusts only the upstream CA. If MITM were active,
		// the proxy would present a cert signed by the MITM CA and the
		// handshake would fail. Success proves the tunnel is passthrough.
		resp, err := doGet(ctx, passthroughClient, "https://passthrough-tls.example.com/")
		if err != nil {
			t.Fatalf("request failed (if TLS error, passthrough is broken): %v", err)
		}
		defer resp.Body.Close()
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("read body: %v", readErr)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200, got %d: %s", resp.StatusCode, string(body))
		}
		t.Logf("passthrough response: %d %s", resp.StatusCode, string(body))
	})

	t.Run("passthrough_cert_is_upstream_not_mitm", func(t *testing.T) {
		// Verify that the TLS certificate seen by the client is from the
		// upstream server, NOT from the proxy's MITM CA.
		resp, err := doGet(ctx, passthroughClient, "https://passthrough-tls.example.com/")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.TLS == nil {
			t.Fatal("response has no TLS connection state")
		}
		if len(resp.TLS.PeerCertificates) == 0 {
			t.Fatal("no peer certificates in TLS handshake")
		}

		leaf := resp.TLS.PeerCertificates[0]
		issuer := leaf.Issuer

		// The cert must be signed by the upstream CA, not the MITM CA
		if issuer.CommonName == "E2E Test CA" {
			t.Fatal("passthrough cert is signed by MITM CA — tunnel is NOT passthrough")
		}
		if issuer.CommonName != "E2E Upstream CA" {
			t.Errorf("passthrough cert issuer CN = %q, want %q", issuer.CommonName, "E2E Upstream CA")
		}
		t.Logf("passthrough cert issuer: CN=%s, O=%v (verified upstream CA, not MITM)", issuer.CommonName, issuer.Organization)
	})
}
