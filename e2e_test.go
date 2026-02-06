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
  - domain: "rewrite.example.com"
    target_ip: %q
    headers:
      X-Rewritten: "true"
      X-Custom-Header: "proxy-injected"
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

	// Start go-httpbin container
	httpbinCtr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "mccutchen/go-httpbin:v2.15.0",
			ExposedPorts: []string{"8080/tcp"},
			Networks:     []string{nw.Name},
			WaitingFor:   wait.ForHTTP("/get").WithPort("8080/tcp").WithStartupTimeout(30 * time.Second),
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
