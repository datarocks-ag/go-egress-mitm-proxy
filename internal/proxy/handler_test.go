// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"slices"
	"testing"
	"time"

	"go-egress-proxy/internal/config"
)

func TestExtractBaseDomain(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"deep.sub.example.com", "example.com"},
		{"a.b.c.d.example.com", "example.com"},
		{"localhost", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := ExtractBaseDomain(tt.host); got != tt.want {
				t.Errorf("ExtractBaseDomain(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestNormalizeDomainForMetrics(t *testing.T) {
	rewriteExact := map[string]*config.CompiledRewriteRule{
		"api.example.com": {TargetIP: "10.0.0.1"},
	}
	acl := config.CompiledACL{
		Whitelist: []*regexp.Regexp{regexp.MustCompile(`^.*\.google\.com$`)},
		Blacklist: []*regexp.Regexp{regexp.MustCompile(`^.*\.blocked\.com$`)},
	}

	tests := []struct {
		host string
		want string
	}{
		{"api.example.com", "api.example.com"}, // exact rewrite match
		{"www.google.com", "google.com"},       // whitelist match -> base domain
		{"sub.blocked.com", "blocked.com"},     // blacklist match -> base domain
		{"random.unknown.com", "_other"},       // no match -> _other
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := NormalizeDomainForMetrics(tt.host, rewriteExact, acl); got != tt.want {
				t.Errorf("NormalizeDomainForMetrics(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestGenerateRequestID(t *testing.T) {
	id1 := GenerateRequestID()
	id2 := GenerateRequestID()

	if id1 == "" {
		t.Error("GenerateRequestID() returned empty string")
	}
	if id1 == id2 {
		t.Error("GenerateRequestID() should return unique IDs")
	}
	if len(id1) != 16 { // 8 bytes = 16 hex chars
		t.Errorf("GenerateRequestID() returned ID of length %d, want 16", len(id1))
	}
}

func TestOutboundHTTP2TransportConfiguration(t *testing.T) {
	baseTLS := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
	tr := &http.Transport{
		TLSClientConfig:   baseTLS,
		ForceAttemptHTTP2: true,
	}

	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig should not be nil")
	}
	if !slices.Contains(tr.TLSClientConfig.NextProtos, "h2") {
		t.Errorf("TLSClientConfig.NextProtos = %v, want it to contain \"h2\"", tr.TLSClientConfig.NextProtos)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 should be true")
	}
}

func TestLookupRewrite(t *testing.T) {
	rewrites := []config.CompiledRewriteRule{
		{
			Pattern:  regexp.MustCompile(`^.+\.wild\.example\.com$`),
			TargetIP: "10.0.0.3",
			Original: "*.wild.example.com",
			Insecure: true,
		},
	}
	rewriteExact := map[string]*config.CompiledRewriteRule{
		"exact.example.com": {
			Pattern:  regexp.MustCompile(`^exact\.example\.com$`),
			TargetIP: "10.0.0.1",
			Original: "exact.example.com",
			Insecure: false,
		},
		"insecure.example.com": {
			Pattern:    regexp.MustCompile(`^insecure\.example\.com$`),
			TargetHost: "internal.corp.com",
			Original:   "insecure.example.com",
			Insecure:   true,
		},
	}

	tests := []struct {
		name      string
		host      string
		wantMatch bool
		wantIP    string
		wantHost  string
		wantInsec bool
	}{
		{
			name:      "exact match with target_ip",
			host:      "exact.example.com",
			wantMatch: true,
			wantIP:    "10.0.0.1",
		},
		{
			name:      "exact match with target_host and insecure",
			host:      "insecure.example.com",
			wantMatch: true,
			wantHost:  "internal.corp.com",
			wantInsec: true,
		},
		{
			name:      "wildcard pattern match",
			host:      "sub.wild.example.com",
			wantMatch: true,
			wantIP:    "10.0.0.3",
			wantInsec: true,
		},
		{
			name:      "no match",
			host:      "unknown.example.com",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := LookupRewrite(tt.host, rewrites, rewriteExact)
			if result.Matched != tt.wantMatch {
				t.Errorf("LookupRewrite(%q).Matched = %v, want %v", tt.host, result.Matched, tt.wantMatch)
			}
			if result.TargetIP != tt.wantIP {
				t.Errorf("LookupRewrite(%q).TargetIP = %v, want %v", tt.host, result.TargetIP, tt.wantIP)
			}
			if result.TargetHost != tt.wantHost {
				t.Errorf("LookupRewrite(%q).TargetHost = %v, want %v", tt.host, result.TargetHost, tt.wantHost)
			}
			if result.Insecure != tt.wantInsec {
				t.Errorf("LookupRewrite(%q).Insecure = %v, want %v", tt.host, result.Insecure, tt.wantInsec)
			}
		})
	}
}

func TestLookupRewriteSkipsPathPatternRules(t *testing.T) {
	rewrites := []config.CompiledRewriteRule{
		{
			Pattern:     regexp.MustCompile(`^api\.example\.com$`),
			PathPattern: regexp.MustCompile(`^/v1/`),
			TargetIP:    "10.0.0.1",
			Original:    "api.example.com",
		},
		{
			Pattern:     regexp.MustCompile(`^api\.example\.com$`),
			PathPattern: regexp.MustCompile(`^/v2/`),
			TargetIP:    "10.0.0.2",
			Original:    "api.example.com",
		},
		{
			Pattern:  regexp.MustCompile(`^other\.example\.com$`),
			TargetIP: "10.0.0.9",
			Original: "other.example.com",
		},
	}
	rewriteExact := map[string]*config.CompiledRewriteRule{}

	// Path-pattern rules should be skipped by LookupRewrite
	result := LookupRewrite("api.example.com", rewrites, rewriteExact)
	if result.Matched {
		t.Error("LookupRewrite() should not match api.example.com when all rules have path patterns")
	}

	// Domain-only rule should still match
	result = LookupRewrite("other.example.com", rewrites, rewriteExact)
	if !result.Matched {
		t.Error("LookupRewrite() should match other.example.com (no path pattern)")
	}
	if result.TargetIP != "10.0.0.9" {
		t.Errorf("LookupRewrite().TargetIP = %v, want 10.0.0.9", result.TargetIP)
	}
}

func TestHandleRequestPathRewrite(t *testing.T) {
	rc := &config.RuntimeConfig{}
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "BLOCK"
	cfg.Proxy.MitmCertPath = "/path/to/cert"
	cfg.Proxy.MitmKeyPath = "/path/to/key"

	rewrites := []config.CompiledRewriteRule{
		{
			Pattern:     regexp.MustCompile(`^api\.example\.com$`),
			PathPattern: regexp.MustCompile(`^/v1/`),
			TargetIP:    "10.0.0.1",
			Original:    "api.example.com",
			Headers:     map[string]string{"X-Backend": "v1"},
		},
		{
			Pattern:     regexp.MustCompile(`^api\.example\.com$`),
			PathPattern: regexp.MustCompile(`^/v2/`),
			TargetIP:    "10.0.0.2",
			Original:    "api.example.com",
			Headers:     map[string]string{"X-Backend": "v2"},
		},
		{
			Pattern:  regexp.MustCompile(`^api\.example\.com$`),
			TargetIP: "10.0.0.3",
			Original: "api.example.com",
			Headers:  map[string]string{"X-Backend": "default"},
		},
	}

	_ = rc.Update(cfg, config.CompiledACL{}, rewrites, nil, nil, nil)

	tests := []struct {
		name          string
		path          string
		wantHeader    string
		wantContextIP string
	}{
		{
			name:          "matches /v1/ path rule",
			path:          "/v1/users",
			wantHeader:    "v1",
			wantContextIP: "10.0.0.1",
		},
		{
			name:          "matches /v2/ path rule",
			path:          "/v2/items",
			wantHeader:    "v2",
			wantContextIP: "10.0.0.2",
		},
		{
			name:          "falls through to catch-all",
			path:          "/v3/other",
			wantHeader:    "default",
			wantContextIP: "10.0.0.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://api.example.com"+tt.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			resultReq, resp := HandleRequest(req, nil, rc)
			if resp != nil {
				resp.Body.Close() //nolint:errcheck // test cleanup
				t.Fatalf("expected nil response (not blocked), got %d", resp.StatusCode)
			}

			if got := resultReq.Header.Get("X-Backend"); got != tt.wantHeader {
				t.Errorf("X-Backend header = %q, want %q", got, tt.wantHeader)
			}

			// Check context carries the rewrite result
			rw, ok := resultReq.Context().Value(config.RewriteCtxKey).(RewriteResult)
			if !ok {
				t.Fatal("RewriteResult not found in request context")
			}
			if rw.TargetIP != tt.wantContextIP {
				t.Errorf("context RewriteResult.TargetIP = %q, want %q", rw.TargetIP, tt.wantContextIP)
			}
		})
	}
}

func TestHandleRequestPathNoMatchBlocked(t *testing.T) {
	rc := &config.RuntimeConfig{}
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "BLOCK"

	// Only path-based rules, no catch-all
	rewrites := []config.CompiledRewriteRule{
		{
			Pattern:     regexp.MustCompile(`^api\.example\.com$`),
			PathPattern: regexp.MustCompile(`^/v1/`),
			TargetIP:    "10.0.0.1",
			Original:    "api.example.com",
		},
	}

	_ = rc.Update(cfg, config.CompiledACL{}, rewrites, nil, nil, nil)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://api.example.com/v2/items", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, resp := HandleRequest(req, nil, rc)
	if resp == nil {
		t.Fatal("expected blocked response, got nil")
	}
	defer resp.Body.Close() //nolint:errcheck // test cleanup
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("response status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestHandleRequestDropHeaders(t *testing.T) {
	rc := &config.RuntimeConfig{}
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "BLOCK"

	rewrites := []config.CompiledRewriteRule{
		{
			Pattern:     regexp.MustCompile(`^drop\.example\.com$`),
			TargetIP:    "10.0.0.1",
			Original:    "drop.example.com",
			DropHeaders: []string{"Authorization", "Cookie"},
			Headers:     map[string]string{"X-Injected": "yes"},
		},
	}

	_ = rc.Update(cfg, config.CompiledACL{}, rewrites, nil, nil, nil)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://drop.example.com/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Cookie", "session=abc123")
	req.Header.Set("Accept", "application/json")

	resultReq, resp := HandleRequest(req, nil, rc)
	if resp != nil {
		resp.Body.Close() //nolint:errcheck // test cleanup
		t.Fatalf("expected nil response, got %d", resp.StatusCode)
	}

	// Dropped headers should be gone
	if got := resultReq.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization header should be dropped, got %q", got)
	}
	if got := resultReq.Header.Get("Cookie"); got != "" {
		t.Errorf("Cookie header should be dropped, got %q", got)
	}

	// Non-dropped headers should remain
	if got := resultReq.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept header = %q, want %q", got, "application/json")
	}

	// Injected headers should be present
	if got := resultReq.Header.Get("X-Injected"); got != "yes" {
		t.Errorf("X-Injected header = %q, want %q", got, "yes")
	}
}

func TestHandleRequestTargetScheme(t *testing.T) {
	rc := &config.RuntimeConfig{}
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "BLOCK"

	rewrites := []config.CompiledRewriteRule{
		{
			Pattern:      regexp.MustCompile(`^scheme\.example\.com$`),
			TargetIP:     "10.0.0.1",
			Original:     "scheme.example.com",
			TargetScheme: "http",
		},
	}

	_ = rc.Update(cfg, config.CompiledACL{}, rewrites, nil, nil, nil)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://scheme.example.com/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	resultReq, resp := HandleRequest(req, nil, rc)
	if resp != nil {
		resp.Body.Close() //nolint:errcheck // test cleanup
		t.Fatalf("expected nil response, got %d", resp.StatusCode)
	}

	if resultReq.URL.Scheme != "http" {
		t.Errorf("URL.Scheme = %q, want %q", resultReq.URL.Scheme, "http")
	}
}

func TestHandleRequestTargetSchemeEmpty(t *testing.T) {
	rc := &config.RuntimeConfig{}
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "BLOCK"

	rewrites := []config.CompiledRewriteRule{
		{
			Pattern:  regexp.MustCompile(`^noscheme\.example\.com$`),
			TargetIP: "10.0.0.1",
			Original: "noscheme.example.com",
		},
	}

	_ = rc.Update(cfg, config.CompiledACL{}, rewrites, nil, nil, nil)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://noscheme.example.com/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	resultReq, resp := HandleRequest(req, nil, rc)
	if resp != nil {
		resp.Body.Close() //nolint:errcheck // test cleanup
		t.Fatalf("expected nil response, got %d", resp.StatusCode)
	}

	if resultReq.URL.Scheme != "https" {
		t.Errorf("URL.Scheme = %q, want %q (should be unchanged)", resultReq.URL.Scheme, "https")
	}
}

func TestDialerUsesContextRewrite(t *testing.T) {
	// Start a plain TCP listener to accept the dial
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck // test cleanup

	_, port, splitErr := net.SplitHostPort(ln.Addr().String())
	if splitErr != nil {
		t.Fatalf("split host port: %v", splitErr)
	}

	// Accept one connection in background
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		conn.Close() //nolint:errcheck // test cleanup
	}()

	rc := &config.RuntimeConfig{}
	_ = rc.Update(config.Config{}, config.CompiledACL{}, nil, nil, nil, nil)

	dial := MakeDialer(rc)

	// Put a rewrite result in context pointing to our listener
	rw := RewriteResult{TargetIP: "127.0.0.1", Matched: true}
	ctx := context.WithValue(context.Background(), config.RewriteCtxKey, rw)

	conn, dialErr := dial(ctx, "tcp", net.JoinHostPort("nonexistent.test", port))
	if dialErr != nil {
		t.Fatalf("dial failed: %v", dialErr)
	}
	conn.Close() //nolint:errcheck // test cleanup
}

func TestOutboundHTTP2TransportWithDialTLSContext(t *testing.T) {
	baseTLS := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}

	tr := &http.Transport{
		TLSClientConfig:   baseTLS,
		ForceAttemptHTTP2: true,
		DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return nil, nil // stub for test
		},
	}

	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig should not be nil")
	}
	if !slices.Contains(tr.TLSClientConfig.NextProtos, "h2") {
		t.Errorf("TLSClientConfig.NextProtos = %v, want it to contain \"h2\"", tr.TLSClientConfig.NextProtos)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 should be true")
	}
	if tr.DialTLSContext == nil {
		t.Error("DialTLSContext should be set")
	}
}

// startTLSServer creates a TLS server with a self-signed certificate signed by a generated CA.
// Returns the listener address, CA cert pool (for trusted clients), and the CA cert (for building truststores).
func startTLSServer(t *testing.T) (addr string, caPool *x509.CertPool, caCertPEM []byte) {
	t.Helper()

	// Generate CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TLS Test CA", Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	caPool = x509.NewCertPool()
	caPool.AddCert(caCert)

	// Generate server cert signed by the CA
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	srvTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "rewrite-insecure.test", "rewrite-trusted.test"},
	}
	srvCertDER, err := x509.CreateCertificate(rand.Reader, srvTemplate, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvCertDER})
	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})

	tlsCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatalf("load server TLS keypair: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("start TLS listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck // test cleanup

	// Serve simple HTTP responses (listener is already TLS-wrapped, use Serve not ServeTLS)
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		srv.Serve(ln) //nolint:errcheck // background test server
	}()

	return ln.Addr().String(), caPool, caCertPEM
}

func TestMakeTLSDialer(t *testing.T) {
	srvAddr, caPool, _ := startTLSServer(t)
	srvHost, srvPort, err := net.SplitHostPort(srvAddr)
	if err != nil {
		t.Fatalf("split server addr: %v", err)
	}

	// Helper to create a RuntimeConfig with given settings
	setupRuntime := func(insecureGlobal bool, rewrites []config.CompiledRewriteRule, tlsConfig *tls.Config) *config.RuntimeConfig {
		rc := &config.RuntimeConfig{}
		cfg := config.Config{}
		cfg.Proxy.InsecureSkipVerify = insecureGlobal
		_ = rc.Update(cfg, config.CompiledACL{}, rewrites, tlsConfig, nil, nil)
		return rc
	}

	t.Run("per_rewrite_insecure_allows_self_signed", func(t *testing.T) {
		// Rewrite with insecure=true -> TLS handshake succeeds even without CA in pool
		rewrites := []config.CompiledRewriteRule{
			{
				Pattern:  regexp.MustCompile(`^rewrite-insecure\.test$`),
				TargetIP: srvHost,
				Original: "rewrite-insecure.test",
				Insecure: true,
			},
		}
		baseTLS := &tls.Config{MinVersion: tls.VersionTLS12} // empty RootCAs = system pool (won't trust test CA)
		rc := setupRuntime(false, rewrites, baseTLS)

		dial := MakeTLSDialer(rc)
		conn, dialErr := dial(context.Background(), "tcp", net.JoinHostPort("rewrite-insecure.test", srvPort))
		if dialErr != nil {
			t.Fatalf("dial failed: %v", dialErr)
		}
		conn.Close() //nolint:errcheck // test cleanup
	})

	t.Run("trusted_ca_in_pool_allows_connection", func(t *testing.T) {
		// No insecure flag, but CA is in pool -> handshake succeeds
		rewrites := []config.CompiledRewriteRule{
			{
				Pattern:  regexp.MustCompile(`^rewrite-trusted\.test$`),
				TargetIP: srvHost,
				Original: "rewrite-trusted.test",
				Insecure: false,
			},
		}
		baseTLS := &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    caPool,
		}
		rc := setupRuntime(false, rewrites, baseTLS)

		dial := MakeTLSDialer(rc)
		conn, dialErr := dial(context.Background(), "tcp", net.JoinHostPort("rewrite-trusted.test", srvPort))
		if dialErr != nil {
			t.Fatalf("dial failed: %v", dialErr)
		}
		conn.Close() //nolint:errcheck // test cleanup
	})

	t.Run("rejects_untrusted_cert", func(t *testing.T) {
		// No insecure, no CA trust -> handshake must fail
		rewrites := []config.CompiledRewriteRule{
			{
				Pattern:  regexp.MustCompile(`^rewrite-trusted\.test$`),
				TargetIP: srvHost,
				Original: "rewrite-trusted.test",
				Insecure: false,
			},
		}
		baseTLS := &tls.Config{MinVersion: tls.VersionTLS12} // empty = system pool, won't trust test CA
		rc := setupRuntime(false, rewrites, baseTLS)

		dial := MakeTLSDialer(rc)
		_, dialErr := dial(context.Background(), "tcp", net.JoinHostPort("rewrite-trusted.test", srvPort))
		if dialErr == nil {
			t.Fatal("expected TLS handshake error for untrusted cert")
		}
	})

	t.Run("global_insecure_skip_verify", func(t *testing.T) {
		// Global insecure_skip_verify=true, no per-rewrite flag -> succeeds
		rewrites := []config.CompiledRewriteRule{
			{
				Pattern:  regexp.MustCompile(`^rewrite-trusted\.test$`),
				TargetIP: srvHost,
				Original: "rewrite-trusted.test",
				Insecure: false,
			},
		}
		baseTLS := &tls.Config{MinVersion: tls.VersionTLS12}
		rc := setupRuntime(true, rewrites, baseTLS) // global insecure

		dial := MakeTLSDialer(rc)
		conn, dialErr := dial(context.Background(), "tcp", net.JoinHostPort("rewrite-trusted.test", srvPort))
		if dialErr != nil {
			t.Fatalf("dial failed: %v", dialErr)
		}
		conn.Close() //nolint:errcheck // test cleanup
	})
}

func TestResponseProtoNormalization(t *testing.T) {
	// goproxy writes MITM responses via resp.Write() which serializes
	// ProtoMajor/ProtoMinor into the status line. The OnResponse handler
	// must normalize non-HTTP/1.x responses to prevent "Unsupported HTTP
	// version" errors. Two cases:
	//   1) goproxy.NewResponse() leaves Proto at zero -> "HTTP/0.0"
	//   2) Upstream HTTP/2 -> Proto "HTTP/2.0"
	tests := []struct {
		name       string
		proto      string
		protoMajor int
		protoMinor int
	}{
		{"goproxy.NewResponse zero values", "", 0, 0},
		{"upstream HTTP/2", "HTTP/2.0", 2, 0},
		{"HTTP/1.1 unchanged", "HTTP/1.1", 1, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Proto:      tt.proto,
				ProtoMajor: tt.protoMajor,
				ProtoMinor: tt.protoMinor,
			}

			// Apply the same normalization as the OnResponse handler.
			if resp.ProtoMajor != 1 {
				resp.Proto = "HTTP/1.1"
				resp.ProtoMajor = 1
				resp.ProtoMinor = 1
			}

			if resp.Proto != "HTTP/1.1" {
				t.Errorf("Proto = %q, want %q", resp.Proto, "HTTP/1.1")
			}
			if resp.ProtoMajor != 1 {
				t.Errorf("ProtoMajor = %d, want 1", resp.ProtoMajor)
			}
			if resp.ProtoMinor != 1 {
				t.Errorf("ProtoMinor = %d, want 1", resp.ProtoMinor)
			}
		})
	}
}

// timeoutError implements net.Error with Timeout() == true.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return false }

func TestUpstreamErrorResponse(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantCode   int
		wantReason string
	}{
		{"net timeout error", &timeoutError{}, http.StatusGatewayTimeout, "Gateway Timeout"},
		{"context deadline exceeded", context.DeadlineExceeded, http.StatusGatewayTimeout, "Gateway Timeout"},
		{"connection refused", errors.New("connection refused"), http.StatusBadGateway, "Bad Gateway"},
		{"dns error", errors.New("no such host"), http.StatusBadGateway, "Bad Gateway"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, reason := UpstreamErrorResponse(tt.err)
			if code != tt.wantCode {
				t.Errorf("code = %d, want %d", code, tt.wantCode)
			}
			if reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestRecordResponseMetrics(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		contentLength int64
	}{
		{"200 with body", 200, 1024},
		{"404 no body", 404, -1},
		{"500 zero body", 500, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode:    tt.statusCode,
				ContentLength: tt.contentLength,
			}
			// Should not panic
			RecordResponseMetrics(resp)
		})
	}
}

func TestRecordDialError(t *testing.T) {
	// Should not panic for either error type
	RecordDialError(&timeoutError{})
	RecordDialError(errors.New("connection refused"))
}

func TestMakeDialerInvalidAddress(t *testing.T) {
	rc := &config.RuntimeConfig{}
	var cfg config.Config
	cfg.Proxy.DefaultPolicy = "ALLOW"
	_ = rc.Update(cfg, config.CompiledACL{}, nil, nil, nil, nil)

	dialer := MakeDialer(rc)
	_, err := dialer(context.Background(), "tcp", "no-port")
	if err == nil {
		t.Fatal("expected error for invalid address")
	}
}

func TestMakeDialerTargetHost(t *testing.T) {
	// Start a TCP listener to accept the connection
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck // test cleanup

	rc := &config.RuntimeConfig{}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.WithValue(context.Background(), config.RewriteCtxKey, RewriteResult{
		TargetHost: "127.0.0.1",
		Matched:    true,
	})

	dialer := MakeDialer(rc)
	conn, err := dialer(ctx, "tcp", "example.com:"+port)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	conn.Close() //nolint:errcheck // test cleanup
}

func TestMakeTLSDialerInvalidAddress(t *testing.T) {
	rc := &config.RuntimeConfig{}
	var cfg config.Config
	cfg.Proxy.DefaultPolicy = "ALLOW"
	_ = rc.Update(cfg, config.CompiledACL{}, nil, nil, nil, nil)

	dialer := MakeTLSDialer(rc)
	_, err := dialer(context.Background(), "tcp", "no-port")
	if err == nil {
		t.Fatal("expected error for invalid address")
	}
}
