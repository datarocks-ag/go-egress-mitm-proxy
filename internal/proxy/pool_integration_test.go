// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/elazarl/goproxy"

	"go-egress-proxy/internal/config"
)

// TestConnectionPoolIgnoresRewriteTarget drives two sequential requests to the
// same host but different paths through a goproxy server wired with the real
// HandleRequest and the real split-brain dialer, using two path_pattern rewrite
// rules that point at *different* target IPs.
//
// http.Transport keys its idle-connection pool on the request URL's host:port
// (see connectMethodKey in net/http), which is computed before DialContext runs.
// Our rewrite substitutes the target IP *inside* the dialer, so both rules share
// the pool key "api.internal:<port>". The second request therefore reuses the
// connection dialed for the first rule's target and never dials its own.
//
// Expected behavior: each rule dials its own target.
// Current behavior: only the first target is ever dialed.
func TestConnectionPoolIgnoresRewriteTarget(t *testing.T) {
	var backendMu sync.Mutex
	var backendPaths []string

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendMu.Lock()
		backendPaths = append(backendPaths, r.URL.Path)
		backendMu.Unlock()
		io.WriteString(w, "v1-backend") //nolint:errcheck // test backend write
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	port := backendURL.Port()

	const (
		v1Target = "127.0.0.1" // the real backend
		v2Target = "127.0.0.2" // deliberately not listening
	)

	// Two path-based rules on one domain, routed to different targets.
	// config.RuntimeConfig.Update excludes domains carrying path_pattern rules
	// from the exact map, so both are evaluated sequentially in order.
	rewrites := []config.CompiledRewriteRule{
		{
			Pattern:     regexp.MustCompile(`^api\.internal$`),
			PathPattern: regexp.MustCompile(`^/v1/`),
			TargetIP:    v1Target,
			Original:    "api.internal",
		},
		{
			Pattern:     regexp.MustCompile(`^api\.internal$`),
			PathPattern: regexp.MustCompile(`^/v2/`),
			TargetIP:    v2Target,
			Original:    "api.internal",
		},
	}

	rc := &config.RuntimeConfig{}
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "BLOCK" // only the rewrite rules may let traffic through
	_ = rc.Update(cfg, config.CompiledACL{}, rewrites, nil, nil, nil)

	// Wrap the real dialer to record which rewrite target each dial was for.
	// The rewrite result is threaded down by HandleRequest via the request context.
	baseDialer := MakeDialer(rc)
	var dialMu sync.Mutex
	var dialedTargets []string
	recordingDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		target := addr
		if rw, ok := ctx.Value(config.RewriteCtxKey).(RewriteResult); ok && rw.TargetIP != "" {
			target = rw.TargetIP
		}
		dialMu.Lock()
		dialedTargets = append(dialedTargets, target)
		dialMu.Unlock()
		return baseDialer(ctx, network, addr)
	}

	px := goproxy.NewProxyHttpServer()
	// Mirror the production transport pooling settings from cmd/mitm-proxy/main.go.
	px.Tr.Proxy = nil // ignore any HTTP_PROXY in the test environment
	px.Tr.DialContext = recordingDialer
	px.Tr.MaxIdleConns = 100
	px.Tr.MaxIdleConnsPerHost = 10
	px.Tr.IdleConnTimeout = 90 * time.Second

	pool := NewTransportPool(px.Tr)
	defer pool.CloseIdleConnections()

	px.OnRequest().DoFunc(func(r *http.Request, pctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// Set before HandleRequest, as production does; the closure runs later and
		// receives the request carrying the rewrite context.
		pctx.RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
			return pool.RoundTrip(req)
		})
		return HandleRequest(r, pctx, rc)
	})

	proxySrv := httptest.NewServer(px)
	defer proxySrv.Close()

	proxyURL, err := url.Parse(proxySrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// The client never resolves api.internal — it hands the absolute URI to the proxy.
	// Both URLs share the host:port that keys the upstream idle-connection pool.
	get := func(path string) int {
		req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet,
			"http://api.internal:"+port+path, nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		resp, doErr := client.Do(req)
		if doErr != nil {
			t.Fatalf("GET %s through proxy: %v", path, doErr)
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck // draining so the upstream conn is pooled
		resp.Body.Close()              //nolint:errcheck // test cleanup
		return resp.StatusCode
	}

	// First request establishes the upstream connection to v1Target and, once
	// goproxy closes the upstream body, returns it to the idle pool.
	if status := get("/v1/users"); status != http.StatusOK {
		t.Fatalf("GET /v1/users = %d, want 200 (backend is reachable)", status)
	}

	// Second request matches the /v2/ rule, which points at a different target.
	v2Status := get("/v2/items")

	dialMu.Lock()
	gotDials := slices.Clone(dialedTargets)
	dialMu.Unlock()

	backendMu.Lock()
	gotPaths := slices.Clone(backendPaths)
	backendMu.Unlock()

	// The core assertion: each rule must dial its own target.
	wantDials := []string{v1Target, v2Target}
	if !slices.Equal(gotDials, wantDials) {
		t.Errorf("dialed targets = %v, want %v\n"+
			"the /v2/ request reused the pooled connection to %s instead of dialing %s",
			gotDials, wantDials, v1Target, v2Target)
	}

	// Corroborating: nothing is listening on v2Target, so the /v2/ request must
	// fail upstream rather than succeed against the /v1/ backend.
	if v2Status == http.StatusOK {
		t.Errorf("GET /v2/items = 200, want an upstream error status; "+
			"it was served by the %s backend, not %s", v1Target, v2Target)
	}

	// Corroborating: traffic destined for v2Target must never reach the v1 backend.
	if slices.Contains(gotPaths, "/v2/items") {
		t.Errorf("backend at %s received %v, want it to never see /v2/items", v1Target, gotPaths)
	}
}

// TestConnectionPoolLeaksInsecureSkipVerify is the security-relevant instance of
// the same pool-keying defect as TestConnectionPoolIgnoresRewriteTarget.
//
// Two path_pattern rules on one host differ only in their per-rewrite `insecure`
// flag. MakeTLSDialer applies that flag when it builds the per-connection TLS
// config, but http.Transport pools the resulting connection under a key that
// knows nothing about it. A connection negotiated with InsecureSkipVerify=true is
// therefore handed to a later request that demanded full certificate verification.
//
// Expected behavior: the strict rule performs its own verified handshake and
// fails against the untrusted test CA.
// Current behavior: it silently rides the unverified connection and succeeds.
func TestConnectionPoolLeaksInsecureSkipVerify(t *testing.T) {
	srvAddr, _ := startTLSServer(t)
	srvHost, srvPort, err := net.SplitHostPort(srvAddr)
	if err != nil {
		t.Fatalf("split server addr: %v", err)
	}

	// No rewrite rules are configured: the helper below puts a RewriteResult
	// directly onto the request context, exactly as HandleRequest does for a
	// path-based rule, and MakeTLSDialer reads the context before consulting the
	// runtime config. Rules here would never be matched, so carrying them would
	// only imply this test pins the path_pattern -> RewriteResult chain, which it
	// does not. TestConnectionPoolIgnoresRewriteTarget covers that end to end.
	rc := &config.RuntimeConfig{}
	cfg := config.Config{}
	// Empty RootCAs = system pool, which does not trust the generated test CA.
	baseTLS := &tls.Config{MinVersion: tls.VersionTLS12}
	_ = rc.Update(cfg, config.CompiledACL{}, nil, baseTLS, nil, nil)

	// Wrap the real TLS dialer to record the verification mode of each handshake.
	baseTLSDialer := MakeTLSDialer(rc)
	var dialMu sync.Mutex
	var handshakeInsecure []bool
	recordingTLSDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if rw, ok := ctx.Value(config.RewriteCtxKey).(RewriteResult); ok {
			dialMu.Lock()
			handshakeInsecure = append(handshakeInsecure, rw.Insecure)
			dialMu.Unlock()
		}
		return baseTLSDialer(ctx, network, addr)
	}

	// Mirror the production transport from cmd/mitm-proxy/main.go.
	tr := &http.Transport{
		TLSClientConfig:       baseTLS,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DialTLSContext:        recordingTLSDialer,
	}
	pool := NewTransportPool(tr)
	defer pool.CloseIdleConnections()
	client := &http.Client{Transport: pool}

	// Issue a request carrying the rewrite result on its context, exactly as
	// HandleRequest does for path-based rules (handler.go:90).
	get := func(path string, insecure bool) (int, error) {
		rw := RewriteResult{TargetIP: srvHost, Insecure: insecure, Matched: true}
		ctx := context.WithValue(context.Background(), config.RewriteCtxKey, rw)
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet,
			"https://rewrite-trusted.test:"+srvPort+path, nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		resp, doErr := client.Do(req)
		if doErr != nil {
			return 0, doErr
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck // draining so the conn is pooled
		resp.Body.Close()              //nolint:errcheck // test cleanup
		return resp.StatusCode, nil
	}

	// The lax rule skips verification, so the handshake succeeds and pools an
	// unverified connection. The status itself is irrelevant (the test server only
	// routes "/ok"); what matters is that no TLS error occurred.
	if _, laxErr := get("/lax/ok", true); laxErr != nil {
		t.Fatalf("GET /lax/ok: %v (insecure rule should tolerate the untrusted CA)", laxErr)
	}

	// The strict rule demands verification against a CA that does not trust the server.
	strictStatus, strictErr := get("/strict/ok", false)

	dialMu.Lock()
	gotHandshakes := slices.Clone(handshakeInsecure)
	dialMu.Unlock()

	// The core assertion: the strict rule must perform its own verified handshake.
	wantHandshakes := []bool{true, false}
	if !slices.Equal(gotHandshakes, wantHandshakes) {
		t.Errorf("handshake insecure flags = %v, want %v\n"+
			"the /strict/ request reused the connection negotiated with InsecureSkipVerify=true",
			gotHandshakes, wantHandshakes)
	}

	// Corroborating: verification against an untrusted CA must fail.
	if strictErr == nil {
		t.Errorf("GET /strict/ok = %d with no error, want a certificate verification failure; "+
			"TLS verification was bypassed by connection reuse", strictStatus)
	}
}
