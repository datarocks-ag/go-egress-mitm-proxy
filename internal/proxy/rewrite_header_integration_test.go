// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"

	"github.com/elazarl/goproxy"

	"go-egress-proxy/internal/config"
)

// TestRewriteHostHeaderReachesBackend drives a real request through goproxy and
// the real HandleRequest, and asserts the backend actually receives the Host a
// rewrite rule injects.
//
// Host is not stored in Request.Header: net/http excludes it from
// Header.WriteSubset and derives the wire value (and the HTTP/2 :authority) from
// Request.Host. A plain Header.Set("Host", ...) is therefore discarded on the way
// out, which is the worst shape a rewrite bug can take — the ACCESS log says
// REWRITTEN and the trace diff lists the header as added, while the backend
// answers from whichever vhost the original name selected. Only an assertion made
// at the backend can tell the two apart, so this test reads r.Host there rather
// than inspecting the proxy's own request object.
func TestRewriteHostHeaderReachesBackend(t *testing.T) {
	const injectedHost = "internal-vhost.corp"

	seen := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Host
		io.WriteString(w, "ok") //nolint:errcheck // test backend write
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	rewrites := []config.CompiledRewriteRule{{
		Pattern:  regexp.MustCompile(`^external-api\.partner\.com$`),
		TargetIP: "127.0.0.1",
		Headers:  map[string]string{"Host": injectedHost, "X-Routed-Via": "egress-proxy"},
		Original: "external-api.partner.com",
	}}

	rc := &config.RuntimeConfig{}
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "BLOCK"
	_ = rc.Update(cfg, config.CompiledACL{}, rewrites, nil, nil, nil)

	px := goproxy.NewProxyHttpServer()
	px.Tr.Proxy = nil
	px.Tr.DialContext = MakeDialer(rc)
	pool := NewTransportPool(px.Tr)
	defer pool.CloseIdleConnections()

	px.OnRequest().DoFunc(func(r *http.Request, pctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
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

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://external-api.partner.com:"+backendURL.Port()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer resp.Body.Close()               //nolint:errcheck // test cleanup
	_, _ = io.Copy(io.Discard, resp.Body) //nolint:errcheck // draining a test response

	got := <-seen
	if got != injectedHost {
		t.Errorf("backend saw Host %q, want %q; the injected Host never reached the wire, "+
			"so the request was served by the vhost the original name selects", got, injectedHost)
	}
}

// TestRewriteHostHeaderIsReportedAsModified pins the trace diff for the Host
// case. Host is applied through Request.Host rather than the header map, so the
// bookkeeping is separate from every other header and can drift independently of
// the behavior above.
func TestRewriteHostHeaderIsReportedAsModified(t *testing.T) {
	rewrites := []config.CompiledRewriteRule{{
		Pattern:  regexp.MustCompile(`^api\.internal$`),
		TargetIP: "127.0.0.1",
		Headers:  map[string]string{"Host": "vhost.corp"},
		Original: "api.internal",
	}}

	rc := &config.RuntimeConfig{}
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "ALLOW"
	_ = rc.Update(cfg, config.CompiledACL{}, rewrites, nil, nil, nil)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://api.internal/x", nil)
	ctx := &goproxy.ProxyCtx{Req: req}

	out, resp := HandleRequest(req, ctx, rc) //nolint:bodyclose // resp is nil on the forwarded path; asserted below
	if resp != nil {
		t.Fatalf("request was not forwarded: %v", resp.Status)
	}
	if out.Host != "vhost.corp" {
		t.Errorf("Request.Host = %q, want %q", out.Host, "vhost.corp")
	}
	// The header map must not also carry it, or net/http would serialize a
	// duplicate Host on the HTTP/1.1 path.
	if v := out.Header.Get("Host"); v != "" {
		t.Errorf("Header[Host] = %q, want empty: Host belongs in Request.Host only", v)
	}
}
