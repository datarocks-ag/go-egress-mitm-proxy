// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/elazarl/goproxy"

	"go-egress-proxy/internal/config"
)

// TestTargetSchemeMovesThePort covers the downgrade the README documents:
// an intercepted HTTPS client talking to a backend that serves plain HTTP.
//
// goproxy builds the MITM request URL from the CONNECT authority, so the URL
// carries :443. Rewriting only the scheme left the port at 443 and sent a
// cleartext HTTP request to the TLS port of the target -- refused by a backend
// serving HTTP on 80, and read as a malformed TLS record by anything that does
// speak TLS there. The documented rewrite could not work.
func TestTargetSchemeMovesThePort(t *testing.T) {
	tests := []struct {
		name         string
		requestURL   string
		targetScheme string
		targetPort   string
		wantURL      string
		wantHostHdr  string
	}{
		{
			name:         "https 443 downgraded to http moves to 80",
			requestURL:   "https://legacy.internal:443/x",
			targetScheme: "http",
			wantURL:      "http://legacy.internal:80/x",
			wantHostHdr:  "legacy.internal",
		},
		{
			name:         "http 80 upgraded to https moves to 443",
			requestURL:   "http://api.internal:80/x",
			targetScheme: "https",
			wantURL:      "https://api.internal:443/x",
			wantHostHdr:  "api.internal",
		},
		{
			name: "an explicitly chosen port is a deliberate destination and is kept",
			// :8443 is not the default for either scheme, so the operator meant it.
			requestURL:   "https://legacy.internal:8443/x",
			targetScheme: "http",
			wantURL:      "http://legacy.internal:8443/x",
			wantHostHdr:  "legacy.internal:8443",
		},
		{
			name:         "target_port overrides the scheme default",
			requestURL:   "https://legacy.internal:443/x",
			targetScheme: "http",
			targetPort:   "8080",
			wantURL:      "http://legacy.internal:8080/x",
			wantHostHdr:  "legacy.internal:8080",
		},
		{
			name:        "target_port alone retargets without touching the scheme",
			requestURL:  "http://api.internal/x",
			targetPort:  "9000",
			wantURL:     "http://api.internal:9000/x",
			wantHostHdr: "api.internal:9000",
		},
		{
			// The port number does not change, but 443 stops being an oddity and
			// becomes the scheme default, so the Host header must drop it.
			name:         "a scheme change can make an unchanged port the default",
			requestURL:   "http://legacy.internal:443/x",
			targetScheme: "https",
			wantURL:      "https://legacy.internal:443/x",
			wantHostHdr:  "legacy.internal",
		},
		{
			// Mirror image: 80 was the default, and after the change it is not.
			name:         "a scheme change can make an unchanged port non-default",
			requestURL:   "https://legacy.internal:80/x",
			targetScheme: "http",
			wantURL:      "http://legacy.internal:80/x",
			wantHostHdr:  "legacy.internal",
		},
		{
			name:         "no scheme change leaves the authority alone",
			requestURL:   "http://api.internal:8080/x",
			targetScheme: "http",
			wantURL:      "http://api.internal:8080/x",
			wantHostHdr:  "api.internal:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rewrites := []config.CompiledRewriteRule{{
				Pattern:      regexp.MustCompile(`^(legacy|api)\.internal$`),
				TargetIP:     "10.20.30.90",
				TargetScheme: tt.targetScheme,
				TargetPort:   tt.targetPort,
				Original:     "legacy.internal",
			}}

			rc := &config.RuntimeConfig{}
			cfg := config.Config{}
			cfg.Proxy.DefaultPolicy = "ALLOW"
			_ = rc.Update(cfg, config.CompiledACL{}, rewrites, nil, nil, nil)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.requestURL, nil)
			// httptest.NewRequest populates Host from the URL; goproxy does the same
			// from the CONNECT authority.
			req.Host = req.URL.Host

			out, resp := HandleRequest(req, &goproxy.ProxyCtx{Req: req}, rc) //nolint:bodyclose // nil on the forwarded path
			if resp != nil {
				t.Fatalf("request was not forwarded: %s", resp.Status)
			}
			if got := out.URL.String(); got != tt.wantURL {
				t.Errorf("URL = %q, want %q\n(the URL authority is what the transport dials)", got, tt.wantURL)
			}
			if out.Host != tt.wantHostHdr {
				t.Errorf("Host header = %q, want %q", out.Host, tt.wantHostHdr)
			}
		})
	}
}

// TestTargetPortIsOverriddenByAnExplicitHostHeader pins the precedence: the port
// logic derives an authority, and headers: {Host: ...} is applied afterwards, so
// an operator setting a vhost name still wins.
func TestTargetPortIsOverriddenByAnExplicitHostHeader(t *testing.T) {
	rewrites := []config.CompiledRewriteRule{{
		Pattern:      regexp.MustCompile(`^legacy\.internal$`),
		TargetIP:     "10.20.30.90",
		TargetScheme: "http",
		Headers:      map[string]string{"Host": "vhost.corp"},
		Original:     "legacy.internal",
	}}

	rc := &config.RuntimeConfig{}
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "ALLOW"
	_ = rc.Update(cfg, config.CompiledACL{}, rewrites, nil, nil, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://legacy.internal:443/x", nil)
	req.Host = req.URL.Host

	out, resp := HandleRequest(req, &goproxy.ProxyCtx{Req: req}, rc) //nolint:bodyclose // nil on the forwarded path
	if resp != nil {
		t.Fatalf("request was not forwarded: %s", resp.Status)
	}
	if out.Host != "vhost.corp" {
		t.Errorf("Host = %q, want the explicitly configured %q", out.Host, "vhost.corp")
	}
	// The dialed authority must still have moved to the http default.
	if got := out.URL.Port(); got != "80" {
		t.Errorf("URL port = %q, want 80: the scheme change must still move the port", got)
	}
}
