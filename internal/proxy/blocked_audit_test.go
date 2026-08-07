// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/elazarl/goproxy"

	"go-egress-proxy/internal/config"
)

// TestHandleRequestWritesBlockedAuditEntry covers the blocked-request log's
// primary producer.
//
// Before this test, `grep -rn "LogBlocked" --include=*_test.go` returned nothing:
// the call inside HandleRequest — which writes every audit entry for plain-HTTP
// blocks and for blacklisted HTTPS hosts that are intercepted rather than
// refused — was exercised by no test at all. Deleting it left the whole suite
// green while the compliance artifact the feature exists for went silently
// empty. The only other coverage was rejectConnect, which after the CONNECT-stage
// narrowing fires only for hosts that are both passthrough and blacklisted.
//
// The field names are asserted here, at the point of production, rather than in
// a test that writes its own attributes and reads them back.
func TestHandleRequestWritesBlockedAuditEntry(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		policy     string
		blacklist  []string
		wantAction string
	}{
		{
			name:       "blacklisted host",
			host:       "denied.example.com",
			policy:     "ALLOW",
			blacklist:  []string{"denied.example.com"},
			wantAction: "BLACK-LISTED",
		},
		{
			name:       "blocked by default policy",
			host:       "unknown.example.com",
			policy:     "BLOCK",
			wantAction: "BLOCKED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Config{}
			cfg.Proxy.DefaultPolicy = tt.policy
			cfg.ACL.Blacklist = tt.blacklist
			acl, err := config.CompileACL(cfg)
			if err != nil {
				t.Fatal(err)
			}

			var audit bytes.Buffer
			rc := &config.RuntimeConfig{}
			_ = rc.Update(cfg, acl, nil, nil, slog.New(slog.NewJSONHandler(&audit, nil)), nil)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
				"http://"+tt.host+"/secret/path", nil)
			req.RemoteAddr = "10.1.2.3:55555"

			_, resp := HandleRequest(req, &goproxy.ProxyCtx{Req: req}, rc)
			if resp == nil {
				t.Fatal("request was forwarded; it should have been refused")
			}
			defer resp.Body.Close() //nolint:errcheck // test cleanup
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("status = %d, want 403", resp.StatusCode)
			}

			if audit.Len() == 0 {
				t.Fatal("nothing written to the blocked-request log; the audit trail for this " +
					"denial does not exist")
			}
			var entry map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(audit.Bytes()), &entry); err != nil {
				t.Fatalf("audit entry is not JSON: %v\n%s", err, audit.String())
			}

			// Asserting "target" by name is what pins the rename from "path";
			// log consumers key on these.
			for field, want := range map[string]string{
				"action": tt.wantAction,
				"host":   tt.host,
				"method": http.MethodGet,
				"target": "/secret/path",
				"client": "10.1.2.3:55555",
			} {
				if got, _ := entry[field].(string); got != want {
					t.Errorf("audit %q = %q, want %q", field, got, want)
				}
			}
			if id, _ := entry["request_id"].(string); id == "" {
				t.Error("audit entry has no request_id; it cannot be correlated with the access log")
			}
		})
	}
}

// TestHandleRequestDoesNotAuditForwardedRequests is the negative control: the
// log is an audit trail of denials, so an allowed request must not appear in it.
func TestHandleRequestDoesNotAuditForwardedRequests(t *testing.T) {
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "ALLOW"

	var audit bytes.Buffer
	rc := &config.RuntimeConfig{}
	_ = rc.Update(cfg, config.CompiledACL{}, []config.CompiledRewriteRule{{
		Pattern:  regexp.MustCompile(`^allowed\.example\.com$`),
		TargetIP: "10.0.0.1",
		Original: "allowed.example.com",
	}}, nil, slog.New(slog.NewJSONHandler(&audit, nil)), nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"http://allowed.example.com/x", nil)

	_, resp := HandleRequest(req, &goproxy.ProxyCtx{Req: req}, rc) //nolint:bodyclose // nil on the forwarded path
	if resp != nil {
		t.Fatalf("request was refused: %s", resp.Status)
	}
	if audit.Len() != 0 {
		t.Errorf("a forwarded request was written to the blocked-request log:\n%s", audit.String())
	}
}
