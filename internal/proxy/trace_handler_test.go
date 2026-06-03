// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"testing"

	"github.com/elazarl/goproxy"

	"go-egress-proxy/internal/config"
	"go-egress-proxy/internal/trace"
)

// traceRuntime builds a RuntimeConfig with tracing enabled for trace.example.com,
// a rewrite that drops/injects headers, and the trace logger writing to buf.
func traceRuntime(t *testing.T, buf *bytes.Buffer) *config.RuntimeConfig {
	t.Helper()
	rc := &config.RuntimeConfig{}
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "ALLOW"

	rewrites := []config.CompiledRewriteRule{
		{
			Pattern:     regexp.MustCompile(`^trace\.example\.com$`),
			TargetIP:    "10.0.0.9",
			Original:    "trace.example.com",
			DropHeaders: []string{"X-Drop-Me"},
			Headers:     map[string]string{"X-Add-Me": "yes"},
		},
	}
	_ = rc.Update(cfg, config.CompiledACL{}, rewrites, nil, nil, nil)

	ct, err := config.CompileTrace(config.TraceConfig{
		Enabled: true,
		Rules:   []config.TraceRule{{Host: `~^trace\.example\.com$`}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rc.SetTrace(ct, slog.New(slog.NewJSONHandler(buf, nil)), nil)
	return rc
}

func TestHandleRequestTraceCapturesHeaderDiff(t *testing.T) {
	var buf bytes.Buffer
	rc := traceRuntime(t, &buf)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://trace.example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Drop-Me", "secret")
	req.Header.Set("Accept", "application/json")

	pctx := &goproxy.ProxyCtx{}
	resultReq, resp := HandleRequest(req, pctx, rc)
	if resp != nil {
		resp.Body.Close() //nolint:errcheck // test cleanup
		t.Fatalf("expected pass-through (nil response), got %d", resp.StatusCode)
	}

	// The record must be threaded to both goproxy ctx and the request context.
	rec, ok := pctx.UserData.(*trace.Record)
	if !ok || rec == nil {
		t.Fatal("expected a *trace.Record in ctx.UserData")
	}
	if trace.FromContext(resultReq.Context()) != rec {
		t.Error("record not propagated via request context (dialers would miss it)")
	}

	// Outbound mutation actually happened.
	if resultReq.Header.Get("X-Drop-Me") != "" {
		t.Error("X-Drop-Me should have been dropped")
	}
	if resultReq.Header.Get("X-Add-Me") != "yes" {
		t.Error("X-Add-Me should have been injected")
	}

	// Emit (normally driven by OnResponse) and inspect the aggregated record.
	rec.Emit()
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("trace not valid JSON: %v\n%s", err, buf.String())
	}
	reqObj := out["request"].(map[string]any)

	in := reqObj["headers_in"].(map[string]any)
	if _, present := in["X-Request-Id"]; present {
		t.Error("inbound snapshot must not contain proxy-injected X-Request-ID")
	}
	if in["X-Drop-Me"] != "secret" {
		t.Errorf("inbound X-Drop-Me = %v, want secret", in["X-Drop-Me"])
	}

	dropped := toStringSet(reqObj["dropped"])
	if !dropped["X-Drop-Me"] {
		t.Errorf("dropped = %v, want it to include X-Drop-Me", reqObj["dropped"])
	}
	added := toStringSet(reqObj["added"])
	if !added["X-Add-Me"] || !added["X-Request-ID"] {
		t.Errorf("added = %v, want X-Add-Me and X-Request-ID", reqObj["added"])
	}
}

// TestHandleRequestTraceOverwriteIsModified verifies that an injected header
// which overwrites an existing client header is reported under "modified",
// not "added".
func TestHandleRequestTraceOverwriteIsModified(t *testing.T) {
	var buf bytes.Buffer
	rc := traceRuntime(t, &buf)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://trace.example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Add-Me", "client-supplied") // rewrite injects X-Add-Me, overwriting this

	pctx := &goproxy.ProxyCtx{}
	if _, resp := HandleRequest(req, pctx, rc); resp != nil {
		resp.Body.Close() //nolint:errcheck // test cleanup
		t.Fatalf("expected pass-through, got %d", resp.StatusCode)
	}
	rec, ok := pctx.UserData.(*trace.Record)
	if !ok {
		t.Fatal("expected a trace record")
	}
	rec.Emit()

	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	reqObj := out["request"].(map[string]any)
	if added := toStringSet(reqObj["added"]); added["X-Add-Me"] {
		t.Errorf("X-Add-Me overwrote an existing header; it must not be in added: %v", reqObj["added"])
	}
	if modified := toStringSet(reqObj["modified"]); !modified["X-Add-Me"] {
		t.Errorf("modified = %v, want it to include X-Add-Me", reqObj["modified"])
	}
}

func TestHandleRequestNoTraceWhenDisabled(t *testing.T) {
	rc := &config.RuntimeConfig{}
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "ALLOW"
	_ = rc.Update(cfg, config.CompiledACL{}, nil, nil, nil, nil)
	// No SetTrace call: trace disabled by default.

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://trace.example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	pctx := &goproxy.ProxyCtx{}
	if _, resp := HandleRequest(req, pctx, rc); resp != nil {
		resp.Body.Close() //nolint:errcheck // test cleanup
	}
	if pctx.UserData != nil {
		t.Errorf("expected no trace record when disabled, got %v", pctx.UserData)
	}
}

func toStringSet(v any) map[string]bool {
	out := map[string]bool{}
	if list, ok := v.([]any); ok {
		for _, e := range list {
			if s, ok := e.(string); ok {
				out[s] = true
			}
		}
	}
	return out
}
