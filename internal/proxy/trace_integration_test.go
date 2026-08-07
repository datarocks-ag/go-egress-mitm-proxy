// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/elazarl/goproxy"

	"go-egress-proxy/internal/config"
	"go-egress-proxy/internal/trace"
)

// TestTraceEndToEndThroughProxy drives a real plain-HTTP request through a
// goproxy server wired with HandleRequest, PrepareResponse, and the real
// split-brain dialer, then asserts the aggregated trace record — including the
// connected IP populated at the TCP layer — was emitted.
func TestTraceEndToEndThroughProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "sid=should-be-redacted")
		io.WriteString(w, `{"hello":"world"}`) //nolint:errcheck // test backend write
	}))
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}

	var traceBuf bytes.Buffer
	rc := &config.RuntimeConfig{}
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "ALLOW"
	_ = rc.Update(cfg, config.CompiledACL{}, nil, nil, nil, nil)

	ct, err := config.CompileTrace(config.TraceConfig{
		Enabled: true,
		Rules: []config.TraceRule{
			{
				Host:   "~^127\\.0\\.0\\.1$",
				Bodies: config.BodyCaptureConfig{Enabled: true},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rc.SetTrace(ct, slog.New(slog.NewJSONHandler(&traceBuf, nil)), nil)

	px := goproxy.NewProxyHttpServer()
	px.OnRequest().DoFunc(func(r *http.Request, pctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		return HandleRequest(r, pctx, rc)
	})
	px.OnResponse().DoFunc(func(resp *http.Response, pctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil {
			return resp
		}
		if rec, ok := pctx.UserData.(*trace.Record); ok {
			trace.PrepareResponse(rec, resp)
		}
		return resp
	})
	px.Tr.DialContext = MakeDialer(rc)
	proxySrv := httptest.NewServer(px)
	defer proxySrv.Close()

	proxyURL, err := url.Parse(proxySrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, backend.URL+"/data?token=secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Probe", "hi")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close() //nolint:errcheck // test cleanup
	if string(body) != `{"hello":"world"}` {
		t.Fatalf("proxied body altered: %q", body)
	}

	var rec0 map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(traceBuf.Bytes()), &rec0); err != nil {
		t.Fatalf("trace not valid JSON: %v\n%s", err, traceBuf.String())
	}

	tcp, ok := rec0["tcp"].(map[string]any)
	if !ok || tcp["connected_ip"] != backendURL.Hostname() {
		t.Errorf("tcp.connected_ip = %v, want %s (populated by the dialer)", rec0["tcp"], backendURL.Hostname())
	}

	// connect.host preserves the explicit port from the request URL.
	if connect := rec0["connect"].(map[string]any); connect["host"] != backendURL.Host {
		t.Errorf("connect.host = %v, want %s (with port)", connect["host"], backendURL.Host)
	}

	reqObj := rec0["request"].(map[string]any)
	if in := reqObj["headers_in"].(map[string]any); in["X-Probe"] != "hi" {
		t.Errorf("X-Probe header_in = %v, want hi", in["X-Probe"])
	}
	if urlStr, _ := reqObj["url"].(string); !bytes.Contains([]byte(urlStr), []byte("token=")) || bytes.Contains([]byte(urlStr), []byte("token=secret")) {
		t.Errorf("query not redacted: %v", reqObj["url"])
	}

	respObj := rec0["response"].(map[string]any)
	if respObj["status"].(float64) != http.StatusOK {
		t.Errorf("status = %v, want 200", respObj["status"])
	}
	if h := respObj["headers"].(map[string]any); h["Set-Cookie"] != "<redacted>" {
		t.Errorf("Set-Cookie = %v, want <redacted>", h["Set-Cookie"])
	}
	if b := respObj["body"].(map[string]any); b["text"] != `{"hello":"world"}` {
		t.Errorf("response body = %v", b["text"])
	}
}
