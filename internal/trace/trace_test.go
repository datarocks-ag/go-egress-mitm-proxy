// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package trace

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"go-egress-proxy/internal/config"
)

// newBufferLogger returns a JSON slog logger writing into buf for assertions.
func newBufferLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, nil))
}

func bodyRule() *config.CompiledTraceRule {
	return &config.CompiledTraceRule{
		Bodies: config.CompiledBodyCapture{
			Enabled:          true,
			CaptureRequest:   true,
			CaptureResponse:  true,
			MaxRequestBytes:  1024,
			MaxResponseBytes: 1024,
			ContentTypes:     []string{"application/json", "text/*"},
			OnBinary:         "base64",
		},
	}
}

func TestRecordEmitAggregatedRedacts(t *testing.T) {
	var buf bytes.Buffer
	// Compile through the real path so built-in redaction defaults
	// (authorization, cookie, set-cookie, ...) are applied.
	ct, err := config.CompileTrace(config.TraceConfig{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	rec := NewRecord("trace-123", "mitm", bodyRule(), NewRedactor(ct), StaticLogger(newBufferLogger(&buf)))
	rec.SetConnect("api.internal", "api.internal")
	rec.SetTCP("10.0.0.5", 4*time.Millisecond, "TLS 1.3", "TLS_AES_128_GCM_SHA256")

	reqIn, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://api.internal/v1/debug?token=supersecret&page=2", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqIn.Header.Set("Authorization", "Bearer secret-token")
	reqIn.Header.Set("Accept", "application/json")
	rec.SetRequestIn(reqIn)
	rec.SetRequestOut(reqIn, []string{"Cookie"}, []string{"X-Request-ID"}, nil, "")

	resp := &http.Response{
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		Header:     http.Header{"Content-Type": {"application/json"}, "Set-Cookie": {"sid=abc"}},
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
	}
	PrepareResponse(rec, resp)
	// Drain + close the wrapped body to trigger emission.
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}

	var rec0 map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec0); err != nil {
		t.Fatalf("trace output is not valid JSON: %v\n%s", err, buf.String())
	}

	if rec0["trace_id"] != "trace-123" || rec0["mode"] != "mitm" {
		t.Errorf("trace_id/mode = %v/%v", rec0["trace_id"], rec0["mode"])
	}
	tcp := rec0["tcp"].(map[string]any)
	if tcp["connected_ip"] != "10.0.0.5" {
		t.Errorf("connected_ip = %v, want 10.0.0.5", tcp["connected_ip"])
	}
	if tcp["tls_version"] != "TLS 1.3" {
		t.Errorf("tls_version = %v", tcp["tls_version"])
	}

	req := rec0["request"].(map[string]any)
	in := req["headers_in"].(map[string]any)
	if in["Authorization"] != "<redacted>" {
		t.Errorf("Authorization = %v, want <redacted>", in["Authorization"])
	}
	if in["Accept"] != "application/json" {
		t.Errorf("Accept = %v, want application/json", in["Accept"])
	}
	if url, _ := req["url"].(string); !strings.Contains(url, "token=%3Credacted%3E") && !strings.Contains(url, "token=<redacted>") {
		t.Errorf("query not redacted: %v", req["url"])
	}

	resp0 := rec0["response"].(map[string]any)
	if resp0["status"].(float64) != http.StatusOK {
		t.Errorf("status = %v, want 200", resp0["status"])
	}
	respHeaders := resp0["headers"].(map[string]any)
	if respHeaders["Set-Cookie"] != "<redacted>" {
		t.Errorf("Set-Cookie = %v, want <redacted> (built-in default)", respHeaders["Set-Cookie"])
	}
	respBody := resp0["body"].(map[string]any)
	if respBody["text"] != `{"ok":true}` {
		t.Errorf("response body text = %v", respBody["text"])
	}
}

func TestRecordEmitsExactlyOnce(t *testing.T) {
	var buf bytes.Buffer
	rec := NewRecord("once", "mitm", &config.CompiledTraceRule{}, Redactor{}, StaticLogger(newBufferLogger(&buf)))
	rec.SetConnect("h", "h")
	rec.Emit()
	rec.Emit()
	rec.Emit()
	if n := strings.Count(buf.String(), "\"trace_id\":\"once\""); n != 1 {
		t.Errorf("emitted %d times, want exactly 1", n)
	}
}

func TestRequestBodyCapturedAndForwarded(t *testing.T) {
	var buf bytes.Buffer
	rec := NewRecord("b", "mitm", bodyRule(), Redactor{}, StaticLogger(newBufferLogger(&buf)))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://x/y",
		strings.NewReader(`{"hello":"world"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	rec.SetRequestIn(req)
	rec.WrapRequestBody(req)

	// Simulate the transport reading the body for forwarding.
	forwarded, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(forwarded) != `{"hello":"world"}` {
		t.Fatalf("forwarded body altered: %q", forwarded)
	}
	rec.Emit()

	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	body := out["request"].(map[string]any)["body"].(map[string]any)
	if body["text"] != `{"hello":"world"}` {
		t.Errorf("captured request body = %v", body["text"])
	}
}

func TestBodyTruncationAndBinary(t *testing.T) {
	tests := []struct {
		name        string
		max         int
		contentType string
		onBinary    string
		data        string
		wantText    bool
		wantBase64  bool
		wantTrunc   bool
	}{
		{"text within cap", 100, "text/plain", "base64", "hello", true, false, false},
		{"text truncated", 3, "text/plain", "base64", "hello", true, false, true},
		{"text truncated mid-rune still text", 2, "text/plain", "base64", "héllo", true, false, true},
		{"binary base64", 100, "application/octet-stream", "base64", "\x00\x01\x02", false, true, false},
		{"binary skipped", 100, "application/octet-stream", "skip", "\x00\x01\x02", false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bb := &bodyBuffer{max: tt.max}
			bb.write([]byte(tt.data))
			cfg := config.CompiledBodyCapture{
				ContentTypes: []string{"text/*", "application/json"},
				OnBinary:     tt.onBinary,
			}
			out := renderBody(bb, tt.contentType, cfg)
			_, hasText := out["text"]
			_, hasB64 := out["base64"]
			_, hasTrunc := out["truncated"]
			if hasText != tt.wantText {
				t.Errorf("text present = %v, want %v (%v)", hasText, tt.wantText, out)
			}
			if hasB64 != tt.wantBase64 {
				t.Errorf("base64 present = %v, want %v (%v)", hasB64, tt.wantBase64, out)
			}
			if hasTrunc != tt.wantTrunc {
				t.Errorf("truncated = %v, want %v (%v)", hasTrunc, tt.wantTrunc, out)
			}
		})
	}
}

func TestLogSecretsDisablesRedaction(t *testing.T) {
	rd := NewRedactor(config.CompiledTrace{
		RedactHeaders: map[string]bool{"authorization": true},
		RedactQuery:   true,
		LogSecrets:    true,
	})
	if got := rd.headerValue("Authorization", "Bearer x"); got != "Bearer x" {
		t.Errorf("with log_secrets, header = %q, want raw", got)
	}
	if got := rd.redactURL("https://x/y?token=abc"); got != "https://x/y?token=abc" {
		t.Errorf("with log_secrets, url = %q, want raw", got)
	}
}

func TestContentTypeAllowed(t *testing.T) {
	allow := []string{"application/json", "text/*"}
	cases := map[string]bool{
		"application/json":                true,
		"application/json; charset=utf-8": true,
		"text/html":                       true,
		"text/plain; charset=utf-8":       true,
		"application/octet-stream":        false,
		"":                                false,
	}
	for ct, want := range cases {
		if got := contentTypeAllowed(ct, allow); got != want {
			t.Errorf("contentTypeAllowed(%q) = %v, want %v", ct, got, want)
		}
	}
}

// TestDefaultRedactionCoversURLBearingHeaders pins the OAuth-code leak.
//
// redact_query only ever saw the request URL. Header values are masked by header
// NAME against DefaultRedactHeaders, which listed only the four
// credential-bearing headers — so a 302 carrying an authorization code in
// Location wrote it to the trace log verbatim, on the shipped example rule, with
// redaction nominally enabled and log_secrets false.
func TestDefaultRedactionCoversURLBearingHeaders(t *testing.T) {
	ct, err := config.CompileTrace(config.TraceConfig{
		Enabled: true,
		Rules:   []config.TraceRule{{Host: "*"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rd := NewRedactor(ct)

	const authCode = "4/0AY0e-g7SECRETCODE"
	hdr := http.Header{}
	hdr.Set("Location", "https://app.internal.com/callback?code="+authCode+"&state=xyz")
	hdr.Set("Referer", "https://app.internal.com/login?session=abc123")
	hdr.Set("Content-Location", "/v1/resource?token=zzz")
	hdr.Set("X-Trace-Id", "keep-me")

	got := rd.headerMap(hdr)

	for _, name := range []string{"Location", "Referer", "Content-Location"} {
		joined := got[name]
		if strings.Contains(joined, "code=4/") || strings.Contains(joined, "session=abc123") ||
			strings.Contains(joined, "token=zzz") {
			t.Errorf("%s leaked a secret into the trace record: %q", name, joined)
		}
	}
	// Non-sensitive headers must still be readable, or the trace stops being useful.
	if got["X-Trace-Id"] != "keep-me" {
		t.Errorf("X-Trace-Id was masked; only the listed headers should be")
	}
}

// TestRedactURLStripsUserinfo covers the other half: url.URL.String() re-emits
// user:password@ for an absolute-form plain-HTTP target, so the credential
// reached the log even with query redaction on.
func TestRedactURLStripsUserinfo(t *testing.T) {
	ct, err := config.CompileTrace(config.TraceConfig{
		Enabled: true,
		Rules:   []config.TraceRule{{Host: "*"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rd := NewRedactor(ct)

	got := rd.redactURL("http://alice:hunter2@api.internal/v1/things?token=abc")
	if strings.Contains(got, "hunter2") {
		t.Errorf("userinfo password survived redaction: %q", got)
	}
	if strings.Contains(got, "abc") {
		t.Errorf("query value survived redaction: %q", got)
	}
	if !strings.Contains(got, "api.internal") {
		t.Errorf("host was lost, making the record useless: %q", got)
	}
}

// TestLogSecretsStillDisablesTheNewRedaction keeps the escape hatch honest.
func TestLogSecretsStillDisablesTheNewRedaction(t *testing.T) {
	ct, err := config.CompileTrace(config.TraceConfig{
		Enabled:    true,
		LogSecrets: true,
		Rules:      []config.TraceRule{{Host: "*"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rd := NewRedactor(ct)

	hdr := http.Header{}
	hdr.Set("Location", "https://app/cb?code=verbatim")
	if got := rd.headerMap(hdr)["Location"]; !strings.Contains(got, "verbatim") {
		t.Errorf("log_secrets did not disable Location redaction: %q", got)
	}
}
