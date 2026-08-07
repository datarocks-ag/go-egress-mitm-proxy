// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package trace

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"go-egress-proxy/internal/config"
	"go-egress-proxy/internal/metrics"
)

// TestPrepareResponseLeavesBodyAloneWhenNotCapturing is the guard that keeps
// tracing from changing the bytes on the wire.
//
// goproxy decides a handler modified the response by comparing resp.Body against
// the original; when they differ it clears Content-Length and forces chunked
// encoding. Asserting object identity is the only way to pin that, and without
// this test the guard could be reduced to `if resp.Body == nil` — the pre-fix
// behavior — with every package still green.
func TestPrepareResponseLeavesBodyAloneWhenNotCapturing(t *testing.T) {
	var buf bytes.Buffer
	rec := recordFor(t, &buf, config.BodyCaptureConfig{Enabled: false})

	original := io.NopCloser(strings.NewReader("payload"))
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"text/plain"}},
		Body:          original,
		ContentLength: 7,
	}

	PrepareResponse(rec, resp)

	if resp.Body != original {
		t.Error("response body was replaced with capture disabled; goproxy will re-frame the response as chunked")
	}
	if buf.Len() == 0 {
		t.Error("record was not emitted at header time; with no wrapper nothing else will emit it")
	}
}

// TestPrepareResponseDoesNotWrapNoBody covers the 204/304 shape: Go leaves
// resp.Body as http.NoBody, and hiding that behind a wrapper produced a chunked
// 204, which RFC 9110 forbids.
func TestPrepareResponseDoesNotWrapNoBody(t *testing.T) {
	var buf bytes.Buffer
	rec := recordFor(t, &buf, config.BodyCaptureConfig{Enabled: true, Capture: "both"})

	resp := &http.Response{
		StatusCode: http.StatusNoContent,
		Header:     http.Header{},
		Body:       http.NoBody,
	}

	PrepareResponse(rec, resp)

	if resp.Body != http.NoBody {
		t.Error("http.NoBody was wrapped; the response would go out chunked in violation of RFC 9110")
	}
	// Skipping the wrapper means nothing else will emit this record.
	if buf.Len() == 0 {
		t.Error("record was not emitted for a NoBody response")
	}
}

// TestPrepareResponseWrapsWhenCapturing is the positive control: without it the
// tests above would also pass against a body wrapper that never runs.
func TestPrepareResponseWrapsWhenCapturing(t *testing.T) {
	var buf bytes.Buffer
	rec := recordFor(t, &buf, config.BodyCaptureConfig{Enabled: true, Capture: "both"})

	original := io.NopCloser(strings.NewReader("payload"))
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       original,
	}

	PrepareResponse(rec, resp)

	if resp.Body == original {
		t.Fatal("response body was not wrapped with capture enabled; nothing would be teed")
	}
	if buf.Len() != 0 {
		t.Error("record emitted at header time with capture on; it must wait for the body to finish")
	}

	io.Copy(io.Discard, resp.Body) //nolint:errcheck // drain to trigger emit
	resp.Body.Close()              //nolint:errcheck // test cleanup

	if buf.Len() == 0 {
		t.Error("record was not emitted when the captured body closed")
	}
}

// TestRecordResolvesLoggerAtEmitTime pins the rotation behavior.
//
// A passthrough record emits when its tunnel closes, which can be long after
// SIGHUP rotated the trace log and closed the file handle the record was created
// with. Capturing the logger meant those writes went to a closed descriptor, and
// slog discards handler errors, so the record vanished with no diagnostic — on
// exactly the code path rotation exists for.
func TestRecordResolvesLoggerAtEmitTime(t *testing.T) {
	ct, err := config.CompileTrace(config.TraceConfig{
		Enabled: true,
		Rules:   []config.TraceRule{{Host: "*"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	var before, after bytes.Buffer
	current := slog.New(slog.NewJSONHandler(&before, nil))

	// The indirection a live proxy uses: read the logger from config each time.
	rec := NewRecord("tid", "passthrough", &ct.Rules[0], NewRedactor(ct),
		func() *slog.Logger { return current })

	// SIGHUP: the destination is swapped while the tunnel is still open.
	current = slog.New(slog.NewJSONHandler(&after, nil))

	rec.Emit()

	if before.Len() != 0 {
		t.Errorf("record went to the pre-rotation destination:\n%s", before.String())
	}
	if after.Len() == 0 {
		t.Error("record did not reach the post-rotation destination; a captured logger would have written to a closed file")
	}
}

// TestLateDialUpdateDoesNotContradictConnectionReuse pins the ordering the mutex
// alone did not fix.
//
// Guarding the fields made concurrent access safe, but an abandoned dial can
// still arrive after applyResponse concluded the connection was reused, and the
// record would then claim connection_reused alongside a connected_ip describing
// a connection this request never used.
func TestLateDialUpdateDoesNotContradictConnectionReuse(t *testing.T) {
	var buf bytes.Buffer
	rec := recordFor(t, &buf, config.BodyCaptureConfig{Enabled: false})

	// A pooled connection: the request went upstream (which is what the
	// round-trip wrapper records) but no dial happened, so applyResponse marks it
	// reused.
	rec.MarkForwarded()
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody}
	PrepareResponse(rec, resp)

	// The abandoned dial completes afterwards.
	rec.SetTCP("10.0.0.99", 42*time.Millisecond, "TLS1.3", "TLS_AES_128_GCM_SHA256")
	rec.SetError("abandoned dial failed")

	var out map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &out); err != nil {
		t.Fatalf("trace record is not JSON: %v\n%s", err, buf.String())
	}

	tcp, _ := out["tcp"].(map[string]any)
	if tcp == nil {
		t.Fatal("no tcp group in record")
	}
	if tcp["connection_reused"] != true {
		t.Errorf("connection_reused = %v, want true", tcp["connection_reused"])
	}
	if ip, ok := tcp["connected_ip"]; ok {
		t.Errorf("connected_ip = %v present alongside connection_reused; the record describes a connection this request never used", ip)
	}
	if errMsg, ok := out["error"]; ok {
		t.Errorf("error = %v attached to a request that succeeded on a pooled connection", errMsg)
	}
}

// TestEmitSkipsCounterWhenRecordIsFiltered pins the backstop.
//
// Records are written at Info while the proxy defaults to Warn, so a
// main-stream record used to be silently discarded — and
// proxy_trace_records_total incremented anyway, so the counter and the log
// diverged permanently. Startup now supplies an Info-admitting handler for that
// case; this guard makes the remaining paths fail loudly instead of quietly.
func TestEmitSkipsCounterWhenRecordIsFiltered(t *testing.T) {
	ct, err := config.CompileTrace(config.TraceConfig{
		Enabled: true,
		Rules:   []config.TraceRule{{Host: "*"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	filtering := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError}))
	rec := NewRecord("tid", "mitm", &ct.Rules[0], NewRedactor(ct), StaticLogger(filtering))

	before := testutil.ToFloat64(metrics.TraceRecords.WithLabelValues("mitm"))
	rec.Emit()
	after := testutil.ToFloat64(metrics.TraceRecords.WithLabelValues("mitm"))

	if buf.Len() != 0 {
		t.Errorf("record unexpectedly written through a filtering handler:\n%s", buf.String())
	}
	if after != before {
		t.Errorf("proxy_trace_records_total moved by %v for a record that was never written", after-before)
	}
}

// TestEmitCountsWhenRecordIsWritten is the positive control.
func TestEmitCountsWhenRecordIsWritten(t *testing.T) {
	ct, err := config.CompileTrace(config.TraceConfig{
		Enabled: true,
		Rules:   []config.TraceRule{{Host: "*"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	rec := NewRecord("tid", "mitm", &ct.Rules[0], NewRedactor(ct),
		StaticLogger(config.MainStreamTraceLogger(&buf)))

	before := testutil.ToFloat64(metrics.TraceRecords.WithLabelValues("mitm"))
	rec.Emit()

	if buf.Len() == 0 {
		t.Error("record was not written through the main-stream trace logger")
	}
	if delta := testutil.ToFloat64(metrics.TraceRecords.WithLabelValues("mitm")) - before; delta != 1 {
		t.Errorf("counter moved by %v, want 1", delta)
	}
}

// TestBlockedRequestIsNotReportedAsConnectionReused pins the gate that
// MarkForwarded exists for.
//
// The reuse inference is "mitm mode, no dial, no error", which was also true of
// a request that never reached the network -- most importantly the 403 the
// handler synthesizes for a blocked host. The record then asserted the proxy had
// reused an upstream connection to a host it deliberately refused to contact.
func TestBlockedRequestIsNotReportedAsConnectionReused(t *testing.T) {
	var buf bytes.Buffer
	rec := recordFor(t, &buf, config.BodyCaptureConfig{Enabled: false})

	// No MarkForwarded: the handler returned 403 without dialing.
	resp := &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{}, Body: http.NoBody}
	PrepareResponse(rec, resp)

	var out map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &out); err != nil {
		t.Fatalf("trace record is not JSON: %v\n%s", err, buf.String())
	}
	if tcp, ok := out["tcp"].(map[string]any); ok {
		if tcp["connection_reused"] == true {
			t.Error("a request that was never forwarded is reported as connection_reused; " +
				"the record claims an upstream connection to a host the proxy refused to contact")
		}
	}
}
