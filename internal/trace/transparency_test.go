// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package trace

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"go-egress-proxy/internal/config"
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
