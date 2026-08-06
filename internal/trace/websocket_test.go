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

// readWriteCloser stands in for the upgraded connection http.Transport returns
// as the body of a 101, which goproxy asserts to io.ReadWriter.
type readWriteCloser struct {
	io.Reader
	io.Writer
}

func (readWriteCloser) Close() error { return nil }

// TestPrepareResponseDoesNotWrapSwitchingProtocols pins the WebSocket case.
// goproxy hands the upgraded connection over via resp.Body.(io.ReadWriter); a
// wrapper exposing only Read and Close fails that assertion and the tunnel is
// dropped with a debug-level warning.
func TestPrepareResponseDoesNotWrapSwitchingProtocols(t *testing.T) {
	var buf bytes.Buffer
	rec := recordFor(t, &buf, config.BodyCaptureConfig{Enabled: true, Capture: "both"})

	original := readWriteCloser{Reader: strings.NewReader(""), Writer: io.Discard}
	resp := &http.Response{
		StatusCode: http.StatusSwitchingProtocols,
		Header:     http.Header{"Upgrade": []string{"websocket"}},
		Body:       original,
	}

	PrepareResponse(rec, resp)

	if _, ok := resp.Body.(io.ReadWriter); !ok {
		t.Fatal("101 body no longer satisfies io.ReadWriter; goproxy would drop the WebSocket tunnel")
	}
	if buf.Len() == 0 {
		t.Error("record was not emitted for the 101; nothing else will emit it")
	}
}
