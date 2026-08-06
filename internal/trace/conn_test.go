// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package trace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"

	"go-egress-proxy/internal/config"
)

// dialLocal is a context-aware dial helper (the linter forbids bare net.Dial).
func dialLocal(t *testing.T, addr string) net.Conn {
	t.Helper()

	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	return conn
}

// echoListener starts a local TCP server that echoes what it receives and then
// half-closes its write side, so tests can exercise a real tunnel.
func echoListener(t *testing.T) net.Listener {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck // test cleanup

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()  //nolint:errcheck // test cleanup
				io.Copy(conn, conn) //nolint:errcheck // echo until EOF
			}()
		}
	}()
	return ln
}

func testRecord(t *testing.T, buf *bytes.Buffer) *Record {
	t.Helper()

	ct, err := config.CompileTrace(config.TraceConfig{
		Enabled: true,
		Rules:   []config.TraceRule{{Host: "*"}},
	})
	if err != nil {
		t.Fatalf("CompileTrace: %v", err)
	}
	return NewRecord("tid", "passthrough", &ct.Rules[0], NewRedactor(ct), slog.New(slog.NewJSONHandler(buf, nil)))
}

// TestPassthroughDialerDecoratesBase pins the routing fix: the tracing dialer
// must delegate to the production dialer, not replace it. A from-scratch dialer
// silently opts the connection out of rewrite targets and dial metrics, so
// turning on tracing would change how a host is routed.
func TestPassthroughDialerDecoratesBase(t *testing.T) {
	ln := echoListener(t)

	var buf bytes.Buffer
	rec := testRecord(t, &buf)

	var (
		mu         sync.Mutex
		baseCalled bool
		gotAddr    string
		sawRecord  bool
	)
	base := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		baseCalled = true
		gotAddr = addr
		sawRecord = FromContext(ctx) != nil
		mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
	}

	conn, err := PassthroughDialer(rec, base)(context.Background(), "tcp", "target.internal:443")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test cleanup
	mu.Lock()
	defer mu.Unlock()
	if !baseCalled {
		t.Error("base dialer was not called; the tracing dialer must decorate, not replace")
	}
	if gotAddr != "target.internal:443" {
		t.Errorf("base received addr %q, want the original target so rewrites still apply", gotAddr)
	}
	if !sawRecord {
		t.Error("record not on the context; base cannot record connected IP, timing or dial errors")
	}
}

// TestPassthroughDialerEmitsOnDialFailure covers the one path where no Close
// ever runs, so the record must be emitted by the dialer itself.
func TestPassthroughDialerEmitsOnDialFailure(t *testing.T) {
	var buf bytes.Buffer
	rec := testRecord(t, &buf)

	base := func(_ context.Context, _, _ string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}

	if _, err := PassthroughDialer(rec, base)(context.Background(), "tcp", "x:443"); err == nil {
		t.Fatal("expected the dial error to propagate")
	}

	var out map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &out); err != nil {
		t.Fatalf("no trace record emitted on dial failure: %v", err)
	}
	if out["error"] != "connection refused" {
		t.Errorf("error = %v, want the dial error recorded", out["error"])
	}
}

// TestCountingConnPreservesHalfClose pins the tunnel-integrity fix. goproxy type-
// asserts for CloseRead/CloseWrite to choose its copy loop; failing the assertion
// drops the tunnel onto a path where the first finished direction fully closes
// the peer, truncating protocols that half-close their write side.
func TestCountingConnPreservesHalfClose(t *testing.T) {
	ln := echoListener(t)

	var buf bytes.Buffer
	wrapped := wrapConn(dialLocal(t, ln.Addr().String()), testRecord(t, &buf))
	defer wrapped.Close() //nolint:errcheck // test cleanup

	hc, ok := wrapped.(interface {
		CloseRead() error
		CloseWrite() error
	})
	if !ok {
		t.Fatal("wrapped TCP conn lost CloseRead/CloseWrite; goproxy's halfClosable assertion would fail")
	}
	if err := hc.CloseWrite(); err != nil {
		t.Errorf("CloseWrite: %v", err)
	}
}

// pipeConn is a net.Conn without CloseRead/CloseWrite.
type pipeConn struct{ net.Conn }

// TestCountingConnDoesNotFakeHalfClose is the other half of the contract: a conn
// that cannot half-close must not advertise that it can, or goproxy would pick a
// copy loop the connection cannot honor.
func TestCountingConnDoesNotFakeHalfClose(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close() //nolint:errcheck // test cleanup
	defer c2.Close() //nolint:errcheck // test cleanup

	var buf bytes.Buffer
	wrapped := wrapConn(pipeConn{c1}, testRecord(t, &buf))

	if _, ok := wrapped.(interface {
		CloseRead() error
		CloseWrite() error
	}); ok {
		t.Error("wrapper advertises half-close for a conn that does not support it")
	}
}

// TestCountingConnConcurrentCopyIsRaceFree runs the two tunnel directions
// concurrently, as goproxy does, under -race.
func TestCountingConnConcurrentCopyIsRaceFree(t *testing.T) {
	ln := echoListener(t)

	var buf bytes.Buffer
	rec := testRecord(t, &buf)

	conn := wrapConn(dialLocal(t, ln.Addr().String()), rec)

	payload := bytes.Repeat([]byte("x"), 4096)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range 20 {
			if _, wErr := conn.Write(payload); wErr != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		sink := make([]byte, 4096)
		for range 20 {
			if _, rErr := conn.Read(sink); rErr != nil {
				return
			}
		}
	}()

	wg.Wait()
	conn.Close() //nolint:errcheck // test cleanup

	var out map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &out); err != nil {
		t.Fatalf("no record emitted on tunnel close: %v", err)
	}
	tcp, ok := out["tcp"].(map[string]any)
	if !ok {
		t.Fatalf("no tcp group in record: %v", out)
	}
	if tcp["bytes_up"].(float64) <= 0 {
		t.Errorf("bytes_up = %v, want the written bytes counted", tcp["bytes_up"])
	}
}
