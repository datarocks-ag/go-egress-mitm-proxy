// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"go-egress-proxy/internal/config"
)

// TestTLSHandshakeIsBounded pins the fix for a blackholed upstream: a target
// that completes the TCP handshake and then never speaks TLS must not park the
// request goroutine forever holding a socket.
//
// Nothing else bounds this. Transport.TLSHandshakeTimeout is not applied when a
// custom DialTLSContext is set, and the context descends from a MITM request
// built over context.Background(), so it carries no deadline.
func TestTLSHandshakeIsBounded(t *testing.T) {
	// A listener that accepts and then goes silent — the classic grey failure.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck // test cleanup

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		accepted <- conn // hold it open, never negotiate
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Shorten the handshake bound for this test. Production keeps
	// DefaultTLSHandshakeTimeout; asserting the behavior does not need to cost
	// ten seconds of CI time.
	original := tlsHandshakeTimeout
	tlsHandshakeTimeout = 500 * time.Millisecond
	t.Cleanup(func() { tlsHandshakeTimeout = original })

	rc := &config.RuntimeConfig{}
	cfg := config.Config{}
	// Update returns the previous blocked-log file handle, not an error.
	_ = rc.Update(cfg, config.CompiledACL{}, nil, &tls.Config{MinVersion: tls.VersionTLS12}, nil, nil)

	rw := RewriteResult{TargetIP: "127.0.0.1", Matched: true}
	ctx := context.WithValue(context.Background(), config.RewriteCtxKey, rw)

	// Bound the test well above the handshake timeout so a hang is distinguishable
	// from a timely failure.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	start := time.Now()
	conn, dialErr := MakeTLSDialer(rc)(ctx, "tcp", net.JoinHostPort("silent.test", port))
	elapsed := time.Since(start)

	if dialErr == nil {
		conn.Close() //nolint:errcheck // test cleanup
		t.Fatal("handshake succeeded against a silent server")
	}
	if elapsed >= 10*time.Second {
		t.Errorf("handshake took %v; it must be bounded by %v", elapsed, tlsHandshakeTimeout)
	}
	if !errors.Is(dialErr, context.DeadlineExceeded) {
		t.Logf("handshake error (informational): %v", dialErr)
	}

	select {
	case c := <-accepted:
		c.Close() //nolint:errcheck // test cleanup
	default:
	}
}

// newStubTransport returns a plain transport for pool-identity assertions.
func newStubTransport() *http.Transport { return &http.Transport{} }

// TestTransportPoolSharesBaseForHeaderOnlyRewrites pins the sizing refinement: a
// rule that only rewrites headers or the scheme dials exactly as the base does,
// so giving it a private pool would fragment idle connections for no benefit.
func TestTransportPoolSharesBaseForHeaderOnlyRewrites(t *testing.T) {
	base := newStubTransport()
	pool := NewTransportPool(base)

	headerOnly := RewriteResult{Matched: true} // no target, not insecure
	if got := pool.For(headerOnly); got != base {
		t.Error("a header-only rewrite should share the base transport, not get its own pool")
	}
	if got := pool.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0; no per-target transport should have been created", got)
	}

	// A real target still gets its own.
	if got := pool.For(RewriteResult{TargetIP: "10.0.0.1", Matched: true}); got == base {
		t.Error("a rewrite with a target must not share the base pool")
	}
	if got := pool.Len(); got != 1 {
		t.Errorf("Len() = %d, want 1", got)
	}
}
