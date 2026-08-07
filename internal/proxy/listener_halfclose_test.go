// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"context"
	"net"
	"testing"

	"go-egress-proxy/internal/netx"
)

// TestTrackingListenerPreservesHalfClose is the counterpart of
// TestCountingConnPreservesHalfClose in internal/trace.
//
// goproxy takes its half-closable tunnel copy loop only when BOTH the client and
// target connections satisfy the interface. The trace package guarded the target
// end; the client end here did not, which made that guard dead code in
// production and downgraded every CONNECT tunnel. Both tests must exist or the
// two ends can drift apart again — which is exactly how this happened.
func TestTrackingListenerPreservesHalfClose(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tl := NewTrackingListener(ln)
	t.Cleanup(func() { tl.Close() }) //nolint:errcheck // test cleanup

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := tl.Accept()
		if acceptErr != nil {
			return
		}
		accepted <- conn
	}()

	client, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", tl.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() }) //nolint:errcheck // test cleanup

	server := <-accepted
	t.Cleanup(func() { server.Close() }) //nolint:errcheck // test cleanup

	hc, ok := server.(netx.HalfCloser)
	if !ok {
		t.Fatal("accepted conn lost CloseRead/CloseWrite; goproxy would downgrade every tunnel " +
			"to the copy loop that closes the peer outright")
	}
	if err := hc.CloseWrite(); err != nil {
		t.Errorf("CloseWrite: %v", err)
	}
}

// TestTrackingListenerStillCountsAfterWrapping guards the interaction between
// the two decorations: preserving half-close must not bypass the tracking that
// makes the drain work.
func TestTrackingListenerStillCountsAfterWrapping(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tl := NewTrackingListener(ln)
	t.Cleanup(func() { tl.Close() }) //nolint:errcheck // test cleanup

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := tl.Accept()
		if acceptErr != nil {
			return
		}
		accepted <- conn
	}()

	client, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", tl.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() }) //nolint:errcheck // test cleanup

	server := <-accepted
	if got := tl.Open(); got != 1 {
		t.Fatalf("Open() = %d, want 1", got)
	}

	server.Close() //nolint:errcheck // test cleanup
	if got := tl.Open(); got != 0 {
		t.Errorf("Open() = %d after close, want 0; the tracking wrapper was bypassed", got)
	}
}
