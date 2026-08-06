// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package netx

import (
	"context"
	"net"
	"testing"
)

// countingWrapper stands in for the real decorators: it embeds the net.Conn
// interface, which is precisely what drops CloseRead/CloseWrite from the method
// set.
type countingWrapper struct {
	net.Conn
	reads int
}

func (c *countingWrapper) Read(p []byte) (int, error) {
	c.reads++
	return c.Conn.Read(p)
}

func localTCP(t *testing.T) net.Conn {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() }) //nolint:errcheck // test cleanup

	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		t.Cleanup(func() { conn.Close() }) //nolint:errcheck // test cleanup
	}()

	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() }) //nolint:errcheck // test cleanup
	return conn
}

// TestPreserveHalfCloseKeepsTCPCapability pins the property both tunnel ends
// depend on: goproxy selects its half-closable copy loop only when BOTH the
// client and target connections satisfy the interface, so a decorator that hides
// it on either side downgrades every tunnel.
func TestPreserveHalfCloseKeepsTCPCapability(t *testing.T) {
	base := localTCP(t)
	wrapper := &countingWrapper{Conn: base}

	// Without the helper the capability is gone — this is the failure mode.
	if _, ok := net.Conn(wrapper).(HalfCloser); ok {
		t.Fatal("bare wrapper unexpectedly satisfies HalfCloser; the test cannot detect the bug it guards")
	}

	got := PreserveHalfClose(base, wrapper)

	hc, ok := got.(HalfCloser)
	if !ok {
		t.Fatal("wrapped TCP conn does not satisfy HalfCloser; goproxy would downgrade the tunnel")
	}
	if err := hc.CloseWrite(); err != nil {
		t.Errorf("CloseWrite: %v", err)
	}
}

// TestPreserveHalfCloseRoutesIOThroughWrapper guards against the opposite
// mistake: delegating half-close must not bypass the decorator's own Read/Write,
// or byte counting and connection tracking would silently stop working.
func TestPreserveHalfCloseRoutesIOThroughWrapper(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close() }) //nolint:errcheck // test cleanup
	t.Cleanup(func() { client.Close() }) //nolint:errcheck // test cleanup

	// net.Pipe conns cannot half-close, so the helper returns the wrapper as-is.
	wrapper := &countingWrapper{Conn: client}
	got := PreserveHalfClose(client, wrapper)

	go func() {
		server.Write([]byte("hello")) //nolint:errcheck // test fixture
	}()

	buf := make([]byte, 5)
	if _, err := got.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if wrapper.reads == 0 {
		t.Error("read bypassed the wrapper; decorator logic would be skipped")
	}
}

// TestPreserveHalfCloseDoesNotFakeCapability is the honesty half of the
// contract: a connection that cannot half-close must not advertise that it can,
// or goproxy picks a copy loop the connection cannot honor.
func TestPreserveHalfCloseDoesNotFakeCapability(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { server.Close() }) //nolint:errcheck // test cleanup
	t.Cleanup(func() { client.Close() }) //nolint:errcheck // test cleanup

	got := PreserveHalfClose(client, &countingWrapper{Conn: client})

	if _, ok := got.(HalfCloser); ok {
		t.Error("wrapper advertises half-close for a net.Pipe conn that cannot do it")
	}
}
