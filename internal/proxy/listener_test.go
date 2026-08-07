// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"context"
	"net"
	"testing"
	"time"
)

func localListener(t *testing.T) *TrackingListener {
	t.Helper()

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tl := NewTrackingListener(ln)
	t.Cleanup(func() { tl.Close() }) //nolint:errcheck // test cleanup
	return tl
}

func dialTo(t *testing.T, addr string) net.Conn {
	t.Helper()

	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

// TestTrackingListenerCountsOpenConnections pins the reason this type exists:
// goproxy hijacks CONNECT connections and http.Server then stops tracking them,
// so the count has to come from the listener.
func TestTrackingListenerCountsOpenConnections(t *testing.T) {
	tl := localListener(t)

	accepted := make(chan net.Conn, 2)
	go func() {
		for range 2 {
			conn, err := tl.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	c1 := dialTo(t, tl.Addr().String())
	defer c1.Close() //nolint:errcheck // test cleanup
	a1 := <-accepted

	c2 := dialTo(t, tl.Addr().String())
	defer c2.Close() //nolint:errcheck // test cleanup
	a2 := <-accepted

	if got := tl.Open(); got != 2 {
		t.Fatalf("Open() = %d, want 2", got)
	}

	a1.Close() //nolint:errcheck // test cleanup
	if got := tl.Open(); got != 1 {
		t.Errorf("Open() after one close = %d, want 1", got)
	}

	// Closing twice must not double-decrement.
	a1.Close() //nolint:errcheck // deliberate second close
	if got := tl.Open(); got != 1 {
		t.Errorf("Open() after double close = %d, want 1", got)
	}

	a2.Close() //nolint:errcheck // test cleanup
	if got := tl.Open(); got != 0 {
		t.Errorf("Open() after all closed = %d, want 0", got)
	}
}

// TestWaitForDrainReturnsWhenConnectionsClose is the success path: the drain
// completes as soon as the last tunnel closes.
func TestWaitForDrainReturnsWhenConnectionsClose(t *testing.T) {
	tl := localListener(t)

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := tl.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	c := dialTo(t, tl.Addr().String())
	defer c.Close() //nolint:errcheck // test cleanup
	a := <-accepted

	go func() {
		time.Sleep(50 * time.Millisecond)
		a.Close() //nolint:errcheck // test cleanup
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if !tl.WaitForDrain(ctx) {
		t.Error("WaitForDrain reported failure though the connection closed well inside the deadline")
	}
}

// TestWaitForDrainRespectsDeadline is the timeout path: a tunnel that never
// closes must not block shutdown forever.
func TestWaitForDrainRespectsDeadline(t *testing.T) {
	tl := localListener(t)

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := tl.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	c := dialTo(t, tl.Addr().String())
	defer c.Close() //nolint:errcheck // test cleanup
	a := <-accepted
	defer a.Close() //nolint:errcheck // test cleanup

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	if tl.WaitForDrain(ctx) {
		t.Error("WaitForDrain reported success with a connection still open")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("WaitForDrain took %v; it must return at the deadline", elapsed)
	}
}

// TestWaitForDrainReturnsImmediatelyWhenIdle covers the common case where
// nothing is open when shutdown starts.
func TestWaitForDrainReturnsImmediatelyWhenIdle(t *testing.T) {
	tl := localListener(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	if !tl.WaitForDrain(ctx) {
		t.Error("WaitForDrain should succeed immediately with no open connections")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("WaitForDrain took %v with nothing open; want immediate", elapsed)
	}
}

// TestLimitedListenerBoundsConcurrentConnections pins the ceiling.
//
// A hijacked CONNECT has no deadline of any kind, so a client that completes the
// CONNECT and then goes silent holds an fd, a goroutine and a bufio buffer until
// the process dies -- bounded only by the process rlimit. This is the lever that
// bounds it, and it also stops those connections making WaitForDrain burn the
// full budget on every rollout.
func TestLimitedListenerBoundsConcurrentConnections(t *testing.T) {
	base, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := NewLimitedTrackingListener(base, 2)
	defer tl.Close() //nolint:errcheck // test cleanup

	accepted := make(chan net.Conn, 3)
	go func() {
		for {
			c, acceptErr := tl.Accept()
			if acceptErr != nil {
				return
			}
			accepted <- c
		}
	}()

	dial := func() net.Conn {
		c, dialErr := (&net.Dialer{}).DialContext(t.Context(), "tcp", base.Addr().String())
		if dialErr != nil {
			t.Errorf("dial: %v", dialErr)
			return nil
		}
		return c
	}

	// Two connections fill the ceiling.
	c1, c2 := dial(), dial()
	defer c1.Close() //nolint:errcheck // test cleanup
	var a1, a2 net.Conn
	for range 2 {
		select {
		case c := <-accepted:
			if a1 == nil {
				a1 = c
			} else {
				a2 = c
			}
		case <-time.After(2 * time.Second):
			t.Fatal("listener did not accept up to its limit")
		}
	}
	_ = a1

	// A third connect must not be accepted while the ceiling is full. The TCP
	// handshake still completes (the kernel backlog absorbs it), so this asserts
	// on Accept returning, not on the dial failing.
	c3 := dial()
	defer c3.Close() //nolint:errcheck // test cleanup
	select {
	case <-accepted:
		t.Fatal("listener accepted beyond its limit; the ceiling does not bound anything")
	case <-time.After(250 * time.Millisecond):
	}

	// Closing one accepted connection frees a slot and the third is accepted.
	if err := a2.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-accepted:
		c.Close() //nolint:errcheck // test cleanup
	case <-time.After(2 * time.Second):
		t.Fatal("a freed slot was never reused; the limiter leaks slots and wedges the listener")
	}
	c2.Close() //nolint:errcheck // test cleanup
}

// TestUnlimitedListenerIsTheDefault: the ceiling is opt-in, so an existing
// deployment's behavior is unchanged until it sets one.
func TestUnlimitedListenerIsTheDefault(t *testing.T) {
	base, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := NewTrackingListener(base)
	defer tl.Close() //nolint:errcheck // test cleanup

	if tl.slots != nil {
		t.Error("NewTrackingListener installed a connection ceiling; it must default to unlimited")
	}
}
