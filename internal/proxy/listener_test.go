// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
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

	// Fatal, not Errorf-and-return-nil: callers defer Close on the result, so a
	// nil would turn a transient dial failure into a panic in the deferred call
	// and bury the real cause. A failed dial makes the rest of this test
	// meaningless anyway.
	dial := func() net.Conn {
		t.Helper()
		c, dialErr := (&net.Dialer{}).DialContext(t.Context(), "tcp", base.Addr().String())
		if dialErr != nil {
			t.Fatalf("dial: %v", dialErr)
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

// TestLimitedListenerAcceptUnblocksOnClose pins the shutdown path of the
// connection ceiling.
//
// Accept waits for a free slot BEFORE calling the underlying Accept, and closing
// a net.Listener does not unblock a channel send. So with the ceiling full,
// Serve's accept loop sat in that send: Shutdown closed the listener and nothing
// woke it. main blocks on Serve (cmd/mitm-proxy/main.go), so the process would
// never reach the drain join and never exit -- it would hang until the kubelet
// escalated to SIGKILL at terminationGracePeriodSeconds.
//
// The saturating connections are hijacked CONNECT tunnels that may never close,
// which is precisely the situation the ceiling was added to survive, so the
// bound would have introduced a shutdown hang in its own motivating case.
func TestLimitedListenerAcceptUnblocksOnClose(t *testing.T) {
	base, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := NewLimitedTrackingListener(base, 1)

	// Fill the single slot and keep it filled.
	client, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close() //nolint:errcheck // test cleanup

	held, err := tl.Accept()
	if err != nil {
		t.Fatalf("first accept: %v", err)
	}
	defer held.Close() //nolint:errcheck // test cleanup

	// This Accept blocks waiting for the slot, as Serve's loop would.
	accepted := make(chan error, 1)
	go func() {
		c, acceptErr := tl.Accept()
		if c != nil {
			c.Close() //nolint:errcheck // test cleanup
		}
		accepted <- acceptErr
	}()

	// Let it reach the blocking send before closing.
	time.Sleep(50 * time.Millisecond)

	if err := tl.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case <-accepted:
		// Any error is fine; returning at all is the property under test.
	case <-time.After(3 * time.Second):
		t.Fatal("Accept did not return after Close while the ceiling was full; " +
			"Serve's accept loop is wedged and the process cannot shut down")
	}
}

// TestServeReturnsAfterShutdownWithSaturatedListener is the end-to-end form of
// the property above: what main actually depends on is not that Accept returns,
// but that http.Server.Serve does.
//
// main blocks on Serve and only then joins the drain goroutine, so a wedged
// accept loop means the process never exits -- the drain finishes, and the
// binary sits there until the kubelet SIGKILLs it at the end of
// terminationGracePeriodSeconds.
//
// The saturating connection is HIJACKED, which matters: an ordinary idle
// connection is closed by Shutdown, which frees the slot and hides the defect.
// http.Server stops tracking a connection once it is hijacked and never closes
// it, so the slot stays held -- and a hijacked connection is what every CONNECT
// tunnel through this proxy is.
func TestServeReturnsAfterShutdownWithSaturatedListener(t *testing.T) {
	base, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := NewLimitedTrackingListener(base, 1)

	hijacked := make(chan net.Conn, 1)
	srv := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, _, hijackErr := w.(http.Hijacker).Hijack()
			if hijackErr != nil {
				t.Errorf("hijack: %v", hijackErr)
				return
			}
			hijacked <- conn // held open, exactly like a CONNECT tunnel
		}),
	}

	served := make(chan error, 1)
	go func() { served <- srv.Serve(tl) }()

	client, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close() //nolint:errcheck // test cleanup
	if _, err = client.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}

	var tunnel net.Conn
	select {
	case tunnel = <-hijacked:
		defer tunnel.Close() //nolint:errcheck // test cleanup
	case <-time.After(5 * time.Second):
		t.Fatal("handler never hijacked the connection")
	}

	// A second connection so the accept loop is parked waiting for the slot the
	// hijacked tunnel holds and will not give back.
	queued, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer queued.Close() //nolint:errcheck // test cleanup
	time.Sleep(100 * time.Millisecond)

	// Shutdown runs on its own goroutine so this test reports a clean failure
	// instead of deadlocking. http.Server.Shutdown waits on its listener group
	// for Serve to return, and that wait is NOT context-aware -- so a wedged
	// accept loop hangs Shutdown itself, past its own timeout. In drain() that is
	// the first call, so nothing after it runs either.
	shutdownCtx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- srv.Shutdown(shutdownCtx) }()

	select {
	case <-shutdownDone:
	case <-time.After(8 * time.Second):
		t.Fatal("Shutdown did not return with the ceiling saturated by a hijacked connection; " +
			"it waits on its listener group for Serve, and that wait ignores the context, " +
			"so drain() blocks on its very first call and the process never exits")
	}

	select {
	case err := <-served:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve returned %v, want ErrServerClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Shutdown; main blocks here and never reaches the drain join")
	}
}
