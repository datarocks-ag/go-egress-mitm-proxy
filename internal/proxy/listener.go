// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go-egress-proxy/internal/metrics"
	"go-egress-proxy/internal/netx"
)

// TrackingListener counts the client connections it has handed out that are
// still open.
//
// It exists because http.Server cannot drain this proxy's main traffic class.
// goproxy hijacks the client connection for every CONNECT, and http.Server stops
// tracking a connection once it is hijacked — so Shutdown returns immediately no
// matter how many MITM or passthrough tunnels are still live. Counting at the
// listener catches every client connection, hijacked or not, because the
// hijacked connection is the same net.Conn and goproxy closes it when the tunnel
// ends.
type TrackingListener struct {
	net.Listener
	open atomic.Int64

	// slots bounds concurrent client connections. nil means unlimited.
	//
	// A hijacked CONNECT has no deadline of any kind: http.Server's
	// ReadHeaderTimeout covers the CONNECT request line and headers, but
	// hijackLocked clears the deadline and nothing re-arms it, so a client that
	// completes a CONNECT and then goes silent holds an fd, a goroutine and a
	// bufio buffer until the process dies. Re-arming a deadline on the wrapped
	// conn is not the answer -- it would override the header deadline
	// http.Server sets on the same connection and silently disable slowloris
	// protection -- so bounding how many such connections can exist is the lever
	// that applies. Those connections also make WaitForDrain burn the full budget
	// on every rollout, since they never close.
	slots chan struct{}
}

// NewTrackingListener wraps ln so open connections can be counted and waited on,
// with no ceiling on their number.
func NewTrackingListener(ln net.Listener) *TrackingListener {
	return NewLimitedTrackingListener(ln, 0)
}

// NewLimitedTrackingListener additionally caps concurrent client connections.
// maxConns <= 0 means unlimited.
//
// At the cap, Accept blocks until a connection closes rather than rejecting:
// the kernel backlog absorbs the wait, and a client that times out retries,
// whereas a rejected connection looks to the caller like the proxy is down.
func NewLimitedTrackingListener(ln net.Listener, maxConns int) *TrackingListener {
	l := &TrackingListener{Listener: ln}
	if maxConns > 0 {
		l.slots = make(chan struct{}, maxConns)
	}
	return l
}

// Accept returns a connection that decrements the open count when closed.
func (l *TrackingListener) Accept() (net.Conn, error) {
	if l.slots != nil {
		// Report saturation once per blocked accept, before waiting: at the cap
		// the symptom is clients hanging, and without this there is nothing in
		// the logs or metrics to explain it.
		select {
		case l.slots <- struct{}{}:
		default:
			metrics.ListenerSaturated.Inc()
			slog.Warn("Client connection limit reached; accepting is paused until one closes",
				"limit", cap(l.slots), "open", l.Open())
			l.slots <- struct{}{}
		}
	}

	conn, err := l.Listener.Accept()
	if err != nil {
		l.releaseSlot()
		return nil, err
	}
	l.open.Add(1)
	tracked := &trackedConn{Conn: conn, release: func() {
		l.open.Add(-1)
		l.releaseSlot()
	}}

	// Every CONNECT tunnel is hijacked from a connection this listener returned,
	// and goproxy takes its half-closable copy loop only when BOTH ends support
	// half-close. Wrapping without preserving it here silently downgraded every
	// tunnel — including the ones internal/trace already takes care to preserve
	// on the target side, which made that work dead code in production.
	return netx.PreserveHalfClose(conn, tracked), nil
}

// releaseSlot returns a connection slot to the pool, if limiting is enabled.
func (l *TrackingListener) releaseSlot() {
	if l.slots == nil {
		return
	}
	select {
	case <-l.slots:
	default:
	}
}

// Open reports how many accepted connections are still open.
func (l *TrackingListener) Open() int64 { return l.open.Load() }

// WaitForDrain blocks until every accepted connection has closed or ctx is done.
// It reports whether the connections drained; false means ctx expired first.
func (l *TrackingListener) WaitForDrain(ctx context.Context) bool {
	const pollInterval = 100 * time.Millisecond

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		if l.Open() == 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return l.Open() == 0
		case <-ticker.C:
		}
	}
}

// trackedConn releases its listener slot exactly once, however it is closed.
type trackedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
