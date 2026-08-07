// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

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
}

// NewTrackingListener wraps ln so open connections can be counted and waited on.
func NewTrackingListener(ln net.Listener) *TrackingListener {
	return &TrackingListener{Listener: ln}
}

// Accept returns a connection that decrements the open count when closed.
func (l *TrackingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.open.Add(1)
	tracked := &trackedConn{Conn: conn, release: func() { l.open.Add(-1) }}

	// Every CONNECT tunnel is hijacked from a connection this listener returned,
	// and goproxy takes its half-closable copy loop only when BOTH ends support
	// half-close. Wrapping without preserving it here silently downgraded every
	// tunnel — including the ones internal/trace already takes care to preserve
	// on the target side, which made that work dead code in production.
	return netx.PreserveHalfClose(conn, tracked), nil
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
