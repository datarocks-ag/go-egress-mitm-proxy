// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package trace

import (
	"context"
	"net"
	"time"
)

// PassthroughDialer returns a CONNECT tunnel dialer that records the resolved
// upstream IP and dial timing onto rec, counts bytes in each direction, and
// emits the aggregated record when the tunnel connection closes.
//
// It is wired via goproxy's per-request ctx.Dialer so passthrough (non-MITM)
// hosts can still be traced at the TCP layer, where headers and bodies are
// inherently invisible.
func PassthroughDialer(rec *Record) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		start := time.Now()
		conn, err := (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext(ctx, network, addr)
		if err != nil {
			rec.SetError(err.Error())
			rec.Emit()
			return nil, err
		}
		rec.SetTCP(remoteIP(conn), time.Since(start), "", "")
		return &countingConn{Conn: conn, rec: rec}, nil
	}
}

// remoteIP extracts the IP (without port) from a connection's remote address.
func remoteIP(conn net.Conn) string {
	addr := conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// countingConn tallies bytes transferred over a passthrough tunnel and emits the
// trace record on Close. Writes to the upstream conn are client->target (up);
// reads are target->client (down). Counters are goroutine-safe because goproxy
// copies the two tunnel directions concurrently.
type countingConn struct {
	net.Conn
	rec *Record
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.rec.addDown(int64(n))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.rec.addUp(int64(n))
	}
	return n, err
}

func (c *countingConn) Close() error {
	err := c.Conn.Close()
	c.rec.Emit()
	return err
}
