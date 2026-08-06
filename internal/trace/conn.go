// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package trace

import (
	"context"
	"net"
)

// DialFunc is the dial signature used by goproxy's ctx.Dialer and by
// http.Transport.DialContext.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// PassthroughDialer wraps base with byte counting and record emission for a
// CONNECT tunnel that is not MITM'd, where headers and bodies are inherently
// invisible and only the TCP layer can be observed.
//
// It decorates rather than replaces. goproxy prefers ctx.Dialer over
// Transport.DialContext, so a dialer built from scratch here would quietly opt
// the connection out of everything the production dialer does: rewrite target
// substitution, address validation, and upstream error metrics. Enabling
// tracing on a host would then change how that host is routed — the opposite of
// what an observability switch should do.
//
// base is expected to be the production dialer. The record is attached to the
// context so base records the connected IP, dial timing and dial errors through
// the normal path; this wrapper adds only the byte counters and the emit-on-close.
func PassthroughDialer(rec *Record, base DialFunc) DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := base(context.WithValue(ctx, CtxKey, rec), network, addr)
		if err != nil {
			// Error recording belongs to base, which sees the record on the context
			// and has the specific failure in hand (MakeDialer also classifies it for
			// the upstream error metrics). Setting it again here would overwrite that
			// with a less specific message. Emitting is this wrapper's job, because a
			// failed dial produces no conn and therefore no Close.
			rec.Emit()
			return nil, err
		}
		return wrapConn(conn, rec), nil
	}
}

// countingConn tallies bytes transferred over a passthrough tunnel and emits the
// trace record on Close. Writes to the upstream conn are client->target (up);
// reads are target->client (down). Counters are goroutine-safe because goproxy
// copies the two tunnel directions concurrently.
type countingConn struct {
	net.Conn
	rec *Record
}

// halfClosableConn preserves CloseRead/CloseWrite for connections that support
// them. Embedding net.Conn alone would hide those methods, and goproxy type-
// asserts for them (halfClosable, https.go:180) to pick its tunnel copy loop.
// Failing that assertion drops the tunnel onto a path where the first finished
// direction fully closes the peer, truncating any protocol that half-closes its
// write side, and it also loses io.Copy's splice fast path.
//
// The two types exist so the assertion result stays honest: a conn that cannot
// half-close must not advertise that it can.
type halfClosableConn struct {
	*countingConn
	hc halfCloser
}

// halfCloser is the half-close half of goproxy's halfClosable interface.
type halfCloser interface {
	CloseRead() error
	CloseWrite() error
}

func (c *halfClosableConn) CloseRead() error  { return c.hc.CloseRead() }
func (c *halfClosableConn) CloseWrite() error { return c.hc.CloseWrite() }

// wrapConn returns a counting wrapper that advertises half-close support only
// when the underlying connection actually has it.
func wrapConn(conn net.Conn, rec *Record) net.Conn {
	cc := &countingConn{Conn: conn, rec: rec}
	if hc, ok := conn.(halfCloser); ok {
		return &halfClosableConn{countingConn: cc, hc: hc}
	}
	return cc
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
