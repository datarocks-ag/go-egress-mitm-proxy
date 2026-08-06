// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

// Package netx holds small net.Conn helpers shared by the proxy and trace
// packages.
package netx

import "net"

// HalfCloser is the half-close half of goproxy's halfClosable interface
// (https.go). *net.TCPConn satisfies it.
type HalfCloser interface {
	CloseRead() error
	CloseWrite() error
}

// PreserveHalfClose returns wrapper, extended to satisfy [HalfCloser] when base
// does.
//
// Any decorator that embeds the net.Conn *interface* silently drops
// CloseRead/CloseWrite from its method set. goproxy type-asserts for them to
// choose its tunnel copy loop, and takes that path only when BOTH the client and
// target connections satisfy it. Failing the assertion on either side drops the
// tunnel onto a fallback loop where the first direction to finish closes the
// peer outright -- truncating any protocol that shuts its write side and waits
// -- and loses io.Copy's splice fast path.
//
// The wrapper's own Read/Write/Close still run; only half-close is delegated to
// base. Two types exist so the assertion stays honest, since a connection that
// cannot half-close must not advertise that it can.
//
// This lives in a shared package because the same decoration is needed at both
// ends of a tunnel, in two packages, and having it written twice is how the two
// ends came to disagree.
func PreserveHalfClose(base, wrapper net.Conn) net.Conn {
	hc, ok := base.(HalfCloser)
	if !ok {
		return wrapper
	}
	return &halfClosableConn{Conn: wrapper, hc: hc}
}

type halfClosableConn struct {
	net.Conn
	hc HalfCloser
}

func (c *halfClosableConn) CloseRead() error  { return c.hc.CloseRead() }
func (c *halfClosableConn) CloseWrite() error { return c.hc.CloseWrite() }
