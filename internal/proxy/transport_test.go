// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go-egress-proxy/internal/config"
)

func TestTransportPoolSeparatesTargets(t *testing.T) {
	base := &http.Transport{MaxIdleConnsPerHost: 7}
	pool := NewTransportPool(base)

	tests := []struct {
		name string
		a    RewriteResult
		b    RewriteResult
		same bool
	}{
		{
			name: "same target and verification mode share a transport",
			a:    RewriteResult{TargetIP: "10.0.0.1", Matched: true},
			b:    RewriteResult{TargetIP: "10.0.0.1", Matched: true},
			same: true,
		},
		{
			name: "different target IPs are separated",
			a:    RewriteResult{TargetIP: "10.0.0.1", Matched: true},
			b:    RewriteResult{TargetIP: "10.0.0.2", Matched: true},
			same: false,
		},
		{
			name: "insecure flag separates otherwise identical targets",
			a:    RewriteResult{TargetIP: "10.0.0.1", Matched: true},
			b:    RewriteResult{TargetIP: "10.0.0.1", Insecure: true, Matched: true},
			same: false,
		},
		{
			name: "target_host is separated from target_ip",
			a:    RewriteResult{TargetIP: "10.0.0.1", Matched: true},
			b:    RewriteResult{TargetHost: "10.0.0.1", Matched: true},
			same: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pool.For(tt.a) == pool.For(tt.b)
			if got != tt.same {
				t.Errorf("For(%+v) == For(%+v) is %v, want %v", tt.a, tt.b, got, tt.same)
			}
		})
	}
}

func TestTransportPoolUnmatchedUsesBase(t *testing.T) {
	base := &http.Transport{}
	pool := NewTransportPool(base)

	if got := pool.For(RewriteResult{}); got != base {
		t.Error("For() on an unmatched rewrite should return the base transport")
	}
	// A matched rule must not be served by the base transport, whose pool key
	// reflects the original host rather than the substituted target.
	if got := pool.For(RewriteResult{TargetIP: "10.0.0.1", Matched: true}); got == base {
		t.Error("For() on a matched rewrite should return a dedicated transport")
	}
}

func TestTransportPoolClonesBaseSettings(t *testing.T) {
	base := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		ForceAttemptHTTP2:   true,
	}
	pool := NewTransportPool(base)

	tr := pool.For(RewriteResult{TargetIP: "10.0.0.1", Matched: true})
	if tr.MaxIdleConnsPerHost != base.MaxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost = %d, want %d (inherited from base)",
			tr.MaxIdleConnsPerHost, base.MaxIdleConnsPerHost)
	}
	if tr.MaxIdleConns != base.MaxIdleConns {
		t.Errorf("MaxIdleConns = %d, want %d (inherited from base)", tr.MaxIdleConns, base.MaxIdleConns)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 should be inherited from base")
	}
}

func TestTransportPoolForRequestReadsContext(t *testing.T) {
	base := &http.Transport{}
	pool := NewTransportPool(base)

	rw := RewriteResult{TargetIP: "10.0.0.1", Matched: true}
	ctx := context.WithValue(context.Background(), config.RewriteCtxKey, rw)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://api.example.com/v1/x", nil)
	if err != nil {
		t.Fatal(err)
	}

	if got := pool.ForRequest(req); got != pool.For(rw) {
		t.Error("ForRequest() should resolve the transport from the context rewrite result")
	}

	plain, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://other.example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := pool.ForRequest(plain); got != base {
		t.Error("ForRequest() without a context rewrite should return the base transport")
	}
}

func TestTransportPoolResetDropsTransports(t *testing.T) {
	base := &http.Transport{}
	pool := NewTransportPool(base)

	rw := RewriteResult{TargetIP: "10.0.0.1", Matched: true}
	before := pool.For(rw)

	pool.Reset()

	if after := pool.For(rw); after == before {
		t.Error("Reset() should discard existing transports so reloaded targets get fresh pools")
	}
}

func TestTransportPoolConcurrentForIsStable(t *testing.T) {
	base := &http.Transport{}
	pool := NewTransportPool(base)
	rw := RewriteResult{TargetIP: "10.0.0.1", Matched: true}

	const goroutines = 32
	var wg sync.WaitGroup
	results := make([]*http.Transport, goroutines)
	for i := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = pool.For(rw)
		}()
	}
	wg.Wait()

	// The double-checked lock must hand every caller the same instance, otherwise
	// concurrent first-use would silently fragment the pool.
	for i, got := range results {
		if got != results[0] {
			t.Fatalf("goroutine %d got a different transport; For() is not stable under concurrency", i)
		}
	}
}

// TestTransportPoolResetClosesIdleConnections covers the half of Reset() that a
// pointer comparison cannot see. Verified by mutation: replacing the close loop
// with `_ = old` makes this test fail. Without it the whole suite stayed green,
// so idle sockets and their persistConn goroutines could linger for
// IdleConnTimeout (90s) per SIGHUP with nothing noticing.
//
// The assertion observes Close() on the connection directly rather than probing
// socket state, which is subject to timing and platform-specific error values.
func TestTransportPoolResetClosesIdleConnections(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var closes atomic.Int64
	base := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &closeCountingConn{Conn: conn, closes: &closes}, nil
		},
	}

	pool := NewTransportPool(base)
	rw := RewriteResult{TargetIP: "127.0.0.1", Matched: true}
	tr := pool.For(rw)

	// Make a request so the transport holds a pooled idle connection.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck // drain so the conn is pooled
	resp.Body.Close()              //nolint:errcheck // test cleanup

	if got := closes.Load(); got != 0 {
		t.Fatalf("connection closed before Reset() (%d closes); it should be pooled as idle", got)
	}

	pool.Reset()

	// CloseIdleConnections is synchronous for connections already parked as idle.
	if got := closes.Load(); got == 0 {
		t.Error("Reset() did not close the pooled idle connection")
	}

	// And a fresh transport is handed out.
	if pool.For(rw) == tr {
		t.Error("Reset() did not drop the per-target transport")
	}
}

// closeCountingConn records how many times the connection was closed.
type closeCountingConn struct {
	net.Conn
	closes *atomic.Int64
}

func (c *closeCountingConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}
