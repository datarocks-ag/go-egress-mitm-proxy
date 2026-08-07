// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package main

import (
	"context"
	"log/slog"
	"time"
)

// shutdowner is the http.Server behaviour the drain sequence needs.
type shutdowner interface {
	Shutdown(ctx context.Context) error
}

// drainableListener is the TrackingListener behaviour the drain sequence needs:
// how many client connections are still open, and a bounded wait for them.
type drainableListener interface {
	Open() int64
	WaitForDrain(ctx context.Context) bool
}

// drainDeps are the collaborators of the shutdown sequence.
//
// The sequence used to live in an anonymous goroutine inside main(), where no
// test could construct it -- the same shape that hid a downgraded CONNECT tunnel
// until NewConnectHandler was extracted, and an untested reload until reload()
// was. It encodes the three ordering decisions this project documents most
// heavily, and each of them could be broken while the suite stayed green:
// moving SetNotReady below Shutdown reinstates the ECONNREFUSED burst
// PROXY_PRESTOP_GRACE exists to prevent; dropping the WaitForDrain call defeats
// the entire reason TrackingListener exists; and neither is observable from
// outside.
type drainDeps struct {
	proxyServer   shutdowner
	metricsServer shutdowner
	listener      drainableListener

	// grace is how long to keep serving after readiness starts failing.
	grace time.Duration
	// timeout bounds Shutdown and the tunnel drain together.
	timeout time.Duration

	setNotReady func()
	closeLogs   func()

	// sleep is time.Sleep in production; tests substitute it so asserting the
	// ordering does not cost the grace period in wall-clock time.
	sleep func(time.Duration)
}

// drain runs the graceful-shutdown sequence: fail readiness, keep serving
// briefly, stop accepting, drain, then release resources.
//
// Failing readiness and closing the listener in the same instant achieves
// nothing. A load balancer only stops routing once its next probe fails, and
// Shutdown closes the listener immediately, so clients get ECONNREFUSED for a
// probe interval or two while only already-accepted connections benefit from the
// drain. Serving through one full probe interval is what lets traffic move away.
func drain(deps drainDeps) {
	deps.setNotReady()
	if deps.grace > 0 {
		slog.Info("Readiness failed; serving briefly so traffic can move away",
			"grace", deps.grace)
		deps.sleep(deps.grace)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), deps.timeout)
	defer cancel()

	if err := deps.proxyServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("Proxy server shutdown error", "err", err)
	}

	// Shutdown has stopped accepting and drained non-hijacked connections; wait
	// out the tunnels it cannot see, within the same budget. goproxy hijacks the
	// client connection for every CONNECT and http.Server stops tracking a
	// connection once hijacked, so Shutdown returns believing it is done while
	// every HTTPS tunnel is still live.
	if open := deps.listener.Open(); open > 0 {
		slog.Info("Waiting for tunnels to close", "open_connections", open)
		if !deps.listener.WaitForDrain(shutdownCtx) {
			slog.Warn("Drain deadline reached with connections still open",
				"open_connections", deps.listener.Open(),
				"timeout", deps.timeout)
		}
	}

	// Its own context: after a timed-out drain shutdownCtx is already expired, so
	// reusing it made every timed-out drain also log a spurious metrics shutdown
	// error.
	metricsCtx, cancelMetrics := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelMetrics()
	if err := deps.metricsServer.Shutdown(metricsCtx); err != nil {
		slog.Error("Metrics server shutdown error", "err", err)
	}

	deps.closeLogs()
}
