// Package health provides HTTP handlers for liveness and readiness probes.
package health

import (
	"net/http"
	"sync/atomic"
)

// ready reports whether the proxy listener is accepting traffic.
//
// Readiness starts false and is set true only once the proxy port is actually
// bound, then false again as the first step of shutdown. A hardcoded 200 made
// the endpoint useless for its one job: it reported ready before the proxy
// listener existed (the metrics mux, which serves this handler, starts first),
// and it kept reporting ready while the listener was draining, so a load
// balancer went on routing at a pod that was going away.
var ready atomic.Bool

// SetReady marks the proxy as accepting traffic. Call once the proxy listener is bound.
func SetReady() { ready.Store(true) }

// SetNotReady marks the proxy as no longer accepting traffic. Call as the first
// step of shutdown, before draining, so load balancers stop sending new
// connections while in-flight ones finish.
func SetNotReady() { ready.Store(false) }

// IsReady reports the current readiness state.
func IsReady() bool { return ready.Load() }

// HealthHandler responds to liveness probe requests.
//
// Liveness answers "is the process alive", which is true for as long as it can
// serve this request. It deliberately stays independent of readiness: reporting
// unhealthy during a drain would have Kubernetes kill the pod mid-drain.
func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// ReadyHandler responds to readiness probe requests, reporting 503 until the
// proxy listener is bound and again once shutdown begins.
func ReadyHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	if !ready.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready"))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}
