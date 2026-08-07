// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// recorder captures the order in which the drain sequence touches its
// collaborators. Ordering is the property under test, so every step appends.
type recorder struct {
	mu    sync.Mutex
	steps []string
}

func (r *recorder) add(step string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, step)
}

func (r *recorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.steps...)
}

// indexOf returns the position of step, or -1.
func indexOf(steps []string, step string) int {
	for i, s := range steps {
		if s == step {
			return i
		}
	}
	return -1
}

type fakeServer struct {
	name string
	rec  *recorder
	err  error
}

func (f *fakeServer) Shutdown(context.Context) error {
	f.rec.add("shutdown:" + f.name)
	return f.err
}

type fakeListener struct {
	rec      *recorder
	open     int64
	drained  bool
	waitSeen bool
}

func (f *fakeListener) Open() int64 { return f.open }

func (f *fakeListener) WaitForDrain(context.Context) bool {
	f.waitSeen = true
	f.rec.add("waitForDrain")
	return f.drained
}

func newDeps(rec *recorder, ln *fakeListener) drainDeps {
	return drainDeps{
		proxyServer:   &fakeServer{name: "proxy", rec: rec},
		metricsServer: &fakeServer{name: "metrics", rec: rec},
		listener:      ln,
		grace:         10 * time.Second,
		timeout:       30 * time.Second,
		setNotReady:   func() { rec.add("setNotReady") },
		closeLogs:     func() { rec.add("closeLogs") },
		// Substituted so asserting the ordering does not cost the grace period.
		sleep: func(d time.Duration) { rec.add("sleep") },
	}
}

// TestDrainFailsReadinessBeforeClosingTheListener is the ordering the pre-stop
// grace exists for.
//
// Failing readiness and closing the listener in the same instant produces
// ECONNREFUSED until the load balancer's next probe, so only already-accepted
// connections benefit from the drain. Moving SetNotReady below Shutdown
// reinstates exactly that, and nothing outside this test would notice.
func TestDrainFailsReadinessBeforeClosingTheListener(t *testing.T) {
	rec := &recorder{}
	drain(newDeps(rec, &fakeListener{rec: rec, drained: true}))

	steps := rec.snapshot()
	notReady, shutdown := indexOf(steps, "setNotReady"), indexOf(steps, "shutdown:proxy")
	if notReady == -1 || shutdown == -1 {
		t.Fatalf("missing steps in %v", steps)
	}
	if notReady > shutdown {
		t.Errorf("readiness failed after the listener closed (%v); clients get ECONNREFUSED "+
			"until the next probe", steps)
	}
	if sleep := indexOf(steps, "sleep"); sleep == -1 || sleep < notReady || sleep > shutdown {
		t.Errorf("the grace period must fall between failing readiness and Shutdown, got %v", steps)
	}
}

// TestDrainWaitsForHijackedTunnels pins the reason TrackingListener exists.
// http.Server stops tracking a connection once goproxy hijacks it for a CONNECT,
// so Shutdown returns believing it drained everything while every HTTPS tunnel
// is still live.
func TestDrainWaitsForHijackedTunnels(t *testing.T) {
	rec := &recorder{}
	ln := &fakeListener{rec: rec, open: 3, drained: true}
	drain(newDeps(rec, ln))

	if !ln.waitSeen {
		t.Fatal("drain did not wait for open tunnels; hijacked CONNECT connections are killed mid-transfer")
	}
	steps := rec.snapshot()
	if shutdown, wait := indexOf(steps, "shutdown:proxy"), indexOf(steps, "waitForDrain"); wait < shutdown {
		t.Errorf("waited for tunnels before Shutdown stopped accepting, got %v", steps)
	}
}

// TestDrainSkipsTheWaitWhenNothingIsOpen keeps the common path fast: a proxy with
// no live tunnels should not sit through a poll interval on every rollout.
func TestDrainSkipsTheWaitWhenNothingIsOpen(t *testing.T) {
	rec := &recorder{}
	ln := &fakeListener{rec: rec, open: 0, drained: true}
	drain(newDeps(rec, ln))

	if ln.waitSeen {
		t.Error("drain waited although no connections were open")
	}
}

// TestDrainReleasesResourcesAfterTheDrain pins the tail: the metrics server and
// the log files are closed last, and closing them is not skipped when the drain
// times out with connections still open.
func TestDrainReleasesResourcesAfterTheDrain(t *testing.T) {
	rec := &recorder{}
	// drained=false is the timed-out drain.
	ln := &fakeListener{rec: rec, open: 2, drained: false}
	drain(newDeps(rec, ln))

	steps := rec.snapshot()
	for _, step := range []string{"shutdown:metrics", "closeLogs"} {
		if indexOf(steps, step) == -1 {
			t.Errorf("%q did not run after a timed-out drain, leaking the resource (%v)", step, steps)
		}
	}
	if wait, logs := indexOf(steps, "waitForDrain"), indexOf(steps, "closeLogs"); logs < wait {
		t.Errorf("log files closed before the drain finished; in-flight audit writes would be "+
			"lost, got %v", steps)
	}
}

// TestDrainContinuesWhenProxyShutdownErrors: a Shutdown error must not abandon
// the tunnel drain or leave the log files open.
func TestDrainContinuesWhenProxyShutdownErrors(t *testing.T) {
	rec := &recorder{}
	deps := newDeps(rec, &fakeListener{rec: rec, open: 1, drained: true})
	deps.proxyServer = &fakeServer{name: "proxy", rec: rec, err: errors.New("boom")}

	drain(deps)

	steps := rec.snapshot()
	if indexOf(steps, "closeLogs") == -1 {
		t.Errorf("a Shutdown error skipped the rest of the sequence, got %v", steps)
	}
}

// TestDrainSkipsTheGraceWhenDisabled covers PROXY_PRESTOP_GRACE=0, which is what
// a deployment with its own preStop hook sets.
func TestDrainSkipsTheGraceWhenDisabled(t *testing.T) {
	rec := &recorder{}
	deps := newDeps(rec, &fakeListener{rec: rec, drained: true})
	deps.grace = 0

	drain(deps)

	if indexOf(rec.snapshot(), "sleep") != -1 {
		t.Error("slept although the pre-stop grace was disabled")
	}
}
