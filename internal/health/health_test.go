// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package health

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func statusOf(t *testing.T, h http.HandlerFunc) int {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec.Code
}

// TestReadinessTracksLifecycle pins the behavior a load balancer depends on:
// not ready before the proxy listener is bound, ready while serving, and not
// ready again the moment shutdown begins — so traffic stops arriving at a pod
// that is draining.
func TestReadinessTracksLifecycle(t *testing.T) {
	t.Cleanup(SetNotReady)

	SetNotReady()
	if got := statusOf(t, ReadyHandler); got != http.StatusServiceUnavailable {
		t.Errorf("before bind: /readyz = %d, want 503", got)
	}

	SetReady()
	if got := statusOf(t, ReadyHandler); got != http.StatusOK {
		t.Errorf("while serving: /readyz = %d, want 200", got)
	}
	if !IsReady() {
		t.Error("IsReady() = false while serving")
	}

	SetNotReady()
	if got := statusOf(t, ReadyHandler); got != http.StatusServiceUnavailable {
		t.Errorf("while draining: /readyz = %d, want 503", got)
	}
}

// TestLivenessIsIndependentOfReadiness guards a deliberate distinction:
// reporting unhealthy during a drain would have Kubernetes kill the pod
// mid-drain, which is the opposite of graceful.
func TestLivenessIsIndependentOfReadiness(t *testing.T) {
	t.Cleanup(SetNotReady)

	SetNotReady()
	if got := statusOf(t, HealthHandler); got != http.StatusOK {
		t.Errorf("/healthz = %d while not ready, want 200", got)
	}
}
