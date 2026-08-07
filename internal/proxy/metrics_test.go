// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/elazarl/goproxy"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"go-egress-proxy/internal/config"
	"go-egress-proxy/internal/metrics"
)

// trafficCount reads the current value of proxy_traffic_total for one label pair.
func trafficCount(t *testing.T, domain, action string) float64 {
	t.Helper()
	return testutil.ToFloat64(metrics.TrafficTotal.WithLabelValues(domain, action))
}

// TestHandleRequestRecordsAction pins the policy engine's primary output.
//
// The action string reaches the outside world only through proxy_traffic_total,
// and nothing asserted it: REWRITTEN, WHITE-LISTED, BLACK-LISTED and
// ALLOWED-BY-DEFAULT were mutually indistinguishable to the suite. That is what
// let an inverted blacklist/whitelist precedence pass everything.
func TestHandleRequestRecordsAction(t *testing.T) {
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "ALLOW"
	// Deliberately overlapping: "both.example.com" is in each list. Disjoint
	// fixtures are why an inverted precedence used to pass the whole suite, and a
	// metric test with disjoint lists reproduces that blind spot.
	cfg.ACL.Whitelist = []string{"allowed.example.com", "both.example.com"}
	cfg.ACL.Blacklist = []string{"denied.example.com", "both.example.com"}
	cfg.Rewrites = []config.RewriteRule{{Domain: "rewritten.example.com", TargetIP: "10.0.0.1"}}

	rc := runtimeFor(t, cfg)

	tests := []struct {
		host   string
		domain string
		action string
	}{
		{"rewritten.example.com", "rewritten.example.com", "REWRITTEN"},
		{"allowed.example.com", "example.com", "WHITE-LISTED"},
		{"denied.example.com", "example.com", "BLACK-LISTED"},
		{"both.example.com", "example.com", "BLACK-LISTED"}, // in both lists: blacklist wins
		{"unknown.example.com", "_other", "ALLOWED-BY-DEFAULT"},
	}

	for _, tt := range tests {
		t.Run(tt.action+"/"+tt.host, func(t *testing.T) {
			before := trafficCount(t, tt.domain, tt.action)

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+tt.host+"/x", nil)
			if err != nil {
				t.Fatal(err)
			}
			_, resp := HandleRequest(req, nil, rc)
			if resp != nil {
				resp.Body.Close() //nolint:errcheck // test cleanup
			}

			if delta := trafficCount(t, tt.domain, tt.action) - before; delta != 1 {
				t.Errorf("proxy_traffic_total{domain=%q,action=%q} moved by %v, want 1",
					tt.domain, tt.action, delta)
			}
		})
	}
}

// TestRecordDialErrorLabels pins the timeout-vs-connection distinction, which is
// RecordDialError's only behavior. The previous test called it and asserted
// nothing beyond "does not panic", so collapsing the two labels passed.
func TestRecordDialErrorLabels(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		label string
	}{
		{"net timeout", &timeoutError{}, "timeout"},
		{"deadline exceeded", context.DeadlineExceeded, "timeout"},
		{"connection refused", errors.New("connection refused"), "connection"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := testutil.ToFloat64(metrics.UpstreamErrors.WithLabelValues(tt.label))
			RecordDialError(tt.err)
			if delta := testutil.ToFloat64(metrics.UpstreamErrors.WithLabelValues(tt.label)) - before; delta != 1 {
				t.Errorf("proxy_upstream_errors_total{type=%q} moved by %v, want 1", tt.label, delta)
			}
		})
	}
}

// TestRequestTimingIsCarriedOnlyByForwardedRequests pins the split introduced
// when duration observation moved out of the handler.
//
// A request the handler short-circuits records its duration inline, because the
// handler's elapsed time *is* the whole request. A forwarded one must instead
// carry its timing to the round-trip wrapper, which is where DNS, dial, TLS
// handshake and upstream think-time happen. Asserting the histogram count would
// need a dto import; asserting the mechanism needs none, and it is the part that
// can silently break.
func TestRequestTimingIsCarriedOnlyByForwardedRequests(t *testing.T) {
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "ALLOW"
	cfg.ACL.Blacklist = []string{"denied.example.com"}
	rc := runtimeFor(t, cfg)

	t.Run("forwarded request carries timing", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://fwd.example.com/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		forwarded, resp := HandleRequest(req, nil, rc)
		if resp != nil {
			resp.Body.Close() //nolint:errcheck // test cleanup
			t.Fatal("request was blocked; this case needs a forwarded one")
		}

		timing, ok := forwarded.Context().Value(timingCtxKey).(*requestTiming)
		if !ok {
			t.Fatal("forwarded request carries no timing; its duration would never be observed")
		}
		if timing.action != "ALLOWED-BY-DEFAULT" {
			t.Errorf("timing action = %q, want ALLOWED-BY-DEFAULT", timing.action)
		}
	})

	t.Run("blocked request does not", func(t *testing.T) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://denied.example.com/x", nil)
		if err != nil {
			t.Fatal(err)
		}
		blocked, resp := HandleRequest(req, nil, rc)
		if resp == nil {
			t.Fatal("expected the request to be blocked")
		}
		resp.Body.Close() //nolint:errcheck // test cleanup

		if _, ok := blocked.Context().Value(timingCtxKey).(*requestTiming); ok {
			t.Error("blocked request carries timing; its duration would be recorded twice")
		}
	})
}

// TestObserveRequestDurationIgnoresUntimedRequests: a request that never went
// through HandleRequest must not record anything.
//
// "Does not record" is asserted by label-set count rather than observation
// count: a histogram's WithLabelValues returns an Observer, which testutil
// cannot read, and reading the sample count would need a client_model import.
// Creating a series is the observable side effect here.
func TestObserveRequestDurationIgnoresUntimedRequests(t *testing.T) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://x.example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}

	before := testutil.CollectAndCount(metrics.RequestDuration)
	ObserveRequestDuration(req) // must not panic or record
	if after := testutil.CollectAndCount(metrics.RequestDuration); after != before {
		t.Errorf("label sets went from %d to %d; an untimed request created a series", before, after)
	}
}

// TestRewriteMetricsAreLabelledPerRule pins per-target attribution for rewrites.
//
// NormalizeDomainForMetrics gives a dedicated label only to hosts in
// rewriteExact, and RuntimeConfig.Update excludes any rule whose domain contains
// "*" or that carries a path_pattern, and files a "~" regex rule under its
// literal pattern string — a key no hostname can equal. So the shipped example's
// "*.internal.example.com" and "~^api[0-9]+\.example\.com$" rewrites all emitted
// as domain="_other", indistinguishable from each other and from unmatched
// traffic, despite a rewrite being the thing most worth attributing per target.
func TestRewriteMetricsAreLabelledPerRule(t *testing.T) {
	rewrites := []config.CompiledRewriteRule{
		{
			Pattern:  regexp.MustCompile(`^.+\.internal\.example\.com$`),
			TargetIP: "10.20.30.50",
			Original: "*.internal.example.com",
		},
		{
			Pattern:  regexp.MustCompile(`(?i)^(?:^api[0-9]+\.example\.com$)$`),
			TargetIP: "10.20.30.60",
			Original: `~^api[0-9]+\.example\.com$`,
		},
	}

	rc := &config.RuntimeConfig{}
	cfg := config.Config{}
	cfg.Proxy.DefaultPolicy = "BLOCK"
	_ = rc.Update(cfg, config.CompiledACL{}, rewrites, nil, nil, nil)

	for _, tc := range []struct{ host, wantLabel string }{
		{"a.internal.example.com", "*.internal.example.com"},
		{"deep.b.internal.example.com", "*.internal.example.com"},
		{"api7.example.com", `~^api[0-9]+\.example\.com$`},
	} {
		before := testutil.ToFloat64(metrics.TrafficTotal.WithLabelValues(tc.wantLabel, "REWRITTEN"))
		other := testutil.ToFloat64(metrics.TrafficTotal.WithLabelValues("_other", "REWRITTEN"))

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+tc.host+"/x", nil)
		_, resp := HandleRequest(req, &goproxy.ProxyCtx{Req: req}, rc) //nolint:bodyclose // nil on the forwarded path
		if resp != nil {
			t.Fatalf("%s was not forwarded: %s", tc.host, resp.Status)
		}

		if delta := testutil.ToFloat64(metrics.TrafficTotal.WithLabelValues(tc.wantLabel, "REWRITTEN")) - before; delta != 1 {
			t.Errorf("%s: series domain=%q moved by %v, want 1", tc.host, tc.wantLabel, delta)
		}
		if delta := testutil.ToFloat64(metrics.TrafficTotal.WithLabelValues("_other", "REWRITTEN")) - other; delta != 0 {
			t.Errorf("%s: collapsed into domain=\"_other\" instead of its own rule label", tc.host)
		}
	}
}
