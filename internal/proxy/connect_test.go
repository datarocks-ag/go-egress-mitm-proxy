// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"go-egress-proxy/internal/config"
	"go-egress-proxy/internal/metrics"
	"go-egress-proxy/internal/trace"
)

var (
	testMitm        = &goproxy.ConnectAction{Action: goproxy.ConnectMitm}
	testPassthrough = &goproxy.ConnectAction{Action: goproxy.ConnectAccept}
)

// connectCtx builds the minimal ProxyCtx the handler reads.
func connectCtx(t *testing.T, host string) *goproxy.ProxyCtx {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodConnect, "https://"+host, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "10.1.2.3:54321"
	return &goproxy.ProxyCtx{Req: req}
}

// traceRuntimeFor returns a RuntimeConfig with tracing enabled for hostPattern.
func traceRuntimeFor(t *testing.T, cfg config.Config, hostPattern string, buf *bytes.Buffer) *config.RuntimeConfig {
	t.Helper()

	rc := runtimeFor(t, cfg)
	ct, err := config.CompileTrace(config.TraceConfig{
		Enabled: true,
		Rules:   []config.TraceRule{{Host: hostPattern}},
	})
	if err != nil {
		t.Fatalf("CompileTrace: %v", err)
	}
	rc.SetTrace(ct, slog.New(slog.NewJSONHandler(buf, nil)), nil) //nolint:errcheck // returns the rotated file, nil here
	return rc
}

// TestConnectHandlerDispatch pins the three outcomes together, which only
// DecideConnect covered before: the handler around it was an anonymous closure
// in main() and unreachable from any test.
func TestConnectHandlerDispatch(t *testing.T) {
	cfg := config.Config{}
	cfg.ACL.Blacklist = []string{"leaked.vault.internal", "denied.example.com"}
	cfg.ACL.Passthrough = []string{"*.vault.internal"}

	rc := runtimeFor(t, cfg)
	handler := NewConnectHandler(rc, testMitm, testPassthrough)

	tests := []struct {
		name string
		host string
		want *goproxy.ConnectAction
	}{
		{"passthrough and blacklisted is refused", "leaked.vault.internal:443", goproxy.RejectConnect},
		{"passthrough only", "ok.vault.internal:443", testPassthrough},
		{"blacklisted but inspectable is intercepted", "denied.example.com:443", testMitm},
		{"unmatched", "api.example.com:443", testMitm},
		{"port is stripped and host normalized", "OK.Vault.Internal.:443", testPassthrough},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, gotHost := handler(tt.host, connectCtx(t, tt.host))
			if action != tt.want {
				t.Errorf("action = %v, want %v", action, tt.want)
			}
			// The host is passed through untouched; normalization is for matching only.
			if gotHost != tt.host {
				t.Errorf("host = %q, want %q", gotHost, tt.host)
			}
		})
	}
}

// TestConnectHandlerRejectWritesResponse pins the 403. goproxy closes the socket
// silently when ctx.Resp is unset, which turned a documented 403 into
// "unexpected EOF" for every blacklisted HTTPS host.
func TestConnectHandlerRejectWritesResponse(t *testing.T) {
	cfg := config.Config{}
	cfg.ACL.Blacklist = []string{"leaked.vault.internal"}
	cfg.ACL.Passthrough = []string{"*.vault.internal"}

	rc := runtimeFor(t, cfg)
	ctx := connectCtx(t, "leaked.vault.internal:443")

	action, _ := NewConnectHandler(rc, testMitm, testPassthrough)("leaked.vault.internal:443", ctx)
	if action != goproxy.RejectConnect {
		t.Fatalf("action = %v, want RejectConnect", action)
	}
	if ctx.Resp == nil {
		t.Fatal("ctx.Resp is nil; goproxy would close the connection with no response")
	}
	defer ctx.Resp.Body.Close() //nolint:errcheck // test cleanup

	if ctx.Resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", ctx.Resp.StatusCode)
	}
	// NewResponse leaves Proto zeroed, which serializes as "HTTP/0.0" on a raw
	// connection.
	if ctx.Resp.ProtoMajor != 1 {
		t.Errorf("ProtoMajor = %d, want 1; the status line would be unusable", ctx.Resp.ProtoMajor)
	}
}

// TestConnectHandlerRejectIsAudited pins the audit trail. A rejected tunnel
// never reaches HandleRequest, so without this call the blocked-request log
// silently omits every blacklisted HTTPS host.
func TestConnectHandlerRejectIsAudited(t *testing.T) {
	cfg := config.Config{}
	cfg.ACL.Blacklist = []string{"leaked.vault.internal"}
	cfg.ACL.Passthrough = []string{"*.vault.internal"}

	var blocked bytes.Buffer
	acl, err := config.CompileACL(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rc := &config.RuntimeConfig{}
	_ = rc.Update(cfg, acl, nil, nil, slog.New(slog.NewJSONHandler(&blocked, nil)), nil)

	NewConnectHandler(rc, testMitm, testPassthrough)("leaked.vault.internal:443",
		connectCtx(t, "leaked.vault.internal:443"))

	if blocked.Len() == 0 {
		t.Fatal("nothing written to the blocked-request log for a rejected CONNECT")
	}
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(blocked.Bytes()), &rec); err != nil {
		t.Fatalf("blocked log entry is not JSON: %v\n%s", err, blocked.String())
	}
	if rec["action"] != "BLACK-LISTED" {
		t.Errorf("action = %v, want BLACK-LISTED", rec["action"])
	}
	if rec["host"] != "leaked.vault.internal" {
		t.Errorf("host = %v, want the normalized hostname", rec["host"])
	}
}

// TestConnectHandlerWiresPassthroughTrace covers the wiring that had no
// reachable test: the record and the decorated dialer are what produce a
// passthrough trace at all.
func TestConnectHandlerWiresPassthroughTrace(t *testing.T) {
	cfg := config.Config{}
	cfg.ACL.Passthrough = []string{"*.vault.internal"}

	var traced bytes.Buffer
	rc := traceRuntimeFor(t, cfg, "*.vault.internal", &traced)

	ctx := connectCtx(t, "ok.vault.internal:443")
	action, _ := NewConnectHandler(rc, testMitm, testPassthrough)("ok.vault.internal:443", ctx)

	if action != testPassthrough {
		t.Fatalf("action = %v, want passthrough", action)
	}
	rec, ok := ctx.UserData.(*trace.Record)
	if !ok {
		t.Fatal("no trace Record on ctx.UserData; the response layer has nothing to attach to")
	}
	if ctx.Dialer == nil {
		t.Fatal("ctx.Dialer not set; the tunnel would bypass the tracing dialer entirely")
	}

	// The record must actually emit.
	rec.Emit()
	if traced.Len() == 0 {
		t.Fatal("record produced no output")
	}
	var out map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(traced.Bytes()), &out); err != nil {
		t.Fatalf("trace record is not JSON: %v", err)
	}
	if out["mode"] != "passthrough" {
		t.Errorf("mode = %v, want passthrough", out["mode"])
	}
}

// TestConnectHandlerSkipsTraceWhenNoRuleMatches guards the negative case: a
// passthrough host with no matching rule must not get a dialer, or every tunnel
// would pay for tracing nobody asked for.
func TestConnectHandlerSkipsTraceWhenNoRuleMatches(t *testing.T) {
	cfg := config.Config{}
	cfg.ACL.Passthrough = []string{"*.vault.internal"}

	var traced bytes.Buffer
	rc := traceRuntimeFor(t, cfg, "other.example.com", &traced)

	ctx := connectCtx(t, "ok.vault.internal:443")
	NewConnectHandler(rc, testMitm, testPassthrough)("ok.vault.internal:443", ctx)

	if ctx.UserData != nil {
		t.Error("trace Record attached for a host no rule matches")
	}
	if ctx.Dialer != nil {
		t.Error("tracing dialer wired for a host no rule matches")
	}
}

// TestConnectHandlerRecordsBlacklistedMITM pins that a denial is observable
// without the client cooperating with interception.
//
// A blacklisted host that is not passthrough is intercepted so HandleRequest can
// answer 403. But a client that refuses our certificate — a pinning SDK, a JVM
// truststore — never reaches HandleRequest, and goproxy logs that failure at
// debug. Recording at CONNECT time means the attempt appears regardless. The
// label is distinct so it does not double-count the BLACK-LISTED that
// HandleRequest records when the handshake does succeed.
func TestConnectHandlerRecordsBlacklistedMITM(t *testing.T) {
	cfg := config.Config{}
	cfg.ACL.Blacklist = []string{"denied.example.com"}

	rc := runtimeFor(t, cfg)

	const domain = "example.com"
	before := testutil.ToFloat64(metrics.TrafficTotal.WithLabelValues(domain, "BLACK-LISTED-CONNECT"))

	action, _ := NewConnectHandler(rc, testMitm, testPassthrough)("denied.example.com:443",
		connectCtx(t, "denied.example.com:443"))

	if action != testMitm {
		t.Fatalf("action = %v, want MITM; the host is not passthrough", action)
	}
	if delta := testutil.ToFloat64(metrics.TrafficTotal.WithLabelValues(domain, "BLACK-LISTED-CONNECT")) - before; delta != 1 {
		t.Errorf("BLACK-LISTED-CONNECT moved by %v, want 1; a denial the client never completes is unrecorded", delta)
	}

	// A host that is not blacklisted must not be recorded.
	clean := testutil.ToFloat64(metrics.TrafficTotal.WithLabelValues("_other", "BLACK-LISTED-CONNECT"))
	NewConnectHandler(rc, testMitm, testPassthrough)("fine.example.org:443", connectCtx(t, "fine.example.org:443"))
	if got := testutil.ToFloat64(metrics.TrafficTotal.WithLabelValues("_other", "BLACK-LISTED-CONNECT")); got != clean {
		t.Error("a non-blacklisted host was recorded as a CONNECT denial")
	}
}

// TestConnectActionLabelsAreDistinct pins which metric label each CONNECT
// outcome uses.
//
// The two blacklist paths are easy to describe backwards, and this project's
// documentation did exactly that: a refused passthrough tunnel and an
// intercepted blacklisted host are different events with different labels, and
// the docs had them swapped. Prose cannot be trusted to keep them straight, so
// the mapping is asserted here — both that the right label moves and that the
// other one does not.
func TestConnectActionLabelsAreDistinct(t *testing.T) {
	const (
		blacklistedOnly = "denied.example.com"
		bothLists       = "leaked.vault.internal"

		// TrafficTotal is labeled by base domain for ACL-matched hosts, not by the
		// full hostname; these are spelled out rather than recomputed so the test
		// also pins that labeling.
		blacklistedOnlyLabel = "example.com"
		bothListsLabel       = "vault.internal"
	)

	cfg := config.Config{}
	cfg.ACL.Blacklist = []string{blacklistedOnly, bothLists}
	cfg.ACL.Passthrough = []string{"*.vault.internal"}
	rc := runtimeFor(t, cfg)
	handler := NewConnectHandler(rc, testMitm, testPassthrough)

	read := func(domain, action string) float64 {
		return testutil.ToFloat64(metrics.TrafficTotal.WithLabelValues(domain, action))
	}

	t.Run("blacklisted host is intercepted and counts as BLACK-LISTED-CONNECT", func(t *testing.T) {
		beforeConnect := read(blacklistedOnlyLabel, "BLACK-LISTED-CONNECT")
		beforePlain := read(blacklistedOnlyLabel, "BLACK-LISTED")

		action, _ := handler(blacklistedOnly+":443", connectCtx(t, blacklistedOnly+":443"))
		if action != testMitm {
			t.Fatalf("action = %v, want the MITM action: a blacklisted host is intercepted so "+
				"HandleRequest can answer 403", action)
		}
		if delta := read(blacklistedOnlyLabel, "BLACK-LISTED-CONNECT") - beforeConnect; delta != 1 {
			t.Errorf("BLACK-LISTED-CONNECT moved by %v, want 1", delta)
		}
		// HandleRequest records BLACK-LISTED later, only if the handshake succeeds.
		// Counting it here too would double-count every intercepted denial.
		if delta := read(blacklistedOnlyLabel, "BLACK-LISTED") - beforePlain; delta != 0 {
			t.Errorf("BLACK-LISTED moved by %v at the CONNECT stage, want 0", delta)
		}
	})

	t.Run("passthrough and blacklisted is refused and counts as BLACK-LISTED", func(t *testing.T) {
		beforeConnect := read(bothListsLabel, "BLACK-LISTED-CONNECT")
		beforePlain := read(bothListsLabel, "BLACK-LISTED")

		action, _ := handler(bothLists+":443", connectCtx(t, bothLists+":443"))
		if action != goproxy.RejectConnect {
			t.Fatalf("action = %v, want RejectConnect: a passthrough tunnel is never inspected, "+
				"so a denied host must not get one", action)
		}
		if delta := read(bothListsLabel, "BLACK-LISTED") - beforePlain; delta != 1 {
			t.Errorf("BLACK-LISTED moved by %v, want 1", delta)
		}
		if delta := read(bothListsLabel, "BLACK-LISTED-CONNECT") - beforeConnect; delta != 0 {
			t.Errorf("BLACK-LISTED-CONNECT moved by %v for a refused tunnel, want 0; "+
				"that label is for intercepted hosts", delta)
		}
	})
}
