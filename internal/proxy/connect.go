// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"context"
	"log/slog"
	"net"
	"net/http"

	"github.com/elazarl/goproxy"

	"go-egress-proxy/internal/config"
	"go-egress-proxy/internal/metrics"
	"go-egress-proxy/internal/trace"
)

// NewConnectHandler builds the CONNECT-stage handler: policy dispatch, metric
// labeling, blocked-request auditing, and the passthrough trace wiring.
//
// Extracted from main() for the same reason reload() was. As an anonymous
// FuncHttpsHandler it was unreachable from any test, so the passthrough trace
// wiring below — and the connection handed to it — had no coverage at all,
// which is how a downgraded tunnel went unnoticed. Only DecideConnect had been
// pulled out, and only that part was tested.
func NewConnectHandler(
	runtimeCfg *config.RuntimeConfig,
	mitmAction, passthroughAction *goproxy.ConnectAction,
) goproxy.FuncHttpsHandler {
	return func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		slog.Log(context.Background(), slog.Level(-8), "CONNECT",
			"host", host,
			"client", ctx.Req.RemoteAddr,
			"method", ctx.Req.Method,
			"user_agent", ctx.Req.Header.Get("User-Agent"),
		)

		_, currentACL, _, rewriteExact, _ := runtimeCfg.Get()
		hostname := host
		if h, _, err := net.SplitHostPort(host); err == nil {
			hostname = h
		}
		hostname = config.NormalizeHost(hostname)

		metricDomain := NormalizeDomainForMetrics(hostname, rewriteExact, currentACL)

		switch DecideConnect(hostname, currentACL) {
		case ConnectReject:
			return rejectConnect(runtimeCfg, ctx, host, hostname, metricDomain), host

		case ConnectMITM:
			// A blacklisted host is intercepted rather than refused so HandleRequest
			// can answer with a readable 403. But that leaves the denial recorded
			// only if the client completes the TLS handshake with our certificate --
			// a pinning SDK or a JVM truststore never will, and goproxy routes that
			// failure to debug level. It also downgrades what used to be a WARN to
			// HandleRequest's Info-level ACCESS line, which the default warn level
			// drops.
			//
			// Record the attempt here so a denial is observable regardless of
			// whether the client cooperates with interception. The distinct action
			// label avoids double-counting the BLACK-LISTED that HandleRequest
			// records when the handshake does succeed.
			if config.Matches(hostname, currentACL.Blacklist) {
				slog.Warn("BLACK-LISTED",
					"host", hostname,
					"client", ctx.Req.RemoteAddr,
					"stage", "connect")
				metrics.TrafficTotal.WithLabelValues(metricDomain, "BLACK-LISTED-CONNECT").Inc()
			}
			return mitmAction, host

		case ConnectPassthrough:
			slog.Info("PASSTHROUGH",
				"host", hostname,
				"client", ctx.Req.RemoteAddr)
			metrics.TrafficTotal.WithLabelValues(metricDomain, "PASSTHROUGH").Inc()
			wirePassthroughTrace(runtimeCfg, ctx, host, hostname)
			return passthroughAction, host

		default:
			return mitmAction, host
		}
	}
}

// rejectConnect refuses a tunnel that would otherwise escape inspection, and
// records it the way the request path records a block.
func rejectConnect(
	runtimeCfg *config.RuntimeConfig,
	ctx *goproxy.ProxyCtx,
	target, hostname, metricDomain string,
) *goproxy.ConnectAction {
	requestID := GenerateRequestID()
	slog.Warn("BLACK-LISTED",
		"request_id", requestID,
		"host", hostname,
		"client", ctx.Req.RemoteAddr)
	metrics.TrafficTotal.WithLabelValues(metricDomain, "BLACK-LISTED").Inc()

	// A rejected tunnel never reaches HandleRequest, so this is the only place
	// the blocked-request audit log can learn about a blacklisted HTTPS host.
	// Without it the log silently omits all of them.
	LogBlocked(ctx.Req.Context(), runtimeCfg, BlockedRequest{
		RequestID: requestID,
		Client:    ctx.Req.RemoteAddr,
		Host:      hostname,
		Method:    ctx.Req.Method,
		// A CONNECT carries host:port as its request-target, not a path, so
		// URL.Path is empty here. Recording the authority keeps the audit entry
		// from losing the target.
		Target: target,
		Action: "BLACK-LISTED",
	})

	// goproxy writes ctx.Resp to the hijacked client connection when it is set,
	// and closes the socket silently when it is not. Leaving it unset turned a
	// documented 403 into "unexpected EOF" for every blacklisted HTTPS host.
	// NewResponse leaves the Proto fields zeroed, which would serialize as
	// "HTTP/0.0"; normalizing is what makes the status line usable on a raw
	// connection.
	//nolint:bodyclose // synthetic response; goproxy writes and closes it
	resp := goproxy.NewResponse(ctx.Req, goproxy.ContentTypeText, http.StatusForbidden, "Policy Blocked")
	NormalizeResponseProto(resp)
	ctx.Resp = resp

	return goproxy.RejectConnect
}

// wirePassthroughTrace attaches a tracing dialer when a host-based trace rule
// matches. A passthrough tunnel is not intercepted, so only the TCP layer is
// observable.
func wirePassthroughTrace(runtimeCfg *config.RuntimeConfig, ctx *goproxy.ProxyCtx, host, hostname string) {
	ct, _ := runtimeCfg.GetTrace()
	if !ct.Enabled {
		return
	}
	rule := ct.Match(hostname, "", false)
	if rule == nil {
		return
	}

	// The logger is resolved at emit time: a passthrough record is written when
	// the tunnel closes, which can be long after a SIGHUP rotated the trace log
	// and closed the handle this would otherwise have captured.
	rec := trace.NewRecord(GenerateRequestID(), "passthrough", rule, trace.NewRedactor(ct),
		func() *slog.Logger {
			_, l := runtimeCfg.GetTrace()
			return l
		})
	rec.SetConnect(host, hostname)
	ctx.UserData = rec

	// Decorate the production dialer rather than replacing it, so a traced
	// passthrough host keeps its rewrite target and its dial error metrics.
	ctx.Dialer = trace.PassthroughDialer(rec, MakeDialer(runtimeCfg))
}
