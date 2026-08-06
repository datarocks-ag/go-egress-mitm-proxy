// Package proxy provides the HTTP request handler and custom dialers
// for the MITM proxy's split-brain DNS and policy enforcement.
package proxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/elazarl/goproxy"

	"go-egress-proxy/internal/config"
	"go-egress-proxy/internal/metrics"
	"go-egress-proxy/internal/trace"
)

// DefaultTLSHandshakeTimeout bounds the upstream TLS handshake performed by
// MakeTLSDialer. It is separate from the 5s TCP dial timeout, which a target
// that accepts the connection and then stalls has already passed.
const DefaultTLSHandshakeTimeout = 10 * time.Second

// tlsHandshakeTimeout is the value actually used. It is a variable rather than a
// constant purely so tests can lower it: asserting that a stalled handshake is
// bounded otherwise costs the full timeout in wall-clock time on every CI run.
// Production never reassigns it.
var tlsHandshakeTimeout = DefaultTLSHandshakeTimeout

// RewriteResult holds the outcome of a rewrite rule lookup.
type RewriteResult struct {
	TargetIP   string
	TargetHost string
	Insecure   bool
	Matched    bool
}

// HandleRequest processes each incoming request through the policy engine.
// It evaluates rules in order: rewrites -> blacklist -> whitelist -> default policy.
func HandleRequest(r *http.Request, pctx *goproxy.ProxyCtx, runtimeCfg *config.RuntimeConfig) (*http.Request, *http.Response) {
	start := time.Now()
	metrics.ActiveConnections.Inc()
	defer metrics.ActiveConnections.Dec()

	// Generate request ID for tracing
	requestID := GenerateRequestID()

	// Set up selective tracing before any header mutation so the inbound snapshot
	// reflects exactly what the client sent. The record rides the request context
	// down to the dialers (TCP/TLS layer) and goproxy ctx.UserData (response layer).
	rec := setupTrace(r, pctx, runtimeCfg, requestID)
	if rec != nil {
		r = r.WithContext(context.WithValue(r.Context(), trace.CtxKey, rec))
		rec.WrapRequestBody(r)
	}

	// Inject request ID
	r.Header.Set("X-Request-ID", requestID)

	cfg, acl, rewrites, rewriteExact, _ := runtimeCfg.Get()

	host := config.NormalizeHost(r.URL.Hostname())
	action := "BLOCKED"
	var matchedRewrite *config.CompiledRewriteRule

	// Check rewrite rules first (highest priority, bypasses ACL)
	// Fast path: exact match (only for domains without path_pattern rules)
	if rw, ok := rewriteExact[host]; ok {
		matchedRewrite = rw
		action = "REWRITTEN"
	} else {
		// Slow path: pattern match with optional path filtering
		for i := range rewrites {
			if !rewrites[i].Pattern.MatchString(host) {
				continue
			}
			if rewrites[i].PathPattern != nil && !rewrites[i].PathPattern.MatchString(r.URL.Path) {
				continue
			}
			matchedRewrite = &rewrites[i]
			action = "REWRITTEN"
			break
		}
	}

	// Store matched rewrite in request context so dialers can use it
	// (dialers only receive addr, not the HTTP request path)
	if matchedRewrite != nil {
		rw := RewriteResult{
			TargetIP:   matchedRewrite.TargetIP,
			TargetHost: matchedRewrite.TargetHost,
			Insecure:   matchedRewrite.Insecure,
			Matched:    true,
		}
		r = r.WithContext(context.WithValue(r.Context(), config.RewriteCtxKey, rw))
	}

	// Evaluate ACL if not rewritten
	if action == "BLOCKED" {
		if config.Matches(host, acl.Blacklist) {
			action = "BLACK-LISTED"
		} else if config.Matches(host, acl.Whitelist) {
			action = "WHITE-LISTED"
		} else if cfg.Proxy.DefaultPolicy == "ALLOW" {
			action = "ALLOWED-BY-DEFAULT"
		}
	}

	// Log access with request ID
	slog.Info("ACCESS",
		"request_id", requestID,
		"client", r.RemoteAddr,
		"host", host,
		"action", action,
		"method", r.Method,
		"path", r.URL.Path)

	// Debug: log full request details for troubleshooting
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		attrs := []slog.Attr{
			slog.String("request_id", requestID),
			slog.String("scheme", r.URL.Scheme),
			slog.String("host", host),
			slog.String("method", r.Method),
			slog.String("url", r.URL.String()),
			slog.String("proto", r.Proto),
			slog.String("remote_addr", r.RemoteAddr),
			slog.Int64("content_length", r.ContentLength),
		}
		if ua := r.Header.Get("User-Agent"); ua != "" {
			attrs = append(attrs, slog.String("user_agent", ua))
		}
		if ct := r.Header.Get("Content-Type"); ct != "" {
			attrs = append(attrs, slog.String("content_type", ct))
		}
		if matchedRewrite != nil {
			attrs = append(attrs,
				slog.String("rewrite_target_ip", matchedRewrite.TargetIP),
				slog.String("rewrite_target_host", matchedRewrite.TargetHost),
				slog.String("rewrite_original", matchedRewrite.Original),
			)
		}
		// Log all request headers at trace level
		if slog.Default().Enabled(context.Background(), slog.Level(-8)) {
			hdrs := make([]string, 0, len(r.Header))
			for k, v := range r.Header {
				hdrs = append(hdrs, k+"="+strings.Join(v, ","))
			}
			attrs = append(attrs, slog.String("headers", strings.Join(hdrs, "; ")))
		}
		slog.LogAttrs(context.Background(), slog.LevelDebug, "REQUEST_DETAIL", attrs...)
	}

	// Record metrics with bounded cardinality
	metricDomain := NormalizeDomainForMetrics(host, rewriteExact, acl)
	metrics.TrafficTotal.WithLabelValues(metricDomain, action).Inc()

	// Track request size
	if r.ContentLength > 0 {
		metrics.BytesTransferred.WithLabelValues("request").Add(float64(r.ContentLength))
	}

	defer func() {
		metrics.RequestDuration.WithLabelValues(action).Observe(time.Since(start).Seconds())
	}()

	// Block denied requests
	if action == "BLACK-LISTED" || action == "BLOCKED" {
		if bl := runtimeCfg.GetBlockedLogger(); bl != nil {
			bl.LogAttrs(context.Background(), slog.LevelInfo, "blocked",
				slog.String("request_id", requestID),
				slog.String("client", r.RemoteAddr),
				slog.String("host", host),
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("action", action),
			)
		}
		if rec != nil {
			// Blocked requests are not forwarded; the only mutation is X-Request-ID.
			rec.SetRequestOut(r, nil, []string{"X-Request-ID"}, nil, "")
		}
		return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden, "Policy Blocked")
	}

	// Apply rewrite transformations: drop headers, inject headers, change scheme.
	// X-Request-ID is always injected by the proxy and is absent from the
	// inbound snapshot, so it is a genuine addition.
	added := []string{"X-Request-ID"}
	var dropped, modified []string
	schemeChanged := ""
	if matchedRewrite != nil {
		for _, h := range matchedRewrite.DropHeaders {
			if len(r.Header.Values(h)) > 0 {
				dropped = append(dropped, h)
			}
			r.Header.Del(h)
		}
		for k, v := range matchedRewrite.Headers {
			// Set overwrites; distinguish a brand-new header from one that
			// replaces an existing client value so the diff stays accurate.
			if len(r.Header.Values(k)) > 0 {
				modified = append(modified, k)
			} else {
				added = append(added, k)
			}
			r.Header.Set(k, v)
		}
		if matchedRewrite.TargetScheme != "" {
			r.URL.Scheme = matchedRewrite.TargetScheme
			schemeChanged = matchedRewrite.TargetScheme
		}
	}

	if rec != nil {
		rec.SetRequestOut(r, dropped, added, modified, schemeChanged)
	}

	return r, nil
}

// setupTrace creates a trace Record when tracing is enabled and the request
// matches a trace rule, capturing the inbound request before any mutation.
// Returns nil when the request is not traced.
func setupTrace(r *http.Request, pctx *goproxy.ProxyCtx, runtimeCfg *config.RuntimeConfig, requestID string) *trace.Record {
	ct, logger := runtimeCfg.GetTrace()
	if !ct.Enabled {
		return nil
	}
	host := config.NormalizeHost(r.URL.Hostname())
	rule := ct.Match(host, r.URL.String(), true)
	if rule == nil {
		return nil
	}
	rec := trace.NewRecord(requestID, "mitm", rule, trace.NewRedactor(ct), logger)
	// connect.host preserves an explicit port (consistent with the passthrough
	// CONNECT path); SNI is the bare hostname.
	rec.SetConnect(r.URL.Host, host)
	rec.SetRequestIn(r)
	if pctx != nil {
		pctx.UserData = rec
	}
	return rec
}

// UpstreamErrorResponse returns the HTTP status code and reason text for an upstream error.
// Timeouts yield 504 Gateway Timeout; all other failures (DNS, refused, reset) yield 502 Bad Gateway.
func UpstreamErrorResponse(err error) (int, string) {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return http.StatusGatewayTimeout, "Gateway Timeout"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout, "Gateway Timeout"
	}
	return http.StatusBadGateway, "Bad Gateway"
}

// RecordResponseMetrics records metrics from the response.
func RecordResponseMetrics(resp *http.Response) {
	// Track response size
	if resp.ContentLength > 0 {
		metrics.BytesTransferred.WithLabelValues("response").Add(float64(resp.ContentLength))
	}

	// Track status code class
	statusClass := fmt.Sprintf("%dxx", resp.StatusCode/100)
	metrics.ResponseStatus.WithLabelValues(statusClass).Inc()
}

// LookupRewrite checks whether host matches a rewrite rule (exact map first, then patterns).
// Rules with PathPattern are skipped because the dialer has no access to the HTTP request path;
// those are resolved in HandleRequest and passed via request context instead.
func LookupRewrite(host string, rewrites []config.CompiledRewriteRule, rewriteExact map[string]*config.CompiledRewriteRule) RewriteResult {
	host = config.NormalizeHost(host)
	if rw, ok := rewriteExact[host]; ok {
		return RewriteResult{TargetIP: rw.TargetIP, TargetHost: rw.TargetHost, Insecure: rw.Insecure, Matched: true}
	}
	for i := range rewrites {
		if rewrites[i].PathPattern != nil {
			continue // path-based rules are resolved via context
		}
		if rewrites[i].Pattern.MatchString(host) {
			return RewriteResult{TargetIP: rewrites[i].TargetIP, TargetHost: rewrites[i].TargetHost, Insecure: rewrites[i].Insecure, Matched: true}
		}
	}
	return RewriteResult{}
}

// RecordDialError records a dial error in the upstream error metrics.
func RecordDialError(err error) {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		metrics.UpstreamErrors.WithLabelValues("timeout").Inc()
	} else {
		metrics.UpstreamErrors.WithLabelValues("connection").Inc()
	}
}

// MakeDialer creates a custom DialContext function that implements split-brain DNS.
// It intercepts TCP dials and routes matching domains to their configured target IPs.
// Path-based rewrites are passed via request context from HandleRequest.
func MakeDialer(runtimeCfg *config.RuntimeConfig) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			metrics.UpstreamErrors.WithLabelValues("invalid_address").Inc()
			return nil, fmt.Errorf("invalid address %q: %w", addr, err)
		}

		// Check context first (set by HandleRequest for path-based rewrites)
		rw, ok := ctx.Value(config.RewriteCtxKey).(RewriteResult)
		if !ok {
			_, _, rewrites, rewriteExact, _ := runtimeCfg.Get()
			rw = LookupRewrite(host, rewrites, rewriteExact)
		}

		if rw.TargetIP != "" {
			addr = net.JoinHostPort(rw.TargetIP, port)
			slog.Debug("Rewriting dial", "original", host, "target", rw.TargetIP)
		} else if rw.TargetHost != "" {
			addr = net.JoinHostPort(rw.TargetHost, port)
			slog.Debug("Rewriting dial", "original", host, "target", rw.TargetHost)
		}

		dialStart := time.Now()
		conn, dialErr := (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext(ctx, network, addr)

		if dialErr != nil {
			RecordDialError(dialErr)
			if rec := trace.FromContext(ctx); rec != nil {
				rec.SetError(dialErr.Error())
			}
			return nil, dialErr
		}

		if rec := trace.FromContext(ctx); rec != nil {
			rec.SetTCP(hostFromAddr(conn.RemoteAddr()), time.Since(dialStart), "", "")
		}

		return conn, nil
	}
}

// hostFromAddr extracts the IP/host (without port) from a network address.
func hostFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}

// MakeTLSDialer creates a custom DialTLSContext function that performs TCP dial with
// rewrite IP substitution followed by a TLS handshake with per-connection configuration.
// This enables per-rewrite InsecureSkipVerify without affecting other connections.
// Path-based rewrites are passed via request context from HandleRequest.
func MakeTLSDialer(runtimeCfg *config.RuntimeConfig) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			metrics.UpstreamErrors.WithLabelValues("invalid_address").Inc()
			return nil, fmt.Errorf("invalid address %q: %w", addr, err)
		}

		cfg, _, rewrites, rewriteExact, baseTLSConfig := runtimeCfg.Get()

		// Check context first (set by HandleRequest for path-based rewrites)
		rw, ok := ctx.Value(config.RewriteCtxKey).(RewriteResult)
		if !ok {
			rw = LookupRewrite(host, rewrites, rewriteExact)
		}

		dialAddr := addr
		if rw.TargetIP != "" {
			dialAddr = net.JoinHostPort(rw.TargetIP, port)
			slog.Debug("Rewriting TLS dial", "original", host, "target", rw.TargetIP)
		} else if rw.TargetHost != "" {
			dialAddr = net.JoinHostPort(rw.TargetHost, port)
			slog.Debug("Rewriting TLS dial", "original", host, "target", rw.TargetHost)
		}

		// TCP connect
		dialStart := time.Now()
		rawConn, dialErr := (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext(ctx, network, dialAddr)
		if dialErr != nil {
			RecordDialError(dialErr)
			if rec := trace.FromContext(ctx); rec != nil {
				rec.SetError(dialErr.Error())
			}
			return nil, dialErr
		}
		// Measure dial_ms as the TCP connect only (excluding the TLS handshake),
		// to stay consistent with the plain MakeDialer path.
		dialDur := time.Since(dialStart)

		// Build per-connection TLS config
		tlsCfg := baseTLSConfig.Clone()
		tlsCfg.ServerName = host // SNI = original hostname
		if cfg.Proxy.InsecureSkipVerify || rw.Insecure {
			tlsCfg.InsecureSkipVerify = true //nolint:gosec // intentional: user-configured insecure for dev/internal endpoints
		}

		// TLS handshake, explicitly bounded.
		//
		// Nothing else bounds it. Transport.TLSHandshakeTimeout is only applied in
		// net/http's own addTLS(); with a custom DialTLSContext the transport calls
		// straight through (transport.go hasCustomTLSDialer branch). The context
		// here descends from goproxy's MITM request, which is built over
		// context.Background(), so it carries no deadline either. The 5s Dialer
		// timeout above covers TCP connect only.
		//
		// Without this, a target that completes the TCP handshake and then goes
		// silent -- half-dead TLS terminator, silent firewall, overloaded LB --
		// parks the request goroutine forever holding an upstream socket and the
		// client's hijacked tunnel. ResponseHeaderTimeout never fires, because the
		// handshake never completes.
		hsCtx, cancelHandshake := context.WithTimeout(ctx, tlsHandshakeTimeout)
		defer cancelHandshake()

		tlsConn := tls.Client(rawConn, tlsCfg)
		if err := tlsConn.HandshakeContext(hsCtx); err != nil {
			rawConn.Close() //nolint:errcheck // best-effort cleanup on handshake failure
			RecordDialError(err)
			if rec := trace.FromContext(ctx); rec != nil {
				rec.SetError(err.Error())
			}
			return nil, err
		}

		if rec := trace.FromContext(ctx); rec != nil {
			state := tlsConn.ConnectionState()
			rec.SetTCP(hostFromAddr(rawConn.RemoteAddr()), dialDur,
				tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite))
		}

		return tlsConn, nil
	}
}

// GenerateRequestID generates a random request ID for tracing.
func GenerateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp if random fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// NormalizeDomainForMetrics prevents metrics cardinality explosion by grouping domains.
// Known rewrite domains are tracked individually, ACL-matched domains by base domain,
// and unknown domains are grouped as "_other".
func NormalizeDomainForMetrics(host string, rewriteExact map[string]*config.CompiledRewriteRule, acl config.CompiledACL) string {
	host = config.NormalizeHost(host)
	// Known rewrite targets get their own label
	if _, ok := rewriteExact[host]; ok {
		return host
	}

	// Extract base domain (TLD+1) for ACL-matched hosts
	if config.Matches(host, acl.Whitelist) || config.Matches(host, acl.Blacklist) || config.Matches(host, acl.Passthrough) {
		return ExtractBaseDomain(host)
	}

	// Unknown domains are grouped to prevent cardinality explosion
	return "_other"
}

// ExtractBaseDomain returns the base domain (e.g., "sub.example.com" -> "example.com").
// This is a simple implementation that assumes standard TLD structure.
func ExtractBaseDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// ConnectDecision is the policy outcome for a CONNECT request, decided before
// any tunnel is established.
type ConnectDecision int

const (
	// ConnectMITM intercepts the tunnel and applies the full request pipeline.
	ConnectMITM ConnectDecision = iota
	// ConnectPassthrough tunnels TCP without TLS interception.
	ConnectPassthrough
	// ConnectReject refuses the tunnel outright.
	ConnectReject
)

// DecideConnect applies ACL policy to a CONNECT target.
//
// hostname must already be normalized via config.NormalizeHost.
//
// The blacklist is evaluated before passthrough, and the ordering is
// load-bearing: a passthrough match accepts the tunnel, and an accepted tunnel
// never reaches HandleRequest, which is where every other blacklist check
// happens. Testing passthrough first would let any passthrough pattern silently
// void the blacklist entries it overlaps.
func DecideConnect(hostname string, acl config.CompiledACL) ConnectDecision {
	switch {
	case config.Matches(hostname, acl.Blacklist):
		return ConnectReject
	case config.Matches(hostname, acl.Passthrough):
		return ConnectPassthrough
	default:
		return ConnectMITM
	}
}

// NormalizeResponseProto forces HTTP/1.1 framing so goproxy's resp.Write() never
// serializes an unusable status line. Two cases need fixing:
//  1. goproxy.NewResponse() leaves the Proto fields at zero, yielding "HTTP/0.0"
//  2. Upstream HTTP/2 responses carry Proto "HTTP/2.0"
//
// Both cause "Unsupported HTTP version" errors in clients on MITM tunnels.
func NormalizeResponseProto(resp *http.Response) {
	if resp == nil || resp.ProtoMajor == 1 {
		return
	}
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1
}

// NewOutboundTransport builds the upstream transport.
//
// Extracted from main so the real construction is reachable from tests; the
// previous tests built an http.Transport literal inside the test and asserted
// the fields they had just set, exercising no repository code at all.
func NewOutboundTransport(baseTLS *tls.Config, runtimeCfg *config.RuntimeConfig, opts OutboundTransportOptions) *http.Transport {
	return &http.Transport{
		TLSClientConfig:       baseTLS,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          opts.MaxIdleConns,
		MaxIdleConnsPerHost:   opts.MaxIdleConnsPerHost,
		MaxConnsPerHost:       opts.MaxConnsPerHost,
		IdleConnTimeout:       opts.IdleConnTimeout,
		ResponseHeaderTimeout: opts.ResponseHeaderTimeout,
		DialContext:           MakeDialer(runtimeCfg),
		DialTLSContext:        MakeTLSDialer(runtimeCfg),
	}
}

// OutboundTransportOptions carries the pool and timeout sizing for
// NewOutboundTransport. These apply per transport: TransportPool clones the
// result once per distinct rewrite target.
type OutboundTransportOptions struct {
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	MaxConnsPerHost       int
	IdleConnTimeout       time.Duration
	ResponseHeaderTimeout time.Duration
}
