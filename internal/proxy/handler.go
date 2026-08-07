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

	// The blacklist outranks everything, including rewrites.
	//
	// Rewrites otherwise bypass the ACL, which is intended: a rewritten host is
	// implicitly allowed without needing a whitelist entry. But a denylist is not
	// a preference. A host in both tables used to be forwarded to its target_ip
	// with the rule's injected headers -- over HTTPS that was unreachable only
	// because DecideConnect rejected blacklisted hosts at CONNECT time, and
	// narrowing that check removed the backstop. Checking the blacklist first
	// makes the precedence explicit instead of dependent on which layer happens
	// to look.
	blacklisted := config.Matches(host, acl.Blacklist)

	// Check rewrite rules (highest priority among the allow paths, bypasses the
	// whitelist and the default policy)
	// Fast path: exact match (only for domains without path_pattern rules)
	if blacklisted {
		action = "BLACK-LISTED"
	} else if rw, ok := rewriteExact[host]; ok {
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

	// Evaluate the remaining ACL stages if nothing above decided
	if action == "BLOCKED" {
		if config.Matches(host, acl.Whitelist) {
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

	// Block denied requests
	if action == "BLACK-LISTED" || action == "BLOCKED" {
		LogBlocked(r.Context(), runtimeCfg, BlockedRequest{
			RequestID: requestID,
			Client:    r.RemoteAddr,
			Host:      host,
			Method:    r.Method,
			Target:    r.URL.Path,
			Action:    action,
		})
		if rec != nil {
			// Blocked requests are not forwarded; the only mutation is X-Request-ID.
			rec.SetRequestOut(r, nil, []string{"X-Request-ID"}, nil, "")
		}
		// Nothing is forwarded, so the handler's own elapsed time is the whole
		// request.
		metrics.RequestDuration.WithLabelValues(action).Observe(time.Since(start).Seconds())
		return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden, "Policy Blocked")
	}

	// Apply rewrite transformations: drop headers, inject headers, change scheme.
	// X-Request-ID is always injected by the proxy and is absent from the
	// inbound snapshot, so it is a genuine addition.
	added := []string{"X-Request-ID"}
	var dropped, modified []string
	schemeChanged := ""
	if matchedRewrite != nil {
		// Scheme and port are applied before the header map so an explicit
		// headers: {Host: ...} still wins over the authority derived here.
		schemeChanged = applyTargetSchemeAndPort(r, matchedRewrite)

		for _, h := range matchedRewrite.DropHeaders {
			if len(r.Header.Values(h)) > 0 {
				dropped = append(dropped, h)
			}
			r.Header.Del(h)
		}
		for k, v := range matchedRewrite.Headers {
			// Host lives in r.Host, not r.Header. net/http excludes it from
			// Header.WriteSubset and derives the wire value (and HTTP/2
			// :authority) from r.Host, so Header.Set("Host", ...) is silently
			// dropped on the way out. Setting a Host that never arrives is the
			// worst kind of failure for a rewrite: the ACCESS log says REWRITTEN
			// and the trace diff lists the header as added, while the backend
			// answers from whichever vhost the original name selected.
			//
			// Every request already carries a Host, so this is always a
			// modification rather than an addition.
			if strings.EqualFold(k, "Host") {
				modified = append(modified, k)
				r.Host = v
				continue
			}
			// Set overwrites; distinguish a brand-new header from one that
			// replaces an existing client value so the diff stays accurate.
			if len(r.Header.Values(k)) > 0 {
				modified = append(modified, k)
			} else {
				added = append(added, k)
			}
			r.Header.Set(k, v)
		}
	}

	if rec != nil {
		rec.SetRequestOut(r, dropped, added, modified, schemeChanged)
	}

	// Forwarded requests are timed around the upstream round-trip instead, which
	// is where DNS, dial, TLS handshake and upstream think-time actually happen.
	// Observing here would have measured rule evaluation and called it request
	// latency.
	r = r.WithContext(context.WithValue(r.Context(), timingCtxKey, &requestTiming{
		start:  start,
		action: action,
	}))

	return r, nil
}

// requestTiming carries the handler's start time and policy outcome to whoever
// completes the request, so the duration histogram spans the upstream call.
type requestTiming struct {
	start  time.Time
	action string
}

type timingCtxKeyType struct{}

var timingCtxKey = timingCtxKeyType{}

// ObserveRequestDuration records the elapsed time for a forwarded request.
// Call once the upstream round-trip has returned. No-op for requests that were
// never forwarded, which record their own duration in HandleRequest.
func ObserveRequestDuration(r *http.Request) {
	t, ok := r.Context().Value(timingCtxKey).(*requestTiming)
	if !ok {
		return
	}
	metrics.RequestDuration.WithLabelValues(t.action).Observe(time.Since(t.start).Seconds())
}

// setupTrace creates a trace Record when tracing is enabled and the request
// matches a trace rule, capturing the inbound request before any mutation.
// Returns nil when the request is not traced.
func setupTrace(r *http.Request, pctx *goproxy.ProxyCtx, runtimeCfg *config.RuntimeConfig, requestID string) *trace.Record {
	ct, _ := runtimeCfg.GetTrace()
	if !ct.Enabled {
		return nil
	}
	host := config.NormalizeHost(r.URL.Hostname())
	rule := ct.Match(host, r.URL.String(), true)
	if rule == nil {
		return nil
	}
	// Resolve the logger at emit time rather than capturing it: SIGHUP rotates
	// the trace log and closes the previous handle, and a record emitted after
	// that must land in the current file rather than a closed descriptor.
	rec := trace.NewRecord(requestID, "mitm", rule, trace.NewRedactor(ct), func() *slog.Logger {
		_, l := runtimeCfg.GetTrace()
		return l
	})
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
// Rejection is reserved for the one case that needs it: a host that would be
// tunneled without interception. Passthrough returns ConnectAccept, and an
// accepted tunnel never reaches HandleRequest, so a passthrough pattern
// overlapping a blacklist entry would otherwise hand out an uninspected tunnel
// to a denied host.
//
// Everything else is MITM'd even when blacklisted. Interception establishes TLS
// with the proxy's own certificate and forwards nothing upstream until
// HandleRequest has applied policy, so a blacklisted host is still blocked --
// but the client receives a real 403 it can read, rather than a rejected
// CONNECT, which Go and most clients surface as an opaque transport error.
// Rejecting earlier would have been a quieter failure, not a safer one.
func DecideConnect(hostname string, acl config.CompiledACL) ConnectDecision {
	if config.Matches(hostname, acl.Passthrough) {
		if config.Matches(hostname, acl.Blacklist) {
			return ConnectReject
		}
		return ConnectPassthrough
	}
	return ConnectMITM
}

// NormalizeResponseProto rewrites non-HTTP/1.x responses to HTTP/1.1 so
// goproxy's resp.Write() never serializes an unusable status line. Two cases
// need fixing:
//  1. goproxy.NewResponse() leaves the Proto fields at zero, yielding "HTTP/0.0"
//  2. Upstream HTTP/2 responses carry Proto "HTTP/2.0"
//
// Both cause "Unsupported HTTP version" errors in clients on MITM tunnels.
//
// HTTP/1.0 and HTTP/1.1 responses are left exactly as they are: both serialize
// to a valid status line, and rewriting 1.0 to 1.1 would misreport what the
// upstream actually spoke.
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

// BlockedRequest is one entry in the blocked-request audit log.
type BlockedRequest struct {
	RequestID string
	Client    string
	Host      string
	Method    string
	// Target is the request path for a forwarded request. A CONNECT carries
	// host:port in its request-target rather than a path, so URL.Path is empty
	// there; the CONNECT caller passes the authority instead of leaving the field
	// blank.
	Target string
	Action string
}

// LogBlocked appends a blocked request to the audit log, if one is configured.
//
// Shared by the request path and the CONNECT path. The CONNECT path needs it
// because a rejected tunnel never reaches HandleRequest, so routing that case
// through here is the only way the log can hold what the documentation promises:
// every BLACK-LISTED and BLOCKED request, including HTTPS.
func LogBlocked(ctx context.Context, runtimeCfg *config.RuntimeConfig, req BlockedRequest) {
	bl := runtimeCfg.GetBlockedLogger()
	if bl == nil {
		return
	}
	bl.LogAttrs(ctx, slog.LevelInfo, "blocked",
		slog.String("request_id", req.RequestID),
		slog.String("client", req.Client),
		slog.String("host", req.Host),
		slog.String("method", req.Method),
		slog.String("target", req.Target),
		slog.String("action", req.Action),
	)
}

// defaultPortForScheme returns the port an HTTP URL scheme implies when the
// authority carries none.
func defaultPortForScheme(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// applyTargetSchemeAndPort applies a rewrite rule's target_scheme and
// target_port to the request, returning the new scheme if it changed.
//
// The port has to move with the scheme. goproxy builds the MITM request URL
// from the CONNECT authority, so an intercepted HTTPS request carries :443.
// Rewriting only the scheme therefore sent a cleartext HTTP request to port 443
// of the target -- refused by a backend that serves HTTP on 80 or 8080, and
// read as a malformed TLS record by anything that does speak TLS there. The
// documented "HTTPS client -> HTTP backend" rewrite could not work at all.
//
// A port that is the default for the *original* scheme was implicit (the client
// wrote https://host, or CONNECT host:443), so it moves to the new scheme's
// default. A port the operator chose explicitly is left alone: it is a
// deliberate destination, not an artifact of the scheme. target_port overrides
// both, for the common case of a legacy backend on 8080.
func applyTargetSchemeAndPort(r *http.Request, rw *config.CompiledRewriteRule) string {
	schemeChanged := ""
	port := r.URL.Port()

	if rw.TargetScheme != "" && rw.TargetScheme != r.URL.Scheme {
		wasImplicitPort := port == "" || port == defaultPortForScheme(r.URL.Scheme)
		r.URL.Scheme = rw.TargetScheme
		schemeChanged = rw.TargetScheme
		if wasImplicitPort {
			port = defaultPortForScheme(rw.TargetScheme)
		}
	}
	if rw.TargetPort != "" {
		port = rw.TargetPort
	}

	if port != "" && port != r.URL.Port() {
		r.URL.Host = net.JoinHostPort(r.URL.Hostname(), port)
		// Keep the Host header consistent with the authority actually dialed.
		// RFC 9110 omits the port when it is the scheme default. An explicit
		// headers: {Host: ...} is applied after this and overrides it.
		if port == defaultPortForScheme(r.URL.Scheme) {
			r.Host = r.URL.Hostname()
		} else {
			r.Host = net.JoinHostPort(r.URL.Hostname(), port)
		}
	}
	return schemeChanged
}
