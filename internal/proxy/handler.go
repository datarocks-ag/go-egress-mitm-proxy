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
)

// RewriteResult holds the outcome of a rewrite rule lookup.
type RewriteResult struct {
	TargetIP   string
	TargetHost string
	Insecure   bool
	Matched    bool
}

// HandleRequest processes each incoming request through the policy engine.
// It evaluates rules in order: rewrites -> blacklist -> whitelist -> default policy.
func HandleRequest(r *http.Request, _ *goproxy.ProxyCtx, runtimeCfg *config.RuntimeConfig) (*http.Request, *http.Response) {
	start := time.Now()
	metrics.ActiveConnections.Inc()
	defer metrics.ActiveConnections.Dec()

	// Generate and inject request ID for tracing
	requestID := GenerateRequestID()
	r.Header.Set("X-Request-ID", requestID)

	cfg, acl, rewrites, rewriteExact, _ := runtimeCfg.Get()

	host := r.URL.Hostname()
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
		return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden, "Policy Blocked")
	}

	// Apply rewrite transformations: drop headers, inject headers, change scheme
	if matchedRewrite != nil {
		for _, h := range matchedRewrite.DropHeaders {
			r.Header.Del(h)
		}
		for k, v := range matchedRewrite.Headers {
			r.Header.Set(k, v)
		}
		if matchedRewrite.TargetScheme != "" {
			r.URL.Scheme = matchedRewrite.TargetScheme
		}
	}

	return r, nil
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

		conn, dialErr := (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext(ctx, network, addr)

		if dialErr != nil {
			RecordDialError(dialErr)
			return nil, dialErr
		}

		return conn, nil
	}
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
		rawConn, dialErr := (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext(ctx, network, dialAddr)
		if dialErr != nil {
			RecordDialError(dialErr)
			return nil, dialErr
		}

		// Build per-connection TLS config
		tlsCfg := baseTLSConfig.Clone()
		tlsCfg.ServerName = host // SNI = original hostname
		if cfg.Proxy.InsecureSkipVerify || rw.Insecure {
			tlsCfg.InsecureSkipVerify = true //nolint:gosec // intentional: user-configured insecure for dev/internal endpoints
		}

		// TLS handshake
		tlsConn := tls.Client(rawConn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close() //nolint:errcheck // best-effort cleanup on handshake failure
			RecordDialError(err)
			return nil, err
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
	// Known rewrite targets get their own label
	if _, ok := rewriteExact[host]; ok {
		return host
	}

	// Extract base domain (TLD+1) for ACL-matched hosts
	if config.Matches(host, acl.Whitelist) || config.Matches(host, acl.Blacklist) {
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
