// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

package proxy

import (
	"net/http"
	"strconv"
	"strings"
	"sync"

	"go-egress-proxy/internal/config"
)

// TransportPool routes each request to an *http.Transport dedicated to the
// upstream identity its rewrite rule resolved to.
//
// http.Transport keys its idle-connection pool on the request URL's scheme and
// host:port, which are fixed before DialContext/DialTLSContext run. Because the
// split-brain dialers substitute the target address (and per-rewrite TLS
// verification) inside the dial, two rules for the same domain — differing only
// by target_ip, target_host, or insecure — would otherwise share one pool key and
// reuse each other's connections. That silently misroutes traffic and can hand a
// connection negotiated with InsecureSkipVerify to a request demanding
// verification.
//
// Giving each identity its own transport keeps Go's pooling intact while making
// the pool key correct: within a single transport every connection under a given
// key really is interchangeable. The dialers are unchanged — they still read the
// rewrite from the request context.
type TransportPool struct {
	base *http.Transport

	mu         sync.RWMutex
	transports map[string]*http.Transport
}

// NewTransportPool returns a pool that derives per-target transports by cloning
// base. Requests matching no rewrite rule are served by base itself, whose pool
// key is already correct because no address substitution happens for them.
//
// base must be fully configured (dialers, TLS config, pooling limits) before this
// call; it is cloned lazily on first use of each target.
func NewTransportPool(base *http.Transport) *TransportPool {
	return &TransportPool{
		base:       base,
		transports: make(map[string]*http.Transport),
	}
}

// transportKey identifies the set of connections that are safely interchangeable:
// same dial target and same TLS verification mode. Requests to different hostnames
// stay separated by Go's own pool key inside the resulting transport.
func transportKey(rw RewriteResult) string {
	var b strings.Builder
	b.WriteString(rw.TargetIP)
	b.WriteByte('|')
	b.WriteString(rw.TargetHost)
	b.WriteByte('|')
	b.WriteString(strconv.FormatBool(rw.Insecure))
	return b.String()
}

// For returns the transport owning connections for the given rewrite result.
// Unmatched rewrites get the base transport.
func (p *TransportPool) For(rw RewriteResult) *http.Transport {
	// A rule that only rewrites headers or the scheme dials exactly as the base
	// transport does, so it can share the base pool rather than getting its own.
	if !rw.Matched || (rw.TargetIP == "" && rw.TargetHost == "" && !rw.Insecure) {
		return p.base
	}

	key := transportKey(rw)

	p.mu.RLock()
	tr, ok := p.transports[key]
	p.mu.RUnlock()
	if ok {
		return tr
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	// Re-check: another goroutine may have created it between the two locks.
	if existing, ok := p.transports[key]; ok {
		return existing
	}
	tr = p.base.Clone()
	p.transports[key] = tr
	return tr
}

// ForRequest returns the transport for the rewrite result that HandleRequest
// stored on the request context, or the base transport if there is none.
func (p *TransportPool) ForRequest(r *http.Request) *http.Transport {
	rw, ok := r.Context().Value(config.RewriteCtxKey).(RewriteResult)
	if !ok {
		return p.base
	}
	return p.For(rw)
}

// RoundTrip implements http.RoundTripper by dispatching to the transport that
// owns the request's rewrite target.
func (p *TransportPool) RoundTrip(r *http.Request) (*http.Response, error) {
	return p.ForRequest(r).RoundTrip(r)
}

// Reset drops every per-target transport and closes its idle connections.
//
// Call this after a config reload: rewrite targets may now point elsewhere, and
// pooled connections to the previous target would otherwise keep serving requests
// until IdleConnTimeout expires. In-flight requests are unaffected — they retain
// the connection they are already using.
func (p *TransportPool) Reset() {
	p.mu.Lock()
	old := p.transports
	p.transports = make(map[string]*http.Transport)
	p.mu.Unlock()

	for _, tr := range old {
		tr.CloseIdleConnections()
	}
	p.base.CloseIdleConnections()
}

// CloseIdleConnections closes idle connections on every pooled transport.
func (p *TransportPool) CloseIdleConnections() {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, tr := range p.transports {
		tr.CloseIdleConnections()
	}
	p.base.CloseIdleConnections()
}

// Ensure TransportPool satisfies the standard RoundTripper contract.
var _ http.RoundTripper = (*TransportPool)(nil)

// Len reports how many per-target transports exist, excluding the base.
// Exposed so pool growth is observable rather than being discovered through
// "cannot assign requested address".
func (p *TransportPool) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.transports)
}
