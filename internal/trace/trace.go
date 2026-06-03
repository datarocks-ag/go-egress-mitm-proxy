// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.

// Package trace provides selective, full-detail request tracing. When a request
// matches a configured trace rule, every layer (TCP/TLS, request, response, and
// optionally bodies) is accumulated into a single Record and emitted as one
// aggregated JSON log entry keyed by the request's trace_id.
package trace

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"go-egress-proxy/internal/config"
	"go-egress-proxy/internal/metrics"
)

// ctxKeyType is an unexported context key type to avoid collisions.
type ctxKeyType struct{}

// CtxKey carries the active *Record from the request handler down to the dialers,
// which only receive a context.Context (not the goproxy ProxyCtx).
var CtxKey = ctxKeyType{}

// FromContext returns the trace Record stored in ctx, or nil.
func FromContext(ctx context.Context) *Record {
	rec, ok := ctx.Value(CtxKey).(*Record)
	if !ok {
		return nil
	}
	return rec
}

// Redactor masks sensitive headers and query values unless logging secrets is enabled.
type Redactor struct {
	headers map[string]bool
	query   bool
	logRaw  bool
}

// NewRedactor builds a Redactor from compiled trace config.
func NewRedactor(ct config.CompiledTrace) Redactor {
	return Redactor{headers: ct.RedactHeaders, query: ct.RedactQuery, logRaw: ct.LogSecrets}
}

func (rd Redactor) headerValue(name, value string) string {
	if rd.logRaw {
		return value
	}
	if rd.headers[strings.ToLower(name)] {
		return "<redacted>"
	}
	return value
}

// headerMap converts an http.Header to a flat, redacted map for logging.
func (rd Redactor) headerMap(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, v := range h {
		m[k] = rd.headerValue(k, strings.Join(v, ", "))
	}
	return m
}

// redactURL masks query-string values while preserving keys.
func (rd Redactor) redactURL(raw string) string {
	if rd.logRaw || !rd.query {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		return raw
	}
	q := u.Query()
	for k := range q {
		q[k] = []string{"<redacted>"}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// Record accumulates the full trace of a single request or passthrough tunnel
// and emits it exactly once as an aggregated JSON log entry.
type Record struct {
	logger   *slog.Logger
	bodies   config.CompiledBodyCapture
	redactor Redactor
	once     sync.Once

	traceID string
	mode    string // "mitm" or "passthrough"

	connectHost string
	sni         string

	connectedIP string
	dialMillis  int64
	connReused  bool
	tlsVersion  string
	tlsCipher   string
	bytesUp     atomic.Int64
	bytesDown   atomic.Int64

	method        string
	url           string
	proto         string
	reqHeadersIn  map[string]string
	reqHeadersOut map[string]string
	dropped       []string
	added         []string
	schemeChanged string
	reqBody       *bodyBuffer
	reqCT         string

	status      int
	respProto   string
	respHeaders map[string]string
	respBody    *bodyBuffer
	respCT      string

	errMsg string
}

// NewRecord creates a trace Record. logger may be nil, in which case the
// aggregated entry is emitted via the default slog logger.
func NewRecord(traceID, mode string, rule *config.CompiledTraceRule, redactor Redactor, logger *slog.Logger) *Record {
	rec := &Record{
		logger:   logger,
		redactor: redactor,
		traceID:  traceID,
		mode:     mode,
	}
	if rule != nil {
		rec.bodies = rule.Bodies
	}
	return rec
}

// SetConnect records the CONNECT/host and SNI for the request.
func (r *Record) SetConnect(host, sni string) {
	r.connectHost = host
	r.sni = sni
}

// SetTCP records the established connection's resolved IP, dial duration, and TLS details.
func (r *Record) SetTCP(connectedIP string, dialDur time.Duration, tlsVersion, tlsCipher string) {
	r.connectedIP = connectedIP
	r.dialMillis = dialDur.Milliseconds()
	r.tlsVersion = tlsVersion
	r.tlsCipher = tlsCipher
}

// SetError records an upstream/dial error for the trace.
func (r *Record) SetError(msg string) {
	r.errMsg = msg
}

// SetRequestIn captures the inbound (client) request line and headers.
// Call before any header mutation so the snapshot reflects what the client sent.
func (r *Record) SetRequestIn(req *http.Request) {
	r.method = req.Method
	r.url = r.redactor.redactURL(req.URL.String())
	r.proto = req.Proto
	r.reqHeadersIn = r.redactor.headerMap(req.Header)
	r.reqCT = req.Header.Get("Content-Type")
}

// SetRequestOut captures the outbound request headers after drop/inject/scheme rewriting.
func (r *Record) SetRequestOut(req *http.Request, dropped, added []string, schemeChanged string) {
	r.reqHeadersOut = r.redactor.headerMap(req.Header)
	r.dropped = dropped
	r.added = added
	r.schemeChanged = schemeChanged
}

// WrapRequestBody tees the request body into the trace buffer (up to the configured
// cap) while leaving it fully readable for forwarding. No-op when request body
// capture is disabled or the request has no body.
func (r *Record) WrapRequestBody(req *http.Request) {
	if !r.bodies.Enabled || !r.bodies.CaptureRequest || req.Body == nil || req.Body == http.NoBody {
		return
	}
	r.reqBody = &bodyBuffer{max: r.bodies.MaxRequestBytes}
	req.Body = &captureReadCloser{rc: req.Body, buf: r.reqBody}
}

// CaptureResponseBody reports whether response bodies should be teed for this trace.
func (r *Record) CaptureResponseBody() bool {
	return r.bodies.Enabled && r.bodies.CaptureResponse
}

// applyResponse records response status/headers and (when enabled) wraps the body
// so the aggregated record is emitted once the body is fully streamed.
func (r *Record) applyResponse(resp *http.Response) {
	r.status = resp.StatusCode
	r.respProto = resp.Proto
	r.respHeaders = r.redactor.headerMap(resp.Header)
	r.respCT = resp.Header.Get("Content-Type")

	// A MITM response with no recorded dial means the upstream connection was
	// reused from the pool; its remote IP is not observable for this request.
	if r.mode == "mitm" && r.connectedIP == "" && r.errMsg == "" {
		r.connReused = true
	}

	// Always wrap the body so the aggregated record is emitted once the response
	// finishes streaming; tee bytes only when body capture is enabled.
	if resp.Body == nil {
		r.Emit()
		return
	}
	if r.CaptureResponseBody() {
		r.respBody = &bodyBuffer{max: r.bodies.MaxResponseBytes}
	}
	resp.Body = &captureReadCloser{rc: resp.Body, buf: r.respBody, onClose: r.Emit}
}

// PrepareResponse records response metadata and arranges for the aggregated
// trace record to be emitted when the response body finishes streaming.
func PrepareResponse(rec *Record, resp *http.Response) {
	rec.applyResponse(resp)
}

// AddBytes accumulates passthrough tunnel byte counts (safe for concurrent copy goroutines).
func (r *Record) addUp(n int64)   { r.bytesUp.Add(n) }
func (r *Record) addDown(n int64) { r.bytesDown.Add(n) }

// Emit writes the aggregated trace record exactly once.
func (r *Record) Emit() {
	r.once.Do(r.emit)
}

func (r *Record) emit() {
	logger := r.logger
	if logger == nil {
		logger = slog.Default()
	}
	metrics.TraceRecords.WithLabelValues(r.mode).Inc()

	attrs := []any{
		slog.String("trace_id", r.traceID),
		slog.String("mode", r.mode),
	}

	connect := []any{slog.String("host", r.connectHost)}
	if r.sni != "" {
		connect = append(connect, slog.String("sni", r.sni))
	}
	attrs = append(attrs, slog.Group("connect", connect...))

	tcp := []any{}
	if r.connectedIP != "" {
		tcp = append(tcp, slog.String("connected_ip", r.connectedIP))
		tcp = append(tcp, slog.Int64("dial_ms", r.dialMillis))
	}
	if r.connReused {
		tcp = append(tcp, slog.Bool("connection_reused", true))
	}
	if r.tlsVersion != "" {
		tcp = append(tcp, slog.String("tls_version", r.tlsVersion), slog.String("tls_cipher", r.tlsCipher))
	}
	if up, down := r.bytesUp.Load(), r.bytesDown.Load(); up != 0 || down != 0 {
		tcp = append(tcp, slog.Int64("bytes_up", up), slog.Int64("bytes_down", down))
	}
	if len(tcp) > 0 {
		attrs = append(attrs, slog.Group("tcp", tcp...))
	}

	if r.method != "" || r.reqHeadersIn != nil {
		req := []any{
			slog.String("method", r.method),
			slog.String("url", r.url),
			slog.String("proto", r.proto),
			slog.Any("headers_in", r.reqHeadersIn),
		}
		if r.reqHeadersOut != nil {
			req = append(req, slog.Any("headers_out", r.reqHeadersOut))
		}
		if len(r.dropped) > 0 {
			req = append(req, slog.Any("dropped", r.dropped))
		}
		if len(r.added) > 0 {
			req = append(req, slog.Any("added", r.added))
		}
		if r.schemeChanged != "" {
			req = append(req, slog.String("scheme_changed", r.schemeChanged))
		}
		if body := renderBody(r.reqBody, r.reqCT, r.bodies); body != nil {
			req = append(req, slog.Any("body", body))
		}
		attrs = append(attrs, slog.Group("request", req...))
	}

	if r.status != 0 {
		resp := []any{
			slog.Int("status", r.status),
			slog.String("proto", r.respProto),
			slog.Any("headers", r.respHeaders),
		}
		if body := renderBody(r.respBody, r.respCT, r.bodies); body != nil {
			resp = append(resp, slog.Any("body", body))
		}
		attrs = append(attrs, slog.Group("response", resp...))
	}

	if r.errMsg != "" {
		attrs = append(attrs, slog.String("error", r.errMsg))
	}

	logger.LogAttrs(context.Background(), slog.LevelInfo, "trace", toAttrs(attrs)...)
}

// toAttrs converts a slice that already holds slog.Attr values into []slog.Attr.
func toAttrs(args []any) []slog.Attr {
	out := make([]slog.Attr, 0, len(args))
	for _, a := range args {
		if attr, ok := a.(slog.Attr); ok {
			out = append(out, attr)
		}
	}
	return out
}

// bodyBuffer captures up to max bytes of a body while counting the total seen.
type bodyBuffer struct {
	max       int
	buf       bytes.Buffer
	total     int64
	truncated bool
}

func (b *bodyBuffer) write(p []byte) {
	if remaining := b.max - b.buf.Len(); remaining > 0 {
		n := len(p)
		if n > remaining {
			n = remaining
		}
		b.buf.Write(p[:n])
	}
	b.total += int64(len(p))
	if b.total > int64(b.buf.Len()) {
		b.truncated = true
	}
}

// captureReadCloser tees reads into a bodyBuffer and runs onClose after the
// underlying body is closed (used to emit the aggregated record on response end).
type captureReadCloser struct {
	rc      io.ReadCloser
	buf     *bodyBuffer
	onClose func()
}

func (c *captureReadCloser) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 && c.buf != nil {
		c.buf.write(p[:n])
	}
	return n, err
}

func (c *captureReadCloser) Close() error {
	err := c.rc.Close()
	if c.onClose != nil {
		c.onClose()
	}
	return err
}

// renderBody builds the JSON-able body representation, choosing text/base64/skip
// based on content type and the on_binary policy.
func renderBody(b *bodyBuffer, contentType string, cfg config.CompiledBodyCapture) map[string]any {
	if b == nil {
		return nil
	}
	out := map[string]any{"bytes": b.total}
	if b.truncated {
		out["truncated"] = true
	}
	data := b.buf.Bytes()
	if len(data) == 0 {
		return out
	}
	if contentTypeAllowed(contentType, cfg.ContentTypes) && utf8.Valid(data) {
		out["text"] = string(data)
	} else if cfg.OnBinary == "base64" {
		out["base64"] = base64.StdEncoding.EncodeToString(data)
	} else {
		out["skipped"] = "binary"
	}
	return out
}

// contentTypeAllowed reports whether a Content-Type matches the allowlist,
// supporting "type/*" suffix wildcards. The parameter part (after ";") is ignored.
func contentTypeAllowed(contentType string, allow []string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct == "" {
		return false
	}
	for _, a := range allow {
		if strings.HasSuffix(a, "/*") {
			if strings.HasPrefix(ct, strings.TrimSuffix(a, "*")) {
				return true
			}
		} else if ct == a {
			return true
		}
	}
	return false
}
