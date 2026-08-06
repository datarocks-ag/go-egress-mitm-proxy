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

// LoggerFunc resolves the destination logger at emit time.
//
// A Record can outlive the configuration it was created under: a passthrough
// record emits from countingConn.Close, which may be hours after the tunnel
// opened. SIGHUP rotates the trace log and closes the previous file handle, so a
// Record holding a captured *slog.Logger would write to a closed descriptor.
// slog discards handler errors, so the record would vanish with no diagnostic —
// on precisely the code path rotation exists for. Resolving late means a record
// emitted after a rotation lands in the current file.
type LoggerFunc func() *slog.Logger

// StaticLogger adapts a fixed logger for callers with no rotation concern.
func StaticLogger(l *slog.Logger) LoggerFunc {
	return func() *slog.Logger { return l }
}

// Record accumulates the full trace of a single request or passthrough tunnel
// and emits it exactly once as an aggregated JSON log entry.
type Record struct {
	logger   LoggerFunc
	bodies   config.CompiledBodyCapture
	redactor Redactor
	once     sync.Once

	traceID string
	mode    string // "mitm" or "passthrough"

	connectHost string
	sni         string

	// mu guards the fields the dialer writes. http.Transport dials on its own
	// goroutine (go t.dialConnFor(w)); when the request goroutine is instead
	// satisfied by a freed idle connection, the abandoned dial keeps running and
	// still calls SetTCP/SetError — potentially while the request goroutine is
	// already emitting. Request cancellation produces the same overlap.
	// bytesUp/bytesDown are atomics for the equivalent reason on the tunnel path.
	mu          sync.Mutex
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
	modified      []string
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
func NewRecord(traceID, mode string, rule *config.CompiledTraceRule, redactor Redactor, logger LoggerFunc) *Record {
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
	r.mu.Lock()
	defer r.mu.Unlock()

	// An abandoned dial can still be running after the request goroutine was
	// satisfied by a pooled connection and applyResponse concluded the connection
	// was reused. Accepting its values here would emit a record claiming both
	// connection_reused and a connected_ip, describing a connection this request
	// never used.
	if r.connReused {
		return
	}

	r.connectedIP = connectedIP
	r.dialMillis = dialDur.Milliseconds()
	r.tlsVersion = tlsVersion
	r.tlsCipher = tlsCipher
}

// SetError records an upstream/dial error for the trace.
func (r *Record) SetError(msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Same reasoning as SetTCP: a dial abandoned after the request completed on a
	// pooled connection must not attach its failure to a request that succeeded.
	if r.connReused {
		return
	}

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

// SetRequestOut captures the outbound request headers after drop/inject/scheme
// rewriting. added are headers newly introduced; modified are injected headers
// that overwrote an existing client value.
func (r *Record) SetRequestOut(req *http.Request, dropped, added, modified []string, schemeChanged string) {
	r.reqHeadersOut = r.redactor.headerMap(req.Header)
	r.dropped = dropped
	r.added = added
	r.modified = modified
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
	r.mu.Lock()
	if r.mode == "mitm" && r.connectedIP == "" && r.errMsg == "" {
		r.connReused = true
	}
	r.mu.Unlock()

	// Wrap the body only when bytes actually need teeing.
	//
	// goproxy compares resp.Body against the original to decide whether a handler
	// modified the response (https.go:518-527); when they differ it clears
	// Content-Length and forces chunked transfer encoding. Wrapping
	// unconditionally — purely to get a Close hook for Emit — therefore re-framed
	// every traced response, turning an observability switch into something that
	// changes the bytes the client receives. For a 204/304 it was worse: Go leaves
	// resp.Body as http.NoBody, the wrapper hid that, and the response went out
	// chunked in violation of RFC 9110.
	//
	// With capture off there is nothing to tee, so emit at header time.
	//
	// Nothing is lost by that in MITM mode: no Record field is populated after
	// the response headers. SetTCP and SetRequestIn/Out have already run,
	// addUp/addDown are passthrough-only, and no caller records an error once the
	// response has arrived. The record would be byte-identical either way -- the
	// wrapper existed only to delay the write. What it does mean is that these
	// records are emitted before the response body finishes streaming, so a
	// failure that occurs mid-body is not reflected; enable body capture for the
	// rule if that matters.
	// A 101 is not a body at all: goproxy hands the upgraded connection to the
	// client by asserting resp.Body.(io.ReadWriter) (https.go:550). Wrapping it
	// leaves only Read and Close, the assertion fails, and goproxy drops the
	// tunnel with a debug-level warning — so enabling body capture on a rule
	// silently broke every MITM WebSocket upgrade to that host. It also tripped
	// the same chunked re-framing this guard exists to prevent.
	if resp.Body == nil || resp.Body == http.NoBody ||
		resp.StatusCode == http.StatusSwitchingProtocols || !r.CaptureResponseBody() {
		r.Emit()
		return
	}

	r.respBody = &bodyBuffer{max: r.bodies.MaxResponseBytes}
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
	var logger *slog.Logger
	if r.logger != nil {
		logger = r.logger()
	}
	if logger == nil {
		logger = slog.Default()
	}

	attrs := []any{
		slog.String("trace_id", r.traceID),
		slog.String("mode", r.mode),
	}

	connect := []any{slog.String("host", r.connectHost)}
	if r.sni != "" {
		connect = append(connect, slog.String("sni", r.sni))
	}
	attrs = append(attrs, slog.Group("connect", connect...))

	// Snapshot under the lock: an abandoned dial may still be writing these.
	r.mu.Lock()
	connectedIP, dialMillis := r.connectedIP, r.dialMillis
	connReused, tlsVersion, tlsCipher := r.connReused, r.tlsVersion, r.tlsCipher
	errMsg := r.errMsg
	r.mu.Unlock()

	tcp := []any{}
	if connectedIP != "" {
		tcp = append(tcp, slog.String("connected_ip", connectedIP))
		tcp = append(tcp, slog.Int64("dial_ms", dialMillis))
	}
	if connReused {
		tcp = append(tcp, slog.Bool("connection_reused", true))
	}
	if tlsVersion != "" {
		tcp = append(tcp, slog.String("tls_version", tlsVersion), slog.String("tls_cipher", tlsCipher))
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
		if len(r.modified) > 0 {
			req = append(req, slog.Any("modified", r.modified))
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

	if errMsg != "" {
		attrs = append(attrs, slog.String("error", errMsg))
	}

	logger.LogAttrs(context.Background(), slog.LevelInfo, "trace", toAttrs(attrs)...)

	// Counted after the write, not before. slog discards handler errors so this
	// cannot detect a failed write, but incrementing first guaranteed the counter
	// and the file diverged whenever a write did not land.
	metrics.TraceRecords.WithLabelValues(r.mode).Inc()
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
//
// Access is mutex-guarded because the two ends genuinely run on different
// goroutines: http.Transport writes the request body from its writeLoop, while
// Emit — triggered by the response body closing — renders that same buffer. A
// server that answers before consuming the upload (an early 4xx, or any large
// streamed request) overlaps the two.
type bodyBuffer struct {
	mu        sync.Mutex
	max       int
	buf       bytes.Buffer
	total     int64
	truncated bool
}

func (b *bodyBuffer) write(p []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()

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
	// Snapshot under the lock; the writer may still be appending.
	b.mu.Lock()
	total, truncated := b.total, b.truncated
	data := bytes.Clone(b.buf.Bytes())
	b.mu.Unlock()

	out := map[string]any{"bytes": total}
	if truncated {
		out["truncated"] = true
	}
	if len(data) == 0 {
		return out
	}
	if contentTypeAllowed(contentType, cfg.ContentTypes) {
		// Truncation may have cut a multi-byte rune in half; drop the trailing
		// partial rune so allowed text content is still emitted as text.
		text := data
		if !utf8.Valid(text) {
			text = trimPartialRune(text)
		}
		if utf8.Valid(text) {
			out["text"] = string(text)
			return out
		}
	}
	if cfg.OnBinary == "base64" {
		out["base64"] = base64.StdEncoding.EncodeToString(data)
	} else {
		out["skipped"] = "binary"
	}
	return out
}

// trimPartialRune drops up to utf8.UTFMax-1 trailing bytes that form an
// incomplete UTF-8 rune (e.g. a character cut by body truncation), returning
// the longest valid-UTF-8 prefix reachable that way.
func trimPartialRune(b []byte) []byte {
	for i := 0; i < utf8.UTFMax-1 && len(b) > 0; i++ {
		b = b[:len(b)-1]
		if utf8.Valid(b) {
			return b
		}
	}
	return b
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
