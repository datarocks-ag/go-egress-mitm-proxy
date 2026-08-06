// Copyright (c) 2026 Sebastian Schmelzer / Data Rocks AG.
// All rights reserved. Use of this source code is governed
// by a MIT license that can be found in the LICENSE file.
//
// Package main implements a MITM HTTP/HTTPS proxy with split-brain DNS capabilities.
//
// The proxy intercepts egress traffic and applies configurable policies:
//   - Domain rewriting: route specific domains to internal IP addresses
//   - ACL enforcement: whitelist/blacklist domains using regex patterns
//   - Header injection: add custom headers to rewritten requests
//
// Split-brain DNS is achieved at the TCP dial layer, not DNS level, allowing
// the proxy to route traffic to different IPs while preserving TLS SNI verification.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"go-egress-proxy/internal/cert"
	"go-egress-proxy/internal/config"
	"go-egress-proxy/internal/health"
	"go-egress-proxy/internal/metrics"
	"go-egress-proxy/internal/proxy"
	"go-egress-proxy/internal/trace"
)

// version is set at build time via -ldflags "-X main.version=<value>".
var version = "dev"

// shutdownTimeout bounds the drain period after SIGINT/SIGTERM.
const shutdownTimeout = 30 * time.Second

// defaultPreStopGrace is how long the proxy keeps serving after failing
// readiness and before it closes the listener, so load balancers notice and
// route away first. Sized at two probe intervals of the shipped Kubernetes
// manifest (5s). This plus shutdownTimeout must stay under
// terminationGracePeriodSeconds.
const defaultPreStopGrace = 10 * time.Second

// preStopGrace reads PROXY_PRESTOP_GRACE, so deployments that already sleep in a
// preStop hook can set it to 0 rather than paying the wait twice. Tests set it
// to 0 to avoid adding the delay to every container teardown.
func preStopGrace() time.Duration {
	raw := os.Getenv("PROXY_PRESTOP_GRACE")
	if raw == "" {
		return defaultPreStopGrace
	}
	d, err := time.ParseDuration(raw)
	switch {
	case err != nil:
		slog.Warn("Unparseable PROXY_PRESTOP_GRACE; using the default",
			"value", raw, "default", defaultPreStopGrace, "err", err)
		return defaultPreStopGrace
	case d < 0:
		slog.Warn("Negative PROXY_PRESTOP_GRACE; using the default",
			"value", raw, "default", defaultPreStopGrace)
		return defaultPreStopGrace
	}
	return d
}

// Outbound connection pool sizing. These apply per transport, and TransportPool
// clones the base transport once per distinct rewrite target.
const (
	maxIdleConnsPerTransport = 32
	maxIdleConnsPerHost      = 10
)

// slogProxyLogger adapts goproxy's Logger interface to route through slog.
type slogProxyLogger struct{}

func (l *slogProxyLogger) Printf(format string, v ...any) {
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		slog.Debug(fmt.Sprintf(format, v...), "source", "goproxy")
	}
}

// firstSetEnv returns the value of the first non-empty variable among names.
func firstSetEnv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: %s [flags] [command]

Commands:
  validate    Validate configuration file and exit
  gencert     Generate CA certificates (root or intermediate)

Flags:
  -h, --help      Show this help message
  --version       Print version and exit
  -v              Enable info logs (includes access logs)
  -vv             Debug output
  -vvv            Trace output (most verbose)

Default log level is warn (errors and warnings only).
Subcommands (validate, gencert) default to info for user-friendly output.

Environment:
  CONFIG_PATH     Path to config file (default: config.yaml)

Use "%s gencert --help" for certificate generation options.
`, os.Args[0], os.Args[0])
}

func main() {
	// Parse top-level flags from os.Args[1:]
	var (
		showVersion  bool
		showHelp     bool
		logLevel     = slog.LevelWarn
		verbositySet bool
	)
	var remaining []string
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--version":
			showVersion = true
		case "-h", "--help":
			showHelp = true
			remaining = append(remaining, arg) // pass through for subcommand help
		case "-vvv":
			if level := slog.Level(-8); !verbositySet || level < logLevel {
				logLevel = level // Trace: below slog.LevelDebug (-4)
			}
			verbositySet = true
		case "-vv":
			if !verbositySet || slog.LevelDebug < logLevel {
				logLevel = slog.LevelDebug
			}
			verbositySet = true
		case "-v":
			if !verbositySet || slog.LevelInfo < logLevel {
				logLevel = slog.LevelInfo
			}
			verbositySet = true
		default:
			remaining = append(remaining, arg)
		}
	}

	if showVersion {
		fmt.Println(version)
		return
	}
	// Show top-level help only when no subcommand is specified;
	// otherwise let the subcommand's FlagSet handle -h/--help.
	hasSubcommand := len(remaining) > 0 && (remaining[0] == "validate" || remaining[0] == "gencert")
	if showHelp && !hasSubcommand {
		printUsage()
		return
	}

	// Subcommands default to info for user-friendly output;
	// the proxy defaults to warn (quiet) unless verbosity is set explicitly.
	if !verbositySet && hasSubcommand {
		logLevel = slog.LevelInfo
	}

	// Initialize structured JSON logging with configured level
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	// Subcommand dispatch
	if len(remaining) > 0 && remaining[0] == "validate" {
		fs := flag.NewFlagSet("validate", flag.ExitOnError)
		configFlag := fs.String("config", "", "path to configuration file")
		if err := fs.Parse(remaining[1:]); err != nil {
			slog.Error("Failed to parse flags", "err", err)
			os.Exit(1)
		}

		configPath := *configFlag
		if configPath == "" {
			configPath = os.Getenv("CONFIG_PATH")
		}
		if configPath == "" {
			configPath = "config.yaml"
		}

		if err := config.RunValidate(configPath); err != nil {
			slog.Error("Configuration validation failed", "path", configPath, "err", err)
			os.Exit(1)
		}
		slog.Info("Configuration is valid", "path", configPath)
		return
	}

	if len(remaining) > 0 && remaining[0] == "gencert" {
		if err := cert.RunGencert(remaining[1:]); err != nil {
			slog.Error("Certificate generation failed", "err", err)
			os.Exit(1)
		}
		return
	}

	// Load configuration from file (path configurable via CONFIG_PATH env var)
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config.yaml"
	}

	// Initial config load
	cfg, acl, rewrites, err := config.LoadAndCompileConfig(configPath)
	if err != nil {
		slog.Error("Failed to load configuration", "path", configPath, "err", err)
		os.Exit(1)
	}

	// Open blocked request log (optional)
	blockedLogger, blockedFile, err := config.OpenBlockedLog(cfg.Proxy.BlockedLogPath)
	if err != nil {
		slog.Error("Failed to open blocked log", "path", cfg.Proxy.BlockedLogPath, "err", err)
		os.Exit(1)
	}

	// Build base TLS configuration for outbound connections. A configured CA
	// source that cannot be loaded is fatal: continuing would install a degraded
	// pool that fails every upstream verification with no clear cause.
	baseTLSConfig, err := cert.BuildOutboundTLSConfig(cfg)
	if err != nil {
		slog.Error("Failed to build outbound TLS configuration", "err", err)
		os.Exit(1)
	}

	// Initialize runtime config (thread-safe, reloadable)
	runtimeCfg := &config.RuntimeConfig{}
	_ = runtimeCfg.Update(cfg, acl, rewrites, baseTLSConfig, blockedLogger, blockedFile)

	// Compile selective-trace config and open its optional dedicated log file.
	compiledTrace, err := config.CompileTrace(cfg.Trace)
	if err != nil {
		slog.Error("Failed to compile trace configuration", "err", err)
		os.Exit(1)
	}
	traceLogger, traceFile, err := config.OpenTraceLog(cfg.Trace.LogPath)
	if err != nil {
		slog.Error("Failed to open trace log", "path", cfg.Trace.LogPath, "err", err)
		os.Exit(1)
	}
	_ = runtimeCfg.SetTrace(compiledTrace, traceLogger, traceFile)

	// Load MITM CA certificate and key for TLS interception
	if err := cert.LoadMITMCertificate(cfg); err != nil {
		slog.Error("Failed to load MITM certificate", "err", err)
		os.Exit(1)
	}

	// Log MITM CA certificate details
	cert.LogMITMCertInfo()

	// Initialize the proxy server
	proxyHandler := goproxy.NewProxyHttpServer()

	// NewProxyHttpServer sets ConnectDial from HTTP_PROXY/HTTPS_PROXY in the
	// environment. connectDial short-circuits to it, so with either variable set
	// no CONNECT ever reaches proxy.dial -- and therefore neither ctx.Dialer nor
	// MakeDialer runs: no target_ip substitution, no trace dialer, no dial
	// metrics, and NO_PROXY ignored. Plain HTTP meanwhile goes through
	// proxyHandler.Tr, which has no Proxy func, so the two paths diverge.
	//
	// Platform teams inject these cluster-wide routinely, and the symptom is
	// "rewrites stopped working on the new cluster" with nothing in the logs.
	// This proxy resolves its own upstreams; clear them and say so.
	if v := firstSetEnv("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"); v != "" {
		slog.Warn("Ignoring upstream proxy environment variables; this proxy dials upstreams directly",
			"value", v)
	}
	proxyHandler.ConnectDial = nil
	proxyHandler.ConnectDialWithReq = nil

	proxyHandler.Logger = &slogProxyLogger{}
	proxyHandler.Verbose = slog.Default().Enabled(context.Background(), slog.LevelDebug)

	// One bounded, TTL'd cache shared by both signing paths. Without it goproxy
	// re-signs on every CONNECT (a fresh RSA key pair each time for an RSA CA),
	// and the mitm_org path used an unbounded cache that never expired.
	certStore := cert.NewCertStore(cert.DefaultCertCacheSize, cert.DefaultCertTTL)
	proxyHandler.CertStore = certStore

	mitmAction := &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&goproxy.GoproxyCa),
	}
	if cfg.Proxy.MitmOrg != "" {
		mitmAction.TLSConfig = cert.MitmTLSConfigFromCA(&goproxy.GoproxyCa, cfg.Proxy.MitmOrg, certStore)
	}
	passthroughAction := &goproxy.ConnectAction{Action: goproxy.ConnectAccept}
	proxyHandler.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(
		func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
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

			decision := proxy.DecideConnect(hostname, currentACL)

			if decision == proxy.ConnectReject {
				requestID := proxy.GenerateRequestID()
				slog.Warn("BLACK-LISTED",
					"request_id", requestID,
					"host", hostname,
					"client", ctx.Req.RemoteAddr)
				metricDomain := proxy.NormalizeDomainForMetrics(hostname, rewriteExact, currentACL)
				metrics.TrafficTotal.WithLabelValues(metricDomain, "BLACK-LISTED").Inc()

				// A rejected tunnel never reaches HandleRequest, so this is the only
				// place the blocked-request audit log can learn about a blacklisted
				// HTTPS host. Without it the log silently omits all of them.
				proxy.LogBlocked(ctx.Req.Context(), runtimeCfg, proxy.BlockedRequest{
					RequestID: requestID,
					Client:    ctx.Req.RemoteAddr,
					Host:      hostname,
					Method:    ctx.Req.Method,
					// A CONNECT carries host:port as its request-target, not a path,
					// so URL.Path is empty here. Recording the authority keeps the
					// audit entry from losing the target.
					Target: host,
					Action: "BLACK-LISTED",
				})

				// goproxy writes ctx.Resp to the hijacked client connection when it is
				// set, and closes the socket silently when it is not. Leaving it unset
				// turned a documented 403 into "unexpected EOF" for every blacklisted
				// HTTPS host. NewResponse leaves the Proto fields zeroed, which would
				// serialize as "HTTP/0.0"; normalizing is what makes the status line
				// usable on a raw connection.
				//nolint:bodyclose // synthetic response; goproxy writes and closes it
				rejectResp := goproxy.NewResponse(ctx.Req,
					goproxy.ContentTypeText, http.StatusForbidden, "Policy Blocked")
				proxy.NormalizeResponseProto(rejectResp)
				ctx.Resp = rejectResp

				return goproxy.RejectConnect, host
			}

			// Passthrough: tunnel without MITM interception
			if decision == proxy.ConnectPassthrough {
				slog.Info("PASSTHROUGH",
					"host", hostname,
					"client", ctx.Req.RemoteAddr)
				metricDomain := proxy.NormalizeDomainForMetrics(hostname, rewriteExact, currentACL)
				metrics.TrafficTotal.WithLabelValues(metricDomain, "PASSTHROUGH").Inc()

				// Passthrough tunnels are not MITM'd, so only the TCP layer is
				// observable. When a host-based trace rule matches, wire a tracing
				// dialer that records the connected IP, timing, and byte counts.
				if ct, _ := runtimeCfg.GetTrace(); ct.Enabled {
					if rule := ct.Match(hostname, "", false); rule != nil {
						// Resolved at emit time: a passthrough record is written when
						// the tunnel closes, which can be long after a SIGHUP rotated
						// the trace log and closed the handle this captured.
						rec := trace.NewRecord(proxy.GenerateRequestID(), "passthrough", rule,
							trace.NewRedactor(ct), func() *slog.Logger {
								_, l := runtimeCfg.GetTrace()
								return l
							})
						rec.SetConnect(host, hostname)
						ctx.UserData = rec
						// Decorate the production dialer rather than replacing it, so a
						// traced passthrough host keeps its rewrite target and its dial
						// error metrics.
						ctx.Dialer = trace.PassthroughDialer(rec, proxy.MakeDialer(runtimeCfg))
					}
				}
				return passthroughAction, host
			}

			return mitmAction, host
		}))

	// Configure the outbound HTTP transport with connection pooling and TLS settings.
	// DialTLSContext handles per-connection TLS with rewrite-specific InsecureSkipVerify.
	// ForceAttemptHTTP2 enables Go's built-in HTTP/2 when custom dial functions are set.
	//
	// MaxIdleConns is per-transport, and TransportPool clones this one per rewrite
	// target, so the process-wide idle ceiling is (targets + 1) x MaxIdleConns.
	// Sized per transport accordingly rather than leaving a global figure to
	// multiply.
	//
	// MaxConnsPerHost is deliberately NOT set. It bounds the wrong key and buys
	// the bound with unbounded latency:
	//
	//   - Go keys connsPerHost on the *request URL* host:port, computed before the
	//     dialer substitutes target_ip, and TransportPool clones per target. So N
	//     rewritten hostnames still permit N x limit sockets to one upstream IP --
	//     the ephemeral-port case a previous comment here claimed it covered is
	//     the one case it does not.
	//   - When the cap is reached, queueForConn parks the request and the only
	//     escape is req.Context().Done(). goproxy builds MITM requests over
	//     context.Background() with a bare WithCancel, so there is no deadline,
	//     and ResponseHeaderTimeout does not bound body streaming. A handful of
	//     large concurrent downloads from one registry would block the next client
	//     indefinitely, holding its tunnel and listener slot, with no queue-depth
	//     metric and no log line.
	//
	// A correct per-target bound has to live in the dialer, where the real dial
	// address is known, and has to fail fast rather than queue. That is not
	// implemented; TransportPool.Len() at least makes pool growth observable.
	proxyHandler.Tr = proxy.NewOutboundTransport(baseTLSConfig, runtimeCfg, proxy.OutboundTransportOptions{
		MaxIdleConns:          maxIdleConnsPerTransport,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	})

	// Give each rewrite target its own connection pool. Go keys idle connections on
	// the request URL's host:port, which is computed before our dialers substitute
	// the target address, so a single transport would let rules for the same domain
	// reuse each other's connections. See proxy.TransportPool.
	//
	transportPool := proxy.NewTransportPool(proxyHandler.Tr)

	// Register the request handler for policy enforcement
	proxyHandler.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// Wrap the transport to convert errors into synthetic HTTP responses.
		// goproxy's MITM handler drops the connection on RoundTrip errors without
		// writing a response (causing EOF on the client). By catching errors here
		// and returning synthetic 502/504 responses, the MITM handler writes them
		// to the client normally.
		//
		// The pool dispatches on the rewrite result that HandleRequest stores on the
		// request context, so req here is the post-handler request, not r.
		ctx.RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
			resp, err := transportPool.RoundTrip(req)

			// Timed here, not in HandleRequest: this span covers DNS, dial, TLS
			// handshake and upstream think-time, which is what request latency
			// means. The handler returns before any of it happens.
			proxy.ObserveRequestDuration(req)

			if err != nil {
				status, reason := proxy.UpstreamErrorResponse(err)
				slog.Warn("Upstream connection error",
					"host", req.URL.Host,
					"status", status,
					"err", err)
				return goproxy.NewResponse(req,
					goproxy.ContentTypeText,
					status,
					reason), nil
			}
			return resp, nil
		})
		return proxy.HandleRequest(r, ctx, runtimeCfg)
	})

	// Register response handler for metrics and upstream error handling
	proxyHandler.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		var rec *trace.Record
		if v, ok := ctx.UserData.(*trace.Record); ok {
			rec = v
		}
		if resp != nil {
			proxy.NormalizeResponseProto(resp)
			proxy.RecordResponseMetrics(resp)
			if rec != nil {
				trace.PrepareResponse(rec, resp)
			}
			return resp
		}
		if ctx.Error != nil {
			status, reason := proxy.UpstreamErrorResponse(ctx.Error)
			slog.Warn("Upstream connection error",
				"host", ctx.Req.URL.Host,
				"status", status,
				"err", ctx.Error)
			errResp := goproxy.NewResponse(ctx.Req,
				goproxy.ContentTypeText,
				status,
				reason)
			proxy.NormalizeResponseProto(errResp)
			if rec != nil {
				rec.SetError(ctx.Error.Error())
				trace.PrepareResponse(rec, errResp)
			}
			return errResp
		}
		if rec != nil {
			rec.Emit()
		}
		return resp
	})

	// Handle CONNECT-level upstream errors with proper status codes instead of default 502
	proxyHandler.ConnectionErrHandler = func(w io.Writer, ctx *goproxy.ProxyCtx, err error) {
		status, reason := proxy.UpstreamErrorResponse(err)
		slog.Warn("Upstream connection error",
			"host", ctx.Req.Host,
			"status", status,
			"err", err)
		errStr := fmt.Sprintf(
			"HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
			status, reason,
			len(reason),
			reason,
		)
		io.WriteString(w, errStr) //nolint:errcheck // best-effort response to client
	}

	// Setup metrics and health endpoints
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsMux.HandleFunc("/healthz", health.HealthHandler)
	metricsMux.HandleFunc("/readyz", health.ReadyHandler)

	metricsServer := &http.Server{
		Addr:         ":" + cfg.Proxy.MetricsPort,
		Handler:      metricsMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	// A forward proxy streams arbitrary bodies, so whole-request deadlines are the
	// wrong shape. ReadTimeout/WriteTimeout are absolute, armed when the request
	// line is read, and hijackLocked clears the deadline on hijack -- so every
	// CONNECT tunnel (all HTTPS, MITM and passthrough) was exempt while plain HTTP
	// was severed at 60s mid-body. A large package download over HTTP was cut; the
	// identical request over HTTPS was unbounded. Nobody would predict that from
	// the config.
	//
	// ReadHeaderTimeout keeps slowloris protection without capping body transfer,
	// and IdleTimeout bounds keep-alive connections.
	//
	// Known gap: a client that streams a body slowly but steadily is not bounded
	// by time. That is inherent -- any deadline large enough for a legitimate
	// multi-gigabyte transfer is also large enough for a slow sender, and this is
	// a proxy for arbitrary payloads. Two things that look like fixes are not:
	// re-adding an absolute ReadTimeout severs legitimate long transfers (the bug
	// this replaced), and refreshing a deadline per read from a wrapped
	// net.Conn overrides the header deadline http.Server sets on the same
	// connection (server.go SetReadDeadline(hdrDeadline)), silently disabling the
	// slowloris protection above. Bounding concurrent client connections is the
	// lever that actually applies here, and is left as a deployment concern.
	proxyServer := &http.Server{
		Addr:              ":" + cfg.Proxy.Port,
		Handler:           proxyHandler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Bind the metrics port before backgrounding the server, and treat a bind
	// failure as fatal like every other startup dependency.
	//
	// ListenAndServe inside a bare goroutine meant a port collision only logged:
	// the proxy still bound, still called SetReady, and served with /healthz,
	// /readyz and /metrics all unreachable — so the readiness mechanism was inert
	// and the pod sat NotReady with nothing obviously wrong in the logs. That
	// "running, healthy-looking, receiving no traffic" state is exactly what the
	// readiness work exists to prevent.
	metricsLn, metricsErr := (&net.ListenConfig{}).Listen(context.Background(), "tcp", metricsServer.Addr)
	if metricsErr != nil {
		slog.Error("Failed to bind metrics port", "addr", metricsServer.Addr, "err", metricsErr)
		os.Exit(1)
	}

	go func() {
		slog.Info("Metrics server starting", "port", cfg.Proxy.MetricsPort)
		if err := metricsServer.Serve(metricsLn); err != nil && err != http.ErrServerClosed {
			slog.Error("Metrics server error", "err", err)
		}
	}()

	// Setup signal handling for graceful shutdown and config reload
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// SIGHUP handler for config reload
	sighupChan := make(chan os.Signal, 1)
	signal.Notify(sighupChan, syscall.SIGHUP)

	go watchSIGHUP(sighupChan, reloadDeps{
		configPath: configPath,
		runtimeCfg: runtimeCfg,
		pool:       transportPool,
	})

	// Bind the proxy listener explicitly so client connections can be tracked.
	// http.Server cannot drain them itself: goproxy hijacks the connection for
	// every CONNECT and the server stops tracking hijacked connections, so
	// Shutdown would return instantly with tunnels still live.
	proxyLn, lnErr := (&net.ListenConfig{}).Listen(context.Background(), "tcp", proxyServer.Addr)
	if lnErr != nil {
		slog.Error("Failed to bind proxy port", "addr", proxyServer.Addr, "err", lnErr)
		os.Exit(1)
	}
	trackedLn := proxy.NewTrackingListener(proxyLn)

	// Publish the live client-connection count. This is the number the old
	// proxy_active_connections gauge was meant to report; it previously
	// bracketed the OnRequest filter and read ~0 at every scrape.
	metrics.RegisterActiveConnections(func() float64 { return float64(trackedLn.Open()) })

	// Closed when the drain finishes, so main waits for it instead of exiting
	// mid-drain. Shutdown closes listeners first, which unblocks Serve on the
	// main goroutine; without this join the process died before the drain ran.
	shutdownDone := make(chan struct{})

	// Graceful shutdown handler
	go func() {
		defer close(shutdownDone)

		<-ctx.Done()
		slog.Info("Shutdown signal received, draining connections...")

		// Fail readiness first, then keep serving for a moment before closing the
		// listener.
		//
		// Failing readiness and shutting down in the same instant achieves
		// nothing: a load balancer only stops routing here once its next probe
		// fails, and Shutdown closes the listener immediately, so clients get
		// ECONNREFUSED for a probe period or two. Only connections already
		// accepted benefited from the drain. Serving through one full probe
		// interval is what actually lets traffic move away first.
		//
		// Deployments with a preStop hook (sleep, then SIGTERM) can set this to
		// zero; the shipped Kubernetes manifest has no hook and probes every 5s,
		// so the default covers two intervals. It is inside
		// terminationGracePeriodSeconds together with the drain budget.
		health.SetNotReady()
		if grace := preStopGrace(); grace > 0 {
			slog.Info("Readiness failed; serving briefly so traffic can move away",
				"grace", grace)
			time.Sleep(grace)
		}

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := proxyServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("Proxy server shutdown error", "err", err)
		}

		// Shutdown has stopped accepting and drained non-hijacked connections;
		// wait out the tunnels it cannot see, within the same budget.
		if open := trackedLn.Open(); open > 0 {
			slog.Info("Waiting for tunnels to close", "open_connections", open)
			if !trackedLn.WaitForDrain(shutdownCtx) {
				slog.Warn("Drain deadline reached with connections still open",
					"open_connections", trackedLn.Open(),
					"timeout", shutdownTimeout)
			}
		}

		// Its own context: after a timed-out drain shutdownCtx is already expired,
		// so reusing it made every timed-out drain also log a spurious metrics
		// shutdown error.
		metricsCtx, cancelMetrics := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelMetrics()
		if err := metricsServer.Shutdown(metricsCtx); err != nil {
			slog.Error("Metrics server shutdown error", "err", err)
		}
		runtimeCfg.CloseBlockedLog()
		runtimeCfg.CloseTraceLog()
	}()

	// Start the proxy server
	slog.Info("Proxy server starting",
		"port", cfg.Proxy.Port,
		"metrics_port", cfg.Proxy.MetricsPort,
		"default_policy", cfg.Proxy.DefaultPolicy,
		"rewrites", len(rewrites),
		"whitelist_rules", len(acl.Whitelist),
		"blacklist_rules", len(acl.Blacklist),
		"passthrough_rules", len(acl.Passthrough),
		"outgoing_ca_bundle", cfg.Proxy.OutgoingCABundle,
		"outgoing_truststore_path", cfg.Proxy.OutgoingTruststorePath,
		"insecure_skip_verify", cfg.Proxy.InsecureSkipVerify,
		"blocked_log_path", cfg.Proxy.BlockedLogPath)

	health.SetReady()

	if serveErr := proxyServer.Serve(trackedLn); serveErr != nil && serveErr != http.ErrServerClosed {
		health.SetNotReady()
		slog.Error("Proxy server error", "err", serveErr)
		os.Exit(1)
	}

	// Serve returns as soon as Shutdown closes the listener, so wait for the
	// drain to finish rather than exiting underneath it.
	<-shutdownDone

	slog.Info("Proxy server stopped")
}
