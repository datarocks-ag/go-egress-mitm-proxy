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

// slogProxyLogger adapts goproxy's Logger interface to route through slog.
type slogProxyLogger struct{}

func (l *slogProxyLogger) Printf(format string, v ...any) {
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		slog.Debug(fmt.Sprintf(format, v...), "source", "goproxy")
	}
}

// normalizeResponseProto forces HTTP/1.1 framing so goproxy's resp.Write()
// never serializes an unusable status line. Two cases need fixing:
//  1. goproxy.NewResponse() leaves Proto fields at zero → "HTTP/0.0"
//  2. Upstream HTTP/2 responses have Proto "HTTP/2.0"
//
// Both cause "Unsupported HTTP version" errors in clients on MITM tunnels.
func normalizeResponseProto(resp *http.Response) {
	if resp.ProtoMajor != 1 {
		resp.Proto = "HTTP/1.1"
		resp.ProtoMajor = 1
		resp.ProtoMinor = 1
	}
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

	// Build base TLS configuration for outbound connections.
	baseTLSConfig := cert.BuildOutboundTLSConfig(cfg)

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
	proxyHandler.Logger = &slogProxyLogger{}
	proxyHandler.Verbose = slog.Default().Enabled(context.Background(), slog.LevelDebug)

	mitmAction := &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(&goproxy.GoproxyCa),
	}
	if cfg.Proxy.MitmOrg != "" {
		mitmAction.TLSConfig = cert.MitmTLSConfigFromCA(&goproxy.GoproxyCa, cfg.Proxy.MitmOrg)
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
				slog.Warn("BLACK-LISTED",
					"host", hostname,
					"client", ctx.Req.RemoteAddr)
				metricDomain := proxy.NormalizeDomainForMetrics(hostname, rewriteExact, currentACL)
				metrics.TrafficTotal.WithLabelValues(metricDomain, "BLACK-LISTED").Inc()
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
				if ct, traceLogger := runtimeCfg.GetTrace(); ct.Enabled {
					if rule := ct.Match(hostname, "", false); rule != nil {
						rec := trace.NewRecord(proxy.GenerateRequestID(), "passthrough", rule, trace.NewRedactor(ct), traceLogger)
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

	// Per-rewrite-target transport pool; built below once proxyHandler.Tr exists.
	var transportPool *proxy.TransportPool

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
			normalizeResponseProto(resp)
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
			normalizeResponseProto(errResp)
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

	// Configure the outbound HTTP transport with connection pooling and TLS settings.
	// DialTLSContext handles per-connection TLS with rewrite-specific InsecureSkipVerify.
	// ForceAttemptHTTP2 enables Go's built-in HTTP/2 when custom dial functions are set.
	proxyHandler.Tr = &http.Transport{
		TLSClientConfig:       baseTLSConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DialContext:           proxy.MakeDialer(runtimeCfg),
		DialTLSContext:        proxy.MakeTLSDialer(runtimeCfg),
	}

	// Give each rewrite target its own connection pool. Go keys idle connections on
	// the request URL's host:port, which is computed before our dialers substitute
	// the target address, so a single transport would let rules for the same domain
	// reuse each other's connections. See proxy.TransportPool.
	//
	// Assigned here (after proxyHandler.Tr is built) but captured by the request
	// handler registered above; the handler only runs once the server is serving.
	transportPool = proxy.NewTransportPool(proxyHandler.Tr)

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

	proxyServer := &http.Server{
		Addr:         ":" + cfg.Proxy.Port,
		Handler:      proxyHandler,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start metrics server in background
	go func() {
		slog.Info("Metrics server starting", "port", cfg.Proxy.MetricsPort)
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Metrics server error", "err", err)
		}
	}()

	// Setup signal handling for graceful shutdown and config reload
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// SIGHUP handler for config reload
	sighupChan := make(chan os.Signal, 1)
	signal.Notify(sighupChan, syscall.SIGHUP)

	go func() {
		for range sighupChan {
			slog.Info("SIGHUP received, reloading configuration...")
			newCfg, newACL, newRewrites, err := config.LoadAndCompileConfig(configPath)
			if err != nil {
				slog.Error("Failed to reload configuration", "err", err)
				metrics.ConfigLoadErrors.Inc()
				continue
			}
			newTrace, tErr := config.CompileTrace(newCfg.Trace)
			if tErr != nil {
				slog.Error("Failed to compile trace config on reload", "err", tErr)
				metrics.ConfigLoadErrors.Inc()
				continue
			}
			newBlockedLogger, newBlockedFile, blErr := config.OpenBlockedLog(newCfg.Proxy.BlockedLogPath)
			if blErr != nil {
				slog.Error("Failed to open blocked log on reload", "path", newCfg.Proxy.BlockedLogPath, "err", blErr)
				metrics.ConfigLoadErrors.Inc()
				continue
			}
			newTraceLogger, newTraceFile, tfErr := config.OpenTraceLog(newCfg.Trace.LogPath)
			if tfErr != nil {
				slog.Error("Failed to open trace log on reload", "path", newCfg.Trace.LogPath, "err", tfErr)
				metrics.ConfigLoadErrors.Inc()
				// Avoid leaking the blocked log FD opened just above when we bail out.
				if newBlockedFile != nil {
					if err := newBlockedFile.Close(); err != nil {
						slog.Warn("Failed to close blocked log file after reload error", "err", err)
					}
				}
				continue
			}
			// Warn about settings that changed but cannot be applied without a
			// restart, rather than reporting a clean reload that silently ignored them.
			previousCfg, _, _, _, _ := runtimeCfg.Get()
			if ignored := config.ReloadIgnoredFields(previousCfg, newCfg); len(ignored) > 0 {
				slog.Warn("Configuration changes require a restart and were NOT applied",
					"fields", ignored,
					"hint", "certificate and listen-port changes take effect on restart only")
			}

			newTLSConfig := cert.BuildOutboundTLSConfig(newCfg)
			oldFile := runtimeCfg.Update(newCfg, newACL, newRewrites, newTLSConfig, newBlockedLogger, newBlockedFile)
			if oldFile != nil {
				if err := oldFile.Close(); err != nil {
					slog.Warn("Failed to close rotated blocked log file", "err", err)
				}
			}
			oldTraceFile := runtimeCfg.SetTrace(newTrace, newTraceLogger, newTraceFile)
			if oldTraceFile != nil {
				if err := oldTraceFile.Close(); err != nil {
					slog.Warn("Failed to close rotated trace log file", "err", err)
				}
			}
			// Rewrite targets may now resolve elsewhere; drop pooled connections to
			// the previous targets instead of letting them serve until IdleConnTimeout.
			transportPool.Reset()
			metrics.ConfigReloads.Inc()
			slog.Info("Configuration reloaded successfully",
				"rewrites", len(newRewrites),
				"whitelist", len(newACL.Whitelist),
				"blacklist", len(newACL.Blacklist),
				"passthrough", len(newACL.Passthrough))
		}
	}()

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

	// Closed when the drain finishes, so main waits for it instead of exiting
	// mid-drain. Shutdown closes listeners first, which unblocks Serve on the
	// main goroutine; without this join the process died before the drain ran.
	shutdownDone := make(chan struct{})

	// Graceful shutdown handler
	go func() {
		defer close(shutdownDone)

		<-ctx.Done()
		slog.Info("Shutdown signal received, draining connections...")

		// Fail readiness first so load balancers stop sending new connections
		// while the in-flight ones finish.
		health.SetNotReady()

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

		if err := metricsServer.Shutdown(shutdownCtx); err != nil {
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
