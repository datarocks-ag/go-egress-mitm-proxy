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
)

// version is set at build time via -ldflags "-X main.version=<value>".
var version = "dev"

// slogProxyLogger adapts goproxy's Logger interface to route through slog.
type slogProxyLogger struct{}

func (l *slogProxyLogger) Printf(format string, v ...any) {
	if slog.Default().Enabled(context.Background(), slog.LevelDebug) {
		slog.Debug(fmt.Sprintf(format, v...), "source", "goproxy")
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

	mitmAction := &goproxy.ConnectAction{Action: goproxy.ConnectMitm}
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

			// Check passthrough ACL: tunnel without MITM interception
			_, currentACL, _, rewriteExact, _ := runtimeCfg.Get()
			hostname := host
			if h, _, err := net.SplitHostPort(host); err == nil {
				hostname = h
			}
			if config.Matches(hostname, currentACL.Passthrough) {
				slog.Info("PASSTHROUGH",
					"host", hostname,
					"client", ctx.Req.RemoteAddr)
				metricDomain := proxy.NormalizeDomainForMetrics(hostname, rewriteExact, currentACL)
				metrics.TrafficTotal.WithLabelValues(metricDomain, "PASSTHROUGH").Inc()
				return passthroughAction, host
			}

			return mitmAction, host
		}))

	// Register the request handler for policy enforcement
	proxyHandler.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// Wrap the transport to convert errors into synthetic HTTP responses.
		// goproxy's MITM handler drops the connection on RoundTrip errors without
		// writing a response (causing EOF on the client). By catching errors here
		// and returning synthetic 502/504 responses, the MITM handler writes them
		// to the client normally.
		ctx.RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
			resp, err := proxyHandler.Tr.RoundTrip(req)
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
		if resp != nil {
			// Normalize response protocol to HTTP/1.1 for MITM tunnels.
			// goproxy writes responses via resp.Write() which serializes
			// ProtoMajor/ProtoMinor into the status line. Two cases need fixing:
			// 1) goproxy.NewResponse() leaves Proto fields at zero → "HTTP/0.0"
			// 2) Upstream HTTP/2 responses have Proto "HTTP/2.0" → "HTTP/2.0"
			// Both cause "Unsupported HTTP version" errors in clients.
			if resp.ProtoMajor != 1 {
				resp.Proto = "HTTP/1.1"
				resp.ProtoMajor = 1
				resp.ProtoMinor = 1
			}
			proxy.RecordResponseMetrics(resp)
			return resp
		}
		if ctx.Error != nil {
			status, reason := proxy.UpstreamErrorResponse(ctx.Error)
			slog.Warn("Upstream connection error",
				"host", ctx.Req.URL.Host,
				"status", status,
				"err", ctx.Error)
			return goproxy.NewResponse(ctx.Req,
				goproxy.ContentTypeText,
				status,
				reason)
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
			newBlockedLogger, newBlockedFile, blErr := config.OpenBlockedLog(newCfg.Proxy.BlockedLogPath)
			if blErr != nil {
				slog.Error("Failed to open blocked log on reload", "path", newCfg.Proxy.BlockedLogPath, "err", blErr)
				metrics.ConfigLoadErrors.Inc()
				continue
			}
			newTLSConfig := cert.BuildOutboundTLSConfig(newCfg)
			oldFile := runtimeCfg.Update(newCfg, newACL, newRewrites, newTLSConfig, newBlockedLogger, newBlockedFile)
			if oldFile != nil {
				if err := oldFile.Close(); err != nil {
					slog.Warn("Failed to close rotated blocked log file", "err", err)
				}
			}
			metrics.ConfigReloads.Inc()
			slog.Info("Configuration reloaded successfully",
				"rewrites", len(newRewrites),
				"whitelist", len(newACL.Whitelist),
				"blacklist", len(newACL.Blacklist),
				"passthrough", len(newACL.Passthrough))
		}
	}()

	// Graceful shutdown handler
	go func() {
		<-ctx.Done()
		slog.Info("Shutdown signal received, draining connections...")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := proxyServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("Proxy server shutdown error", "err", err)
		}
		if err := metricsServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("Metrics server shutdown error", "err", err)
		}
		runtimeCfg.CloseBlockedLog()
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

	if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Proxy server error", "err", err)
		os.Exit(1)
	}

	slog.Info("Proxy server stopped")
}
