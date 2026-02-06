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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/pkcs12"

	"github.com/elazarl/goproxy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

// version is set at build time via -ldflags "-X main.version=<value>".
var version = "dev"

// Prometheus metrics for monitoring proxy behavior.
var (
	// requestCounter tracks total requests by domain and action taken.
	requestCounter = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "proxy_traffic_total",
		Help: "Total requests by domain and action",
	}, []string{"domain", "action"})

	// requestDuration measures request latency distribution by action.
	requestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "proxy_request_duration_seconds",
		Help:    "Request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"action"})

	// activeConnections tracks currently active proxy connections.
	activeConnections = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "proxy_active_connections",
		Help: "Number of active proxy connections",
	})

	// configLoadErrors counts configuration loading failures.
	configLoadErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "proxy_config_load_errors_total",
		Help: "Total number of configuration load errors",
	})

	// configReloads counts successful configuration reloads.
	configReloads = promauto.NewCounter(prometheus.CounterOpts{
		Name: "proxy_config_reloads_total",
		Help: "Total number of successful configuration reloads",
	})

	// upstreamErrors counts errors connecting to upstream servers.
	upstreamErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "proxy_upstream_errors_total",
		Help: "Total upstream connection errors by type",
	}, []string{"type"})

	// responseStatus counts responses by status code class.
	responseStatus = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "proxy_response_status_total",
		Help: "Total responses by status code class",
	}, []string{"class"})

	// bytesTransferred tracks bytes sent and received.
	bytesTransferred = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "proxy_bytes_total",
		Help: "Total bytes transferred by direction",
	}, []string{"direction"})
)

// RewriteRule defines a domain rewrite configuration.
// When a request matches the Domain pattern, it will be routed to TargetIP or TargetHost
// and the specified Headers will be injected.
// Exactly one of TargetIP or TargetHost must be set.
type RewriteRule struct {
	Domain       string            `yaml:"domain"`        // Domain pattern (exact or wildcard like "*.example.com")
	PathPattern  string            `yaml:"path_pattern"`  // Optional regex matched against r.URL.Path
	TargetIP     string            `yaml:"target_ip"`     // IP address to route to (e.g., "10.0.0.1")
	TargetHost   string            `yaml:"target_host"`   // Hostname to route to (resolved via DNS at dial time)
	TargetScheme string            `yaml:"target_scheme"` // Optional: "http" or "https" to change request scheme
	Headers      map[string]string `yaml:"headers"`       // Headers to inject into the request
	DropHeaders  []string          `yaml:"drop_headers"`  // Headers to remove before forwarding
	Insecure     bool              `yaml:"insecure"`      // Skip TLS verification for this rewrite only
}

// CompiledRewriteRule holds a rewrite rule with its compiled pattern.
type CompiledRewriteRule struct {
	Pattern      *regexp.Regexp
	PathPattern  *regexp.Regexp // nil when no path_pattern is set
	TargetIP     string
	TargetHost   string
	TargetScheme string // "http" or "https" to change request scheme (empty = keep original)
	Headers      map[string]string
	DropHeaders  []string // Headers to remove before forwarding
	Original     string   // Original domain string for exact match optimization
	Insecure     bool     // Skip TLS verification for this rewrite only
}

// rewriteCtxKeyType is an unexported type for context keys to avoid collisions.
type rewriteCtxKeyType struct{}

// rewriteCtxKey is used to pass a matched rewriteResult from handleRequest to the dialers.
var rewriteCtxKey = rewriteCtxKeyType{}

// Config holds the complete proxy configuration loaded from YAML.
type Config struct {
	Proxy struct {
		Port                       string   `yaml:"port"`                         // Proxy listen port (default: "8080")
		MetricsPort                string   `yaml:"metrics_port"`                 // Metrics/health endpoint port (default: "9090")
		DefaultPolicy              string   `yaml:"default_policy"`               // "ALLOW" or "BLOCK" for unmatched domains
		OutgoingCABundle           string   `yaml:"outgoing_ca_bundle"`           // Optional CA bundle for upstream TLS
		OutgoingCA                 []string `yaml:"outgoing_ca"`                  // Optional list of individual CA cert files
		OutgoingTruststorePath     string   `yaml:"outgoing_truststore_path"`     // Optional PKCS#12 truststore for upstream TLS
		OutgoingTruststorePassword string   `yaml:"outgoing_truststore_password"` // Password for outgoing truststore
		InsecureSkipVerify         bool     `yaml:"insecure_skip_verify"`         // Disable TLS verification globally
		MitmCertPath               string   `yaml:"mitm_cert_path"`               // Path to MITM CA certificate
		MitmKeyPath                string   `yaml:"mitm_key_path"`                // Path to MITM CA private key
		MitmKeystorePath           string   `yaml:"mitm_keystore_path"`           // Path to PKCS#12 keystore (.p12) containing cert and key
		MitmKeystorePassword       string   `yaml:"mitm_keystore_password"`       // Password for PKCS#12 keystore
		MitmOrg                    string   `yaml:"mitm_org"`                     // Custom Organization for MITM leaf certificates
		BlockedLogPath             string   `yaml:"blocked_log_path"`             // Optional path for blocked request log
	} `yaml:"proxy"`
	Rewrites []RewriteRule `yaml:"rewrites"` // Domain rewrite rules
	ACL      struct {
		Whitelist []string `yaml:"whitelist"` // Regex patterns to allow
		Blacklist []string `yaml:"blacklist"` // Regex patterns to block
	} `yaml:"acl"`
}

// CompiledACL holds pre-compiled regex patterns for efficient matching.
type CompiledACL struct {
	Whitelist []*regexp.Regexp
	Blacklist []*regexp.Regexp
}

// RuntimeConfig holds the compiled, thread-safe runtime configuration.
type RuntimeConfig struct {
	mu            sync.RWMutex
	config        Config
	acl           CompiledACL
	rewrites      []CompiledRewriteRule
	rewriteExact  map[string]*CompiledRewriteRule // Fast path for exact matches
	blockedLogger *slog.Logger                    // nil when blocked log feature disabled
	blockedFile   *os.File                        // underlying file handle for Close()
}

// Update atomically updates the runtime configuration.
// It returns the previous blocked log file (if any) so the caller can close it after releasing the lock.
func (rc *RuntimeConfig) Update(cfg Config, acl CompiledACL, rewrites []CompiledRewriteRule,
	blockedLogger *slog.Logger, blockedFile *os.File) *os.File {
	// Collect domains that have at least one path-based rule.
	// These domains must be excluded from the exact map so that all their rules
	// are evaluated sequentially (preserving YAML order / first-match-wins).
	domainsWithPath := make(map[string]bool)
	for i := range rewrites {
		if rewrites[i].PathPattern != nil {
			domainsWithPath[rewrites[i].Original] = true
		}
	}

	exactMap := make(map[string]*CompiledRewriteRule)
	for i := range rewrites {
		if !strings.Contains(rewrites[i].Original, "*") && !domainsWithPath[rewrites[i].Original] {
			if _, exists := exactMap[rewrites[i].Original]; !exists {
				exactMap[rewrites[i].Original] = &rewrites[i]
			}
		}
	}

	rc.mu.Lock()
	oldFile := rc.blockedFile
	rc.config = cfg
	rc.acl = acl
	rc.rewrites = rewrites
	rc.rewriteExact = exactMap
	rc.blockedLogger = blockedLogger
	rc.blockedFile = blockedFile
	rc.mu.Unlock()

	return oldFile
}

// Get returns the current configuration (read-locked).
func (rc *RuntimeConfig) Get() (Config, CompiledACL, []CompiledRewriteRule, map[string]*CompiledRewriteRule) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.config, rc.acl, rc.rewrites, rc.rewriteExact
}

// GetBlockedLogger returns the blocked request logger, or nil if disabled.
func (rc *RuntimeConfig) GetBlockedLogger() *slog.Logger {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.blockedLogger
}

// CloseBlockedLog closes the blocked log file handle, if open.
func (rc *RuntimeConfig) CloseBlockedLog() {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.blockedFile != nil {
		if err := rc.blockedFile.Close(); err != nil {
			slog.Warn("Failed to close blocked log file", "err", err)
		}
		rc.blockedFile = nil
		rc.blockedLogger = nil
	}
}

// openBlockedLog opens (or creates) the blocked request log file and returns a JSON logger writing to it.
// If path is empty, the feature is disabled and nil values are returned.
func openBlockedLog(path string) (*slog.Logger, *os.File, error) {
	if path == "" {
		return nil, nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open blocked log: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(f, nil))
	return logger, f, nil
}

// Validate checks the configuration for required fields and valid values.
// It also applies defaults for optional fields.
func (c *Config) Validate() error {
	// Apply defaults
	if c.Proxy.Port == "" {
		c.Proxy.Port = "8080"
	}
	if c.Proxy.MetricsPort == "" {
		c.Proxy.MetricsPort = "9090"
	}
	if c.Proxy.DefaultPolicy == "" {
		c.Proxy.DefaultPolicy = "BLOCK"
	}

	// Validate required fields
	if c.Proxy.DefaultPolicy != "ALLOW" && c.Proxy.DefaultPolicy != "BLOCK" {
		return fmt.Errorf("invalid default_policy %q: must be ALLOW or BLOCK", c.Proxy.DefaultPolicy)
	}

	// Require either cert+key or keystore, but not both
	hasCertKey := c.Proxy.MitmCertPath != "" || c.Proxy.MitmKeyPath != ""
	hasKeystore := c.Proxy.MitmKeystorePath != ""
	if hasCertKey && hasKeystore {
		return errors.New("proxy.mitm_keystore_path and proxy.mitm_cert_path/mitm_key_path are mutually exclusive")
	}
	if !hasCertKey && !hasKeystore {
		return errors.New("proxy.mitm_cert_path and proxy.mitm_key_path are required (or use proxy.mitm_keystore_path)")
	}
	if hasCertKey {
		if c.Proxy.MitmCertPath == "" {
			return errors.New("proxy.mitm_cert_path is required")
		}
		if c.Proxy.MitmKeyPath == "" {
			return errors.New("proxy.mitm_key_path is required")
		}
	}
	if hasKeystore && c.Proxy.MitmKeystorePassword == "" {
		return errors.New("proxy.mitm_keystore_password is required when using proxy.mitm_keystore_path")
	}

	// Validate outgoing truststore
	if c.Proxy.OutgoingTruststorePath != "" && c.Proxy.OutgoingTruststorePassword == "" {
		return errors.New("proxy.outgoing_truststore_password is required when using proxy.outgoing_truststore_path")
	}

	// Validate rewrite rules
	for i, rw := range c.Rewrites {
		if rw.Domain == "" {
			return fmt.Errorf("rewrites[%d]: domain is required", i)
		}
		hasIP := rw.TargetIP != ""
		hasHost := rw.TargetHost != ""
		if hasIP && hasHost {
			return fmt.Errorf("rewrites[%d]: target_ip and target_host are mutually exclusive", i)
		}
		if !hasIP && !hasHost {
			return fmt.Errorf("rewrites[%d]: target_ip or target_host is required", i)
		}
		if hasIP && net.ParseIP(rw.TargetIP) == nil {
			return fmt.Errorf("rewrites[%d]: invalid target_ip %q", i, rw.TargetIP)
		}
		if rw.PathPattern != "" {
			if _, err := regexp.Compile(rw.PathPattern); err != nil {
				return fmt.Errorf("rewrites[%d]: invalid path_pattern %q: %w", i, rw.PathPattern, err)
			}
		}
		if rw.TargetScheme != "" && rw.TargetScheme != "http" && rw.TargetScheme != "https" {
			return fmt.Errorf("rewrites[%d]: invalid target_scheme %q: must be \"http\" or \"https\"", i, rw.TargetScheme)
		}
	}

	// Detect duplicate exact domains without path_pattern (second rule would be unreachable).
	// Domains with path_pattern are exempt because multiple path-based rules on the same
	// domain is the intended usage (first-match-wins).
	seen := make(map[string]int) // domain -> first index
	for i, rw := range c.Rewrites {
		if rw.PathPattern != "" {
			continue
		}
		if first, ok := seen[rw.Domain]; ok {
			return fmt.Errorf("rewrites[%d]: duplicate domain %q without path_pattern (first at rewrites[%d]); second rule is unreachable", i, rw.Domain, first)
		}
		seen[rw.Domain] = i
	}

	return nil
}

// ApplyEnvOverrides applies environment variable overrides to the configuration.
// Environment variables take precedence over YAML values.
func (c *Config) ApplyEnvOverrides() {
	if v := os.Getenv("PROXY_PORT"); v != "" {
		c.Proxy.Port = v
	}
	if v := os.Getenv("PROXY_METRICS_PORT"); v != "" {
		c.Proxy.MetricsPort = v
	}
	if v := os.Getenv("PROXY_DEFAULT_POLICY"); v != "" {
		c.Proxy.DefaultPolicy = v
	}
	if v := os.Getenv("PROXY_MITM_CERT_PATH"); v != "" {
		c.Proxy.MitmCertPath = v
	}
	if v := os.Getenv("PROXY_MITM_KEY_PATH"); v != "" {
		c.Proxy.MitmKeyPath = v
	}
	if v := os.Getenv("PROXY_OUTGOING_CA_BUNDLE"); v != "" {
		c.Proxy.OutgoingCABundle = v
	}
	if v := os.Getenv("PROXY_MITM_KEYSTORE_PATH"); v != "" {
		c.Proxy.MitmKeystorePath = v
	}
	if v := os.Getenv("PROXY_MITM_KEYSTORE_PASSWORD"); v != "" {
		c.Proxy.MitmKeystorePassword = v
	}
	if v := os.Getenv("PROXY_OUTGOING_TRUSTSTORE_PATH"); v != "" {
		c.Proxy.OutgoingTruststorePath = v
	}
	if v := os.Getenv("PROXY_OUTGOING_TRUSTSTORE_PASSWORD"); v != "" {
		c.Proxy.OutgoingTruststorePassword = v
	}
	if v := os.Getenv("PROXY_MITM_ORG"); v != "" {
		c.Proxy.MitmOrg = v
	}
	if v := os.Getenv("PROXY_INSECURE_SKIP_VERIFY"); v == "true" {
		c.Proxy.InsecureSkipVerify = true
	}
	if v := os.Getenv("PROXY_BLOCKED_LOG_PATH"); v != "" {
		c.Proxy.BlockedLogPath = v
	}
}

// runValidate loads and validates the configuration without starting the proxy.
// It checks YAML parsing, pattern compilation, and file existence for referenced paths.
func runValidate(configPath string) error {
	cfg, _, _, err := loadAndCompileConfig(configPath)
	if err != nil {
		return err
	}

	// Check that all referenced files exist and are readable
	filesToCheck := map[string]string{
		"mitm_cert_path":           cfg.Proxy.MitmCertPath,
		"mitm_key_path":            cfg.Proxy.MitmKeyPath,
		"mitm_keystore_path":       cfg.Proxy.MitmKeystorePath,
		"outgoing_ca_bundle":       cfg.Proxy.OutgoingCABundle,
		"outgoing_truststore_path": cfg.Proxy.OutgoingTruststorePath,
	}
	for name, path := range filesToCheck {
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("%s: close: %w", name, err)
		}
	}

	// Validate blocked_log_path parent directory exists
	if cfg.Proxy.BlockedLogPath != "" {
		dir := filepath.Dir(cfg.Proxy.BlockedLogPath)
		if _, err := os.Stat(dir); err != nil {
			return fmt.Errorf("blocked_log_path: parent directory: %w", err)
		}
	}

	return nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: %s [flags] [command]

Commands:
  validate    Validate configuration file and exit

Flags:
  -h, --help      Show this help message
  --version       Print version and exit
  -v              Verbose output (info level, default)
  -vv             Debug output
  -vvv            Trace output (most verbose)

Environment:
  CONFIG_PATH     Path to config file (default: config.yaml)
`, os.Args[0])
}

func main() {
	// Parse top-level flags from os.Args[1:]
	var (
		showVersion bool
		showHelp    bool
		logLevel    = slog.LevelInfo
	)
	var remaining []string
	for _, arg := range os.Args[1:] {
		switch arg {
		case "--version":
			showVersion = true
		case "-h", "--help":
			showHelp = true
		case "-vvv":
			logLevel = slog.Level(-8) // Trace: below slog.LevelDebug (-4)
		case "-vv":
			logLevel = slog.LevelDebug
		case "-v":
			// Explicit info level (same as default)
		default:
			remaining = append(remaining, arg)
		}
	}

	if showVersion {
		fmt.Println(version)
		return
	}
	if showHelp {
		printUsage()
		return
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

		if err := runValidate(configPath); err != nil {
			slog.Error("Configuration validation failed", "path", configPath, "err", err)
			os.Exit(1)
		}
		slog.Info("Configuration is valid", "path", configPath)
		return
	}

	// Load configuration from file (path configurable via CONFIG_PATH env var)
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config.yaml"
	}

	// Initial config load
	cfg, acl, rewrites, err := loadAndCompileConfig(configPath)
	if err != nil {
		slog.Error("Failed to load configuration", "path", configPath, "err", err)
		os.Exit(1)
	}

	// Open blocked request log (optional)
	blockedLogger, blockedFile, err := openBlockedLog(cfg.Proxy.BlockedLogPath)
	if err != nil {
		slog.Error("Failed to open blocked log", "path", cfg.Proxy.BlockedLogPath, "err", err)
		os.Exit(1)
	}

	// Initialize runtime config (thread-safe, reloadable)
	runtimeCfg := &RuntimeConfig{}
	_ = runtimeCfg.Update(cfg, acl, rewrites, blockedLogger, blockedFile)

	// Load MITM CA certificate and key for TLS interception
	if err := loadMITMCertificate(cfg); err != nil {
		slog.Error("Failed to load MITM certificate", "err", err)
		os.Exit(1)
	}

	// Log MITM CA certificate details
	logMITMCertInfo()

	// Initialize the proxy server
	proxy := goproxy.NewProxyHttpServer()
	if cfg.Proxy.MitmOrg != "" {
		mitmAction := &goproxy.ConnectAction{
			Action:    goproxy.ConnectMitm,
			TLSConfig: mitmTLSConfigFromCA(&goproxy.GoproxyCa, cfg.Proxy.MitmOrg),
		}
		proxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(
			func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
				return mitmAction, host
			}))
	} else {
		proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	}

	// Register the request handler for policy enforcement
	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// Wrap the transport to convert errors into synthetic HTTP responses.
		// goproxy's MITM handler drops the connection on RoundTrip errors without
		// writing a response (causing EOF on the client). By catching errors here
		// and returning synthetic 502/504 responses, the MITM handler writes them
		// to the client normally.
		ctx.RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
			resp, err := proxy.Tr.RoundTrip(req)
			if err != nil {
				status, reason := upstreamErrorResponse(err)
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
		return handleRequest(r, ctx, runtimeCfg)
	})

	// Register response handler for metrics and upstream error handling
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
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
			recordResponseMetrics(resp)
			return resp
		}
		if ctx.Error != nil {
			status, reason := upstreamErrorResponse(ctx.Error)
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
	proxy.ConnectionErrHandler = func(w io.Writer, ctx *goproxy.ProxyCtx, err error) {
		status, reason := upstreamErrorResponse(err)
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

	// Build base TLS configuration for outbound connections.
	baseTLSConfig := &tls.Config{
		RootCAs:    loadCertPool(cfg.Proxy.OutgoingCABundle, cfg.Proxy.OutgoingCA, cfg.Proxy.OutgoingTruststorePath, cfg.Proxy.OutgoingTruststorePassword),
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}

	if cfg.Proxy.InsecureSkipVerify {
		slog.Warn("Global insecure_skip_verify is ENABLED — upstream TLS certificate verification is disabled")
		baseTLSConfig.InsecureSkipVerify = true //nolint:gosec // intentional: user-configured global insecure for dev/test
	}

	// Configure the outbound HTTP transport with connection pooling and TLS settings.
	// DialTLSContext handles per-connection TLS with rewrite-specific InsecureSkipVerify.
	// ForceAttemptHTTP2 enables Go's built-in HTTP/2 when custom dial functions are set.
	proxy.Tr = &http.Transport{
		TLSClientConfig:       baseTLSConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DialContext:           makeDialer(runtimeCfg),
		DialTLSContext:        makeTLSDialer(runtimeCfg, baseTLSConfig),
	}

	// Setup metrics and health endpoints
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsMux.HandleFunc("/healthz", healthHandler)
	metricsMux.HandleFunc("/readyz", readyHandler)

	metricsServer := &http.Server{
		Addr:         ":" + cfg.Proxy.MetricsPort,
		Handler:      metricsMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	proxyServer := &http.Server{
		Addr:         ":" + cfg.Proxy.Port,
		Handler:      proxy,
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
			newCfg, newACL, newRewrites, err := loadAndCompileConfig(configPath)
			if err != nil {
				slog.Error("Failed to reload configuration", "err", err)
				configLoadErrors.Inc()
				continue
			}
			newBlockedLogger, newBlockedFile, blErr := openBlockedLog(newCfg.Proxy.BlockedLogPath)
			if blErr != nil {
				slog.Error("Failed to open blocked log on reload", "path", newCfg.Proxy.BlockedLogPath, "err", blErr)
				configLoadErrors.Inc()
				continue
			}
			oldFile := runtimeCfg.Update(newCfg, newACL, newRewrites, newBlockedLogger, newBlockedFile)
			if oldFile != nil {
				if err := oldFile.Close(); err != nil {
					slog.Warn("Failed to close rotated blocked log file", "err", err)
				}
			}
			configReloads.Inc()
			slog.Info("Configuration reloaded successfully",
				"rewrites", len(newRewrites),
				"whitelist", len(newACL.Whitelist),
				"blacklist", len(newACL.Blacklist))
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

// loadAndCompileConfig loads, validates, and compiles the configuration.
func loadAndCompileConfig(path string) (Config, CompiledACL, []CompiledRewriteRule, error) {
	cfg, err := loadConfig(path)
	if err != nil {
		return Config{}, CompiledACL{}, nil, err
	}

	acl, err := compileACL(cfg)
	if err != nil {
		return Config{}, CompiledACL{}, nil, err
	}

	rewrites, err := compileRewrites(cfg.Rewrites)
	if err != nil {
		return Config{}, CompiledACL{}, nil, err
	}

	return cfg, acl, rewrites, nil
}

// loadMITMCertificate loads the MITM CA certificate and key into goproxy.
// It supports either PEM cert+key files or a PKCS#12 (.p12) keystore.
func loadMITMCertificate(cfg Config) error {
	if cfg.Proxy.MitmKeystorePath != "" {
		return loadMITMFromKeystore(cfg.Proxy.MitmKeystorePath, cfg.Proxy.MitmKeystorePassword)
	}
	return loadMITMFromPEM(cfg.Proxy.MitmCertPath, cfg.Proxy.MitmKeyPath)
}

func loadMITMFromPEM(certPath, keyPath string) error {
	caCert, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read certificate: %w", err)
	}
	caKey, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}

	goproxy.GoproxyCa, err = tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return fmt.Errorf("parse keypair: %w", err)
	}

	return validateMITMCA()
}

func loadMITMFromKeystore(keystorePath, password string) error {
	data, err := os.ReadFile(keystorePath)
	if err != nil {
		return fmt.Errorf("read keystore: %w", err)
	}

	privateKey, cert, err := pkcs12.Decode(data, password)
	if err != nil {
		return fmt.Errorf("decode keystore: %w", err)
	}

	goproxy.GoproxyCa = tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}

	return validateMITMCA()
}

// validateMITMCA checks that the loaded MITM certificate is actually a CA certificate.
// A non-CA certificate would silently produce per-domain certs that clients reject.
func validateMITMCA() error {
	leaf := goproxy.GoproxyCa.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(goproxy.GoproxyCa.Certificate[0])
		if err != nil {
			return fmt.Errorf("parse MITM certificate for validation: %w", err)
		}
	}
	if !leaf.IsCA {
		return errors.New("MITM certificate is not a CA certificate (BasicConstraints CA:TRUE is required); " +
			"per-domain certificates signed by a non-CA will be rejected by clients")
	}
	return nil
}

// logMITMCertInfo parses the loaded MITM CA certificate and logs its details.
func logMITMCertInfo() {
	if len(goproxy.GoproxyCa.Certificate) == 0 {
		return
	}

	leaf := goproxy.GoproxyCa.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(goproxy.GoproxyCa.Certificate[0])
		if err != nil {
			slog.Warn("Failed to parse MITM CA certificate for logging", "err", err)
			return
		}
	}

	slog.Info("MITM CA certificate loaded",
		"subject", leaf.Subject.String(),
		"issuer", leaf.Issuer.String(),
		"serial", leaf.SerialNumber.String(),
		"not_before", leaf.NotBefore.Format(time.RFC3339),
		"not_after", leaf.NotAfter.Format(time.RFC3339),
		"is_ca", leaf.IsCA)

	if time.Now().After(leaf.NotAfter) {
		slog.Warn("MITM CA certificate has EXPIRED", "expired_at", leaf.NotAfter.Format(time.RFC3339))
	} else if time.Until(leaf.NotAfter) < 30*24*time.Hour {
		slog.Warn("MITM CA certificate expires soon", "expires_in_days", int(time.Until(leaf.NotAfter).Hours()/24))
	}
}

// signHost generates a leaf TLS certificate for the given hosts, signed by the CA,
// using the specified Organization. The key type matches the CA key (RSA, ECDSA, or Ed25519).
func signHost(ca tls.Certificate, hosts []string, org string) (*tls.Certificate, error) {
	// Parse the CA certificate
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	// Generate serial number
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	// Build leaf certificate template
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   hosts[0],
		},
		NotBefore:             time.Now().Add(-24 * 30 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	// Generate key matching the CA key type
	var privKey any
	switch ca.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case ed25519.PrivateKey:
		_, privKey, err = ed25519.GenerateKey(rand.Reader)
	default: // RSA or unknown → RSA 2048
		privKey, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	// Extract public key
	var pubKey any
	switch k := privKey.(type) {
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	}

	// Sign the leaf certificate with the CA
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pubKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER, ca.Certificate[0]},
		PrivateKey:  privKey,
	}, nil
}

// mitmTLSConfigFromCA returns a TLS config callback that generates leaf certificates
// with the specified Organization, using the given CA. A sync.Map cache avoids
// regenerating certificates for the same host.
func mitmTLSConfigFromCA(ca *tls.Certificate, org string) func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	certCache := &sync.Map{}
	return func(host string, _ *goproxy.ProxyCtx) (*tls.Config, error) {
		// Strip port if present
		hostname, _, err := net.SplitHostPort(host)
		if err != nil {
			hostname = host
		}

		if cached, ok := certCache.Load(hostname); ok {
			cert := cached.(*tls.Certificate) //nolint:errcheck // stored type is always *tls.Certificate
			return &tls.Config{
				Certificates: []tls.Certificate{*cert},
				MinVersion:   tls.VersionTLS12,
			}, nil
		}

		cert, err := signHost(*ca, []string{hostname}, org)
		if err != nil {
			return nil, err
		}

		certCache.Store(hostname, cert)
		return &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS12,
		}, nil
	}
}

// handleRequest processes each incoming request through the policy engine.
// It evaluates rules in order: rewrites -> blacklist -> whitelist -> default policy.
func handleRequest(r *http.Request, _ *goproxy.ProxyCtx, runtimeCfg *RuntimeConfig) (*http.Request, *http.Response) {
	start := time.Now()
	activeConnections.Inc()
	defer activeConnections.Dec()

	// Generate and inject request ID for tracing
	requestID := generateRequestID()
	r.Header.Set("X-Request-ID", requestID)

	cfg, acl, rewrites, rewriteExact := runtimeCfg.Get()

	host := r.URL.Hostname()
	action := "BLOCKED"
	var matchedRewrite *CompiledRewriteRule

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
		rw := rewriteResult{
			targetIP:   matchedRewrite.TargetIP,
			targetHost: matchedRewrite.TargetHost,
			insecure:   matchedRewrite.Insecure,
			matched:    true,
		}
		r = r.WithContext(context.WithValue(r.Context(), rewriteCtxKey, rw))
	}

	// Evaluate ACL if not rewritten
	if action == "BLOCKED" {
		if matches(host, acl.Blacklist) {
			action = "BLACK-LISTED"
		} else if matches(host, acl.Whitelist) {
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
	metricDomain := normalizeDomainForMetrics(host, rewriteExact, acl)
	requestCounter.WithLabelValues(metricDomain, action).Inc()

	// Track request size
	if r.ContentLength > 0 {
		bytesTransferred.WithLabelValues("request").Add(float64(r.ContentLength))
	}

	defer func() {
		requestDuration.WithLabelValues(action).Observe(time.Since(start).Seconds())
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

// upstreamErrorResponse returns the HTTP status code and reason text for an upstream error.
// Timeouts yield 504 Gateway Timeout; all other failures (DNS, refused, reset) yield 502 Bad Gateway.
func upstreamErrorResponse(err error) (int, string) {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return http.StatusGatewayTimeout, "Gateway Timeout"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout, "Gateway Timeout"
	}
	return http.StatusBadGateway, "Bad Gateway"
}

// recordResponseMetrics records metrics from the response.
func recordResponseMetrics(resp *http.Response) {
	// Track response size
	if resp.ContentLength > 0 {
		bytesTransferred.WithLabelValues("response").Add(float64(resp.ContentLength))
	}

	// Track status code class
	statusClass := fmt.Sprintf("%dxx", resp.StatusCode/100)
	responseStatus.WithLabelValues(statusClass).Inc()
}

// rewriteResult holds the outcome of a rewrite rule lookup.
type rewriteResult struct {
	targetIP   string
	targetHost string
	insecure   bool
	matched    bool
}

// lookupRewrite checks whether host matches a rewrite rule (exact map first, then patterns).
// Rules with PathPattern are skipped because the dialer has no access to the HTTP request path;
// those are resolved in handleRequest and passed via request context instead.
func lookupRewrite(host string, rewrites []CompiledRewriteRule, rewriteExact map[string]*CompiledRewriteRule) rewriteResult {
	if rw, ok := rewriteExact[host]; ok {
		return rewriteResult{targetIP: rw.TargetIP, targetHost: rw.TargetHost, insecure: rw.Insecure, matched: true}
	}
	for i := range rewrites {
		if rewrites[i].PathPattern != nil {
			continue // path-based rules are resolved via context
		}
		if rewrites[i].Pattern.MatchString(host) {
			return rewriteResult{targetIP: rewrites[i].TargetIP, targetHost: rewrites[i].TargetHost, insecure: rewrites[i].Insecure, matched: true}
		}
	}
	return rewriteResult{}
}

// recordDialError records a dial error in the upstream error metrics.
func recordDialError(err error) {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		upstreamErrors.WithLabelValues("timeout").Inc()
	} else {
		upstreamErrors.WithLabelValues("connection").Inc()
	}
}

// makeDialer creates a custom DialContext function that implements split-brain DNS.
// It intercepts TCP dials and routes matching domains to their configured target IPs.
// Path-based rewrites are passed via request context from handleRequest.
func makeDialer(runtimeCfg *RuntimeConfig) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			upstreamErrors.WithLabelValues("invalid_address").Inc()
			return nil, fmt.Errorf("invalid address %q: %w", addr, err)
		}

		// Check context first (set by handleRequest for path-based rewrites)
		rw, ok := ctx.Value(rewriteCtxKey).(rewriteResult)
		if !ok {
			_, _, rewrites, rewriteExact := runtimeCfg.Get()
			rw = lookupRewrite(host, rewrites, rewriteExact)
		}

		if rw.targetIP != "" {
			addr = net.JoinHostPort(rw.targetIP, port)
			slog.Debug("Rewriting dial", "original", host, "target", rw.targetIP)
		} else if rw.targetHost != "" {
			addr = net.JoinHostPort(rw.targetHost, port)
			slog.Debug("Rewriting dial", "original", host, "target", rw.targetHost)
		}

		conn, dialErr := (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext(ctx, network, addr)

		if dialErr != nil {
			recordDialError(dialErr)
			return nil, dialErr
		}

		return conn, nil
	}
}

// makeTLSDialer creates a custom DialTLSContext function that performs TCP dial with
// rewrite IP substitution followed by a TLS handshake with per-connection configuration.
// This enables per-rewrite InsecureSkipVerify without affecting other connections.
// Path-based rewrites are passed via request context from handleRequest.
func makeTLSDialer(runtimeCfg *RuntimeConfig, baseTLSConfig *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			upstreamErrors.WithLabelValues("invalid_address").Inc()
			return nil, fmt.Errorf("invalid address %q: %w", addr, err)
		}

		cfg, _, rewrites, rewriteExact := runtimeCfg.Get()

		// Check context first (set by handleRequest for path-based rewrites)
		rw, ok := ctx.Value(rewriteCtxKey).(rewriteResult)
		if !ok {
			rw = lookupRewrite(host, rewrites, rewriteExact)
		}

		dialAddr := addr
		if rw.targetIP != "" {
			dialAddr = net.JoinHostPort(rw.targetIP, port)
			slog.Debug("Rewriting TLS dial", "original", host, "target", rw.targetIP)
		} else if rw.targetHost != "" {
			dialAddr = net.JoinHostPort(rw.targetHost, port)
			slog.Debug("Rewriting TLS dial", "original", host, "target", rw.targetHost)
		}

		// TCP connect
		rawConn, dialErr := (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext(ctx, network, dialAddr)
		if dialErr != nil {
			recordDialError(dialErr)
			return nil, dialErr
		}

		// Build per-connection TLS config
		tlsCfg := baseTLSConfig.Clone()
		tlsCfg.ServerName = host // SNI = original hostname
		if cfg.Proxy.InsecureSkipVerify || rw.insecure {
			tlsCfg.InsecureSkipVerify = true //nolint:gosec // intentional: user-configured insecure for dev/internal endpoints
		}

		// TLS handshake
		tlsConn := tls.Client(rawConn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close() //nolint:errcheck // best-effort cleanup on handshake failure
			recordDialError(err)
			return nil, err
		}

		return tlsConn, nil
	}
}

// generateRequestID generates a random request ID for tracing.
func generateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp if random fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// healthHandler responds to liveness probe requests.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// readyHandler responds to readiness probe requests.
func readyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

// normalizeDomainForMetrics prevents metrics cardinality explosion by grouping domains.
// Known rewrite domains are tracked individually, ACL-matched domains by base domain,
// and unknown domains are grouped as "_other".
func normalizeDomainForMetrics(host string, rewriteExact map[string]*CompiledRewriteRule, acl CompiledACL) string {
	// Known rewrite targets get their own label
	if _, ok := rewriteExact[host]; ok {
		return host
	}

	// Extract base domain (TLD+1) for ACL-matched hosts
	if matches(host, acl.Whitelist) || matches(host, acl.Blacklist) {
		return extractBaseDomain(host)
	}

	// Unknown domains are grouped to prevent cardinality explosion
	return "_other"
}

// extractBaseDomain returns the base domain (e.g., "sub.example.com" -> "example.com").
// This is a simple implementation that assumes standard TLD structure.
func extractBaseDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// loadCertPool loads the system CA pool, optionally appends a PEM CA bundle, individual CA cert
// files, and/or certificates from a PKCS#12 truststore. All sources are additive.
func loadCertPool(caBundle string, certPaths []string, truststorePath, truststorePassword string) *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil {
		slog.Warn("Failed to load system cert pool, using empty pool", "err", err)
		pool = x509.NewCertPool()
	}
	if caBundle != "" {
		ca, readErr := os.ReadFile(caBundle)
		if readErr != nil {
			slog.Warn("Failed to read CA bundle", "path", caBundle, "err", readErr)
		} else if !pool.AppendCertsFromPEM(ca) {
			slog.Warn("Failed to parse CA bundle", "path", caBundle)
		}
	}
	for _, p := range certPaths {
		ca, readErr := os.ReadFile(p)
		if readErr != nil {
			slog.Warn("Failed to read CA cert", "path", p, "err", readErr)
			continue
		}
		if !pool.AppendCertsFromPEM(ca) {
			slog.Warn("Failed to parse CA cert", "path", p)
		}
	}
	if truststorePath != "" {
		certs, tsErr := loadTruststoreCerts(truststorePath, truststorePassword)
		if tsErr != nil {
			slog.Warn("Failed to load truststore", "path", truststorePath, "err", tsErr)
		} else {
			for _, cert := range certs {
				pool.AddCert(cert)
			}
			slog.Info("Loaded truststore certificates", "path", truststorePath, "count", len(certs))
		}
	}
	return pool
}

// loadTruststoreCerts extracts CA certificates from a PKCS#12 (.p12) truststore.
func loadTruststoreCerts(path, password string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read truststore: %w", err)
	}

	pemBlocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		return nil, fmt.Errorf("decode truststore: %w", err)
	}

	var certs []*x509.Certificate
	for _, block := range pemBlocks {
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse truststore certificate: %w", parseErr)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, errors.New("truststore contains no certificates")
	}
	return certs, nil
}

// matches checks if a host matches any of the compiled regex patterns.
func matches(host string, patterns []*regexp.Regexp) bool {
	for _, p := range patterns {
		if p.MatchString(host) {
			return true
		}
	}
	return false
}

// compileACL compiles all patterns in the configuration using wildcardToRegex.
// Patterns support exact match, wildcards (*.example.com), and raw regex (~<pattern>).
// Returns an error if any pattern is invalid.
func compileACL(cfg Config) (CompiledACL, error) {
	c := CompiledACL{}
	for i, p := range cfg.ACL.Whitelist {
		re, err := wildcardToRegex(p)
		if err != nil {
			return CompiledACL{}, fmt.Errorf("invalid whitelist pattern[%d] %q: %w", i, p, err)
		}
		c.Whitelist = append(c.Whitelist, re)
	}
	for i, p := range cfg.ACL.Blacklist {
		re, err := wildcardToRegex(p)
		if err != nil {
			return CompiledACL{}, fmt.Errorf("invalid blacklist pattern[%d] %q: %w", i, p, err)
		}
		c.Blacklist = append(c.Blacklist, re)
	}
	return c, nil
}

// compileRewrites compiles rewrite rules, converting wildcards to regex patterns.
func compileRewrites(rules []RewriteRule) ([]CompiledRewriteRule, error) {
	compiled := make([]CompiledRewriteRule, 0, len(rules))
	for i, rule := range rules {
		pattern, err := wildcardToRegex(rule.Domain)
		if err != nil {
			return nil, fmt.Errorf("invalid rewrite domain[%d] %q: %w", i, rule.Domain, err)
		}
		var pathPattern *regexp.Regexp
		if rule.PathPattern != "" {
			pathPattern, err = regexp.Compile(rule.PathPattern)
			if err != nil {
				return nil, fmt.Errorf("invalid rewrite path_pattern[%d] %q: %w", i, rule.PathPattern, err)
			}
		}
		compiled = append(compiled, CompiledRewriteRule{
			Pattern:      pattern,
			PathPattern:  pathPattern,
			TargetIP:     rule.TargetIP,
			TargetHost:   rule.TargetHost,
			TargetScheme: rule.TargetScheme,
			Headers:      rule.Headers,
			DropHeaders:  rule.DropHeaders,
			Original:     rule.Domain,
			Insecure:     rule.Insecure,
		})
	}
	return compiled, nil
}

// wildcardToRegex converts a domain pattern with wildcards to a regex.
// Supports:
//   - Exact match: "example.com" -> "^example\.com$"
//   - Wildcard: "*.example.com" -> "^.+\.example\.com$" (matches any subdomain depth)
//   - Full wildcard: "*" -> ".*"
//   - Raw regex: "~<regex>" -> compiled as-is (no escaping/anchoring)
func wildcardToRegex(pattern string) (*regexp.Regexp, error) {
	if strings.HasPrefix(pattern, "~") {
		return regexp.Compile(pattern[1:])
	}

	if pattern == "*" {
		return regexp.Compile(".*")
	}

	// Escape regex special characters except *
	escaped := regexp.QuoteMeta(pattern)

	// Replace \* with appropriate regex
	// *.example.com -> matches any subdomain depth (e.g. a.b.c.example.com)
	if strings.HasPrefix(escaped, `\*\.`) {
		escaped = `.+\.` + escaped[4:]
	}

	// Anchor the pattern
	escaped = "^" + escaped + "$"

	return regexp.Compile(escaped)
}

// loadConfig reads and validates the configuration file.
func loadConfig(path string) (Config, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		configLoadErrors.Inc()
		return Config{}, fmt.Errorf("read config file: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(f, &c); err != nil {
		configLoadErrors.Inc()
		return Config{}, fmt.Errorf("parse config file: %w", err)
	}

	// Apply environment variable overrides
	c.ApplyEnvOverrides()

	if err := c.Validate(); err != nil {
		configLoadErrors.Inc()
		return Config{}, fmt.Errorf("validate config: %w", err)
	}
	return c, nil
}
