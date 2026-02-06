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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/pkcs12"
	"golang.org/x/net/http2"

	"github.com/elazarl/goproxy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

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
	Domain     string            `yaml:"domain"`      // Domain pattern (exact or wildcard like "*.example.com")
	TargetIP   string            `yaml:"target_ip"`   // IP address to route to (e.g., "10.0.0.1")
	TargetHost string            `yaml:"target_host"` // Hostname to route to (resolved via DNS at dial time)
	Headers    map[string]string `yaml:"headers"`     // Headers to inject into the request
}

// CompiledRewriteRule holds a rewrite rule with its compiled pattern.
type CompiledRewriteRule struct {
	Pattern    *regexp.Regexp
	TargetIP   string
	TargetHost string
	Headers    map[string]string
	Original   string // Original domain string for exact match optimization
}

// Config holds the complete proxy configuration loaded from YAML.
type Config struct {
	Proxy struct {
		Port                 string `yaml:"port"`                   // Proxy listen port (default: "8080")
		MetricsPort          string `yaml:"metrics_port"`           // Metrics/health endpoint port (default: "9090")
		DefaultPolicy        string `yaml:"default_policy"`         // "ALLOW" or "BLOCK" for unmatched domains
		OutgoingCABundle     string `yaml:"outgoing_ca_bundle"`     // Optional CA bundle for upstream TLS
		MitmCertPath         string `yaml:"mitm_cert_path"`         // Path to MITM CA certificate
		MitmKeyPath          string `yaml:"mitm_key_path"`          // Path to MITM CA private key
		MitmKeystorePath     string `yaml:"mitm_keystore_path"`     // Path to PKCS#12 keystore (.p12) containing cert and key
		MitmKeystorePassword string `yaml:"mitm_keystore_password"` // Password for PKCS#12 keystore
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
	mu           sync.RWMutex
	config       Config
	acl          CompiledACL
	rewrites     []CompiledRewriteRule
	rewriteExact map[string]*CompiledRewriteRule // Fast path for exact matches
}

// Update atomically updates the runtime configuration.
func (rc *RuntimeConfig) Update(cfg Config, acl CompiledACL, rewrites []CompiledRewriteRule) {
	exactMap := make(map[string]*CompiledRewriteRule)
	for i := range rewrites {
		if !strings.Contains(rewrites[i].Original, "*") {
			exactMap[rewrites[i].Original] = &rewrites[i]
		}
	}

	rc.mu.Lock()
	rc.config = cfg
	rc.acl = acl
	rc.rewrites = rewrites
	rc.rewriteExact = exactMap
	rc.mu.Unlock()
}

// Get returns the current configuration (read-locked).
func (rc *RuntimeConfig) Get() (Config, CompiledACL, []CompiledRewriteRule, map[string]*CompiledRewriteRule) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.config, rc.acl, rc.rewrites, rc.rewriteExact
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
		"mitm_cert_path":     cfg.Proxy.MitmCertPath,
		"mitm_key_path":      cfg.Proxy.MitmKeyPath,
		"mitm_keystore_path": cfg.Proxy.MitmKeystorePath,
		"outgoing_ca_bundle": cfg.Proxy.OutgoingCABundle,
	}
	for name, path := range filesToCheck {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}

	return nil
}

func main() {
	// Initialize structured JSON logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Subcommand dispatch
	if len(os.Args) > 1 && os.Args[1] == "validate" {
		fs := flag.NewFlagSet("validate", flag.ExitOnError)
		configFlag := fs.String("config", "", "path to configuration file")
		if err := fs.Parse(os.Args[2:]); err != nil {
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

	// Initialize runtime config (thread-safe, reloadable)
	runtimeCfg := &RuntimeConfig{}
	runtimeCfg.Update(cfg, acl, rewrites)

	// Load MITM CA certificate and key for TLS interception
	if err := loadMITMCertificate(cfg); err != nil {
		slog.Error("Failed to load MITM certificate", "err", err)
		os.Exit(1)
	}

	// Initialize the proxy server
	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	// Register the request handler for policy enforcement
	proxy.OnRequest().DoFunc(func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		return handleRequest(r, ctx, runtimeCfg)
	})

	// Register response handler for metrics
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp != nil {
			recordResponseMetrics(resp)
		}
		return resp
	})

	// Configure the outbound HTTP transport with connection pooling and TLS settings.
	// ForceAttemptHTTP2 is required because we set a custom TLSClientConfig and DialContext.
	proxy.Tr = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    loadCertPool(cfg.Proxy.OutgoingCABundle),
			MinVersion: tls.VersionTLS12, // Enforce TLS 1.2 minimum
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DialContext:           makeDialer(runtimeCfg),
	}
	if err := http2.ConfigureTransport(proxy.Tr); err != nil {
		slog.Warn("Failed to configure HTTP/2 for outbound transport", "err", err)
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
			runtimeCfg.Update(newCfg, newACL, newRewrites)
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
	}()

	// Start the proxy server
	slog.Info("Proxy server starting",
		"port", cfg.Proxy.Port,
		"metrics_port", cfg.Proxy.MetricsPort,
		"default_policy", cfg.Proxy.DefaultPolicy,
		"rewrites", len(rewrites),
		"whitelist_rules", len(acl.Whitelist),
		"blacklist_rules", len(acl.Blacklist))

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

	return nil
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

	return nil
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
	// Fast path: exact match
	if rw, ok := rewriteExact[host]; ok {
		matchedRewrite = rw
		action = "REWRITTEN"
	} else {
		// Slow path: pattern match
		for i := range rewrites {
			if rewrites[i].Pattern.MatchString(host) {
				matchedRewrite = &rewrites[i]
				action = "REWRITTEN"
				break
			}
		}
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
		return r, goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusForbidden, "Policy Blocked")
	}

	// Inject headers for rewritten requests
	if matchedRewrite != nil {
		for k, v := range matchedRewrite.Headers {
			r.Header.Set(k, v)
		}
	}

	return r, nil
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

// makeDialer creates a custom DialContext function that implements split-brain DNS.
// It intercepts TCP dials and routes matching domains to their configured target IPs.
func makeDialer(runtimeCfg *RuntimeConfig) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			upstreamErrors.WithLabelValues("invalid_address").Inc()
			return nil, fmt.Errorf("invalid address %q: %w", addr, err)
		}

		_, _, rewrites, rewriteExact := runtimeCfg.Get()

		// Check for rewrite (fast path first)
		var targetIP, targetHost string
		if rw, ok := rewriteExact[host]; ok {
			targetIP = rw.TargetIP
			targetHost = rw.TargetHost
		} else {
			for i := range rewrites {
				if rewrites[i].Pattern.MatchString(host) {
					targetIP = rewrites[i].TargetIP
					targetHost = rewrites[i].TargetHost
					break
				}
			}
		}

		if targetIP != "" {
			addr = net.JoinHostPort(targetIP, port)
			slog.Debug("Rewriting dial", "original", host, "target", targetIP)
		} else if targetHost != "" {
			addr = net.JoinHostPort(targetHost, port)
			slog.Debug("Rewriting dial", "original", host, "target", targetHost)
		}

		conn, err := (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext(ctx, network, addr)

		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				upstreamErrors.WithLabelValues("timeout").Inc()
			} else {
				upstreamErrors.WithLabelValues("connection").Inc()
			}
			return nil, err
		}

		return conn, nil
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

// loadCertPool loads the system CA pool and optionally appends a custom CA bundle.
func loadCertPool(path string) *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil {
		slog.Warn("Failed to load system cert pool, using empty pool", "err", err)
		pool = x509.NewCertPool()
	}
	if path != "" {
		ca, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("Failed to read CA bundle", "path", path, "err", err)
		} else if !pool.AppendCertsFromPEM(ca) {
			slog.Warn("Failed to parse CA bundle", "path", path)
		}
	}
	return pool
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
		compiled = append(compiled, CompiledRewriteRule{
			Pattern:    pattern,
			TargetIP:   rule.TargetIP,
			TargetHost: rule.TargetHost,
			Headers:    rule.Headers,
			Original:   rule.Domain,
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
